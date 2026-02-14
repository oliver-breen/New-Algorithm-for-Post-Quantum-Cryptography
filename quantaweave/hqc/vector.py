"""
Vector operations and sampling for HQC.

Ported from vector.c in the HQC reference implementation.
"""

from typing import List

from .parameters import HQCParameters, bitmask
from .symmetric import Shake256XOF
from .byte_utils import bytes_to_u64_list, u64_list_to_bytes

U64_MASK = (1 << 64) - 1


def _barrett_reduce(x: int, params: HQCParameters) -> int:
    q = (x * params.param_n_mu) >> 32
    r = x - q * params.param_n
    if r >= params.param_n:
        r -= params.param_n
    return r


def vect_generate_random_support1(ctx: Shake256XOF, params: HQCParameters, weight: int) -> List[int]:
    support: List[int] = []
    while len(support) < weight:
        rand_bytes = ctx.get_bytes(3)
        candidate = rand_bytes[0] | (rand_bytes[1] << 8) | (rand_bytes[2] << 16)
        if candidate >= params.utils_rejection_threshold:
            continue
        candidate = _barrett_reduce(candidate, params)
        if candidate in support:
            continue
        support.append(candidate)
    return support


def vect_generate_random_support2(ctx: Shake256XOF, params: HQCParameters, weight: int) -> List[int]:
    rand_bytes = ctx.get_bytes(4 * weight)
    support = [0] * weight
    for i in range(weight):
        buff = int.from_bytes(rand_bytes[i * 4 : (i + 1) * 4], "little")
        support[i] = i + ((buff * (params.param_n - i)) >> 32)

    for i in range(weight - 1, -1, -1):
        found = 0
        for j in range(i + 1, weight):
            found |= 1 if support[j] == support[i] else 0
        if found:
            support[i] = i
    return support


def vect_write_support_to_vector(params: HQCParameters, support: List[int], weight: int) -> List[int]:
    v = [0] * params.vec_n_size_64
    index_tab = [0] * weight
    bit_tab = [0] * weight

    for i in range(weight):
        index_tab[i] = support[i] >> 6
        pos = support[i] & 0x3F
        bit_tab[i] = (1 << pos) & U64_MASK

    for i in range(params.vec_n_size_64):
        val = 0
        for j in range(weight):
            tmp = i - index_tab[j]
            val1 = 1 ^ (((tmp | -tmp) >> 31) & 1)
            mask = -val1 & U64_MASK
            val |= bit_tab[j] & mask
        v[i] |= val & U64_MASK

    return v


def vect_sample_fixed_weight1(ctx: Shake256XOF, params: HQCParameters, weight: int) -> List[int]:
    support = vect_generate_random_support1(ctx, params, weight)
    return vect_write_support_to_vector(params, support, weight)


def vect_sample_fixed_weight2(ctx: Shake256XOF, params: HQCParameters, weight: int) -> List[int]:
    support = vect_generate_random_support2(ctx, params, weight)
    return vect_write_support_to_vector(params, support, weight)


def vect_set_random(ctx: Shake256XOF, params: HQCParameters) -> List[int]:
    data = ctx.get_bytes(params.vec_n_size_bytes)
    v = bytes_to_u64_list(data, params.vec_n_size_64)
    v[-1] &= bitmask(params.param_n, 64)
    return v


def vect_add(v1: List[int], v2: List[int]) -> List[int]:
    return [(a ^ b) & U64_MASK for a, b in zip(v1, v2)]


def vect_compare(v1: bytes, v2: bytes) -> int:
    r = 0x0100
    for a, b in zip(v1, v2):
        r |= a ^ b
    return (r - 1) >> 8


def vect_truncate(params: HQCParameters, v: List[int]) -> List[int]:
    orig_words = (params.param_n + 63) // 64
    new_full_words = params.param_n1n2 // 64
    remaining_bits = params.param_n1n2 % 64

    if remaining_bits > 0:
        mask = (1 << remaining_bits) - 1
        v[new_full_words] &= mask
        new_full_words += 1

    for i in range(new_full_words, orig_words):
        v[i] = 0
    return v


def vect_to_bytes(params: HQCParameters, v: List[int], byte_len: int) -> bytes:
    return u64_list_to_bytes(v, byte_len)
