"""
Carry-less polynomial multiplication over GF(2) modulo X^n - 1.

Ported from gf2x.c with a simplified schoolbook implementation.
"""

from typing import List

from .parameters import HQCParameters

U64_MASK = (1 << 64) - 1


def _schoolbook_mul(a: List[int], b: List[int]) -> List[int]:
    n = len(a)
    r = [0] * (2 * n)
    for i in range(n):
        ai = a[i]
        for bit in range(64):
            if (ai >> bit) & 1:
                base = i
                sh = bit
                inv = 64 - sh
                if sh == 0:
                    for j in range(n):
                        r[base + j] ^= b[j]
                else:
                    for j in range(n):
                        r[base + j] ^= (b[j] << sh) & U64_MASK
                        r[base + j + 1] ^= (b[j] >> inv) & U64_MASK
    return r


def _reduce(params: HQCParameters, a: List[int]) -> List[int]:
    poly = 0
    for idx, word in enumerate(a):
        poly |= (word & U64_MASK) << (64 * idx)

    modulus = params.param_n
    mask = (1 << modulus) - 1
    while poly >> modulus:
        overflow = poly >> modulus
        poly &= mask
        poly ^= overflow

    out = []
    for _ in range(params.vec_n_size_64):
        out.append(poly & U64_MASK)
        poly >>= 64
    rem = params.param_n % 64
    if rem != 0:
        out[-1] &= (1 << rem) - 1
    return out


def vect_mul(params: HQCParameters, a1: List[int], a2: List[int]) -> List[int]:
    unreduced = _schoolbook_mul(a1, a2)
    return _reduce(params, unreduced)
