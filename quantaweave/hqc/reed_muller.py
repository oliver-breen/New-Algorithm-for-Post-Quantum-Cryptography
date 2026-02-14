"""
Reed-Muller RM(1,7) codec for HQC.

Ported from reed_muller.c.
"""

from typing import List
import struct

from .parameters import HQCParameters
from .byte_utils import bytes_to_u64_list, u64_list_to_bytes


def _bit0mask(x: int) -> int:
    return -((x) & 1) & 0xFFFFFFFF


def _encode_byte(message: int) -> List[int]:
    first_word = _bit0mask(message >> 7)
    first_word ^= _bit0mask(message >> 0) & 0xAAAAAAAA
    first_word ^= _bit0mask(message >> 1) & 0xCCCCCCCC
    first_word ^= _bit0mask(message >> 2) & 0xF0F0F0F0
    first_word ^= _bit0mask(message >> 3) & 0xFF00FF00
    first_word ^= _bit0mask(message >> 4) & 0xFFFF0000

    u32_0 = first_word & 0xFFFFFFFF

    first_word ^= _bit0mask(message >> 5)
    u32_1 = first_word & 0xFFFFFFFF
    first_word ^= _bit0mask(message >> 6)
    u32_3 = first_word & 0xFFFFFFFF
    first_word ^= _bit0mask(message >> 5)
    u32_2 = first_word & 0xFFFFFFFF

    return [u32_0, u32_1, u32_2, u32_3]


def _hadamard(src: List[int]) -> List[int]:
    p1 = src[:]
    p2 = [0] * 128
    for _ in range(7):
        for i in range(64):
            p2[i] = p1[2 * i] + p1[2 * i + 1]
            p2[i + 64] = p1[2 * i] - p1[2 * i + 1]
        p1, p2 = p2, p1
    return p1


def _expand_and_sum(codewords: List[bytes]) -> List[int]:
    dest = [0] * 128
    for part in range(4):
        word = int.from_bytes(codewords[0][part * 4 : (part + 1) * 4], "little")
        for bit in range(32):
            dest[part * 32 + bit] = (word >> bit) & 1

    for cw in codewords[1:]:
        for part in range(4):
            word = int.from_bytes(cw[part * 4 : (part + 1) * 4], "little")
            for bit in range(32):
                dest[part * 32 + bit] += (word >> bit) & 1

    return dest


def _find_peaks(transform: List[int]) -> int:
    peak_abs_value = 0
    peak_value = 0
    peak_pos = 0
    for i in range(128):
        t = transform[i]
        absolute = abs(t)
        if absolute > peak_abs_value:
            peak_abs_value = absolute
            peak_value = t
            peak_pos = i
    if peak_value > 0:
        peak_pos |= 128
    return peak_pos


def reed_muller_encode(params: HQCParameters, msg: List[int]) -> List[int]:
    message_bytes = u64_list_to_bytes(msg, params.vec_n1_size_bytes)
    multiplicity = (params.param_n2 + 127) // 128
    total_codewords = params.vec_n1_size_bytes * multiplicity
    out = bytearray(total_codewords * 16)

    for i, byte_val in enumerate(message_bytes):
        codeword = _encode_byte(byte_val)
        code_bytes = struct.pack("<4I", *codeword)
        base = i * multiplicity * 16
        for copy in range(multiplicity):
            out[base + copy * 16 : base + (copy + 1) * 16] = code_bytes

    return bytes_to_u64_list(bytes(out), params.vec_n1n2_size_64)


def reed_muller_decode(params: HQCParameters, cdw: List[int]) -> List[int]:
    cdw_bytes = u64_list_to_bytes(cdw, params.vec_n1n2_size_bytes)
    multiplicity = (params.param_n2 + 127) // 128
    message = bytearray(params.vec_n1_size_bytes)

    for i in range(params.vec_n1_size_bytes):
        base = i * multiplicity * 16
        codewords = [cdw_bytes[base + j * 16 : base + (j + 1) * 16] for j in range(multiplicity)]
        expanded = _expand_and_sum(codewords)
        transform = _hadamard(expanded)
        transform[0] -= 64 * multiplicity
        message[i] = _find_peaks(transform) & 0xFF

    return bytes_to_u64_list(bytes(message), params.vec_n1_size_64)
