"""
Byte and word conversion utilities for HQC.
"""

from typing import List


U64_MASK = (1 << 64) - 1


def bytes_to_u64_list(data: bytes, word_count: int) -> List[int]:
    """Convert little-endian bytes into a list of 64-bit words."""
    total_len = word_count * 8
    if len(data) < total_len:
        data = data + b"\x00" * (total_len - len(data))
    words = []
    for i in range(word_count):
        chunk = data[i * 8 : (i + 1) * 8]
        words.append(int.from_bytes(chunk, "little") & U64_MASK)
    return words


def u64_list_to_bytes(words: List[int], byte_len: int) -> bytes:
    """Convert a list of 64-bit words into little-endian bytes."""
    out = bytearray()
    for word in words:
        out.extend((word & U64_MASK).to_bytes(8, "little"))
    return bytes(out[:byte_len])


def bytes_to_u32_list(data: bytes, word_count: int) -> List[int]:
    """Convert little-endian bytes into a list of 32-bit words."""
    total_len = word_count * 4
    if len(data) < total_len:
        data = data + b"\x00" * (total_len - len(data))
    words = []
    for i in range(word_count):
        chunk = data[i * 4 : (i + 1) * 4]
        words.append(int.from_bytes(chunk, "little") & 0xFFFFFFFF)
    return words


def u32_list_to_bytes(words: List[int], byte_len: int) -> bytes:
    """Convert a list of 32-bit words into little-endian bytes."""
    out = bytearray()
    for word in words:
        out.extend((word & 0xFFFFFFFF).to_bytes(4, "little"))
    return bytes(out[:byte_len])
