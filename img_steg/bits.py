from typing import Iterable, List


def bytes_to_bits(data: bytes) -> List[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    bits = list(bits)
    if len(bits) % 8 != 0:
        raise ValueError("Bit length not multiple of 8")

    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)

    return bytes(out)


def set_lsb(value: int, bit: int) -> int:
    return (value & ~1) | (bit & 1)


def get_lsb(value: int) -> int:
    return value & 1
