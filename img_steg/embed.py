from typing import Iterable

from .bits import bytes_to_bits, bits_to_bytes, set_lsb, get_lsb
from .image_io import load_image, save_image


class StegError(Exception):
    """Raised when steganography embedding/extraction fails."""
    pass


def _image_capacity_bits(img) -> int:
    """
    Calculate embedding capacity in bits.
    We use 1 LSB per RGB channel.
    """
    width, height = img.size
    return width * height * 3


def embed_payload(
    input_image: str,
    payload: bytes,
    output_image: str,
) -> None:
    """
    Embed payload bytes into an image using LSB steganography.

    - Lossless images only (enforced by load_image)
    - 1 bit per RGB channel
    """

    img = load_image(input_image)
    pixels = img.load()

    bits = bytes_to_bits(payload)
    capacity = _image_capacity_bits(img)

    if len(bits) > capacity:
        raise StegError(f"Payload too large: need {len(bits)} bits, "
                        f"image supports {capacity} bits")

    width, height = img.size
    bit_index = 0

    for y in range(height):
        for x in range(width):
            if bit_index >= len(bits):
                save_image(img, output_image)
                return

            r, g, b = pixels[x, y]  # type: ignore

            if bit_index < len(bits):
                r = set_lsb(r, bits[bit_index])
                bit_index += 1
            if bit_index < len(bits):
                g = set_lsb(g, bits[bit_index])
                bit_index += 1
            if bit_index < len(bits):
                b = set_lsb(b, bits[bit_index])
                bit_index += 1

            pixels[x, y] = (r, g, b)  # type: ignore

    save_image(img, output_image)


def extract_payload(
    image_path: str,
    payload_size_bytes: int,
) -> bytes:
    """
    Extract payload bytes from an image.

    NOTE:
    - payload_size_bytes must be known
    - higher layers (crypto/format) ensure correctness
    """

    img = load_image(image_path)
    pixels = img.load()

    width, height = img.size
    total_bits_needed = payload_size_bytes * 8
    bits = []

    for y in range(height):
        for x in range(width):
            if len(bits) >= total_bits_needed:
                return bits_to_bytes(bits)

            r, g, b = pixels[x, y]  # type: ignore

            bits.append(get_lsb(r))
            if len(bits) >= total_bits_needed:
                break
            bits.append(get_lsb(g))
            if len(bits) >= total_bits_needed:
                break
            bits.append(get_lsb(b))

    if len(bits) < total_bits_needed:
        raise StegError("Image does not contain enough data")

    return bits_to_bytes(bits)
