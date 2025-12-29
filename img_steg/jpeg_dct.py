import numpy as np
from scipy.fftpack import dct, idct
from PIL import Image
from pathlib import Path


class JpegStegError(Exception):
    pass


# Mid-frequency AC positions (safe defaults)
MID_FREQ_POSITIONS = [
    (2, 1),
    (1, 2),
    (2, 2),
    (3, 1),
    (1, 3),
]


def _block_dct(block: np.ndarray) -> np.ndarray:
    return dct(dct(block.T, norm="ortho").T, norm="ortho")


def _block_idct(block: np.ndarray) -> np.ndarray:
    return idct(idct(block.T, norm="ortho").T, norm="ortho")


def embed_jpeg(
    payload_bits: list[int],
    image_path: str,
    output_path: str,
) -> None:
    """
    Embed payload bits into a JPEG/JPG image using DCT-domain steganography.
    """

    image_path = Path(image_path)
    output_path = Path(output_path)

    if image_path.suffix.lower() not in (".jpg", ".jpeg"):
        raise JpegStegError("Input image must be .jpg or .jpeg")

    # Load image and convert to grayscale (Y channel)
    img = Image.open(image_path).convert("L")
    arr = np.array(img, dtype=np.float32)

    height, width = arr.shape
    bit_idx = 0

    # Process 8x8 blocks
    for y in range(0, height - 7, 8):
        for x in range(0, width - 7, 8):
            if bit_idx >= len(payload_bits):
                break

            block = arr[y:y + 8, x:x + 8] - 128.0
            coeffs = _block_dct(block)

            for i, j in MID_FREQ_POSITIONS:
                if bit_idx >= len(payload_bits):
                    break

                c = coeffs[i, j]

                # Skip zero or near-zero coefficients
                if abs(c) < 1:
                    continue

                bit = payload_bits[bit_idx]
                rounded = int(np.round(c))

                # Adjust parity safely
                if (rounded & 1) != bit:
                    coeffs[i, j] = rounded + 1 if rounded > 0 else rounded - 1

                bit_idx += 1

            arr[y:y + 8, x:x + 8] = _block_idct(coeffs) + 128.0

    if bit_idx < len(payload_bits):
        raise JpegStegError("Image capacity insufficient for payload")

    out = Image.fromarray(
        np.clip(arr, 0, 255).astype(np.uint8)
    )

    out.save(
        output_path,
        format="JPEG",
        quality=95,
        subsampling=0,
        optimize=False,
    )
