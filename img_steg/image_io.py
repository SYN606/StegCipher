from PIL import Image
from pathlib import Path


# Lossless formats safe for pixel-domain steganography
LOSSLESS_FORMATS = {
    "PNG",
    "BMP",
    "TIFF",
    "PPM",
    "PGM",
    "WEBP",  # lossless only
}


class ImageFormatError(Exception):
    """Raised when image format is unsupported or unsafe."""
    pass


def load_image(path: str) -> Image.Image:
    """
    Load an image safely for bit-level steganography.

    Guarantees:
    - Lossless format
    - No alpha channel
    - Fully decoded
    - RGB mode
    """

    path = Path(path)

    if not path.exists():
        raise ImageFormatError(f"Image not found: {path}")

    img = Image.open(path)
    img.load()  # force full decode (avoid lazy-load bugs)

    # Pillow format is sometimes None; fall back to extension
    fmt = (img.format or path.suffix.lstrip(".")).upper()

    if fmt not in LOSSLESS_FORMATS:
        raise ImageFormatError(
            f"Unsupported or lossy image format: {fmt}. "
            "Allowed: PNG, BMP, TIFF, PPM, PGM, lossless WebP."
        )

    # Explicit WebP lossless check
    if fmt == "WEBP" and not img.info.get("lossless", False):
        raise ImageFormatError(
            "WebP image is lossy. Use lossless WebP for steganography."
        )

    # Alpha-channel handling (forbidden)
    if img.mode in ("RGBA", "LA"):
        raise ImageFormatError(
            "Alpha-channel images are not supported for steganography"
        )

    # Normalize to RGB
    if img.mode != "RGB":
        img = img.convert("RGB")

    return img


def save_image(img: Image.Image, path: str) -> None:
    """
    Save image losslessly with ALL metadata stripped.

    The saved image is guaranteed to:
    - Be RGB
    - Contain no EXIF / ICC / text chunks
    - Preserve pixel values exactly (lossless)
    """

    path = Path(path)
    ext = path.suffix.lower()

    # Recreate image to strip metadata completely
    clean = Image.new("RGB", img.size)
    clean.putdata(list(img.getdata()))

    if ext == ".png":
        clean.save(
            path,
            format="PNG",
            optimize=False,
        )

    elif ext == ".bmp":
        clean.save(
            path,
            format="BMP",
        )

    elif ext in (".tif", ".tiff"):
        clean.save(
            path,
            format="TIFF",
            compression="raw",
        )

    elif ext == ".webp":
        clean.save(
            path,
            format="WEBP",
            lossless=True,
            quality=100,
            method=6,
        )

    else:
        raise ImageFormatError(
            f"Cannot save image as '{ext}'. "
            "Use png, bmp, tiff, or lossless webp."
        )
