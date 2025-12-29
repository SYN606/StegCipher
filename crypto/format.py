import json
import struct
from typing import Tuple, Dict, Any

MAGIC_BYTES = b"SCIF"   # 4 bytes identifier for StegCipher payloads
FORMAT_VERSION = 1


class FormatError(Exception):
    """Raised when payload format is invalid or corrupted."""


def pack_payload(
    encrypted_data: bytes,
    metadata: Dict[str, Any],
) -> bytes:
    """
    Pack encrypted data and metadata into a single byte payload.

    Returns:
        bytes suitable for bit-wise image embedding
    """

    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise TypeError("encrypted_data must be bytes")

    meta_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")

    payload = bytearray()
    payload += MAGIC_BYTES  # 4 bytes
    payload += struct.pack(">B", FORMAT_VERSION)  # 1 byte
    payload += struct.pack(">H", len(meta_bytes))  # 2 bytes
    payload += meta_bytes  # variable
    payload += struct.pack(">I", len(encrypted_data))  # 4 bytes
    payload += encrypted_data  # variable

    return bytes(payload)


def unpack_payload(payload: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """
    Unpack payload extracted from an image.

    Returns:
        encrypted_data, metadata
    """

    try:
        offset = 0

        magic = payload[offset:offset + 4]
        offset += 4
        if magic != MAGIC_BYTES:
            raise FormatError("Invalid magic header")

        version = payload[offset]
        offset += 1
        if version != FORMAT_VERSION:
            raise FormatError(f"Unsupported format version: {version}")

        meta_len = struct.unpack(">H", payload[offset:offset + 2])[0]
        offset += 2

        meta_bytes = payload[offset:offset + meta_len]
        offset += meta_len
        metadata = json.loads(meta_bytes.decode("utf-8"))

        data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4

        encrypted_data = payload[offset:offset + data_len]
        if len(encrypted_data) != data_len:
            raise FormatError("Encrypted data length mismatch")

        return encrypted_data, metadata

    except (IndexError, ValueError, json.JSONDecodeError) as e:
        raise FormatError("Malformed payload") from e
