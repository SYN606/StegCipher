from typing import Dict, Any

from crypto.kdf import derive_key_new, derive_key_existing
from crypto.cipher import encrypt, decrypt, CryptoError
from crypto.format import pack_payload, unpack_payload, FormatError


class StegCipherError(Exception):
    """High-level StegCipher error."""


def encrypt_for_steg(
    plaintext: bytes,
    password: bytes,
    *,
    kdf_method: str = "scrypt",
) -> bytes:
    """
    Encrypt plaintext and prepare payload for image steganography.
    """

    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")

    # 1. Derive NEW key (encryption path)
    key, salt, kdf_params = derive_key_new(password, method=kdf_method)

    # 2. Encrypt plaintext
    encrypted_data = encrypt(plaintext, key)

    # 3. Metadata stored inside payload
    metadata: Dict[str, Any] = {
        "kdf": kdf_params,
        "salt": salt.hex(),
        "cipher": "AES-256-GCM",
    }

    # 4. Pack into binary payload
    return pack_payload(encrypted_data, metadata)


def decrypt_from_steg(
    payload: bytes,
    password: bytes,
) -> bytes:
    """
    Decrypt payload extracted from an image.
    """

    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")

    try:
        encrypted_data, metadata = unpack_payload(payload)

        kdf_params = metadata["kdf"]
        salt = bytes.fromhex(metadata["salt"])

        key = derive_key_existing(password, salt, kdf_params)

        return decrypt(encrypted_data, key)

    except (KeyError, ValueError) as e:
        raise StegCipherError("Invalid or missing metadata") from e
    except (CryptoError, FormatError) as e:
        raise StegCipherError("Decryption failed") from e
