from typing import Dict, Any

from crypto.kdf import derive_key_new, derive_key_existing
from crypto.cipher import encrypt, decrypt, CryptoError
from crypto.format import pack_payload, unpack_payload, FormatError


class StegCipherError(Exception):
    """High-level StegCipher error."""
    pass


def encrypt_for_steg(
    plaintext: bytes,
    password: bytes,
    *,
    kdf_method: str = "scrypt",
) -> bytes:
    """
    Encrypt plaintext and return a binary payload
    suitable for image steganography.
    """

    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")

    # Derive a fresh key (encryption path)
    key, salt, kdf_params = derive_key_new(password, method=kdf_method)

    # Encrypt (AEAD)
    encrypted_data = encrypt(plaintext, key)

    # Metadata embedded inside the payload
    metadata: Dict[str, Any] = {
        "kdf": kdf_params,
        "salt": salt.hex(),
        "cipher": "AES-256-GCM",
        "version": 1,  # protocol versioning (future-proofing)
    }

    return pack_payload(encrypted_data, metadata)


def decrypt_from_steg(
    payload: bytes,
    password: bytes,
) -> bytes:
    """
    Decrypt payload extracted from an image
    and return the original plaintext.
    """

    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")

    try:
        encrypted_data, metadata = unpack_payload(payload)

        # Mandatory metadata checks
        if "kdf" not in metadata or "salt" not in metadata:
            raise StegCipherError("Missing required metadata fields")

        kdf_params = metadata["kdf"]
        salt = bytes.fromhex(metadata["salt"])

        # Re-derive existing key (decryption path)
        key = derive_key_existing(password, salt, kdf_params)

        return decrypt(encrypted_data, key)

    except (KeyError, ValueError) as e:
        raise StegCipherError("Invalid or corrupted payload metadata") from e

    except (CryptoError, FormatError) as e:
        raise StegCipherError("Decryption failed") from e
