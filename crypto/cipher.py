from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# AES-GCM parameters
KEY_SIZE = 32  # 256-bit key
NONCE_SIZE = 12  # Recommended for GCM
TAG_SIZE = 16  # 128-bit auth tag (implicit in AESGCM)


class CryptoError(Exception):
    """Raised when encryption or decryption fails."""


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-256-GCM.

    Args:
        plaintext : bytes to encrypt
        key       : 32-byte symmetric key

    Returns:
        bytes: nonce || ciphertext || auth_tag
    """

    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")

    if len(key) != KEY_SIZE:
        raise ValueError("Invalid key length")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    # AESGCM returns ciphertext || tag
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return nonce + ciphertext


def decrypt(encrypted_blob: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.

    Args:
        encrypted_blob : nonce || ciphertext || auth_tag
        key            : 32-byte symmetric key

    Returns:
        bytes: decrypted plaintext

    Raises:
        CryptoError if authentication fails or data is invalid
    """

    if not isinstance(encrypted_blob, (bytes, bytearray)):
        raise TypeError("encrypted_blob must be bytes")

    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")

    if len(key) != KEY_SIZE:
        raise ValueError("Invalid key length")

    if len(encrypted_blob) < NONCE_SIZE + TAG_SIZE:
        raise CryptoError("Encrypted data too short")

    nonce = encrypted_blob[:NONCE_SIZE]
    ciphertext = encrypted_blob[NONCE_SIZE:]

    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        # Covers invalid tag, wrong key, corrupted data
        raise CryptoError("Decryption failed or data tampered") from e
