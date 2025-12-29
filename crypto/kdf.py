import os
from typing import Tuple, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_LEN = 32  # AES-256
DEFAULT_SALT_LEN = 16


def _generate_salt(size: int = DEFAULT_SALT_LEN) -> bytes:
    return os.urandom(size)


def derive_key_new(
    password: bytes,
    method: str = "scrypt",
) -> Tuple[bytes, bytes, Dict[str, int | str]]:
    """
    Derive a NEW key (encryption path).
    Generates a fresh random salt.
    """

    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")

    salt = _generate_salt()
    key, params = _derive(password, salt, method)
    return key, salt, params


def derive_key_existing(
    password: bytes,
    salt: bytes,
    params: Dict[str, int | str],
) -> bytes:
    """
    Re-derive an EXISTING key (decryption path).
    Uses stored salt + params.
    """

    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")

    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")

    method = params.get("method")
    key, _ = _derive(password, salt, method, params)  # type: ignore
    return key


def _derive(
    password: bytes,
    salt: bytes,
    method: str,
    params: Dict[str, int | str] | None = None,
) -> Tuple[bytes, Dict[str, int | str]]:
    """
    Internal KDF engine.
    """

    if method == "pbkdf2":
        iterations = params["iterations"] if params else 300_000

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=salt,
            iterations=iterations,  # type: ignore
        )

        out_params = {
            "method": "pbkdf2",
            "iterations": iterations,
        }

    elif method == "scrypt":
        n = params["n"] if params else 2**14
        r = params["r"] if params else 8
        p = params["p"] if params else 1

        kdf = Scrypt(
            salt=salt,
            length=KEY_LEN, n=n,  r=r, p=p, # type: ignore
        )

        out_params = {
            "method": "scrypt",
            "n": n,
            "r": r,
            "p": p,
        }

    else:
        raise ValueError(f"Unsupported KDF method: {method}")

    return kdf.derive(password), out_params
