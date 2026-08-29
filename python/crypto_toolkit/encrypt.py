"""Symmetric AEAD encryption with safe, modern defaults."""

import secrets
from typing import Optional, Union

from .exceptions import AlgorithmError, DecryptionError, InvalidKeyError, MissingDependencyError

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False

_VERSION = 1

_ALGORITHMS: dict = {}
if _HAS_CRYPTOGRAPHY:
    _ALGORITHMS = {
        "aes-256-gcm": {
            "id": 1,
            "key_len": 32,
            "nonce_len": 12,
            "cipher_cls": AESGCM,
        },
        "chacha20-poly1305": {
            "id": 2,
            "key_len": 32,
            "nonce_len": 12,
            "cipher_cls": ChaCha20Poly1305,
        },
    }

_ALGO_BY_ID = {v["id"]: k for k, v in _ALGORITHMS.items()}


def _require_crypto():
    if not _HAS_CRYPTOGRAPHY:
        raise MissingDependencyError(
            "AEAD encryption requires cryptography. Install: pip install 'crypto-toolkit-py[crypto]'"
        )


def _load_algorithm(algorithm: str) -> dict:
    try:
        return _ALGORITHMS[algorithm]
    except KeyError:
        raise AlgorithmError(f"Unsupported cipher: {algorithm}")


def _make_cipher(algorithm: str, key: bytes):
    spec = _load_algorithm(algorithm)
    if len(key) != spec["key_len"]:
        raise InvalidKeyError(f"{algorithm} requires a {spec['key_len']}-byte key")
    return spec["cipher_cls"](key)


def symmetric(data: Union[str, bytes], key: bytes, algorithm: str = "aes-256-gcm") -> bytes:
    """Encrypt ``data`` with an AEAD cipher using a versioned header."""
    _require_crypto()
    if isinstance(data, str):
        data = data.encode("utf-8")

    spec = _load_algorithm(algorithm)
    cipher = _make_cipher(algorithm, key)
    nonce = secrets.token_bytes(spec["nonce_len"])
    ciphertext = cipher.encrypt(nonce, data, None)
    return bytes([_VERSION, spec["id"]]) + nonce + ciphertext


def decrypt(token: bytes, key: bytes, encoding: Optional[str] = "utf-8") -> Union[str, bytes]:
    """Decrypt and authenticate a token produced by ``symmetric``."""
    _require_crypto()
    if len(token) < 2:
        raise DecryptionError("Ciphertext too short")

    version = token[0]
    if version != _VERSION:
        raise DecryptionError(f"Unsupported ciphertext version: {version}")

    algo_id = token[1]
    algorithm = _ALGO_BY_ID.get(algo_id)
    if algorithm is None:
        raise DecryptionError(f"Unknown algorithm id: {algo_id}")

    spec = _load_algorithm(algorithm)
    if len(key) != spec["key_len"]:
        raise InvalidKeyError(f"{algorithm} requires a {spec['key_len']}-byte key")

    nonce_len = spec["nonce_len"]
    if len(token) < 2 + nonce_len + 16:
        raise DecryptionError("Ciphertext too short")

    nonce = token[2 : 2 + nonce_len]
    ciphertext = token[2 + nonce_len :]
    cipher = _make_cipher(algorithm, key)

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise DecryptionError("Decryption or authentication failed") from exc

    if encoding:
        try:
            return plaintext.decode(encoding)
        except UnicodeDecodeError:
            return plaintext
    return plaintext
