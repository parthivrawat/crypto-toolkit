"""Symmetric AEAD encryption with safe, modern defaults."""

from __future__ import annotations

import secrets
import struct
from typing import Any

from .exceptions import (
    AlgorithmError,
    DecryptionError,
    InvalidKeyError,
    MissingDependencyError,
)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False

_VERSION = 2

_ALGORITHMS: dict[str, dict[str, Any]] = {}
if _HAS_CRYPTOGRAPHY:
    _ALGORITHMS = {
        "aes-256-gcm": {
            "id": 1,
            "key_len": 32,
            "nonce_len": 12,
            "tag_len": 16,
            "cipher_cls": AESGCM,
        },
        "chacha20-poly1305": {
            "id": 2,
            "key_len": 32,
            "nonce_len": 12,
            "tag_len": 16,
            "cipher_cls": ChaCha20Poly1305,
        },
    }

_ALGO_BY_ID = {v["id"]: k for k, v in _ALGORITHMS.items()}


def _require_crypto() -> None:
    if not _HAS_CRYPTOGRAPHY:
        raise MissingDependencyError(
            "AEAD encryption requires cryptography. Install: pip install 'crypto-toolkit-py[crypto]'"
        )


def _normalize_algorithm(algorithm: str) -> str:
    return algorithm.lower().replace("_", "-")


def _load_algorithm(algorithm: str) -> dict[str, Any]:
    name = _normalize_algorithm(algorithm)
    try:
        return _ALGORITHMS[name]
    except KeyError:
        raise AlgorithmError(f"Unsupported cipher: {algorithm}")


def _make_cipher(algorithm: str, key: bytes) -> Any:
    spec = _load_algorithm(algorithm)
    if len(key) != spec["key_len"]:
        raise InvalidKeyError(f"{algorithm} requires a {spec['key_len']}-byte key")
    return spec["cipher_cls"](key)


def _build_aad(version: int, algorithm_id: int, aad: bytes | None, nonce: bytes) -> bytes:
    aad = aad or b""
    return (
        bytes([version, algorithm_id])
        + struct.pack(">H", len(aad))
        + aad
        + nonce
    )


def _to_bytes(data: str | bytes) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else data


def encrypt(
    data: str | bytes,
    key: bytes,
    aad: bytes | None = None,
    algorithm: str = "aes-256-gcm",
) -> bytes:
    """Encrypt ``data`` with an AEAD cipher using a versioned v2 header."""
    _require_crypto()
    plaintext = _to_bytes(data)
    spec = _load_algorithm(algorithm)
    cipher = _make_cipher(algorithm, key)
    nonce = secrets.token_bytes(spec["nonce_len"])
    aad_for_cipher = _build_aad(_VERSION, spec["id"], aad, nonce)
    ciphertext: bytes = cipher.encrypt(nonce, plaintext, aad_for_cipher)
    user_aad = aad or b""
    return (
        bytes([_VERSION, spec["id"]])
        + struct.pack(">H", len(user_aad))
        + user_aad
        + nonce
        + ciphertext
    )


def decrypt(
    token: bytes,
    key: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate a token produced by ``encrypt``."""
    _require_crypto()
    if len(token) < 2:
        raise DecryptionError("Ciphertext too short")

    version = token[0]

    if version == _VERSION:
        return _decrypt_v2(token, key, aad)
    if version == 1:
        return _decrypt_v1(token, key, aad)

    raise DecryptionError(f"Unsupported ciphertext version: {version}")


def _decrypt_v2(token: bytes, key: bytes, aad: bytes | None) -> bytes:
    if len(token) < 4:
        raise DecryptionError("Ciphertext too short")

    algo_id = token[1]
    aad_len = struct.unpack(">H", token[2:4])[0]
    aad_start = 4
    expected_aad_end = aad_start + aad_len

    if len(token) < expected_aad_end:
        raise DecryptionError("Ciphertext too short")

    stored_aad = token[aad_start:expected_aad_end]
    if (aad or b"") != stored_aad:
        raise DecryptionError("Additional authenticated data does not match")

    algorithm = _ALGO_BY_ID.get(algo_id)
    if algorithm is None:
        raise DecryptionError(f"Unknown algorithm id: {algo_id}")

    spec = _load_algorithm(algorithm)
    if len(key) != spec["key_len"]:
        raise InvalidKeyError(f"{algorithm} requires a {spec['key_len']}-byte key")

    nonce_start = expected_aad_end
    nonce_end = nonce_start + spec["nonce_len"]
    if len(token) < nonce_end + spec["tag_len"]:
        raise DecryptionError("Ciphertext too short")

    nonce = token[nonce_start:nonce_end]
    sealed = token[nonce_end:]
    aad_for_cipher = _build_aad(token[0], algo_id, stored_aad, nonce)
    cipher = spec["cipher_cls"](key)

    try:
        plaintext: bytes = cipher.decrypt(nonce, sealed, aad_for_cipher)
        return plaintext
    except Exception as exc:
        raise DecryptionError("Decryption or authentication failed") from exc


def _decrypt_v1(token: bytes, key: bytes, aad: bytes | None) -> bytes:
    if aad is not None and aad != b"":
        raise DecryptionError("v1 ciphertext does not support additional authenticated data")

    algo_id = token[1]
    algorithm = _ALGO_BY_ID.get(algo_id)
    if algorithm is None:
        raise DecryptionError(f"Unknown algorithm id: {algo_id}")

    spec = _load_algorithm(algorithm)
    if len(key) != spec["key_len"]:
        raise InvalidKeyError(f"{algorithm} requires a {spec['key_len']}-byte key")

    nonce = token[2 : 2 + spec["nonce_len"]]
    sealed = token[2 + spec["nonce_len"] :]
    if len(sealed) < spec["tag_len"]:
        raise DecryptionError("Ciphertext too short")

    cipher = spec["cipher_cls"](key)
    try:
        plaintext: bytes = cipher.decrypt(nonce, sealed, None)
        return plaintext
    except Exception as exc:
        raise DecryptionError("Decryption or authentication failed") from exc


def encrypt_string(
    plaintext: str,
    key: bytes,
    aad: bytes | None = None,
    algorithm: str = "aes-256-gcm",
) -> bytes:
    """Encrypt a UTF-8 string and return a v2 token."""
    return encrypt(plaintext.encode("utf-8"), key, aad, algorithm)


def decrypt_string(
    token: bytes,
    key: bytes,
    aad: bytes | None = None,
    encoding: str = "utf-8",
) -> str:
    """Decrypt a v2 token and decode the plaintext as a string."""
    plaintext = decrypt(token, key, aad)
    try:
        return plaintext.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ValueError(f"Plaintext is not valid {encoding} data") from exc


def symmetric(
    data: str | bytes,
    key: bytes,
    algorithm: str = "aes-256-gcm",
) -> bytes:
    """Deprecated compatibility alias for ``encrypt`` without user AAD."""
    return encrypt(data, key, None, algorithm)
