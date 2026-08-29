"""Deterministic hashing and HMAC with safe, modern defaults."""

import hashlib
import hmac as _hmac
from pathlib import Path
from typing import Union

from .exceptions import AlgorithmError

_ALLOWED_HASH = frozenset(
    {
        "sha-256",
        "sha-384",
        "sha-512",
        "sha3-256",
        "sha3-384",
        "sha3-512",
        "blake2b",
        "blake2s",
    }
)

_HASHLIB_NAME = {
    "sha-256": "sha256",
    "sha-384": "sha384",
    "sha-512": "sha512",
    "sha3-256": "sha3_256",
    "sha3-384": "sha3_384",
    "sha3-512": "sha3_512",
    "blake2b": "blake2b",
    "blake2s": "blake2s",
}


def _normalize(algorithm: str) -> str:
    name = algorithm.lower().replace("_", "-")
    if name not in _ALLOWED_HASH:
        raise AlgorithmError(f"Unsupported or unsafe hashing algorithm: {algorithm}")
    return _HASHLIB_NAME[name]


def _to_bytes(data: Union[str, bytes]) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else data


def string(data: Union[str, bytes], algorithm: str = "sha-256") -> str:
    """Return a safe, deterministic hash of ``data`` as a hex string."""
    digestmod = _normalize(algorithm)
    return hashlib.new(digestmod, _to_bytes(data)).hexdigest()


def file(path: Union[str, Path], algorithm: str = "sha-256", block_size: int = 8192) -> str:
    """Return the hash of a file as a hex string."""
    digestmod = _normalize(algorithm)
    h = hashlib.new(digestmod)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()


def hmac(key: Union[str, bytes], data: Union[str, bytes], algorithm: str = "sha-256") -> str:
    """Return an HMAC of ``data`` as a hex string."""
    digestmod = _normalize(algorithm)
    mac = _hmac.new(_to_bytes(key), _to_bytes(data), digestmod)
    return mac.hexdigest()


def verify_hmac(mac: str, key: Union[str, bytes], data: Union[str, bytes], algorithm: str = "sha-256") -> bool:
    """Verify an HMAC in constant time."""
    expected = hmac(key, data, algorithm)
    return _hmac.compare_digest(mac, expected)
