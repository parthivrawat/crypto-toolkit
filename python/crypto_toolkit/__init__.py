"""Modern Cryptography & Hashing Toolkit for Python.

A misuse-resistant, high-level cryptography library with safe defaults,
constant-time verification, and clear APIs for hashing, password hashing,
key derivation, symmetric encryption, HMAC, and digital signatures.
"""

from . import encrypt, hash, password, sign
from .exceptions import (
    AlgorithmError,
    CryptoKitError,
    DecryptionError,
    InvalidKeyError,
    MissingDependencyError,
    SignatureError,
    VerificationError,
)

__version__ = "1.0.0"

__all__ = [
    "AlgorithmError",
    "CryptoKitError",
    "DecryptionError",
    "InvalidKeyError",
    "MissingDependencyError",
    "SignatureError",
    "VerificationError",
    "__version__",
    "encrypt",
    "hash",
    "password",
    "sign",
]
