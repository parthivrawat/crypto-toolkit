"""Exceptions raised by the crypto toolkit."""


class CryptoKitError(Exception):
    """Base exception for the crypto toolkit."""


class AlgorithmError(CryptoKitError):
    """Raised when an invalid or unsafe algorithm is requested."""


class InvalidKeyError(CryptoKitError):
    """Raised when a key is malformed or has an incorrect length."""


class DecryptionError(CryptoKitError):
    """Raised when decryption or authentication fails."""


class SignatureError(CryptoKitError):
    """Raised when a signature operation fails."""


class MissingDependencyError(CryptoKitError):
    """Raised when an optional dependency is required but not installed."""


class VerificationError(CryptoKitError):
    """Raised when a password hash format is malformed."""
