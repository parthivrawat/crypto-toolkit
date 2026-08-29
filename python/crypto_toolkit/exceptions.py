"""Exceptions raised by the crypto toolkit."""


class CryptoKitError(Exception):
    """Base exception for the crypto toolkit."""
    pass


class AlgorithmError(CryptoKitError):
    """Raised when an invalid or unsafe algorithm is requested."""
    pass


class InvalidKeyError(CryptoKitError):
    """Raised when a key is malformed or has an incorrect length."""
    pass


class DecryptionError(CryptoKitError):
    """Raised when decryption or authentication fails."""
    pass


class SignatureError(CryptoKitError):
    """Raised when a signature operation fails."""
    pass


class MissingDependencyError(CryptoKitError):
    """Raised when an optional dependency is required but not installed."""
    pass


class VerificationError(CryptoKitError):
    """Raised when a password hash format is malformed."""
    pass
