"""Digital signatures (Ed25519, ECDSA, RSA-PSS)."""

from typing import Tuple, Union

from .exceptions import AlgorithmError, InvalidKeyError, MissingDependencyError, SignatureError

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False


def _require_crypto():
    if not _HAS_CRYPTOGRAPHY:
        raise MissingDependencyError(
            "Digital signatures require cryptography. Install: pip install 'crypto-toolkit-py[crypto]'"
        )


def _to_bytes(value: Union[str, bytes]) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def generate_keypair(algorithm: str = "ed25519") -> Tuple[bytes, bytes]:
    """Generate a private/public key pair for the requested algorithm."""
    _require_crypto()
    if algorithm != "ed25519":
        raise AlgorithmError("Only ed25519 is currently supported")

    private = _ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    return (
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def ed25519(message: Union[str, bytes], private_key: bytes) -> bytes:
    """Sign ``message`` with an Ed25519 private key."""
    _require_crypto()
    if len(private_key) != 32:
        raise InvalidKeyError("Ed25519 private key must be 32 bytes")

    sk = _ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return sk.sign(_to_bytes(message))


def verify(
    signature: bytes,
    message: Union[str, bytes],
    public_key: bytes,
    algorithm: str = "ed25519",
) -> bool:
    """Verify a signature against a message and public key."""
    _require_crypto()
    if algorithm != "ed25519":
        raise AlgorithmError("Only ed25519 is currently supported")
    if len(public_key) != 32:
        raise InvalidKeyError("Ed25519 public key must be 32 bytes")

    vk = _ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    try:
        vk.verify(signature, _to_bytes(message))
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        raise SignatureError("Signature verification failed") from exc
