"""Digital signatures (Ed25519)."""

from typing import Tuple, Union

from .exceptions import AlgorithmError, InvalidKeyError, MissingDependencyError, SignatureError

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False


def _require_crypto() -> None:
    if not _HAS_CRYPTOGRAPHY:
        raise MissingDependencyError(
            "Digital signatures require cryptography. Install: pip install 'crypto-toolkit-py[crypto]'"
        )


def _to_bytes(value: Union[str, bytes]) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def generate_keypair(algorithm: str = "ed25519") -> Tuple[bytes, bytes]:
    """Generate a 32-byte private/public key pair for the requested algorithm."""
    _require_crypto()
    if algorithm != "ed25519":
        raise AlgorithmError("Only ed25519 is currently supported")

    private = _ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def ed25519(message: Union[str, bytes], private_key: bytes) -> bytes:
    """Sign ``message`` with an Ed25519 private key."""
    _require_crypto()
    if len(private_key) != 32:
        raise InvalidKeyError("Ed25519 private key must be 32 bytes")

    sk = _ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return sk.sign(_to_bytes(message))


def sign(message: Union[str, bytes], private_key: bytes) -> bytes:
    """Alias for ``ed25519``."""
    return ed25519(message, private_key)


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


def private_key_to_pem(private_key: bytes) -> str:
    """Serialize a 32-byte Ed25519 private key to PEM (PKCS#8)."""
    _require_crypto()
    if len(private_key) != 32:
        raise InvalidKeyError("Ed25519 private key must be 32 bytes")
    sk = _ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def private_key_from_pem(pem: str) -> bytes:
    """Load an Ed25519 private key from PEM (PKCS#8) and return 32 raw bytes."""
    _require_crypto()
    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    except Exception as exc:
        raise InvalidKeyError("Unable to load Ed25519 private key from PEM") from exc

    if not isinstance(key, _ed25519.Ed25519PrivateKey):
        raise InvalidKeyError("PEM does not contain an Ed25519 private key")
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: bytes) -> str:
    """Serialize a 32-byte Ed25519 public key to PEM (SPKI)."""
    _require_crypto()
    if len(public_key) != 32:
        raise InvalidKeyError("Ed25519 public key must be 32 bytes")
    vk = _ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    return vk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_pem(pem: str) -> bytes:
    """Load an Ed25519 public key from PEM (SPKI) and return 32 raw bytes."""
    _require_crypto()
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except Exception as exc:
        raise InvalidKeyError("Unable to load Ed25519 public key from PEM") from exc

    if not isinstance(key, _ed25519.Ed25519PublicKey):
        raise InvalidKeyError("PEM does not contain an Ed25519 public key")
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
