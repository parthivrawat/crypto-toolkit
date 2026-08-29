"""Password hashing, verification, and key derivation with safe defaults."""

import base64
import hashlib
import hmac as _hmac
import secrets
from typing import Any, Optional, Union

from .exceptions import AlgorithmError, MissingDependencyError, VerificationError

try:
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2 import Type as _Argon2Type

    _HAS_ARGON2 = True
except Exception:  # pragma: no cover
    _HAS_ARGON2 = False

try:
    import bcrypt as _bcrypt

    _HAS_BCRYPT = True
except Exception:  # pragma: no cover
    _HAS_BCRYPT = False

_ALLOWED = frozenset({"argon2id", "scrypt", "bcrypt", "pbkdf2_sha256"})


def _scrypt_available() -> bool:
    try:
        hashlib.scrypt(b"", salt=b"", n=2, r=1, p=1, dklen=1, maxmem=1024)
        return True
    except Exception:
        return False


_SCRYPT_AVAILABLE = _scrypt_available()

_DEFAULT = (
    "argon2id"
    if _HAS_ARGON2
    else ("scrypt" if _SCRYPT_AVAILABLE else "pbkdf2_sha256")
)


def _to_bytes(value: Union[str, bytes]) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def _parse_pbkdf2(hashed: str):
    try:
        _, iterations, salt_b64, key_b64 = hashed.split("$")
        return int(iterations), base64.b64decode(salt_b64), base64.b64decode(key_b64)
    except Exception as exc:
        raise VerificationError("Invalid PBKDF2 hash format") from exc


def _parse_scrypt(hashed: str):
    try:
        _, n, r, p, salt_b64, key_b64 = hashed.split("$")
        return (
            int(n),
            int(r),
            int(p),
            base64.b64decode(salt_b64),
            base64.b64decode(key_b64),
        )
    except Exception as exc:
        raise VerificationError("Invalid scrypt hash format") from exc


def hash(password: str, algorithm: Optional[str] = None, **params: Any) -> str:
    """Hash a password with the strongest available algorithm by default."""
    algo = algorithm or _DEFAULT
    if algo not in _ALLOWED:
        raise AlgorithmError(f"Unsupported password algorithm: {algo}")

    if algo == "argon2id":
        if not _HAS_ARGON2:
            raise MissingDependencyError(
                "Argon2id requires argon2-cffi. Install: pip install 'crypto-toolkit-py[argon2]'"
            )
        ph = _Argon2Hasher(
            time_cost=params.get("time_cost", 3),
            memory_cost=params.get("memory_cost", 65536),
            parallelism=params.get("parallelism", 4),
            type=_Argon2Type.ID,
        )
        return ph.hash(password)

    if algo == "bcrypt":
        if not _HAS_BCRYPT:
            raise MissingDependencyError(
                "bcrypt requires the bcrypt package. Install: pip install 'crypto-toolkit-py[bcrypt]'"
            )
        salt = _bcrypt.gensalt(rounds=params.get("rounds", 12))
        return _bcrypt.hashpw(password.encode(), salt).decode("ascii")

    if algo == "scrypt":
        if not _SCRYPT_AVAILABLE:
            raise MissingDependencyError("scrypt is not available on this platform")
        salt = secrets.token_bytes(32)
        n = params.get("n", 16384)
        r = params.get("r", 8)
        p = params.get("p", 1)
        dklen = params.get("dklen", 64)
        key = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=dklen,
            maxmem=params.get("maxmem", 0),
        )
        return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"

    # pbkdf2_sha256
    iterations = params.get("iterations", 100_000)
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"


def verify(password: str, hashed: str) -> bool:
    """Verify a password against a hash in constant time."""
    try:
        if hashed.startswith("$argon2id$"):
            if not _HAS_ARGON2:
                return False
            ph = _Argon2Hasher()
            ph.verify(hashed, password)
            return True

        if hashed.startswith("$2") and len(hashed) >= 59:
            if not _HAS_BCRYPT:
                return False
            return _bcrypt.checkpw(password.encode(), hashed.encode())

        if hashed.startswith("scrypt$"):
            if not _SCRYPT_AVAILABLE:
                return False
            n, r, p, salt, stored_key = _parse_scrypt(hashed)
            candidate = hashlib.scrypt(
                password.encode(),
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=len(stored_key),
                maxmem=0,
            )
            return _hmac.compare_digest(candidate, stored_key)

        if hashed.startswith("pbkdf2_sha256$"):
            iterations, salt, stored_key = _parse_pbkdf2(hashed)
            candidate = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt,
                iterations,
                dklen=len(stored_key),
            )
            return _hmac.compare_digest(candidate, stored_key)
    except Exception:
        return False

    return False


def derive(
    passphrase: Union[str, bytes],
    salt: Optional[bytes] = None,
    length: int = 32,
    algorithm: str = "pbkdf2_sha256",
    **params: Any,
) -> bytes:
    """Derive a key from a passphrase and salt."""
    if salt is None:
        raise AlgorithmError("A non-None salt is required for deterministic key derivation")
    if length < 1:
        raise AlgorithmError("length must be a positive integer")

    p = _to_bytes(passphrase)

    if algorithm == "pbkdf2_sha256":
        iterations = params.get("iterations", 100_000)
        return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, dklen=length)

    if algorithm == "scrypt":
        if not _SCRYPT_AVAILABLE:
            raise MissingDependencyError("scrypt is not available on this platform")
        return hashlib.scrypt(
            p,
            salt=salt,
            n=params.get("n", 16384),
            r=params.get("r", 8),
            p=params.get("p", 1),
            dklen=length,
            maxmem=params.get("maxmem", 0),
        )

    raise AlgorithmError(f"Unsupported key derivation algorithm: {algorithm}")
