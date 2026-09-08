"""Password hashing, verification, and key derivation with safe defaults."""

import base64
import hashlib
import hmac as _hmac
import logging
import math
import secrets
from typing import Any, Dict, Optional, TypedDict, Union

from .exceptions import AlgorithmError, InvalidKeyError, MissingDependencyError

_logger = logging.getLogger(__name__)


class HashOptions(TypedDict, total=False):
    """Typed options for password hashing and key derivation.

    Every field is optional; algorithm defaults are applied for missing keys.
    Only the fields relevant to the selected algorithm are used.

    - ``iterations``: PBKDF2 iteration count
    - ``time_cost``: Argon2 time cost
    - ``memory_cost``: Argon2 memory cost in KiB
    - ``parallelism``: Argon2 lanes
    - ``dklen``: derived key length in bytes
    - ``n``, ``r``, ``p``, ``maxmem``: scrypt parameters
    - ``rounds``: bcrypt cost factor
    """

    iterations: int
    time_cost: int
    memory_cost: int
    parallelism: int
    dklen: int
    n: int
    r: int
    p: int
    maxmem: int
    rounds: int

try:
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2 import Type as _Argon2Type
    import argon2.low_level as _Argon2LowLevel

    _HAS_ARGON2 = True
except Exception:  # pragma: no cover
    _HAS_ARGON2 = False

try:
    import bcrypt as _bcrypt

    _HAS_BCRYPT = True
except Exception:  # pragma: no cover
    _HAS_BCRYPT = False

_ALLOWED = frozenset({"argon2id", "scrypt", "bcrypt", "pbkdf2_sha256"})


_PBALG_ALLOWED = frozenset({"argon2id", "scrypt", "pbkdf2_sha256"})


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


def _phc_b64_encode(data: bytes) -> str:
    """Base64 without padding/whitespace (PHC)."""
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _phc_b64_decode(text: str) -> bytes:
    """Decode PHC Base64 (no padding)."""
    b = text.encode("ascii")
    pad = (-len(b) % 4)
    return base64.b64decode(b + b"=" * pad, validate=True)


def _ab64_encode(data: bytes) -> str:
    """Passlib ab64: standard Base64, then + -> ., strip =."""
    return base64.b64encode(data).decode("ascii").replace("+", ".").rstrip("=")


def _ab64_decode(text: str) -> bytes:
    """Decode Passlib ab64: . -> +, re-pad."""
    s = text.replace(".", "+")
    pad = (-len(s) % 4)
    return base64.b64decode(s + "=" * pad, validate=True)


def _default_options(algorithm: str) -> Dict[str, Any]:
    algorithm = algorithm.lower()
    if algorithm == "argon2id":
        return {"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "dklen": 32}
    if algorithm == "scrypt":
        return {"n": 16384, "r": 8, "p": 1, "dklen": 32, "maxmem": 64 * 1024 * 1024}
    if algorithm == "pbkdf2_sha256":
        return {"iterations": 100_000, "dklen": 32}
    if algorithm == "bcrypt":
        return {"rounds": 12}
    raise AlgorithmError(f"Unsupported password algorithm: {algorithm}")


def _resolve_options(
    algorithm: str,
    options: Optional[HashOptions] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resolved = _default_options(algorithm)
    if options:
        resolved.update(options)
    if params:
        resolved.update(params)
    return resolved


def _normalize(algorithm: Optional[str]) -> str:
    return (algorithm or _DEFAULT).lower().replace("-", "_")


def hash(
    password: str,
    algorithm: Optional[str] = None,
    options: Optional[HashOptions] = None,
    **params: Any,
) -> str:
    """Hash a password with the strongest available algorithm by default.

    Cost parameters may be supplied either as a typed ``HashOptions`` dict via
    ``options`` or as keyword ``params`` (keyword arguments take precedence).
    """
    algo = _normalize(algorithm)
    if algo not in _ALLOWED:
        raise AlgorithmError(f"Unsupported password algorithm: {algo}")
    return _hash_algorithm(password, algo, _resolve_options(algo, options, params))


def hash_with(
    password: str,
    algorithm: str,
    options: Optional[HashOptions] = None,
    **params: Any,
) -> str:
    """Explicitly hash a password with the chosen algorithm."""
    return hash(password, algorithm, options, **params)


def _hash_algorithm(password: str, algorithm: str, options: Dict[str, Any]) -> str:
    p = _to_bytes(password)

    if algorithm == "argon2id":
        if not _HAS_ARGON2:
            raise MissingDependencyError(
                "Argon2id requires argon2-cffi. Install: pip install 'crypto-toolkit-py[argon2]'"
            )
        ph = _Argon2Hasher(
            time_cost=options["time_cost"],
            memory_cost=options["memory_cost"],
            parallelism=options["parallelism"],
            hash_len=options["dklen"],
            type=_Argon2Type.ID,
        )
        return ph.hash(password)

    if algorithm == "bcrypt":
        if not _HAS_BCRYPT:
            raise MissingDependencyError(
                "bcrypt requires the bcrypt package. Install: pip install 'crypto-toolkit-py[bcrypt]'"
            )
        salt = _bcrypt.gensalt(rounds=options["rounds"])
        return _bcrypt.hashpw(p, salt).decode("ascii")

    if algorithm == "scrypt":
        if not _SCRYPT_AVAILABLE:
            raise MissingDependencyError("scrypt is not available on this platform")
        salt = secrets.token_bytes(32)
        n = options["n"]
        r = options["r"]
        p_cost = options["p"]
        dklen = options["dklen"]
        maxmem = options.get("maxmem", 64 * 1024 * 1024)
        ln = int(math.log2(n))
        if 2 ** ln != n:
            raise AlgorithmError("scrypt N must be a power of two")
        key = hashlib.scrypt(p, salt=salt, n=n, r=r, p=p_cost, dklen=dklen, maxmem=maxmem)
        return (
            f"$scrypt$ln={ln},r={r},p={p_cost}$"
            f"{_phc_b64_encode(salt)}$"
            f"{_phc_b64_encode(key)}"
        )

    # pbkdf2_sha256
    iterations = options["iterations"]
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac("sha256", p, salt, iterations, dklen=options["dklen"])
    return (
        f"$pbkdf2-sha256${iterations}$"
        f"{_ab64_encode(salt)}$"
        f"{_ab64_encode(key)}"
    )


def verify(password: str, hashed: str) -> bool:
    """Verify a password against a hash in constant time."""
    try:
        if hashed.startswith("$argon2id$"):
            if not _HAS_ARGON2:
                return False
            _Argon2Hasher().verify(hashed, password)
            return True

        if hashed.startswith("$2") and len(hashed) >= 59:
            if not _HAS_BCRYPT:
                return False
            return _bcrypt.checkpw(password.encode(), hashed.encode())

        if hashed.startswith("$scrypt$"):
            if not _SCRYPT_AVAILABLE:
                return False
            parts = hashed.split("$")
            params = parts[2]
            salt_b64 = parts[3]
            key_b64 = parts[4]
            pairs = dict(p.split("=") for p in params.split(","))
            ln = int(pairs["ln"])
            r = int(pairs["r"])
            p_cost = int(pairs["p"])
            salt = _phc_b64_decode(salt_b64)
            stored = _phc_b64_decode(key_b64)
            if not salt or not stored:
                return False
            candidate = hashlib.scrypt(
                password.encode(),
                salt=salt,
                n=2 ** ln,
                r=r,
                p=p_cost,
                dklen=len(stored),
                maxmem=0,
            )
            return _hmac.compare_digest(candidate, stored)

        if hashed.startswith("$pbkdf2-sha256$"):
            parts = hashed.split("$")
            rounds = parts[2]
            salt_ab64 = parts[3]
            key_ab64 = parts[4]
            salt = _ab64_decode(salt_ab64)
            stored = _ab64_decode(key_ab64)
            if not salt or not stored:
                return False
            candidate = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt,
                int(rounds),
                dklen=len(stored),
            )
            return _hmac.compare_digest(candidate, stored)
    except Exception:
        # Returning False on a malformed hash is intentional: verification
        # must never leak why input failed. Log so implementation issues are
        # still visible during debugging/testing instead of being silent.
        _logger.debug(
            "password.verify: rejected malformed or unverifiable hash",
            exc_info=True,
        )
        return False

    return False


def derive(
    passphrase: Union[str, bytes],
    salt: bytes,
    length: int = 32,
    algorithm: str = "pbkdf2_sha256",
    options: Optional[HashOptions] = None,
    **params: Any,
) -> bytes:
    """Derive a key from a passphrase and salt.

    Cost parameters may be supplied either as a typed ``HashOptions`` dict via
    ``options`` or as keyword ``params`` (keyword arguments take precedence).
    """
    if salt is None or len(salt) == 0:
        raise InvalidKeyError("A non-empty salt is required for key derivation")
    if length <= 0:
        raise InvalidKeyError("length must be a positive integer")

    merged: Dict[str, Any] = dict(options) if options else {}
    merged.update(params)

    p = _to_bytes(passphrase)
    algo = algorithm.lower().replace("-", "_")

    if algo == "pbkdf2_sha256":
        iterations = merged.get("iterations", 100_000)
        return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, dklen=length)

    if algo == "scrypt":
        if not _SCRYPT_AVAILABLE:
            raise MissingDependencyError("scrypt is not available on this platform")
        n = merged.get("n", 16384)
        r = merged.get("r", 8)
        p_cost = merged.get("p", 1)
        maxmem = merged.get("maxmem", 64 * 1024 * 1024)
        return hashlib.scrypt(p, salt=salt, n=n, r=r, p=p_cost, dklen=length, maxmem=maxmem)

    if algo == "argon2id":
        if not _HAS_ARGON2:
            raise MissingDependencyError(
                "Argon2id key derivation requires argon2-cffi"
            )
        time_cost = merged.get("time_cost", 3)
        memory_cost = merged.get("memory_cost", 65536)
        parallelism = merged.get("parallelism", 4)
        return _Argon2LowLevel.hash_secret_raw(
            p,
            salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=length,
            type=_Argon2Type.ID,
        )

    raise AlgorithmError(f"Unsupported key derivation algorithm: {algorithm}")
