"""Comprehensive tests for the Modern Cryptography & Hashing Toolkit."""

import hashlib
import hmac as _hmac

import pytest

from crypto_toolkit import encrypt, hash, password, sign
from crypto_toolkit.exceptions import AlgorithmError, DecryptionError

try:
    import cryptography  # noqa: F401

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def test_hash_string():
    assert hash.string("hello world", "sha-256") == hashlib.sha256(b"hello world").hexdigest()
    assert hash.string(b"", "blake2b") == hashlib.blake2b(b"").hexdigest()


def test_hash_rejects_weak_algorithms():
    with pytest.raises(AlgorithmError):
        hash.string("test", "md5")
    with pytest.raises(AlgorithmError):
        hash.string("test", "sha-1")


def test_hmac():
    mac = hash.hmac("key", "message", "sha-256")
    expected = _hmac.new(b"key", b"message", "sha256").hexdigest()
    assert mac == expected
    assert hash.verify_hmac(mac, "key", "message", "sha-256")


def test_hmac_bytes():
    mac = hash.hmac(b"key", b"message", "sha-256")
    assert hash.verify_hmac(mac, b"key", b"message", "sha-256")


def test_password_hash_and_verify_pbkdf2():
    h = password.hash("user-password", algorithm="pbkdf2_sha256", iterations=1000)
    assert h.startswith("pbkdf2_sha256$")
    assert password.verify("user-password", h)
    assert not password.verify("wrong", h)


def test_password_derive():
    salt = b"saltsaltsaltsalt"
    key = password.derive("passphrase", salt=salt, length=32)
    assert len(key) == 32
    assert key == password.derive("passphrase", salt=salt, length=32)


def test_password_default_safe():
    h = password.hash("secret")
    assert password.verify("secret", h)
    assert not password.verify("other", h)


def test_password_derive_requires_salt():
    with pytest.raises(AlgorithmError):
        password.derive("passphrase", length=32)


def test_password_derive_requires_positive_length():
    with pytest.raises(AlgorithmError):
        password.derive("passphrase", salt=b"salt", length=0)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_aes_gcm():
    key = password.derive(
        "passphrase", salt=b"saltsaltsaltsalt", length=32, algorithm="pbkdf2_sha256"
    )
    ct = encrypt.symmetric("sensitive data", key=key)
    assert isinstance(ct, bytes)
    pt = encrypt.decrypt(ct, key=key)
    assert pt == "sensitive data"


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_chacha20_poly1305():
    key = password.derive(
        "passphrase", salt=b"saltsaltsaltsalt", length=32, algorithm="pbkdf2_sha256"
    )
    ct = encrypt.symmetric("sensitive data", key=key, algorithm="chacha20-poly1305")
    pt = encrypt.decrypt(ct, key=key)
    assert pt == "sensitive data"


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_rejects_tampering():
    key = b"x" * 32
    ct = encrypt.symmetric("data", key=key)
    tampered = bytearray(ct)
    tampered[-1] ^= 1
    with pytest.raises(DecryptionError):
        encrypt.decrypt(bytes(tampered), key=key)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_ed25519_sign_and_verify():
    sk, pk = sign.generate_keypair()
    sig = sign.ed25519("hello world", private_key=sk)
    assert sign.verify(sig, "hello world", public_key=pk)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_ed25519_verifies_wrong_message():
    sk, pk = sign.generate_keypair()
    sig = sign.ed25519("message", private_key=sk)
    assert not sign.verify(sig, "other message", public_key=pk)
