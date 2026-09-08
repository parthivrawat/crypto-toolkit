"""Comprehensive tests for the Modern Cryptography & Hashing Toolkit."""

import hashlib
import hmac as _hmac
import os
import random

import pytest

from crypto_toolkit import encrypt, hash, password, sign
from crypto_toolkit.exceptions import AlgorithmError, CryptoKitError, DecryptionError, InvalidKeyError

try:
    import cryptography  # noqa: F401

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import argon2  # noqa: F401

    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


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
    h = password.hash_with("user-password", "pbkdf2_sha256", iterations=1000)
    assert h.startswith("$pbkdf2-sha256$")
    assert password.verify("user-password", h)
    assert not password.verify("wrong", h)


@pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
def test_password_hash_and_verify_argon2id():
    h = password.hash_with("user-password", "argon2id")
    assert h.startswith("$argon2id$")
    assert password.verify("user-password", h)
    assert not password.verify("wrong", h)


def test_password_hash_and_verify_scrypt():
    h = password.hash_with("user-password", "scrypt", n=1024, r=8, p=1, dklen=32)
    assert h.startswith("$scrypt$")
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


def test_password_hash_options():
    from crypto_toolkit import HashOptions

    opts: HashOptions = {"iterations": 1000}
    h = password.hash_with("user-password", "pbkdf2_sha256", options=opts)
    assert h.startswith("$pbkdf2-sha256$1000$")
    assert password.verify("user-password", h)
    # Keyword params still take precedence over options.
    h2 = password.hash_with("user-password", "pbkdf2_sha256", options=opts, iterations=2000)
    assert h2.startswith("$pbkdf2-sha256$2000$")


def test_password_derive_options():
    from crypto_toolkit import HashOptions

    salt = b"saltsaltsaltsalt"
    opts: HashOptions = {"iterations": 5000}
    k1 = password.derive("passphrase", salt=salt, length=32, options=opts)
    k2 = password.derive("passphrase", salt=salt, length=32, iterations=5000)
    assert k1 == k2


def test_password_verify_logs_malformed_hash(caplog):
    import logging

    with caplog.at_level(logging.DEBUG, logger="crypto_toolkit.password"):
        assert password.verify("pw", "$scrypt$garbage") is False
    assert any("malformed" in r.message for r in caplog.records)


def test_password_derive_requires_salt():
    with pytest.raises(InvalidKeyError):
        password.derive("passphrase", salt=None, length=32)


def test_password_derive_requires_positive_length():
    with pytest.raises(InvalidKeyError):
        password.derive("passphrase", salt=b"salt", length=0)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_aes_gcm():
    key = password.derive(
        "passphrase", salt=b"saltsaltsaltsalt", length=32, algorithm="pbkdf2_sha256"
    )
    ct = encrypt.symmetric("sensitive data", key=key)
    assert ct[0] == 2
    pt = encrypt.decrypt(ct, key=key)
    assert pt == b"sensitive data"


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_string_aes_gcm():
    key = b"x" * 32
    ct = encrypt.encrypt_string("sensitive data", key)
    pt = encrypt.decrypt_string(ct, key)
    assert pt == "sensitive data"


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_chacha20_poly1305():
    key = b"x" * 32
    ct = encrypt.encrypt("sensitive data", key, algorithm="chacha20-poly1305")
    pt = decrypt = encrypt.decrypt(ct, key)
    assert pt == b"sensitive data"


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_with_aad():
    key = b"x" * 32
    aad = b"context"
    ct = encrypt.encrypt("sensitive data", key, aad=aad)
    pt = encrypt.decrypt(ct, key, aad=aad)
    assert pt == b"sensitive data"
    with pytest.raises(DecryptionError):
        encrypt.decrypt(ct, key, aad=b"wrong")


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_rejects_tampering():
    key = b"x" * 32
    ct = encrypt.encrypt("data", key)
    tampered = bytearray(ct)
    tampered[-1] ^= 1
    with pytest.raises(DecryptionError):
        encrypt.decrypt(bytes(tampered), key)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_ed25519_sign_and_verify():
    sk, pk = sign.generate_keypair()
    sig = sign.sign("hello world", private_key=sk)
    assert sign.verify(sig, "hello world", public_key=pk)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_ed25519_verifies_wrong_message():
    sk, pk = sign.generate_keypair()
    sig = sign.sign("message", private_key=sk)
    assert not sign.verify(sig, "other message", public_key=pk)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_ed25519_pem_roundtrip():
    sk, pk = sign.generate_keypair()
    pem_sk = sign.private_key_to_pem(sk)
    pem_pk = sign.public_key_to_pem(pk)
    assert "BEGIN PRIVATE KEY" in pem_sk
    assert "BEGIN PUBLIC KEY" in pem_pk
    assert sign.private_key_from_pem(pem_sk) == sk
    assert sign.public_key_from_pem(pem_pk) == pk


# Edge case tests
def test_hash_empty():
    expected = hashlib.sha256(b"").hexdigest()
    assert hash.string("") == expected
    assert hash.string(b"") == expected


def test_hash_file_large(tmp_path):
    path = tmp_path / "large.bin"
    data = os.urandom(5_000_000)
    path.write_bytes(data)
    assert hash.file(path) == hashlib.sha256(data).hexdigest()


def test_password_derive_empty_salt_raises():
    with pytest.raises(InvalidKeyError):
        password.derive("passphrase", salt=b"", length=32)


MALFORMED_HASHES = [
    "notahash",
    "",
    "$scrypt$garbage",
    "$pbkdf2-sha256$abc$bad$bad",
    # argon2id variants
    "$argon2id$v=19$m=65536,t=3,p=4$bad$bad",
    "$argon2id$v=19$m=65536,t=3,p=4$c29sdA$wrong",
    "$argon2id$",
    "$argon2id$garbage",
    "$argon2id$v=19$m=65536,t=3,p=4$c29sdA",
    "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$invalidhash",
    "$argon2id$v=19$m=bad,t=3,p=4$c29sdA$wrong",
    "$argon2id$v=16$m=65536,t=3,p=4$c29sdA$wrong",
    "$argon2id$v=19$m=65536,t=3,p=4$$",
    "$argon2id$v=19$m=65536,t=0,p=4$c29sdA$wrong",
    # bcrypt variants
    "$2a$08$short",
    "$2b$08$" + "x" * 59,
    "$2b$08$" + "garbage$" * 10,
    "$2y$08$" + "x" * 59,
    "$2x$08$" + "x" * 59,
    "$2b$99$" + "x" * 59,
    "$2b$08$garbagegarbagegarbagegarbagegarbagegarbagegarbagegarbagegarbageg",
    "$2b$08$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "$2b$08$" + "A" * 59,
    "$2$08$" + "x" * 59,
    # scrypt variants
    "$scrypt$garbage",
    "$scrypt$ln=10,r=8,p=1$bad$bad",
    "$scrypt$ln=notanumber,r=8,p=1$bad$bad",
    "$scrypt$ln=10$bad$bad",
    "$scrypt$ln=10,r=8,p=1$bad",
    "$scrypt$ln=10,r=8,p=1$$",
    "$scrypt$ln=-1,r=8,p=1$c2FsdA$bad",
    "$scrypt$ln=10,r=8,p=1$c2FsdA$wronghash",
    "$scrypt$ln=10,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$badbase64!!",
    "$scrypt$ln=10,r=8,p=1$c2FsdA$",
    # pbkdf2-sha256 variants
    "$pbkdf2-sha256$1000$bad$bad",
    "$pbkdf2-sha256$1000$",
    "$pbkdf2-sha256$1000$salt",
    "$pbkdf2-sha256$notnumber$salt$hash",
    "$pbkdf2-sha256$1000$badbase64$hash",
    "$pbkdf2-sha256$1000$c2FsdA$badbase64",
    "$pbkdf2-sha256$1000$$",
    "$pbkdf2-sha256$1000$c2FsdA$",
    "$pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$badbase64!",
    "$pbkdf2-sha256$1000$c2FsdA$hash$extra",
]


def test_password_verify_uniform_rejection():
    for malformed in MALFORMED_HASHES:
        assert password.verify("any-password", malformed) is False
    valid = password.hash_with("secret", "pbkdf2_sha256", iterations=100)
    assert password.verify("wrong-password", valid) is False


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_empty_plaintext_roundtrip():
    key = b"x" * 32
    ct = encrypt.encrypt(b"", key)
    assert encrypt.decrypt(ct, key) == b""


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_binary_non_utf8_roundtrip():
    key = b"x" * 32
    pt = bytes([0xFF, 0xFE, 0x80, 0x00])
    ct = encrypt.encrypt(pt, key)
    assert encrypt.decrypt(ct, key) == pt


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_decrypt_string_rejects_non_utf8():
    key = b"x" * 32
    pt = bytes([0xFF, 0xFE, 0x80, 0x00])
    ct = encrypt.encrypt(pt, key)
    with pytest.raises(ValueError):
        encrypt.decrypt_string(ct, key)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_empty_key_raises():
    with pytest.raises(InvalidKeyError):
        encrypt.encrypt(b"data", b"")


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_token_truncations():
    key = b"\x00" * 32
    token = encrypt.encrypt(b"data", key)
    for i in range(len(token)):
        with pytest.raises(DecryptionError):
            encrypt.decrypt(token[:i], key)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_token_bit_flips():
    key = b"\x00" * 32
    token = encrypt.encrypt(b"data", key)
    for i in range(len(token)):
        mutated = bytearray(token)
        mutated[i] ^= 0xFF
        with pytest.raises(CryptoKitError):
            encrypt.decrypt(bytes(mutated), key)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_encrypt_random_tokens():
    key = b"\x00" * 32
    rng = random.Random(0)
    for _ in range(500):
        length = rng.randint(0, 64)
        token = bytes(rng.choices(range(256), k=length))
        with pytest.raises(DecryptionError):
            encrypt.decrypt(token, key)
