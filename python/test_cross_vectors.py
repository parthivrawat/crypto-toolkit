"""Cross-language and known-answer test vectors for crypto_toolkit."""

import hashlib

import pytest

from crypto_toolkit import encrypt, hash, password, sign
from crypto_toolkit.exceptions import DecryptionError

try:
    import argon2  # noqa: F401

    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

try:
    import cryptography  # noqa: F401

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

HAS_SCRYPT = hasattr(hashlib, "scrypt")

SALT = b"saltsaltsaltsaltsaltsaltsaltsalt"

PBKDF2_VECTOR = (
    "$pbkdf2-sha256$1000$"
    "c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$"
    "NQw0IIbZMo3k82KG1TAVtju63YeHXZMliByZZ4DKD9o"
)

SCRYPT_VECTOR = (
    "$scrypt$ln=10,r=8,p=1$"
    "c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$"
    "KXXf8GmVmUQTGZ9L0BWzp7rywGFqGVKQ+kazyyuoqFM"
)


def test_cross_language_hash_string():
    assert (
        hash.string("cross-language-test", "sha-256")
        == "8de4271480b58aedac9d059165faa03bf42062f77ae9196f0932f2ab9994c96e"
    )


def test_cross_language_hmac():
    assert (
        hash.hmac("cross-language-key", "cross-language-test", "sha-256")
        == "9d67f44518758c0e736fa7961cbe9d5f5bd2dde2ee85867b01b7e9cbfdb8e4c5"
    )


def test_cross_language_pbkdf2_sha256_derive():
    key = password.derive(
        "cross-language-test",
        salt=SALT,
        length=32,
        algorithm="pbkdf2_sha256",
        options={"iterations": 1000},
    )
    assert key.hex() == (
        "350c342086d9328de4f36286d53015b63bbadd87875d9325881c996780ca0fda"
    )
    # Keyword form should produce the same key.
    key2 = password.derive(
        "cross-language-test",
        salt=SALT,
        length=32,
        algorithm="pbkdf2_sha256",
        iterations=1000,
    )
    assert key == key2


@pytest.mark.skipif(not HAS_SCRYPT, reason="scrypt not available")
def test_cross_language_scrypt_derive():
    key = password.derive(
        "cross-language-test",
        salt=SALT,
        length=32,
        algorithm="scrypt",
        options={"n": 1024, "r": 8, "p": 1},
    )
    assert key.hex() == (
        "2975dff06995994413199f4bd015b3a7baf2c0616a195290fa46b3cb2ba8a853"
    )
    # Keyword form should produce the same key.
    key2 = password.derive(
        "cross-language-test",
        salt=SALT,
        length=32,
        algorithm="scrypt",
        n=1024,
        r=8,
        p=1,
    )
    assert key == key2


@pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
def test_cross_language_argon2id_derive():
    key = password.derive(
        "cross-language-test",
        salt=SALT,
        length=32,
        algorithm="argon2id",
        options={"time_cost": 3, "memory_cost": 65536, "parallelism": 4},
    )
    assert key.hex() == (
        "4495c94ca3852576fa10b1ee381c3742f7aaf152499bd42be93b59427fca331c"
    )
    # Keyword form should produce the same key.
    key2 = password.derive(
        "cross-language-test",
        salt=SALT,
        length=32,
        algorithm="argon2id",
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
    )
    assert key == key2


ENCRYPTION_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_cross_language_decrypt_aes_256_gcm_vector():
    token = bytes.fromhex(
        "020100007437945cda0539277c709cf7e0fb65ec51a3771fa6d2cba682cb9326194759aa3f8874d8663d3140d81fc020b807aa"
    )
    assert encrypt.decrypt(token, key=ENCRYPTION_KEY) == b"cross-language-test"


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_cross_language_decrypt_chacha20_poly1305_vector():
    token = bytes.fromhex(
        "020200008676258015ff452777b5af24cae1327aacf84a42bf66cb5db3160557782b15d330fa33de6b5d7dc9169377c183e30f"
    )
    assert encrypt.decrypt(token, key=ENCRYPTION_KEY) == b"cross-language-test"


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_cross_language_decrypt_aad_vector():
    token = bytes.fromhex(
        "0201000e766563746f722d636f6e746578747f436a5f29c8ff2d66c01fe330f582ecb37d3abc041f46ffa88d9eab1639c59d5570e5cbaec07eaa77be7c3ce8ae8b"
    )
    assert (
        encrypt.decrypt(token, key=ENCRYPTION_KEY, aad=b"vector-context")
        == b"cross-language-test"
    )
    with pytest.raises(DecryptionError):
        encrypt.decrypt(token, key=ENCRYPTION_KEY, aad=b"wrong-context")


ED25519_SEED = bytes.fromhex(
    "d177524e40ee195afe206345792e20c8117c8254f2ce98ee45589625f89fc4b8"
)
ED25519_PUB = bytes.fromhex(
    "a3b599b8cef3428956452bf75a445860958633aa3bf0c4160a09e6c0fcba2463"
)
ED25519_SIG = bytes.fromhex(
    "8b0dd73d7644c49c208398874ce6cdfc98a49a7c05fc613dc5be9382c10bbdd43da9466d6f10646c72d9d5adea33e8f15c3349fab5478d58400fcf93db0f0b09"
)


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_cross_language_ed25519_vector():
    sig = sign.ed25519(b"cross-language-test", ED25519_SEED)
    assert sig == ED25519_SIG
    assert sign.verify(sig, b"cross-language-test", public_key=ED25519_PUB) is True


# Existing password verification cross-language tests.

def test_verify_cross_language_pbkdf2_vector():
    assert password.verify("cross-language-test", PBKDF2_VECTOR) is True


@pytest.mark.skipif(not HAS_SCRYPT, reason="scrypt not available")
def test_verify_cross_language_scrypt_vector():
    assert password.verify("cross-language-test", SCRYPT_VECTOR) is True


def test_verify_wrong_password_against_vectors():
    assert password.verify("wrong-password", PBKDF2_VECTOR) is False
    if HAS_SCRYPT:
        assert password.verify("wrong-password", SCRYPT_VECTOR) is False
