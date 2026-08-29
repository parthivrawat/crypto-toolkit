"""Usage examples for the Modern Cryptography & Hashing Toolkit."""

from crypto_toolkit import encrypt, hash, password, sign


def main():
    # Hashing and HMAC
    print("SHA-256:", hash.string("hello world", algorithm="sha-256"))
    mac = hash.hmac("secret-key", "message", algorithm="sha-256")
    print("HMAC verified:", hash.verify_hmac(mac, "secret-key", "message"))

    # Password hashing
    ph = password.hash("user-password")
    print("Password valid:", password.verify("user-password", ph))

    # Key derivation
    salt = b"0123456789abcdef"
    key = password.derive("passphrase", salt=salt, length=32)

    # Symmetric encryption (requires cryptography)
    try:
        ciphertext = encrypt.symmetric("sensitive data", key=key)
        plaintext = encrypt.decrypt(ciphertext, key=key)
        print("Decrypted:", plaintext)
    except Exception as exc:  # pragma: no cover
        print("Skipping encryption:", exc)

    # Ed25519 signatures (requires cryptography)
    try:
        sk, pk = sign.generate_keypair()
        signature = sign.ed25519("message", private_key=sk)
        print("Signature valid:", sign.verify(signature, "message", public_key=pk))
    except Exception as exc:  # pragma: no cover
        print("Skipping signing:", exc)


if __name__ == "__main__":
    main()
