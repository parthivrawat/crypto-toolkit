# Cross-Language Test Vectors

These are fixed, deterministic vectors that every `crypto-toolkit`
implementation should pass. They cover hashing, HMAC, key derivation,
AEAD decryption, and Ed25519 signatures.

Common inputs unless stated otherwise:

- **Message / password**: `cross-language-test`
- **Salt** (32 bytes): `saltsaltsaltsaltsaltsaltsaltsalt`
- **Encryption key** (hex):
  `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`

## Deterministic Hashing

SHA-256 of `cross-language-test`:

```
8de4271480b58aedac9d059165faa03bf42062f77ae9196f0932f2ab9994c96e
```

## HMAC-SHA-256

Key `cross-language-key`, message `cross-language-test`:

```
9d67f44518758c0e736fa7961cbe9d5f5bd2dde2ee85867b01b7e9cbfdb8e4c5
```

## Key Derivation

All derive 32 bytes from password `cross-language-test` and the salt above.

### PBKDF2-SHA256 (iterations = 1000)

```
350c342086d9328de4f36286d53015b63bbadd87875d9325881c996780ca0fda
```

### scrypt (N = 2^10 = 1024, r = 8, p = 1)

```
2975dff06995994413199f4bd015b3a7baf2c0616a195290fa46b3cb2ba8a853
```

### Argon2id (time = 3, memory = 65536 KiB, parallelism = 4, v = 19)

```
4495c94ca3852576fa10b1ee381c3742f7aaf152499bd42be93b59427fca331c
```

> TypeScript note: this vector requires Node >= 23.6 (`crypto.argon2Sync`)
> and assumes Node's `memory` parameter is in KiB. If the platform output
> differs, treat the vector as conditional.

## Password-Hash Verification

Fixed password hashes that `password.verify('cross-language-test', …)` must
accept in every language (and `verify('wrong-password', …)` must reject).

### PBKDF2-SHA256

```
$pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$NQw0IIbZMo3k82KG1TAVtju63YeHXZMliByZZ4DKD9o
```

- Iterations: `1000`
- Salt & hash encoding: Passlib AB64 (`+` → `.`, padding stripped)

### scrypt

```
$scrypt$ln=10,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$KXXf8GmVmUQTGZ9L0BWzp7rywGFqGVKQ+kazyyuoqFM
```

- `N = 2^10`, `r = 8`, `p = 1`
- Salt & hash encoding: PHC Base64 (no padding)

## AEAD Encryption Tokens

Versioned v2 tokens: `version | algo_id | u16 aad_len | aad | nonce | ct | tag`.
Each must decrypt to `cross-language-test` with the encryption key above.

### AES-256-GCM (algo_id = 1, no AAD)

```
020100007437945cda0539277c709cf7e0fb65ec51a3771fa6d2cba682cb9326194759aa3f8874d8663d3140d81fc020b807aa
```

### ChaCha20-Poly1305 (algo_id = 2, no AAD)

```
020200008676258015ff452777b5af24cae1327aacf84a42bf66cb5db3160557782b15d330fa33de6b5d7dc9169377c183e30f
```

### AES-256-GCM with AAD `vector-context`

```
0201000e766563746f722d636f6e746578747f436a5f29c8ff2d66c01fe330f582ecb37d3abc041f46ffa88d9eab1639c59d5570e5cbaec07eaa77be7c3ce8ae8b
```

Decrypting this token with any other AAD must fail.

## Ed25519 Signature

Message: `cross-language-test`. Ed25519 is deterministic, so both the
signature bytes and successful verification are checkable.

- Private seed (32 bytes):
  `d177524e40ee195afe206345792e20c8117c8254f2ce98ee45589625f89fc4b8`
- Public key (32 bytes):
  `a3b599b8cef3428956452bf75a445860958633aa3bf0c4160a09e6c0fcba2463`
- Signature (64 bytes):
  `8b0dd73d7644c49c208398874ce6cdfc98a49a7c05fc613dc5be9382c10bbdd43da9466d6f10646c72d9d5adea33e8f15c3349fab5478d58400fcf93db0f0b09`

## Notes

- Vectors were generated with the Python implementation and verified against
  its outputs; each language's test suite asserts identical results.
- Argon2id password-hash strings are not included because salts are random;
  the deterministic key-derivation vector above covers the algorithm.
