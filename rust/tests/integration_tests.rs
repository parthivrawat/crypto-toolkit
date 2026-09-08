use modern_crypto_toolkit::{encrypt, hash, password, sign};

#[test]
fn test_aes_gcm_roundtrip() {
    let key = vec![0x78u8; 32];
    let ct = encrypt::encrypt_string("sensitive data", &key, None).unwrap();
    assert_eq!(ct[0], 2);
    let pt = encrypt::decrypt_string(&ct, &key, None).unwrap();
    assert_eq!(pt, "sensitive data");
}

#[test]
fn test_chacha20_poly1305_roundtrip() {
    let key = vec![0x12u8; 32];
    let ct = encrypt::encrypt_with("sensitive data".as_bytes(), &key, None, "chacha20-poly1305").unwrap();
    let pt = encrypt::decrypt_string(&ct, &key, None).unwrap();
    assert_eq!(pt, "sensitive data");
}

#[test]
fn test_aad() {
    let key = vec![0xabu8; 32];
    let aad = b"context";
    let ct = encrypt::encrypt("data".as_bytes(), &key, Some(aad.as_slice())).unwrap();
    let pt = encrypt::decrypt(&ct, &key, Some(aad.as_slice())).unwrap();
    assert_eq!(pt, b"data");
    assert!(encrypt::decrypt(&ct, &key, Some(b"wrong".as_slice())).is_err());
}

#[test]
fn test_tampering_rejected() {
    let key = vec![0xabu8; 32];
    let mut ct = encrypt::encrypt_string("data", &key, None).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 1;
    assert!(encrypt::decrypt(&ct, &key, None).is_err());
}

#[test]
fn test_pbkdf2_hash_and_verify() {
    let h = password::hash_with(
        "user-password",
        "pbkdf2_sha256",
        Some(&password::HashOptions {
            iterations: 1000,
            ..Default::default()
        }),
    )
    .unwrap();
    assert!(h.starts_with("$pbkdf2-sha256$"));
    assert!(password::verify("user-password", &h).unwrap());
    assert!(!password::verify("wrong", &h).unwrap());
}

#[test]
fn test_scrypt_hash_and_verify() {
    let h = password::hash_with(
        "user-password",
        "scrypt",
        Some(&password::HashOptions {
            log_n: 10,
            r: 8,
            p: 1,
            output_length: 32,
            ..Default::default()
        }),
    )
    .unwrap();
    assert!(h.starts_with("$scrypt$"));
    assert!(password::verify("user-password", &h).unwrap());
    assert!(!password::verify("wrong", &h).unwrap());
}

#[test]
fn test_derive() {
    let salt = b"saltsaltsaltsalt";
    let key1 = password::derive("passphrase", salt, 32, None, None).unwrap();
    let key2 = password::derive("passphrase", salt, 32, None, None).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn test_derive_requires_salt() {
    assert!(password::derive("passphrase", b"", 32, None, None).is_err());
}

#[test]
fn test_derive_pbkdf2_custom_iterations() {
    let salt = b"saltsaltsaltsalt";
    let key1 = password::derive("passphrase", salt, 32, Some("pbkdf2_sha256"), Some(&password::HashOptions {
        iterations: 1000,
        ..Default::default()
    })).unwrap();
    let key2 = password::derive("passphrase", salt, 32, Some("pbkdf2_sha256"), Some(&password::HashOptions {
        iterations: 1000,
        ..Default::default()
    })).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn test_derive_scrypt_custom_params() {
    let salt = b"saltsaltsaltsalt";
    let key1 = password::derive("passphrase", salt, 32, Some("scrypt"), Some(&password::HashOptions {
        log_n: 10,
        r: 8,
        p: 1,
        ..Default::default()
    })).unwrap();
    let key2 = password::derive("passphrase", salt, 32, Some("scrypt"), Some(&password::HashOptions {
        log_n: 10,
        r: 8,
        p: 1,
        ..Default::default()
    })).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn test_derive_with_partial_options_uses_defaults() {
    let salt = b"saltsaltsaltsalt";
    // Only iterations is provided; all other zero/empty values must be replaced by defaults.
    let _ = password::derive("passphrase", salt, 32, Some("pbkdf2_sha256"), Some(&password::HashOptions {
        iterations: 1000,
        ..Default::default()
    })).unwrap();
}

#[test]
fn test_ed25519_sign_and_verify() {
    let (sk, pk) = sign::generate_keypair().unwrap();
    let sig = sign::ed25519("message", &sk).unwrap();
    assert!(sign::verify(&sig, "message", &pk).unwrap());
    assert!(!sign::verify(&sig, "other", &pk).unwrap());
}

#[test]
fn test_pem_round_trip() {
    let (sk, pk) = sign::generate_keypair().unwrap();
    let sk_pem = sign::private_key_to_pem(&sk).unwrap();
    let pk_pem = sign::public_key_to_pem(&pk).unwrap();
    let loaded_sk = sign::private_key_from_pem(&sk_pem).unwrap();
    let loaded_pk = sign::public_key_from_pem(&pk_pem).unwrap();
    assert_eq!(sk, loaded_sk);
    assert_eq!(pk, loaded_pk);
}

#[test]
fn test_invalid_key_length_rejected() {
    assert!(sign::private_key_to_pem(&[0u8; 31]).is_err());
    assert!(sign::public_key_to_pem(&[0u8; 31]).is_err());
}

// ===========================================================================
// Token-parsing mutation tests
// ===========================================================================

#[test]
fn test_decrypt_every_truncation_rejected() {
    let key = vec![0xabu8; 32];
    let token = encrypt::encrypt(b"data", &key, None).unwrap();
    for i in 0..token.len() {
        assert!(
            encrypt::decrypt(&token[..i], &key, None).is_err(),
            "truncated token of length {i} decrypted successfully"
        );
    }
}

#[test]
fn test_decrypt_every_byte_flip_rejected() {
    let key = vec![0xabu8; 32];
    let token = encrypt::encrypt(b"data", &key, None).unwrap();
    for i in 0..token.len() {
        let mut mutated = token.clone();
        mutated[i] ^= 0xFF;
        assert!(
            encrypt::decrypt(&mutated, &key, None).is_err(),
            "token with byte {i} flipped decrypted successfully"
        );
    }
}

#[test]
fn test_decrypt_random_garbage_never_panics() {
    let key = vec![0xabu8; 32];
    // Deterministic xorshift64* PRNG — no external deps.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..500 {
        let len = (next() % 65) as usize;
        let mut token = vec![0u8; len];
        for b in token.iter_mut() {
            *b = (next() & 0xFF) as u8;
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            encrypt::decrypt(&token, &key, None)
        }));
        assert!(outcome.is_ok(), "decrypt panicked on garbage token");
        assert!(
            outcome.unwrap().is_err(),
            "garbage token decrypted successfully"
        );
    }
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn test_hash_empty_string() {
    let h = hash::string("", "sha-256").unwrap();
    assert_eq!(h.len(), 64);
    assert_eq!(
        h,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_hash_large_file() {
    use sha2::Digest;
    // ~5 MB of deterministic content.
    let mut contents = Vec::with_capacity(5 * 1024 * 1024 + 123);
    let mut x: u32 = 0x12345678;
    while contents.len() < 5 * 1024 * 1024 + 123 {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        contents.extend_from_slice(&x.to_le_bytes());
    }
    let path = std::env::temp_dir().join(format!(
        "mct_hash_test_{}_{}.bin",
        std::process::id(),
        contents.len()
    ));
    std::fs::write(&path, &contents).unwrap();
    let got = hash::file(path.to_str().unwrap(), "sha-256");
    let _ = std::fs::remove_file(&path);
    let expected = hex::encode(sha2::Sha256::digest(&contents));
    assert_eq!(got.unwrap(), expected);
}

#[test]
fn test_encrypt_empty_plaintext_roundtrip() {
    let key = vec![0x55u8; 32];
    let ct = encrypt::encrypt(b"", &key, None).unwrap();
    let pt = encrypt::decrypt(&ct, &key, None).unwrap();
    assert!(pt.is_empty());
    let s = encrypt::decrypt_string(&ct, &key, None).unwrap();
    assert_eq!(s, "");
}

#[test]
fn test_encrypt_binary_plaintext_roundtrip() {
    let key = vec![0x55u8; 32];
    let pt = vec![0xff, 0xfe, 0x80, 0x00];
    let ct = encrypt::encrypt(&pt, &key, None).unwrap();
    assert_eq!(encrypt::decrypt(&ct, &key, None).unwrap(), pt);
    // Non-UTF-8 plaintext must not come back through the string API.
    assert!(encrypt::decrypt_string(&ct, &key, None).is_err());
}

#[test]
fn test_encrypt_zero_length_key_rejected() {
    match encrypt::encrypt(b"data", &[], None) {
        Err(modern_crypto_toolkit::Error::InvalidKey(_)) => {}
        other => panic!("expected InvalidKey, got {other:?}"),
    }
}

#[test]
fn test_password_verify_rejects_malformed() {
    for bad in [
        "notahash",
        "",
        "$scrypt$garbage",
        "$pbkdf2-sha256$abc$bad$bad",
    ] {
        let res = password::verify("password", bad);
        if let Ok(true) = res {
            panic!("verify({bad:?}) returned Ok(true)");
        }
    }
}

#[test]
fn test_verify_hmac_malformed_macs() {
    let key = b"key";
    let data = b"data";
    let good = hash::hmac(key, data, "sha-256").unwrap();
    // Non-hex MAC -> error or Ok(false), never Ok(true).
    if let Ok(true) = hash::verify_hmac("zzzznothex", key, data, "sha-256") {
        panic!("verify_hmac accepted non-hex mac");
    }
    // Wrong-length hex MAC -> Ok(false) or Err, never Ok(true).
    if let Ok(true) = hash::verify_hmac("abcd", key, data, "sha-256") {
        panic!("verify_hmac accepted truncated mac");
    }
    // Truncated-but-valid-hex of real MAC must be false.
    let short = &good[..32];
    assert!(!hash::verify_hmac(short, key, data, "sha-256").unwrap());
    // Sanity: the real MAC verifies.
    assert!(hash::verify_hmac(&good, key, data, "sha-256").unwrap());
}

// ===========================================================================
// Uniform rejection of malformed password hashes
// ===========================================================================

#[test]
fn test_password_verify_malformed_table() {
    let cases = [
        // argon2id malformed variants
        "$argon2id$",
        "$argon2id$v=19$m=65536,t=3,p=4$$",
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$",
        "$argon2id$v=19$m=65536,t=3$c2FsdHNhbHRzYWx0$AAAA",
        "$argon2id$v=19$m=abc,t=3,p=4$c2FsdHNhbHRzYWx0$AAAA",
        "$argon2id$v=19$m=65536,t=3,p=4$!!!notb64!!!$AAAA",
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$AAAA$extra",
        "$argon2id$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$AAAA",
        "$argon2id$v=19$x=1,t=3,p=4$c2FsdHNhbHRzYWx0$AAAA",
        "$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$AAAA",
        // scrypt malformed variants
        "$scrypt$",
        "$scrypt$ln=10,r=8,p=1$$",
        "$scrypt$ln=10,r=8,p=1$c2FsdA$",
        "$scrypt$ln=10,r=8$c2FsdHNhbHRzYWx0$AAAA",
        "$scrypt$ln=abc,r=8,p=1$c2FsdHNhbHRzYWx0$AAAA",
        "$scrypt$ln=10,r=8,p=1$!!!notb64!!!$AAAA",
        "$scrypt$ln=10,r=8,p=1$c2FsdHNhbHRzYWx0$AAAA$extra",
        "$scrypt$n=1024,r=8,p=1$c2FsdHNhbHRzYWx0$AAAA",
        "$scrypt$ln=10,r=8,p=1,p=2$c2FsdHNhbHRzYWx0$AAAA",
        "$scrypt$$ln=10,r=8,p=1$c2FsdHNhbHRzYWx0$AAAA",
        // pbkdf2-sha256 malformed variants
        "$pbkdf2-sha256$",
        "$pbkdf2-sha256$1000$$",
        "$pbkdf2-sha256$1000$c2FsdA$",
        "$pbkdf2-sha256$abc$c2FsdHNhbHRzYWx0$AAAA",
        "$pbkdf2-sha256$-1$c2FsdHNhbHRzYWx0$AAAA",
        "$pbkdf2-sha256$1000$!!!notb64!!!$AAAA",
        "$pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0$AAAA$extra",
        "$pbkdf2-sha256$$c2FsdHNhbHRzYWx0$AAAA",
        "$pbkdf2-sha256$1000 $c2FsdHNhbHRzYWx0$AAAA",
        "$pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0",
        // bcrypt malformed variants
        "$2y$",
        "$2y$10$",
        "$2y$10$short",
        "$2y$xx$abcdefghijklmnopqrstuv",
        "$2y$10$!!!!!!!!!!!!!!!!!!!!!!!!",
        "$2y$10$abcdefghijklmnopqrstuvextra$extra",
        "$2y$99$abcdefghijklmnopqrstuv",
        "$2a$10$notrealbcrypthashvaluehereok",
        "$2b$10$..............................",
        "$2y$abc$def",
    ];
    for bad in cases {
        let outcome = std::panic::catch_unwind(|| password::verify("password", bad));
        assert!(outcome.is_ok(), "verify({bad:?}) panicked");
        if let Ok(true) = outcome.unwrap() {
            panic!("verify({bad:?}) returned Ok(true)");
        }
    }
}
