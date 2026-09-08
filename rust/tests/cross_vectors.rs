use modern_crypto_toolkit::password::HashOptions;
use modern_crypto_toolkit::{encrypt, hash, password, sign};

const PBKDF2_VECTOR: &str = "$pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$NQw0IIbZMo3k82KG1TAVtju63YeHXZMliByZZ4DKD9o";
const SCRYPT_VECTOR: &str = "$scrypt$ln=10,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$KXXf8GmVmUQTGZ9L0BWzp7rywGFqGVKQ+kazyyuoqFM";

const MSG: &str = "cross-language-test";
const SALT: &[u8] = b"saltsaltsaltsaltsaltsaltsaltsalt"; // 32 bytes

#[test]
fn test_verify_cross_language_pbkdf2_vector() {
    assert!(password::verify(MSG, PBKDF2_VECTOR).unwrap());
}

#[test]
fn test_verify_cross_language_scrypt_vector() {
    assert!(password::verify(MSG, SCRYPT_VECTOR).unwrap());
}

#[test]
fn test_verify_wrong_password_against_vectors() {
    assert!(!password::verify("wrong-password", PBKDF2_VECTOR).unwrap());
    assert!(!password::verify("wrong-password", SCRYPT_VECTOR).unwrap());
}

// ---------------------------------------------------------------------------
// Hashing vectors
// ---------------------------------------------------------------------------

#[test]
fn test_cross_language_sha256() {
    let got = hash::string(MSG, "sha-256").unwrap();
    assert_eq!(
        got,
        "8de4271480b58aedac9d059165faa03bf42062f77ae9196f0932f2ab9994c96e"
    );
}

#[test]
fn test_cross_language_hmac_sha256() {
    let got = hash::hmac(b"cross-language-key", b"cross-language-test", "sha-256").unwrap();
    assert_eq!(
        got,
        "9d67f44518758c0e736fa7961cbe9d5f5bd2dde2ee85867b01b7e9cbfdb8e4c5"
    );
}

// ---------------------------------------------------------------------------
// Key-derivation vectors
// ---------------------------------------------------------------------------

#[test]
fn test_cross_language_derive_pbkdf2() {
    let out = password::derive(
        MSG,
        SALT,
        32,
        Some("pbkdf2_sha256"),
        Some(&HashOptions {
            iterations: 1000,
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(
        hex::encode(out),
        "350c342086d9328de4f36286d53015b63bbadd87875d9325881c996780ca0fda"
    );
}

#[test]
fn test_cross_language_derive_scrypt() {
    let out = password::derive(
        MSG,
        SALT,
        32,
        Some("scrypt"),
        Some(&HashOptions {
            log_n: 10,
            r: 8,
            p: 1,
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(
        hex::encode(out),
        "2975dff06995994413199f4bd015b3a7baf2c0616a195290fa46b3cb2ba8a853"
    );
}

#[test]
fn test_cross_language_derive_argon2id() {
    let out = password::derive(
        MSG,
        SALT,
        32,
        Some("argon2id"),
        Some(&HashOptions {
            time_cost: 3,
            memory_cost: 65536,
            parallelism: 4,
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(
        hex::encode(out),
        "4495c94ca3852576fa10b1ee381c3742f7aaf152499bd42be93b59427fca331c"
    );
}

// ---------------------------------------------------------------------------
// Encryption token vectors (v2 format)
// ---------------------------------------------------------------------------

fn vector_key() -> Vec<u8> {
    hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .unwrap()
}

#[test]
fn test_cross_language_decrypt_aes256gcm_token() {
    let token = hex::decode(
        "020100007437945cda0539277c709cf7e0fb65ec51a3771fa6d2cba682cb9326194759aa3f8874d8663d3140d81fc020b807aa",
    )
    .unwrap();
    let pt = encrypt::decrypt(&token, &vector_key(), None).unwrap();
    assert_eq!(pt, b"cross-language-test");
}

#[test]
fn test_cross_language_decrypt_chacha20_token() {
    let token = hex::decode(
        "020200008676258015ff452777b5af24cae1327aacf84a42bf66cb5db3160557782b15d330fa33de6b5d7dc9169377c183e30f",
    )
    .unwrap();
    let pt = encrypt::decrypt(&token, &vector_key(), None).unwrap();
    assert_eq!(pt, b"cross-language-test");
}

#[test]
fn test_cross_language_decrypt_aad_token() {
    let token = hex::decode(
        "0201000e766563746f722d636f6e746578747f436a5f29c8ff2d66c01fe330f582ecb37d3abc041f46ffa88d9eab1639c59d5570e5cbaec07eaa77be7c3ce8ae8b",
    )
    .unwrap();
    let aad = b"vector-context";
    let pt = encrypt::decrypt(&token, &vector_key(), Some(aad.as_slice())).unwrap();
    assert_eq!(pt, b"cross-language-test");

    // Wrong AAD must fail, and so must missing AAD.
    assert!(encrypt::decrypt(&token, &vector_key(), Some(b"wrong-context".as_slice())).is_err());
    assert!(encrypt::decrypt(&token, &vector_key(), None).is_err());
}

// ---------------------------------------------------------------------------
// Ed25519 vector (deterministic)
// ---------------------------------------------------------------------------

#[test]
fn test_cross_language_ed25519_vector() {
    let seed = hex::decode("d177524e40ee195afe206345792e20c8117c8254f2ce98ee45589625f89fc4b8")
        .unwrap();
    let expected_pub =
        hex::decode("a3b599b8cef3428956452bf75a445860958633aa3bf0c4160a09e6c0fcba2463")
            .unwrap();
    let expected_sig = hex::decode(
        "8b0dd73d7644c49c208398874ce6cdfc98a49a7c05fc613dc5be9382c10bbdd43da9466d6f10646c72d9d5adea33e8f15c3349fab5478d58400fcf93db0f0b09",
    )
    .unwrap();

    let sig = sign::ed25519(MSG, &seed).unwrap();
    assert_eq!(sig, expected_sig);

    // The seed must correspond to the published public key.
    let pk_pem = sign::public_key_to_pem(&expected_pub).unwrap();
    let pk = sign::public_key_from_pem(&pk_pem).unwrap();
    assert!(sign::verify(&sig, MSG, &pk).unwrap());
    assert!(sign::verify(&sig, MSG, &expected_pub).unwrap());
    assert!(!sign::verify(&sig, "cross-language-tesT", &expected_pub).unwrap());
}
