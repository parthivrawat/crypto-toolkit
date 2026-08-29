//! Password hashing, verification, and key derivation with safe defaults.

use std::str::FromStr;

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// Options for password hashing.
#[derive(Clone, Debug)]
pub struct HashOptions {
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Argon2 time cost.
    pub time_cost: u32,
    /// Argon2 memory cost in KiB.
    pub memory_cost: u32,
    /// Argon2 parallelism.
    pub parallelism: u32,
    /// Derived key length in bytes.
    pub output_length: usize,
    /// scrypt log₂(N).
    pub log_n: u8,
    /// scrypt block size parameter.
    pub r: u32,
    /// scrypt parallelization parameter.
    pub p: u32,
    /// bcrypt cost factor.
    pub cost: u32,
}

impl Default for HashOptions {
    fn default() -> Self {
        Self {
            iterations: 100_000,
            time_cost: 2,
            memory_cost: 64 * 1024,
            parallelism: 1,
            output_length: 32,
            log_n: 14,
            r: 8,
            p: 1,
            cost: 12,
        }
    }
}

fn opts_or_default(options: Option<&HashOptions>) -> HashOptions {
    options.cloned().unwrap_or_default()
}

/// Hash a password with the default algorithm (Argon2id).
pub fn hash(password: &str) -> Result<String> {
    hash_with(password, "argon2id", None)
}

/// Hash a password with a chosen algorithm and optional cost parameters.
pub fn hash_with(password: &str, algorithm: &str, options: Option<&HashOptions>) -> Result<String> {
    let opts = opts_or_default(options);
    match algorithm.to_lowercase().as_str() {
        "argon2id" => hash_argon2id(password, &opts),
        "scrypt" => hash_scrypt(password, &opts),
        "pbkdf2_sha256" | "pbkdf2" => hash_pbkdf2(password, &opts),
        "bcrypt" => hash_bcrypt(password, &opts),
        _ => Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

fn random_salt(len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn hash_argon2id(password: &str, opts: &HashOptions) -> Result<String> {
    let salt = random_salt(16);
    let params = Argon2Params::new(
        opts.memory_cost,
        opts.time_cost,
        opts.parallelism as u32,
        Some(opts.output_length),
    )
    .map_err(|e| Error::InvalidParameter(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; opts.output_length];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(format!(
        "argon2id${}${}${}${}${}",
        opts.time_cost,
        opts.memory_cost,
        opts.parallelism,
        STANDARD.encode(&salt),
        STANDARD.encode(&out)
    ))
}

fn hash_scrypt(password: &str, opts: &HashOptions) -> Result<String> {
    let salt = random_salt(32);
    let params = ScryptParams::new(opts.log_n, opts.r, opts.p, opts.output_length)
        .map_err(|e| Error::InvalidParameter(e.to_string()))?;
    let mut out = vec![0u8; opts.output_length];
    scrypt(password.as_bytes(), &salt, &params, &mut out)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(format!(
        "scrypt${}${}${}${}${}",
        opts.log_n,
        opts.r,
        opts.p,
        STANDARD.encode(&salt),
        STANDARD.encode(&out)
    ))
}

fn hash_pbkdf2(password: &str, opts: &HashOptions) -> Result<String> {
    let salt = random_salt(32);
    let mut out = vec![0u8; opts.output_length];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, opts.iterations, &mut out);
    Ok(format!(
        "pbkdf2_sha256${}${}${}",
        opts.iterations,
        STANDARD.encode(&salt),
        STANDARD.encode(&out)
    ))
}

fn hash_bcrypt(password: &str, opts: &HashOptions) -> Result<String> {
    let cost = if opts.cost == 0 { 12 } else { opts.cost };
    bcrypt::hash(password, cost).map_err(|e| Error::Internal(e.to_string()))
}

/// Verify a password against a stored hash.
pub fn verify(password: &str, hashed: &str) -> Result<bool> {
    if hashed.starts_with("argon2id$") {
        verify_argon2id(password, hashed)
    } else if hashed.starts_with("scrypt$") {
        verify_scrypt(password, hashed)
    } else if hashed.starts_with("pbkdf2_sha256$") {
        verify_pbkdf2(password, hashed)
    } else if hashed.starts_with("$2a$") || hashed.starts_with("$2b$") || hashed.starts_with("$2y$") {
        bcrypt::verify(password, hashed).map_err(|e| Error::Internal(e.to_string()))
    } else {
        Err(Error::InvalidHashFormat(hashed.to_string()))
    }
}

fn verify_argon2id(password: &str, hashed: &str) -> Result<bool> {
    let parts: Vec<&str> = hashed.split('$').collect();
    if parts.len() != 6 {
        return Err(Error::InvalidHashFormat(hashed.to_string()));
    }
    let time = u32::from_str(parts[1]).map_err(|_| Error::InvalidHashFormat("time".to_string()))?;
    let memory = u32::from_str(parts[2]).map_err(|_| Error::InvalidHashFormat("memory".to_string()))?;
    let parallelism = u32::from_str(parts[3])
        .map_err(|_| Error::InvalidHashFormat("parallelism".to_string()))?;
    let salt = STANDARD.decode(parts[4]).map_err(|e| Error::Base64(e.to_string()))?;
    let stored = STANDARD.decode(parts[5]).map_err(|e| Error::Base64(e.to_string()))?;

    let params = Argon2Params::new(memory, time, parallelism, Some(stored.len()))
        .map_err(|e| Error::InvalidParameter(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; stored.len()];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(out.as_slice().ct_eq(stored.as_slice()).into())
}

fn verify_scrypt(password: &str, hashed: &str) -> Result<bool> {
    let parts: Vec<&str> = hashed.split('$').collect();
    if parts.len() != 6 {
        return Err(Error::InvalidHashFormat(hashed.to_string()));
    }
    let log_n = u8::from_str(parts[1]).map_err(|_| Error::InvalidHashFormat("log_n".to_string()))?;
    let r = u32::from_str(parts[2]).map_err(|_| Error::InvalidHashFormat("r".to_string()))?;
    let p = u32::from_str(parts[3]).map_err(|_| Error::InvalidHashFormat("p".to_string()))?;
    let salt = STANDARD.decode(parts[4]).map_err(|e| Error::Base64(e.to_string()))?;
    let stored = STANDARD.decode(parts[5]).map_err(|e| Error::Base64(e.to_string()))?;

    let params = ScryptParams::new(log_n, r, p, stored.len())
        .map_err(|e| Error::InvalidParameter(e.to_string()))?;
    let mut out = vec![0u8; stored.len()];
    scrypt(password.as_bytes(), &salt, &params, &mut out)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(out.as_slice().ct_eq(stored.as_slice()).into())
}

fn verify_pbkdf2(password: &str, hashed: &str) -> Result<bool> {
    let parts: Vec<&str> = hashed.split('$').collect();
    if parts.len() != 4 {
        return Err(Error::InvalidHashFormat(hashed.to_string()));
    }
    let iterations = u32::from_str(parts[1])
        .map_err(|_| Error::InvalidHashFormat("iterations".to_string()))?;
    let salt = STANDARD.decode(parts[2]).map_err(|e| Error::Base64(e.to_string()))?;
    let stored = STANDARD.decode(parts[3]).map_err(|e| Error::Base64(e.to_string()))?;

    let mut out = vec![0u8; stored.len()];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut out);
    Ok(out.as_slice().ct_eq(stored.as_slice()).into())
}

/// Derive a key from a passphrase and salt.
///
/// `algorithm` may be `"pbkdf2_sha256"` or `"scrypt"`. It defaults to PBKDF2-SHA256.
pub fn derive(
    passphrase: &str,
    salt: &[u8],
    length: usize,
    algorithm: Option<&str>,
) -> Result<Vec<u8>> {
    if salt.is_empty() {
        return Err(Error::InvalidParameter("salt must not be empty".to_string()));
    }
    if length == 0 {
        return Err(Error::InvalidParameter("length must be positive".to_string()));
    }

    match algorithm.unwrap_or("pbkdf2_sha256").to_lowercase().as_str() {
        "pbkdf2_sha256" | "pbkdf2" => {
            let mut out = vec![0u8; length];
            pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, 100_000, &mut out);
            Ok(out)
        }
        "scrypt" => {
            let params = ScryptParams::new(14, 8, 1, length)
                .map_err(|e| Error::InvalidParameter(e.to_string()))?;
            let mut out = vec![0u8; length];
            scrypt(passphrase.as_bytes(), salt, &params, &mut out)
                .map_err(|e| Error::Internal(e.to_string()))?;
            Ok(out)
        }
        _ => Err(Error::UnsupportedAlgorithm(
            algorithm.unwrap_or("pbkdf2_sha256").to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_hash_and_verify() {
        let h = hash_with(
            "user-password",
            "pbkdf2_sha256",
            Some(&HashOptions {
                iterations: 1000,
                ..Default::default()
            }),
        )
        .unwrap();
        assert!(h.starts_with("pbkdf2_sha256$"));
        assert!(verify("user-password", &h).unwrap());
        assert!(!verify("wrong", &h).unwrap());
    }

    #[test]
    fn test_derive() {
        let salt = b"saltsaltsaltsalt";
        let key1 = derive("passphrase", salt, 32, None).unwrap();
        let key2 = derive("passphrase", salt, 32, None).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_requires_salt() {
        assert!(derive("passphrase", b"", 32, None).is_err());
    }
}
