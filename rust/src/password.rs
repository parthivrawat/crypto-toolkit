//! Password hashing, verification, and key derivation with safe defaults.

use std::str::FromStr;

use argon2::{Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version};
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// Options for password hashing and key derivation.
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
            time_cost: 3,
            memory_cost: 64 * 1024,
            parallelism: 4,
            output_length: 32,
            log_n: 14,
            r: 8,
            p: 1,
            cost: 12,
        }
    }
}

impl HashOptions {
    /// Validates that the cost parameters are internally consistent and
    /// above safe minimums. Called automatically by [`hash_with`] and
    /// [`derive`]; also usable standalone to check a hand-built struct.
    pub fn validate(&self) -> Result<()> {
        if self.iterations == 0 {
            return Err(Error::InvalidParameter(
                "iterations must be at least 1".to_string(),
            ));
        }
        if self.time_cost == 0 {
            return Err(Error::InvalidParameter(
                "argon2 time_cost must be at least 1".to_string(),
            ));
        }
        if self.parallelism == 0 {
            return Err(Error::InvalidParameter(
                "argon2 parallelism must be at least 1".to_string(),
            ));
        }
        // Argon2 requires memory >= 8 * parallelism (RFC 9106).
        if u64::from(self.memory_cost) < 8 * u64::from(self.parallelism) {
            return Err(Error::InvalidParameter(
                "argon2 memory_cost is too low for the requested parallelism".to_string(),
            ));
        }
        // scrypt requires 1 <= log_n < 64 and n = 2^log_n < 2^(128*r/8).
        if self.log_n == 0 || self.log_n >= 64 {
            return Err(Error::InvalidParameter(
                "scrypt log_n must be between 1 and 63".to_string(),
            ));
        }
        if self.r == 0 {
            return Err(Error::InvalidParameter(
                "scrypt r must be at least 1".to_string(),
            ));
        }
        if self.p == 0 {
            return Err(Error::InvalidParameter(
                "scrypt p must be at least 1".to_string(),
            ));
        }
        if self.output_length == 0 {
            return Err(Error::InvalidParameter(
                "output_length must be at least 1".to_string(),
            ));
        }
        // bcrypt accepts cost factors in [4, 31].
        if !(4..=31).contains(&self.cost) {
            return Err(Error::InvalidParameter(
                "bcrypt cost must be between 4 and 31".to_string(),
            ));
        }
        Ok(())
    }
}

fn opts_or_default(options: Option<&HashOptions>) -> HashOptions {
    let mut defaults = HashOptions::default();
    if let Some(o) = options {
        if o.iterations != 0 {
            defaults.iterations = o.iterations;
        }
        if o.time_cost != 0 {
            defaults.time_cost = o.time_cost;
        }
        if o.memory_cost != 0 {
            defaults.memory_cost = o.memory_cost;
        }
        if o.parallelism != 0 {
            defaults.parallelism = o.parallelism;
        }
        if o.output_length != 0 {
            defaults.output_length = o.output_length;
        }
        if o.log_n != 0 {
            defaults.log_n = o.log_n;
        }
        if o.r != 0 {
            defaults.r = o.r;
        }
        if o.p != 0 {
            defaults.p = o.p;
        }
        if o.cost != 0 {
            defaults.cost = o.cost;
        }
    }
    defaults
}

fn normalize_algorithm(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// Hash a password with the default algorithm (Argon2id).
pub fn hash(password: &str) -> Result<String> {
    hash_with(password, "argon2id", None)
}

/// Hash a password with a chosen algorithm and optional cost parameters.
pub fn hash_with(password: &str, algorithm: &str, options: Option<&HashOptions>) -> Result<String> {
    let algorithm = normalize_algorithm(algorithm);
    let opts = opts_or_default(options);
    opts.validate()?;
    match algorithm.as_str() {
        "argon2id" => hash_argon2id(password, &opts),
        "scrypt" => hash_scrypt(password, &opts),
        "pbkdf2-sha256" => hash_pbkdf2(password, &opts),
        "bcrypt" => hash_bcrypt(password, &opts),
        _ => Err(Error::UnsupportedAlgorithm(algorithm)),
    }
}

fn random_salt(len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn phc_b64(data: &[u8]) -> String {
    STANDARD_NO_PAD.encode(data)
}

fn phc_b64_decode(text: &str) -> Result<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(text)
        .map_err(|e| Error::Base64(e.to_string()))
}

fn ab64_encode(data: &[u8]) -> String {
    STANDARD
        .encode(data)
        .replace('+', ".")
        .trim_end_matches('=')
        .to_string()
}

fn ab64_decode(text: &str) -> Result<Vec<u8>> {
    let mut s = text.replace('.', "+");
    let pad = (4 - (s.len() % 4)) % 4;
    s.push_str(&"=".repeat(pad));
    STANDARD
        .decode(s)
        .map_err(|e| Error::Base64(e.to_string()))
}

fn hash_argon2id(password: &str, opts: &HashOptions) -> Result<String> {
    let salt = random_salt(16);
    let params = Argon2Params::new(
        opts.memory_cost,
        opts.time_cost,
        opts.parallelism,
        Some(opts.output_length),
    )
    .map_err(|e| Error::InvalidParameter(e.to_string()))?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; opts.output_length];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        opts.memory_cost,
        opts.time_cost,
        opts.parallelism,
        phc_b64(&salt),
        phc_b64(&out)
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
        "$scrypt$ln={},r={},p={}${}${}",
        opts.log_n,
        opts.r,
        opts.p,
        phc_b64(&salt),
        phc_b64(&out)
    ))
}

fn hash_pbkdf2(password: &str, opts: &HashOptions) -> Result<String> {
    let salt = random_salt(32);
    let mut out = vec![0u8; opts.output_length];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, opts.iterations, &mut out);
    Ok(format!(
        "$pbkdf2-sha256${}${}${}",
        opts.iterations,
        ab64_encode(&salt),
        ab64_encode(&out)
    ))
}

fn hash_bcrypt(password: &str, opts: &HashOptions) -> Result<String> {
    let cost = if opts.cost == 0 { 12 } else { opts.cost };
    bcrypt::hash(password, cost).map_err(|e| Error::Internal(e.to_string()))
}

/// Verify a password against a stored hash.
pub fn verify(password: &str, hashed: &str) -> Result<bool> {
    if hashed.starts_with("$argon2id$") {
        verify_argon2id(password, hashed)
    } else if hashed.starts_with("$scrypt$") {
        verify_scrypt(password, hashed)
    } else if hashed.starts_with("$pbkdf2-sha256$") {
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
    let params = parse_params(parts[3])?;
    let memory = u32::from_str(params.get("m").ok_or_else(|| Error::InvalidHashFormat("m".to_string()))?)
        .map_err(|_| Error::InvalidHashFormat("m".to_string()))?;
    let time = u32::from_str(params.get("t").ok_or_else(|| Error::InvalidHashFormat("t".to_string()))?)
        .map_err(|_| Error::InvalidHashFormat("t".to_string()))?;
    let parallelism = u32::from_str(params.get("p").ok_or_else(|| Error::InvalidHashFormat("p".to_string()))?)
        .map_err(|_| Error::InvalidHashFormat("p".to_string()))?;
    let salt = phc_b64_decode(parts[4])?;
    let stored = phc_b64_decode(parts[5])?;
    if salt.is_empty() || stored.is_empty() {
        return Err(Error::InvalidHashFormat(hashed.to_string()));
    }

    let params = Argon2Params::new(memory, time, parallelism, Some(stored.len()))
        .map_err(|e| Error::InvalidParameter(e.to_string()))?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; stored.len()];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(out.as_slice().ct_eq(stored.as_slice()).into())
}

fn verify_scrypt(password: &str, hashed: &str) -> Result<bool> {
    let parts: Vec<&str> = hashed.split('$').collect();
    if parts.len() != 5 {
        return Err(Error::InvalidHashFormat(hashed.to_string()));
    }
    let params = parse_params(parts[2])?;
    let log_n = u8::from_str(params.get("ln").ok_or_else(|| Error::InvalidHashFormat("ln".to_string()))?)
        .map_err(|_| Error::InvalidHashFormat("ln".to_string()))?;
    let r = u32::from_str(params.get("r").ok_or_else(|| Error::InvalidHashFormat("r".to_string()))?)
        .map_err(|_| Error::InvalidHashFormat("r".to_string()))?;
    let p = u32::from_str(params.get("p").ok_or_else(|| Error::InvalidHashFormat("p".to_string()))?)
        .map_err(|_| Error::InvalidHashFormat("p".to_string()))?;
    let salt = phc_b64_decode(parts[3])?;
    let stored = phc_b64_decode(parts[4])?;
    if salt.is_empty() || stored.is_empty() {
        return Err(Error::InvalidHashFormat(hashed.to_string()));
    }

    let params = ScryptParams::new(log_n, r, p, stored.len())
        .map_err(|e| Error::InvalidParameter(e.to_string()))?;
    let mut out = vec![0u8; stored.len()];
    scrypt(password.as_bytes(), &salt, &params, &mut out)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(out.as_slice().ct_eq(stored.as_slice()).into())
}

fn verify_pbkdf2(password: &str, hashed: &str) -> Result<bool> {
    let parts: Vec<&str> = hashed.split('$').collect();
    if parts.len() != 5 {
        return Err(Error::InvalidHashFormat(hashed.to_string()));
    }
    let iterations = u32::from_str(parts[2])
        .map_err(|_| Error::InvalidHashFormat("iterations".to_string()))?;
    let salt = ab64_decode(parts[3])?;
    let stored = ab64_decode(parts[4])?;
    if salt.is_empty() || stored.is_empty() {
        return Err(Error::InvalidHashFormat(hashed.to_string()));
    }

    let mut out = vec![0u8; stored.len()];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut out);
    Ok(out.as_slice().ct_eq(stored.as_slice()).into())
}

fn parse_params(s: &str) -> Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    for pair in s.split(',') {
        let mut kv = pair.splitn(2, '=');
        let k = kv.next().ok_or_else(|| Error::InvalidHashFormat(s.to_string()))?;
        let v = kv.next().ok_or_else(|| Error::InvalidHashFormat(s.to_string()))?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

/// Derive a key from a passphrase and salt.
pub fn derive(
    passphrase: &str,
    salt: &[u8],
    length: usize,
    algorithm: Option<&str>,
    options: Option<&HashOptions>,
) -> Result<Vec<u8>> {
    if salt.is_empty() {
        return Err(Error::InvalidParameter("salt must not be empty".to_string()));
    }
    if length == 0 {
        return Err(Error::InvalidParameter("length must be positive".to_string()));
    }

    let algorithm = normalize_algorithm(algorithm.unwrap_or("pbkdf2_sha256"));
    let opts = opts_or_default(options);
    opts.validate()?;

    match algorithm.as_str() {
        "pbkdf2-sha256" => {
            let mut out = vec![0u8; length];
            pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, opts.iterations, &mut out);
            Ok(out)
        }
        "scrypt" => {
            let params = ScryptParams::new(opts.log_n, opts.r, opts.p, length)
                .map_err(|e| Error::InvalidParameter(e.to_string()))?;
            let mut out = vec![0u8; length];
            scrypt(passphrase.as_bytes(), salt, &params, &mut out)
                .map_err(|e| Error::Internal(e.to_string()))?;
            Ok(out)
        }
        "argon2id" => {
            let params = Argon2Params::new(
                opts.memory_cost,
                opts.time_cost,
                opts.parallelism,
                Some(length),
            )
            .map_err(|e| Error::InvalidParameter(e.to_string()))?;
            let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
            let mut out = vec![0u8; length];
            argon2
                .hash_password_into(passphrase.as_bytes(), salt, &mut out)
                .map_err(|e| Error::Internal(e.to_string()))?;
            Ok(out)
        }
        _ => Err(Error::UnsupportedAlgorithm(algorithm)),
    }
}
