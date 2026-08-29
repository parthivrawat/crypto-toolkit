/**
 * Password hashing, verification, and key derivation with safe defaults.
 */

import * as crypto from 'crypto';
import { AlgorithmError, InvalidKeyError } from './errors';

export { AlgorithmError, InvalidKeyError };

const PBKDF2_DEFAULT_ITERATIONS = 100_000;
const SCRYPT_DEFAULT_N = 16384;
const SCRYPT_DEFAULT_R = 8;
const SCRYPT_DEFAULT_P = 1;
const SCRYPT_DEFAULT_DKLEN = 64;

export interface HashOptions {
  iterations?: number;
  N?: number;
  r?: number;
  p?: number;
  dklen?: number;
  maxmem?: number;
}

function parseScrypt(hash: string): [number, number, number, Buffer, Buffer] {
  const parts = hash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') {
    throw new Error('Invalid scrypt hash format');
  }
  return [
    parseInt(parts[1], 10),
    parseInt(parts[2], 10),
    parseInt(parts[3], 10),
    Buffer.from(parts[4], 'base64'),
    Buffer.from(parts[5], 'base64'),
  ];
}

function parsePBKDF2(hash: string): [number, Buffer, Buffer] {
  const parts = hash.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha256') {
    throw new Error('Invalid PBKDF2 hash format');
  }
  return [
    parseInt(parts[1], 10),
    Buffer.from(parts[2], 'base64'),
    Buffer.from(parts[3], 'base64'),
  ];
}

/**
 * Hash a password with PBKDF2-SHA256 or scrypt.
 */
export function hash(
  password: string,
  algorithm: 'pbkdf2_sha256' | 'scrypt' = 'scrypt',
  options: HashOptions = {}
): string {
  const salt = crypto.randomBytes(32);

  if (algorithm === 'scrypt') {
    const N = options.N ?? SCRYPT_DEFAULT_N;
    const r = options.r ?? SCRYPT_DEFAULT_R;
    const p = options.p ?? SCRYPT_DEFAULT_P;
    const dklen = options.dklen ?? SCRYPT_DEFAULT_DKLEN;
    const maxmem = options.maxmem ?? 32 * 1024 * 1024;
    const derived = crypto.scryptSync(password, salt, dklen, { N, r, p, maxmem });
    return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${derived.toString('base64')}`;
  }

  const iterations = options.iterations ?? PBKDF2_DEFAULT_ITERATIONS;
  const derived = crypto.pbkdf2Sync(
    password,
    salt,
    iterations,
    64,
    'sha256'
  );
  return `pbkdf2_sha256$${iterations}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

/**
 * Verify a password against a hash in constant time.
 */
export function verify(password: string, hashed: string): boolean {
  try {
    if (hashed.startsWith('scrypt$')) {
      const [N, r, p, salt, stored] = parseScrypt(hashed);
      const derived = crypto.scryptSync(password, salt, stored.length, { N, r, p });
      if (derived.length !== stored.length) return false;
      return crypto.timingSafeEqual(derived, stored);
    }

    if (hashed.startsWith('pbkdf2_sha256$')) {
      const [iterations, salt, stored] = parsePBKDF2(hashed);
      const derived = crypto.pbkdf2Sync(password, salt, iterations, stored.length, 'sha256');
      if (derived.length !== stored.length) return false;
      return crypto.timingSafeEqual(derived, stored);
    }
  } catch {
    return false;
  }
  return false;
}

/**
 * Derive a key from a passphrase and salt.
 */
export function derive(
  passphrase: string,
  salt: Buffer,
  length: number,
  algorithm: 'pbkdf2_sha256' | 'scrypt' = 'pbkdf2_sha256',
  options: HashOptions = {}
): Buffer {
  if (!salt || salt.length === 0) throw new InvalidKeyError('A non-empty salt is required for key derivation');
  if (length < 1) throw new AlgorithmError('length must be a positive integer');

  if (algorithm === 'scrypt') {
    const N = options.N ?? SCRYPT_DEFAULT_N;
    const r = options.r ?? SCRYPT_DEFAULT_R;
    const p = options.p ?? SCRYPT_DEFAULT_P;
    const maxmem = options.maxmem ?? 32 * 1024 * 1024;
    return crypto.scryptSync(passphrase, salt, length, { N, r, p, maxmem });
  }

  const iterations = options.iterations ?? PBKDF2_DEFAULT_ITERATIONS;
  return crypto.pbkdf2Sync(passphrase, salt, iterations, length, 'sha256');
}
