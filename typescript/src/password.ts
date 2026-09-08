/**
 * Password hashing, verification, and key derivation with safe defaults.
 */

import * as crypto from 'crypto';
import { AlgorithmError, InvalidKeyError, MissingDependencyError } from './errors';

export { AlgorithmError, InvalidKeyError, MissingDependencyError };

const PBKDF2_DEFAULT_ITERATIONS = 100_000;
const SCRYPT_DEFAULT_N = 16384;
const SCRYPT_DEFAULT_R = 8;
const SCRYPT_DEFAULT_P = 1;
const SCRYPT_DEFAULT_DKLEN = 32;
const SCRYPT_DEFAULT_MAXMEM = 64 * 1024 * 1024;
const ARGON2_VERSION = 0x13;

let _bcrypt: any;

try {
  _bcrypt = require('bcrypt');
} catch {
  _bcrypt = null;
}

const _HAS_ARGON2 = typeof (crypto as any).argon2Sync === 'function';
const _SCRYPT_AVAILABLE = typeof (crypto as any).scryptSync === 'function';
const _DEFAULT = _HAS_ARGON2 ? 'argon2id' : (_SCRYPT_AVAILABLE ? 'scrypt' : 'pbkdf2_sha256');

const _ALLOWED = new Set(['argon2id', 'scrypt', 'bcrypt', 'pbkdf2-sha256']);

export interface HashOptions {
  iterations?: number;
  N?: number;
  r?: number;
  p?: number;
  dklen?: number;
  maxmem?: number;
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
  rounds?: number;
}

function toBuffer(value: string | Buffer | Uint8Array): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return Buffer.from(value, 'utf-8');
}

function phcB64Encode(data: Buffer): string {
  return data.toString('base64').replace(/=+$/g, '');
}

function phcB64Decode(text: string): Buffer {
  const pad = (4 - (text.length % 4)) % 4;
  return Buffer.from(text + '='.repeat(pad), 'base64');
}

function ab64Encode(data: Buffer): string {
  return data.toString('base64').replace(/\+/g, '.').replace(/=+$/g, '');
}

function ab64Decode(text: string): Buffer {
  const s = text.replace(/\./g, '+') + '='.repeat((4 - (text.length % 4)) % 4);
  return Buffer.from(s, 'base64');
}

function normalizeAlgorithm(algorithm?: string): string {
  const name = (algorithm ?? _DEFAULT).toLowerCase().replace(/_/g, '-');
  if (!_ALLOWED.has(name)) {
    throw new AlgorithmError(`Unsupported password algorithm: ${algorithm}`);
  }
  return name;
}

function resolveOptions(algorithm: string, options: HashOptions): Required<HashOptions> {
  const defaults: HashOptions = {
    iterations: PBKDF2_DEFAULT_ITERATIONS,
    N: SCRYPT_DEFAULT_N,
    r: SCRYPT_DEFAULT_R,
    p: SCRYPT_DEFAULT_P,
    dklen: SCRYPT_DEFAULT_DKLEN,
    maxmem: SCRYPT_DEFAULT_MAXMEM,
    timeCost: 3,
    memoryCost: 65536,
    parallelism: 4,
    rounds: 12,
  };

  if (algorithm === 'pbkdf2-sha256' || algorithm === 'argon2id' || algorithm === 'scrypt' || algorithm === 'bcrypt') {
    defaults.dklen = 32;
  }

  return { ...defaults, ...options } as Required<HashOptions>;
}

/**
 * Hash a password. Default algorithm is `argon2id` when the platform provides
 * `crypto.argon2Sync` (Node >= 23.6), otherwise `scrypt`, otherwise
 * `pbkdf2_sha256`. Pass `algorithm` explicitly to pin a specific one.
 */
export function hash(password: string, algorithm?: string, options: HashOptions = {}): string {
  const algo = normalizeAlgorithm(algorithm);
  const opts = resolveOptions(algo, options);

  if (algo === 'argon2id') {
    if (!_HAS_ARGON2) {
      throw new MissingDependencyError(
        'Argon2id requires Node.js crypto.argon2Sync (Node >= 23.6)'
      );
    }
    const salt = crypto.randomBytes(16);
    const derived = (crypto as any).argon2Sync('argon2id', {
      message: Buffer.from(password, 'utf-8'),
      nonce: salt,
      parallelism: opts.parallelism,
      tagLength: opts.dklen,
      memory: opts.memoryCost,
      passes: opts.timeCost,
      version: ARGON2_VERSION,
    }) as Buffer;
    return `$argon2id$v=19$m=${opts.memoryCost},t=${opts.timeCost},p=${opts.parallelism}$${phcB64Encode(salt)}$${phcB64Encode(derived)}`;
  }

  if (algo === 'bcrypt') {
    if (!_bcrypt) {
      throw new MissingDependencyError(
        'bcrypt requires the bcrypt package. Install: npm install bcrypt'
      );
    }
    return _bcrypt.hashSync(password, opts.rounds);
  }

  if (algo === 'scrypt') {
    if (!_SCRYPT_AVAILABLE) {
      throw new MissingDependencyError('scrypt is not available on this platform');
    }
    const salt = crypto.randomBytes(32);
    const N = opts.N;
    const r = opts.r;
    const p = opts.p;
    const dklen = opts.dklen;
    const maxmem = opts.maxmem;
    const ln = Math.log2(N);
    if (Math.floor(ln) !== ln) {
      throw new AlgorithmError('scrypt N must be a power of two');
    }
    const derived = (crypto as any).scryptSync(password, salt, dklen, { N, r, p, maxmem });
    return `$scrypt$ln=${Math.round(ln)},r=${r},p=${p}$${phcB64Encode(salt)}$${phcB64Encode(derived)}`;
  }

  // pbkdf2_sha256
  const iterations = opts.iterations;
  const salt = crypto.randomBytes(32);
  const derived = crypto.pbkdf2Sync(password, salt, iterations, opts.dklen, 'sha256');
  return `$pbkdf2-sha256$${iterations}$${ab64Encode(salt)}$${ab64Encode(derived)}`;
}

export function hash_with(password: string, algorithm: string, options: HashOptions = {}): string {
  return hash(password, algorithm, options);
}

export function verify(password: string, hashed: string): boolean {
  try {
    if (hashed.startsWith('$argon2id$')) {
      if (!_HAS_ARGON2) return false;
      const parts = hashed.split('$');
      if (parts.length !== 6) return false;
      const params: Record<string, string> = {};
      parts[3].split(',').forEach((pair) => {
        const [k, v] = pair.split('=');
        params[k] = v;
      });
      const memory = parseInt(params.m, 10);
      const time = parseInt(params.t, 10);
      const parallelism = parseInt(params.p, 10);
      const salt = phcB64Decode(parts[4]);
      const stored = phcB64Decode(parts[5]);
      if (salt.length === 0 || stored.length === 0) return false;
      const derived = (crypto as any).argon2Sync('argon2id', {
        message: Buffer.from(password, 'utf-8'),
        nonce: salt,
        parallelism,
        tagLength: stored.length,
        memory,
        passes: time,
        version: ARGON2_VERSION,
      }) as Buffer;
      return crypto.timingSafeEqual(derived, stored);
    }

    if (hashed.startsWith('$2a$') || hashed.startsWith('$2b$') || hashed.startsWith('$2y$')) {
      if (!_bcrypt) return false;
      return _bcrypt.compareSync(password, hashed);
    }

    if (hashed.startsWith('$scrypt$')) {
      if (!_SCRYPT_AVAILABLE) return false;
      const parts = hashed.split('$');
      if (parts.length !== 5) return false;
      const params: Record<string, string> = {};
      parts[2].split(',').forEach((pair) => {
        const [k, v] = pair.split('=');
        params[k] = v;
      });
      const ln = parseInt(params.ln, 10);
      const r = parseInt(params.r, 10);
      const p = parseInt(params.p, 10);
      const salt = phcB64Decode(parts[3]);
      const stored = phcB64Decode(parts[4]);
      if (salt.length === 0 || stored.length === 0) return false;
      const derived = (crypto as any).scryptSync(
        password,
        salt,
        stored.length,
        { N: 2 ** ln, r, p, maxmem: 0 }
      );
      return crypto.timingSafeEqual(derived, stored);
    }

    if (hashed.startsWith('$pbkdf2-sha256$')) {
      const parts = hashed.split('$');
      if (parts.length !== 5) return false;
      const iterations = parseInt(parts[2], 10);
      const salt = ab64Decode(parts[3]);
      const stored = ab64Decode(parts[4]);
      if (salt.length === 0 || stored.length === 0) return false;
      const derived = crypto.pbkdf2Sync(password, salt, iterations, stored.length, 'sha256');
      return crypto.timingSafeEqual(derived, stored);
    }
  } catch {
    return false;
  }
  return false;
}

export function derive(
  passphrase: string | Buffer | Uint8Array,
  salt: Buffer,
  length: number,
  algorithm = 'pbkdf2_sha256',
  options: HashOptions = {}
): Buffer {
  if (!salt || salt.length === 0) {
    throw new InvalidKeyError('A non-empty salt is required for key derivation');
  }
  if (length < 1) {
    throw new InvalidKeyError('length must be a positive integer');
  }

  const p = toBuffer(passphrase);
  const algo = normalizeAlgorithm(algorithm);
  const opts = resolveOptions(algo, options);

  if (algo === 'pbkdf2-sha256') {
    return crypto.pbkdf2Sync(p, salt, opts.iterations, length, 'sha256');
  }

  if (algo === 'scrypt') {
    if (!_SCRYPT_AVAILABLE) {
      throw new MissingDependencyError('scrypt is not available on this platform');
    }
    return (crypto as any).scryptSync(p, salt, length, {
      N: opts.N,
      r: opts.r,
      p: opts.p,
      maxmem: opts.maxmem,
    });
  }

  if (algo === 'argon2id') {
    if (!_HAS_ARGON2) {
      throw new MissingDependencyError(
        'Argon2id requires Node.js crypto.argon2Sync (Node >= 23.6)'
      );
    }
    return (crypto as any).argon2Sync('argon2id', {
      message: p,
      nonce: salt,
      parallelism: opts.parallelism,
      tagLength: length,
      memory: opts.memoryCost,
      passes: opts.timeCost,
      version: ARGON2_VERSION,
    }) as Buffer;
  }

  throw new AlgorithmError(`Unsupported key derivation algorithm: ${algorithm}`);
}
