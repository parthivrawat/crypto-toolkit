/**
 * Deterministic hashing and HMAC with safe, modern defaults.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import { AlgorithmError } from './errors';

export { AlgorithmError };

const ALLOWED_HASH = new Set([
  'sha-256',
  'sha-384',
  'sha-512',
  'sha3-256',
  'sha3-384',
  'sha3-512',
  'blake2b',
  'blake2s',
]);

const HASH_NAME: Record<string, string> = {
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512',
  'sha3-256': 'sha3-256',
  'sha3-384': 'sha3-384',
  'sha3-512': 'sha3-512',
  'blake2b': 'blake2b512',
  'blake2s': 'blake2s256',
};

function normalize(algorithm: string): string {
  const name = algorithm.toLowerCase().replace(/_/g, '-');
  if (!ALLOWED_HASH.has(name)) {
    throw new AlgorithmError(`Unsupported or unsafe hashing algorithm: ${algorithm}`);
  }
  return HASH_NAME[name];
}

function toBuffer(data: string | Buffer | Uint8Array): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  return Buffer.from(data, 'utf-8');
}

/**
 * Return a safe, deterministic hash of `data` as a hex string.
 */
export function string(data: string | Buffer | Uint8Array, algorithm = 'sha-256'): string {
  return crypto.createHash(normalize(algorithm)).update(toBuffer(data)).digest('hex');
}

/**
 * Return the hash of a file as a hex string.
 */
export function file(
  path: string,
  algorithm = 'sha-256',
  blockSize = 8192
): string {
  const digestmod = normalize(algorithm);
  const hash = crypto.createHash(digestmod);
  const fd = fs.openSync(path, 'r');
  try {
    const buf = Buffer.alloc(blockSize);
    let read = 0;
    while ((read = fs.readSync(fd, buf, 0, blockSize, null)) > 0) {
      hash.update(buf.subarray(0, read));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

/**
 * Return an HMAC of `data` as a hex string.
 */
export function hmac(
  key: string | Buffer | Uint8Array,
  data: string | Buffer | Uint8Array,
  algorithm = 'sha-256'
): string {
  return crypto
    .createHmac(normalize(algorithm), toBuffer(key))
    .update(toBuffer(data))
    .digest('hex');
}

/**
 * Verify an HMAC in constant time.
 */
export function verifyHmac(
  mac: string,
  key: string | Buffer | Uint8Array,
  data: string | Buffer | Uint8Array,
  algorithm = 'sha-256'
): boolean {
  const expected = hmac(key, data, algorithm);
  const a = Buffer.from(mac, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
