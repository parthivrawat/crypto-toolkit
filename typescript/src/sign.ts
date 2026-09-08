/**
 * Digital signatures (Ed25519).
 */

import * as crypto from 'crypto';
import { AlgorithmError, InvalidKeyError, SignatureError } from './errors';

export { AlgorithmError, InvalidKeyError, SignatureError };

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

export interface RawKeyPair {
  /** 64-byte raw private key (32-byte seed || 32-byte public key). */
  privateKey: Buffer;
  /** 32-byte raw public key. */
  publicKey: Buffer;
}

function toBuffer(data: string | Buffer | Uint8Array): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  return Buffer.from(data, 'utf-8');
}

function b64url(buffer: Buffer): string {
  return buffer.toString('base64url');
}

function fromB64url(text: string): Buffer {
  return Buffer.from(text, 'base64url');
}

function assertLength(name: string, data: Buffer, expected: number) {
  if (data.length !== expected) {
    throw new InvalidKeyError(`${name} must be ${expected} bytes, got ${data.length}`);
  }
}

/**
 * Generate a private/public key pair for Ed25519.
 */
export function generateKeypair(algorithm = 'ed25519'): KeyPair {
  if (algorithm !== 'ed25519') {
    throw new AlgorithmError('Only ed25519 is currently supported');
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}

/**
 * Generate an Ed25519 key pair as raw bytes, for parity with the Go/Python/Rust
 * APIs. Returns a 64-byte private key (seed || public) and a 32-byte public key.
 * Use `ed25519Raw`/`verifyRaw` with these, or convert to PEM via
 * `privateKeyToPem`/`publicKeyToPem`.
 */
export function generateKeypairRaw(algorithm = 'ed25519'): RawKeyPair {
  const { privateKey, publicKey } = generateKeypair(algorithm);
  return {
    privateKey: privateKeyFromPem(privateKey),
    publicKey: publicKeyFromPem(publicKey),
  };
}

/**
 * Sign `message` with an Ed25519 private key (PEM string).
 */
export function ed25519(
  message: string | Buffer | Uint8Array,
  privateKey: string
): Buffer {
  try {
    return crypto.sign(null, toBuffer(message), crypto.createPrivateKey(privateKey));
  } catch (err) {
    throw new SignatureError('Signing failed');
  }
}

/**
 * Sign `message` with a raw Ed25519 private key.
 * `privateKey` may be the 64-byte seed || public or the 32-byte seed plus `publicKey`.
 */
export function ed25519Raw(
  message: string | Buffer | Uint8Array,
  privateKey: Buffer,
  publicKey?: Buffer
): Buffer {
  const pem = privateKeyToPem(privateKey, publicKey);
  return ed25519(message, pem);
}

/**
 * Verify a signature against a message and public key (PEM string).
 */
export function verify(
  signature: Buffer,
  message: string | Buffer | Uint8Array,
  publicKey: string,
  algorithm = 'ed25519'
): boolean {
  if (algorithm !== 'ed25519') {
    throw new AlgorithmError('Only ed25519 is currently supported');
  }
  try {
    return crypto.verify(null, toBuffer(message), crypto.createPublicKey(publicKey), signature);
  } catch (err) {
    throw new SignatureError('Verification failed');
  }
}

/**
 * Verify a signature against a message and a raw 32-byte public key.
 */
export function verifyRaw(
  signature: Buffer,
  message: string | Buffer | Uint8Array,
  publicKey: Buffer,
  algorithm = 'ed25519'
): boolean {
  if (algorithm !== 'ed25519') {
    throw new AlgorithmError('Only ed25519 is currently supported');
  }
  const pem = publicKeyToPem(publicKey);
  return verify(signature, message, pem, algorithm);
}

/**
 * Serialize a PEM private key to raw bytes (64 bytes: seed || public).
 */
export function privateKeyFromPem(pem: string): Buffer {
  const key = crypto.createPrivateKey(pem);
  const jwk = key.export({ format: 'jwk' }) as { d: string; x: string };
  const d = fromB64url(jwk.d);
  const x = fromB64url(jwk.x);
  assertLength('private key seed', d, 32);
  assertLength('public key', x, 32);
  return Buffer.concat([d, x]);
}

/**
 * Serialize a PEM public key to raw 32 bytes.
 */
export function publicKeyFromPem(pem: string): Buffer {
  const key = crypto.createPublicKey(pem);
  const jwk = key.export({ format: 'jwk' }) as { x: string };
  const x = fromB64url(jwk.x);
  assertLength('public key', x, 32);
  return x;
}

/**
 * Load a private key from raw bytes and return a PEM string.
 * `privateKey` may be 64 bytes (seed || public) or 32 bytes with `publicKey` provided.
 */
export function privateKeyToPem(privateKey: Buffer, publicKey?: Buffer): string {
  let d: Buffer;
  let x: Buffer;
  if (privateKey.length === 64) {
    d = privateKey.subarray(0, 32);
    x = privateKey.subarray(32, 64);
  } else if (privateKey.length === 32) {
    if (!publicKey) {
      throw new InvalidKeyError('publicKey is required for a 32-byte private seed');
    }
    d = privateKey;
    x = publicKey;
  } else {
    throw new InvalidKeyError('Ed25519 private key must be 32 or 64 bytes');
  }
  assertLength('private key seed', d, 32);
  assertLength('public key', x, 32);
  const jwk = { kty: 'OKP', crv: 'Ed25519', d: b64url(d), x: b64url(x) };
  const key = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  return key.export({ type: 'pkcs8', format: 'pem' }) as string;
}

/**
 * Load a public key from raw 32 bytes and return a PEM string.
 */
export function publicKeyToPem(publicKey: Buffer): string {
  assertLength('public key', publicKey, 32);
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(publicKey) };
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return key.export({ type: 'spki', format: 'pem' }) as string;
}

/** Alias for `privateKeyToPem`. */
export function serializePrivateKey(privateKey: Buffer, publicKey?: Buffer): string {
  return privateKeyToPem(privateKey, publicKey);
}

/** Alias for `publicKeyToPem`. */
export function serializePublicKey(publicKey: Buffer): string {
  return publicKeyToPem(publicKey);
}

/** Alias for `privateKeyFromPem`. */
export function loadPrivateKey(pem: string): Buffer {
  return privateKeyFromPem(pem);
}

/** Alias for `publicKeyFromPem`. */
export function loadPublicKey(pem: string): Buffer {
  return publicKeyFromPem(pem);
}
