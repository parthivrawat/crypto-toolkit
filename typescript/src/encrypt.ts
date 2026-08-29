/**
 * Symmetric AEAD encryption with safe, modern defaults.
 */

import * as crypto from 'crypto';
import { AlgorithmError, DecryptionError, InvalidKeyError } from './errors';

export { AlgorithmError, DecryptionError, InvalidKeyError };

const VERSION = 1;

interface AlgorithmSpec {
  id: number;
  keyLen: number;
  ivLen: number;
  cipherName: string;
}

const ALGORITHMS: Record<string, AlgorithmSpec> = {
  'aes-256-gcm': { id: 1, keyLen: 32, ivLen: 12, cipherName: 'aes-256-gcm' },
  'chacha20-poly1305': { id: 2, keyLen: 32, ivLen: 12, cipherName: 'chacha20-poly1305' },
};

const ID_TO_ALGO: Record<number, string> = {
  1: 'aes-256-gcm',
  2: 'chacha20-poly1305',
};

function toBuffer(data: string | Buffer | Uint8Array): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  return Buffer.from(data, 'utf-8');
}

function getSpec(algorithm: string): AlgorithmSpec {
  const spec = ALGORITHMS[algorithm];
  if (!spec) throw new AlgorithmError(`Unsupported cipher: ${algorithm}`);
  return spec;
}

function makeCipher(algorithm: string, key: Buffer, iv: Buffer) {
  return crypto.createCipheriv(algorithm, key, iv) as crypto.CipherGCM;
}

/**
 * Encrypt `data` with an AEAD cipher using a versioned header.
 */
export function symmetric(
  data: string | Buffer | Uint8Array,
  key: Buffer,
  algorithm = 'aes-256-gcm'
): Buffer {
  const spec = getSpec(algorithm);
  if (key.length !== spec.keyLen) {
    throw new InvalidKeyError(`${algorithm} requires a ${spec.keyLen}-byte key`);
  }
  const iv = crypto.randomBytes(spec.ivLen);
  const cipher = makeCipher(spec.cipherName, key, iv);
  const ciphertext = Buffer.concat([cipher.update(toBuffer(data)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([VERSION, spec.id]), iv, ciphertext, tag]);
}

/**
 * Decrypt and authenticate a token produced by `symmetric`.
 */
export function decrypt(
  token: Buffer,
  key: Buffer,
  encoding: BufferEncoding | null = 'utf-8'
): string | Buffer {
  if (token.length < 2) throw new DecryptionError('Ciphertext too short');
  const version = token[0];
  if (version !== VERSION) throw new DecryptionError(`Unsupported ciphertext version: ${version}`);
  const algoId = token[1];
  const name = ID_TO_ALGO[algoId];
  if (!name) throw new DecryptionError(`Unknown algorithm id: ${algoId}`);
  const spec = getSpec(name);
  if (key.length !== spec.keyLen) {
    throw new InvalidKeyError(`${name} requires a ${spec.keyLen}-byte key`);
  }
  if (token.length < 2 + spec.ivLen + 16) {
    throw new DecryptionError('Ciphertext too short');
  }
  const iv = token.subarray(2, 2 + spec.ivLen);
  const rest = token.subarray(2 + spec.ivLen);
  const tag = rest.subarray(-16);
  const ciphertext = rest.subarray(0, -16);

  const decipher = crypto.createDecipheriv(spec.cipherName, key, iv) as crypto.DecipherGCM;
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new DecryptionError('Decryption or authentication failed');
  }

  if (encoding) {
    try {
      return plaintext.toString(encoding);
    } catch {
      return plaintext;
    }
  }
  return plaintext;
}
