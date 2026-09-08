/**
 * Symmetric AEAD encryption with safe, modern defaults.
 */

import * as crypto from 'crypto';
import { AlgorithmError, DecryptionError, InvalidKeyError } from './errors';

export { AlgorithmError, DecryptionError, InvalidKeyError };

const VERSION = 2;

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

function normalizeAlgorithm(algorithm: string): string {
  return algorithm.toLowerCase().replace(/_/g, '-');
}

function getSpec(algorithm: string): AlgorithmSpec {
  const name = normalizeAlgorithm(algorithm);
  const spec = ALGORITHMS[name];
  if (!spec) throw new AlgorithmError(`Unsupported cipher: ${algorithm}`);
  return spec;
}

function buildAAD(version: number, algoId: number, aad: Buffer, iv: Buffer): Buffer {
  const aadLen = Buffer.alloc(2);
  aadLen.writeUInt16BE(aad.length, 0);
  return Buffer.concat([Buffer.from([version, algoId]), aadLen, aad, iv]);
}

export function encrypt(
  data: string | Buffer | Uint8Array,
  key: Buffer,
  aad: Buffer | null = null,
  algorithm = 'aes-256-gcm'
): Buffer {
  const spec = getSpec(algorithm);
  if (key.length !== spec.keyLen) {
    throw new InvalidKeyError(`${algorithm} requires a ${spec.keyLen}-byte key`);
  }
  const iv = crypto.randomBytes(spec.ivLen);
  const cipher = crypto.createCipheriv(spec.cipherName, key, iv) as crypto.CipherGCM;
  const userAad = aad ?? Buffer.alloc(0);
  const aadForCipher = buildAAD(VERSION, spec.id, userAad, iv);
  cipher.setAAD(aadForCipher);
  const ciphertext = Buffer.concat([cipher.update(toBuffer(data)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([VERSION, spec.id]), aadForCipher.subarray(2, 4), userAad, iv, ciphertext, tag]);
}

export function encryptString(
  plaintext: string,
  key: Buffer,
  aad: Buffer | null = null,
  algorithm = 'aes-256-gcm'
): Buffer {
  return encrypt(Buffer.from(plaintext, 'utf-8'), key, aad, algorithm);
}

export function decrypt(token: Buffer, key: Buffer, aad: Buffer | null = null): Buffer {
  if (token.length < 2) throw new DecryptionError('Ciphertext too short');
  const version = token[0];
  if (version === VERSION) return decryptV2(token, key, aad);
  if (version === 1) {
    if (aad && aad.length > 0) {
      throw new DecryptionError('v1 ciphertext does not support AAD');
    }
    return decryptV1(token, key);
  }
  throw new DecryptionError(`Unsupported ciphertext version: ${version}`);
}

export function decryptString(
  token: Buffer,
  key: Buffer,
  aad: Buffer | null = null,
  encoding: BufferEncoding = 'utf-8'
): string {
  const plaintext = decrypt(token, key, aad);
  if (encoding === 'utf-8' || encoding === 'utf8') {
    // Strict decoding: Buffer.toString('utf-8') silently substitutes U+FFFD
    // for invalid bytes, which can mask corrupted or binary plaintext that
    // legitimately passed authentication. TextDecoder with fatal:true rejects.
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    } catch {
      throw new Error('Plaintext is not valid utf-8 data');
    }
  }
  try {
    return plaintext.toString(encoding);
  } catch {
    throw new Error(`Plaintext is not valid ${encoding} data`);
  }
}

function decryptV2(token: Buffer, key: Buffer, aad: Buffer | null): Buffer {
  if (token.length < 4) throw new DecryptionError('Ciphertext too short');
  const algoId = token[1];
  const aadLen = token.readUInt16BE(2);
  const aadStart = 4;
  const aadEnd = aadStart + aadLen;
  if (token.length < aadEnd) throw new DecryptionError('Ciphertext too short');

  const storedAad = token.subarray(aadStart, aadEnd);
  const expectedAad = aad ?? Buffer.alloc(0);
  if (!storedAad.equals(expectedAad)) {
    throw new DecryptionError('Additional authenticated data does not match');
  }

  const name = ID_TO_ALGO[algoId];
  if (!name) throw new DecryptionError(`Unknown algorithm id: ${algoId}`);
  const spec = getSpec(name);
  if (key.length !== spec.keyLen) {
    throw new InvalidKeyError(`${name} requires a ${spec.keyLen}-byte key`);
  }
  if (token.length < aadEnd + spec.ivLen + 16) throw new DecryptionError('Ciphertext too short');

  const iv = token.subarray(aadEnd, aadEnd + spec.ivLen);
  const rest = token.subarray(aadEnd + spec.ivLen);
  const tag = rest.subarray(-16);
  const ciphertext = rest.subarray(0, -16);

  const aadForCipher = buildAAD(VERSION, algoId, storedAad, iv);
  const decipher = crypto.createDecipheriv(spec.cipherName, key, iv) as crypto.DecipherGCM;
  decipher.setAuthTag(tag);
  decipher.setAAD(aadForCipher);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new DecryptionError('Decryption or authentication failed');
  }
}

function decryptV1(token: Buffer, key: Buffer): Buffer {
  const algoId = token[1];
  const name = ID_TO_ALGO[algoId];
  if (!name) throw new DecryptionError(`Unknown algorithm id: ${algoId}`);
  const spec = getSpec(name);
  if (key.length !== spec.keyLen) {
    throw new InvalidKeyError(`${name} requires a ${spec.keyLen}-byte key`);
  }
  if (token.length < 2 + spec.ivLen + 16) throw new DecryptionError('Ciphertext too short');
  const iv = token.subarray(2, 2 + spec.ivLen);
  const rest = token.subarray(2 + spec.ivLen);
  const tag = rest.subarray(-16);
  const ciphertext = rest.subarray(0, -16);

  const decipher = crypto.createDecipheriv(spec.cipherName, key, iv) as crypto.DecipherGCM;
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new DecryptionError('Decryption or authentication failed');
  }
}

export function symmetric(
  data: string | Buffer | Uint8Array,
  key: Buffer,
  algorithm = 'aes-256-gcm'
): Buffer {
  return encrypt(data, key, null, algorithm);
}
