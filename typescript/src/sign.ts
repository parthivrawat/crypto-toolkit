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

function toBuffer(data: string | Buffer | Uint8Array): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  return Buffer.from(data, 'utf-8');
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
 * Sign `message` with an Ed25519 private key.
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
 * Verify a signature against a message and public key.
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
