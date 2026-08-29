/**
 * Exceptions raised by the crypto toolkit.
 */

export class CryptoKitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class AlgorithmError extends CryptoKitError {}
export class InvalidKeyError extends CryptoKitError {}
export class DecryptionError extends CryptoKitError {}
export class SignatureError extends CryptoKitError {}
