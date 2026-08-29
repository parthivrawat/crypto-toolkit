import { describe, it, expect } from 'vitest';
import { hash, password, encrypt, sign } from './index';

const SALT = Buffer.from('saltsaltsaltsalt', 'utf-8');

describe('hash', () => {
  it('should produce deterministic sha-256 hashes', () => {
    const sha256 = hash.string('hello world', 'sha-256');
    expect(sha256).toHaveLength(64);
    expect(hash.string('hello world', 'sha-256')).toBe(sha256);
  });

  it('should reject weak algorithms', () => {
    expect(() => hash.string('test', 'md5')).toThrow();
    expect(() => hash.string('test', 'sha-1')).toThrow();
  });

  it('should compute and verify HMAC', () => {
    const mac = hash.hmac('key', 'message', 'sha-256');
    expect(hash.verifyHmac(mac, 'key', 'message', 'sha-256')).toBe(true);
    expect(hash.verifyHmac(mac, 'key', 'tampered', 'sha-256')).toBe(false);
  });
});

describe('password', () => {
  it('should hash and verify with pbkdf2', () => {
    const h = password.hash('user-password', 'pbkdf2_sha256', { iterations: 1000 });
    expect(h).toMatch(/^pbkdf2_sha256\$/);
    expect(password.verify('user-password', h)).toBe(true);
    expect(password.verify('wrong', h)).toBe(false);
  });

  it('should derive a key', () => {
    const key = password.derive('passphrase', SALT, 32);
    expect(key).toHaveLength(32);
    expect(password.derive('passphrase', SALT, 32).toString('hex')).toBe(key.toString('hex'));
  });

  it('should require salt', () => {
    expect(() => password.derive('passphrase', Buffer.alloc(0), 32)).toThrow();
  });
});

describe('encrypt', () => {
  it('should roundtrip aes-256-gcm', () => {
    const key = password.derive('passphrase', SALT, 32, 'pbkdf2_sha256');
    const ct = encrypt.symmetric('sensitive data', key);
    expect(ct).toBeInstanceOf(Buffer);
    const pt = encrypt.decrypt(ct, key);
    expect(pt).toBe('sensitive data');
  });

  it('should roundtrip chacha20-poly1305', () => {
    const key = password.derive('passphrase', SALT, 32, 'pbkdf2_sha256');
    const ct = encrypt.symmetric('sensitive data', key, 'chacha20-poly1305');
    const pt = encrypt.decrypt(ct, key);
    expect(pt).toBe('sensitive data');
  });

  it('should reject tampered ciphertext', () => {
    const key = Buffer.alloc(32, 0x78);
    const ct = encrypt.symmetric('data', key);
    const tampered = Buffer.from(ct);
    tampered[tampered.length - 1] ^= 1;
    expect(() => encrypt.decrypt(tampered, key)).toThrow();
  });
});

describe('sign', () => {
  it('should sign and verify with ed25519', () => {
    const { privateKey, publicKey } = sign.generateKeypair();
    const signature = sign.ed25519('hello world', privateKey);
    expect(sign.verify(signature, 'hello world', publicKey)).toBe(true);
  });

  it('should fail verification for wrong message', () => {
    const { privateKey, publicKey } = sign.generateKeypair();
    const signature = sign.ed25519('message', privateKey);
    expect(sign.verify(signature, 'other', publicKey)).toBe(false);
  });
});
