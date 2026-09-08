import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
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
    expect(h).toMatch(/^\$pbkdf2-sha256\$/);
    expect(password.verify('user-password', h)).toBe(true);
    expect(password.verify('wrong', h)).toBe(false);
  });

  it('should hash and verify with scrypt', () => {
    const h = password.hash('user-password', 'scrypt', { N: 1024, r: 8, p: 1, dklen: 32 });
    expect(h).toMatch(/^\$scrypt\$/);
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

  it('should reject unsupported algorithms', () => {
    expect(() => password.hash('pw', 'md5')).toThrow(password.AlgorithmError);
    expect(() => password.hash('pw', 'sha-1')).toThrow(password.AlgorithmError);
    expect(() => password.hash('pw', 'not-an-algo')).toThrow(password.AlgorithmError);
    expect(() => password.derive('pw', SALT, 32, 'bcrypt')).toThrow();
    expect(() => password.derive('pw', SALT, 32, 'bogus')).toThrow();
  });

  it('should reject invalid derive parameters', () => {
    expect(() => password.derive('pw', SALT, 0)).toThrow(password.InvalidKeyError);
    expect(() => password.derive('pw', SALT, -1)).toThrow(password.InvalidKeyError);
    expect(() => password.derive('pw', null as any, 32)).toThrow(password.InvalidKeyError);
  });

  it('should return false for malformed or unknown hash formats', () => {
    expect(password.verify('pw', 'not-a-hash')).toBe(false);
    expect(password.verify('pw', '')).toBe(false);
    expect(password.verify('pw', '$scrypt$garbage')).toBe(false);
    expect(password.verify('pw', '$pbkdf2-sha256$abc$bad$bad')).toBe(false);
    expect(password.verify('pw', '$argon2id$v=19$bad$bad$bad')).toBe(false);
  });

  it('should reject invalid scrypt parameters', () => {
    expect(() => password.hash('pw', 'scrypt', { N: 1000 })).toThrow();
  });
});

describe('password argon2id and bcrypt', () => {
  it('should hash and verify with argon2id when available', () => {
    try {
      const h = password.hash('user-password', 'argon2id', { timeCost: 3, memoryCost: 65536, parallelism: 4 });
      expect(h).toMatch(/^\$argon2id\$/);
      expect(password.verify('user-password', h)).toBe(true);
      expect(password.verify('wrong', h)).toBe(false);
    } catch (err: any) {
      if (err.message && err.message.includes('Node.js crypto.argon2Sync')) {
        // Node does not provide built-in argon2; skip in this environment
        return;
      }
      throw err;
    }
  });

  it('should hash and verify with bcrypt when available', () => {
    try {
      const h = password.hash('user-password', 'bcrypt', { rounds: 10 });
      expect(h).toMatch(/^\$2[aby]\$/);
      expect(password.verify('user-password', h)).toBe(true);
      expect(password.verify('wrong', h)).toBe(false);
    } catch (err: any) {
      if (err.message && err.message.includes('bcrypt requires')) {
        return;
      }
      throw err;
    }
  });
});

describe('encrypt', () => {
  it('should roundtrip aes-256-gcm', () => {
    const key = password.derive('passphrase', SALT, 32, 'pbkdf2_sha256');
    const ct = encrypt.symmetric('sensitive data', key);
    expect(ct).toBeInstanceOf(Buffer);
    expect(ct[0]).toBe(2);
    const pt = encrypt.decryptString(ct, key);
    expect(pt).toBe('sensitive data');
  });

  it('should roundtrip chacha20-poly1305', () => {
    const key = password.derive('passphrase', SALT, 32, 'pbkdf2_sha256');
    const ct = encrypt.symmetric('sensitive data', key, 'chacha20-poly1305');
    const pt = encrypt.decryptString(ct, key);
    expect(pt).toBe('sensitive data');
  });

  it('should roundtrip with AAD', () => {
    const key = Buffer.alloc(32, 0x78);
    const aad = Buffer.from('context');
    const ct = encrypt.encrypt('data', key, aad);
    expect(encrypt.decrypt(ct, key, aad).toString()).toBe('data');
    expect(() => encrypt.decrypt(ct, key, Buffer.from('wrong'))).toThrow();
  });

  it('should reject tampered ciphertext', () => {
    const key = Buffer.alloc(32, 0x78);
    const ct = encrypt.symmetric('data', key);
    const tampered = Buffer.from(ct);
    tampered[tampered.length - 1] ^= 1;
    expect(() => encrypt.decrypt(tampered, key)).toThrow();
  });

  it('should reject unsupported cipher algorithms', () => {
    const key = Buffer.alloc(32, 0x78);
    for (const algo of ['aes-128-gcm', 'des', 'rot13', 'bogus']) {
      expect(() => encrypt.encrypt('data', key, null, algo)).toThrow(encrypt.AlgorithmError);
    }
  });

  it('should reject invalid key lengths', () => {
    for (const len of [0, 16, 31, 33]) {
      const key = Buffer.alloc(len, 0x01);
      expect(() => encrypt.encrypt('data', key)).toThrow(encrypt.InvalidKeyError);
      expect(() => encrypt.encrypt('data', key, null, 'chacha20-poly1305')).toThrow(encrypt.InvalidKeyError);
    }
  });

  it('should reject malformed tokens and wrong keys', () => {
    const key = Buffer.alloc(32, 0x78);
    expect(() => encrypt.decrypt(Buffer.alloc(0), key)).toThrow(encrypt.DecryptionError);
    expect(() => encrypt.decrypt(Buffer.from([2]), key)).toThrow(encrypt.DecryptionError);
    expect(() => encrypt.decrypt(Buffer.from([99, 1, 0, 0]), key)).toThrow(encrypt.DecryptionError);
    expect(() => encrypt.decrypt(Buffer.from([2, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), key)).toThrow(encrypt.DecryptionError);

    const ct = encrypt.symmetric('data', key);
    expect(() => encrypt.decrypt(ct, Buffer.alloc(32, 0x79))).toThrow(encrypt.DecryptionError);
    expect(() => encrypt.decrypt(ct, Buffer.alloc(16))).toThrow(encrypt.InvalidKeyError);
  });

  it('should reject non-UTF-8 plaintext in decryptString', () => {
    const key = Buffer.alloc(32, 0x78);
    const ct = encrypt.encrypt(Buffer.from([0xff, 0xfe, 0x80]), key);
    expect(encrypt.decrypt(ct, key)).toEqual(Buffer.from([0xff, 0xfe, 0x80]));
    expect(() => encrypt.decryptString(ct, key)).toThrow(/utf-8/);
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

  it('should round-trip raw and PEM key formats', () => {
    const { privateKey, publicKey } = sign.generateKeypair();
    const rawPriv = sign.privateKeyFromPem(privateKey);
    const rawPub = sign.publicKeyFromPem(publicKey);
    expect(rawPriv).toHaveLength(64);
    expect(rawPub).toHaveLength(32);
    const pemPriv = sign.privateKeyToPem(rawPriv);
    const pemPub = sign.publicKeyToPem(rawPub);
    expect(pemPriv).toContain('BEGIN PRIVATE KEY');
    expect(pemPub).toContain('BEGIN PUBLIC KEY');

    const signature = sign.ed25519('hello world', pemPriv);
    expect(sign.verify(signature, 'hello world', pemPub)).toBe(true);

    const signature2 = sign.ed25519Raw('hello world', rawPriv);
    expect(sign.verifyRaw(signature2, 'hello world', rawPub)).toBe(true);
  });

  it('should generate a raw-bytes keypair', () => {
    const { privateKey, publicKey } = sign.generateKeypairRaw();
    expect(privateKey).toHaveLength(64);
    expect(publicKey).toHaveLength(32);
    const sig = sign.ed25519Raw('msg', privateKey);
    expect(sign.verifyRaw(sig, 'msg', publicKey)).toBe(true);
    expect(sign.verifyRaw(sig, 'other', publicKey)).toBe(false);
  });

  it('should reject unsupported sign algorithms', () => {
    expect(() => sign.generateKeypair('rsa')).toThrow(sign.AlgorithmError);
    expect(() => sign.generateKeypairRaw('rsa')).toThrow(sign.AlgorithmError);
    expect(() => sign.verify(Buffer.alloc(64), 'm', 'pem', 'rsa')).toThrow(sign.AlgorithmError);
  });

  it('should reject invalid keys', () => {
    expect(() => sign.ed25519('m', 'not a pem')).toThrow(sign.SignatureError);
    expect(() => sign.publicKeyToPem(Buffer.alloc(31))).toThrow(sign.InvalidKeyError);
    expect(() => sign.privateKeyToPem(Buffer.alloc(31))).toThrow(sign.InvalidKeyError);
    expect(() => sign.privateKeyToPem(Buffer.alloc(32))).toThrow(sign.InvalidKeyError);
    expect(() => sign.privateKeyFromPem('not a pem')).toThrow();
    expect(() => sign.verifyRaw(Buffer.alloc(64), 'm', Buffer.alloc(31))).toThrow();
  });

  it('should reject a wrong HMAC and unknown HMAC algorithms', () => {
    const mac = hash.hmac('key', 'message', 'sha-256');
    expect(hash.verifyHmac(mac, 'wrong-key', 'message', 'sha-256')).toBe(false);
    expect(() => hash.hmac('key', 'message', 'md5')).toThrow();
    expect(() => hash.hmac('key', 'message', 'sha-1')).toThrow();
    expect(() => hash.hmac('key', 'message', 'bogus')).toThrow();
  });
});

describe('encrypt token-parsing mutation tests', () => {
  const key = Buffer.alloc(32, 0x42);
  const token = encrypt.encrypt('data', key);

  it('rejects every truncation of a valid token', () => {
    for (let i = 0; i < token.length; i++) {
      const truncated = token.subarray(0, i);
      expect(() => encrypt.decrypt(truncated, key)).toThrow();
    }
  });

  it('rejects the token with each byte XORed with 0xFF', () => {
    for (let i = 0; i < token.length; i++) {
      const mutated = Buffer.from(token);
      mutated[i] ^= 0xff;
      expect(() => encrypt.decrypt(mutated, key)).toThrow();
    }
  });

  it('rejects 500 deterministic pseudo-random tokens of lengths 0..64', () => {
    let s = 1;
    const rnd = () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x80000000;
    for (let i = 0; i < 500; i++) {
      const len = Math.floor(rnd() * 65); // 0..64 inclusive
      const buf = Buffer.alloc(len);
      for (let j = 0; j < len; j++) buf[j] = Math.floor(rnd() * 256);
      expect(() => encrypt.decrypt(buf, key)).toThrow();
    }
  });
});

describe('edge cases', () => {
  it('hashes the empty string', () => {
    const d = hash.string('');
    expect(d).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(d).toHaveLength(64);
  });

  it('hashes a ~5MB file identically to hashing its bytes', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypto-toolkit-'));
    const file = path.join(dir, 'blob.bin');
    try {
      // ~5MB of deterministic bytes.
      const chunk = Buffer.alloc(4096);
      for (let i = 0; i < chunk.length; i++) chunk[i] = (i * 31 + 7) & 0xff;
      const content = Buffer.concat(Array(1280).fill(chunk)); // 1280 * 4096 = 5,242,880 bytes
      fs.writeFileSync(file, content);
      expect(hash.file(file, 'sha-256')).toBe(hash.string(content, 'sha-256'));
      expect(hash.file(file, 'sha-512')).toBe(hash.string(content, 'sha-512'));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('round-trips an empty plaintext', () => {
    const key = Buffer.alloc(32, 0x42);
    const ct = encrypt.encrypt('', key);
    expect(encrypt.decrypt(ct, key)).toEqual(Buffer.alloc(0));
    expect(encrypt.decryptString(ct, key)).toBe('');
  });

  it('round-trips binary non-UTF-8 plaintext and rejects decryptString', () => {
    const key = Buffer.alloc(32, 0x42);
    const plain = Buffer.from([0xff, 0xfe, 0x80, 0x00]);
    const ct = encrypt.encrypt(plain, key);
    expect(encrypt.decrypt(ct, key)).toEqual(plain);
    expect(() => encrypt.decryptString(ct, key)).toThrow(/utf-8/i);
  });

  it('rejects a zero-length key', () => {
    expect(() => encrypt.encrypt('data', Buffer.alloc(0))).toThrow(encrypt.InvalidKeyError);
    expect(() => encrypt.decrypt(Buffer.alloc(40), Buffer.alloc(0))).toThrow();
  });

  it('verifyHmac returns false for wrong-length or invalid-hex macs', () => {
    // Buffer.from(mac, 'hex') never throws on bad hex (it truncates at the
    // first invalid pair), so malformed input yields a length mismatch -> false.
    const mac = hash.hmac('key', 'message', 'sha-256');
    expect(hash.verifyHmac(mac.slice(0, -2), 'key', 'message', 'sha-256')).toBe(false);
    expect(hash.verifyHmac(mac + 'ff', 'key', 'message', 'sha-256')).toBe(false);
    expect(hash.verifyHmac('', 'key', 'message', 'sha-256')).toBe(false);
    expect(hash.verifyHmac('zzzz-not-hex', 'key', 'message', 'sha-256')).toBe(false);
    expect(hash.verifyHmac('0', 'key', 'message', 'sha-256')).toBe(false); // odd length
  });
});

describe('password.verify uniform rejection', () => {
  const malformed: string[] = [
    // generic garbage
    'notahash',
    '',
    ' ',
    '$',
    '$$$',
    '$unknown$abc$def$ghi',
    // pbkdf2-sha256 variants
    '$pbkdf2-sha256$garbage',
    '$pbkdf2-sha256$abc$bad$bad',
    '$pbkdf2-sha256$1000$$',
    '$pbkdf2-sha256$1000$onlysalt',
    '$pbkdf2-sha256$-1$c2FsdA$YWJjZA',
    '$pbkdf2-sha256$1e9$c2FsdA$YWJjZA',
    '$pbkdf2-sha256$1000$***$***',
    '$pbkdf2-sha256$1000$c2FsdA$YWJjZA$extra',
    '$pbkdf2-sha256$$c2FsdA$YWJjZA',
    'pbkdf2-sha256$1000$c2FsdA$YWJjZA',
    // scrypt variants
    '$scrypt$garbage',
    '$scrypt$ln=10,r=8,p=1$$',
    '$scrypt$ln=abc,r=8,p=1$c2FsdA$YWJjZA',
    '$scrypt$ln=10$c2FsdA$YWJjZA',
    '$scrypt$r=8,p=1,ln=10$c2FsdA$YWJjZA',
    '$scrypt$ln=99,r=8,p=1$c2FsdA$YWJjZA',
    '$scrypt$ln=10,r=0,p=1$c2FsdA$YWJjZA',
    '$scrypt$ln=10,r=8,p=1$***$***',
    '$scrypt$ln=10,r=8,p=1$c2FsdA$YWJjZA$extra',
    'scrypt$ln=10,r=8,p=1$c2FsdA$YWJjZA',
    // argon2id variants
    '$argon2id$v=19$bad$bad$bad',
    '$argon2id$v=19$m=65536,t=3,p=4$$',
    '$argon2id$v=19$m=abc,t=3,p=4$c2FsdA$YWJjZA',
    '$argon2id$v=19$m=65536,t=3$c2FsdA$YWJjZA',
    '$argon2id$v=19$m=65536,t=3,p=4$***$***',
    '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$YWJjZA$extra',
    '$argon2id$m=65536,t=3,p=4$c2FsdA$YWJjZA',
    // bcrypt variants
    '$2a$garbage',
    '$2b$notreal$notreal',
    '$2y$12$......................',
    '$2a$99$short',
  ];

  it('returns false (never throws) for every malformed hash', () => {
    for (const bad of malformed) {
      expect(password.verify('pw', bad)).toBe(false);
    }
  });
});
