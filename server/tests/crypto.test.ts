import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, rmSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { canonicalize } from '../src/modules/crypto/canonicalize.js';
import { sha256 } from '../src/modules/crypto/hash.js';
import { generateEd25519KeyPair, sign, verify } from '../src/modules/crypto/signature.js';

describe('canonicalize', () => {
  it('sorts object properties deterministically, including nested objects', () => {
    expect(canonicalize({ b: 2, a: { d: 4, c: 3 } })).toBe(
      canonicalize({ a: { c: 3, d: 4 }, b: 2 }),
    );
  });

  it('preserves array order and supports Unicode', () => {
    expect(canonicalize({ values: ['first', 'second'], label: 'मरीज़' })).toBe(
      '{"label":"मरीज़","values":["first","second"]}',
    );
    expect(canonicalize({ values: ['first', 'second'] })).not.toBe(
      canonicalize({ values: ['second', 'first'] }),
    );
  });

  it('does not mutate the input object', () => {
    const input = { nested: { b: 2, a: 1 }, values: [1, 2] };
    const before = JSON.stringify(input);
    canonicalize(input);
    expect(JSON.stringify(input)).toBe(before);
  });

  it('rejects values that cannot be represented as canonical JSON', () => {
    expect(() => canonicalize(BigInt(1))).toThrow('Unable to canonicalize value');
    expect(() => canonicalize(undefined)).toThrow('Unable to canonicalize value');
  });
});

describe('sha256', () => {
  it('returns the same digest for logically equivalent objects', () => {
    expect(sha256({ b: 2, a: 1 })).toBe(sha256({ a: 1, b: 2 }));
  });

  it('changes when a nested value changes', () => {
    expect(sha256({ payload: { value: 10 } })).not.toBe(sha256({ payload: { value: 11 } }));
  });
});

describe('Ed25519 signatures', () => {
  const payload = { transactionId: 'tx-crypto-001', payload: { result: 'synthetic' } };

  it('signs and verifies canonicalized values', () => {
    const keyPair = generateEd25519KeyPair();
    const signature = sign(payload, keyPair.privateKey);

    expect(signature).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(
      verify(
        { payload: { result: 'synthetic' }, transactionId: 'tx-crypto-001' },
        signature,
        keyPair.publicKey,
      ),
    ).toBe(true);
    expect(verify(payload, sign(payload, keyPair.privateKey), keyPair.publicKey)).toBe(true);
  });

  it('rejects modified payloads, wrong keys, and mutated signatures', () => {
    const keyPair = generateEd25519KeyPair();
    const otherKeyPair = generateEd25519KeyPair();
    const signature = sign(payload, keyPair.privateKey);
    const mutatedSignature = `${signature.startsWith('A') ? 'B' : 'A'}${signature.slice(1)}`;

    expect(verify({ ...payload, transactionId: 'tx-modified' }, signature, keyPair.publicKey)).toBe(
      false,
    );
    expect(verify(payload, signature, otherKeyPair.publicKey)).toBe(false);
    expect(verify(payload, mutatedSignature, keyPair.publicKey)).toBe(false);
  });

  it('loads generated PEM keys and verifies a signature', () => {
    const directory = mkdtempSync(join(tmpdir(), 'trust-pass-crypto-'));
    try {
      const generated = generateEd25519KeyPair();
      const privatePath = join(directory, 'private.pem');
      const publicPath = join(directory, 'public.pem');
      writeFileSync(privatePath, generated.privateKey.export({ type: 'pkcs8', format: 'pem' }));
      writeFileSync(publicPath, generated.publicKey.export({ type: 'spki', format: 'pem' }));

      const privateKey = createPrivateKey(readFileSync(privatePath));
      const publicKey = createPublicKey(readFileSync(publicPath));
      expect(verify(payload, sign(payload, privateKey), publicKey)).toBe(true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

describe('demo key safety', () => {
  it('keeps demo key storage ignored by Git', async () => {
    const gitignore = readFileSync(resolve(process.cwd(), '.gitignore'), 'utf8');
    expect(gitignore).toContain('.demo-keys/');
  });
});
