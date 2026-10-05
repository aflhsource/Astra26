import { createHash, timingSafeEqual } from 'node:crypto';
import { canonicalize } from './canonicalize.js';

export function sha256(value: unknown): string {
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');
}

export function verifySha256(value: unknown, expectedHash: string): boolean {
  try {
    const calculated = Buffer.from(sha256(value), 'utf8');
    const expected = Buffer.from(expectedHash.trim().toLowerCase(), 'utf8');
    return calculated.length === expected.length && timingSafeEqual(calculated, expected);
  } catch {
    return false;
  }
}
