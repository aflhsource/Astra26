import stableStringify from 'json-stable-stringify';

const MAX_CANONICAL_DEPTH = 64;

export function canonicalize(value: unknown): string {
  try {
    if (
      value === undefined ||
      typeof value === 'bigint' ||
      typeof value === 'function' ||
      typeof value === 'symbol'
    ) {
      throw new TypeError('Value cannot be represented as canonical JSON');
    }
    const result = stableStringify(normalize(value));
    if (typeof result !== 'string') {
      throw new Error('Value cannot be represented as canonical JSON');
    }
    return result;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown canonicalization error';
    throw new Error(`Unable to canonicalize value: ${message}`);
  }
}

function normalize(value: unknown, seen = new WeakSet<object>(), depth = 0): unknown {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new RangeError(
      `Maximum canonicalization depth (${MAX_CANONICAL_DEPTH}) exceeded (depth bomb defense)`,
    );
  }
  if (value === null) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'object') return value;
  if (seen.has(value)) throw new TypeError('Cannot canonicalize circular structure');
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (item === undefined || typeof item === 'function' || typeof item === 'symbol') return null;
      return normalize(item, seen, depth + 1);
    });
  }
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(value)) {
    if (key === '__proto__' || key === 'prototype') continue;
    const item = value[key as keyof typeof value];
    if (item === undefined || typeof item === 'function' || typeof item === 'symbol') continue;
    result[key] = normalize(item, seen, depth + 1);
  }
  return result;
}
