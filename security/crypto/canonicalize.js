/**
 * TRUST-PASS Cryptographic Foundation
 * Deterministic JSON Canonicalization (compatible with RFC 8785 principles)
 *
 * Ensures that two logically identical JSON objects produce the exact same
 * byte/character representation regardless of key order in memory.
 */

'use strict';

const MAX_CANONICAL_DEPTH = 64;

/**
 * Recursively sorts keys and formats values deterministically.
 * Hardened against Prototype Pollution and Stack Exhaustion Depth Bombs.
 *
 * @param {*} value The value to canonicalize.
 * @param {WeakSet} seen Set of seen objects for circular reference detection.
 * @param {number} depth Current recursion depth.
 * @returns {*} The canonical representation structure.
 */
function canonicalizeValue(value, seen = new WeakSet(), depth = 0) {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new RangeError(`Maximum canonicalization depth (${MAX_CANONICAL_DEPTH}) exceeded (depth bomb defense)`);
  }

  if (value === null || typeof value !== 'object') {
    // Handle special numbers per JSON standard
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        return null;
      }
    }
    return value;
  }

  // Handle Date objects explicitly to ensure consistent ISO string output
  if (value instanceof Date) {
    return value.toISOString();
  }

  // Circular reference detection
  if (seen.has(value)) {
    throw new TypeError('Cannot canonicalize circular structure');
  }
  seen.add(value);

  // Handle Arrays: preserve order, canonicalize children
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (item === undefined || typeof item === 'symbol' || typeof item === 'function') {
        return null;
      }
      return canonicalizeValue(item, seen, depth + 1);
    });
  }

  // Handle Objects: sort keys lexicographically by UTF-16 code unit values
  // Filter out dangerous prototype pollution properties (__proto__, constructor, prototype)
  const sortedKeys = Object.keys(value).filter(k => k !== '__proto__' && k !== 'prototype').sort();
  const canonicalObj = Object.create(null);

  for (const key of sortedKeys) {
    const val = value[key];
    // Skip undefined, functions, and symbols, matching JSON.stringify semantics
    if (val === undefined || typeof val === 'function' || typeof val === 'symbol') {
      continue;
    }
    canonicalObj[key] = canonicalizeValue(val, seen, depth + 1);
  }

  return canonicalObj;
}

/**
 * Canonicalizes any JavaScript object or primitive into a deterministic JSON string.
 * @param {*} data Data to serialize.
 * @returns {string} Deterministic canonical JSON string.
 * @throws {TypeError} If circular references or serialization errors occur.
 */
function canonicalize(data) {
  if (data === undefined) {
    return undefined;
  }
  const prepared = canonicalizeValue(data);
  return JSON.stringify(prepared);
}

module.exports = {
  canonicalize,
  canonicalizeValue
};
