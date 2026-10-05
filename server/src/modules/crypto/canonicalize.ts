import stableStringify from 'json-stable-stringify';

export function canonicalize(value: unknown): string {
  try {
    const result = stableStringify(value);
    if (typeof result !== 'string') {
      throw new Error('Value cannot be represented as canonical JSON');
    }
    return result;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown canonicalization error';
    throw new Error(`Unable to canonicalize value: ${message}`);
  }
}
