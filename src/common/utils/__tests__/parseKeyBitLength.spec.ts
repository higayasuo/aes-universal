import { describe, it, expect } from 'vitest';
import { parseKeyBitLength } from '../parseKeyBitLength';

describe('parseKeyBitLength', () => {
  it('should parse 128 bits key size', () => {
    const enc = 'A128GCM';
    expect(parseKeyBitLength(enc)).toBe(128);
  });

  it('should parse 192 bits key size', () => {
    const enc = 'A192GCM';
    expect(parseKeyBitLength(enc)).toBe(192);
  });

  it('should parse 256 bits key size', () => {
    const enc = 'A256GCM';
    expect(parseKeyBitLength(enc)).toBe(256);
  });
});
