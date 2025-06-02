import { describe, it, expect } from 'vitest';
import { parseKeyBits } from '../parseKeyBits';
import { Enc } from '../../../constants/Enc';

describe('parseKeyBits', () => {
  it('should parse 128 bits key size', () => {
    const enc = 'a128' as Enc;
    expect(parseKeyBits(enc)).toBe(128);
  });

  it('should parse 192 bits key size', () => {
    const enc = 'a192' as Enc;
    expect(parseKeyBits(enc)).toBe(192);
  });

  it('should parse 256 bits key size', () => {
    const enc = 'a256' as Enc;
    expect(parseKeyBits(enc)).toBe(256);
  });
});
