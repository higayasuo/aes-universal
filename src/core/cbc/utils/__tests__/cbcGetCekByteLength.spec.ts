import { describe, it, expect } from 'vitest';
import { cbcGetCekByteLength } from '../cbcGetCekByteLength';

describe('cbcGetCekByteLength', () => {
  it('should return 32 bytes for A128CBC-HS256', () => {
    expect(cbcGetCekByteLength('A128CBC-HS256')).toBe(32);
  });

  it('should return 48 bytes for A192CBC-HS384', () => {
    expect(cbcGetCekByteLength('A192CBC-HS384')).toBe(48);
  });

  it('should return 64 bytes for A256CBC-HS512', () => {
    expect(cbcGetCekByteLength('A256CBC-HS512')).toBe(64);
  });
});
