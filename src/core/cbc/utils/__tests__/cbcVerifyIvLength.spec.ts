import { describe, it, expect } from 'vitest';
import { cbcVerifyIvLength } from '../cbcVerifyIvLength';

describe('cbcVerifyIvLength', () => {
  it('should not throw an error when IV length is valid', () => {
    // CBC mode requires a 16-byte IV
    const iv = new Uint8Array(16);
    expect(() => cbcVerifyIvLength(iv)).not.toThrow();
  });

  it('should throw an error when IV length is too short', () => {
    const iv = new Uint8Array(8);
    expect(() => cbcVerifyIvLength(iv)).toThrow(
      'Invalid CBC IV length: expected 16 bytes, got 8 bytes',
    );
  });

  it('should throw an error when IV length is too long', () => {
    const iv = new Uint8Array(24);
    expect(() => cbcVerifyIvLength(iv)).toThrow(
      'Invalid CBC IV length: expected 16 bytes, got 24 bytes',
    );
  });

  it('should throw an error when IV length is zero', () => {
    const iv = new Uint8Array(0);
    expect(() => cbcVerifyIvLength(iv)).toThrow(
      'Invalid CBC IV length: expected 16 bytes, got 0 bytes',
    );
  });
});
