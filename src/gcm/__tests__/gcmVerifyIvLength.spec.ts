import { describe, it, expect } from 'vitest';
import { gcmVerifyIvLength } from '../gcmVerifyIvLength';

describe('gcmVerifyIvLength', () => {
  it('should not throw an error when IV length is valid', () => {
    // GCM mode requires a 12-byte IV
    const iv = new Uint8Array(12);
    expect(() => gcmVerifyIvLength(iv)).not.toThrow();
  });

  it('should throw an error when IV length is too short', () => {
    const iv = new Uint8Array(8);
    expect(() => gcmVerifyIvLength(iv)).toThrow(
      'Invalid GCM IV length: expected 12 bytes, got 8 bytes',
    );
  });

  it('should throw an error when IV length is too long', () => {
    const iv = new Uint8Array(16);
    expect(() => gcmVerifyIvLength(iv)).toThrow(
      'Invalid GCM IV length: expected 12 bytes, got 16 bytes',
    );
  });

  it('should throw an error when IV length is zero', () => {
    const iv = new Uint8Array(0);
    expect(() => gcmVerifyIvLength(iv)).toThrow(
      'Invalid GCM IV length: expected 12 bytes, got 0 bytes',
    );
  });
});
