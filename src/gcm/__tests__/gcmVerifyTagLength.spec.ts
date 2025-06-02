import { describe, it, expect } from 'vitest';
import { gcmVerifyTagLength } from '../gcmVerifyTagLength';

describe('gcmVerifyTagLength', () => {
  it('should not throw an error when tag length is valid', () => {
    // GCM mode requires a 16-byte (128-bit) authentication tag
    const tag = new Uint8Array(16);
    expect(() => gcmVerifyTagLength(tag)).not.toThrow();
  });

  it('should throw an error when tag length is too short', () => {
    const tag = new Uint8Array(12);
    expect(() => gcmVerifyTagLength(tag)).toThrow(
      'Invalid GCM authentication tag length: expected 16 bytes, but got 12 bytes',
    );
  });

  it('should throw an error when tag length is too long', () => {
    const tag = new Uint8Array(24);
    expect(() => gcmVerifyTagLength(tag)).toThrow(
      'Invalid GCM authentication tag length: expected 16 bytes, but got 24 bytes',
    );
  });

  it('should throw an error when tag length is zero', () => {
    const tag = new Uint8Array(0);
    expect(() => gcmVerifyTagLength(tag)).toThrow(
      'Invalid GCM authentication tag length: expected 16 bytes, but got 0 bytes',
    );
  });
});
