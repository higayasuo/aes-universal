import { describe, it, expect } from 'vitest';
import { createGcmCipher } from '../createGcmCipher';
import {
  AbstractGcmCipher,
  GcmEncryptInternalParams,
  GcmDecryptInternalParams,
} from '../AbstractGcmCipher';
import { RandomBytes } from '@/common/types';

// Mock implementation for testing
class MockGcmCipher extends AbstractGcmCipher {
  encryptInternal = async (_args: GcmEncryptInternalParams) => {
    return {
      ciphertext: new Uint8Array([1, 2, 3]),
      tag: new Uint8Array(16).fill(0x42),
    };
  };

  decryptInternal = async (
    _args: GcmDecryptInternalParams,
  ): Promise<Uint8Array> => {
    return new Uint8Array([4, 5, 6]);
  };
}

describe('createGcmCipher', () => {
  it('should create a new instance of the GCM cipher', () => {
    const randomBytes: RandomBytes = (size = 32) =>
      new Uint8Array(size).fill(0x42);
    const cipher = createGcmCipher(MockGcmCipher, randomBytes);

    expect(cipher).toBeInstanceOf(MockGcmCipher);
    expect(cipher).toBeInstanceOf(AbstractGcmCipher);
  });

  it('should pass constructor arguments correctly', () => {
    const randomBytes: RandomBytes = (size = 32) =>
      new Uint8Array(size).fill(0x42);
    const cipher = createGcmCipher(MockGcmCipher, randomBytes);

    // Verify that the randomBytes function is properly passed
    const iv = cipher.generateIv();
    expect(iv).toBeInstanceOf(Uint8Array);
    expect(iv.length).toBe(12); // GCM IV length
    expect(iv.every((byte) => byte === 0x42)).toBe(true);
  });
});
