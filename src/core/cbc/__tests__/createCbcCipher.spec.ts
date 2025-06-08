import { describe, it, expect } from 'vitest';
import { createCbcCipher } from '../createCbcCipher';
import {
  AbstractCbcCipher,
  CbcEncryptInternalParams,
  CbcDecryptInternalParams,
  GenerateTagParams,
} from '../AbstractCbcCipher';
import { RandomBytes } from '@/common/types';

// Mock implementation for testing
class MockCbcCipher extends AbstractCbcCipher {
  encryptInternal = async (
    _args: CbcEncryptInternalParams,
  ): Promise<Uint8Array> => {
    return new Uint8Array([1, 2, 3]);
  };

  decryptInternal = async (
    _args: CbcDecryptInternalParams,
  ): Promise<Uint8Array> => {
    return new Uint8Array([4, 5, 6]);
  };

  generateTag = async (_args: GenerateTagParams): Promise<Uint8Array> => {
    return new Uint8Array(32).fill(0x42);
  };
}

describe('createCbcCipher', () => {
  it('should create a new instance of the CBC cipher', () => {
    const randomBytes: RandomBytes = (size = 32) =>
      new Uint8Array(size).fill(0x42);
    const cipher = createCbcCipher(MockCbcCipher, randomBytes);

    expect(cipher).toBeInstanceOf(MockCbcCipher);
    expect(cipher).toBeInstanceOf(AbstractCbcCipher);
  });

  it('should pass constructor arguments correctly', () => {
    const randomBytes: RandomBytes = (size = 32) =>
      new Uint8Array(size).fill(0x42);
    const cipher = createCbcCipher(MockCbcCipher, randomBytes);

    // Verify that the randomBytes function is properly passed
    const iv = cipher.generateIv();
    expect(iv).toBeInstanceOf(Uint8Array);
    expect(iv.length).toBe(16); // CBC IV length
    expect(iv.every((byte) => byte === 0x42)).toBe(true);
  });
});
