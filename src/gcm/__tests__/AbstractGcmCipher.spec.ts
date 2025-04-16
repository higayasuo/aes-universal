import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  AbstractGcmCipher,
  GcmEncryptInternalArgs,
  GcmEncryptInternalResult,
} from '../AbstractGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

// Mock implementation for testing
class MockGcmCipher extends AbstractGcmCipher {
  async encryptInternal(
    _args: GcmEncryptInternalArgs,
  ): Promise<GcmEncryptInternalResult> {
    return {
      ciphertext: new Uint8Array([1, 2, 3]),
      tag: new Uint8Array([7, 8, 9]),
    };
  }

  async decryptInternal(): Promise<Uint8Array> {
    return new Uint8Array([4, 5, 6]);
  }

  async generateTag(): Promise<Uint8Array> {
    return new Uint8Array([7, 8, 9]);
  }
}

describe('AbstractGcmCipher', () => {
  let mockCryptoModule: CryptoModule;
  let cipher: MockGcmCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
    } as unknown as CryptoModule;
    cipher = new MockGcmCipher(mockCryptoModule);
  });

  describe('generateIv', () => {
    it('should generate a 12-byte IV', () => {
      const iv = cipher.generateIv();
      expect(iv).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(12);
      expect(mockCryptoModule.getRandomBytes).toHaveBeenCalledWith(12);
      expect(iv.every((byte) => byte === 0x42)).toBe(true);
    });
  });
});
