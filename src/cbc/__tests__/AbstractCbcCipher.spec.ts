import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AbstractCbcCipher } from '../AbstractCbcCipher';
import { CbcEnc } from '../../Enc';
import { CryptoModule } from 'expo-crypto-universal';

// Mock implementation for testing
class MockCbcCipher extends AbstractCbcCipher {
  async encryptInternal(): Promise<Uint8Array> {
    return new Uint8Array([1, 2, 3]);
  }

  async decryptInternal(): Promise<Uint8Array> {
    return new Uint8Array([4, 5, 6]);
  }

  async generateTag(): Promise<Uint8Array> {
    return new Uint8Array([7, 8, 9]);
  }
}

describe('AbstractCbcCipher', () => {
  let mockCryptoModule: CryptoModule;
  let cipher: MockCbcCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
      sha256Async: vi.fn().mockImplementation((data: Uint8Array) => {
        const hash = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
          hash[i] = data.reduce((acc, val) => acc + val, 0) % 256;
        }
        return Promise.resolve(hash);
      }),
    } as unknown as CryptoModule;
    cipher = new MockCbcCipher(mockCryptoModule);
  });

  describe('constructor', () => {
    it('should initialize with the provided crypto module', () => {
      expect(cipher).toBeInstanceOf(MockCbcCipher);
      expect(cipher['cryptoModule']).toBe(mockCryptoModule);
    });
  });

  describe('generateIv', () => {
    it('should generate a 16-byte IV', () => {
      const enc: CbcEnc = 'A128CBC-HS256';
      const iv = cipher.generateIv(enc);
      expect(iv).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(16);
      expect(mockCryptoModule.getRandomBytes).toHaveBeenCalledWith(16);
      expect(iv.every((byte) => byte === 0x42)).toBe(true);
    });
  });

  describe('timingSafeEqual', () => {
    it('should return true for equal arrays', async () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3]);

      const result = await cipher.timingSafeEqual(a, b);
      expect(result).toBe(true);
    });

    it('should return false for different arrays', async () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 4]);

      const result = await cipher.timingSafeEqual(a, b);
      expect(result).toBe(false);
    });

    it('should handle empty arrays', async () => {
      const a = new Uint8Array(0);
      const b = new Uint8Array(0);

      const result = await cipher.timingSafeEqual(a, b);
      expect(result).toBe(true);
    });

    it('should handle arrays of different lengths', async () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);

      const result = await cipher.timingSafeEqual(a, b);
      expect(result).toBe(false);
    });

    it('should use sha256Async from cryptoModule', async () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3]);

      await cipher.timingSafeEqual(a, b);

      expect(mockCryptoModule.sha256Async).toHaveBeenCalledTimes(2);
      expect(mockCryptoModule.sha256Async).toHaveBeenCalledWith(a);
      expect(mockCryptoModule.sha256Async).toHaveBeenCalledWith(b);
    });
  });
});
