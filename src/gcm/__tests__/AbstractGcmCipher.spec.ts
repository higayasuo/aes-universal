import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NodeGcmCipher } from './NodeGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

describe('AbstractGcmCipher', () => {
  let mockCryptoModule: CryptoModule;
  let cipher: NodeGcmCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
    } as unknown as CryptoModule;
    cipher = new NodeGcmCipher(mockCryptoModule);
  });

  describe('generateIv', () => {
    it('should generate a 12-byte IV', () => {
      const iv = cipher.generateIv();
      expect(iv).toBeDefined();
      expect(iv.length).toBe(12);
      expect(iv).toEqual(new Uint8Array(12).fill(0x42));
    });
  });
});
