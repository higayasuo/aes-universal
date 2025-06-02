import { describe, it, expect } from 'vitest';
import { encodeEncryptionData, decodeEncryptionData } from '../encryptionData';

describe('encryptionData', () => {
  describe('encodeEncryptionData', () => {
    it('should encode encryption data correctly', () => {
      const data = {
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array([4, 5, 6]),
        tag: new Uint8Array([7, 8, 9]),
        aad: new Uint8Array([10, 11, 12]),
      };

      const encoded = encodeEncryptionData(data);
      expect(encoded).toBeInstanceOf(Uint8Array);
      expect(encoded.length).toBeGreaterThan(0);
    });

    it('should handle empty arrays', () => {
      const data = {
        ciphertext: new Uint8Array(0),
        iv: new Uint8Array(0),
        tag: new Uint8Array(0),
        aad: new Uint8Array(0),
      };

      const encoded = encodeEncryptionData(data);
      expect(encoded).toBeInstanceOf(Uint8Array);
      expect(encoded.length).toBeGreaterThan(0);
    });
  });

  describe('decodeEncryptionData', () => {
    it('should decode encryption data correctly', () => {
      const originalData = {
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array([4, 5, 6]),
        tag: new Uint8Array([7, 8, 9]),
        aad: new Uint8Array([10, 11, 12]),
      };

      const encoded = encodeEncryptionData(originalData);
      const decoded = decodeEncryptionData(encoded);

      expect(decoded).toEqual(originalData);
      expect(decoded.ciphertext).toBeInstanceOf(Uint8Array);
      expect(decoded.iv).toBeInstanceOf(Uint8Array);
      expect(decoded.tag).toBeInstanceOf(Uint8Array);
      expect(decoded.aad).toBeInstanceOf(Uint8Array);
    });

    it('should handle empty arrays', () => {
      const originalData = {
        ciphertext: new Uint8Array(0),
        iv: new Uint8Array(0),
        tag: new Uint8Array(0),
        aad: new Uint8Array(0),
      };

      const encoded = encodeEncryptionData(originalData);
      const decoded = decodeEncryptionData(encoded);

      expect(decoded).toEqual(originalData);
      expect(decoded.ciphertext).toBeInstanceOf(Uint8Array);
      expect(decoded.iv).toBeInstanceOf(Uint8Array);
      expect(decoded.tag).toBeInstanceOf(Uint8Array);
      expect(decoded.aad).toBeInstanceOf(Uint8Array);
    });

    it('should handle large arrays', () => {
      const originalData = {
        ciphertext: new Uint8Array(1000).fill(1),
        iv: new Uint8Array(1000).fill(2),
        tag: new Uint8Array(1000).fill(3),
        aad: new Uint8Array(1000).fill(4),
      };

      const encoded = encodeEncryptionData(originalData);
      const decoded = decodeEncryptionData(encoded);

      expect(decoded).toEqual(originalData);
      expect(decoded.ciphertext).toBeInstanceOf(Uint8Array);
      expect(decoded.iv).toBeInstanceOf(Uint8Array);
      expect(decoded.tag).toBeInstanceOf(Uint8Array);
      expect(decoded.aad).toBeInstanceOf(Uint8Array);
    });
  });
});
