import { describe, it, expect, vi } from 'vitest';
import { AesCipher } from '../AesCipher';
import {
  AbstractCbcCipher,
  CbcEncryptInternalParams,
  CbcDecryptInternalParams,
  GenerateTagParams,
} from '../cbc/AbstractCbcCipher';
import {
  AbstractGcmCipher,
  GcmEncryptInternalParams,
  GcmDecryptInternalParams,
} from '../gcm/AbstractGcmCipher';
import { RandomBytes } from '@/common/types';
import { Enc } from '@/constants/Enc';

// Mock CBC implementation
class MockCbcCipher extends AbstractCbcCipher {
  private readonly mockTag = new Uint8Array(16).fill(0x42);

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
    return this.mockTag;
  };
}

// Mock GCM implementation
class MockGcmCipher extends AbstractGcmCipher {
  encryptInternal = async (_args: GcmEncryptInternalParams) => {
    return {
      ciphertext: new Uint8Array([7, 8, 9]),
      tag: new Uint8Array(16).fill(0x42),
    };
  };

  decryptInternal = async (
    _args: GcmDecryptInternalParams,
  ): Promise<Uint8Array> => {
    return new Uint8Array([10, 11, 12]);
  };
}

describe('AesCipher', () => {
  const randomBytes: RandomBytes = (size = 32) =>
    new Uint8Array(size).fill(0x42);
  const cipher = new AesCipher({
    cbc: MockCbcCipher,
    gcm: MockGcmCipher,
    randomBytes,
  });

  describe('encrypt', () => {
    it('should use CBC mode for A128CBC-HS256', async () => {
      const params = {
        enc: 'A128CBC-HS256' as Enc,
        plaintext: new Uint8Array([1, 2, 3]),
        cek: new Uint8Array(32),
        aad: new Uint8Array([4, 5, 6]),
      };

      const result = await cipher.encrypt(params);

      expect(result.ciphertext).toEqual(new Uint8Array([1, 2, 3]));
      expect(result.tag).toBeDefined();
      expect(result.iv).toBeDefined();
    });

    it('should use GCM mode for A128GCM', async () => {
      const params = {
        enc: 'A128GCM' as Enc,
        plaintext: new Uint8Array([1, 2, 3]),
        cek: new Uint8Array(16),
        aad: new Uint8Array([4, 5, 6]),
      };

      const result = await cipher.encrypt(params);

      expect(result.ciphertext).toEqual(new Uint8Array([7, 8, 9]));
      expect(result.tag).toEqual(new Uint8Array(16).fill(0x42));
      expect(result.iv).toBeDefined();
    });

    it('should throw for invalid encryption mode', async () => {
      const params = {
        enc: 'INVALID' as Enc,
        plaintext: new Uint8Array([1, 2, 3]),
        cek: new Uint8Array(16),
        aad: new Uint8Array([4, 5, 6]),
      };

      await expect(cipher.encrypt(params)).rejects.toThrow(
        'Invalid encryption mode: INVALID',
      );
    });
  });

  describe('decrypt', () => {
    it('should use CBC mode for A128CBC-HS256', async () => {
      const mockTag = new Uint8Array(16).fill(0x42);
      const params = {
        enc: 'A128CBC-HS256' as Enc,
        cek: new Uint8Array(32),
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array(16),
        tag: mockTag,
        aad: new Uint8Array([4, 5, 6]),
      };

      const result = await cipher.decrypt(params);

      expect(result).toEqual(new Uint8Array([4, 5, 6]));
    });

    it('should use GCM mode for A128GCM', async () => {
      const params = {
        enc: 'A128GCM' as Enc,
        cek: new Uint8Array(16),
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array(12),
        tag: new Uint8Array(16),
        aad: new Uint8Array([4, 5, 6]),
      };

      const result = await cipher.decrypt(params);

      expect(result).toEqual(new Uint8Array([10, 11, 12]));
    });

    it('should throw for invalid decryption mode', async () => {
      const params = {
        enc: 'INVALID' as Enc,
        cek: new Uint8Array(16),
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array(12),
        tag: new Uint8Array(16),
        aad: new Uint8Array([4, 5, 6]),
      };

      await expect(cipher.decrypt(params)).rejects.toThrow(
        'Invalid encryption mode: INVALID',
      );
    });
  });

  describe('generateCek', () => {
    it('should generate correct CEK length for A128CBC-HS256', () => {
      const cek = cipher.generateCek('A128CBC-HS256');
      expect(cek.length).toBe(32); // 16 bytes for encryption + 16 bytes for MAC
      expect(cek).toEqual(new Uint8Array(32).fill(0x42));
    });

    it('should generate correct CEK length for A192CBC-HS384', () => {
      const cek = cipher.generateCek('A192CBC-HS384');
      expect(cek.length).toBe(48); // 24 bytes for encryption + 24 bytes for MAC
      expect(cek).toEqual(new Uint8Array(48).fill(0x42));
    });

    it('should generate correct CEK length for A256CBC-HS512', () => {
      const cek = cipher.generateCek('A256CBC-HS512');
      expect(cek.length).toBe(64); // 32 bytes for encryption + 32 bytes for MAC
      expect(cek).toEqual(new Uint8Array(64).fill(0x42));
    });

    it('should generate correct CEK length for A128GCM', () => {
      const cek = cipher.generateCek('A128GCM');
      expect(cek.length).toBe(16);
      expect(cek).toEqual(new Uint8Array(16).fill(0x42));
    });

    it('should generate correct CEK length for A192GCM', () => {
      const cek = cipher.generateCek('A192GCM');
      expect(cek.length).toBe(24);
      expect(cek).toEqual(new Uint8Array(24).fill(0x42));
    });

    it('should generate correct CEK length for A256GCM', () => {
      const cek = cipher.generateCek('A256GCM');
      expect(cek.length).toBe(32);
      expect(cek).toEqual(new Uint8Array(32).fill(0x42));
    });
  });
});
