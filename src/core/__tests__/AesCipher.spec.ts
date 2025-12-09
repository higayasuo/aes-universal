import { describe, it, expect, beforeEach } from 'vitest';
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
  let cipher: AesCipher;
  let cbc: MockCbcCipher;
  let gcm: MockGcmCipher;

  beforeEach(() => {
    cbc = new MockCbcCipher();
    gcm = new MockGcmCipher();
    cipher = new AesCipher({
      cbc,
      gcm,
    });
  });

  describe('encrypt', () => {
    it('should use CBC mode for A128CBC-HS256', async () => {
      const params = {
        enc: 'A128CBC-HS256' as Enc,
        plaintext: new Uint8Array([1, 2, 3]),
        cek: new Uint8Array(32),
        iv: new Uint8Array(16),
        aad: new Uint8Array([4, 5, 6]),
      };

      const result = await cipher.encrypt(params);

      expect(result.ciphertext).toEqual(new Uint8Array([1, 2, 3]));
      expect(result.tag).toBeDefined();
    });

    it('should use GCM mode for A128GCM', async () => {
      const params = {
        enc: 'A128GCM' as Enc,
        plaintext: new Uint8Array([1, 2, 3]),
        cek: new Uint8Array(16),
        iv: new Uint8Array(12),
        aad: new Uint8Array([4, 5, 6]),
      };

      const result = await cipher.encrypt(params);

      expect(result.ciphertext).toEqual(new Uint8Array([7, 8, 9]));
      expect(result.tag).toEqual(new Uint8Array(16).fill(0x42));
    });

    it('should throw for invalid encryption mode', async () => {
      const params = {
        enc: 'INVALID' as Enc,
        plaintext: new Uint8Array([1, 2, 3]),
        cek: new Uint8Array(16),
        iv: new Uint8Array(12),
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

  describe('getIvByteLength', () => {
    it('should return 16 for CBC algorithms', () => {
      expect(cipher.getIvByteLength('A128CBC-HS256')).toBe(16);
      expect(cipher.getIvByteLength('A192CBC-HS384')).toBe(16);
      expect(cipher.getIvByteLength('A256CBC-HS512')).toBe(16);
    });

    it('should return 12 for GCM algorithms', () => {
      expect(cipher.getIvByteLength('A128GCM')).toBe(12);
      expect(cipher.getIvByteLength('A192GCM')).toBe(12);
      expect(cipher.getIvByteLength('A256GCM')).toBe(12);
    });

    it('should throw for invalid encryption mode', () => {
      expect(() => cipher.getIvByteLength('INVALID' as Enc)).toThrow(
        'Invalid encryption mode: INVALID',
      );
    });
  });

  describe('getCekByteLength', () => {
    it('should return correct CEK byte length for CBC algorithms', () => {
      expect(cipher.getCekByteLength('A128CBC-HS256')).toBe(32);
      expect(cipher.getCekByteLength('A192CBC-HS384')).toBe(48);
      expect(cipher.getCekByteLength('A256CBC-HS512')).toBe(64);
    });

    it('should return correct CEK byte length for GCM algorithms', () => {
      expect(cipher.getCekByteLength('A128GCM')).toBe(16);
      expect(cipher.getCekByteLength('A192GCM')).toBe(24);
      expect(cipher.getCekByteLength('A256GCM')).toBe(32);
    });

    it('should throw for invalid encryption mode', () => {
      expect(() => cipher.getCekByteLength('INVALID' as Enc)).toThrow(
        'Invalid encryption mode: INVALID',
      );
    });
  });
});
