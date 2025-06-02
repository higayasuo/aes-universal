import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  AbstractGcmCipher,
  GcmEncryptInternalArgs,
  GcmDecryptInternalArgs,
} from '../AbstractGcmCipher';
import { RandomBytes } from '@/common/types';

// Key configurations for testing
const keyConfigs = [
  {
    enc: 'A128GCM',
    keyBits: 128,
    cekLength: 16,
    invalidCekLength: 15,
  },
  {
    enc: 'A192GCM',
    keyBits: 192,
    cekLength: 24,
    invalidCekLength: 23,
  },
  {
    enc: 'A256GCM',
    keyBits: 256,
    cekLength: 32,
    invalidCekLength: 31,
  },
] as const;

// Mock implementation for testing
class MockGcmCipher extends AbstractGcmCipher {
  encryptInternal = async (_args: GcmEncryptInternalArgs) => {
    return {
      ciphertext: new Uint8Array([1, 2, 3]),
      tag: new Uint8Array(16).fill(0x42),
    };
  };

  decryptInternal = async (_args: GcmDecryptInternalArgs) => {
    return new Uint8Array([4, 5, 6]);
  };
}

describe('AbstractGcmCipher', () => {
  let randomBytes: RandomBytes;
  let cipher: MockGcmCipher;

  beforeEach(() => {
    randomBytes = vi
      .fn()
      .mockImplementation((size) => new Uint8Array(size).fill(0x42));
    cipher = new MockGcmCipher(randomBytes);
  });

  describe('encrypt', () => {
    it.each(keyConfigs)(
      'should verify CEK length before encryption with $enc',
      async ({ enc, cekLength }) => {
        const cek = new Uint8Array(cekLength);
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);

        const result = await cipher.encrypt({
          enc,
          cek,
          plaintext,
          aad,
        });

        expect(result).toBeDefined();
        expect(result.ciphertext).toBeDefined();
        expect(result.tag).toBeDefined();
        expect(result.iv).toBeDefined();
      },
    );

    it.each(keyConfigs)(
      'should throw for invalid CEK length with $enc',
      async ({ enc, invalidCekLength }) => {
        const cek = new Uint8Array(invalidCekLength);
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);

        await expect(
          cipher.encrypt({
            enc,
            cek,
            plaintext,
            aad,
          }),
        ).rejects.toThrow('Invalid GCM content encryption key length');
      },
    );
  });

  describe('decrypt', () => {
    it.each(keyConfigs)(
      'should verify CEK length before decryption with $enc',
      async ({ enc, cekLength }) => {
        const cek = new Uint8Array(cekLength);
        const ciphertext = new Uint8Array([1, 2, 3]);
        const iv = new Uint8Array(12);
        const tag = new Uint8Array(16).fill(0x42);
        const aad = new Uint8Array([4, 5, 6]);

        const result = await cipher.decrypt({
          enc,
          cek,
          ciphertext,
          iv,
          tag,
          aad,
        });

        expect(result).toBeDefined();
        expect(result).toBeInstanceOf(Uint8Array);
      },
    );

    it.each(keyConfigs)(
      'should throw for invalid CEK length with $enc',
      async ({ enc, invalidCekLength }) => {
        const cek = new Uint8Array(invalidCekLength);
        const ciphertext = new Uint8Array([1, 2, 3]);
        const iv = new Uint8Array(12);
        const tag = new Uint8Array(16).fill(0x42);
        const aad = new Uint8Array([4, 5, 6]);

        await expect(
          cipher.decrypt({
            enc,
            cek,
            ciphertext,
            iv,
            tag,
            aad,
          }),
        ).rejects.toThrow('Invalid GCM content encryption key length');
      },
    );

    it('should verify IV length before decryption', async () => {
      const config = keyConfigs[0]; // A128GCM
      const cek = new Uint8Array(config.cekLength);
      const ciphertext = new Uint8Array([1, 2, 3]);
      const iv = new Uint8Array(11); // Invalid length
      const tag = new Uint8Array(16).fill(0x42);
      const aad = new Uint8Array([4, 5, 6]);

      await expect(
        cipher.decrypt({
          enc: config.enc,
          cek,
          ciphertext,
          iv,
          tag,
          aad,
        }),
      ).rejects.toThrow('Invalid GCM IV length');
    });

    it('should verify tag length before decryption', async () => {
      const config = keyConfigs[0]; // A128GCM
      const cek = new Uint8Array(config.cekLength);
      const ciphertext = new Uint8Array([1, 2, 3]);
      const iv = new Uint8Array(12);
      const tag = new Uint8Array(15); // Invalid length
      const aad = new Uint8Array([4, 5, 6]);

      await expect(
        cipher.decrypt({
          enc: config.enc,
          cek,
          ciphertext,
          iv,
          tag,
          aad,
        }),
      ).rejects.toThrow('Invalid GCM authentication tag length');
    });
  });

  describe('constructor', () => {
    it('should initialize with the provided randomBytes function', () => {
      const randomBytes = vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42));
      const cipher = new MockGcmCipher(randomBytes);
      expect(cipher).toBeInstanceOf(MockGcmCipher);
    });
  });

  describe('generateIv', () => {
    it('should generate a 12-byte IV', () => {
      const iv = cipher.generateIv();
      expect(iv).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(12);
      expect(randomBytes).toHaveBeenCalledWith(12);
      expect(iv.every((byte) => byte === 0x42)).toBe(true);
    });
  });
});
