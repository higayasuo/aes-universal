import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  AbstractCbcCipher,
  CbcEncryptInternalArgs,
  CbcDecryptInternalArgs,
  GenerateTagArgs,
} from '../AbstractCbcCipher';

// Key configurations for testing
const keyConfigs = [
  {
    enc: 'A128CBC-HS256',
    keyBitLength: 128,
    cekLength: 32,
    validTagLength: 16,
    invalidTagLength: 15,
  },
  {
    enc: 'A192CBC-HS384',
    keyBitLength: 192,
    cekLength: 48,
    validTagLength: 24,
    invalidTagLength: 23,
  },
  {
    enc: 'A256CBC-HS512',
    keyBitLength: 256,
    cekLength: 64,
    validTagLength: 32,
    invalidTagLength: 31,
  },
] as const;

// Mock implementation for testing
class MockCbcCipher extends AbstractCbcCipher {
  encryptInternal = async (
    _args: CbcEncryptInternalArgs,
  ): Promise<Uint8Array> => {
    return new Uint8Array([1, 2, 3]);
  };

  decryptInternal = async (
    _args: CbcDecryptInternalArgs,
  ): Promise<Uint8Array> => {
    return new Uint8Array([4, 5, 6]);
  };

  generateTag = async (args: GenerateTagArgs): Promise<Uint8Array> => {
    // Return a tag with length based on keyBitLength
    const tagLength = args.keyBitLength >>> 3;
    return new Uint8Array(tagLength).fill(0x42);
  };
}

describe('AbstractCbcCipher', () => {
  let cipher: MockCbcCipher;

  beforeEach(() => {
    const randomBytes = vi
      .fn()
      .mockImplementation((size) => new Uint8Array(size).fill(0x42));
    cipher = new MockCbcCipher(randomBytes);
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
      async ({ enc, cekLength }) => {
        const cek = new Uint8Array(cekLength - 1);
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);

        await expect(
          cipher.encrypt({
            enc,
            cek,
            plaintext,
            aad,
          }),
        ).rejects.toThrow('Invalid CBC content encryption key length');
      },
    );
  });

  describe('decrypt', () => {
    it.each(keyConfigs)(
      'should verify CEK length before decryption with $enc',
      async ({ enc, cekLength, validTagLength }) => {
        const cek = new Uint8Array(cekLength);
        const ciphertext = new Uint8Array([1, 2, 3]);
        const iv = new Uint8Array(16);
        const tag = new Uint8Array(validTagLength).fill(0x42);
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
      async ({ enc, cekLength, validTagLength }) => {
        const cek = new Uint8Array(cekLength - 1);
        const ciphertext = new Uint8Array([1, 2, 3]);
        const iv = new Uint8Array(16);
        const tag = new Uint8Array(validTagLength).fill(0x42);
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
        ).rejects.toThrow('Invalid CBC content encryption key length');
      },
    );

    it('should verify IV length before decryption', async () => {
      const config = keyConfigs[0]; // A128CBC-HS256
      const cek = new Uint8Array(config.cekLength);
      const ciphertext = new Uint8Array([1, 2, 3]);
      const iv = new Uint8Array(15); // Invalid length
      const tag = new Uint8Array(config.validTagLength).fill(0x42);
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
      ).rejects.toThrow('Invalid CBC IV length');
    });

    it.each(keyConfigs)(
      'should verify tag length before decryption with $enc',
      async ({ enc, cekLength, invalidTagLength }) => {
        const cek = new Uint8Array(cekLength);
        const ciphertext = new Uint8Array([1, 2, 3]);
        const iv = new Uint8Array(16);
        const tag = new Uint8Array(invalidTagLength);
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
        ).rejects.toThrow('Invalid CBC authentication tag length');
      },
    );
  });

  describe('constructor', () => {
    it('should initialize with the provided randomBytes function', () => {
      const randomBytes = vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42));
      const cipher = new MockCbcCipher(randomBytes);
      expect(cipher).toBeInstanceOf(MockCbcCipher);
    });
  });

  describe('generateIv', () => {
    it('should generate a 16-byte IV', () => {
      const randomBytes = vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42));
      const cipher = new MockCbcCipher(randomBytes);
      const iv = cipher.generateIv();
      expect(iv).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(16);
      expect(randomBytes).toHaveBeenCalledWith(16);
      expect(iv.every((byte) => byte === 0x42)).toBe(true);
    });
  });
});
