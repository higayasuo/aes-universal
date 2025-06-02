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
    keyBits: 128,
    cekLength: 32,
    validTagLength: 16,
    invalidTagLength: 15,
  },
  {
    enc: 'A192CBC-HS384',
    keyBits: 192,
    cekLength: 48,
    validTagLength: 24,
    invalidTagLength: 23,
  },
  {
    enc: 'A256CBC-HS512',
    keyBits: 256,
    cekLength: 64,
    validTagLength: 32,
    invalidTagLength: 31,
  },
] as const;

// Mock implementation for testing
class MockCbcCipher extends AbstractCbcCipher {
  async encryptInternal(_args: CbcEncryptInternalArgs): Promise<Uint8Array> {
    return new Uint8Array([1, 2, 3]);
  }

  async decryptInternal(_args: CbcDecryptInternalArgs): Promise<Uint8Array> {
    return new Uint8Array([4, 5, 6]);
  }

  async generateTag(args: GenerateTagArgs): Promise<Uint8Array> {
    // Return a tag with length based on keyBits
    const tagLength = args.keyBits >>> 3;
    return new Uint8Array(tagLength).fill(0x42);
  }
}

describe('AbstractCbcCipher', () => {
  let cipher: MockCbcCipher;

  beforeEach(() => {
    const randomBytes = vi
      .fn()
      .mockImplementation((size) => new Uint8Array(size).fill(0x42));
    cipher = new MockCbcCipher(randomBytes);
  });

  describe('verifyCekLength', () => {
    it.each(keyConfigs)(
      'should not throw for valid CEK length with $enc',
      ({ keyBits, cekLength }) => {
        const cek = new Uint8Array(cekLength);
        expect(() => cipher.verifyCekLength(cek, keyBits)).not.toThrow();
      },
    );

    it.each(keyConfigs)(
      'should throw for invalid CEK length with $enc',
      ({ keyBits, cekLength }) => {
        const cek = new Uint8Array(cekLength - 1);
        expect(() => cipher.verifyCekLength(cek, keyBits)).toThrow(
          'Invalid content encryption key length',
        );
      },
    );
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
        ).rejects.toThrow('Invalid content encryption key length');
      },
    );
  });

  describe('verifyTagLength', () => {
    it.each(keyConfigs)(
      'should not throw for valid tag length with $enc',
      ({ keyBits, validTagLength }) => {
        const tag = new Uint8Array(validTagLength);
        expect(() => cipher.verifyTagLength(tag, keyBits)).not.toThrow();
      },
    );

    it.each(keyConfigs)(
      'should throw for invalid tag length with $enc',
      ({ keyBits, invalidTagLength }) => {
        const tag = new Uint8Array(invalidTagLength);
        expect(() => cipher.verifyTagLength(tag, keyBits)).toThrow(
          'Invalid tag length',
        );
      },
    );
  });

  describe('verifyIvLength', () => {
    it('should not throw for valid IV length', () => {
      const iv = new Uint8Array(16);
      expect(() => cipher.verifyIvLength(iv)).not.toThrow();
    });

    it('should throw for invalid IV length', () => {
      const iv = new Uint8Array(15);
      expect(() => cipher.verifyIvLength(iv)).toThrow(
        'Invalid initialization vector length',
      );
    });
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
        ).rejects.toThrow('Invalid content encryption key length');
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
      ).rejects.toThrow('Invalid initialization vector length');
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
        ).rejects.toThrow('Invalid tag length');
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

  describe('generateTag', () => {
    it('should generate a tag with length based on keyBits', async () => {
      const args: GenerateTagArgs = {
        keyBits: 256,
        macRawKey: new Uint8Array(32),
        macData: new Uint8Array([1, 2, 3]),
      };

      const tag = await cipher.generateTag(args);
      expect(tag).toBeInstanceOf(Uint8Array);
      expect(tag.length).toBe(32); // 256 >>> 3 = 32
      expect(tag.every((byte) => byte === 0x42)).toBe(true);
    });

    it('should generate a tag with length based on keyBits for 128-bit key', async () => {
      const args: GenerateTagArgs = {
        keyBits: 128,
        macRawKey: new Uint8Array(16),
        macData: new Uint8Array([1, 2, 3]),
      };

      const tag = await cipher.generateTag(args);
      expect(tag).toBeInstanceOf(Uint8Array);
      expect(tag.length).toBe(16); // 128 >>> 3 = 16
      expect(tag.every((byte) => byte === 0x42)).toBe(true);
    });
  });
});
