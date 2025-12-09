import { describe, it, expect, beforeEach } from 'vitest';
import {
  AbstractGcmCipher,
  GcmEncryptInternalParams,
  GcmDecryptInternalParams,
} from '../AbstractGcmCipher';

// Key configurations for testing
const keyConfigs = [
  {
    enc: 'A128GCM',
    keyBitLength: 128,
    cekLength: 16,
    invalidCekLength: 15,
  },
  {
    enc: 'A192GCM',
    keyBitLength: 192,
    cekLength: 24,
    invalidCekLength: 23,
  },
  {
    enc: 'A256GCM',
    keyBitLength: 256,
    cekLength: 32,
    invalidCekLength: 31,
  },
] as const;

// Mock implementation for testing
class MockGcmCipher extends AbstractGcmCipher {
  encryptInternal = async (_args: GcmEncryptInternalParams) => {
    return {
      ciphertext: new Uint8Array([1, 2, 3]),
      tag: new Uint8Array(16).fill(0x42),
    };
  };

  decryptInternal = async (_args: GcmDecryptInternalParams) => {
    return new Uint8Array([4, 5, 6]);
  };
}

describe('AbstractGcmCipher', () => {
  let cipher: MockGcmCipher;

  beforeEach(() => {
    cipher = new MockGcmCipher();
  });

  describe('encrypt', () => {
    it.each(keyConfigs)(
      'should verify CEK length before encryption with $enc',
      async ({ enc, cekLength }) => {
        const cek = new Uint8Array(cekLength);
        const plaintext = new Uint8Array([1, 2, 3]);
        const iv = new Uint8Array(12);
        const aad = new Uint8Array([4, 5, 6]);

        const result = await cipher.encrypt({
          enc,
          cek,
          plaintext,
          iv,
          aad,
        });

        expect(result).toBeDefined();
        expect(result.ciphertext).toBeDefined();
        expect(result.tag).toBeDefined();
      },
    );

    it.each(keyConfigs)(
      'should throw for invalid CEK length with $enc',
      async ({ enc, invalidCekLength }) => {
        const cek = new Uint8Array(invalidCekLength);
        const plaintext = new Uint8Array([1, 2, 3]);
        const iv = new Uint8Array(12);
        const aad = new Uint8Array([4, 5, 6]);

        await expect(
          cipher.encrypt({
            enc,
            cek,
            plaintext,
            iv,
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

  describe('getIvByteLength', () => {
    it.each(keyConfigs)(
      'should return 12 for GCM mode with $enc',
      ({ enc }) => {
        expect(cipher.getIvByteLength(enc)).toBe(12);
      },
    );
  });

  describe('getCekByteLength', () => {
    it.each(keyConfigs)(
      'should return correct CEK byte length for $enc',
      ({ enc, cekLength }) => {
        expect(cipher.getCekByteLength(enc)).toBe(cekLength);
      },
    );
  });
});
