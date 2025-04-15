import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Aes } from '../Aes';
import { CryptoModule } from 'expo-crypto-universal';
import crypto from 'crypto';

// Mock expo-crypto
vi.mock('expo-crypto', () => ({}));

describe('Aes', () => {
  let mockCryptoModule: CryptoModule;
  let originalWindow: any;

  beforeEach(() => {
    // Save original window object
    originalWindow = global.window;

    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
      sha256Async: vi.fn().mockImplementation((data: Uint8Array) => {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return Promise.resolve(new Uint8Array(hash.digest()));
      }),
    } as unknown as CryptoModule;
  });

  afterEach(() => {
    // Restore original window object
    global.window = originalWindow;
  });

  describe('implementation switching', () => {
    it('should use WebCbcCipher and WebGcmCipher when isWeb is true', () => {
      global.window = {
        crypto: {
          getRandomValues: vi.fn(),
        },
      } as unknown as Window & typeof globalThis;

      const webAes = new Aes(mockCryptoModule);
      expect(webAes['cbcCipher'].constructor.name).toBe('WebCbcCipher');
      expect(webAes['gcmCipher'].constructor.name).toBe('WebGcmCipher');
    });

    it('should use ForgeCbcCipher and ForgeGcmCipher when isWeb is false', () => {
      global.window = {} as unknown as Window & typeof globalThis;

      const nativeAes = new Aes(mockCryptoModule);
      expect(nativeAes['cbcCipher'].constructor.name).toBe('ForgeCbcCipher');
      expect(nativeAes['gcmCipher'].constructor.name).toBe('ForgeGcmCipher');
    });
  });

  describe('encrypt', () => {
    it.each([
      ['A128CBC-HS256', 32],
      ['A192CBC-HS384', 48],
      ['A256CBC-HS512', 64],
    ] as const)(
      'should encrypt data using CBC mode for %s',
      async (enc, cekLength) => {
        const cek = new Uint8Array(cekLength).fill(0xaa);
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);
        const aes = new Aes(mockCryptoModule);
        const result = await aes.encrypt({
          enc,
          cek,
          plaintext,
          aad,
        });

        expect(result.ciphertext).toBeDefined();
        expect(result.tag).toBeDefined();
        expect(result.iv).toBeDefined();
        expect(result.iv.length).toBe(16);
      },
    );

    it.each([
      ['A128GCM', 16],
      ['A192GCM', 24],
      ['A256GCM', 32],
    ] as const)(
      'should encrypt data using GCM mode for %s',
      async (enc, cekLength) => {
        const cek = new Uint8Array(cekLength).fill(0xaa);
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);
        const aes = new Aes(mockCryptoModule);

        const result = await aes.encrypt({
          enc,
          cek,
          plaintext,
          aad,
        });

        expect(result.ciphertext).toBeDefined();
        expect(result.tag).toBeDefined();
        expect(result.iv).toBeDefined();
        expect(result.iv.length).toBe(12);
      },
    );

    it('should throw error for unsupported encryption algorithm', async () => {
      const cek = new Uint8Array(32).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const aes = new Aes(mockCryptoModule);

      await expect(
        aes.encrypt({
          enc: 'UNSUPPORTED' as any,
          cek,
          plaintext,
          aad,
        }),
      ).rejects.toThrow('Unsupported encryption algorithm');
    });
  });

  describe('decrypt', () => {
    it.each([
      ['A128CBC-HS256', 32],
      ['A192CBC-HS384', 48],
      ['A256CBC-HS512', 64],
    ] as const)(
      'should decrypt data using CBC mode for %s',
      async (enc, cekLength) => {
        const cek = new Uint8Array(cekLength).fill(0xaa);
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);
        const aes = new Aes(mockCryptoModule);
        // First encrypt the data
        const encrypted = await aes.encrypt({
          enc,
          cek,
          plaintext,
          aad,
        });

        // Then decrypt it
        const decrypted = await aes.decrypt({
          enc,
          cek,
          ciphertext: encrypted.ciphertext,
          tag: encrypted.tag,
          iv: encrypted.iv,
          aad,
        });

        expect(decrypted).toEqual(plaintext);
      },
    );

    it.each([
      ['A128GCM', 16],
      ['A192GCM', 24],
      ['A256GCM', 32],
    ] as const)(
      'should decrypt data using GCM mode for %s',
      async (enc, cekLength) => {
        const cek = new Uint8Array(cekLength).fill(0xaa);
        const plaintext = new Uint8Array([1, 2, 3]);
        const aad = new Uint8Array([4, 5, 6]);
        const aes = new Aes(mockCryptoModule);
        // First encrypt the data
        const encrypted = await aes.encrypt({
          enc,
          cek,
          plaintext,
          aad,
        });

        // Then decrypt it
        const decrypted = await aes.decrypt({
          enc,
          cek,
          ciphertext: encrypted.ciphertext,
          tag: encrypted.tag,
          iv: encrypted.iv,
          aad,
        });

        expect(decrypted).toEqual(plaintext);
      },
    );

    it('should throw error for unsupported decryption algorithm', async () => {
      const cek = new Uint8Array(32).fill(0xaa);
      const ciphertext = new Uint8Array([1, 2, 3]);
      const tag = new Uint8Array(16).fill(0xbb);
      const iv = new Uint8Array(16).fill(0xcc);
      const aad = new Uint8Array([4, 5, 6]);
      const aes = new Aes(mockCryptoModule);
      await expect(
        aes.decrypt({
          enc: 'UNSUPPORTED' as any,
          cek,
          ciphertext,
          tag,
          iv,
          aad,
        }),
      ).rejects.toThrow('Unsupported decryption algorithm');
    });
  });
});
