import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebCbcCipher } from '../WebCbcCipher';
import { ForgeCbcCipher } from '../ForgeCbcCipher';
import { NodeCbcCipher } from './NodeCbcCipher';
import { CryptoModule } from 'expo-crypto-universal';

describe('CbcCipher.encrypt', () => {
  let mockCryptoModule: CryptoModule;
  let webCipher: WebCbcCipher;
  let forgeCipher: ForgeCbcCipher;
  let nodeCipher: NodeCbcCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
    } as unknown as CryptoModule;
    webCipher = new WebCbcCipher(mockCryptoModule);
    forgeCipher = new ForgeCbcCipher(mockCryptoModule);
    nodeCipher = new NodeCbcCipher(mockCryptoModule);
  });

  it.each([
    ['A128CBC-HS256', 32],
    ['A192CBC-HS384', 48],
    ['A256CBC-HS512', 64],
  ] as const)(
    'should produce the same result across all implementations for %s',
    async (enc, cekLength) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);

      const webResult = await webCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const forgeResult = await forgeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(forgeResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(webResult.tag).toEqual(nodeResult.tag);
      expect(forgeResult.tag).toEqual(nodeResult.tag);
      expect(webResult.iv).toEqual(nodeResult.iv);
      expect(forgeResult.iv).toEqual(nodeResult.iv);
      expect(webResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );

  it.each([
    ['A128CBC-HS256', 32],
    ['A192CBC-HS384', 48],
    ['A256CBC-HS512', 64],
  ] as const)(
    'should handle empty plaintext consistently for %s',
    async (enc, cekLength) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);

      const webResult = await webCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const forgeResult = await forgeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(forgeResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(webResult.tag).toEqual(nodeResult.tag);
      expect(forgeResult.tag).toEqual(nodeResult.tag);
      expect(webResult.iv).toEqual(nodeResult.iv);
      expect(forgeResult.iv).toEqual(nodeResult.iv);
      expect(webResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );

  it.each([
    ['A128CBC-HS256', 32],
    ['A192CBC-HS384', 48],
    ['A256CBC-HS512', 64],
  ] as const)(
    'should handle empty AAD consistently for %s',
    async (enc, cekLength) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);

      const webResult = await webCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const forgeResult = await forgeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(forgeResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(webResult.tag).toEqual(nodeResult.tag);
      expect(forgeResult.tag).toEqual(nodeResult.tag);
      expect(webResult.iv).toEqual(nodeResult.iv);
      expect(forgeResult.iv).toEqual(nodeResult.iv);
      expect(webResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );
});
