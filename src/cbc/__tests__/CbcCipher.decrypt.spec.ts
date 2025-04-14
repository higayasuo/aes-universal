import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebCbcCipher } from '../WebCbcCipher';
import { ForgeCbcCipher } from '../ForgeCbcCipher';
import { NodeCbcCipher } from './NodeCbcCipher';
import { CryptoModule } from 'expo-crypto-universal';
import crypto from 'crypto';

describe('CbcCipher.decrypt', () => {
  let mockCryptoModule: CryptoModule;
  let webCipher: WebCbcCipher;
  let forgeCipher: ForgeCbcCipher;
  let nodeCipher: NodeCbcCipher;

  beforeEach(() => {
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
    webCipher = new WebCbcCipher(mockCryptoModule);
    forgeCipher = new ForgeCbcCipher(mockCryptoModule);
    nodeCipher = new NodeCbcCipher(mockCryptoModule);
  });

  it.each(['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'] as const)(
    'should produce the same result across all implementations for %s',
    async (enc) => {
      const keyBytes =
        enc === 'A128CBC-HS256' ? 16 : enc === 'A192CBC-HS384' ? 24 : 32;
      const cek = new Uint8Array(keyBytes * 2).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const forgeResult = await forgeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(forgeResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'] as const)(
    'should handle empty ciphertext consistently for %s',
    async (enc) => {
      const keyBytes =
        enc === 'A128CBC-HS256' ? 16 : enc === 'A192CBC-HS384' ? 24 : 32;
      const cek = new Uint8Array(keyBytes * 2).fill(0xaa);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const forgeResult = await forgeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(forgeResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'] as const)(
    'should handle empty AAD consistently for %s',
    async (enc) => {
      const keyBytes =
        enc === 'A128CBC-HS256' ? 16 : enc === 'A192CBC-HS384' ? 24 : 32;
      const cek = new Uint8Array(keyBytes * 2).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      const webResult = await webCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const forgeResult = await forgeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(webResult).toEqual(nodeResult);
      expect(forgeResult).toEqual(nodeResult);
      expect(webResult).toEqual(plaintext);
    },
  );

  it.each(['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'] as const)(
    'should reject invalid tag for %s',
    async (enc) => {
      const keyBytes =
        enc === 'A128CBC-HS256' ? 16 : enc === 'A192CBC-HS384' ? 24 : 32;
      const cek = new Uint8Array(keyBytes * 2).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const invalidTag = new Uint8Array(keyBytes).fill(0xff);

      await expect(
        webCipher.decrypt({
          enc,
          cek,
          ciphertext,
          tag: invalidTag,
          iv,
          aad,
        }),
      ).rejects.toThrow();
      await expect(
        forgeCipher.decrypt({
          enc,
          cek,
          ciphertext,
          tag: invalidTag,
          iv,
          aad,
        }),
      ).rejects.toThrow();
      await expect(
        nodeCipher.decrypt({
          enc,
          cek,
          ciphertext,
          tag: invalidTag,
          iv,
          aad,
        }),
      ).rejects.toThrow();
    },
  );
});
