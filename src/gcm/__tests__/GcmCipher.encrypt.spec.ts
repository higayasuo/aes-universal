import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebGcmCipher } from '../WebGcmCipher';
import { ForgeGcmCipher } from '../ForgeGcmCipher';
import { NodeGcmCipher } from './NodeGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

describe('GcmCipher.encrypt', () => {
  let mockCryptoModule: CryptoModule;
  let webCipher: WebGcmCipher;
  let forgeCipher: ForgeGcmCipher;
  let nodeCipher: NodeGcmCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
    } as unknown as CryptoModule;
    webCipher = new WebGcmCipher(mockCryptoModule);
    forgeCipher = new ForgeGcmCipher(mockCryptoModule);
    nodeCipher = new NodeGcmCipher(mockCryptoModule);
  });

  it.each(['A128GCM', 'A192GCM', 'A256GCM'] as const)(
    'should produce the same result across all implementations for %s',
    async (enc) => {
      const cek = new Uint8Array(16).fill(0xaa);
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
    },
  );

  it.each(['A128GCM', 'A192GCM', 'A256GCM'] as const)(
    'should handle empty plaintext consistently for %s',
    async (enc) => {
      const cek = new Uint8Array(16).fill(0xaa);
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
    },
  );

  it.each(['A128GCM', 'A192GCM', 'A256GCM'] as const)(
    'should handle empty AAD consistently for %s',
    async (enc) => {
      const cek = new Uint8Array(16).fill(0xaa);
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
    },
  );
});
