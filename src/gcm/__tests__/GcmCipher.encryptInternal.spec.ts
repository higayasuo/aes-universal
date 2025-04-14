import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebGcmCipher } from '../WebGcmCipher';
import { ForgeGcmCipher } from '../ForgeGcmCipher';
import { NodeGcmCipher } from './NodeGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

describe('GcmCipher.encryptInternal', () => {
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

  it('should produce the same result across all implementations', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(12).fill(0x42);
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array([4, 5, 6]);

    const webResult = await webCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const forgeResult = await forgeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });

    expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(forgeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(webResult.tag).toEqual(nodeResult.tag);
    expect(forgeResult.tag).toEqual(nodeResult.tag);
  });

  it('should handle empty plaintext consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(12).fill(0x42);
    const plaintext = new Uint8Array(0);
    const aad = new Uint8Array([4, 5, 6]);

    const webResult = await webCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const forgeResult = await forgeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });

    expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(forgeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(webResult.tag).toEqual(nodeResult.tag);
    expect(forgeResult.tag).toEqual(nodeResult.tag);
  });

  it('should handle empty AAD consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(12).fill(0x42);
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array(0);

    const webResult = await webCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const forgeResult = await forgeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });

    expect(webResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(forgeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(webResult.tag).toEqual(nodeResult.tag);
    expect(forgeResult.tag).toEqual(nodeResult.tag);
  });
});
