import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebGcmCipher } from '../WebGcmCipher';
import { ForgeGcmCipher } from '../ForgeGcmCipher';
import { NodeGcmCipher } from './NodeGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

describe('GcmCipher.decryptInternal', () => {
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
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array([4, 5, 6]);
    const { ciphertext, tag, iv } = await nodeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });

    const webResult = await webCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });
    const forgeResult = await forgeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });
    const nodeResult = await nodeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });

    expect(webResult).toEqual(nodeResult);
    expect(forgeResult).toEqual(nodeResult);
    expect(webResult).toEqual(plaintext);
  });

  it('should handle empty ciphertext consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const plaintext = new Uint8Array(0);
    const aad = new Uint8Array([4, 5, 6]);
    const { ciphertext, tag, iv } = await nodeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });

    const webResult = await webCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });
    const forgeResult = await forgeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });
    const nodeResult = await nodeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });

    expect(webResult).toEqual(nodeResult);
    expect(forgeResult).toEqual(nodeResult);
    expect(webResult).toEqual(plaintext);
  });

  it('should handle empty AAD consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array(0);
    const { ciphertext, tag, iv } = await nodeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });

    const webResult = await webCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });
    const forgeResult = await forgeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });
    const nodeResult = await nodeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
      tag,
      aad,
    });

    expect(webResult).toEqual(nodeResult);
    expect(forgeResult).toEqual(nodeResult);
    expect(webResult).toEqual(plaintext);
  });

  it('should reject invalid tag', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array([4, 5, 6]);
    const { ciphertext, iv } = await nodeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });
    const invalidTag = new Uint8Array(16).fill(0xff);

    await expect(
      webCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag: invalidTag,
        aad,
      }),
    ).rejects.toThrow();
    await expect(
      forgeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag: invalidTag,
        aad,
      }),
    ).rejects.toThrow();
    await expect(
      nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag: invalidTag,
        aad,
      }),
    ).rejects.toThrow();
  });
});
