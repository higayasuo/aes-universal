import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebCbcCipher } from '../WebCbcCipher';
import { ForgeCbcCipher } from '../ForgeCbcCipher';
import { NodeCbcCipher } from './NodeCbcCipher';
import { CryptoModule } from 'expo-crypto-universal';
import crypto from 'crypto';

describe('CbcCipher.encryptInternal', () => {
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

  it('should produce the same result across all implementations', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(16).fill(0x42);
    const plaintext = new Uint8Array([1, 2, 3]);

    const webResult = await webCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });
    const forgeResult = await forgeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });

    expect(webResult).toEqual(nodeResult);
    expect(forgeResult).toEqual(nodeResult);
  });

  it('should handle empty plaintext consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(16).fill(0x42);
    const plaintext = new Uint8Array(0);

    const webResult = await webCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });
    const forgeResult = await forgeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });

    expect(webResult).toEqual(nodeResult);
    expect(forgeResult).toEqual(nodeResult);
  });

  it('should handle block-aligned plaintext with PKCS#7 padding consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(16).fill(0x42);
    const plaintext = new Uint8Array(1024).fill(0xaa);

    const webResult = await webCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });
    const forgeResult = await forgeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });

    expect(webResult).toEqual(nodeResult);
    expect(forgeResult).toEqual(nodeResult);
    expect(webResult.length).toBe(1040); // 1024 + 16 bytes of padding
  });
});
