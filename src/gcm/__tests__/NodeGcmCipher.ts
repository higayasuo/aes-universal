import { AbstractGcmCipher } from '../AbstractGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';
import crypto from 'crypto';

export class NodeGcmCipher extends AbstractGcmCipher {
  constructor(cryptoModule: CryptoModule) {
    super(cryptoModule);
  }

  async encryptInternal({
    encRawKey,
    iv,
    plaintext,
    aad,
  }: {
    encRawKey: Uint8Array;
    iv: Uint8Array;
    plaintext: Uint8Array;
    aad: Uint8Array;
  }): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
    const nodeCipher = crypto.createCipheriv('aes-128-gcm', encRawKey, iv);
    nodeCipher.setAAD(aad);
    const nodeResult = Buffer.concat([
      nodeCipher.update(plaintext),
      nodeCipher.final(),
    ]);
    const tag = nodeCipher.getAuthTag();
    return {
      ciphertext: new Uint8Array(nodeResult),
      tag: new Uint8Array(tag),
    };
  }

  async decryptInternal({
    encRawKey,
    iv,
    ciphertext,
    tag,
    aad,
  }: {
    encRawKey: Uint8Array;
    iv: Uint8Array;
    ciphertext: Uint8Array;
    tag: Uint8Array;
    aad: Uint8Array;
  }): Promise<Uint8Array> {
    const nodeDecipher = crypto.createDecipheriv('aes-128-gcm', encRawKey, iv);
    nodeDecipher.setAAD(aad);
    nodeDecipher.setAuthTag(tag);
    const nodeResult = Buffer.concat([
      nodeDecipher.update(ciphertext),
      nodeDecipher.final(),
    ]);
    return new Uint8Array(nodeResult);
  }
}
