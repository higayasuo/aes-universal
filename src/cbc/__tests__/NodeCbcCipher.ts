import { AbstractCbcCipher } from '../AbstractCbcCipher';
import { CryptoModule } from 'expo-crypto-universal';
import {
  CbcDecryptInternalArgs,
  CbcEncryptInternalArgs,
  GenerateTagArgs,
} from '../AbstractCbcCipher';
import crypto from 'crypto';

export class NodeCbcCipher extends AbstractCbcCipher {
  constructor(cryptoModule: CryptoModule) {
    super(cryptoModule);
  }

  async encryptInternal({
    encRawKey,
    iv,
    plaintext,
  }: CbcEncryptInternalArgs): Promise<Uint8Array> {
    const keyLength = encRawKey.length * 8;
    const nodeCipher = crypto.createCipheriv(
      `aes-${keyLength}-cbc`,
      encRawKey,
      iv,
    );
    const nodeResult = Buffer.concat([
      nodeCipher.update(plaintext),
      nodeCipher.final(),
    ]);

    return new Uint8Array(nodeResult);
  }

  async decryptInternal({
    encRawKey,
    iv,
    ciphertext,
  }: CbcDecryptInternalArgs): Promise<Uint8Array> {
    const keyLength = encRawKey.length * 8;
    const nodeDecipher = crypto.createDecipheriv(
      `aes-${keyLength}-cbc`,
      encRawKey,
      iv,
    );
    const nodeResult = Buffer.concat([
      nodeDecipher.update(ciphertext),
      nodeDecipher.final(),
    ]);

    return new Uint8Array(nodeResult);
  }

  async generateTag({
    macRawKey,
    macData,
    keyBits,
  }: GenerateTagArgs): Promise<Uint8Array> {
    const hash = `sha${keyBits << 1}` as 'sha256' | 'sha384' | 'sha512';
    const hmac = crypto.createHmac(hash, macRawKey);
    hmac.update(macData);
    return new Uint8Array(hmac.digest()).slice(0, keyBits / 8);
  }
}
