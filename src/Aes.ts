import { CryptoModule } from 'expo-crypto-universal';
import { Cipher, DecryptArgs, EncryptArgs, EncryptResult } from './Cipher';
import { isCbcEnc, isGcmEnc } from './Enc';
import { WebCbcCipher } from './cbc/WebCbcCipher';
import { ForgeCbcCipher } from './cbc/ForgeCbcCipher';
import { WebGcmCipher } from './gcm/WebGcmCipher';
import { ForgeGcmCipher } from './gcm/ForgeGcmCipher';

export const isWeb = () =>
  typeof window !== 'undefined' &&
  typeof window.crypto?.getRandomValues === 'function';

export class Aes implements Cipher {
  protected cryptoModule: CryptoModule;
  protected cbcCipher: Cipher;
  protected gcmCipher: Cipher;

  constructor(cryptoModule: CryptoModule) {
    this.cryptoModule = cryptoModule;

    if (isWeb()) {
      this.cbcCipher = new WebCbcCipher(cryptoModule);
      this.gcmCipher = new WebGcmCipher(cryptoModule);
    } else {
      this.cbcCipher = new ForgeCbcCipher(cryptoModule);
      this.gcmCipher = new ForgeGcmCipher(cryptoModule);
    }
  }

  async encrypt(args: EncryptArgs): Promise<EncryptResult> {
    if (isCbcEnc(args.enc)) {
      return this.cbcCipher.encrypt(args);
    }

    if (isGcmEnc(args.enc)) {
      return this.gcmCipher.encrypt(args);
    }

    throw new Error(`Unsupported encryption algorithm: ${args.enc}`);
  }

  async decrypt(args: DecryptArgs): Promise<Uint8Array> {
    if (isCbcEnc(args.enc)) {
      return this.cbcCipher.decrypt(args);
    }

    if (isGcmEnc(args.enc)) {
      return this.gcmCipher.decrypt(args);
    }

    throw new Error(`Unsupported decryption algorithm: ${args.enc}`);
  }
}
