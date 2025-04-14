import { CryptoModule } from 'expo-crypto-universal';
import forge from 'node-forge';
import {
  AbstractCbcCipher,
  CbcDecryptInternalArgs,
  CbcEncryptInternalArgs,
  GenerateTagArgs,
} from './AbstractCbcCipher';

/**
 * Class representing a Forge-based CBC mode cipher.
 * Extends the AbstractCbcCipher class to provide specific implementations
 * for environments using the node-forge library.
 */
export class ForgeCbcCipher extends AbstractCbcCipher {
  /**
   * Constructs a ForgeCbcCipher instance.
   * @param cryptoModule - The crypto module to be used for cryptographic operations.
   */
  constructor(cryptoModule: CryptoModule) {
    super(cryptoModule);
  }

  /**
   * Performs the internal encryption process using the AES-CBC algorithm.
   * @param args - The arguments required for encryption, including the raw encryption key, IV, and plaintext.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  async encryptInternal({
    encRawKey,
    iv,
    plaintext,
  }: CbcEncryptInternalArgs): Promise<Uint8Array> {
    const keyBinary = forge.util.binary.raw.encode(encRawKey);
    const ivBinary = forge.util.binary.raw.encode(iv);

    const cipher = forge.cipher.createCipher('AES-CBC', keyBinary);
    cipher.start({
      iv: ivBinary,
    });

    const plaintextBuffer = forge.util.createBuffer(plaintext);
    cipher.update(plaintextBuffer);

    if (!cipher.finish()) {
      throw new Error('Encryption failed');
    }

    return forge.util.binary.raw.decode(cipher.output.getBytes());
  }

  /**
   * Performs the internal decryption process using the AES-CBC algorithm.
   * @param args - The arguments required for decryption, including the raw encryption key, IV, and ciphertext.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  async decryptInternal({
    encRawKey,
    iv,
    ciphertext,
  }: CbcDecryptInternalArgs): Promise<Uint8Array> {
    const keyBinary = forge.util.binary.raw.encode(encRawKey);
    const ivBinary = forge.util.binary.raw.encode(iv);

    const decipher = forge.cipher.createDecipher('AES-CBC', keyBinary);
    decipher.start({
      iv: ivBinary,
    });

    const ciphertextBuffer = forge.util.createBuffer(ciphertext);
    decipher.update(ciphertextBuffer);

    if (!decipher.finish()) {
      throw new Error('Decryption failed');
    }

    return forge.util.binary.raw.decode(decipher.output.getBytes());
  }

  /**
   * Generates a tag using the HMAC algorithm.
   * @param args - The arguments required for tag generation, including the raw MAC key, MAC data, and key bits.
   * @returns A promise that resolves to the generated tag as a Uint8Array.
   */
  async generateTag({
    macRawKey,
    macData,
    keyBits,
  }: GenerateTagArgs): Promise<Uint8Array> {
    const algorithm = `sha${keyBits << 1}` as forge.md.Algorithm;
    const hmac = forge.hmac.create();
    hmac.start(algorithm, forge.util.binary.raw.encode(macRawKey));
    hmac.update(forge.util.binary.raw.encode(macData));

    return forge.util.binary.raw
      .decode(hmac.digest().getBytes())
      .slice(0, keyBits >> 3);
  }
}
