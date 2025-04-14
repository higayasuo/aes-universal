import { CryptoModule } from 'expo-crypto-universal';
import {
  AbstractCbcCipher,
  CbcDecryptInternalArgs,
  CbcEncryptInternalArgs,
  GenerateTagArgs,
} from './AbstractCbcCipher';

/**
 * Class representing a Web-based CBC mode cipher.
 * Extends the AbstractCbcCipher class to provide specific implementations
 * for web environments using the SubtleCrypto API.
 */
export class WebCbcCipher extends AbstractCbcCipher {
  /**
   * Constructs a WebCbcCipher instance.
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
    const encKey = await crypto.subtle.importKey(
      'raw',
      encRawKey,
      'AES-CBC',
      false,
      ['encrypt'],
    );

    return new Uint8Array(
      await crypto.subtle.encrypt(
        {
          iv,
          name: 'AES-CBC',
        },
        encKey,
        plaintext,
      ),
    );
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
    const encKey = await crypto.subtle.importKey(
      'raw',
      encRawKey,
      'AES-CBC',
      false,
      ['decrypt'],
    );

    return new Uint8Array(
      await crypto.subtle.decrypt({ iv, name: 'AES-CBC' }, encKey, ciphertext),
    );
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
    const macKey = await crypto.subtle.importKey(
      'raw',
      macRawKey,
      {
        hash: `SHA-${keyBits << 1}`,
        name: 'HMAC',
      },
      false,
      ['sign'],
    );

    return new Uint8Array(
      (await crypto.subtle.sign('HMAC', macKey, macData)).slice(
        0,
        keyBits >> 3,
      ),
    );
  }
}
