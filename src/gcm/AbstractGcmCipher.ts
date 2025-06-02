import { Cipher, DecryptArgs, EncryptArgs, EncryptResult } from '../Cipher';
import { isGcmEnc } from '../Enc';
import { parseKeyBits } from '../parseKeyBits';
import { RandomBytes } from '../types';
import { gcmVerifyCekLength } from './gcmVerifyCekLength';
import { gcmVerifyIvLength } from './gcmVerifyIvLength';
import { gcmVerifyTagLength } from './gcmVerifyTagLength';

/**
 * Arguments required for the internal GCM encryption process.
 */
export type GcmEncryptInternalArgs = {
  /**
   * The raw encryption key as a Uint8Array.
   */
  encRawKey: Uint8Array;

  /**
   * The plaintext data to be encrypted as a Uint8Array.
   */
  plaintext: Uint8Array;

  /**
   * The initialization vector as a Uint8Array.
   */
  iv: Uint8Array;

  /**
   * Additional authenticated data as a Uint8Array.
   */
  aad: Uint8Array;
};

/**
 * Result of the internal GCM encryption process.
 */
export type GcmEncryptInternalResult = {
  /**
   * The encrypted data as a Uint8Array.
   */
  ciphertext: Uint8Array;

  /**
   * The authentication tag as a Uint8Array.
   */
  tag: Uint8Array;
};

/**
 * Arguments required for the internal GCM decryption process.
 */
export type GcmDecryptInternalArgs = {
  /**
   * The raw encryption key as a Uint8Array.
   */
  encRawKey: Uint8Array;

  /**
   * The ciphertext data to be decrypted as a Uint8Array.
   */
  ciphertext: Uint8Array;

  /**
   * The authentication tag as a Uint8Array.
   */
  tag: Uint8Array;

  /**
   * The initialization vector as a Uint8Array.
   */
  iv: Uint8Array;

  /**
   * Additional authenticated data as a Uint8Array.
   */
  aad: Uint8Array;
};

/**
 * Abstract class representing a GCM mode cipher.
 * Implements the Cipher interface.
 */
export abstract class AbstractGcmCipher implements Cipher {
  /** The function used to generate random bytes. */
  protected randomBytes: RandomBytes;

  /**
   * Constructs an AbstractGcmCipher instance.
   * @param randomBytes - The function used to generate random bytes.
   */
  constructor(randomBytes: RandomBytes) {
    this.randomBytes = randomBytes;
  }

  /**
   * Encrypts the given plaintext using the specified encryption algorithm.
   * @param enc - The encryption algorithm to use.
   * @param plaintext - The plaintext data to encrypt.
   * @param cek - The content encryption key.
   * @param aad - Additional authenticated data.
   * @returns A promise that resolves to the encryption result.
   * @throws Will throw an error if the encryption algorithm is invalid.
   */
  encrypt = async ({
    enc,
    plaintext,
    cek,
    aad,
  }: EncryptArgs): Promise<EncryptResult> => {
    if (!isGcmEnc(enc)) {
      throw new Error('Invalid encryption algorithm');
    }

    const keyBits = parseKeyBits(enc);
    gcmVerifyCekLength(cek, keyBits);

    const iv = this.generateIv();
    const { ciphertext, tag } = await this.encryptInternal({
      encRawKey: cek,
      plaintext,
      iv,
      aad,
    });

    return { ciphertext, tag, iv };
  };

  /**
   * Decrypts the given ciphertext using the specified decryption algorithm.
   * @param enc - The decryption algorithm to use.
   * @param cek - The content encryption key.
   * @param ciphertext - The ciphertext data to decrypt.
   * @param iv - The initialization vector.
   * @param tag - The authentication tag.
   * @param aad - Additional authenticated data.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  decrypt = async ({
    enc,
    cek,
    ciphertext,
    iv,
    tag,
    aad,
  }: DecryptArgs): Promise<Uint8Array> => {
    if (!isGcmEnc(enc)) {
      throw new Error('Invalid encryption algorithm');
    }

    gcmVerifyTagLength(tag);
    gcmVerifyIvLength(iv);

    const keyBits = parseKeyBits(enc);
    gcmVerifyCekLength(cek, keyBits);

    const plaintext = await this.decryptInternal({
      encRawKey: cek,
      ciphertext,
      tag,
      iv,
      aad,
    });

    return plaintext;
  };

  /**
   * Generates an initialization vector (IV) for the given encryption algorithm.
   * @returns A Uint8Array representing the generated IV.
   */
  generateIv = () => this.randomBytes(12);

  /**
   * Abstract method for the internal encryption process.
   * @param args - The arguments required for encryption.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  encryptInternal = (
    _: GcmEncryptInternalArgs,
  ): Promise<GcmEncryptInternalResult> => {
    throw new Error('Not implemented');
  };

  /**
   * Abstract method for the internal GCM decryption process.
   * @param args - The arguments required for GCM decryption.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  decryptInternal = (_: GcmDecryptInternalArgs): Promise<Uint8Array> => {
    throw new Error('Not implemented');
  };
}
