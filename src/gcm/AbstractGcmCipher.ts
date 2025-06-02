import { Cipher, DecryptArgs, EncryptArgs, EncryptResult } from '../Cipher';
import { isGcmEnc } from '../Enc';
import { parseKeyBits } from '../cbc/parseKeyBits';
import { RandomBytes } from '../types';

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
  async encrypt({
    enc,
    plaintext,
    cek,
    aad,
  }: EncryptArgs): Promise<EncryptResult> {
    if (!isGcmEnc(enc)) {
      throw new Error('Invalid encryption algorithm');
    }

    const keyBits = parseKeyBits(enc);
    this.verifyCekLength(cek, keyBits);

    const iv = this.generateIv();
    const { ciphertext, tag } = await this.encryptInternal({
      encRawKey: cek,
      plaintext,
      iv,
      aad,
    });

    return { ciphertext, tag, iv };
  }

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
  async decrypt({
    enc,
    cek,
    ciphertext,
    iv,
    tag,
    aad,
  }: DecryptArgs): Promise<Uint8Array> {
    if (!isGcmEnc(enc)) {
      throw new Error('Invalid encryption algorithm');
    }

    this.verifyTagLength(tag);
    this.verifyIvLength(iv);

    const keyBits = parseKeyBits(enc);
    this.verifyCekLength(cek, keyBits);

    const plaintext = await this.decryptInternal({
      encRawKey: cek,
      ciphertext,
      tag,
      iv,
      aad,
    });

    return plaintext;
  }

  /**
   * Verifies the length of the content encryption key (CEK).
   * @param cek - The content encryption key as a Uint8Array.
   * @param keyBits - The expected length of the key in bits.
   * @throws Will throw an error if the length of the CEK is not as expected.
   */
  verifyCekLength(cek: Uint8Array, keyBits: number) {
    if (cek.length !== keyBits >>> 3) {
      throw new Error('Invalid content encryption key length');
    }
  }

  /**
   * Verifies the length of the authentication tag.
   * @param tag - The authentication tag as a Uint8Array.
   * @throws Will throw an error if the length of the tag is not 16 bytes.
   */
  verifyTagLength(tag: Uint8Array) {
    if (tag.length !== 16) {
      throw new Error('Invalid tag length');
    }
  }

  /**
   * Verifies the length of the initialization vector (IV).
   * @param iv - The initialization vector as a Uint8Array.
   * @throws Will throw an error if the length of the IV is not 12 bytes.
   */
  verifyIvLength(iv: Uint8Array) {
    if (iv.length !== 12) {
      throw new Error('Invalid initialization vector length');
    }
  }

  /**
   * Generates an initialization vector (IV) for the given encryption algorithm.
   * @returns A Uint8Array representing the generated IV.
   */
  generateIv() {
    return this.randomBytes(12);
  }

  /**
   * Abstract method for the internal encryption process.
   * @param args - The arguments required for encryption.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  abstract encryptInternal(
    args: GcmEncryptInternalArgs,
  ): Promise<GcmEncryptInternalResult>;

  /**
   * Abstract method for the internal GCM decryption process.
   * @param args - The arguments required for GCM decryption.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  abstract decryptInternal(args: GcmDecryptInternalArgs): Promise<Uint8Array>;
}
