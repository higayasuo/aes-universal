import { Cipher, DecryptArgs, EncryptArgs, EncryptResult } from '../Cipher';
import { generateMacData } from './generateMacData';
import { isCbcEnc } from '../Enc';
import { parseKeyBits } from './parseKeyBits';
import { divideCek } from './divideCek';
import { RandomBytes } from '../types';
import { timingSafeEqual } from './timingSafeEqual';

/**
 * Arguments required for the internal CBC encryption process.
 */
export type CbcEncryptInternalArgs = {
  /** The raw encryption key as a Uint8Array. */
  encRawKey: Uint8Array;
  /** The initialization vector as a Uint8Array. */
  iv: Uint8Array;
  /** The plaintext data to be encrypted as a Uint8Array. */
  plaintext: Uint8Array;
};

/**
 * Arguments required for the internal CBC decryption process.
 */
export type CbcDecryptInternalArgs = {
  /** The raw encryption key as a Uint8Array. */
  encRawKey: Uint8Array;
  /** The initialization vector as a Uint8Array. */
  iv: Uint8Array;
  /** The ciphertext data to be decrypted as a Uint8Array. */
  ciphertext: Uint8Array;
};

/**
 * Arguments required for generating a tag.
 */
export type GenerateTagArgs = {
  /** The raw MAC key as a Uint8Array. */
  macRawKey: Uint8Array;
  /** The MAC data as a Uint8Array. */
  macData: Uint8Array;
  /** The number of key bits. */
  keyBits: number;
};

/**
 * Abstract class representing a CBC mode cipher.
 * Implements the Cipher interface.
 */
export abstract class AbstractCbcCipher implements Cipher {
  /** The function used to generate random bytes. */
  protected randomBytes: RandomBytes;

  /**
   * Constructs an AbstractCbcCipher instance.
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
    if (!isCbcEnc(enc)) {
      throw new Error('Invalid encryption algorithm');
    }

    const iv = this.generateIv();
    const keyBits = parseKeyBits(enc);
    this.verifyCekLength(cek, keyBits);
    const { encRawKey, macRawKey } = divideCek({ cek, keyBytes: keyBits >> 3 });

    const ciphertext = await this.encryptInternal({
      iv,
      encRawKey,
      plaintext,
    });

    const macData = generateMacData({ aad, iv, ciphertext });
    const tag = await this.generateTag({
      macRawKey: macRawKey,
      macData,
      keyBits,
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
    if (!isCbcEnc(enc)) {
      throw new Error('Invalid encryption algorithm');
    }

    this.verifyIvLength(iv);

    const keyBits = parseKeyBits(enc);
    this.verifyCekLength(cek, keyBits);
    this.verifyTagLength(tag, keyBits);

    const { encRawKey, macRawKey } = divideCek({ cek, keyBytes: keyBits >> 3 });
    const macData = generateMacData({ aad, iv, ciphertext });
    const expectedTag = await this.generateTag({ macRawKey, macData, keyBits });

    if (!timingSafeEqual(expectedTag, tag)) {
      throw new Error('Invalid authentication tag');
    }

    const plaintext = await this.decryptInternal({
      encRawKey,
      ciphertext,
      iv,
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
    if (cek.length !== keyBits >>> 2) {
      throw new Error('Invalid content encryption key length');
    }
  }

  /**
   * Verifies the length of the authentication tag.
   * @param tag - The authentication tag as a Uint8Array.
   * @param keyBits - The expected length of the key in bits.
   * @throws Will throw an error if the length of the tag is not as expected.
   */
  verifyTagLength(tag: Uint8Array, keyBits: number) {
    if (tag.length !== keyBits >>> 3) {
      throw new Error('Invalid tag length');
    }
  }

  /**
   * Verifies the length of the initialization vector (IV).
   * @param iv - The initialization vector as a Uint8Array.
   * @throws Will throw an error if the length of the IV is not 16 bytes.
   */
  verifyIvLength(iv: Uint8Array) {
    if (iv.length !== 16) {
      throw new Error('Invalid initialization vector length');
    }
  }

  /**
   * Generates an initialization vector (IV) for the given encryption algorithm.
   * @returns A Uint8Array representing the generated IV.
   */
  generateIv() {
    return this.randomBytes(16);
  }

  /**
   * Abstract method for the internal encryption process.
   * @param args - The arguments required for encryption.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  abstract encryptInternal(args: CbcEncryptInternalArgs): Promise<Uint8Array>;

  /**
   * Abstract method for the internal decryption process.
   * @param args - The arguments required for decryption.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  abstract decryptInternal(args: CbcDecryptInternalArgs): Promise<Uint8Array>;

  /**
   * Abstract method for generating a tag.
   * @param args - The arguments required for tag generation.
   * @returns A promise that resolves to the generated tag as a Uint8Array.
   */
  abstract generateTag(args: GenerateTagArgs): Promise<Uint8Array>;
}
