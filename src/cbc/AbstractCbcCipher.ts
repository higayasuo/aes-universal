import { Cipher, DecryptArgs, EncryptArgs, EncryptResult } from '../Cipher';
import { generateMacData } from './generateMacData';
import { isCbcEnc } from '../Enc';
import { parseKeyBits } from '../parseKeyBits';
import { divideCek } from './divideCek';
import { RandomBytes } from '../types';
import { timingSafeEqual } from './timingSafeEqual';
import { cbcVerifyCekLength } from './cbcVerifyCekLength';
import { cbcVerifyTagLength } from './cbcVerifyTagLength';
import { cbcVerifyIvLength } from './cbcVerifyIvLength';

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
  encrypt = async ({
    enc,
    plaintext,
    cek,
    aad,
  }: EncryptArgs): Promise<EncryptResult> => {
    if (!isCbcEnc(enc)) {
      throw new Error('Invalid encryption algorithm');
    }

    const iv = this.generateIv();
    const keyBits = parseKeyBits(enc);
    cbcVerifyCekLength(cek, keyBits);
    const { encRawKey, macRawKey } = divideCek({ cek, keyBytes: keyBits >> 3 });

    const ciphertext = await this.encryptInternal({
      iv,
      encRawKey,
      plaintext,
    });

    const macData = generateMacData({ aad, iv, ciphertext });
    const tag = await this.generateTag({
      macRawKey,
      macData,
      keyBits,
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
    if (!isCbcEnc(enc)) {
      throw new Error('Invalid encryption algorithm');
    }

    cbcVerifyIvLength(iv);

    const keyBits = parseKeyBits(enc);
    cbcVerifyCekLength(cek, keyBits);
    cbcVerifyTagLength(tag, keyBits);

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
  };

  /**
   * Generates an initialization vector (IV) for the given encryption algorithm.
   * @returns A Uint8Array representing the generated IV.
   */
  generateIv = () => this.randomBytes(16);

  /**
   * Abstract method for the internal encryption process.
   * @param args - The arguments required for encryption.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  encryptInternal = (_: CbcEncryptInternalArgs): Promise<Uint8Array> => {
    throw new Error('Not implemented');
  };

  /**
   * Abstract method for the internal decryption process.
   * @param args - The arguments required for decryption.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  decryptInternal = (_: CbcDecryptInternalArgs): Promise<Uint8Array> => {
    throw new Error('Not implemented');
  };

  /**
   * Abstract method for generating a tag.
   * @param args - The arguments required for tag generation.
   * @returns A promise that resolves to the generated tag as a Uint8Array.
   */
  generateTag = (_: GenerateTagArgs): Promise<Uint8Array> => {
    throw new Error('Not implemented');
  };
}
