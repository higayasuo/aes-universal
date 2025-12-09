import { Cipher, DecryptParams, EncryptParams, EncryptResult } from '../Cipher';
import { generateMacData } from './utils/generateMacData';
import { Enc, isCbcEnc } from '@/constants/Enc';
import { parseKeyBitLength } from '@/common/utils/parseKeyBitLength';
import { divideCek } from './utils/divideCek';
import { timingSafeEqual } from './utils/timingSafeEqual';
import { cbcVerifyCekLength } from './utils/cbcVerifyCekLength';
import { cbcVerifyTagLength } from './utils/cbcVerifyTagLength';
import { cbcVerifyIvLength } from './utils/cbcVerifyIvLength';
import { cbcGetCekByteLength } from './utils/cbcGetCekByteLength';

/**
 * Parameters required for the internal CBC encryption process.
 */
export type CbcEncryptInternalParams = {
  /** The raw encryption key as a Uint8Array. */
  encRawKey: Uint8Array;
  /** The initialization vector as a Uint8Array. */
  iv: Uint8Array;
  /** The plaintext data to be encrypted as a Uint8Array. */
  plaintext: Uint8Array;
};

/**
 * Parameters required for the internal CBC decryption process.
 */
export type CbcDecryptInternalParams = {
  /** The raw encryption key as a Uint8Array. */
  encRawKey: Uint8Array;
  /** The initialization vector as a Uint8Array. */
  iv: Uint8Array;
  /** The ciphertext data to be decrypted as a Uint8Array. */
  ciphertext: Uint8Array;
};

/**
 * Parameters required for generating a tag.
 */
export type GenerateTagParams = {
  /** The raw MAC key as a Uint8Array. */
  macRawKey: Uint8Array;
  /** The MAC data as a Uint8Array. */
  macData: Uint8Array;
  /** The length of the key in bits. */
  keyBitLength: number;
};

/**
 * Abstract class representing a CBC mode cipher.
 * Implements the Cipher interface.
 */
export abstract class AbstractCbcCipher implements Cipher {
  /**
   * Encrypts the given plaintext using the specified encryption algorithm.
   * @param enc - The encryption algorithm to use.
   * @param plaintext - The plaintext data to encrypt.
   * @param cek - The content encryption key.
   * @param iv - The initialization vector.
   * @param aad - Additional authenticated data.
   * @returns A promise that resolves to the encryption result.
   * @throws Will throw an error if the encryption algorithm is invalid.
   */
  encrypt = async ({
    enc,
    plaintext,
    cek,
    iv,
    aad,
  }: EncryptParams): Promise<EncryptResult> => {
    if (!isCbcEnc(enc)) {
      throw new Error(`Invalid encryption algorithm: ${enc}`);
    }

    cbcVerifyIvLength(iv);

    const keyBitLength = parseKeyBitLength(enc);
    cbcVerifyCekLength(cek, keyBitLength);
    const { encRawKey, macRawKey } = divideCek({
      cek,
      keyBitLength,
    });

    const ciphertext = await this.encryptInternal({
      iv,
      encRawKey,
      plaintext,
    });

    const macData = generateMacData({ aad, iv, ciphertext });
    const tag = await this.generateTag({
      macRawKey,
      macData,
      keyBitLength,
    });

    return { ciphertext, tag };
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
  }: DecryptParams): Promise<Uint8Array> => {
    if (!isCbcEnc(enc)) {
      throw new Error(`Invalid encryption algorithm: ${enc}`);
    }

    cbcVerifyIvLength(iv);

    const keyBitLength = parseKeyBitLength(enc);
    cbcVerifyCekLength(cek, keyBitLength);
    cbcVerifyTagLength(tag, keyBitLength);

    const { encRawKey, macRawKey } = divideCek({
      cek,
      keyBitLength,
    });
    const macData = generateMacData({ aad, iv, ciphertext });
    const expectedTag = await this.generateTag({
      macRawKey,
      macData,
      keyBitLength,
    });

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
   * Returns the byte length of the initialization vector (IV) required for CBC encryption.
   * The IV length required for CBC mode (AES-CBC) is always 16 bytes (128 bits) per the JWE specification.
   * @param enc - The encryption algorithm identifier (not used, included for interface compatibility).
   * @returns The IV byte length required for CBC mode (always 16).
   */
  getIvByteLength = (_enc: Enc) => 16;

  /**
   * Returns the required byte length of the content encryption key (CEK) for the given CBC encryption algorithm.
   * For CBC mode, the CEK is twice the key length since it's used for both encryption and MAC operations.
   * @param enc - The encryption algorithm identifier.
   * @returns The required CEK byte length for the specified CBC algorithm.
   */
  getCekByteLength = (enc: Enc) => cbcGetCekByteLength(enc);

  /**
   * Abstract method for the internal encryption process.
   * @param args - The arguments required for encryption.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  encryptInternal = (_: CbcEncryptInternalParams): Promise<Uint8Array> => {
    throw new Error('Not implemented');
  };

  /**
   * Abstract method for the internal decryption process.
   * @param args - The arguments required for decryption.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  decryptInternal = (_: CbcDecryptInternalParams): Promise<Uint8Array> => {
    throw new Error('Not implemented');
  };

  /**
   * Abstract method for generating a tag.
   * @param args - The arguments required for tag generation.
   * @returns A promise that resolves to the generated tag as a Uint8Array.
   */
  generateTag = (_: GenerateTagParams): Promise<Uint8Array> => {
    throw new Error('Not implemented');
  };
}
