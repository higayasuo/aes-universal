import { Cipher, DecryptParams, EncryptParams, EncryptResult } from '../Cipher';
import { Enc, isGcmEnc } from '@/constants/Enc';
import { parseKeyBitLength } from '@/common/utils/parseKeyBitLength';
import { gcmVerifyCekLength } from './utils/gcmVerifyCekLength';
import { gcmVerifyIvLength } from './utils/gcmVerifyIvLength';
import { gcmVerifyTagLength } from './utils/gcmVerifyTagLength';
import { gcmGetCekByteLength } from './utils/gcmGetCekByteLength';

/**
 * Parameters required for the internal GCM encryption process.
 */
export type GcmEncryptInternalParams = {
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
 * Parameters required for the internal GCM decryption process.
 */
export type GcmDecryptInternalParams = {
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
    if (!isGcmEnc(enc)) {
      throw new Error(`Invalid encryption algorithm: ${enc}`);
    }

    gcmVerifyIvLength(iv);

    const keyBitLength = parseKeyBitLength(enc);
    gcmVerifyCekLength(cek, keyBitLength);

    const { ciphertext, tag } = await this.encryptInternal({
      encRawKey: cek,
      plaintext,
      iv,
      aad,
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
    if (!isGcmEnc(enc)) {
      throw new Error(`Invalid encryption algorithm: ${enc}`);
    }

    gcmVerifyTagLength(tag);
    gcmVerifyIvLength(iv);

    const keyBitLength = parseKeyBitLength(enc);
    gcmVerifyCekLength(cek, keyBitLength);

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
   * Returns the byte length of the initialization vector (IV) for GCM encryption.
   * For GCM mode, the IV is always 12 bytes.
   * @returns The IV byte length as a number (always 12 for GCM).
   */
  getIvByteLength = () => 12;

  /**
   * Returns the required byte length of the content encryption key (CEK) for the given GCM encryption algorithm.
   * For GCM mode, the CEK length matches the key length.
   * @param enc - The encryption algorithm identifier.
   * @returns The required CEK byte length for the specified GCM algorithm.
   */
  getCekByteLength = (enc: Enc) => gcmGetCekByteLength(enc);

  /**
   * Abstract method for the internal encryption process.
   * @param args - The arguments required for encryption.
   * @returns A promise that resolves to the encrypted data as a Uint8Array.
   */
  encryptInternal = (
    _: GcmEncryptInternalParams,
  ): Promise<GcmEncryptInternalResult> => {
    throw new Error('Not implemented');
  };

  /**
   * Abstract method for the internal GCM decryption process.
   * @param args - The arguments required for GCM decryption.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   */
  decryptInternal = (_: GcmDecryptInternalParams): Promise<Uint8Array> => {
    throw new Error('Not implemented');
  };
}
