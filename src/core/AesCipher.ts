import { Enc } from '@/types/Enc';
import { isCbcEnc, isGcmEnc } from '@/common/utils/isEnc';
import { AbstractCbcCipher } from './cbc/AbstractCbcCipher';
import { Cipher, DecryptParams, EncryptParams, EncryptResult } from './Cipher';
import { AbstractGcmCipher } from './gcm/AbstractGcmCipher';

/**
 * Parameters required to construct an AesCipher instance.
 * @property {AbstractCbcCipher} cbc - The CBC cipher instance.
 * @property {AbstractGcmCipher} gcm - The GCM cipher instance.
 */
export interface AesCipherConstructorParams {
  cbc: AbstractCbcCipher;
  gcm: AbstractGcmCipher;
}

/**
 * A cipher implementation that supports both CBC and GCM modes of AES encryption.
 * Implements the Cipher interface.
 */
export class AesCipher implements Cipher {
  /** The CBC cipher instance */
  private cbc: AbstractCbcCipher;
  /** The GCM cipher instance */
  private gcm: AbstractGcmCipher;

  /**
   * Constructs an AesCipher instance.
   * @param params - The parameters required to construct the cipher
   */
  constructor({ cbc, gcm }: AesCipherConstructorParams) {
    this.cbc = cbc;
    this.gcm = gcm;
  }

  /**
   * Encrypts data using either CBC or GCM mode based on the specified algorithm.
   * @param params - The encryption parameters
   * @returns A promise that resolves to the encryption result
   * @throws Will throw an error if the encryption algorithm is invalid
   */
  encrypt = async (params: EncryptParams): Promise<EncryptResult> => {
    const { enc } = params;
    if (isCbcEnc(enc)) {
      return this.cbc.encrypt(params);
    }

    if (isGcmEnc(enc)) {
      return this.gcm.encrypt(params);
    }

    throw new Error(`Invalid encryption mode: ${enc}`);
  };

  /**
   * Decrypts data using either CBC or GCM mode based on the specified algorithm.
   * @param params - The decryption parameters
   * @returns A promise that resolves to the decrypted data
   * @throws Will throw an error if the decryption algorithm is invalid
   */
  decrypt = async (params: DecryptParams): Promise<Uint8Array> => {
    const { enc } = params;
    if (isCbcEnc(enc)) {
      return this.cbc.decrypt(params);
    }

    if (isGcmEnc(enc)) {
      return this.gcm.decrypt(params);
    }

    throw new Error(`Invalid encryption mode: ${enc}`);
  };

  /**
   * Returns the required byte length of the initialization vector (IV)
   * for the specified encryption algorithm.
   * Delegates to CBC or GCM implementation depending on the mode.
   *
   * @param enc - The encryption algorithm identifier.
   * @returns The IV byte length required for the specified algorithm.
   * @throws Will throw an error if the encryption mode is invalid.
   */
  getIvByteLength = (enc: Enc) => {
    if (isCbcEnc(enc)) {
      return this.cbc.getIvByteLength(enc);
    }

    if (isGcmEnc(enc)) {
      return this.gcm.getIvByteLength(enc);
    }

    throw new Error(`Invalid encryption mode: ${enc}`);
  };

  /**
   * Returns the required byte length of the content encryption key (CEK)
   * for the specified encryption algorithm.
   * Delegates to CBC or GCM implementation depending on the mode.
   *
   * @param enc - The encryption algorithm identifier.
   * @returns The CEK byte length required for the specified algorithm.
   * @throws Will throw an error if the encryption mode is invalid.
   */
  getCekByteLength = (enc: Enc) => {
    if (isCbcEnc(enc)) {
      return this.cbc.getCekByteLength(enc);
    }

    if (isGcmEnc(enc)) {
      return this.gcm.getCekByteLength(enc);
    }

    throw new Error(`Invalid encryption mode: ${enc}`);
  };
}
