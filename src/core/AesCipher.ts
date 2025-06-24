import { isCbcEnc, isGcmEnc, Enc } from '@/constants/Enc';
import { AbstractCbcCipher } from './cbc/AbstractCbcCipher';
import { createCbcCipher } from './cbc/createCbcCipher';
import { Cipher, DecryptParams, EncryptParams, EncryptResult } from './Cipher';
import { AbstractGcmCipher } from './gcm/AbstractGcmCipher';
import { createGcmCipher } from './gcm/createGcmCipher';
import { RandomBytes } from '@/common/types';
import { parseKeyBitLength } from '@/common/utils/parseKeyBitLength';

/**
 * Parameters required to construct an AesCipher instance.
 * @template CBC - The type of CBC cipher instance, must extend AbstractCbcCipher
 * @template CBCConstructor - The constructor type for the CBC cipher
 * @template GCM - The type of GCM cipher instance, must extend AbstractGcmCipher
 * @template GCMConstructor - The constructor type for the GCM cipher
 * @property {CBCConstructor} cbc - The constructor function for the CBC cipher
 * @property {GCMConstructor} gcm - The constructor function for the GCM cipher
 * @property {RandomBytes} randomBytes - The function used to generate random bytes
 */
export type AesCipherConstructorParams<
  CBC extends AbstractCbcCipher,
  CBCConstructor extends new (...args: any[]) => CBC,
  GCM extends AbstractGcmCipher,
  GCMConstructor extends new (...args: any[]) => GCM,
> = {
  cbc: CBCConstructor;
  gcm: GCMConstructor;
  randomBytes: RandomBytes;
};

/**
 * A cipher implementation that supports both CBC and GCM modes of AES encryption.
 * @template CBC - The type of CBC cipher instance, must extend AbstractCbcCipher
 * @template CBCConstructor - The constructor type for the CBC cipher
 * @template GCM - The type of GCM cipher instance, must extend AbstractGcmCipher
 * @template GCMConstructor - The constructor type for the GCM cipher
 */
export class AesCipher<
  CBC extends AbstractCbcCipher = AbstractCbcCipher,
  CBCConstructor extends new (...args: any[]) => CBC = new (
    ...args: any[]
  ) => CBC,
  GCM extends AbstractGcmCipher = AbstractGcmCipher,
  GCMConstructor extends new (...args: any[]) => GCM = new (
    ...args: any[]
  ) => GCM,
> implements Cipher
{
  /** The CBC cipher instance */
  private cbc: CBC;
  /** The GCM cipher instance */
  private gcm: GCM;
  /** The function used to generate random bytes */
  readonly randomBytes: RandomBytes;

  /**
   * Constructs an AesCipher instance.
   * @param params - The parameters required to construct the cipher
   */
  constructor({
    cbc,
    gcm,
    randomBytes,
  }: AesCipherConstructorParams<CBC, CBCConstructor, GCM, GCMConstructor>) {
    this.cbc = createCbcCipher(cbc, randomBytes);
    this.gcm = createGcmCipher(gcm, randomBytes);
    this.randomBytes = randomBytes;
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
   * Generates a Content Encryption Key (CEK) for the specified encryption algorithm.
   * For CBC mode, the CEK length is twice the key length since it's used for both
   * encryption and MAC operations. For GCM mode, the CEK length matches the key length.
   *
   * @param enc - The encryption algorithm identifier
   * @returns A Uint8Array containing the generated CEK
   */
  generateCek = (enc: Enc): Uint8Array => {
    const keyBitLength = parseKeyBitLength(enc);
    const keyByteLength = keyBitLength >> 3;
    const cekByteLength = keyByteLength * (isCbcEnc(enc) ? 2 : 1);
    return this.randomBytes(cekByteLength);
  };
}
