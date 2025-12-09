import { Enc } from '@/types/Enc';

/**
 * Parameters required for encryption operation.
 * @property {Enc} enc - The encryption algorithm to use.
 * @property {Uint8Array} plaintext - The data to be encrypted.
 * @property {Uint8Array} cek - The content encryption key.
 * @property {Uint8Array} iv - The initialization vector.
 * @property {Uint8Array} aad - Additional authenticated data.
 */
export interface EncryptParams {
  enc: Enc;
  plaintext: Uint8Array;
  cek: Uint8Array;
  iv: Uint8Array;
  aad: Uint8Array;
}

/**
 * Result of an encryption operation.
 * @property {Uint8Array} ciphertext - The encrypted data.
 * @property {Uint8Array} tag - The authentication tag.
 */
export interface EncryptResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

/**
 * Parameters required for decryption operation.
 * @property {string} enc - The encryption algorithm used.
 * @property {Uint8Array} cek - The content encryption key.
 * @property {Uint8Array} ciphertext - The data to be decrypted.
 * @property {Uint8Array} iv - The initialization vector.
 * @property {Uint8Array} tag - The authentication tag.
 * @property {Uint8Array} aad - Additional authenticated data.
 */
export interface DecryptParams {
  enc: string;
  cek: Uint8Array;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  aad: Uint8Array;
}

/**
 * Interface for cryptographic cipher operations.
 */
export interface Cipher {
  /**
   * Encrypts data using the specified algorithm and parameters.
   * @param params - The encryption parameters.
   * @returns A promise that resolves to the encryption result.
   */
  encrypt: ({
    enc,
    plaintext,
    cek,
    iv,
    aad,
  }: EncryptParams) => Promise<EncryptResult>;

  /**
   * Decrypts data using the specified algorithm and parameters.
   * @param params - The decryption parameters.
   * @returns A promise that resolves to the decrypted data.
   */
  decrypt: ({
    enc,
    cek,
    ciphertext,
    iv,
    tag,
    aad,
  }: DecryptParams) => Promise<Uint8Array>;

  /**
   * Returns the byte length of the initialization vector (IV) required for the specified encryption algorithm.
   * @param enc - The encryption algorithm identifier.
   * @returns The IV byte length for the specified algorithm.
   */
  getIvByteLength: (enc: Enc) => number;

  /**
   * Returns the required byte length of the content encryption key (CEK) for the given encryption algorithm.
   * This value depends on the selected algorithm—for CBC modes, the CEK is typically twice the underlying key size due to combined encryption/MAC.
   * @param enc - The encryption algorithm identifier.
   * @returns The required CEK byte length for the specified algorithm.
   */
  getCekByteLength: (enc: Enc) => number;
}
