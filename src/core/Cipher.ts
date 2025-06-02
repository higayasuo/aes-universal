import { Enc } from '@/constants/Enc';

/**
 * Arguments required for encryption operation.
 * @property {Enc} enc - The encryption algorithm to use.
 * @property {Uint8Array} plaintext - The data to be encrypted.
 * @property {Uint8Array} cek - The content encryption key.
 * @property {Uint8Array} aad - Additional authenticated data.
 */
export type EncryptArgs = {
  enc: Enc;
  plaintext: Uint8Array;
  cek: Uint8Array;
  aad: Uint8Array;
};

/**
 * Result of an encryption operation.
 * @property {Uint8Array} ciphertext - The encrypted data.
 * @property {Uint8Array} tag - The authentication tag.
 * @property {Uint8Array} iv - The initialization vector.
 */
export type EncryptResult = {
  ciphertext: Uint8Array;
  tag: Uint8Array;
  iv: Uint8Array;
};

/**
 * Arguments required for decryption operation.
 * @property {string} enc - The encryption algorithm used.
 * @property {Uint8Array} cek - The content encryption key.
 * @property {Uint8Array} ciphertext - The data to be decrypted.
 * @property {Uint8Array} iv - The initialization vector.
 * @property {Uint8Array} tag - The authentication tag.
 * @property {Uint8Array} aad - Additional authenticated data.
 */
export type DecryptArgs = {
  enc: string;
  cek: Uint8Array;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  aad: Uint8Array;
};

/**
 * Interface for cryptographic cipher operations.
 */
export interface Cipher {
  /**
   * Encrypts data using the specified algorithm and parameters.
   * @param {EncryptArgs} args - The encryption arguments.
   * @returns {Promise<EncryptResult>} A promise that resolves to the encryption result.
   */
  encrypt: (args: EncryptArgs) => Promise<EncryptResult>;

  /**
   * Decrypts data using the specified algorithm and parameters.
   * @param {DecryptArgs} args - The decryption arguments.
   * @returns {Promise<Uint8Array>} A promise that resolves to the decrypted data.
   */
  decrypt: (args: DecryptArgs) => Promise<Uint8Array>;
}
