import { encode, decode } from 'cbor-js';

/**
 * Represents the data required for encryption and decryption operations.
 * @property {Uint8Array} ciphertext - The encrypted data.
 * @property {Uint8Array} iv - The initialization vector.
 * @property {Uint8Array} tag - The authentication tag.
 * @property {Uint8Array} aad - The additional authenticated data.
 */
export type EncryptionData = {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  aad: Uint8Array;
};

/**
 * Encodes the given EncryptionData into a single Uint8Array.
 * @param {EncryptionData} data - The data to be encoded.
 * @returns {Uint8Array} The encoded data.
 */
export const encodeEncryptionData = ({
  ciphertext,
  iv,
  tag,
  aad,
}: EncryptionData): Uint8Array => {
  const data = [ciphertext, iv, tag, aad];

  return new Uint8Array(encode(data));
};

/**
 * Decodes the given Uint8Array into EncryptionData.
 * @param {Uint8Array} encoded - The encoded data.
 * @returns {EncryptionData} The decoded data.
 */
export const decodeEncryptionData = (encoded: Uint8Array): EncryptionData => {
  const [ciphertext, iv, tag, aad] = decode(encoded.buffer);

  return {
    ciphertext: new Uint8Array(ciphertext),
    iv: new Uint8Array(iv),
    tag: new Uint8Array(tag),
    aad: new Uint8Array(aad),
  };
};
