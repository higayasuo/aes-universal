import { uint64BE, concatUint8Arrays } from '@higayasuo/u8a-utils';

/**
 * Arguments for generating MAC data.
 * @typedef {Object} GenerateMacDataArgs
 * @property {Uint8Array} aad - Additional authenticated data.
 * @property {Uint8Array} iv - Initialization vector.
 * @property {Uint8Array} ciphertext - Ciphertext.
 */
type GenerateMacDataArgs = {
  aad: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
};

/**
 * Generates MAC data by concatenating AAD, IV, ciphertext, and AAD length in bits.
 * @param {GenerateMacDataArgs} args - The arguments for generating MAC data.
 * @returns {Uint8Array} - The generated MAC data.
 */
export const generateMacData = ({
  aad,
  iv,
  ciphertext,
}: GenerateMacDataArgs): Uint8Array => {
  const aadBitLength = uint64BE(aad.length << 3);

  return concatUint8Arrays(aad, iv, ciphertext, aadBitLength);
};
