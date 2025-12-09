import { Enc } from '@/types/Enc';
import { parseKeyBitLength } from '@/common/utils/parseKeyBitLength';

/**
 * Returns the required byte length of the content encryption key (CEK) for CBC encryption.
 * For CBC mode, the CEK is twice the key length since it's used for both encryption and MAC operations.
 * @param enc - The encryption algorithm identifier.
 * @returns The required CEK byte length for the specified CBC algorithm.
 */
export const cbcGetCekByteLength = (enc: Enc) => {
  const keyBitLength = parseKeyBitLength(enc);
  const keyByteLength = keyBitLength >>> 3;

  return keyByteLength * 2;
};
