import { parseKeyBitLength } from '@/common/utils/parseKeyBitLength';
import { Enc } from '@/constants/Enc';

/**
 * Returns the required byte length of the content encryption key (CEK) for GCM encryption.
 * For GCM mode, the CEK length matches the key length.
 * @param enc - The encryption algorithm identifier.
 * @returns The required CEK byte length for the specified GCM algorithm.
 */
export const gcmGetCekByteLength = (enc: Enc) => {
  const keyBitLength = parseKeyBitLength(enc);
  const keyByteLength = keyBitLength >>> 3;

  return keyByteLength;
};
