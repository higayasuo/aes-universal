import { Enc } from './Enc';

/**
 * Parses the key bits from the given encryption algorithm string.
 *
 * @param enc - The encryption algorithm string.
 * @returns The number of key bits.
 */
export const parseKeyBits = (enc: Enc): number => {
  return parseInt(enc.slice(1, 4), 10);
};
