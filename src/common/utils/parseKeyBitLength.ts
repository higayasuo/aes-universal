import { Enc } from '../../constants/Enc';

/**
 * Extracts the key length in bits from an encryption algorithm identifier.
 * The identifier is expected to follow the format where the key length
 * is represented by the three digits following the first character.
 *
 * @example
 * parseKeyBitLength('A128GCM') // returns 128
 * parseKeyBitLength('A256GCM') // returns 256
 *
 * @param enc - The encryption algorithm identifier string
 * @returns The key length in bits as a number
 * @throws Will throw an error if the input format is invalid
 */
export const parseKeyBitLength = (enc: Enc): number => {
  return parseInt(enc.slice(1, 4), 10);
};
