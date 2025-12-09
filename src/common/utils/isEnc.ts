import { cbcEncArray, gcmEncArray, encArray } from '@/constants/Enc';
import { CbcEnc, GcmEnc, Enc } from '@/types/Enc';

/**
 * Checks if a given string is a valid CBC mode encryption algorithm with HMAC.
 * @param enc - The string to check.
 * @returns True if the string is a valid CBC mode encryption algorithm with HMAC, false otherwise.
 */
export const isCbcEnc = (enc: string): enc is CbcEnc => {
  return cbcEncArray.includes(enc as CbcEnc);
};

/**
 * Checks if a given string is a valid GCM mode encryption algorithm.
 * @param enc - The string to check.
 * @returns True if the string is a valid GCM mode encryption algorithm, false otherwise.
 */
export const isGcmEnc = (enc: string): enc is GcmEnc => {
  return gcmEncArray.includes(enc as GcmEnc);
};

/**
 * Checks if a given string is a valid encryption algorithm.
 * @param value - The string to check.
 * @returns True if the string is a valid encryption algorithm, false otherwise.
 */
export const isEnc = (value: string): value is Enc => {
  return encArray.includes(value as Enc);
};
