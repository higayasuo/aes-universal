/**
 * Array of supported CBC mode encryption algorithms with HMAC.
 */
export const cbcEncArray = [
  'A128CBC-HS256',
  'A192CBC-HS384',
  'A256CBC-HS512',
] as const;

/**
 * Array of supported GCM mode encryption algorithms.
 */
export const gcmEncArray = ['A128GCM', 'A192GCM', 'A256GCM'] as const;

/**
 * Array of all supported encryption algorithms.
 */
export const encArray = [...cbcEncArray, ...gcmEncArray] as const;

/**
 * Type representing all supported encryption algorithms.
 */
export type Enc = (typeof encArray)[number];

/**
 * Type representing CBC mode encryption algorithms with HMAC.
 */
export type CbcEnc = (typeof cbcEncArray)[number];

/**
 * Type representing GCM mode encryption algorithms.
 */
export type GcmEnc = (typeof gcmEncArray)[number];

/**
 * Checks if a given string is a valid CBC mode encryption algorithm with HMAC.
 *
 * @param enc - The string to check.
 * @returns True if the string is a valid CBC mode encryption algorithm with HMAC, false otherwise.
 */
export const isCbcEnc = (enc: string): enc is CbcEnc => {
  return cbcEncArray.includes(enc as CbcEnc);
};

/**
 * Checks if a given string is a valid GCM mode encryption algorithm.
 *
 * @param enc - The string to check.
 * @returns True if the string is a valid GCM mode encryption algorithm, false otherwise.
 */
export const isGcmEnc = (enc: string): enc is GcmEnc => {
  return gcmEncArray.includes(enc as GcmEnc);
};

/**
 * Checks if a given string is a valid encryption algorithm.
 *
 * @param value - The string to check.
 * @returns True if the string is a valid encryption algorithm, false otherwise.
 */
export const isEnc = (value: string): value is Enc => {
  return encArray.includes(value as Enc);
};
