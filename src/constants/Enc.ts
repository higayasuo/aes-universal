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
