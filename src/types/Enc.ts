import { cbcEncArray, gcmEncArray, encArray } from '@/constants/Enc';

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
