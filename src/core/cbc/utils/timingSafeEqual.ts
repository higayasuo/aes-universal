import { sha256 } from '@noble/hashes/sha2';

/**
 * Compares two Uint8Array values in a timing-safe manner.
 * @param a - The first Uint8Array to compare.
 * @param b - The second Uint8Array to compare.
 * @returns true if the values are equal, false otherwise.
 */
export const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  const aDigest = sha256(a);
  const bDigest = sha256(b);

  let out = 0;
  let i = -1;
  while (++i < 32) {
    out |= aDigest[i] ^ bDigest[i];
  }

  return out === 0;
};
