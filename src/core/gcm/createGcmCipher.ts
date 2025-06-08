import { AbstractGcmCipher } from './AbstractGcmCipher';
import { RandomBytes } from '@/common/types';

/**
 * Creates a new instance of a GCM cipher.
 * @template T - The type of the GCM cipher instance, must extend AbstractGcmCipher
 * @template C - The constructor type for the GCM cipher
 * @param {C} Ctor - The constructor function for the GCM cipher
 * @param {RandomBytes} randomBytes - The function used to generate random bytes
 * @returns {T} A new instance of the GCM cipher
 */
export const createGcmCipher = <
  T extends AbstractGcmCipher,
  C extends new (randomBytes: RandomBytes) => T,
>(
  Ctor: C,
  randomBytes: RandomBytes,
): T => {
  return new Ctor(randomBytes);
};
