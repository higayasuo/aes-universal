import { AbstractCbcCipher } from './AbstractCbcCipher';
import { RandomBytes } from '@/common/types';

/**
 * Creates a new instance of a CBC cipher.
 * @template T - The type of the CBC cipher instance, must extend AbstractCbcCipher
 * @template C - The constructor type for the CBC cipher
 * @param {C} Ctor - The constructor function for the CBC cipher
 * @param {RandomBytes} randomBytes - The function used to generate random bytes
 * @returns {T} A new instance of the CBC cipher
 */
export const createCbcCipher = <
  T extends AbstractCbcCipher,
  C extends new (randomBytes: RandomBytes) => T,
>(
  Ctor: C,
  randomBytes: RandomBytes,
): T => {
  return new Ctor(randomBytes);
};
