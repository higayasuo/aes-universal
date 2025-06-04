import { cbcVerifyCekLength } from './cbcVerifyCekLength';

/**
 * Arguments for the divideCek function.
 */
type DivideCekArgs = {
  /**
   * The content encryption key (CEK) as a Uint8Array.
   */
  cek: Uint8Array;

  /**
   * The length of the key in bits.
   * This value is used to determine how to split the content encryption key (CEK)
   * into encryption and MAC raw keys.
   */
  keyBitLength: number;
};

/**
 * Result of the divideCek function.
 */
type DivideCekResult = {
  /**
   * The encryption raw key as a Uint8Array.
   */
  encRawKey: Uint8Array;

  /**
   * The MAC raw key as a Uint8Array.
   */
  macRawKey: Uint8Array;
};

/**
 * Divides the content encryption key (CEK) into encryption and MAC raw keys.
 *
 * @param {DivideCekArgs} args - The arguments for dividing the CEK.
 * @returns {DivideCekResult} The divided encryption and MAC raw keys.
 * @throws {Error} If the CEK length is not twice the keyBytes.
 */
export const divideCek = ({
  cek,
  keyBitLength,
}: DivideCekArgs): DivideCekResult => {
  cbcVerifyCekLength(cek, keyBitLength);
  const keyByteLength = keyBitLength >>> 3;

  const encRawKey = cek.slice(keyByteLength);
  const macRawKey = cek.slice(0, keyByteLength);

  return { encRawKey, macRawKey };
};
