/**
 * Arguments for the divideCek function.
 */
type DivideCekArgs = {
  /**
   * The content encryption key (CEK) as a Uint8Array.
   */
  cek: Uint8Array;

  /**
   * The number of key bytes.
   */
  keyBytes: number;
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
  keyBytes,
}: DivideCekArgs): DivideCekResult => {
  if (cek.length !== keyBytes * 2) {
    throw new Error('CEK length must be twice the keyBytes');
  }

  const encRawKey = cek.slice(keyBytes);
  const macRawKey = cek.slice(0, keyBytes);

  return { encRawKey, macRawKey };
};
