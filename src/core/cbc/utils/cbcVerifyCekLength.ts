/**
 * Verifies the length of the content encryption key (CEK) for CBC encryption.
 * @param cek - The content encryption key as a Uint8Array.
 * @param keyBitLength - The expected length of the key in bits.
 * @throws Will throw an error if the length of the CEK is not as expected.
 */
export const cbcVerifyCekLength = (cek: Uint8Array, keyBitLength: number) => {
  const keyByteLength = keyBitLength >>> 3;
  const expectedLength = keyByteLength * 2;
  if (cek.length !== expectedLength) {
    throw new Error(
      `Invalid CBC content encryption key length: expected ${expectedLength} bytes (${
        keyBitLength << 1
      } bits), but got ${cek.length} bytes`,
    );
  }
};
