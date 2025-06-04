/**
 * Verifies the length of the content encryption key (CEK) for GCM encryption.
 * @param cek - The content encryption key as a Uint8Array.
 * @param keyBitLength - The expected length of the key in bits.
 * @throws Will throw an error if the length of the CEK is not as expected.
 */
export const gcmVerifyCekLength = (cek: Uint8Array, keyBitLength: number) => {
  const expectedByteLength = keyBitLength >>> 3;
  if (cek.length !== expectedByteLength) {
    throw new Error(
      `Invalid GCM content encryption key length: expected ${expectedByteLength} bytes (${keyBitLength} bits), but got ${cek.length} bytes`,
    );
  }
};
