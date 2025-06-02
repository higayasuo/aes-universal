/**
 * Verifies the length of the content encryption key (CEK) for CBC encryption.
 * @param cek - The content encryption key as a Uint8Array.
 * @param keyBits - The expected length of the key in bits.
 * @throws Will throw an error if the length of the CEK is not as expected.
 */
export const cbcVerifyCekLength = (cek: Uint8Array, keyBits: number) => {
  const expectedLength = keyBits >>> 2;
  if (cek.length !== expectedLength) {
    throw new Error(
      `Invalid CBC content encryption key length: expected ${expectedLength} bytes (${keyBits} bits), but got ${cek.length} bytes`,
    );
  }
};
