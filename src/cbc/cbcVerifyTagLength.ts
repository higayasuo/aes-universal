/**
 * Verifies the length of the authentication tag for CBC encryption.
 * @param tag - The authentication tag as a Uint8Array.
 * @param keyBits - The expected length of the key in bits.
 * @throws Will throw an error if the length of the tag is not as expected.
 */
export const cbcVerifyTagLength = (tag: Uint8Array, keyBits: number) => {
  const expectedLength = keyBits >>> 3;
  if (tag.length !== expectedLength) {
    throw new Error(
      `Invalid CBC authentication tag length: expected ${expectedLength} bytes (${keyBits} bits), but got ${tag.length} bytes`,
    );
  }
};
