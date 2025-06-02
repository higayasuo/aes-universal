/**
 * Verifies the length of the initialization vector (IV) for CBC encryption.
 * @param iv - The initialization vector as a Uint8Array.
 * @throws Will throw an error if the length of the IV is not 16 bytes.
 */
export const cbcVerifyIvLength = (iv: Uint8Array) => {
  if (iv.length !== 16) {
    throw new Error(
      `Invalid CBC IV length: expected 16 bytes, got ${iv.length} bytes`,
    );
  }
};
