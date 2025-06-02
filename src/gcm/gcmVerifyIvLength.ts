/**
 * Verifies the length of the initialization vector (IV) for GCM encryption.
 * @param iv - The initialization vector as a Uint8Array.
 * @throws Will throw an error if the length of the IV is not 12 bytes.
 */
export const gcmVerifyIvLength = (iv: Uint8Array) => {
  if (iv.length !== 12) {
    throw new Error(
      `Invalid GCM IV length: expected 12 bytes, got ${iv.length} bytes`,
    );
  }
};
