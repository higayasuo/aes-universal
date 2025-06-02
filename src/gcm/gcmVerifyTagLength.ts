/**
 * Verifies the length of the authentication tag for GCM encryption.
 * GCM requires a 16-byte (128-bit) authentication tag.
 * @param {Uint8Array} tag - The authentication tag to verify
 * @throws {Error} Will throw an error if the tag length is not 16 bytes
 * @example
 * const tag = new Uint8Array(16);
 * gcmVerifyTagLength(tag); // No error
 *
 * const invalidTag = new Uint8Array(12);
 * gcmVerifyTagLength(invalidTag); // Throws error
 */
export const gcmVerifyTagLength = (tag: Uint8Array) => {
  const expectedLength = 16;
  if (tag.length !== expectedLength) {
    throw new Error(
      `Invalid GCM authentication tag length: expected ${expectedLength} bytes, but got ${tag.length} bytes`,
    );
  }
};
