/**
 * Function type that generates random bytes.
 * @param size - The number of bytes to generate. If not provided, the default size is 32.
 * @returns A Uint8Array containing the generated random bytes.
 */
export type RandomBytes = (size?: number) => Uint8Array;
