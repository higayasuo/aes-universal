import { describe, it, expect } from 'vitest';
import { generateMacData } from '../generateMacData';

describe('generateMacData', () => {
  it('should generate MAC data with non-empty inputs', () => {
    const aad = new Uint8Array([1, 2, 3]);
    const iv = new Uint8Array([
      4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    ]);
    const ciphertext = new Uint8Array([20, 21, 22, 23, 24]);

    const result = generateMacData({ aad, iv, ciphertext });

    // Expected result:
    // aad (3 bytes) + iv (16 bytes) + ciphertext (5 bytes) + aadBits (8 bytes)
    // [1,2,3] + [4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19] + [20,21,22,23,24] + [0,0,0,0,0,0,0,24]
    const expected = new Uint8Array([
      1,
      2,
      3, // aad
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16,
      17,
      18,
      19, // iv
      20,
      21,
      22,
      23,
      24, // ciphertext
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      24, // aadBits (3 bytes * 8 = 24 bits)
    ]);

    expect(result).toEqual(expected);
  });

  it('should generate MAC data with empty AAD', () => {
    const aad = new Uint8Array(0);
    const iv = new Uint8Array([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ]);
    const ciphertext = new Uint8Array([17, 18, 19, 20, 21]);

    const result = generateMacData({ aad, iv, ciphertext });

    // Expected result:
    // aad (0 bytes) + iv (16 bytes) + ciphertext (5 bytes) + aadBits (8 bytes)
    const expected = new Uint8Array([
      // aad (empty)
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16, // iv
      17,
      18,
      19,
      20,
      21, // ciphertext
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, // aadBits (0 bytes * 8 = 0 bits)
    ]);

    expect(result).toEqual(expected);
  });

  it('should generate MAC data with empty IV', () => {
    const aad = new Uint8Array([1, 2, 3]);
    const iv = new Uint8Array(0);
    const ciphertext = new Uint8Array([4, 5, 6, 7, 8]);

    const result = generateMacData({ aad, iv, ciphertext });

    // Expected result:
    // aad (3 bytes) + iv (0 bytes) + ciphertext (5 bytes) + aadBits (8 bytes)
    const expected = new Uint8Array([
      1,
      2,
      3, // aad
      // iv (empty)
      4,
      5,
      6,
      7,
      8, // ciphertext
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      24, // aadBits (3 bytes * 8 = 24 bits)
    ]);

    expect(result).toEqual(expected);
  });

  it('should generate MAC data with empty ciphertext', () => {
    const aad = new Uint8Array([1, 2, 3]);
    const iv = new Uint8Array([
      4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    ]);
    const ciphertext = new Uint8Array(0);

    const result = generateMacData({ aad, iv, ciphertext });

    // Expected result:
    // aad (3 bytes) + iv (16 bytes) + ciphertext (0 bytes) + aadBits (8 bytes)
    const expected = new Uint8Array([
      1,
      2,
      3, // aad
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16,
      17,
      18,
      19, // iv
      // ciphertext (empty)
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      24, // aadBits (3 bytes * 8 = 24 bits)
    ]);

    expect(result).toEqual(expected);
  });
});
