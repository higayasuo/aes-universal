import { describe, it, expect } from 'vitest';
import { divideCek } from '../divideCek';

describe('divideCek', () => {
  it('should divide 256-bit CEK into 128-bit encryption and MAC keys', () => {
    const cek = new Uint8Array(32); // 256 bits = 32 bytes
    for (let i = 0; i < 32; i++) {
      cek[i] = i;
    }

    const result = divideCek({ cek, keyBytes: 16 }); // 128 bits = 16 bytes

    // Check encryption key (second half)
    expect(result.encRawKey).toEqual(new Uint8Array(cek.slice(16)));
    // Check MAC key (first half)
    expect(result.macRawKey).toEqual(new Uint8Array(cek.slice(0, 16)));
  });

  it('should divide 384-bit CEK into 192-bit encryption and MAC keys', () => {
    const cek = new Uint8Array(48); // 384 bits = 48 bytes
    for (let i = 0; i < 48; i++) {
      cek[i] = i;
    }

    const result = divideCek({ cek, keyBytes: 24 }); // 192 bits = 24 bytes

    // Check encryption key (second half)
    expect(result.encRawKey).toEqual(new Uint8Array(cek.slice(24)));
    // Check MAC key (first half)
    expect(result.macRawKey).toEqual(new Uint8Array(cek.slice(0, 24)));
  });

  it('should divide 512-bit CEK into 256-bit encryption and MAC keys', () => {
    const cek = new Uint8Array(64); // 512 bits = 64 bytes
    for (let i = 0; i < 64; i++) {
      cek[i] = i;
    }

    const result = divideCek({ cek, keyBytes: 32 }); // 256 bits = 32 bytes

    // Check encryption key (second half)
    expect(result.encRawKey).toEqual(new Uint8Array(cek.slice(32)));
    // Check MAC key (first half)
    expect(result.macRawKey).toEqual(new Uint8Array(cek.slice(0, 32)));
  });

  it('should throw error when CEK length is not twice the keyBytes', () => {
    const cek = new Uint8Array(32); // 256 bits
    expect(() => divideCek({ cek, keyBytes: 24 })).toThrow(
      'CEK length must be twice the keyBytes',
    );
  });
});
