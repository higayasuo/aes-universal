import { describe, it, expect } from 'vitest';
import { divideCek } from '../divideCek';

describe('divideCek', () => {
  it('should divide 256-bit CEK into 128-bit encryption and MAC keys', () => {
    const cek = new Uint8Array(32); // 256 bits = 32 bytes
    // First half (MAC key): 0-15
    for (let i = 0; i < 16; i++) {
      cek[i] = i;
    }
    // Second half (Encryption key): 16-31
    for (let i = 16; i < 32; i++) {
      cek[i] = i + 100;
    }

    const result = divideCek({ cek, keyBitLength: 128 }); // 128 bits = 16 bytes

    // Check encryption key (second half)
    expect(result.encRawKey).toEqual(new Uint8Array(cek.slice(16)));
    // Check MAC key (first half)
    expect(result.macRawKey).toEqual(new Uint8Array(cek.slice(0, 16)));
  });

  it('should divide 384-bit CEK into 192-bit encryption and MAC keys', () => {
    const cek = new Uint8Array(48); // 384 bits = 48 bytes
    // First half (MAC key): 0-23
    for (let i = 0; i < 24; i++) {
      cek[i] = i;
    }
    // Second half (Encryption key): 24-47
    for (let i = 24; i < 48; i++) {
      cek[i] = i + 100;
    }

    const result = divideCek({ cek, keyBitLength: 192 }); // 192 bits = 24 bytes

    // Check encryption key (second half)
    expect(result.encRawKey).toEqual(new Uint8Array(cek.slice(24)));
    // Check MAC key (first half)
    expect(result.macRawKey).toEqual(new Uint8Array(cek.slice(0, 24)));
  });

  it('should divide 512-bit CEK into 256-bit encryption and MAC keys', () => {
    const cek = new Uint8Array(64); // 512 bits = 64 bytes
    // First half (MAC key): 0-31
    for (let i = 0; i < 32; i++) {
      cek[i] = i;
    }
    // Second half (Encryption key): 32-63
    for (let i = 32; i < 64; i++) {
      cek[i] = i + 100;
    }

    const result = divideCek({ cek, keyBitLength: 256 }); // 256 bits = 32 bytes

    // Check encryption key (second half)
    expect(result.encRawKey).toEqual(new Uint8Array(cek.slice(32)));
    // Check MAC key (first half)
    expect(result.macRawKey).toEqual(new Uint8Array(cek.slice(0, 32)));
  });

  it('should throw error when CEK length is not twice the keyBytes', () => {
    const cek = new Uint8Array(32); // 256 bits
    expect(() => divideCek({ cek, keyBitLength: 192 })).toThrow(
      'Invalid CBC content encryption key length: expected 48 bytes (384 bits), but got 32 bytes',
    );
  });
});
