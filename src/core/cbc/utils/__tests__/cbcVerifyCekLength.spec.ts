import { describe, it, expect } from 'vitest';
import { cbcVerifyCekLength } from '../cbcVerifyCekLength';

describe('cbcVerifyCekLength', () => {
  const keyConfigs = [
    {
      keyBits: 128,
      cekLength: 32, // 16 bytes for encryption + 16 bytes for MAC
      description: 'A128CBC-HS256',
    },
    {
      keyBits: 192,
      cekLength: 48, // 24 bytes for encryption + 24 bytes for MAC
      description: 'A192CBC-HS384',
    },
    {
      keyBits: 256,
      cekLength: 64, // 32 bytes for encryption + 32 bytes for MAC
      description: 'A256CBC-HS512',
    },
  ] as const;

  it.each(keyConfigs)(
    'should not throw an error when CEK length is valid for $description',
    ({ keyBits, cekLength }) => {
      const cek = new Uint8Array(cekLength);
      expect(() => cbcVerifyCekLength(cek, keyBits)).not.toThrow();
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is too short for $description',
    ({ keyBits, cekLength }) => {
      const cek = new Uint8Array(cekLength - 1);
      expect(() => cbcVerifyCekLength(cek, keyBits)).toThrow(
        `Invalid CBC content encryption key length: expected ${cekLength} bytes (${keyBits} bits), but got ${
          cekLength - 1
        } bytes`,
      );
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is too long for $description',
    ({ keyBits, cekLength }) => {
      const cek = new Uint8Array(cekLength + 1);
      expect(() => cbcVerifyCekLength(cek, keyBits)).toThrow(
        `Invalid CBC content encryption key length: expected ${cekLength} bytes (${keyBits} bits), but got ${
          cekLength + 1
        } bytes`,
      );
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is zero for $description',
    ({ keyBits, cekLength }) => {
      const cek = new Uint8Array(0);
      expect(() => cbcVerifyCekLength(cek, keyBits)).toThrow(
        `Invalid CBC content encryption key length: expected ${cekLength} bytes (${keyBits} bits), but got 0 bytes`,
      );
    },
  );
});
