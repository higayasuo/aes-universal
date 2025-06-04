import { describe, it, expect } from 'vitest';
import { gcmVerifyCekLength } from '../gcmVerifyCekLength';

describe('gcmVerifyCekLength', () => {
  const keyConfigs = [
    {
      keyBitLength: 128,
      cekLength: 16, // 128 bits / 8
      description: 'A128GCM',
    },
    {
      keyBitLength: 192,
      cekLength: 24, // 192 bits / 8
      description: 'A192GCM',
    },
    {
      keyBitLength: 256,
      cekLength: 32, // 256 bits / 8
      description: 'A256GCM',
    },
  ] as const;

  it.each(keyConfigs)(
    'should not throw an error when CEK length is valid for $description',
    ({ keyBitLength, cekLength }) => {
      const cek = new Uint8Array(cekLength);
      expect(() => gcmVerifyCekLength(cek, keyBitLength)).not.toThrow();
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is too short for $description',
    ({ keyBitLength, cekLength }) => {
      const cek = new Uint8Array(cekLength - 1);
      expect(() => gcmVerifyCekLength(cek, keyBitLength)).toThrow(
        `Invalid GCM content encryption key length: expected ${cekLength} bytes (${keyBitLength} bits), but got ${
          cekLength - 1
        } bytes`,
      );
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is too long for $description',
    ({ keyBitLength, cekLength }) => {
      const cek = new Uint8Array(cekLength + 1);
      expect(() => gcmVerifyCekLength(cek, keyBitLength)).toThrow(
        `Invalid GCM content encryption key length: expected ${cekLength} bytes (${keyBitLength} bits), but got ${
          cekLength + 1
        } bytes`,
      );
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is zero for $description',
    ({ keyBitLength, cekLength }) => {
      const cek = new Uint8Array(0);
      expect(() => gcmVerifyCekLength(cek, keyBitLength)).toThrow(
        `Invalid GCM content encryption key length: expected ${cekLength} bytes (${keyBitLength} bits), but got 0 bytes`,
      );
    },
  );
});
