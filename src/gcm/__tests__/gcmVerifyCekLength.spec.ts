import { describe, it, expect } from 'vitest';
import { gcmVerifyCekLength } from '../gcmVerifyCekLength';

describe('gcmVerifyCekLength', () => {
  const keyConfigs = [
    {
      keyBits: 128,
      cekLength: 16, // 128 bits / 8
      description: 'A128GCM',
    },
    {
      keyBits: 192,
      cekLength: 24, // 192 bits / 8
      description: 'A192GCM',
    },
    {
      keyBits: 256,
      cekLength: 32, // 256 bits / 8
      description: 'A256GCM',
    },
  ] as const;

  it.each(keyConfigs)(
    'should not throw an error when CEK length is valid for $description',
    ({ keyBits, cekLength }) => {
      const cek = new Uint8Array(cekLength);
      expect(() => gcmVerifyCekLength(cek, keyBits)).not.toThrow();
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is too short for $description',
    ({ keyBits, cekLength }) => {
      const cek = new Uint8Array(cekLength - 1);
      expect(() => gcmVerifyCekLength(cek, keyBits)).toThrow(
        `Invalid GCM content encryption key length: expected ${cekLength} bytes (${keyBits} bits), but got ${
          cekLength - 1
        } bytes`,
      );
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is too long for $description',
    ({ keyBits, cekLength }) => {
      const cek = new Uint8Array(cekLength + 1);
      expect(() => gcmVerifyCekLength(cek, keyBits)).toThrow(
        `Invalid GCM content encryption key length: expected ${cekLength} bytes (${keyBits} bits), but got ${
          cekLength + 1
        } bytes`,
      );
    },
  );

  it.each(keyConfigs)(
    'should throw an error when CEK length is zero for $description',
    ({ keyBits, cekLength }) => {
      const cek = new Uint8Array(0);
      expect(() => gcmVerifyCekLength(cek, keyBits)).toThrow(
        `Invalid GCM content encryption key length: expected ${cekLength} bytes (${keyBits} bits), but got 0 bytes`,
      );
    },
  );
});
