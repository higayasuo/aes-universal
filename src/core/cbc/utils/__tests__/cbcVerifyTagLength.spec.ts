import { describe, it, expect } from 'vitest';
import { cbcVerifyTagLength } from '../cbcVerifyTagLength';

describe('cbcVerifyTagLength', () => {
  const keyConfigs = [
    {
      keyBits: 128,
      tagLength: 16, // 128 bits / 8
      description: 'A128CBC-HS256',
    },
    {
      keyBits: 192,
      tagLength: 24, // 192 bits / 8
      description: 'A192CBC-HS384',
    },
    {
      keyBits: 256,
      tagLength: 32, // 256 bits / 8
      description: 'A256CBC-HS512',
    },
  ] as const;

  it.each(keyConfigs)(
    'should not throw an error when tag length is valid for $description',
    ({ keyBits, tagLength }) => {
      const tag = new Uint8Array(tagLength);
      expect(() => cbcVerifyTagLength(tag, keyBits)).not.toThrow();
    },
  );

  it.each(keyConfigs)(
    'should throw an error when tag length is too short for $description',
    ({ keyBits, tagLength }) => {
      const tag = new Uint8Array(tagLength - 1);
      expect(() => cbcVerifyTagLength(tag, keyBits)).toThrow(
        `Invalid CBC authentication tag length: expected ${tagLength} bytes (${keyBits} bits), but got ${
          tagLength - 1
        } bytes`,
      );
    },
  );

  it.each(keyConfigs)(
    'should throw an error when tag length is too long for $description',
    ({ keyBits, tagLength }) => {
      const tag = new Uint8Array(tagLength + 1);
      expect(() => cbcVerifyTagLength(tag, keyBits)).toThrow(
        `Invalid CBC authentication tag length: expected ${tagLength} bytes (${keyBits} bits), but got ${
          tagLength + 1
        } bytes`,
      );
    },
  );

  it.each(keyConfigs)(
    'should throw an error when tag length is zero for $description',
    ({ keyBits, tagLength }) => {
      const tag = new Uint8Array(0);
      expect(() => cbcVerifyTagLength(tag, keyBits)).toThrow(
        `Invalid CBC authentication tag length: expected ${tagLength} bytes (${keyBits} bits), but got 0 bytes`,
      );
    },
  );
});
