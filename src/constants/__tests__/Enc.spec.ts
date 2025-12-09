import { describe, it, expect } from 'vitest';
import { cbcEncArray, gcmEncArray, encArray } from '../Enc';

describe('Enc', () => {
  describe('cbcEncArray', () => {
    it('should contain all CBC mode encryption algorithms with HMAC', () => {
      expect(cbcEncArray).toEqual([
        'A128CBC-HS256',
        'A192CBC-HS384',
        'A256CBC-HS512',
      ]);
    });
  });

  describe('gcmEncArray', () => {
    it('should contain all GCM mode encryption algorithms', () => {
      expect(gcmEncArray).toEqual(['A128GCM', 'A192GCM', 'A256GCM']);
    });
  });

  describe('encArray', () => {
    it('should contain all supported encryption algorithms', () => {
      expect(encArray).toEqual([
        'A128CBC-HS256',
        'A192CBC-HS384',
        'A256CBC-HS512',
        'A128GCM',
        'A192GCM',
        'A256GCM',
      ]);
    });
  });
});
