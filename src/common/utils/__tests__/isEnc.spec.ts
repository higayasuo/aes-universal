import { describe, it, expect } from 'vitest';
import { isCbcEnc, isGcmEnc, isEnc } from '../isEnc';

describe('isEnc', () => {
  describe('isCbcEnc', () => {
    it('should return true for valid CBC mode encryption algorithms with HMAC', () => {
      expect(isCbcEnc('A128CBC-HS256')).toBe(true);
      expect(isCbcEnc('A192CBC-HS384')).toBe(true);
      expect(isCbcEnc('A256CBC-HS512')).toBe(true);
    });

    it('should return false for invalid CBC mode encryption algorithms', () => {
      expect(isCbcEnc('A128GCM')).toBe(false);
      expect(isCbcEnc('A192GCM')).toBe(false);
      expect(isCbcEnc('A256GCM')).toBe(false);
      expect(isCbcEnc('INVALID')).toBe(false);
    });
  });

  describe('isGcmEnc', () => {
    it('should return true for valid GCM mode encryption algorithms', () => {
      expect(isGcmEnc('A128GCM')).toBe(true);
      expect(isGcmEnc('A192GCM')).toBe(true);
      expect(isGcmEnc('A256GCM')).toBe(true);
    });

    it('should return false for invalid GCM mode encryption algorithms', () => {
      expect(isGcmEnc('A128CBC-HS256')).toBe(false);
      expect(isGcmEnc('A192CBC-HS384')).toBe(false);
      expect(isGcmEnc('A256CBC-HS512')).toBe(false);
      expect(isGcmEnc('INVALID')).toBe(false);
    });
  });

  describe('isEnc', () => {
    it('should return true for all valid encryption algorithms', () => {
      expect(isEnc('A128CBC-HS256')).toBe(true);
      expect(isEnc('A192CBC-HS384')).toBe(true);
      expect(isEnc('A256CBC-HS512')).toBe(true);
      expect(isEnc('A128GCM')).toBe(true);
      expect(isEnc('A192GCM')).toBe(true);
      expect(isEnc('A256GCM')).toBe(true);
    });

    it('should return false for invalid encryption algorithms', () => {
      expect(isEnc('INVALID')).toBe(false);
      expect(isEnc('A128CBC-HS256-INVALID')).toBe(false);
      expect(isEnc('A128GCM-INVALID')).toBe(false);
    });
  });
});
