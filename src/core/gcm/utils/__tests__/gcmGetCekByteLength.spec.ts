import { describe, it, expect } from 'vitest';
import { gcmGetCekByteLength } from '../gcmGetCekByteLength';

describe('gcmGetCekByteLength', () => {
  it('should return 16 bytes for A128GCM', () => {
    expect(gcmGetCekByteLength('A128GCM')).toBe(16);
  });

  it('should return 24 bytes for A192GCM', () => {
    expect(gcmGetCekByteLength('A192GCM')).toBe(24);
  });

  it('should return 32 bytes for A256GCM', () => {
    expect(gcmGetCekByteLength('A256GCM')).toBe(32);
  });
});
