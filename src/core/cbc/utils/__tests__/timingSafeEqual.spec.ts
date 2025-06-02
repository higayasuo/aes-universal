import { describe, it, expect } from 'vitest';
import { timingSafeEqual } from '../timingSafeEqual';

describe('timingSafeEqual', () => {
  it('should return true for identical Uint8Arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(timingSafeEqual(a, b)).toBe(true);
  });

  it('should return false for different Uint8Arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 5]);
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it('should return false for Uint8Arrays of different lengths', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it('should handle empty Uint8Arrays', () => {
    const a = new Uint8Array([]);
    const b = new Uint8Array([]);
    expect(timingSafeEqual(a, b)).toBe(true);
  });

  it('should handle Uint8Arrays with all zeros', () => {
    const a = new Uint8Array([0, 0, 0, 0]);
    const b = new Uint8Array([0, 0, 0, 0]);
    expect(timingSafeEqual(a, b)).toBe(true);
  });

  it('should handle Uint8Arrays with maximum values', () => {
    const a = new Uint8Array([255, 255, 255, 255]);
    const b = new Uint8Array([255, 255, 255, 255]);
    expect(timingSafeEqual(a, b)).toBe(true);
  });
});
