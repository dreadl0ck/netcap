import { describe, expect, it } from 'vitest';
import { producerConsumerRatio } from '../lib/hunting';

describe('producer–consumer evidence', () => {
  it('preserves direction and signed range', () => {
    expect(producerConsumerRatio(100, 0)).toBe(1);
    expect(producerConsumerRatio(0, 100)).toBe(-1);
    expect(producerConsumerRatio(300, 100)).toBe(0.5);
    expect(producerConsumerRatio(100, 100)).toBe(0);
  });
  it('does not present unavailable bytes as balanced traffic', () => {
    for (const [a, b] of [[0, 0], [-1, 5], [NaN, 5], [Infinity, 5]]) expect(producerConsumerRatio(a, b)).toBeNull();
  });
});
