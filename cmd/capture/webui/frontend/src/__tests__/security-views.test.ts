import { beforeEach, describe, expect, it } from 'vitest';
import { SECURITY_VIEWS, pickRandomView, viewsForFields, viewsForTypes } from '../../packages/netcap-ui/src/lib/securityViews';

describe('Explore security views', () => {
  beforeEach(() => localStorage.clear());

  it('only offers views for record types the capture contains', () => {
    const views = viewsForTypes(['DNS', 'IPv6HopByHop', 'Ethernet']);
    expect(views.length).toBeGreaterThan(0);
    expect(views.every(v => v.type === 'DNS')).toBe(true);
    expect(viewsForTypes(['Ethernet', 'IPv6HopByHop'])).toEqual([]);
  });

  it('only offers views whose field the capture populated', () => {
    const views = viewsForFields('DNS', ['Questions.Name', 'SrcIP']);
    expect(views.map(v => v.field)).toEqual(['Questions.Name']);
  });

  it('does not show the same view twice in a row', () => {
    const candidates = SECURITY_VIEWS.filter(v => v.type === 'Alert');
    let previous = pickRandomView(candidates, () => 0)!;
    for (const r of [0, 0, 0.5, 0.99, 0.99, 0]) {
      const next = pickRandomView(candidates, () => r)!;
      expect(next).not.toBe(previous);
      previous = next;
    }
  });

  it('every view asks a question and is unique', () => {
    const keys = SECURITY_VIEWS.map(v => `${v.type}|${v.field}|${v.chartType}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(SECURITY_VIEWS.every(v => v.question.endsWith('?'))).toBe(true);
  });
});
