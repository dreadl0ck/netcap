import { describe, expect, it } from 'vitest';
import { appearanceColor, appearanceTokens, categoryAppearance, contrastRatio } from './appearance';
import { highlightFilterExpression } from './filterSyntaxHighlight';
import { highlightBPFExpression } from './bpfSyntaxHighlight';
import { highlightRegexPattern } from './regexSyntaxHighlight';

// Independent WCAG calculation so a regression in the production helper cannot hide a bad token.
function ratio(a: string, b: string) {
  const luminance = (hex: string) => [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map(v => v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)
    .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
  const x = luminance(a), y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

describe.each(['dark', 'light'] as const)('%s appearance contrast', mode => {
  const t = appearanceTokens(mode);
  it('meets 4.5:1 for text, syntax, semantic colors and labels on every surface', () => {
    for (const bg of [t.canvas, t.surface, t.raised]) {
      for (const fg of [t.text, t.muted, t.primary, t.secondary, t.success, t.warning, t.error, t.info, ...Object.values(t.syntax), ...Object.values(t.protocol)]) {
        expect(ratio(fg, bg), `${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
      }
      for (const fg of [t.border, ...t.series]) expect(ratio(fg, bg), `${fg} mark on ${bg}`).toBeGreaterThanOrEqual(3);
    }
    expect(ratio(t.selectionText, t.selection)).toBeGreaterThanOrEqual(4.5);
  });
  it('keeps the whole blue/violet gradient readable with its actual white label', () => {
    for (let n = 0; n <= 100; n++) {
      const bg = '#' + [1, 3, 5].map(i => Math.round(parseInt(t.gradient[0].slice(i, i + 2), 16) * (1 - n / 100) + parseInt(t.gradient[1].slice(i, i + 2), 16) * n / 100).toString(16).padStart(2, '0')).join('');
      expect(ratio(t.onGradient, bg), bg).toBeGreaterThanOrEqual(4.5);
    }
  });
  it('pairs deterministic chip foregrounds with their actual tinted backgrounds', () => {
    for (let i = 0; i < 400; i++) {
      const chip = categoryAppearance(`field-${i}`, mode);
      expect(ratio(chip.foreground, chip.background)).toBeGreaterThanOrEqual(4.5);
      expect(ratio(chip.border, t.surface)).toBeGreaterThanOrEqual(3);
    }
  });
  it('recolors arbitrary entity hues and all three syntax tokenizers without changing evidence', () => {
    for (const color of ['#134e4a', '#365314', '#3730a3', '#fbbf24', '#f472b6', '#666']) {
      const fg = appearanceColor(color, mode);
      expect(ratio(fg, t.raised)).toBeGreaterThanOrEqual(4.5);
    }
    const samples = [
      { text: 'SrcIP == "<wire>&" && Length > 42', tokens: highlightFilterExpression('SrcIP == "<wire>&" && Length > 42', mode) },
      { text: 'tcp and host 10.0.0.1 and port 443', tokens: highlightBPFExpression('tcp and host 10.0.0.1 and port 443', mode) },
      { text: '(?i)^(foo|bar)[0-9]+\\w$', tokens: highlightRegexPattern('(?i)^(foo|bar)[0-9]+\\w$', mode) },
    ];
    for (const { text, tokens } of samples) {
      expect(tokens.map(t => t.value).join('')).toBe(text);
      for (const token of tokens.filter(t => t.color !== 'inherit')) expect(ratio(token.color, t.raised), token.type).toBeGreaterThanOrEqual(4.5);
    }
  });
});

it('calculates the WCAG reference endpoints', () => {
  expect(contrastRatio('#000000', '#ffffff')).toBe(21);
  expect(contrastRatio('#ffffff', '#ffffff')).toBe(1);
});
