import type { CSSProperties } from 'react';

export type AppearanceMode = 'dark' | 'light';

export interface AppearanceTokens {
  mode: AppearanceMode;
  canvas: string;
  surface: string;
  raised: string;
  text: string;
  muted: string;
  primary: string;
  secondary: string;
  success: string;
  warning: string;
  error: string;
  info: string;
  divider: string;
  border: string;
  selection: string;
  selectionText: string;
  overlay: string;
  gradient: readonly [string, string];
  onGradient: string;
  series: readonly string[];
  syntax: Record<'text' | 'key' | 'string' | 'number' | 'keyword' | 'operator' | 'function' | 'comment' | 'error', string>;
  protocol: Readonly<Record<string, string>>;
}

const dark: AppearanceTokens = {
  mode: 'dark', canvas: '#050508', surface: '#0b0c14', raised: '#11131f',
  text: '#f4f7fb', muted: '#a4aec2', primary: '#79b8ff', secondary: '#bba4ff',
  success: '#5ee0ac', warning: '#fcd36a', error: '#ff8fa3', info: '#69d3fa',
  divider: '#292e42', border: '#76839d', selection: '#233a60', selectionText: '#f4f7fb',
  overlay: 'rgba(5, 5, 8, 0.88)', gradient: ['#1d4ed8', '#6d28d9'], onGradient: '#ffffff',
  series: ['#79b8ff', '#bba4ff', '#69d3fa', '#5ee0ac', '#fcd36a', '#ff8fa3'],
  syntax: { text: '#f4f7fb', key: '#9cdcfe', string: '#f0ad91', number: '#b5dea4', keyword: '#dba8dc', operator: '#fcd36a', function: '#e3dda2', comment: '#a4aec2', error: '#ff8fa3' },
  protocol: { TCP: '#79b8ff', UDP: '#fcd36a', ICMP: '#dba8dc', 'Other IP': '#5ee0ac', 'Non-IP': '#a4aec2' },
};

const light: AppearanceTokens = {
  mode: 'light', canvas: '#f4f7fb', surface: '#ffffff', raised: '#eef2f9',
  text: '#172033', muted: '#475569', primary: '#1d4ed8', secondary: '#6d28d9',
  success: '#11683f', warning: '#854d0e', error: '#b91c3c', info: '#075985',
  divider: '#cbd5e1', border: '#64748b', selection: '#dbe7ff', selectionText: '#172033',
  overlay: 'rgba(244, 247, 251, 0.92)', gradient: ['#1d4ed8', '#6d28d9'], onGradient: '#ffffff',
  series: ['#1d4ed8', '#6d28d9', '#075985', '#11683f', '#854d0e', '#b91c3c'],
  syntax: { text: '#172033', key: '#075985', string: '#963b19', number: '#28612c', keyword: '#73268b', operator: '#854d0e', function: '#634d08', comment: '#475569', error: '#b91c3c' },
  protocol: { TCP: '#1d4ed8', UDP: '#854d0e', ICMP: '#73268b', 'Other IP': '#11683f', 'Non-IP': '#475569' },
};

/** Stable objects keep paint effects independent of unrelated React renders. */
export function appearanceTokens(mode: AppearanceMode): AppearanceTokens {
  return mode === 'light' ? light : dark;
}

function luminance(hex: string): number {
  const channels = hex.replace('#', '').match(/.{2}/g)!.map(c => {
    const v = parseInt(c, 16) / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

export function contrastRatio(a: string, b: string): number {
  const x = luminance(a), y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

function mix(a: string, b: string, weight: number): string {
  const channel = (i: number) => Math.round(parseInt(a.slice(i, i + 2), 16) * (1 - weight) + parseInt(b.slice(i, i + 2), 16) * weight).toString(16).padStart(2, '0');
  return `#${channel(1)}${channel(3)}${channel(5)}`;
}

/** Retains an entity's hue while making its label/mark readable on UI surfaces. */
export function appearanceColor(color: string, mode: AppearanceMode, minimum = 4.5): string {
  if (/^#[0-9a-f]{3}$/i.test(color)) color = `#${[...color.slice(1)].map(c => c + c).join('')}`;
  if (!/^#[0-9a-f]{6}$/i.test(color)) return appearanceTokens(mode).text;
  const tokens = appearanceTokens(mode);
  const target = mode === 'light' ? '#000000' : '#ffffff';
  for (let step = 0; step <= 100; step++) {
    const candidate = mix(color, target, step / 100);
    if ([tokens.canvas, tokens.surface, tokens.raised].every(bg => contrastRatio(candidate, bg) >= minimum)) return candidate;
  }
  return tokens.text;
}

export function categoryAppearance(label: string, mode: AppearanceMode): { background: string; foreground: string; border: string } {
  let hash = 0;
  for (const char of label) hash = ((hash << 5) - hash + char.charCodeAt(0)) | 0;
  const tokens = appearanceTokens(mode);
  const border = tokens.series[(hash >>> 0) % tokens.series.length];
  const background = mix(tokens.surface, border, 0.12);
  // The neutral foreground also passes on every tinted chip, including yellow.
  return { background, foreground: tokens.text, border };
}

export function appearanceCssVariables(mode: AppearanceMode): Record<string, string> {
  const t = appearanceTokens(mode);
  const variables: Record<string, string> = {};
  for (const role of ['canvas', 'surface', 'raised', 'text', 'muted', 'primary', 'secondary', 'success', 'warning', 'error', 'info', 'divider', 'border', 'selection', 'selectionText', 'overlay'] as const) {
    variables[`--netcap-${role.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)}`] = t[role];
  }
  for (const [role, color] of Object.entries(t.syntax)) variables[`--netcap-syntax-${role}`] = color;
  variables['--netcap-blue'] = t.primary;
  variables['--netcap-violet'] = t.secondary;
  return variables;
}

export function prismAppearance(mode: AppearanceMode): Record<string, CSSProperties> {
  const c = appearanceTokens(mode);
  const base = { color: c.text, background: c.canvas, textShadow: 'none', fontFamily: 'var(--netcap-mono, monospace)' };
  const styles: Record<string, CSSProperties> = {
    'code[class*="language-"]': base,
    'pre[class*="language-"]': { ...base, margin: 0, padding: '1em', overflow: 'auto' },
  };
  const groups: [string[], string][] = [
    [['comment', 'prolog', 'doctype', 'cdata'], c.syntax.comment],
    [['punctuation', 'operator', 'entity', 'url'], c.syntax.operator],
    [['property', 'tag', 'constant', 'symbol', 'attr-name'], c.syntax.key],
    [['boolean', 'number'], c.syntax.number],
    [['selector', 'string', 'char', 'attr-value', 'regex'], c.syntax.string],
    [['atrule', 'keyword', 'builtin'], c.syntax.keyword],
    [['function', 'class-name', 'variable'], c.syntax.function],
    [['deleted'], c.error], [['inserted'], c.success],
  ];
  for (const [names, color] of groups) for (const name of names) styles[name] = { color };
  return styles;
}
