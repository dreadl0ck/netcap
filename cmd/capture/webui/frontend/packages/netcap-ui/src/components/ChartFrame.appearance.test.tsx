import { act, fireEvent, render } from '@testing-library/react';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ChartFrame, chartFrameURL } from './ChartFrame';
import { setLocale } from '../lib/i18n';

afterEach(() => setLocale('en'));

describe('chart frame appearance', () => {
  it('preserves relative/absolute routes, encoded evidence, locale, query and fragment', () => {
    for (const path of ['/api/charts/dns', 'https://capture.invalid/chart']) {
      const result = chartFrameURL(`${path}?inputFile=a%26b.pcap&locale=fr&theme=dark#legend`, 'light')!;
      expect(result.startsWith(path + '?')).toBe(true);
      expect(result.endsWith('#legend')).toBe(true);
      const query = new URLSearchParams(result.split('?')[1].split('#')[0]);
      expect(query.get('inputFile')).toBe('a&b.pcap');
      expect(query.get('locale')).toBe('fr');
      expect(query.getAll('theme')).toEqual(['light']);
    }
    expect(chartFrameURL(undefined, 'dark')).toBeUndefined();
  });
  it('updates the existing iframe and keeps the sandbox non-overridable', () => {
    const frame = (mode: 'dark' | 'light') => <ThemeProvider theme={createTheme({ palette: { mode } })}><ChartFrame title="Capture chart" src="/api/chart?record=DNS" {...({ sandbox: 'allow-same-origin' } as object)} /></ThemeProvider>;
    const { container, rerender } = render(frame('dark'));
    const iframe = container.querySelector('iframe')!;
    const src = iframe.getAttribute('src');
    const post = vi.spyOn(iframe.contentWindow!, 'postMessage');
    expect(iframe.getAttribute('src')).toContain('theme=dark');
    rerender(frame('light'));
    expect(container.querySelector('iframe')).toBe(iframe);
    expect(iframe.getAttribute('src')).toBe(src);
    expect(iframe.getAttribute('sandbox')).toBe('allow-scripts allow-downloads');
    expect(iframe.style.colorScheme).toBe('light');
    act(() => setLocale('zh-Hans'));
    expect(container.querySelector('iframe')).toBe(iframe);
    expect(iframe.getAttribute('src')).toBe(src);
    expect(post).toHaveBeenLastCalledWith({ type: 'netcap:presentation', theme: 'light', locale: 'zh-Hans' }, '*');
    fireEvent.load(iframe);
    expect(post).toHaveBeenLastCalledWith({ type: 'netcap:presentation', theme: 'light', locale: 'zh-Hans' }, '*');
  });
});
