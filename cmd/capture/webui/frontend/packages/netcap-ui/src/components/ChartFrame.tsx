import { useEffect, useMemo, useRef, type IframeHTMLAttributes } from 'react';
import { useTheme } from '@mui/material/styles';
import { appearanceTokens, type AppearanceMode } from '../lib/appearance';
import { getLocale, useLocale, type Locale } from '../lib/i18n';
import { useLocale as useUILocale } from "../lib/i18n";


export function chartFrameURL(src: string | undefined, mode: AppearanceMode, locale?: Locale): string | undefined {
  if (!src) return src;
  const hashAt = src.indexOf('#');
  const hash = hashAt < 0 ? '' : src.slice(hashAt);
  const url = hashAt < 0 ? src : src.slice(0, hashAt);
  const queryAt = url.indexOf('?');
  const path = queryAt < 0 ? url : url.slice(0, queryAt);
  const query = new URLSearchParams(queryAt < 0 ? '' : url.slice(queryAt + 1));
  query.set('theme', mode);
  query.set('locale', locale ?? query.get('locale') ?? getLocale());
  return `${path}?${query}${hash}`;
}

/**
 * Sandbox applied to every server-rendered chart frame.
 *
 * The critical omission is `allow-same-origin`. Charts are HTML documents built
 * by the Go backend via go-echarts, and their content is derived from
 * user-supplied capture files -- chart labels are HTTP User-Agent and Host
 * values, DNS query names, harvested credentials and certificate subjects,
 * lifted verbatim off the wire. Without `allow-same-origin` the frame gets an
 * opaque origin, so even if a label ever escapes its script context again the
 * resulting script cannot read `parent`, `localStorage`, cookies, or call the
 * `/api/*` surface. It contains the blast radius to a blank throwaway origin.
 *
 * `allow-scripts` is required because echarts draws the chart from JavaScript.
 * Note that `allow-scripts` together with `allow-same-origin` would let the
 * frame remove its own sandbox attribute, which is exactly why the pair is
 * avoided here.
 *
 * `allow-downloads` preserves the echarts toolbox "Save as image" button, which
 * triggers a download from inside the frame.
 */
const CHART_SANDBOX = 'allow-scripts allow-downloads';

/**
 * Props accepted by ChartFrame: everything an <iframe> takes except `sandbox`,
 * which is deliberately not overridable from a call site.
 */
export type ChartFrameProps = Omit<IframeHTMLAttributes<HTMLIFrameElement>, 'sandbox'>;

/**
 * ChartFrame renders a sandboxed iframe for a backend-generated chart.
 *
 * Use this instead of a bare <iframe> for anything whose content the backend
 * builds from capture data. It exists so the sandbox is declared once rather
 * than repeated across ~50 call sites, where a newly added chart would
 * silently omit it -- the failure mode is invisible, because an unsandboxed
 * chart looks and behaves identically to a sandboxed one.
 *
 * `sandbox` is applied after the prop spread so it always wins.
 */
export function ChartFrame({ style, src, onLoad, ...props }: ChartFrameProps) {
  const __uiLocale = useUILocale();
  const mode = useTheme().palette.mode;
  const locale = useLocale();
  const frame = useRef<HTMLIFrameElement>(null);
  // Presentation changes update the existing document, retaining zoom/selection.
  const requestURL = useMemo(() => chartFrameURL(src, mode, locale), [src]);
  const present = () => frame.current?.contentWindow?.postMessage({ type: 'netcap:presentation', theme: mode, locale }, '*');
  useEffect(present, [mode, locale, requestURL]);
  const colors = appearanceTokens(mode);
  return (
    <iframe {...props}
      ref={frame}
      src={requestURL}
      onLoad={event => { present(); onLoad?.(event); }}
      style={{ backgroundColor: colors.canvas, colorScheme: mode, ...style }}
      sandbox={CHART_SANDBOX} />
  );
}
