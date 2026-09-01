import type { IframeHTMLAttributes } from 'react';

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
export function ChartFrame(props: ChartFrameProps) {
  return <iframe {...props} sandbox={CHART_SANDBOX} />;
}
