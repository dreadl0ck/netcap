import React from 'react';
import '@testing-library/jest-dom/vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, renderHook, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import { NetcapProvider } from '../providers';
import BehaviorPage from '../pages/BehaviorPage';
import { useLiveAlerts } from '../hooks/useLiveAlerts';
import { behaviorSelection, learningReady } from '../lib/behavior';
import type { BehaviorSnapshot } from '../lib/behavior';
import type { Alert, StatusResponse } from '../lib/api';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));

const status: StatusResponse = { isProcessing: false, outputDir: '/capture', inputFiles: ['/fixture.pcap'], serverStarted: '',
  activeInputFile: '/fixture.pcap', isMultiFile: false, isLiveMode: false };

function snapshot(): BehaviorSnapshot {
  return { schema: 1, mode: 'learning', version: 0, baselineId: '', learningStarted: 1700000000000000000,
    watermark: 1700000001000000000, samples: 2, overflow: 0, outOfOrder: 0, minLearningNS: 1e9, minSamples: 2, maxFacts: 10,
    observed: { device: { fact: { scope: { sensor: 'fixture', interface: 'pcap' }, kind: 'device', mac: '00:11:22:33:44:55' },
      firstSeen: 1700000000000000000, lastSeen: 1700000001000000000, samples: 2 } }, approved: {}, suppressed: {}, decisions: [] };
}

class MockSource extends EventTarget {
  static sources: MockSource[] = [];
  closed = false;
  onerror: (() => void) | null = null;
  constructor(public url: string) { super(); MockSource.sources.push(this); }
  close() { this.closed = true; }
  emit(type: string, data: unknown) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
}

afterEach(() => { cleanup(); vi.unstubAllGlobals(); MockSource.sources = []; });

describe('behavioral monitoring', () => {
  it('pins explicit capture selectors and blocks incomplete learning', () => {
    expect(behaviorSelection(status)).toBe('?inputFile=%2Ffixture.pcap');
    expect(behaviorSelection({ ...status, isServiceMode: true, sessionId: 'session-1' })).toBe('?sessionId=session-1');
    expect(learningReady(snapshot())).toBe(true);
    expect(learningReady({ ...snapshot(), overflow: 1 })).toBe(false);
    expect(learningReady({ ...snapshot(), samples: 1 })).toBe(false);
    expect(learningReady({ ...snapshot(), watermark: snapshot().learningStarted })).toBe(false);
    expect(learningReady({ ...snapshot(), error: 'disk failure' })).toBe(false);
  });

  it('requires a reason and submits approval against the displayed version', async () => {
    let current = snapshot();
    const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'POST') current = { ...current, mode: 'monitoring', version: 1, baselineId: 'approved', approved: { device: current.observed.device.fact } };
      return { ok: true, status: 200, json: async () => current } as Response;
    });
    render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}><NetcapProvider config={{
      backendUrl: 'http://fixture', router: { pathname: '/behavior', query: {}, isReady: true, push: vi.fn() },
      Link: ({ href, children }) => <a href={href}>{children}</a>, fetch: fetcher,
      api: { getStatus: async () => status, getInputFiles: async () => [] },
    }}><BehaviorPage /></NetcapProvider></SWRConfig>);
    const user = userEvent.setup();
    const approve = await screen.findByRole('button', { name: 'Approve learned baseline' });
    await waitFor(() => expect(approve).toBeEnabled());
    await user.click(approve);
    expect(screen.getByRole('button', { name: 'Apply decision' })).toBeDisabled();
    await user.type(screen.getByRole('textbox', { name: /Decision reason/ }), 'Reviewed fixture inventory');
    await user.click(screen.getByRole('button', { name: 'Apply decision' }));
    await waitFor(() => expect(screen.getByText('Baseline v1')).toBeInTheDocument());
    const request = fetcher.mock.calls.find(([, init]) => init?.method === 'POST');
    expect(request?.[0]).toBe('http://fixture/api/behavior/change?inputFile=%2Ffixture.pcap');
    expect(JSON.parse(request?.[1]?.body as string)).toEqual({ action: 'approve', ids: [], reason: 'Reviewed fixture inventory', version: 0 });
  });

  it('bounds the live feed, reports gaps and closes old capture streams', () => {
    vi.stubGlobal('EventSource', MockSource);
    const { result, rerender } = renderHook(({ url }) => useLiveAlerts(url), { initialProps: { url: '/api/alerts/stream?sessionId=one' } });
    const source = MockSource.sources[0];
    act(() => {
      source.emit('connected', {});
      for (let i = 0; i < 205; i++) source.emit('alert', { alertId: String(i), name: `alert-${i}` } as Alert);
    });
    expect(result.current.alerts).toHaveLength(200);
    expect(result.current.alerts[0].name).toBe('alert-204');
    act(() => source.emit('gap', { error: 'history replaced' }));
    expect(result.current.state).toBe('gap');
    expect(result.current.error).toBe('history replaced');
    expect(source.closed).toBe(true);
    rerender({ url: '/api/alerts/stream?sessionId=two' });
    expect(result.current.alerts).toHaveLength(0);
    expect(MockSource.sources[1].url).toContain('sessionId=two');
  });

  it('keeps the reviewed version when a refresh changes the baseline', async () => {
    let current = snapshot();
    const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => init?.method === 'POST'
      ? { ok: false, status: 409, text: async () => 'baseline version changed; refresh before applying the decision' } as Response
      : { ok: true, status: 200, json: async () => current } as Response);
    render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}><NetcapProvider config={{
      backendUrl: 'http://fixture', router: { pathname: '/behavior', query: {}, isReady: true, push: vi.fn() },
      Link: ({ href, children }) => <a href={href}>{children}</a>, fetch: fetcher,
      api: { getStatus: async () => status, getInputFiles: async () => [] },
    }}><BehaviorPage /></NetcapProvider></SWRConfig>);
    const user = userEvent.setup();
    const approve = await screen.findByRole('button', { name: 'Approve learned baseline' });
    await waitFor(() => expect(approve).toBeEnabled());
    await user.click(approve);
    current = { ...current, mode: 'monitoring', version: 1, baselineId: 'changed' };
    await waitFor(() => expect(screen.getByText('Baseline v1')).toBeInTheDocument(), { timeout: 3000 });
    await user.type(screen.getByRole('textbox', { name: /Decision reason/ }), 'Reviewed earlier baseline');
    await user.click(screen.getByRole('button', { name: 'Apply decision' }));
    await waitFor(() => expect(screen.getAllByText(/baseline version changed/).length).toBeGreaterThan(0));
    const request = fetcher.mock.calls.find(([, init]) => init?.method === 'POST');
    expect(JSON.parse(request?.[1]?.body as string).version).toBe(0);
  });

  it('saves inventory labels and keeps the topology frame sandboxed', async () => {
    let current = snapshot();
    const fetcher = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (String(url).includes('/topology')) return { ok: true, status: 200, json: async () => ({ nodes: [], links: [], totalNodes: 1, totalLinks: 0, truncated: false }) } as Response;
      if (init?.method === 'POST') current = { ...current, version: 1, labels: { device: { fact: current.observed.device.fact, name: 'Office gateway', role: 'router' } } };
      return { ok: true, status: 200, json: async () => current } as Response;
    });
    render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}><NetcapProvider config={{
      backendUrl: 'http://fixture', router: { pathname: '/behavior', query: {}, isReady: true, push: vi.fn() },
      Link: ({ href, children }) => <a href={href}>{children}</a>, fetch: fetcher,
      api: { getStatus: async () => status, getInputFiles: async () => [] },
    }}><BehaviorPage /></NetcapProvider></SWRConfig>);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Label' }));
    expect(screen.getByRole('button', { name: 'Save inventory' })).toBeDisabled();
    await user.type(screen.getByRole('textbox', { name: 'Asset name' }), 'Office gateway');
    await user.type(screen.getByRole('textbox', { name: 'Asset role' }), 'router');
    await user.type(screen.getByRole('textbox', { name: /Inventory decision reason/ }), 'Reviewed gateway inventory');
    await user.click(screen.getByRole('button', { name: 'Save inventory' }));
    await waitFor(() => expect(screen.getByText('Office gateway')).toBeInTheDocument());
    const request = fetcher.mock.calls.find(([, init]) => init?.method === 'POST');
    const body = JSON.parse(request?.[1]?.body as string);
    expect(body.version).toBe(0);
    expect(body.inventory).toEqual({ id: 'device', name: 'Office gateway', role: 'router', notes: '' });
    await user.click(await screen.findByRole('tab', { name: 'Topology' }));
    const frame = screen.getByTitle('Scoped observed network topology');
    expect(frame).toHaveAttribute('sandbox', 'allow-scripts allow-downloads');
    expect(frame.getAttribute('src')).toContain('format=html');
  });
});
