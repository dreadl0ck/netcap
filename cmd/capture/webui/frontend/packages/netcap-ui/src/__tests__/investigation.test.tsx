import React from 'react';
import '@testing-library/jest-dom/vitest';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import { NetcapProvider } from '../providers';
import InvestigationPage from '../pages/InvestigationPage';

vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));
afterEach(cleanup);

it('keeps exact time/counter strings and distinguishes unavailable collection evidence', async () => {
  const fetcher = vi.fn(async (url: RequestInfo | URL) => ({ ok: true, status: 200, json: async () => {
    if (String(url).includes('/investigation/capture')) return { runId: 'fixture', status: 'partial', inputSHA256: 'a'.repeat(64), configSHA256: 'b'.repeat(64), ingressPackets: 10, admittedPackets: 9, queueDrops: 1, truncatedPackets: 0, kernelReceived: null, kernelDrops: null, firstNs: '1700000000000000001', lastNs: '1700000000000000003', limitations: ['Sensor topology unknown'], segments: [{ state: 'expired', name: 'segment', packets: 1, sha256: 'c'.repeat(64) }] };
    if (String(url).includes('/investigation/streams')) return [];
    return { matchedObservations: 1, totalGroups: 1, recordFileSHA256: 'd'.repeat(64), limitations: ['Whole observations; no time clipping'], series: [{ startNs: '1700000000000000001', endNs: '1700000000000000002', estimatedBytes: 10, estimatedBitsPerSecond: 80000000000, directionalComplete: false }], groups: [{ key: '192.0.2.1', bytes: '9007199254740993', packets: '42', distinctPeers: 1, members: [{ ordinal: 7, observationId: 'fixture' }] }] };
  }} as Response));
  render(<SWRConfig value={{ provider: () => new Map() }}><NetcapProvider config={{ backendUrl: 'http://fixture', router: { pathname: '/investigation-evidence', query: {}, isReady: true, push: vi.fn() }, Link: ({ href, children }) => <a href={href}>{children}</a>, fetch: fetcher, api: { getStatus: async () => ({ isProcessing: false, outputDir: '/capture', inputFiles: ['/fixture.pcap'], serverStarted: '', activeInputFile: '/fixture.pcap', isMultiFile: false, isLiveMode: false }), getInputFiles: async () => [] } }}><InvestigationPage /></NetcapProvider></SWRConfig>);
  expect(await screen.findByText(/Kernel received: unavailable/)).toHaveTextContent('Kernel drops: unavailable');
  expect(screen.getByText(/Packet segments:/)).toHaveTextContent('0 retained, 1 expired');
  await waitFor(() => expect(screen.getByLabelText('Start UTC nanoseconds')).toHaveValue('1700000000000000001'));
  const user = userEvent.setup();
  await user.type(screen.getByLabelText('Estimated series bin width (nanoseconds)'), '1');
  await user.click(screen.getByRole('button', { name: 'Run scoped query' }));
  expect(await screen.findByText('9007199254740993')).toBeInTheDocument();
  expect(screen.getByText('Whole observations; no time clipping')).toBeInTheDocument();
  const request = fetcher.mock.calls.find(([url]) => String(url).includes('/flows/query'));
  expect(request).toBeDefined();
  const params = new URL(String(request![0])).searchParams;
  expect(params.get('startNs')).toBe('1700000000000000001');
  expect(params.get('endNs')).toBe('1700000000000000003');
  expect(params.get('inputFile')).toBe('/fixture.pcap');
  expect(params.get('bucketNs')).toBe('1');
  expect(screen.getByRole('table', { name: 'Estimated flow time series' })).toHaveTextContent('Incomplete');
});
