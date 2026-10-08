import React from 'react';
import '@testing-library/jest-dom/vitest';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import { NetcapProvider } from '../providers';
import RelatedEvidence from '../components/RelatedEvidence';
import FeatureToggles from '../components/FeatureToggles';
import { parseRelatedEvidence, selectorForAlert } from '../lib/evidenceLinks';

afterEach(cleanup);

const result = {
  schema: 1,
  target: { type: 'HTTP', ordinal: 0, timestamp: 1_800_000_002_000_000_000, communityId: '1:a=', summary: [{ name: 'Method', value: 'GET' }] },
  session: { communityId: '1:a=', first: 1_800_000_002_000_000_000, last: 1_800_000_005_000_000_000, srcIp: '10.0.0.5', srcPort: '40000', dstIp: '192.0.2.80', dstPort: '80', ordinal: 1 },
  links: [
    { kind: 'dns-resolution', basis: 'dns-answer-before-connection', record: { type: 'DNS', ordinal: 1, timestamp: 1_800_000_001_000_000_000, summary: [{ name: 'Query', value: 'example.test' }] } },
    { kind: 'alert', basis: 'community-id-in-connection-span', record: { type: 'Alert', ordinal: 0, timestamp: 1_800_000_002_000_000_000, summary: [{ name: 'RuleName', value: 'rule' }] } },
  ],
  truncated: false, indexed: 4, limits: { enabled: true, windowNs: 3600e9, maxRecords: 1e6, maxLinks: 500 }, notes: [],
};

const wrap = (api: object, child: React.ReactNode) => render(
  <SWRConfig value={{ provider: () => new Map() }}>
    <NetcapProvider config={{ backendUrl: 'http://fixture', router: { pathname: '/', query: {}, isReady: true, push: vi.fn() }, Link: ({ href, children }) => <a href={href}>{children}</a>, api }}>{child}</NetcapProvider>
  </SWRConfig>);

it('validates the related-evidence contract', () => {
  expect(parseRelatedEvidence(result)).not.toBeNull();
  expect(parseRelatedEvidence({ ...result, schema: 2 })).toBeNull();
  expect(parseRelatedEvidence({ ...result, links: [{ kind: 'guess', basis: '', record: result.target }] })).toBeNull();
});

it('selects an alert source with exact nanosecond time and rejects fallback identifiers', () => {
  const matched = '{"Timestamp":1800000002000000001,"CommunityID":"1:a=","Method":"GET"}';
  expect(selectorForAlert('NC_HTTP', matched)).toEqual({ type: 'HTTP', communityId: '1:a=', time: '1800000002000000001' });
  expect(selectorForAlert('NC_Connection', '{"TimestampFirst":5,"CommunityID":"1:b="}')).toEqual({ type: 'Connection', communityId: '1:b=', time: '5' });
  expect(selectorForAlert('NC_HTTP', '{"Timestamp":1,"CommunityID":"0f00"}')).toBeNull();
  expect(selectorForAlert('NetworkDetection', '{"schema":1}')).toBeNull();
});

it('renders the session timeline with link reasons and the selected record', async () => {
  const getRelatedEvidence = vi.fn(async () => ({ status: 'ok', result }));
  wrap({ getRelatedEvidence }, <RelatedEvidence selector={{ observationId: 'obs1' }} />);
  const table = await screen.findByRole('table', { name: 'Related evidence timeline' });
  const rows = within(table).getAllByRole('row');
  expect(rows[1]).toHaveTextContent('Resolved by DNS');
  expect(rows[1]).toHaveTextContent('Query=example.test');
  expect(rows[1]).toHaveTextContent('−1.00 s');
  expect(table).toHaveTextContent('Selected');
  expect(table).toHaveTextContent('RuleName=rule');
  expect(screen.getByText(/10\.0\.0\.5:40000 → 192\.0\.2\.80:80/)).toBeInTheDocument();
  expect(getRelatedEvidence).toHaveBeenCalledWith({ observationId: 'obs1' }, undefined);
});

it('explains a disabled feature instead of showing an empty result', async () => {
  wrap({ getRelatedEvidence: async () => ({ status: 'disabled', error: 'evidence linking is disabled' }) }, <RelatedEvidence selector={{ type: 'HTTP', ordinal: 0 }} />);
  expect(await screen.findByText(/Enable it in Settings → Features/)).toBeInTheDocument();
});

it('toggles a feature individually', async () => {
  const features = [
    { name: 'evidence-links', title: 'Evidence linking', description: 'd', scope: 'query', flag: '-evidence-links', env: 'NC_EVIDENCE_LINKS', enabled: true },
    { name: 'network-detection', title: 'Network detections', description: 'd', scope: 'capture', flag: '-network-detection', env: 'NC_NETWORK_DETECTION', enabled: true },
  ];
  const setFeature = vi.fn(async (name: string, enabled: boolean) => ({ features: features.map(f => f.name === name ? { ...f, enabled } : f) }));
  wrap({ getFeatures: async () => ({ features }), setFeature }, <FeatureToggles />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole('switch', { name: 'Evidence linking' }));
  expect(setFeature).toHaveBeenCalledWith('evidence-links', false);
  expect(await screen.findByRole('switch', { name: 'Evidence linking' })).not.toBeChecked();
  expect(screen.getByRole('switch', { name: 'Network detections' })).toBeChecked();
});
