import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { NetcapProvider } from '../providers/NetcapProvider';
import VulnerabilitiesPage from './VulnerabilitiesPage';
import type { KEVStatus } from '../components/VulnerabilityKEV';

const view = vi.hoisted(() => ({ mobile: false }));
vi.mock('../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock('../components/FileSelectorHeader', () => ({ default: () => null }));
vi.mock('../components/ResponsiveDataView', () => ({ default: ({ data, renderCard, desktopTable }: { data: unknown[]; renderCard: (row: unknown) => React.ReactNode; desktopTable: React.ReactNode }) => view.mobile ? <>{data.map(renderCard)}</> : desktopTable }));
vi.mock('../contexts/CommunityIDFilterContext', () => ({ useCommunityIDFilter: () => ({ selectedCommunityIDs: new Set(), isFilterActive: false }) }));
vi.mock('../hooks', async importOriginal => ({ ...await importOriginal<typeof import('../hooks')>(), useViewMode: () => ['table', vi.fn()], useTableKeyboardNavigation: () => ({}) }));

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const reference = { url: 'https://example.org/advisory', source: 'nvd', tags: ['Exploit'] };

function mount(mobile: boolean, kev?: KEVStatus) {
  view.mobile = mobile;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, json: async () => ({
    vulnerabilities: [{ id: 'CVE-fixture', description: 'Fixture vulnerability', severity: 'HIGH', v2Score: '7.5', accessVector: 'NETWORK', versions: ['1'], count: 7, affected: 3, software: null, communityIds: [], references: [reference], kev }],
    kevStatus: kev ? 'available' : 'unavailable',
    exploits: [{ id: 'EDB-fixture', description: 'Historical exploit metadata', file: 'retired.txt', count: 2, affected: 1, software: null, communityIds: [] }],
    affectedHosts: [], totalVulns: 7, totalExploits: 2,
  }) } as Response);
  render(<SWRConfig value={{ provider: () => new Map(), shouldRetryOnError: false }}>
    <NetcapProvider config={{ backendUrl: 'http://fixture', api: { getStatus: async () => ({}), getInputFiles: async () => [] } as never,
      router: { pathname: '/vulnerabilities', query: {}, isReady: true, push: vi.fn() }, Link: ({ href, children }) => <a href={href}>{children}</a>,
    }}><VulnerabilitiesPage /></NetcapProvider>
  </SWRConfig>);
  return fetcher;
}

it('shows attributed references in desktop details and retires payload loading without changing NVD counts', async () => {
  const fetcher = mount(false);
  const row = await screen.findByRole('row', { name: /CVE-fixture/ });
  expect(within(row).getByRole('cell', { name: '7' })).toBeVisible();
  expect(within(row).getByRole('cell', { name: '3' })).toBeVisible();
  fireEvent.click(row);
  expect(await screen.findByRole('link', { name: reference.url })).toHaveAttribute('href', reference.url);
  expect(screen.getByText('Severity & Scoring')).toBeVisible();
  expect(screen.getByText('Impact')).toBeVisible();
  fireEvent.click(screen.getByRole('tab', { name: /Exploits/ }));
  fireEvent.click(await screen.findByRole('row', { name: /EDB-fixture/ }));
  expect(await screen.findByText(/Exploit payload delivery is retired/)).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Load Code' })).not.toBeInTheDocument();
  expect(fetcher.mock.calls.every(([url]) => new URL(String(url)).pathname === '/api/vulnerabilities')).toBe(true);
});

it('joins optional KEV in desktop details without changing occurrence counts or NVD references', async () => {
  mount(false, { cve: 'CVE-fixture', date_added: '2026-11-04', ransomware: 'Unknown', federal_due_date: '2026-11-18', required_action: 'Synthetic action', urls: [] });
  const row = await screen.findByRole('row', { name: /CVE-fixture/ });
  expect(within(row).getByText('CISA KEV')).toBeVisible();
  expect(within(row).getByRole('cell', { name: '7' })).toBeVisible();
  expect(within(row).getByRole('cell', { name: '3' })).toBeVisible();
  fireEvent.click(row);
  expect(await screen.findByText('Ransomware campaign use: Unknown')).toBeVisible();
  expect(screen.getByRole('link', { name: reference.url })).toBeVisible();
  expect(screen.getByText('Optional CISA KEV: available')).toBeVisible();
});

it('shows the same reference metadata in mobile cards with original occurrence and host counts', async () => {
  const fetcher = mount(true);
  expect(await screen.findByRole('link', { name: reference.url })).toHaveAttribute('rel', 'noopener noreferrer');
  expect(screen.getByText('Source: nvd')).toBeVisible();
  expect(screen.getByText('Tags: Exploit')).toBeVisible();
  expect(screen.getByText('Count: 7')).toBeVisible();
  expect(screen.getByText('Affected: 3')).toBeVisible();
  expect(fetcher.mock.calls.every(([url]) => new URL(String(url)).pathname === '/api/vulnerabilities')).toBe(true);
});
