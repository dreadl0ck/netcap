import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { SWRConfig } from 'swr';
import { NetcapProvider } from '../../packages/netcap-ui/src/providers/NetcapProvider';
import SignaturesPage from '../../packages/netcap-ui/src/pages/ProbesPage';
import { api } from '../../packages/netcap-ui/src/lib/api';

vi.mock('../../packages/netcap-ui/src/components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

const rules = [
  { id: 'netcap.ssh.ident.v1', protocol: 'ssh', transport: 'tcp', direction: 'server-to-client', kind: 'ssh-ident', provenance: [{ url: 'https://www.rfc-editor.org/rfc/rfc4253', section: '4.2 Protocol Version Exchange' }] },
  { id: 'netcap.http.response.v1', protocol: 'http', transport: 'tcp', direction: 'server-to-client', kind: 'http1-response', provenance: [{ url: 'https://www.rfc-editor.org/rfc/rfc9112', section: '4 Status Line' }] },
];
const inventory = { state: 'loaded', source: 'builtin', source_sha256: 'a'.repeat(64), checked_at: '2026-10-24T00:00:00Z', degraded: true, warning: 'Catalogue absent; built-in fallback active', rule_count: 2, protocols: ['http', 'ssh'], limitations: ['TCP server-to-client greetings only'] };
const catalogue = { catalogue: { format: 'netcap-service-signatures', schema_version: 1, rules }, inventory, source: 'builtin', degraded: true };

function renderPage(search = '', response = Promise.resolve(catalogue)) {
  const getServiceSignatures = vi.fn().mockReturnValue(response);
  const getServiceSignatureStatus = vi.fn().mockResolvedValue({ ...inventory, source: 'external', source_sha256: 'b'.repeat(64), degraded: false, warning: undefined });
  render(<SWRConfig value={{ provider: () => new Map(), shouldRetryOnError: false }}>
    <NetcapProvider config={{
      backendUrl: 'http://127.0.0.1:1234',
      api: { getServiceSignatures, getServiceSignatureStatus, getStatus: vi.fn().mockResolvedValue({ isServiceMode: true, sessionId: 'fixture-session' }), getInputFiles: vi.fn().mockResolvedValue([]) } as never,
      router: { pathname: '/service-signatures', query: { search }, isReady: true, push: vi.fn(), replace: vi.fn() },
      Link: ({ href, children }) => <a href={href}>{children}</a>,
    }}><SignaturesPage /></NetcapProvider>
  </SWRConfig>);
  return { getServiceSignatures, getServiceSignatureStatus };
}

describe('service signatures', () => {
  it('shows source evidence, fallback and separate capture inventory without mutation controls', async () => {
    const calls = renderPage('netcap.ssh.ident.v1');
    expect(await screen.findByText('netcap.ssh.ident.v1')).toBeInTheDocument();
    expect(screen.queryByText('netcap.http.response.v1')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: '4.2 Protocol Version Exchange' })).toHaveAttribute('href', rules[0].provenance[0].url);
    expect(screen.getByText(inventory.warning)).toBeInTheDocument();
    expect(await screen.findByText(/Source SHA-256: b{64}/)).toBeInTheDocument();
    expect(screen.getByText(/imports and exports are retired/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /create|import|export|save|toggle/i })).not.toBeInTheDocument();
    expect(calls.getServiceSignatureStatus).toHaveBeenCalledWith('?sessionId=fixture-session');
    await userEvent.setup().clear(screen.getByRole('textbox', { name: /Search signature/ }));
    expect(await screen.findByText('netcap.http.response.v1')).toBeInTheDocument();
  });

  it('shows a real error instead of inventing a ready empty catalogue', async () => {
    renderPage('', Promise.reject(new Error('Backend unavailable')));
    expect(await screen.findByText(/Catalogue unavailable: Backend unavailable/)).toBeInTheDocument();
    expect(screen.queryByText(/0 of 0 signatures/)).not.toBeInTheDocument();
  });

  it('only requests the replacement GET endpoints', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, json: async () => catalogue } as Response);
    try {
      await api.getServiceSignatures();
      await api.getServiceSignatureStatus('?sessionId=fixture');
      expect(fetcher.mock.calls.map(([url]) => { const parsed = new URL(String(url), 'http://localhost'); return parsed.pathname + parsed.search; })).toEqual(['/api/service-signatures', '/api/service-signatures/status?sessionId=fixture']);
      expect(fetcher.mock.calls.every(([, init]) => init?.method === undefined || init.method === 'GET')).toBe(true);
    } finally { fetcher.mockRestore(); }
  });
});
