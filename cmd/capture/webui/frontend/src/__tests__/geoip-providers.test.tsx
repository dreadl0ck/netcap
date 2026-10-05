import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { SWRConfig } from 'swr';
import { NetcapProvider } from '../../packages/netcap-ui/src/providers/NetcapProvider';
import DatabasesPage from '../../packages/netcap-ui/src/pages/DbsPage';
import GeoIPAttribution from '../../packages/netcap-ui/src/components/GeoIPAttribution';

vi.mock('../../packages/netcap-ui/src/components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

const status = {
  geoProviders: 'dbip,geolite2',
  geoStatus: [
    { name: 'dbip', selected: true, available: true, loaded: true, cityBuild: '2026-10-01', asnBuild: '2026-10-01' },
    { name: 'geolite2', selected: true, available: false, loaded: false, error: 'User-installed files are missing' },
  ],
};

function renderPage(save: ReturnType<typeof vi.fn>) {
  render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <NetcapProvider config={{
        backendUrl: 'http://127.0.0.1:1234',
        api: {
          getDatabaseInfo: vi.fn().mockResolvedValue({ files: [], fileCount: 0, totalSize: 0 }),
          getDatabaseStatus: vi.fn().mockResolvedValue(status),
          getStatus: vi.fn().mockResolvedValue({ isServiceMode: false }),
          setGeoProviders: save,
        } as never,
        router: { pathname: '/dbs', query: {}, isReady: true, push: () => {}, replace: () => {} },
        Link: ({ href, children }) => <a href={href}>{children}</a>,
      }}><DatabasesPage /></NetcapProvider>
    </SWRConfig>,
  );
}

describe('GeoIP providers', () => {
  it('shows readiness and saves an explicit single-provider selection', async () => {
    const save = vi.fn().mockResolvedValue({ ...status, geoProviders: 'geolite2' });
    renderPage(save);
    expect(await screen.findByText(/DB-IP Lite: selected, available, loaded/)).toBeInTheDocument();
    expect(screen.getByText('User-installed files are missing')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('combobox', { name: 'Provider order' }));
    await user.click(screen.getByRole('option', { name: 'GeoLite2 only' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith('geolite2'));
    expect(await screen.findByText(/Provider order saved/)).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Provider order' })).toHaveTextContent('GeoLite2 only');
  });

  it('keeps the displayed order when saving fails', async () => {
    renderPage(vi.fn().mockRejectedValue(new Error('Cannot save settings')));
    await screen.findByRole('combobox', { name: 'Provider order' });
    const user = userEvent.setup();
    await user.click(screen.getByRole('combobox', { name: 'Provider order' }));
    await user.click(screen.getByRole('option', { name: 'DB-IP only' }));
    expect(await screen.findByText('Cannot save settings')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Provider order' })).toHaveTextContent('DB-IP, then GeoLite2');
  });

  it('provides visible source and licence links for result pages', () => {
    render(<GeoIPAttribution />);
    expect(screen.getByRole('link', { name: 'IP Geolocation by DB-IP' })).toHaveAttribute('href', 'https://db-ip.com');
    expect(screen.getByRole('link', { name: 'CC BY 4.0' })).toHaveAttribute('href', 'https://creativecommons.org/licenses/by/4.0/');
    expect(screen.getByRole('link', { name: 'GeoNames' })).toHaveAttribute('href', 'https://www.geonames.org');
  });
});
