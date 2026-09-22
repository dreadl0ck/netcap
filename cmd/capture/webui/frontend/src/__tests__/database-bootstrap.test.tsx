/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * Cover for the first-launch database prompt. The download is ~91 MB and is
 * never started on its own: the user presses the button, and the progress they
 * then see is what distinguishes a slow transfer from a stall.
 */

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NetcapProvider } from '@dreadl0ck/netcap-ui/providers';
import { DatabaseBootstrap } from '@dreadl0ck/netcap-ui/components';
import type { DatabaseStatus } from '@dreadl0ck/netcap-ui';

const IDLE = { state: 'idle' as const, downloaded: 0, total: 0, percent: 0 };

const MISSING: DatabaseStatus = {
  satisfied: false,
  missing: [
    { file: 'GeoLite2-City.mmdb', feature: 'geolocation enrichment' },
    { file: 'GeoLite2-ASN.mmdb', feature: 'geolocation enrichment' },
  ],
  databaseDir: 'C:\\Users\\x\\.config\\netcap\\dbs',
  download: IDLE,
};

const SATISFIED: DatabaseStatus = {
  satisfied: true,
  missing: [],
  databaseDir: '/home/x/.config/netcap/dbs',
  download: IDLE,
};

function renderBootstrap(api: Record<string, unknown>) {
  render(
    <NetcapProvider
      config={{
        backendUrl: 'http://127.0.0.1:1234',
        api: api as never,
        router: { pathname: '/', query: {}, isReady: true, push: () => {}, replace: () => {} },
        Link: ({ href, children }) => <a href={href}>{children}</a>,
      }}
    >
      {/* No startup delay: the delay exists so the embedded server has time
          to bind its port, and waiting for it in a test buys nothing. */}
      <DatabaseBootstrap startupDelayMs={0} />
    </NetcapProvider>,
  );
}

beforeEach(() => {
  sessionStorage.clear();
});

describe('DatabaseBootstrap', () => {
  it('prompts when a required database is missing', async () => {
    renderBootstrap({
      getDatabaseStatus: vi.fn().mockResolvedValue(MISSING),
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue(IDLE),
      updateDatabases: vi.fn(),
    });

    expect(await screen.findByText(/analysis databases are missing/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /download databases/i })).toBeInTheDocument();
  });

  it('names the enrichment that is lost, deduplicated', async () => {
    renderBootstrap({
      getDatabaseStatus: vi.fn().mockResolvedValue(MISSING),
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue(IDLE),
      updateDatabases: vi.fn(),
    });

    const body = await screen.findByText(/geolocation enrichment/i);
    // Both missing files share one feature; saying it twice reads as two
    // separate problems.
    expect(body.textContent?.match(/geolocation enrichment/gi)?.length).toBe(1);
  });

  it('stays silent when every database is present', async () => {
    renderBootstrap({
      getDatabaseStatus: vi.fn().mockResolvedValue(SATISFIED),
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue(IDLE),
      updateDatabases: vi.fn(),
    });

    await new Promise(resolve => setTimeout(resolve, 50));
    expect(screen.queryByText(/analysis databases/i)).not.toBeInTheDocument();
  });

  // The App Store build serves no such endpoint and needs no download. A null
  // status must not produce a prompt offering something it cannot do.
  it('stays silent when the backend has no database endpoint', async () => {
    renderBootstrap({
      getDatabaseStatus: vi.fn().mockResolvedValue(null),
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue(null),
      updateDatabases: vi.fn(),
    });

    await new Promise(resolve => setTimeout(resolve, 50));
    expect(screen.queryByText(/analysis databases/i)).not.toBeInTheDocument();
  });

  it('never starts the download without a click', async () => {
    const updateDatabases = vi.fn();
    renderBootstrap({
      getDatabaseStatus: vi.fn().mockResolvedValue(MISSING),
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue(IDLE),
      updateDatabases,
    });

    await screen.findByText(/analysis databases are missing/i);
    await new Promise(resolve => setTimeout(resolve, 100));

    expect(updateDatabases).not.toHaveBeenCalled();
  });

  it('starts the download and shows progress when the button is pressed', async () => {
    const updateDatabases = vi.fn().mockResolvedValue({
      success: true,
      started: true,
      message: 'Database download started',
      download: {
        state: 'running',
        stage: 'download',
        downloaded: 45_000_000,
        total: 91_021_882,
        percent: 49.4,
        message: 'Downloading 43 MB of 87 MB',
      },
    });

    renderBootstrap({
      getDatabaseStatus: vi.fn().mockResolvedValue(MISSING),
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue(IDLE),
      updateDatabases,
    });

    await userEvent.click(await screen.findByRole('button', { name: /download databases/i }));

    expect(updateDatabases).toHaveBeenCalledTimes(1);

    await waitFor(() => {
      expect(screen.getByText(/downloading analysis databases/i)).toBeInTheDocument();
      expect(screen.getByText(/43 MB of 87 MB/i)).toBeInTheDocument();
    });

    // A running download must not offer a second start.
    expect(screen.queryByRole('button', { name: /download databases/i })).not.toBeInTheDocument();
  });

  // A fire-and-forget goroutine used to report success unconditionally, so a
  // download that never happened looked like one that did.
  it('reports a failed start instead of claiming success', async () => {
    renderBootstrap({
      getDatabaseStatus: vi.fn().mockResolvedValue(MISSING),
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue(IDLE),
      updateDatabases: vi.fn().mockRejectedValue(new Error('dial tcp: no route to host')),
    });

    await userEvent.click(await screen.findByRole('button', { name: /download databases/i }));

    await waitFor(() => {
      expect(screen.getByText(/database download failed/i)).toBeInTheDocument();
      expect(screen.getByText(/no route to host/i)).toBeInTheDocument();
    });

    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
  });

  it('can be dismissed and stays dismissed for the session', async () => {
    const api = {
      getDatabaseStatus: vi.fn().mockResolvedValue(MISSING),
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue(IDLE),
      updateDatabases: vi.fn(),
    };

    renderBootstrap(api);

    await userEvent.click(await screen.findByRole('button', { name: /not now/i }));

    await waitFor(() => {
      expect(screen.queryByText(/analysis databases are missing/i)).not.toBeInTheDocument();
    });

    expect(sessionStorage.getItem('netcap.dbBootstrap.dismissed')).toBe('1');
  });

  it('clears the prompt once the databases are installed', async () => {
    const getDatabaseStatus = vi
      .fn()
      .mockResolvedValueOnce(MISSING)
      .mockResolvedValue(SATISFIED);

    renderBootstrap({
      getDatabaseStatus,
      getDatabaseDownloadProgress: vi.fn().mockResolvedValue({
        state: 'completed',
        stage: 'completed',
        downloaded: 91_021_882,
        total: 91_021_882,
        percent: 100,
        message: 'Databases installed',
      }),
      updateDatabases: vi.fn().mockResolvedValue({
        success: true,
        started: true,
        message: 'Database download started',
        download: { state: 'running', stage: 'download', downloaded: 0, total: 91_021_882, percent: 0 },
      }),
    });

    await userEvent.click(await screen.findByRole('button', { name: /download databases/i }));

    await waitFor(
      () => {
        expect(screen.queryByText(/analysis databases/i)).not.toBeInTheDocument();
      },
      { timeout: 4000 },
    );

    expect(getDatabaseStatus.mock.calls.length).toBeGreaterThan(1);
  });
});
