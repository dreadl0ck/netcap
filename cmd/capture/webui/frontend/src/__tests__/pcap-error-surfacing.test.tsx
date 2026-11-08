/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * Regression cover for the reported desktop failure: analysing a PCAP failed,
 * the UI offered nothing but "retry", and the helper's actual message was
 * unreachable. The crash-log button was gated on `status.isServiceMode &&
 * file.sessionId`, and the desktop app is always local mode with no session.
 */

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { NetcapProvider } from '@dreadl0ck/netcap-ui/providers';
import { CommunityIDFilterProvider, LearnModeProvider } from '@dreadl0ck/netcap-ui/contexts';
import { PcapsPage } from '@dreadl0ck/netcap-ui/pages';
import type { FileInfo } from '@dreadl0ck/netcap-ui';
import { SWRConfig } from 'swr';

const FAILED_FILE: FileInfo = {
  id: 'abc123hash',
  name: 'capture.pcap',
  path: 'C:\\Users\\x\\.config\\netcap-pro\\pcaps\\capture.pcap',
  size: 4096,
  modifiedTime: 1_700_000_000,
  isCompleted: false,
  error: 'Analysis failed: exit status 1 — geolocation database not found: GeoLite2-City.mmdb',
  errorLogId: 'abc123hash',
};

const LOCAL_MODE_STATUS = {
  isProcessing: false,
  outputDir: '/tmp/out',
  inputFiles: [FAILED_FILE.path],
  serverStarted: '',
  activeInputFile: '',
  isMultiFile: false,
  isLiveMode: false,
  // The desktop app. Service mode is the hosted "try" deployment.
  isServiceMode: false,
};

function renderPcaps(overrides: Record<string, unknown> = {}, fetcher?: typeof fetch) {
  const getErrorLogContent = vi.fn().mockResolvedValue(
    'geolocation database not found: GeoLite2-City.mmdb\n',
  );

  const api = {
    getInputFiles: vi.fn().mockResolvedValue([FAILED_FILE]),
    getStatus: vi.fn().mockResolvedValue(LOCAL_MODE_STATUS),
    getProgress: vi.fn().mockResolvedValue({
      sessionId: FAILED_FILE.id,
      status: 'failed',
      progressPercent: 0,
      message: 'Analysis failed',
    }),
    getErrorLogContent,
    ...overrides,
  };

  // NetcapProvider directly rather than the React Router adapter: the adapter
  // exposes no `api` override, and this needs one to drive the page without a
  // live backend.
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
    <NetcapProvider
      config={{
        backendUrl: 'http://127.0.0.1:1234',
        fetch: fetcher,
        api: api as never,
        router: {
          pathname: '/pcaps',
          query: {},
          isReady: true,
          push: () => {},
          replace: () => {},
        },
        Link: ({ href, children }) => <a href={href}>{children}</a>,
      }}
    >
      <LearnModeProvider>
        <CommunityIDFilterProvider>
          <PcapsPage />
        </CommunityIDFilterProvider>
      </LearnModeProvider>
    </NetcapProvider>
    </SWRConfig>,
  );

  return { getErrorLogContent, api };
}

describe('PCAPs page error surfacing in local mode', () => {
  it('shows the failure message returned by the backend', async () => {
    renderPcaps();

    await waitFor(() => {
      expect(screen.getAllByText(FAILED_FILE.error!).length).toBeGreaterThan(0);
    });
  });

  it('renders a button to read the analysis log', async () => {
    renderPcaps();

    // This is the button that did not exist. Its absence is why a user could
    // only see "restart capture" and had no way to learn the cause.
    await waitFor(() => {
      expect(screen.getAllByLabelText(/view analysis log/i).length).toBeGreaterThan(0);
    });
  });

  // getAllBy: the responsive view renders a table and a card variant, so a
  // control legitimately appears more than once in jsdom.
  it('still offers a retry alongside it', async () => {
    renderPcaps();

    await waitFor(() => {
      expect(screen.getAllByLabelText(/retry analysis/i).length).toBeGreaterThan(0);
    });
  });

  it('fetches the log by errorLogId, which local mode sets and sessionId does not', async () => {
    const { getErrorLogContent } = renderPcaps();

    const [button] = await screen.findAllByLabelText(/view analysis log/i);
    await userEvent.click(button);

    await waitFor(() => {
      expect(getErrorLogContent).toHaveBeenCalledWith(FAILED_FILE.errorLogId);
    });
  });

  it('shows the log contents in the dialog once loaded', async () => {
    renderPcaps();

    const [button] = await screen.findAllByLabelText(/view analysis log/i);
    await userEvent.click(button);

    // Scoped to the dialog: the row's own error text also mentions the
    // database, so an unscoped query passes without proving the log loaded.
    await waitFor(() => {
      const dialog = screen.getByRole('dialog');
      expect(
        within(dialog).getByText(/geolocation database not found/i),
      ).toBeInTheDocument();
    });
  });

  it('falls back to the file id when a backend predates errorLogId', async () => {
    const withoutErrorLogId = { ...FAILED_FILE, errorLogId: undefined };
    const { getErrorLogContent } = renderPcaps({
      getInputFiles: vi.fn().mockResolvedValue([withoutErrorLogId]),
    });

    const [button] = await screen.findAllByLabelText(/view analysis log/i);
    await userEvent.click(button);

    await waitFor(() => {
      expect(getErrorLogContent).toHaveBeenCalledWith(FAILED_FILE.id);
    });
  });
});

describe('PCAP child analysis', () => {
  it('does not reselect the child row when its Parent action is clicked', async () => {
    const parent = { ...FAILED_FILE, isCompleted: true, error: undefined };
    const child = { ...parent, id: 'analysis-child', name: 'selected.pcapng', path: '/analysis-child/source/selected.pcapng', parentInputFile: parent.path };
    let active = child.path;
    const setActiveDirectory = vi.fn(async (path: string) => { active = path; return { success: true, outputDir: '/owned' }; });
    renderPcaps({
      getInputFiles: vi.fn(async () => [parent, child]), setActiveDirectory,
      getStatus: vi.fn(async () => ({ ...LOCAL_MODE_STATUS, activeInputFile: active, isMultiFile: true, childAnalysisVersion: 1 })),
    });
    const childRow = await screen.findByRole('row', { name: /selected.pcapng/ });
    await waitFor(() => expect(within(childRow).getByLabelText('Currently viewing', { exact: true })).toBeInTheDocument());
    await userEvent.click(within(childRow).getByRole('button', { name: 'Parent' }));
    await waitFor(() => expect(setActiveDirectory).toHaveBeenCalledExactlyOnceWith(parent.path));
    expect(active).toBe(parent.path);
  });

  async function openDialog() {
    await userEvent.click((await screen.findAllByRole('button', { name: /retry analysis/i }))[0]);
    return screen.findByRole('dialog');
  }

  it('refuses reanalysis against a backend without the child-analysis contract', async () => {
    const reanalyzeFile = vi.fn();
    renderPcaps({ reanalyzeFile });
    const dialog = await openDialog();
    expect(within(dialog).getByText(/does not advertise version 1/)).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Reanalyze' })).toBeDisabled();
    expect(reanalyzeFile).not.toHaveBeenCalled();
  });

  it('binds subset requests to the parent generation and preserves nanosecond strings', async () => {
    const reanalyzeFile = vi.fn().mockResolvedValue({ success: true, sessionId: 'analysis-child' });
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ runId: 'generation-parent', inputSHA256: 'a'.repeat(64) })));
    renderPcaps({ getStatus: vi.fn().mockResolvedValue({ ...LOCAL_MODE_STATUS, childAnalysisVersion: 1 }), reanalyzeFile }, fetcher);
    const dialog = await openDialog();
    const user = userEvent.setup();
    await user.click(within(dialog).getByRole('combobox', { name: 'Analysis scope' }));
    await user.click(screen.getByRole('option', { name: 'Selected packets' }));
    for (const [label, value] of [['Packet selection BPF', 'tcp port 9243'], ['Start time (inclusive nanoseconds)', '1700000000000000001'], ['End time (inclusive nanoseconds)', '1700000000000000002']]) {
      await user.click(within(dialog).getByLabelText(label));
      await user.paste(value);
    }
    await user.click(within(dialog).getByRole('button', { name: 'Reanalyze' }));
    await waitFor(() => expect(reanalyzeFile).toHaveBeenCalledWith(FAILED_FILE.path, undefined, {
      runId: 'generation-parent', selection: { version: 1, sourceSHA256: 'a'.repeat(64), bpf: 'tcp port 9243',
        startNs: '1700000000000000001', endNs: '1700000000000000002' },
    }));
    expect(new URL(fetcher.mock.calls[0][0]).searchParams.get('inputFile')).toBe(FAILED_FILE.path);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getAllByText(FAILED_FILE.error!).length).toBeGreaterThan(0);
  });

  it('retains the dialog and parent evidence when preparation is rejected', async () => {
    const reanalyzeFile = vi.fn().mockRejectedValue(new Error('Capture generation is stale'));
    renderPcaps({ getStatus: vi.fn().mockResolvedValue({ ...LOCAL_MODE_STATUS, childAnalysisVersion: 1 }), reanalyzeFile });
    const dialog = await openDialog();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reanalyze' }));
    expect(await within(dialog).findByText('Capture generation is stale')).toBeInTheDocument();
    expect(screen.getAllByText(FAILED_FILE.error!).length).toBeGreaterThan(0);
    expect(within(dialog).getByRole('button', { name: 'Reanalyze' })).toBeEnabled();
  });
});
