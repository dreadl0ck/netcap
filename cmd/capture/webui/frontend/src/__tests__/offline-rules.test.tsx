import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { NetcapProvider } from '../../packages/netcap-ui/src/providers/NetcapProvider';
import OfflineRulesPanel, { OfflineReportView } from '../../packages/netcap-ui/src/components/OfflineRulesPanel';
import { OfflineApiError, type OfflineReport, type StatusResponse } from '../../packages/netcap-ui/src/lib/api';

const pack = { format: 'netcap-offline-rules/v1', rules: [{ id: 'fixture', name: 'Fixture', type: 'TCP', expression: 'DstPort == 443', enabled: true, severity: 'medium', threshold: { count: 2, window: '60s', groupBy: ['SrcIP'] } }] };
function setup(options: { invalid?: boolean; report?: OfflineReport; unavailable?: boolean; disabled?: boolean } = {}) {
  const executeOfflinePack = vi.fn().mockResolvedValue({ report: options.report || { status: 'complete', committedAlerts: '0' } });
  const validateOfflinePack = vi.fn().mockResolvedValue(options.invalid ? { valid: false, errors: [{ field: 'yaml', message: 'invalid threshold' }] } : { valid: true, errors: [], pack: options.disabled ? { ...pack, rules: pack.rules.map(rule => ({ ...rule, enabled: false })) } : pack });
  const api = {
    getOfflinePacks: vi.fn().mockImplementation(() => options.unavailable ? Promise.reject(new OfflineApiError('Not found', 404)) : Promise.resolve({ packs: [{ name: 'Fixture pack', yaml: 'fixture-yaml' }] })),
    getOfflineEvaluations: vi.fn().mockResolvedValue({ evaluations: [] }), validateOfflinePack, executeOfflinePack,
  };
  render(<NetcapProvider config={{ backendUrl: 'http://localhost', api: api as never,
    router: { pathname: '/rules', query: {}, isReady: true, push: vi.fn(), replace: vi.fn() },
    Link: ({ href, children }) => <a href={href}>{children}</a>,
  }}><OfflineRulesPanel status={{ activeInputFile: '/fixture.pcap', outputDir: '/fixture', isProcessing: false, isLiveMode: false } as StatusResponse} /></NetcapProvider>);
  return { executeOfflinePack, validateOfflinePack };
}

describe('offline rules panel', () => {
  it.each(['0', '1', '2', '9007199254740993'])('renders decimal-string alert count %s without losing precision', committedAlerts => {
    render(<OfflineReportView report={{ status: 'complete', committedAlerts }} />);
    expect(screen.getByText(`${committedAlerts} alert${committedAlerts === '1' ? '' : 's'} committed`)).toBeInTheDocument();
  });
  it('keeps validation failure separate from an empty completed execution', async () => {
    const calls = setup({ invalid: true }); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Fixture pack' }));
    await user.click(screen.getByRole('button', { name: 'Validate pack' }));
    expect(await screen.findByText(/Validation failed: yaml: invalid threshold/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Evaluate capture' })).toBeDisabled();
    expect(calls.executeOfflinePack).not.toHaveBeenCalled();
    expect(screen.queryByText('Offline evaluation completed')).not.toBeInTheDocument();
  });
  it('executes validated YAML with the frozen capture selector and displays zero-alert completion', async () => {
    const calls = setup(); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Fixture pack' }));
    await user.click(screen.getByRole('button', { name: 'Validate pack' }));
    await screen.findByText(/Pack validated. Ready/);
    await user.click(screen.getByRole('button', { name: 'Evaluate capture' }));
    expect(await screen.findByText('Offline evaluation completed')).toBeInTheDocument();
    expect(screen.getByText('0 alerts committed')).toBeInTheDocument();
    expect(calls.executeOfflinePack).toHaveBeenCalledWith('fixture-yaml', { inputFile: '/fixture.pcap' }, expect.any(AbortSignal));
  });
  it('makes partial coverage visible instead of calling it completed', async () => {
    setup({ report: { status: 'partial', error: 'record limit reached', limits: { records: 2 } } }); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Fixture pack' }));
    await user.click(screen.getByRole('button', { name: 'Validate pack' }));
    await screen.findByText(/Pack validated. Ready/);
    await user.click(screen.getByRole('button', { name: 'Evaluate capture' }));
    expect(await screen.findByText(/Incomplete offline evaluation: partial/)).toBeInTheDocument();
    expect(screen.getByText(/record limit reached/)).toBeInTheDocument();
    expect(screen.queryByText('Offline evaluation completed')).not.toBeInTheDocument();
  });
  it('does not fall back to legacy execution when capability returns 404', async () => {
    const calls = setup({ unavailable: true });
    expect(await screen.findByText(/unavailable on this backend/)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Evaluate capture' })).not.toBeInTheDocument());
    expect(calls.executeOfflinePack).not.toHaveBeenCalled();
  });
  it('explains the disabled example and prevents a no-op default execution', async () => {
    const calls = setup({ disabled: true }); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Fixture pack' }));
    await user.click(screen.getByRole('button', { name: 'Validate pack' }));
    expect(await screen.findByText(/all rules are disabled/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Evaluate capture' })).toBeDisabled();
    expect(calls.executeOfflinePack).not.toHaveBeenCalled();
  });
});
