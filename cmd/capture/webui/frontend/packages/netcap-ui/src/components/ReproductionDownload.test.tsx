import { cleanup, render, screen, waitFor, fireEvent } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ReproductionDownload from './ReproductionDownload';

const { request } = vi.hoisted(() => ({ request: vi.fn() }));
const host = vi.hoisted(() => ({ saveJSON: undefined as undefined | ReturnType<typeof vi.fn> }));
vi.mock('../providers', () => ({ useNetcapConfig: () => ({ apiBaseUrl: '/api', fetch: request, saveJSON: host.saveJSON }) }));
const createURL = URL.createObjectURL, revokeURL = URL.revokeObjectURL;
beforeEach(() => {
  request.mockReset();
  host.saveJSON = undefined;
  URL.createObjectURL = vi.fn().mockReturnValue('blob:owned');
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); URL.createObjectURL = createURL; URL.revokeObjectURL = revokeURL; });

describe('reproduction metadata download', () => {
  it('awaits native saves and surfaces write failures without a browser fallback', async () => {
    const bundle = { schema: 'netcap-reproduction-metadata/v1', state: 'metadata-only' };
    request.mockResolvedValue({ ok: true, json: async () => bundle });
    host.saveJSON = vi.fn().mockRejectedValue(new Error('Native save failed'));
    render(<ReproductionDownload selection={{ inputFile: '/owned.pcap' }} />);
    fireEvent.click(screen.getByRole('button', { name: 'Download reproduction metadata' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Native save failed');
    expect(host.saveJSON).toHaveBeenCalledWith('netcap-reproduction-metadata.json', bundle);
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
  it('never falls back to an active capture when the row has no identity', async () => {
    render(<ReproductionDownload selection={{}} />);
    fireEvent.click(screen.getByRole('button', { name: 'Download reproduction metadata' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Select a capture');
    expect(request).not.toHaveBeenCalled();
  });
  it('exports only the selected capture and releases its download URL', async () => {
    request.mockResolvedValue({ ok: true, json: async () => ({ schema: 'netcap-reproduction-metadata/v1', state: 'metadata-only', attachments: [{ state: 'missing' }] }) });
    render(<ReproductionDownload selection={{ sessionId: 'owned', runId: 'generation' }} />);
    fireEvent.click(screen.getByRole('button', { name: 'Download reproduction metadata' }));
    await waitFor(() => expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:owned'));
    expect(request).toHaveBeenCalledWith('/api/investigation/reproduction?sessionId=owned&runId=generation');
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalledOnce();
  });
  it('surfaces rejected attachment fetches without downloading an empty success', async () => {
    request.mockResolvedValue({ ok: false, status: 403 });
    render(<ReproductionDownload selection={{ sessionId: 'denied' }} />);
    fireEvent.click(screen.getByRole('button', { name: 'Download reproduction metadata' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('HTTP 403');
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
  it('rejects a successful but unsupported backend response', async () => {
    request.mockResolvedValue({ ok: true, json: async () => ({}) });
    render(<ReproductionDownload selection={{ inputFile: '/owned.pcap' }} />);
    fireEvent.click(screen.getByRole('button', { name: 'Download reproduction metadata' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unsupported reproduction metadata response');
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});
