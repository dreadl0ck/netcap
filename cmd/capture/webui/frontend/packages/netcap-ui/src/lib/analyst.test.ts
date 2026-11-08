import { describe, expect, it, vi } from 'vitest';
import { analystRequest, resolveOccurrence, type AnalystSource, type OccurrenceReference } from './analyst';

const binding = { runId: 'owned', sourceSHA256: 'a'.repeat(64), manifestSHA256: 'b'.repeat(64) };
const reference: OccurrenceReference = { version: 1, binding, type: 'Connection', file: 'Connection.ncap.gz', fileSHA256: 'c'.repeat(64), ordinal: '9001', recordSHA256: 'd'.repeat(64), timestampNs: '1700000000000000001' };

describe('content-bound analyst client', () => {
  it('does not start or continue a canceled operation even when an adapter ignores abort', async () => {
    const canceled = new AbortController(); canceled.abort(); const unused = vi.fn();
    await expect(analystRequest(unused, '/api', 'capabilities', undefined, canceled.signal)).rejects.toThrow('aborted');
    expect(unused).not.toHaveBeenCalled();
    const late = new AbortController();
    const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => { late.abort(); return { version: 1 }; } });
    await expect(analystRequest(fetcher, '/api', 'capabilities', undefined, late.signal)).rejects.toThrow('aborted');
  });
  it('preserves every source/file/frame component, exact strings and cancellation signal', async () => {
    const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ version: 1, reference }) });
    const source: AnalystSource = { inputFile: '/owned.pcap', binding: { manifestSHA256: binding.manifestSHA256, runId: binding.runId, sourceSHA256: binding.sourceSHA256 } };
    const controller = new AbortController();
    await resolveOccurrence(fetcher, '/api', source, reference, controller.signal);
    const [path, init] = fetcher.mock.calls[0];
    expect(path).toBe('/api/analyst/resolve');
    expect(JSON.parse(init.body)).toEqual({ source, reference });
    expect(init.signal).toBe(controller.signal);
  });
  it('never rebinds stale or missing source identities', async () => {
    const fetcher = vi.fn();
    await expect(resolveOccurrence(fetcher, '/api', { inputFile: '/owned.pcap', binding: { ...binding, runId: 'other' } }, reference)).rejects.toThrow('conflict');
    await expect(resolveOccurrence(fetcher, '/api', { binding }, reference)).rejects.toThrow('Explicit occurrence source');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('surfaces stale/rejected capabilities without falling back to another endpoint', async () => {
    const fetcher = vi.fn().mockResolvedValue({ ok: false, status: 409, text: async () => 'stale binding' });
    await expect(resolveOccurrence(fetcher, '/api', { sessionId: 'owned', binding }, reference)).rejects.toThrow('HTTP 409');
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('keeps the entire explicit novelty baseline in catalogue requests', async () => {
    const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ version: 1, snapshotSHA256: 'e'.repeat(64), totalOccurrences: 0, sources: [], coverage: [], occurrences: [], limitations: [] }) });
    const sources = [{ inputFile: '/a.pcap', binding }, { sessionId: 'baseline', binding: { ...binding, runId: 'baseline' } }];
    await analystRequest(fetcher, '/api', 'catalogue', { sources, query: { kind: 'domain', value: 'example.test', types: ['DNS'] } });
    expect(JSON.parse(fetcher.mock.calls[0][1].body).sources).toEqual(sources);
  });
  it('rejects an HTTP 200 that has no supported analyst contract', async () => {
    const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    await expect(analystRequest(fetcher, '/api', 'catalogue', {})).rejects.toThrow('Unsupported or malformed');
  });
});
