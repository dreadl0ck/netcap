export interface CaptureBinding { runId: string; sourceSHA256: string; manifestSHA256: string }
export function sameBinding(a: CaptureBinding, b: CaptureBinding) { return a.runId === b.runId && a.sourceSHA256 === b.sourceSHA256 && a.manifestSHA256 === b.manifestSHA256; }
export interface AnalystSource { sessionId?: string; inputFile?: string; binding: CaptureBinding }
export interface OccurrenceReference { version: number; binding: CaptureBinding; type: string; file: string; fileSHA256: string; ordinal: string; recordSHA256: string; timestampNs: string }
export interface AnalystQuery { kind: string; value: string; types: string[] }
export interface AnalystOccurrence { sourceId: string; reference: OccurrenceReference; fields: string[]; endpoints: string[] }
export interface CatalogueResult { version: number; snapshotSHA256: string; totalOccurrences: number; nextOffset?: number; query: AnalystQuery; sources: { id: string; binding: CaptureBinding }[]; coverage: { sourceId: string; type: string; state: string; records: number }[]; occurrences: AnalystOccurrence[]; novelty: string; limitations: string[] }
export interface AnalystDocument { id: string; revision: number; kind: string; title: string; body: string; binding: CaptureBinding; includedSources: AnalystSource[]; catalogueSnapshotSHA256?: string; query?: AnalystQuery; references: OccurrenceReference[]; review: string; reviewer?: string; updatedAt: string }
export async function analystRequest<T>(fetcher: typeof fetch, base: string, endpoint: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  if (signal?.aborted) throw new DOMException('Analyst request aborted', 'AbortError');
  const response = await fetcher(`${base}/analyst/${endpoint}`, body === undefined ? { signal } : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal });
  if (!response.ok) throw new Error(`Analyst request failed (HTTP ${response.status}): ${await response.text()}`);
  const payload = await response.json();
  if (signal?.aborted) throw new DOMException('Analyst request aborted', 'AbortError');
  const name = endpoint.split('?')[0];
  const object = payload && typeof payload === 'object';
  let valid = Boolean(object);
  if (['capabilities', 'catalogue', 'occurrences', 'resolve', 'inspect'].includes(name)) valid = valid && payload.version === 1;
  if (name === 'binding') valid = valid && typeof payload.runId === 'string' && typeof payload.sourceSHA256 === 'string' && typeof payload.manifestSHA256 === 'string';
  if (name === 'catalogue') valid = valid && /^[a-f0-9]{64}$/.test(payload.snapshotSHA256) && Number.isSafeInteger(payload.totalOccurrences) && Array.isArray(payload.sources) && Array.isArray(payload.coverage) && Array.isArray(payload.limitations) && Array.isArray(payload.occurrences) && payload.totalOccurrences >= payload.occurrences.length && payload.occurrences.every((item: AnalystOccurrence) => item?.reference?.version === 1 && /^-?\d{1,19}$/.test(item.reference.timestampNs));
  if (name === 'workspace') valid = valid && (Array.isArray(payload.documents) ? payload.version === 1 : typeof payload.id === 'string' && Number.isSafeInteger(payload.revision) && payload.revision > 0);
  if (!valid) throw new Error('Unsupported or malformed analyst response.');
  return payload as T;
}

export async function resolveOccurrence(fetcher: typeof fetch, base: string, source: AnalystSource, reference: OccurrenceReference, signal?: AbortSignal) {
  if (!source.sessionId && !source.inputFile) throw new Error('Explicit occurrence source is required.');
  if (reference.version !== 1 || !sameBinding(source.binding, reference.binding)) throw new Error('Occurrence/source binding conflict.');
  return analystRequest<{ version: number; reference: OccurrenceReference; record: Record<string, unknown> }>(fetcher, base, 'resolve', { source, reference }, signal);
}
