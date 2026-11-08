import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, Checkbox, FormControlLabel, MenuItem, Paper, Stack, TextField, Typography } from '@mui/material';
import { useNetcapConfig } from '../providers';
import ReproductionDownload from './ReproductionDownload';
import OccurrenceViews from './OccurrenceViews';
import { analystRequest, resolveOccurrence, type AnalystSource, type AnalystQuery, type CatalogueResult, type AnalystOccurrence, type AnalystDocument, type CaptureBinding } from '../lib/analyst';

interface FileChoice { id?: string; sessionId?: string; path: string; name: string; isCompleted?: boolean }
export default function AnalystWorkbench({ files, serviceMode = false }: { files: FileChoice[]; serviceMode?: boolean }) {
  const config = useNetcapConfig(), fetcher = config.fetch ?? fetch;
  const [included, setIncluded] = useState<string[]>([]), [kind, setKind] = useState('endpoint'), [value, setValue] = useState(''), [types, setTypes] = useState('Connection');
  const [sources, setSources] = useState<AnalystSource[]>([]), [result, setResult] = useState<CatalogueResult | null>(null);
  const [selected, setSelected] = useState<AnalystOccurrence | null>(null), [record, setRecord] = useState<unknown>(null), [inspection, setInspection] = useState<unknown>(null);
  const [docs, setDocs] = useState<AnalystDocument[]>([]), [editing, setEditing] = useState<AnalystDocument | null>(null), [docKind, setDocKind] = useState('query');
  const [title, setTitle] = useState(''), [body, setBody] = useState(''), [reviewer, setReviewer] = useState('');
  const [logFile, setLogFile] = useState(''), [logStart, setLogStart] = useState('1'), [logEnd, setLogEnd] = useState('10'), [logPreview, setLogPreview] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState(''), [busy, setBusy] = useState(false), [enabled, setEnabled] = useState(false);
  const [approvedLog, setApprovedLog] = useState(false);
  const operation = useRef<AbortController | null>(null);
  useEffect(() => () => operation.current?.abort(), []);
  const clear = () => { operation.current?.abort(); setResult(null); setSources([]); setSelected(null); setRecord(null); setDocs([]); setEditing(null); setLogPreview(null); setInspection(null); setApprovedLog(false); };
  const run = async (action: (signal: AbortSignal) => Promise<void>) => {
    operation.current?.abort(); const controller = new AbortController(); operation.current = controller; setBusy(true); setError('');
    try {
      const caps = await analystRequest<Record<string, number>>(fetcher, config.apiBaseUrl, 'capabilities', undefined, controller.signal);
      if (['version', 'occurrenceVersion', 'catalogueVersion', 'workspaceVersion', 'reviewedLogVersion', 'inspectionVersion'].some(key => caps[key] !== 1)) throw new Error('This backend does not support the complete analyst workspace contract.');
      setEnabled(true); await action(controller.signal);
    } catch (failure) { if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : 'Analyst operation failed.'); }
    finally { if (operation.current === controller) setBusy(false); }
  };
  const bind = async (signal: AbortSignal, diagnostic = false) => {
    if (!included.length || included.length > 8) throw new Error('Explicitly include 1–8 captures. First included capture is the target.');
    const next: AnalystSource[] = [];
    for (const path of included) {
      const file = files.find(file => file.path === path); if (!file) throw new Error('Included capture is no longer registered.');
      const selector = serviceMode ? { sessionId: file.sessionId || file.id } : { inputFile: file.path };
      if (!selector.sessionId && !selector.inputFile) throw new Error('Capture identity unavailable.');
      const params = new URLSearchParams(); Object.entries(selector).forEach(([key, val]) => { if (val) params.set(key, val); });
      if (diagnostic) params.set('diagnostic', 'true');
      const binding = await analystRequest<CaptureBinding>(fetcher, config.apiBaseUrl, `binding?${params}`, undefined, signal);
      next.push({ ...selector, binding });
    }
    if (!signal.aborted) setSources(next); return next;
  };
  const loadDocs = async (source: AnalystSource, signal: AbortSignal) => {
    const workspace = await analystRequest<{ documents: AnalystDocument[] }>(fetcher, config.apiBaseUrl, 'workspace', { source, expectedRevision: 0 }, signal);
    if (!signal.aborted) setDocs(workspace.documents);
  };
  const query = (): AnalystQuery => ({ kind, value, types: types.split(',').map(type => type.trim()).filter(Boolean) });
  const search = () => run(async signal => {
    const next = await bind(signal); const data = await analystRequest<CatalogueResult>(fetcher, config.apiBaseUrl, 'catalogue', { sources: next, query: query() }, signal);
    if (!signal.aborted) { setResult(data); setSelected(null); setRecord(null); }
  });
  const inspectOccurrence = (item: AnalystOccurrence) => run(async signal => {
    const source = sources.find(source => source.binding.runId === item.sourceId); if (!source) throw new Error('Occurrence source not included.');
    const data = await resolveOccurrence(fetcher, config.apiBaseUrl, source, item.reference, signal);
    if (!signal.aborted) { setSelected(item); setRecord(data); }
  });
  const save = () => run(async signal => {
    if (!sources[0]) throw new Error('Run a source-bound query or load the workspace first.');
    if (selected && selected.sourceId !== sources[0].binding.runId) throw new Error('Select a primary-capture occurrence before saving this capture-local report.');
    if (docKind === 'query' && (!result || JSON.stringify(result.query) !== JSON.stringify(query()))) throw new Error('Run this exact included query before saving its snapshot.');
    const document: AnalystDocument = { id: editing?.id ?? '', revision: editing?.revision ?? 0, kind: docKind, title, body, binding: sources[0].binding, includedSources: sources,
      ...(docKind === 'query' ? { query: query(), catalogueSnapshotSHA256: result!.snapshotSHA256 } : {}), references: selected && selected.sourceId === sources[0].binding.runId ? [selected.reference] : [], review: 'draft', updatedAt: '' };
    const saved = await analystRequest<AnalystDocument>(fetcher, config.apiBaseUrl, 'workspace', { source: sources[0], document, expectedRevision: editing?.revision ?? 0 }, signal);
    if (!signal.aborted) setEditing(saved); await loadDocs(sources[0], signal);
  });
  const review = () => run(async signal => {
    if (!editing || !sources[0]) throw new Error('Load a persisted document before review.');
    if (title !== editing.title || body !== editing.body) throw new Error('Save changed content as draft before review.');
    const saved = await analystRequest<AnalystDocument>(fetcher, config.apiBaseUrl, 'workspace', { source: sources[0], document: { ...editing, review: 'reviewed', reviewer }, expectedRevision: editing.revision }, signal);
    if (!signal.aborted) setEditing(saved); await loadDocs(sources[0], signal);
  });
  return <Paper sx={{ p: 2 }}><Stack spacing={2}>
    <Typography variant="h6">Bound analyst workspace</Typography>
    <Alert severity="info">Explicit capture inclusion only. First checked capture is the target; later captures form the novelty baseline. Results describe retained records, not global rarity or complete traffic.</Alert>
    {files.map(file => <FormControlLabel key={file.path} control={<Checkbox checked={included.includes(file.path)} disabled={busy} onChange={event => { clear(); setIncluded(event.target.checked ? [...included, file.path] : included.filter(path => path !== file.path)); }} />} label={`${file.name}${included[0] === file.path ? ' (target)' : ''}`} />)}
    <Stack direction={{ xs: 'column', md: 'row' }} spacing={1}>
      <TextField select label="Catalogue kind" value={kind} onChange={e => setKind(e.target.value)}>{['endpoint', 'domain', 'sha256', 'text'].map(k => <MenuItem key={k} value={k}>{k}</MenuItem>)}</TextField>
      <TextField label="Exact indicator / selected text" value={value} onChange={e => setValue(e.target.value)} />
      <TextField label="Included audit types (comma separated)" value={types} onChange={e => setTypes(e.target.value)} />
      <Button disabled={busy} onClick={search}>Search included captures</Button>
      <Button disabled={busy} onClick={() => run(async signal => { const next = await bind(signal); await loadDocs(next[0], signal); })}>Load saved workspace</Button>
      <Button disabled={busy} onClick={() => run(async signal => { const next = await bind(signal); const data = await analystRequest(fetcher, config.apiBaseUrl, 'inspect', { source: next[0] }, signal); if (!signal.aborted) setInspection(data); })}>Inspect original capture</Button>
      <Button disabled={!busy} onClick={() => { operation.current?.abort(); setBusy(false); }}>Cancel analyst operation</Button>
    </Stack>
    {error && <Alert severity="error">{error}</Alert>}
    {inspection !== null && <Box component="pre" sx={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(inspection, null, 2)}</Box>}
    {result && <>
      <Typography>Novelty: {result.novelty} · {result.occurrences.length} retained occurrences</Typography>
      {result.limitations.map((text, i) => <Typography variant="caption" key={i}>{text}</Typography>)}
      <details><summary>Catalogue source inclusion and coverage</summary><pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify({ sources: result.sources, coverage: result.coverage }, null, 2)}</pre></details>
      <OccurrenceViews result={result} busy={busy} resolve={inspectOccurrence} />
    </>}
    {record !== null && <><Typography>Verified occurrence (record preview capped at 40,000 characters; reference remains exact)</Typography><Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(record, null, 2).slice(0, 40000)}</Box></>}
    <Typography variant="h6">Saved queries and analyst-reviewed reports</Typography>
    <TextField select label="Document kind" value={docKind} onChange={e => setDocKind(e.target.value)}><MenuItem value="query">query</MenuItem><MenuItem value="report">report</MenuItem></TextField>
    <TextField label="Document title" value={title} onChange={e => setTitle(e.target.value)} />
    <TextField label="Report / query notes" multiline value={body} onChange={e => setBody(e.target.value)} />
    <TextField label="Reviewer" value={reviewer} onChange={e => setReviewer(e.target.value)} />
    <Stack direction="row"><Button disabled={busy || !enabled} onClick={save}>Save draft</Button><Button disabled={busy || !editing} onClick={review}>Mark persisted document reviewed</Button><Button onClick={() => { setEditing(null); setTitle(''); setBody(''); }}>New document</Button></Stack>
    {editing && <Typography>Document revision {editing.revision} · {editing.review}</Typography>}
    {docs.map(doc => <Stack key={doc.id} direction="row"><Button onClick={() => { setEditing(doc); setTitle(doc.title); setBody(doc.body); setDocKind(doc.kind); if (doc.query) { setKind(doc.query.kind); setValue(doc.query.value); setTypes(doc.query.types.join(',')); } }}>{doc.title} · r{doc.revision} · {doc.review}</Button>{doc.query && <Button disabled={busy} onClick={() => run(async signal => { if (!sources[0] || JSON.stringify(sources[0].binding) !== JSON.stringify(doc.binding)) throw new Error('Saved query capture binding changed.'); const data = await analystRequest<CatalogueResult>(fetcher, config.apiBaseUrl, 'catalogue', { sources: doc.includedSources, query: doc.query, expectedSnapshotSHA256: doc.catalogueSnapshotSHA256 }, signal); if (!signal.aborted) { setSources(doc.includedSources); setResult(data); } })}>Rerun saved query with stored binding</Button>}</Stack>)}
    <Typography variant="h6">Review safe diagnostic attachment</Typography>
    <Typography variant="caption">Selected log lines export hashes and fixed diagnostic classes only; raw text is never attached.</Typography>
    <Stack direction="row"><TextField label="Local log basename" value={logFile} onChange={e => { setLogFile(e.target.value); setLogPreview(null); }} /><TextField label="First log line" value={logStart} onChange={e => setLogStart(e.target.value)} /><TextField label="Last log line" value={logEnd} onChange={e => setLogEnd(e.target.value)} /></Stack>
    <Button disabled={busy} onClick={() => run(async signal => { const next = await bind(signal, true); const data = await analystRequest<Record<string, unknown>>(fetcher, config.apiBaseUrl, 'log-review', { source: next[0], file: logFile, start: Number(logStart), end: Number(logEnd) }, signal); if (!signal.aborted) setLogPreview(data); })}>Preview safe log projection</Button>
    {logPreview && <><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(logPreview, null, 2)}</pre><Button disabled={busy} onClick={() => run(async signal => { await analystRequest(fetcher, config.apiBaseUrl, 'log-review', { source: sources[0], file: logFile, start: Number(logStart), end: Number(logEnd), approve: logPreview }, signal); if (!signal.aborted) { setLogPreview(null); setApprovedLog(true); } })}>Approve exact log projection</Button></>}
    {approvedLog && sources[0] && <ReproductionDownload selection={{ sessionId: sources[0].sessionId, inputFile: sources[0].inputFile, runId: sources[0].binding.runId }} reviewedLog />}
  </Stack></Paper>;
}
