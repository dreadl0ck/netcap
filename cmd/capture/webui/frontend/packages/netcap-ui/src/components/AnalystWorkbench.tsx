import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, Checkbox, FormControlLabel, MenuItem, Paper, Stack, TextField, Typography } from '@mui/material';
import { useNetcapConfig } from '../providers';
import ReproductionDownload from './ReproductionDownload';
import OccurrenceViews from './OccurrenceViews';
import { analystRequest, resolveOccurrence, type AnalystSource, type AnalystQuery, type CatalogueResult, type AnalystOccurrence, type AnalystDocument, type CaptureBinding } from '../lib/analyst';
import { message as i18nMessage, translate as i18nText, renderText as i18nRenderText, richText as i18nRichText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { message, displayError } from "../lib/i18n";
import { errorText } from "../lib/i18n";
import { translate as finalCopyText } from "../lib/i18n";





interface FileChoice { id?: string; sessionId?: string; path: string; name: string; isCompleted?: boolean }
export default function AnalystWorkbench({ files, serviceMode = false }: { files: FileChoice[]; serviceMode?: boolean }) {
  const __uiLocale = useUILocale();
  const config = useNetcapConfig(), fetcher = config.fetch ?? fetch;
  const [included, setIncluded] = useState<string[]>([]), [kind, setKind] = useState('endpoint'), [value, setValue] = useState(''), [types, setTypes] = useState('Connection');
  const [sources, setSources] = useState<AnalystSource[]>([]), [result, setResult] = useState<CatalogueResult | null>(null);
  const [selected, setSelected] = useState<AnalystOccurrence | null>(null), [record, setRecord] = useState<unknown>(null), [inspection, setInspection] = useState<unknown>(null);
  const [docs, setDocs] = useState<AnalystDocument[]>([]), [editing, setEditing] = useState<AnalystDocument | null>(null), [docKind, setDocKind] = useState('query');
  const [title, setTitle] = useState(''), [body, setBody] = useState(''), [reviewer, setReviewer] = useState('');
  const [logFile, setLogFile] = useState(''), [logStart, setLogStart] = useState('1'), [logEnd, setLogEnd] = useState('10'), [logPreview, setLogPreview] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<UIMessageText>(''), [busy, setBusy] = useState(false), [enabled, setEnabled] = useState(false);
  const [approvedLog, setApprovedLog] = useState(false);
  const operation = useRef<AbortController | null>(null);
  useEffect(() => () => operation.current?.abort(), []);
  const clear = () => { operation.current?.abort(); setResult(null); setSources([]); setSelected(null); setRecord(null); setDocs([]); setEditing(null); setLogPreview(null); setInspection(null); setApprovedLog(false); };
  const run = async (action: (signal: AbortSignal) => Promise<void>) => {
    operation.current?.abort(); const controller = new AbortController(); operation.current = controller; setBusy(true); setError('');
    try {
      const caps = await analystRequest<Record<string, number>>(fetcher, config.apiBaseUrl, 'capabilities', undefined, controller.signal);
      if (['version', 'occurrenceVersion', 'catalogueVersion', 'workspaceVersion', 'reviewedLogVersion', 'inspectionVersion'].some(key => caps[key] !== 1)) throw displayError(message("ui:m_9e71f652254421184964"));
      setEnabled(true); await action(controller.signal);
    } catch (failure) { if (!controller.signal.aborted) setError(failure instanceof Error ? errorText(failure) : i18nMessage("ui:m_5b9b569657ec84a3e934")); }
    finally { if (operation.current === controller) setBusy(false); }
  };
  const bind = async (signal: AbortSignal, diagnostic = false) => {
    if (!included.length || included.length > 8) throw displayError(message("ui:m_6e1e51f282e0efeeb1f4"));
    const next: AnalystSource[] = [];
    for (const path of included) {
      const file = files.find(file => file.path === path); if (!file) throw displayError(message("ui:m_6977579a82f6fe1ddf0e"));
      const selector = serviceMode ? { sessionId: file.sessionId || file.id } : { inputFile: file.path };
      if (!selector.sessionId && !selector.inputFile) throw displayError(message("ui:m_c683c399eddacac6d0a2"));
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
    const source = sources.find(source => source.binding.runId === item.sourceId); if (!source) throw displayError(message("ui:m_db096ece95805c6e4061"));
    const data = await resolveOccurrence(fetcher, config.apiBaseUrl, source, item.reference, signal);
    if (!signal.aborted) { setSelected(item); setRecord(data); }
  });
  const save = () => run(async signal => {
    if (!sources[0]) throw displayError(message("ui:m_2904eae6520ca56419f5"));
    if (selected && selected.sourceId !== sources[0].binding.runId) throw displayError(message("ui:m_df4f8a8dc7a034a76d62"));
    if (docKind === 'query' && (!result || JSON.stringify(result.query) !== JSON.stringify(query()))) throw displayError(message("ui:m_e220f28d2ecab83b1d43"));
    const document: AnalystDocument = { id: editing?.id ?? '', revision: editing?.revision ?? 0, kind: docKind, title, body, binding: sources[0].binding, includedSources: sources,
      ...(docKind === 'query' ? { query: query(), catalogueSnapshotSHA256: result!.snapshotSHA256 } : {}), references: selected && selected.sourceId === sources[0].binding.runId ? [selected.reference] : [], review: 'draft', updatedAt: '' };
    const saved = await analystRequest<AnalystDocument>(fetcher, config.apiBaseUrl, 'workspace', { source: sources[0], document, expectedRevision: editing?.revision ?? 0 }, signal);
    if (!signal.aborted) setEditing(saved); await loadDocs(sources[0], signal);
  });
  const review = () => run(async signal => {
    if (!editing || !sources[0]) throw displayError(message("ui:m_545ad615d93423f98ab0"));
    if (title !== editing.title || body !== editing.body) throw displayError(message("ui:m_8ef412d6ba5c6c2924db"));
    const saved = await analystRequest<AnalystDocument>(fetcher, config.apiBaseUrl, 'workspace', { source: sources[0], document: { ...editing, review: 'reviewed', reviewer }, expectedRevision: editing.revision }, signal);
    if (!signal.aborted) setEditing(saved); await loadDocs(sources[0], signal);
  });
  return <Paper sx={{ p: 2 }}><Stack spacing={2}><Typography variant="h6">{i18nText("ui:m_6721ec950ff9fcf5aabb")}</Typography><Alert severity="info">{i18nText("ui:m_e6c53607fd1e3b7348dd")}</Alert>{files.map(file => <FormControlLabel key={file.path} control={<Checkbox checked={included.includes(file.path)} disabled={busy} onChange={event => { clear(); setIncluded(event.target.checked ? [...included, file.path] : included.filter(path => path !== file.path)); }} />} label={`${file.name}${included[0] === file.path ? finalCopyText("ui:m_05ff8c90d6761226c55c") : ''}`} />)}<Stack direction={{ xs: 'column', md: 'row' }} spacing={1}><TextField select label={i18nText("ui:m_e08aa5aaddeb4e742ae2")} value={kind} onChange={e => setKind(e.target.value)}>{['endpoint', 'domain', 'sha256', 'text'].map(k => <MenuItem key={k} value={k}>{i18nText(k)}</MenuItem>)}</TextField><TextField label={i18nText("ui:m_ed0a75bfe553f4c836fd")} value={value} onChange={e => setValue(e.target.value)} /><TextField label={i18nText("ui:m_0f6b9a37bb281b82087d")} value={types} onChange={e => setTypes(e.target.value)} /><Button disabled={busy} onClick={search}>{i18nText("ui:m_14b05d89b7782de97db5")}</Button><Button disabled={busy} onClick={() => run(async signal => { const next = await bind(signal); await loadDocs(next[0], signal); })}>{i18nText("ui:m_71b98121e6abac8f5af2")}</Button><Button disabled={busy} onClick={() => run(async signal => { const next = await bind(signal); const data = await analystRequest(fetcher, config.apiBaseUrl, 'inspect', { source: next[0] }, signal); if (!signal.aborted) setInspection(data); })}>{i18nText("ui:m_23b09b129e289f46fbcf")}</Button><Button disabled={!busy} onClick={() => { operation.current?.abort(); setBusy(false); }}>{i18nText("ui:m_17d46691f950dd140bae")}</Button></Stack>{i18nRenderText(error) && <Alert severity="error">{i18nRenderText(error)}</Alert>}{inspection !== null && <Box component="pre" sx={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(inspection, null, 2)}</Box>}{result && <><Typography>{i18nRichText("ui:m_fe01e169f513a7c884c3", { arg0: result.novelty, arg1: result.occurrences.length })}</Typography>{result.limitations.map((text, i) => <Typography variant="caption" key={i}>{text}</Typography>)}<details><summary>{i18nText("ui:m_77cb37057605270fe134")}</summary><pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify({ sources: result.sources, coverage: result.coverage }, null, 2)}</pre></details><OccurrenceViews result={result} busy={busy} resolve={inspectOccurrence} /></>}{record !== null && <><Typography>{i18nText("ui:m_9c66c467963870605a95")}</Typography><Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(record, null, 2).slice(0, 40000)}</Box></>}<Typography variant="h6">{i18nText("ui:m_c02e2b294bcdf69c3fd4")}</Typography><TextField select label={i18nText("ui:m_ecb81ffd6dce536824fb")} value={docKind} onChange={e => setDocKind(e.target.value)}><MenuItem value="query">{i18nText("ui:m_58148915e4e16abe9e3f")}</MenuItem><MenuItem value="report">{i18nText("ui:m_cc764c6dd6384adc8850")}</MenuItem></TextField><TextField label={i18nText("ui:m_20a153dd52c28075abc7")} value={title} onChange={e => setTitle(e.target.value)} /><TextField label={i18nText("ui:m_becc9fb76f2234b2b8be")} multiline value={body} onChange={e => setBody(e.target.value)} /><TextField label={i18nText("ui:m_4ea4bde1de9f52b7d30e")} value={reviewer} onChange={e => setReviewer(e.target.value)} /><Stack direction="row"><Button disabled={busy || !enabled} onClick={save}>{i18nText("ui:m_92c4b74c7c19a8913fa8")}</Button><Button disabled={busy || !editing} onClick={review}>{i18nText("ui:m_5339e4d98063584f1e6d")}</Button><Button onClick={() => { setEditing(null); setTitle(''); setBody(''); }}>{i18nText("ui:m_89a81d90bab998d3f5ad")}</Button></Stack>{editing && <Typography>{i18nRichText("ui:m_9e1a416c7c8a039cd9a1", { arg0: editing.revision, arg1: editing.review })}</Typography>}{docs.map(doc => <Stack key={doc.id} direction="row"><Button onClick={() => { setEditing(doc); setTitle(doc.title); setBody(doc.body); setDocKind(doc.kind); if (doc.query) { setKind(doc.query.kind); setValue(doc.query.value); setTypes(doc.query.types.join(',')); } }}>{i18nRichText("ui:m_f4a0e5a71e9bfabc9012", { arg0: doc.title, arg1: doc.revision, arg2: doc.review })}</Button>{doc.query && <Button disabled={busy} onClick={() => run(async signal => { if (!sources[0] || JSON.stringify(sources[0].binding) !== JSON.stringify(doc.binding)) throw displayError(message("ui:m_f69dcfbf0f0a69d6b86f")); const data = await analystRequest<CatalogueResult>(fetcher, config.apiBaseUrl, 'catalogue', { sources: doc.includedSources, query: doc.query, expectedSnapshotSHA256: doc.catalogueSnapshotSHA256 }, signal); if (!signal.aborted) { setSources(doc.includedSources); setResult(data); } })}>{i18nText("ui:m_0b70f86c297ee7667e3a")}</Button>}</Stack>)}<Typography variant="h6">{i18nText("ui:m_aae1e10839d0c4b07c35")}</Typography><Typography variant="caption">{i18nText("ui:m_05a00016682f213240b2")}</Typography><Stack direction="row"><TextField label={i18nText("ui:m_19c87cc5e0c48fc181b1")} value={logFile} onChange={e => { setLogFile(e.target.value); setLogPreview(null); }} /><TextField label={i18nText("ui:m_02ca1afc4a14a7b64209")} value={logStart} onChange={e => setLogStart(e.target.value)} /><TextField label={i18nText("ui:m_e434fc5c642a0851ab99")} value={logEnd} onChange={e => setLogEnd(e.target.value)} /></Stack><Button disabled={busy} onClick={() => run(async signal => { const next = await bind(signal, true); const data = await analystRequest<Record<string, unknown>>(fetcher, config.apiBaseUrl, 'log-review', { source: next[0], file: logFile, start: Number(logStart), end: Number(logEnd) }, signal); if (!signal.aborted) setLogPreview(data); })}>{i18nText("ui:m_a67baf1b91b3d6aa83df")}</Button>{logPreview && <><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(logPreview, null, 2)}</pre><Button disabled={busy} onClick={() => run(async signal => { await analystRequest(fetcher, config.apiBaseUrl, 'log-review', { source: sources[0], file: logFile, start: Number(logStart), end: Number(logEnd), approve: logPreview }, signal); if (!signal.aborted) { setLogPreview(null); setApprovedLog(true); } })}>{i18nText("ui:m_5b4bb22fb7ca82ebeb2c")}</Button></>}{approvedLog && sources[0] && <ReproductionDownload selection={{ sessionId: sources[0].sessionId, inputFile: sources[0].inputFile, runId: sources[0].binding.runId }} reviewedLog />}</Stack></Paper>;
}
