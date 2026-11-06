import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, CircularProgress, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { useNetcapApi } from '../hooks';
import { OfflineApiError, type OfflineExecution, type OfflineReport, type OfflineValidation, type StatusResponse } from '../lib/api';

export function OfflineReportView({ report }: { report: OfflineReport }) {
  const complete = report.status === 'complete';
  return <Box sx={{ my: 1 }}>
    <Alert severity={complete ? 'success' : 'warning'}>
      {complete ? 'Offline evaluation completed' : `Incomplete offline evaluation: ${report.status || 'unknown'}. Coverage is not complete.`}
    </Alert>
    {report.committedAlerts !== undefined && <Typography variant="body2">{report.committedAlerts} alert{String(report.committedAlerts) === '1' ? '' : 's'} committed</Typography>}
    <Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 }}>{JSON.stringify(report, null, 2)}</Box>
  </Box>;
}

export default function OfflineRulesPanel({ status }: { status?: StatusResponse }) {
  const api = useNetcapApi();
  const [available, setAvailable] = useState<boolean>();
  const [yaml, setYaml] = useState('');
  const [name, setName] = useState('');
  const [validation, setValidation] = useState<OfflineValidation>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<'validating' | 'evaluating'>();
  const [result, setResult] = useState<OfflineExecution>();
  const [history, setHistory] = useState<OfflineReport[]>([]);
  const [templates, setTemplates] = useState<{ name: string; yaml: string }[]>([]);
  const [limits, setLimits] = useState<Record<string, number>>();
  const controller = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const selection = status?.sessionId ? { sessionId: status.sessionId } : { inputFile: status?.activeInputFile };
  const selectionKey = status?.sessionId || status?.activeInputFile || status?.outputDir;

  useEffect(() => {
    let alive = true;
    api.getOfflinePacks().then(data => { if (alive) { setAvailable(true); setTemplates(data.packs); setLimits(data.limits); } })
      .catch(err => { if (alive) { setAvailable(false); if (!(err instanceof OfflineApiError && err.status === 404)) setError(String(err)); } });
    return () => { alive = false; controller.current?.abort(); };
  }, [api]);

  useEffect(() => {
    let alive = true;
    generation.current++;
    controller.current?.abort();
    setBusy(undefined); setResult(undefined); setHistory([]);
    if (available && selectionKey) api.getOfflineEvaluations(selection).then(data => { if (alive) setHistory(data.evaluations); })
      .catch(err => { if (alive) setError(String(err)); });
    return () => { alive = false; };
  // Selection is represented by its stable key.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, available, selectionKey]);

  async function loadPack(file: File) {
    setValidation(undefined); setResult(undefined); setError(''); setYaml('');
    if (file.size > 1 << 20) { setError('Pack upload exceeds 1 MiB.'); return; }
    try {
      const text = await file.text();
      if (new TextEncoder().encode(JSON.stringify({ yaml: text, ...selection })).length > 1 << 20) {
        setError('Pack exceeds the 1 MiB JSON request budget after encoding.'); return;
      }
      setYaml(text); setName(file.name);
    } catch (err) { setError(String(err)); }
  }
  async function validate() {
    setBusy('validating'); setError(''); setResult(undefined);
    try { setValidation(await api.validateOfflinePack(yaml)); } catch (err) { setError(String(err)); }
    finally { setBusy(undefined); }
  }
  async function execute() {
    const current = generation.current;
    const abort = new AbortController(); controller.current = abort;
    setBusy('evaluating'); setError(''); setResult(undefined);
    try {
      const response = await api.executeOfflinePack(yaml, selection, abort.signal);
      if (generation.current !== current) return;
      setResult(response);
      const data = await api.getOfflineEvaluations(selection);
      if (generation.current === current) setHistory(data.evaluations);
    } catch (err) { if (generation.current === current) setError(abort.signal.aborted ? 'Evaluation cancelled. Check execution history for persisted partial coverage.' : String(err)); }
    finally { if (generation.current === current) setBusy(undefined); }
  }
  const enabled = validation?.pack?.rules.some(rule => rule.enabled);
  return <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
    <Typography variant="h6">Offline Evaluation</Typography>
    <Typography variant="body2" color="text.secondary">Optional netcap-offline-rules/v1 pack · TCP, UDP, HTTP and DNS · completed captures only · no runtime actions</Typography>
    {available === false ? <Alert severity="info">Offline evaluation is unavailable on this backend.</Alert> : available === undefined ? <Typography>Checking offline capability…</Typography> : <>
      <Typography variant="body2" sx={{ my: 1 }}>Capture: {selectionKey || 'No capture selected'}</Typography>
      {limits && <details><summary>Evaluation limits (bytes, records and nanoseconds)</summary><Box component="pre" sx={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(limits, null, 2)}</Box></details>}
      <Stack direction="row" spacing={1} sx={{ my: 1 }}>
        <Button component="label" variant="outlined" disabled={!!busy}>Upload YAML pack<input aria-label="Upload offline YAML pack" hidden type="file" accept=".yaml,.yml,text/yaml" onChange={event => { const file = event.target.files?.[0]; if (file) void loadPack(file); event.target.value = ''; }} /></Button>
        {templates.map(template => <Button key={template.name} disabled={!!busy} onClick={() => { setYaml(template.yaml); setName(template.name); setValidation(undefined); setResult(undefined); }}>{template.name}</Button>)}
        <Button onClick={validate} disabled={!yaml || !!busy}>Validate pack</Button>
        <Button variant="contained" onClick={execute} disabled={!validation?.valid || !enabled || !!busy || !selectionKey || status?.isLiveMode || status?.isProcessing}>Evaluate capture</Button>
        {busy === 'evaluating' && <Button onClick={() => controller.current?.abort()}>Cancel evaluation</Button>}
      </Stack>
      {busy && <Stack direction="row" spacing={1}><CircularProgress size={18} /><Typography role="status">{busy === 'evaluating' ? 'Evaluating selected capture…' : 'Validating pack…'}</Typography></Stack>}
      {yaml && <details><summary>{name} (read-only YAML)</summary><Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{yaml}</Box></details>}
      {validation && !validation.valid && <Alert severity="error">Validation failed: {validation.errors.map(item => `${item.field}: ${item.message}`).join('; ')}</Alert>}
      {validation?.valid && <>
        <Alert severity={enabled ? 'success' : 'info'}>{enabled ? 'Pack validated. Ready for explicit evaluation.' : 'Pack validated, but all rules are disabled. Enable rules in your local YAML file and upload it again.'}</Alert>
        <Table size="small"><TableHead><TableRow>{['Rule', 'Type', 'Expression', 'Severity', 'Threshold', 'Enabled'].map(label => <TableCell key={label}>{label}</TableCell>)}</TableRow></TableHead><TableBody>
          {validation.pack?.rules.map(rule => <TableRow key={rule.id}><TableCell>{rule.name} ({rule.id})</TableCell><TableCell>{rule.type}</TableCell><TableCell>{rule.expression}</TableCell><TableCell>{rule.severity}</TableCell><TableCell>{rule.threshold.count} / {rule.threshold.window || '60s'} by {rule.threshold.groupBy.join(', ')}</TableCell><TableCell>{rule.enabled ? 'Yes' : 'No'}</TableCell></TableRow>)}
        </TableBody></Table>
      </>}
      {result?.error && <Alert severity="error">Evaluation failed: {result.error}</Alert>}
      {result?.report && <OfflineReportView report={result.report} />}
      {history.some(report => report.status !== 'complete') && <Alert severity="warning">Execution history includes incomplete coverage. Review limits and failures below before interpreting alerts.</Alert>}
      <details><summary>Execution history ({history.length})</summary>{history.map((report, index) => <OfflineReportView key={index} report={report} />)}</details>
    </>}
    {error && <Alert severity="error">{error}</Alert>}
  </Paper>;
}
