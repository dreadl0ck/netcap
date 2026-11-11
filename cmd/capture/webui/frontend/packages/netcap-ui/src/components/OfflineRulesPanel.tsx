import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
  Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button, Chip, CircularProgress, Paper, Stack,
  Table, TableBody, TableCell, TableHead, TableRow, Tooltip, Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import FactCheckOutlinedIcon from '@mui/icons-material/FactCheckOutlined';
import { useNetcapApi } from '../hooks';
import { formatBytes, OfflineApiError, type OfflineExecution, type OfflineReport, type OfflineValidation, type StatusResponse } from '../lib/api';

const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'DNS'];
const accordion = { bgcolor: 'transparent', '&:before': { display: 'none' } } as const;

function words(key: string): string {
  const spaced = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

function formatNanos(ns: number): string {
  if (ns >= 3_600e9) return `${+(ns / 3_600e9).toFixed(1)} h`;
  if (ns >= 60e9) return `${+(ns / 60e9).toFixed(1)} min`;
  if (ns >= 1e9) return `${+(ns / 1e9).toFixed(1)} s`;
  if (ns >= 1e6) return `${+(ns / 1e6).toFixed(1)} ms`;
  return `${ns.toLocaleString()} ns`;
}

/** Renders a limit by the unit its key names: bytes, nanoseconds or a count. */
export function formatLimit(key: string, value: number): string {
  if (/bytes?$/i.test(key)) return formatBytes(value);
  if (/(ns|nanos|nanoseconds)$/i.test(key)) return formatNanos(value);
  return value.toLocaleString();
}

function limitLabel(key: string): string {
  return words(key.replace(/(Bytes?|Ns|Nanos|Nanoseconds)$/, ''));
}

function n(value?: string | number): number {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

function Stat({ label, value }: { label: string; value: ReactNode }) {
  return <Box sx={{ px: 1.5, py: 1, border: 1, borderColor: 'divider', borderRadius: 1.5, minWidth: 0 }}>
    <Typography variant="caption" color="text.secondary" noWrap display="block">{label}</Typography>
    <Typography variant="subtitle1" sx={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }} noWrap>{value}</Typography>
  </Box>;
}

export function OfflineReportView({ report }: { report: OfflineReport }) {
  const complete = report.status === 'complete';
  const records = (report.types ?? []).reduce((sum, t) => sum + n(t.records), 0);
  const rules = report.rules ?? [];
  const matched = rules.filter(r => n(r.matches) > 0).length;
  return <Stack spacing={1.5} sx={{ my: 1 }}>
    <Alert severity={complete ? 'success' : 'warning'}>
      {complete ? 'Offline evaluation completed' : `Incomplete offline evaluation: ${report.status || 'unknown'}. Coverage is not complete.`}
    </Alert>
    <Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: { xs: 'repeat(2, minmax(0, 1fr))', md: 'repeat(4, minmax(0, 1fr))' } }}>
      <Stat label="Alerts" value={report.committedAlerts !== undefined ? `${report.committedAlerts} alert${String(report.committedAlerts) === '1' ? '' : 's'} committed` : '—'} />
      <Stat label="Records evaluated" value={report.types ? records.toLocaleString() : '—'} />
      <Stat label="Rules matched" value={rules.length ? `${matched} / ${rules.length}` : '—'} />
      <Stat label="Elapsed" value={report.elapsed || '—'} />
    </Box>
    {report.error && <Box component="pre" sx={{ m: 0, p: 1.5, borderRadius: 1, bgcolor: 'action.hover', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 }}>{report.error}</Box>}
    {!!report.limitations?.length && <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 0.75 }}>
      {report.limitations.map(item => <Chip key={item} size="small" variant="outlined" color="warning" label={item} />)}
    </Stack>}
    {rules.length > 0 && <Box sx={{ overflowX: 'auto' }}><Table size="small" aria-label="Rule results">
      <TableHead><TableRow><TableCell>Rule</TableCell><TableCell>Type</TableCell><TableCell align="right">Matches</TableCell><TableCell align="right">Alerts</TableCell></TableRow></TableHead>
      <TableBody>{rules.map(rule => <TableRow key={rule.id} sx={{ opacity: rule.enabled ? 1 : 0.55 }}>
        <TableCell sx={{ fontFamily: 'var(--netcap-mono)' }}>{rule.id}</TableCell><TableCell>{rule.type}</TableCell>
        <TableCell align="right">{n(rule.matches).toLocaleString()}</TableCell><TableCell align="right">{n(rule.alerts).toLocaleString()}</TableCell>
      </TableRow>)}</TableBody>
    </Table></Box>}
    <Accordion disableGutters elevation={0} sx={accordion} slotProps={{ transition: { unmountOnExit: true } }}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 1, minHeight: 36 }}><Typography variant="body2" color="text.secondary">Raw report</Typography></AccordionSummary>
      <AccordionDetails sx={{ px: 1 }}><Box component="pre" sx={{ m: 0, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 }}>{JSON.stringify(report, null, 2)}</Box></AccordionDetails>
    </Accordion>
  </Stack>;
}

type StepState = 'done' | 'active' | 'pending' | 'error';

function Step({ index, title, state, children }: { index: number; title: string; state: StepState; children: ReactNode }) {
  const color = { done: 'success.main', active: 'primary.main', pending: 'text.disabled', error: 'error.main' }[state];
  return <Box sx={{ p: 1.5, border: 1, borderColor: state === 'active' ? 'primary.main' : 'divider', borderRadius: 2, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 1, transition: 'border-color .15s' }}>
    <Stack direction="row" spacing={1} alignItems="center">
      <Box aria-hidden sx={{ width: 22, height: 22, borderRadius: '50%', display: 'grid', placeItems: 'center', fontSize: 12, fontWeight: 700, border: 2, borderColor: color, color }}>{state === 'done' ? '✓' : index}</Box>
      <Typography variant="subtitle2">{title}</Typography>
    </Stack>
    {children}
  </Box>;
}

function captureLabel(status?: StatusResponse): string | undefined {
  if (status?.activeInputFile) return status.activeInputFile.split('/').pop();
  if (status?.sessionId) return `Session ${status.sessionId.slice(0, 12)}`;
  return status?.outputDir?.split('/').pop();
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
  const rules = validation?.pack?.rules ?? [];
  const gated = status?.isLiveMode ? 'Unavailable during live capture' : status?.isProcessing ? 'Waiting for analysis to finish' : !selectionKey ? 'Select a completed capture' : undefined;
  const capture = captureLabel(status);
  const packState: StepState = yaml ? 'done' : 'active';
  const validateState: StepState = !yaml ? 'pending' : validation ? (validation.valid ? (enabled ? 'done' : 'error') : 'error') : 'active';
  const evaluateState: StepState = result?.report?.status === 'complete' ? 'done' : result?.error || (result?.report && result.report.status !== 'complete') ? 'error' : validation?.valid && enabled ? 'active' : 'pending';

  return <Paper variant="outlined" sx={{ p: { xs: 1.5, md: 2 }, mb: 3, borderRadius: 2 }}>
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ sm: 'center' }} justifyContent="space-between" sx={{ mb: 1.5 }}>
      <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: 'wrap', rowGap: 0.75 }}>
        <FactCheckOutlinedIcon fontSize="small" color="primary" />
        <Typography variant="h6" sx={{ fontSize: '1rem' }}>Offline Evaluation</Typography>
        <Tooltip title="Run a netcap-offline-rules/v1 YAML pack against a completed capture. Produces alerts only; no runtime actions are taken.">
          <InfoOutlinedIcon fontSize="small" sx={{ color: 'text.secondary', cursor: 'help' }} aria-label="About offline evaluation" />
        </Tooltip>
        {PROTOCOLS.map(protocol => <Chip key={protocol} label={protocol} size="small" variant="outlined" />)}
      </Stack>
      {available && <Tooltip title={selectionKey || ''}><Chip size="small" color={selectionKey ? 'primary' : 'default'} variant="outlined" label={capture || 'No capture selected'} sx={{ maxWidth: { xs: '100%', sm: 320 } }} /></Tooltip>}
    </Stack>

    {available === false ? <Alert severity="info">Offline evaluation is unavailable on this backend.</Alert> : available === undefined ? <Stack direction="row" spacing={1} alignItems="center"><CircularProgress size={16} /><Typography variant="body2" color="text.secondary">Checking offline capability…</Typography></Stack> : <Stack spacing={1.5}>
      <Box sx={{ display: 'grid', gap: 1.5, gridTemplateColumns: { xs: 'minmax(0, 1fr)', md: 'repeat(3, minmax(0, 1fr))' } }}>
        <Step index={1} title="Load pack" state={packState}>
          <Typography variant="body2" color={yaml ? 'text.primary' : 'text.secondary'} noWrap title={name}>{yaml ? name : 'Upload a YAML pack or start from an example'}</Typography>
          <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 1 }}>
            <Button component="label" size="small" variant="outlined" startIcon={<UploadFileIcon />} disabled={!!busy}>Upload YAML pack<input aria-label="Upload offline YAML pack" hidden type="file" accept=".yaml,.yml,text/yaml" onChange={event => { const file = event.target.files?.[0]; if (file) void loadPack(file); event.target.value = ''; }} /></Button>
            {templates.map(template => <Button key={template.name} size="small" disabled={!!busy} onClick={() => { setYaml(template.yaml); setName(template.name); setValidation(undefined); setResult(undefined); }}>{template.name}</Button>)}
          </Stack>
        </Step>
        <Step index={2} title="Validate" state={validateState}>
          <Typography variant="body2" color="text.secondary">{!yaml ? 'Load a pack first' : !validation ? 'Check syntax and thresholds' : validation.valid ? `${rules.length} rule${rules.length === 1 ? '' : 's'} · ${rules.filter(r => r.enabled).length} enabled` : `${validation.errors.length} error${validation.errors.length === 1 ? '' : 's'}`}</Typography>
          <Box><Button size="small" variant="outlined" onClick={validate} disabled={!yaml || !!busy}>Validate pack</Button></Box>
        </Step>
        <Step index={3} title="Evaluate" state={evaluateState}>
          <Typography variant="body2" color="text.secondary" noWrap>{gated || (validation?.valid && enabled ? `Run against ${capture}` : 'Validate a pack with enabled rules')}</Typography>
          <Stack direction="row" spacing={1}>
            <Button size="small" variant="contained" startIcon={<PlayArrowIcon />} onClick={execute} disabled={!validation?.valid || !enabled || !!busy || !selectionKey || status?.isLiveMode || status?.isProcessing}>Evaluate capture</Button>
            {busy === 'evaluating' && <Button size="small" onClick={() => controller.current?.abort()}>Cancel evaluation</Button>}
          </Stack>
        </Step>
      </Box>

      {busy && <Stack direction="row" spacing={1} alignItems="center"><CircularProgress size={16} /><Typography role="status" variant="body2">{busy === 'evaluating' ? 'Evaluating selected capture…' : 'Validating pack…'}</Typography></Stack>}
      {validation && !validation.valid && <Alert severity="error">Validation failed: {validation.errors.map(item => `${item.field}: ${item.message}`).join('; ')}</Alert>}
      {validation?.valid && <Alert severity={enabled ? 'success' : 'info'}>{enabled ? 'Pack validated. Ready for explicit evaluation.' : 'Pack validated, but all rules are disabled. Enable rules in your local YAML file and upload it again.'}</Alert>}
      {validation?.valid && rules.length > 0 && <Box sx={{ overflowX: 'auto' }}><Table size="small" aria-label="Pack rules">
        <TableHead><TableRow>{['Rule', 'Type', 'Expression', 'Severity', 'Threshold', 'Enabled'].map(label => <TableCell key={label}>{label}</TableCell>)}</TableRow></TableHead>
        <TableBody>{rules.map(rule => <TableRow key={rule.id} sx={{ opacity: rule.enabled ? 1 : 0.55 }}>
          <TableCell><Typography variant="body2">{rule.name}</Typography><Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'var(--netcap-mono)' }}>{rule.id}</Typography></TableCell>
          <TableCell><Chip size="small" variant="outlined" label={rule.type} /></TableCell>
          <TableCell sx={{ fontFamily: 'var(--netcap-mono)', fontSize: 12, maxWidth: 360, overflowWrap: 'anywhere' }}>{rule.expression}</TableCell>
          <TableCell>{rule.severity}</TableCell>
          <TableCell sx={{ whiteSpace: 'nowrap' }}>≥ {rule.threshold.count} in {rule.threshold.window || '60s'}<Typography variant="caption" color="text.secondary" display="block">by {rule.threshold.groupBy.join(', ')}</Typography></TableCell>
          <TableCell>{rule.enabled ? 'Yes' : 'No'}</TableCell>
        </TableRow>)}</TableBody>
      </Table></Box>}
      {result?.error && <Alert severity="error">Evaluation failed: {result.error}</Alert>}
      {result?.report && <OfflineReportView report={result.report} />}
      {history.some(report => report.status !== 'complete') && <Alert severity="warning">Execution history includes incomplete coverage. Review limits and failures below before interpreting alerts.</Alert>}

      <Box sx={{ borderTop: 1, borderColor: 'divider' }}>
        {yaml && <Accordion disableGutters elevation={0} sx={accordion} slotProps={{ transition: { unmountOnExit: true } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 1 }}><Typography variant="body2">{name} (read-only YAML)</Typography></AccordionSummary>
          <AccordionDetails sx={{ px: 1 }}><Box component="pre" sx={{ m: 0, p: 1.5, borderRadius: 1, bgcolor: 'action.hover', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12, maxHeight: 360, overflow: 'auto' }}>{yaml}</Box></AccordionDetails>
        </Accordion>}
        {limits && <Accordion disableGutters elevation={0} sx={accordion} slotProps={{ transition: { unmountOnExit: true } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 1 }}><Typography variant="body2">Evaluation limits</Typography></AccordionSummary>
          <AccordionDetails sx={{ px: 1 }}><Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))' }}>
            {Object.entries(limits).map(([key, value]) => <Stat key={key} label={limitLabel(key)} value={formatLimit(key, value)} />)}
          </Box></AccordionDetails>
        </Accordion>}
        <Accordion disableGutters elevation={0} sx={accordion} slotProps={{ transition: { unmountOnExit: true } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 1 }}><Typography variant="body2">Execution history ({history.length})</Typography></AccordionSummary>
          <AccordionDetails sx={{ px: 1 }}>{history.length === 0 ? <Typography variant="body2" color="text.secondary">No evaluations for this capture yet.</Typography> : history.map((report, index) => <OfflineReportView key={index} report={report} />)}</AccordionDetails>
        </Accordion>
      </Box>
    </Stack>}
    {error && <Alert severity="error" sx={{ mt: 1.5 }}>{error}</Alert>}
  </Paper>;
}
