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
import { translate as i18nText, getLocale as getUILocale, message as i18nMessage, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { errorText, translate } from "../lib/i18n";
import { formatNumber, getLocale } from "../lib/i18n";
import { recordTypeLabel, enumLabel } from "../lib/i18n";





const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'DNS'];
const accordion = { bgcolor: 'transparent', '&:before': { display: 'none' } } as const;

function words(key: string): string {
  const spaced = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

function formatNanos(ns: number): string {
  if (ns >= 3_600e9) return `${+formatNumber((ns / 3_600e9), { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false })} h`;
  if (ns >= 60e9) return `${+formatNumber((ns / 60e9), { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false })} min`;
  if (ns >= 1e9) return `${+formatNumber((ns / 1e9), { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false })} s`;
  if (ns >= 1e6) return `${+formatNumber((ns / 1e6), { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false })} ms`;
  return `${ns.toLocaleString(getLocale())} ns`;
}

/** Renders a limit by the unit its key names: bytes, nanoseconds or a count. */
export function formatLimit(key: string, value: number): string {
  if (/bytes?$/i.test(key)) return formatBytes(value);
  if (/(ns|nanos|nanoseconds)$/i.test(key)) return formatNanos(value);
  return value.toLocaleString(getLocale());
}

function limitLabel(key: string): string {
  return words(key.replace(/(Bytes?|Ns|Nanos|Nanoseconds)$/, ''));
}

function n(value?: string | number): number {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

function Stat({ label, value }: { label: string; value: ReactNode }) {
  const __uiLocale = useUILocale();
  return <Box sx={{ px: 1.5, py: 1, border: 1, borderColor: 'divider', borderRadius: 1.5, minWidth: 0 }}><Typography variant="caption" color="text.secondary" noWrap display="block">{label}</Typography><Typography variant="subtitle1" sx={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }} noWrap>{value}</Typography></Box>;
}

export function OfflineReportView({ report }: { report: OfflineReport }) {
  const __uiLocale = useUILocale();
  const complete = report.status === 'complete';
  const records = (report.types ?? []).reduce((sum, t) => sum + n(t.records), 0);
  const rules = report.rules ?? [];
  const matched = rules.filter(r => n(r.matches) > 0).length;
  return <Stack spacing={1.5} sx={{ my: 1 }}><Alert severity={complete ? 'success' : 'warning'}>{complete ? i18nText("ui:m_d0a72bbc5f3939a6ba3f") : i18nText("ui:m_588a43ebca606a2ebdaf", { arg0: report.status || i18nText("ui:m_b1b6b391498fb13c454c") })}</Alert><Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: { xs: 'repeat(2, minmax(0, 1fr))', md: 'repeat(4, minmax(0, 1fr))' } }}><Stat label={i18nText("ui:m_451e6181764a06e7c139")} value={report.committedAlerts !== undefined ? `${report.committedAlerts} alert${String(report.committedAlerts) === '1' ? '' : 's'} committed` : '—'} /><Stat label={i18nText("ui:m_c644000603bd558490f2")} value={report.types ? records.toLocaleString(getUILocale()) : '—'} /><Stat label={i18nText("ui:m_48785a17a8a569113274")} value={rules.length ? `${matched} / ${rules.length}` : '—'} /><Stat label={i18nText("ui:m_14f486e77c4bf0d13c9d")} value={report.elapsed || '—'} /></Box>{report.error && <Box component="pre" sx={{ m: 0, p: 1.5, borderRadius: 1, bgcolor: 'action.hover', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 }}>{report.error}</Box>}{!!report.limitations?.length && <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 0.75 }}>{report.limitations.map(item => <Chip key={item} size="small" variant="outlined" color="warning" label={item} />)}</Stack>}{rules.length > 0 && <Box sx={{ overflowX: 'auto' }}><Table size="small" aria-label={i18nText("ui:m_685d2eeab1693be382b9")}><TableHead><TableRow><TableCell>{i18nText("ui:m_302f3877c278fc8de616")}</TableCell><TableCell>{i18nText("ui:m_3da346bd3b7d84ce65d6")}</TableCell><TableCell align="right">{i18nText("ui:m_19a8ea127b5154566a05")}</TableCell><TableCell align="right">{i18nText("ui:m_451e6181764a06e7c139")}</TableCell></TableRow></TableHead><TableBody>{rules.map(rule => <TableRow key={rule.id} sx={{ opacity: rule.enabled ? 1 : 0.55 }}><TableCell sx={{ fontFamily: 'var(--netcap-mono)' }}>{rule.id}</TableCell><TableCell>{recordTypeLabel(rule.type)}</TableCell><TableCell align="right">{n(rule.matches).toLocaleString(getUILocale())}</TableCell><TableCell align="right">{n(rule.alerts).toLocaleString(getUILocale())}</TableCell></TableRow>)}</TableBody></Table></Box>}<Accordion disableGutters elevation={0} sx={accordion} slotProps={{ transition: { unmountOnExit: true } }}><AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 1, minHeight: 36 }}><Typography variant="body2" color="text.secondary">{i18nText("ui:m_068719ae4d10c5c70c3f")}</Typography></AccordionSummary><AccordionDetails sx={{ px: 1 }}><Box component="pre" sx={{ m: 0, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 }}>{JSON.stringify(report, null, 2)}</Box></AccordionDetails></Accordion></Stack>;
}

type StepState = 'done' | 'active' | 'pending' | 'error';

function Step({ index, title, state, children }: { index: number; title: string; state: StepState; children: ReactNode }) {
  const __uiLocale = useUILocale();
  const color = { done: 'success.main', active: 'primary.main', pending: 'text.disabled', error: 'error.main' }[state];
  return <Box sx={{ p: 1.5, border: 1, borderColor: state === 'active' ? 'primary.main' : 'divider', borderRadius: 2, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 1, transition: 'border-color .15s' }}><Stack direction="row" spacing={1} alignItems="center"><Box aria-hidden sx={{ width: 22, height: 22, borderRadius: '50%', display: 'grid', placeItems: 'center', fontSize: 12, fontWeight: 700, border: 2, borderColor: color, color }}>{state === 'done' ? '✓' : index}</Box><Typography variant="subtitle2">{title}</Typography></Stack>{children}</Box>;
}

function captureLabel(status?: StatusResponse): string | undefined {
  if (status?.activeInputFile) return status.activeInputFile.split('/').pop();
  if (status?.sessionId) return i18nText("ui:m_ecdbb451a6007ad30461", { arg0: status.sessionId.slice(0, 12) });
  return status?.outputDir?.split('/').pop();
}

export default function OfflineRulesPanel({ status }: { status?: StatusResponse }) {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const [available, setAvailable] = useState<boolean>();
  const [yaml, setYaml] = useState('');
  const [name, setName] = useState('');
  const [validation, setValidation] = useState<OfflineValidation>();
  const [error, setError] = useState<UIMessageText>('');
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
      .catch(err => { if (alive) { setAvailable(false); if (!(err instanceof OfflineApiError && err.status === 404)) setError(errorText(err)); } });
    return () => { alive = false; controller.current?.abort(); };
  }, [api]);

  useEffect(() => {
    let alive = true;
    generation.current++;
    controller.current?.abort();
    setBusy(undefined); setResult(undefined); setHistory([]);
    if (available && selectionKey) api.getOfflineEvaluations(selection).then(data => { if (alive) setHistory(data.evaluations); })
      .catch(err => { if (alive) setError(errorText(err)); });
    return () => { alive = false; };
  // Selection is represented by its stable key.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, available, selectionKey]);

  async function loadPack(file: File) {
    setValidation(undefined); setResult(undefined); setError(''); setYaml('');
    if (file.size > 1 << 20) { setError(i18nMessage("ui:m_ffce95a4bae0a6ce2325")); return; }
    try {
      const text = await file.text();
      if (new TextEncoder().encode(JSON.stringify({ yaml: text, ...selection })).length > 1 << 20) {
        setError(i18nMessage("ui:m_3c99196a450a8adf85bb")); return;
      }
      setYaml(text); setName(file.name);
    } catch (err) { setError(errorText(err)); }
  }
  async function validate() {
    setBusy('validating'); setError(''); setResult(undefined);
    try { setValidation(await api.validateOfflinePack(yaml)); } catch (err) { setError(errorText(err)); }
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
    } catch (err) { if (generation.current === current) setError(abort.signal.aborted ? i18nMessage("ui:m_a5d526ae005dc5b564a7") : String(err)); }
    finally { if (generation.current === current) setBusy(undefined); }
  }

  const enabled = validation?.pack?.rules.some(rule => rule.enabled);
  const rules = validation?.pack?.rules ?? [];
  const gated = status?.isLiveMode ? translate("ui:m_b1db32bfb966f41a34e0") : status?.isProcessing ? translate("ui:m_c8a4603f180bbfcdf4e3") : !selectionKey ? translate("ui:m_60b519b116b807f5a288") : undefined;
  const capture = captureLabel(status);
  const packState: StepState = yaml ? 'done' : 'active';
  const validateState: StepState = !yaml ? 'pending' : validation ? (validation.valid ? (enabled ? 'done' : 'error') : 'error') : 'active';
  const evaluateState: StepState = result?.report?.status === 'complete' ? 'done' : result?.error || (result?.report && result.report.status !== 'complete') ? 'error' : validation?.valid && enabled ? 'active' : 'pending';

  return <Paper variant="outlined" sx={{ p: { xs: 1.5, md: 2 }, mb: 3, borderRadius: 2 }}><Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ sm: 'center' }} justifyContent="space-between" sx={{ mb: 1.5 }}><Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: 'wrap', rowGap: 0.75 }}><FactCheckOutlinedIcon fontSize="small" color="primary" /><Typography variant="h6" sx={{ fontSize: '1rem' }}>{i18nText("ui:m_9dc54939ef41620206c6")}</Typography><Tooltip title={i18nText("ui:m_365fb6f8342355284a70")}><InfoOutlinedIcon fontSize="small" sx={{ color: 'text.secondary', cursor: 'help' }} aria-label={i18nText("ui:m_abdc9c530b499919ad9f")} /></Tooltip>{PROTOCOLS.map(protocol => <Chip key={protocol} label={i18nText(protocol)} size="small" variant="outlined" />)}</Stack>{available && <Tooltip title={selectionKey || ''}><Chip size="small" color={selectionKey ? 'primary' : 'default'} variant="outlined" label={capture || i18nText("ui:m_c6c974cbb82c44d77cf3")} sx={{ maxWidth: { xs: '100%', sm: 320 } }} /></Tooltip>}</Stack>{available === false ? <Alert severity="info">{i18nText("ui:m_b2a5f8415302af2517ca")}</Alert> : available === undefined ? <Stack direction="row" spacing={1} alignItems="center"><CircularProgress size={16} /><Typography variant="body2" color="text.secondary">{i18nText("ui:m_449d326fa04b701a7fd1")}</Typography></Stack> : <Stack spacing={1.5}><Box sx={{ display: 'grid', gap: 1.5, gridTemplateColumns: { xs: 'minmax(0, 1fr)', md: 'repeat(3, minmax(0, 1fr))' } }}><Step index={1} title={i18nText("ui:m_7a8ae92da9261926507e")} state={packState}><Typography variant="body2" color={yaml ? 'text.primary' : 'text.secondary'} noWrap title={name}>{yaml ? name : i18nText("ui:m_892940df9d8c2fb7f1d8")}</Typography><Stack direction="row" sx={{ flexWrap: 'wrap', gap: 1 }}><Button component="label" size="small" variant="outlined" startIcon={<UploadFileIcon />} disabled={!!busy}>{i18nText("ui:m_ae3698c76e4bb21f0627")}<input aria-label={i18nText("ui:m_9079a5540bfd7ebbe929")} hidden type="file" accept=".yaml,.yml,text/yaml" onChange={event => { const file = event.target.files?.[0]; if (file) void loadPack(file); event.target.value = ''; }} /></Button>{templates.map(template => <Button key={template.name} size="small" disabled={!!busy} onClick={() => { setYaml(template.yaml); setName(template.name); setValidation(undefined); setResult(undefined); }}>{template.name}</Button>)}</Stack></Step><Step index={2} title={i18nText("ui:m_1b0a177e9fef413dde1e")} state={validateState}><Typography variant="body2" color="text.secondary">{!yaml ? i18nText("ui:m_bbc74b1b7468da119cdf") : !validation ? i18nText("ui:m_50abb1c3d446ac2c83fa") : validation.valid ? i18nText("ui:m_43d3cb1490cfcf09e8b4", { arg0: rules.length, arg2: rules.filter(r => r.enabled).length }) : i18nText("ui:m_f6db361867a44d88d063", { arg0: validation.errors.length })}</Typography><Box><Button size="small" variant="outlined" onClick={validate} disabled={!yaml || !!busy}>{i18nText("ui:m_2b65216af5c96a0843c1")}</Button></Box></Step><Step index={3} title={i18nText("ui:m_36168d33268d9a6a8d5f")} state={evaluateState}><Typography variant="body2" color="text.secondary" noWrap>{gated || (validation?.valid && enabled ? i18nText("ui:m_9163dab7b2a223ccbb6c", { arg0: capture }) : i18nText("ui:m_6076cf4660bbb92b5267"))}</Typography><Stack direction="row" spacing={1}><Button size="small" variant="contained" startIcon={<PlayArrowIcon />} onClick={execute} disabled={!validation?.valid || !enabled || !!busy || !selectionKey || status?.isLiveMode || status?.isProcessing}>{i18nText("ui:m_37fdc7e8a82053374723")}</Button>{busy === 'evaluating' && <Button size="small" onClick={() => controller.current?.abort()}>{i18nText("ui:m_9b75d846ac967c38d13f")}</Button>}</Stack></Step></Box>{busy && <Stack direction="row" spacing={1} alignItems="center"><CircularProgress size={16} /><Typography role="status" variant="body2">{busy === 'evaluating' ? i18nText("ui:m_9a0b90cc3df958cb9e1c") : i18nText("ui:m_cedd8f4aedbf3da9a07d")}</Typography></Stack>}{validation && !validation.valid && <Alert severity="error">{i18nRichText("ui:m_7f25b3df49ffbc01b304", { arg0: validation.errors.map(item => `${item.field}: ${item.message}`).join('; ') })}</Alert>}{validation?.valid && <Alert severity={enabled ? 'success' : 'info'}>{enabled ? i18nText("ui:m_c3f126b2ada224edc84d") : i18nText("ui:m_28e145ad27396c0d611f")}</Alert>}{validation?.valid && rules.length > 0 && <Box sx={{ overflowX: 'auto' }}><Table size="small" aria-label={i18nText("ui:m_a3b9d73c387239be67c8")}><TableHead><TableRow>{['Rule', 'Type', 'Expression', 'Severity', 'Threshold', 'Enabled'].map(label => <TableCell key={label}>{i18nText(label)}</TableCell>)}</TableRow></TableHead><TableBody>{rules.map(rule => <TableRow key={rule.id} sx={{ opacity: rule.enabled ? 1 : 0.55 }}><TableCell><Typography variant="body2">{rule.name}</Typography><Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'var(--netcap-mono)' }}>{rule.id}</Typography></TableCell><TableCell><Chip size="small" variant="outlined" label={recordTypeLabel(rule.type)} /></TableCell><TableCell sx={{ fontFamily: 'var(--netcap-mono)', fontSize: 12, maxWidth: 360, overflowWrap: 'anywhere' }}>{rule.expression}</TableCell><TableCell>{enumLabel(rule.severity)}</TableCell><TableCell sx={{ whiteSpace: 'nowrap' }}>{i18nRichText("ui:m_78fe352b932f92844004", { arg0: rule.threshold.count, arg1: rule.threshold.window || i18nText("ui:m_9c45fd96f129a09315e7") })}<Typography variant="caption" color="text.secondary" display="block">{i18nRichText("ui:m_f454ab2049c1d7f930f3", { arg0: rule.threshold.groupBy.join(', ') })}</Typography></TableCell><TableCell>{rule.enabled ? i18nText("ui:m_7a78db986796aa2b0a40") : i18nText("ui:m_2db1494f02b6ab264e05")}</TableCell></TableRow>)}</TableBody></Table></Box>}{result?.error && <Alert severity="error">{i18nRichText("ui:m_521b8fd41791bea12042", { arg0: result.error })}</Alert>}{result?.report && <OfflineReportView report={result.report} />}{history.some(report => report.status !== 'complete') && <Alert severity="warning">{i18nText("ui:m_f4dfcc9c3ba32f8ab38d")}</Alert>}<Box sx={{ borderTop: 1, borderColor: 'divider' }}>{yaml && <Accordion disableGutters elevation={0} sx={accordion} slotProps={{ transition: { unmountOnExit: true } }}><AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 1 }}><Typography variant="body2">{i18nRichText("ui:m_3d552cfa6b7c3b49119e", { arg0: name })}</Typography></AccordionSummary><AccordionDetails sx={{ px: 1 }}><Box component="pre" sx={{ m: 0, p: 1.5, borderRadius: 1, bgcolor: 'action.hover', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12, maxHeight: 360, overflow: 'auto' }}>{yaml}</Box></AccordionDetails></Accordion>}{limits && <Accordion disableGutters elevation={0} sx={accordion} slotProps={{ transition: { unmountOnExit: true } }}><AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 1 }}><Typography variant="body2">{i18nText("ui:m_70479d5df7774b1a248c")}</Typography></AccordionSummary><AccordionDetails sx={{ px: 1 }}><Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))' }}>{Object.entries(limits).map(([key, value]) => <Stat key={key} label={limitLabel(key)} value={formatLimit(key, value)} />)}</Box></AccordionDetails></Accordion>}<Accordion disableGutters elevation={0} sx={accordion} slotProps={{ transition: { unmountOnExit: true } }}><AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 1 }}><Typography variant="body2">{i18nRichText("ui:m_20bd2ab88d62c7e4f1f6", { arg0: history.length })}</Typography></AccordionSummary><AccordionDetails sx={{ px: 1 }}>{history.length === 0 ? <Typography variant="body2" color="text.secondary">{i18nText("ui:m_b20473f2fddc338f2063")}</Typography> : history.map((report, index) => <OfflineReportView key={index} report={report} />)}</AccordionDetails></Accordion></Box></Stack>}{i18nRenderText(error) && <Alert severity="error" sx={{ mt: 1.5 }}>{i18nRenderText(error)}</Alert>}</Paper>;
}
