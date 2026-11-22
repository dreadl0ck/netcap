import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, CircularProgress, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';

import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { useNetcapApi } from '../hooks';
import { useNetcapConfig } from '../providers';
import { behaviorSelection } from '../lib/behavior';
import AnalystWorkbench from '../components/AnalystWorkbench';
import { message as i18nMessage, translate as i18nText, renderText as i18nRenderText, richText as i18nRichText, formatNumber as i18nNumber, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { message, displayError, renderError } from "../lib/i18n";
import { errorText } from "../lib/i18n";





async function investigationRequest<T>(fetcher: typeof fetch, url: string): Promise<T> {
  const response = await fetcher(url);
  if (!response.ok) throw displayError(await response.text() || message("ui:m_05c33ceea29a3acaa577", { arg0: response.status }));
  return response.json() as Promise<T>;
}

interface CaptureManifest {
  runId: string; status: string; inputSHA256?: string; configSHA256: string; error?: string;
  ingressPackets: number; admittedPackets: number; queueDrops: number; truncatedPackets: number;
  kernelReceived: number | null; kernelDrops: number | null; firstNs?: string; lastNs?: string;
  limitations: string[]; segments: { name: string; state: string; packets: number; sha256: string }[];
}
interface StreamRow {
  id: string; spanCount: number;
  manifest: { connectionKey: string; protocol: string; status: string; communityId: string;
    client: { length: string; sha256: string }; server: { length: string; sha256: string } };
}
interface FlowReport {
  query?: Record<string, unknown>;
  matchedObservations?: number; matchedRecords?: number; totalGroups: number; unquantifiableRecords?: number;
  recordFileSHA256?: string; sourceSHA256?: string; limitations: string[];
  statistics?: { bytes: { count: number; min: string; median: string; p95: string; max: string } };
  series?: { startNs: string; endNs: string; estimatedBytes: number; estimatedBitsPerSecond: number; directionalComplete: boolean }[];
  groups: { key: string; bytes: string; packets: string; distinctPeers?: number; peers?: number;
    members?: { ordinal: number; observationId?: string }[]; observationIds?: string[] }[];
}

export interface InvestigationPageProps {
  downloadArtifact?: (url: string, filename: string) => Promise<void>;
}

export default function InvestigationPage({ downloadArtifact }: InvestigationPageProps = {}) {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const config = useNetcapConfig();
  const fetcher = config.fetch ?? fetch;
  const { data: status, mutate: refreshStatus } = useSWR('status', () => api.getStatus());
  const { data: files } = useSWR('inputFiles', () => api.getInputFiles());
  const selection = behaviorSelection(status, files);
  const captureURL = `${config.apiBaseUrl}/investigation/capture${selection}`;
  const streamURL = `${config.apiBaseUrl}/investigation/streams${selection}`;
  const { data: capture, error: captureError } = useSWR<CaptureManifest>(status ? captureURL : null, () => investigationRequest(fetcher, captureURL), { keepPreviousData: false });
  const { data: streams, error: streamError } = useSWR<StreamRow[]>(status ? streamURL : null, () => investigationRequest(fetcher, streamURL), { keepPreviousData: false });
  const healthURL = (kind: string) => `${config.apiBaseUrl}/investigation/health${selection}${selection ? '&' : '?'}kind=${kind}`;
  const { data: ftpHealth, error: ftpHealthError } = useSWR(status ? healthURL('ftp') : null, () => investigationRequest(fetcher, healthURL('ftp')), { keepPreviousData: false });
  const { data: reassemblyHealth, error: reassemblyHealthError } = useSWR(status ? healthURL('reassembly') : null, () => investigationRequest(fetcher, healthURL('reassembly')), { keepPreviousData: false });
  const [source, setSource] = useState('packet');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [expression, setExpression] = useState('');
  const [exporter, setExporter] = useState('');
  const [domain, setDomain] = useState('');
  const [ingress, setIngress] = useState('');
  const [egress, setEgress] = useState('');
  const [nextHop, setNextHop] = useState('');
  const [sortBy, setSortBy] = useState('bytes');
  const [format, setFormat] = useState('netflow-v9');
  const [basis, setBasis] = useState('flow');
  const [group, setGroup] = useState('srcIP');
  const [windowMode, setWindowMode] = useState('overlap');
  const [bucketNs, setBucketNs] = useState('');
  const [report, setReport] = useState<FlowReport | null>(null);
  const [error, setError] = useState<UIMessageText>('');
  const [busy, setBusy] = useState(false);
  const [switching, setSwitching] = useState(false);
  const generation = useRef(0);
  useEffect(() => { generation.current++; setReport(null); setError(''); setBusy(false); setStart(''); setEnd(''); }, [selection]);
  useEffect(() => { if (capture) { setStart(capture.firstNs ?? ''); setEnd(capture.lastNs ?? ''); } }, [capture]);
  const changeCapture = async (path: string) => {
    setSwitching(true);
    try { const result = await api.setActiveDirectory(path); await refreshStatus(); window.dispatchEvent(new CustomEvent('directory-changed', { detail: result })); }
    catch (failure) { setError(failure instanceof Error ? errorText(failure) : i18nMessage("ui:m_05bbfcab9a0907cba25b")); }
    finally { setSwitching(false); }
  };
  const query = async () => {
    const requestGeneration = ++generation.current;
    setReport(null); setError(''); setBusy(true);
    try {
      if (!/^-?\d+$/.test(start) || !/^-?\d+$/.test(end) || BigInt(start) > BigInt(end)) throw displayError(message("ui:m_60f3bac9bac5c2027a4d"));
      const params = new URLSearchParams(selection.replace(/^\?/, ''));
      params.set('startNs', start); params.set('endNs', end); params.set('groupBy', group); params.set('limit', '100');
      let endpoint = 'flows/query';
      if (source === 'export') {
        if (!exporter || !/^\d+$/.test(domain)) throw displayError(message("ui:m_adf61281fd37b658b831"));
        endpoint = 'flows/exports/query'; params.set('exporter', exporter); params.set('domain', domain); params.set('format', format); params.set('timeBasis', basis);
        if (ingress) params.set('ingress', ingress); if (egress) params.set('egress', egress); if (nextHop) params.set('nextHop', nextHop);
      } else { params.set('filter', expression); params.set('sortBy', sortBy); params.set('windowMode', windowMode); if (bucketNs) params.set('bucketNs', bucketNs); }
      const result = await investigationRequest<FlowReport>(fetcher, `${config.apiBaseUrl}/${endpoint}?${params}`);
      if (generation.current === requestGeneration) setReport(result);
    } catch (failure) { if (generation.current === requestGeneration) setError(failure instanceof Error ? errorText(failure) : i18nMessage("ui:m_67003645590f5daefec2")); }
    finally { if (generation.current === requestGeneration) setBusy(false); }
  };
  const download = async (id: string, direction: string) => {
    try {
      const params = new URLSearchParams(selection.replace(/^\?/, '')); params.set('id', id); params.set('direction', direction);
      const downloadURL = `${config.apiBaseUrl}/investigation/streams?${params}`;
      const filename = `${id}-${direction}.${direction === 'manifest' ? 'json' : 'bin'}`;
      if (downloadArtifact) { await downloadArtifact(downloadURL, filename); return; }
      const response = await fetcher(downloadURL);
      if (!response.ok) throw new Error(await response.text());
      const url = URL.createObjectURL(await response.blob()); const anchor = document.createElement('a');
      anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url);
    } catch (failure) { setError(failure instanceof Error ? errorText(failure) : i18nMessage("ui:m_57f98c7a0c92825af316")); }
  };
  return <Layout title={i18nText("ui:m_f37ff098317017d02ecd")} headerAction={<FileSelectorHeader inputFiles={files ?? []} status={status} switchingFile={switching} onFileChange={changeCapture} />}><Stack spacing={3}><AnalystWorkbench files={files ?? []} serviceMode={status?.isServiceMode} />{i18nRenderText(error) && <Alert severity="error">{i18nRenderText(error)}</Alert>}<Paper sx={{ p: 2 }}><Stack spacing={2}><Typography variant="h6" component="h2">{i18nText("ui:m_8d548cecd2e5cb178ae2")}</Typography>{captureError && <Alert severity="warning">{renderError(captureError)}</Alert>}{!capture && !captureError && <CircularProgress aria-label={i18nText("ui:m_0d9d81083611dc331d18")} />}{capture && <><Typography>{i18nRichText("ui:m_c13597168744f9b1b738", { arg0: capture.status, arg1: capture.ingressPackets, arg2: capture.admittedPackets, arg3: capture.queueDrops, arg4: capture.truncatedPackets })}</Typography><Typography>{i18nRichText("ui:m_fdd1f857c1606f3fc612", { arg0: capture.kernelReceived ?? i18nText("ui:m_ddddc9fec2c62ce5d4b3"), arg1: capture.kernelDrops ?? i18nText("ui:m_ddddc9fec2c62ce5d4b3") })}</Typography>{capture.error && <Alert severity="error">{capture.error}</Alert>}<Typography sx={{ overflowWrap: 'anywhere' }}>{i18nRichText("ui:m_d44781ad31c912a7f80c", { arg0: capture.inputSHA256 || i18nText("ui:m_eaf808272f5653e4cce4") })}</Typography><Typography sx={{ overflowWrap: 'anywhere' }}>{i18nRichText("ui:m_c46541d9e748755ee3e8", { arg0: capture.runId, arg1: capture.configSHA256 })}</Typography>{capture.limitations.map(text => <Typography key={text} variant="body2">{text}</Typography>)}<Typography>{i18nRichText("ui:m_c092a7b7d2717aef8d50", { arg0: capture.segments.filter(segment => segment.state === 'retained').length, arg1: capture.segments.filter(segment => segment.state === 'expired').length })}</Typography></>}<details><summary>{i18nText("ui:m_cf4374a707add42a81bf")}</summary>{ftpHealthError ? <Alert severity="warning">{renderError(ftpHealthError)}</Alert> : <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(ftpHealth ?? { status: 'loading' }, null, 2)}</pre>}</details><details><summary>{i18nText("ui:m_07450594ced84389abfe")}</summary>{reassemblyHealthError ? <Alert severity="warning">{renderError(reassemblyHealthError)}</Alert> : <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(reassemblyHealth ?? { status: 'loading' }, null, 2)}</pre>}</details></Stack></Paper><Paper sx={{ p: 2 }}><Stack spacing={2}><Typography variant="h6" component="h2">{i18nText("ui:m_156e97198bbf849c3119")}</Typography><Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><TextField select label={i18nText("ui:m_e7cb8469dad0acf2a072")} value={source} onChange={event => { setSource(event.target.value); setReport(null); setGroup('srcIP'); }}><MenuItem value="packet">{i18nText("ui:m_ee81ad0b9a5033884445")}</MenuItem><MenuItem value="export">{i18nText("ui:m_37e4048480b8ba5ebe35")}</MenuItem></TextField><TextField label={i18nText("ui:m_737a972dcffc05807ac0")} value={start} onChange={event => setStart(event.target.value)} fullWidth /><TextField label={i18nText("ui:m_5ac72507a929c60b2473")} value={end} onChange={event => setEnd(event.target.value)} fullWidth /></Stack>{source === 'packet' ? <TextField label={i18nText("ui:m_9b425213abbed2729260")} value={expression} onChange={event => setExpression(event.target.value)} fullWidth helperText={i18nText("ui:m_14897e70a050993d6c30")} /> : <Stack spacing={2} direction={{ xs: 'column', md: 'row' }}><TextField label={i18nText("ui:m_64e0c3718b80486f1fa6")} value={exporter} onChange={event => setExporter(event.target.value)} /><TextField label={i18nText("ui:m_64aadc7a48b551fe392c")} value={domain} onChange={event => setDomain(event.target.value)} /><TextField select label={i18nText("ui:m_260d7a6cb0402bc65698")} value={format} onChange={event => setFormat(event.target.value)}>{['netflow-v5', 'netflow-v9', 'ipfix', 'sflow-v5'].map(value => <MenuItem key={value} value={value}>{i18nText(value)}</MenuItem>)}</TextField><TextField select label={i18nText("ui:m_1e61a3a77e13f5b928c9")} value={basis} onChange={event => setBasis(event.target.value)}><MenuItem value="flow">{i18nText("ui:m_8f3312fdfb36a0e8d32d")}</MenuItem><MenuItem value="receive">{i18nText("ui:m_e2a69ee14cf70d216704")}</MenuItem></TextField></Stack>}<TextField select label={i18nText("ui:m_81301369a08ce10a3159")} value={group} onChange={event => setGroup(event.target.value)}>{(source === 'packet' ? ['srcIP', 'dstIP', 'dstPort', 'pair', 'hostPair', 'protocol'] : ['srcIP', 'dstIP', 'dstPort', 'protocol', 'ingress', 'egress', 'ingressEgress', 'srcAS', 'dstAS', 'srcPrefix', 'dstPrefix', 'nextHop']).map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}</TextField>{source === 'export' && <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><TextField label={i18nText("ui:m_a9f2b904029a6138e7ae")} value={ingress} onChange={event => setIngress(event.target.value)} /><TextField label={i18nText("ui:m_f515e473a9fb66e7d066")} value={egress} onChange={event => setEgress(event.target.value)} /><TextField label={i18nText("ui:m_b9da6e0003c476827c2e")} value={nextHop} onChange={event => setNextHop(event.target.value)} /></Stack>}{source === 'packet' && <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><TextField select label={i18nText("ui:m_5946d0555d777bf7009b")} value={sortBy} onChange={event => setSortBy(event.target.value)}>{['bytes', 'packets', 'records', 'peers', 'ports', 'duration', 'rate'].map(value => <MenuItem key={value} value={value}>{i18nText(value)}</MenuItem>)}</TextField><TextField select label={i18nText("ui:m_4d1b34a6af09a3c851ef")} value={windowMode} onChange={event => setWindowMode(event.target.value)}>{['overlap', 'contained', 'start', 'end'].map(value => <MenuItem key={value} value={value}>{i18nText(value)}</MenuItem>)}</TextField><TextField label={i18nText("ui:m_1218941dad9c93da5bcf")} value={bucketNs} onChange={event => setBucketNs(event.target.value)} helperText={i18nText("ui:m_a0dd33adbf761380423e")} fullWidth /></Stack>}<Box><Button variant="contained" disabled={busy || switching || !status} onClick={query}>{busy ? i18nText("ui:m_16e2aa8015fb5ffc9b48") : i18nText("ui:m_8b52eb31daa0dae16b1b")}</Button></Box>{report && <><Typography role="status">{i18nRichText("ui:m_6a18d583505384171513", { arg0: report.matchedObservations ?? report.matchedRecords ?? 0, arg1: report.totalGroups, arg2: report.unquantifiableRecords ?? 0 })}</Typography>{report.query && <details><summary>{i18nText("ui:m_350a7f24648861c25fd8")}</summary><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(report.query, null, 2)}</pre></details>}{report.limitations.map(text => <Alert key={text} severity="info">{text}</Alert>)}<Typography sx={{ overflowWrap: 'anywhere' }}>{i18nRichText("ui:m_d040674b2f930fccb9d5", { arg0: report.recordFileSHA256 ?? report.sourceSHA256 })}</Typography>{report.statistics && <Typography>{i18nRichText("ui:m_a17d6e4f2c431a121d4b", { arg0: report.statistics.bytes.min, arg1: report.statistics.bytes.median, arg2: report.statistics.bytes.p95, arg3: report.statistics.bytes.max, arg4: report.statistics.bytes.count })}</Typography>}<TableContainer><Table size="small" aria-label={i18nText("ui:m_61b5f1154a1e08dc0641")}><TableHead><TableRow><TableCell>{i18nText("ui:m_095fcc857c0ecaa94bb7")}</TableCell><TableCell>{i18nText("ui:m_dc58fb07f5e14e63a67b")}</TableCell><TableCell>{i18nText("ui:m_ebe2f7ca86cd1049725b")}</TableCell><TableCell>{i18nText("ui:m_b2d011fadace8b187b08")}</TableCell><TableCell>{i18nText("ui:m_51b08c2431c9f9861be4")}</TableCell></TableRow></TableHead><TableBody>{report.groups.map(row => <TableRow key={row.key}><TableCell>{row.key}</TableCell><TableCell>{row.bytes}</TableCell><TableCell>{row.packets}</TableCell><TableCell>{row.distinctPeers ?? row.peers}</TableCell><TableCell><details><summary>{i18nText("ui:m_a9eecda78c069c3ef094")}</summary><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(row.members ?? row.observationIds, null, 2)}</pre></details></TableCell></TableRow>)}</TableBody></Table></TableContainer>{!!report.series?.length && <TableContainer><Table size="small" aria-label={i18nText("ui:m_b155c3c06ffcd92640dd")}><TableHead><TableRow><TableCell>{i18nText("ui:m_565cc0392f60687a0da1")}</TableCell><TableCell>{i18nText("ui:m_ca4964f4ee0e8f8b4d2c")}</TableCell><TableCell>{i18nText("ui:m_f117630adedcb8de280a")}</TableCell><TableCell>{i18nText("ui:m_bead73a68ac752a2782f")}</TableCell><TableCell>{i18nText("ui:m_a8e73f34e1334356840e")}</TableCell></TableRow></TableHead><TableBody>{report.series.map(bin => <TableRow key={bin.startNs}><TableCell>{bin.startNs}</TableCell><TableCell>{bin.endNs}</TableCell><TableCell>{i18nNumber(bin.estimatedBytes, { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false })}</TableCell><TableCell>{i18nNumber(bin.estimatedBitsPerSecond, { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false })}</TableCell><TableCell>{bin.directionalComplete ? i18nText("ui:m_8dca807bfb9007101cfb") : i18nText("ui:m_7ffed0eaf3231e993c97")}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}</>}</Stack></Paper><Paper sx={{ p: 2 }}><Stack spacing={2}><Typography variant="h6" component="h2">{i18nText("ui:m_034440ee1657e83e8655")}</Typography>{streamError && <Alert severity="warning">{renderError(streamError)}</Alert>}<Typography>{i18nText("ui:m_ba093caa9523f93dc3b6")}</Typography>{streams?.length === 0 && <Typography>{i18nText("ui:m_f2a6f6f842d7581f3f3c")}</Typography>}{streams?.map(row => <Box key={row.id}><Typography sx={{ overflowWrap: 'anywhere' }}>{i18nRichText("ui:m_9337672dbf79341c4764", { arg0: row.manifest.protocol, arg1: row.manifest.connectionKey, arg2: row.manifest.status, arg3: row.spanCount })}</Typography><Stack direction="row" spacing={1} flexWrap="wrap">{['client', 'server', 'manifest'].map(direction => <Button key={direction} onClick={() => download(row.id, direction)}>{i18nRichText("ui:m_bd4def42785911911d91", { arg0: i18nText(direction) })}</Button>)}</Stack></Box>)}</Stack></Paper></Stack></Layout>;
}
