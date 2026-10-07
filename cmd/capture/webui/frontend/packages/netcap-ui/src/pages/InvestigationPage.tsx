import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, CircularProgress, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import useSWR from 'swr';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { useNetcapApi } from '../hooks';
import { useNetcapConfig } from '../providers';
import { behaviorRequest, behaviorSelection } from '../lib/behavior';

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

export default function InvestigationPage() {
  const api = useNetcapApi();
  const config = useNetcapConfig();
  const fetcher = config.fetch ?? fetch;
  const { data: status, mutate: refreshStatus } = useSWR('status', () => api.getStatus());
  const { data: files } = useSWR('inputFiles', () => api.getInputFiles());
  const selection = behaviorSelection(status, files);
  const captureURL = `${config.apiBaseUrl}/investigation/capture${selection}`;
  const streamURL = `${config.apiBaseUrl}/investigation/streams${selection}`;
  const { data: capture, error: captureError } = useSWR<CaptureManifest>(status ? captureURL : null, () => behaviorRequest(fetcher, captureURL), { keepPreviousData: false });
  const { data: streams, error: streamError } = useSWR<StreamRow[]>(status ? streamURL : null, () => behaviorRequest(fetcher, streamURL), { keepPreviousData: false });
  const [source, setSource] = useState('packet');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [expression, setExpression] = useState('');
  const [exporter, setExporter] = useState('');
  const [domain, setDomain] = useState('');
  const [format, setFormat] = useState('netflow-v9');
  const [basis, setBasis] = useState('flow');
  const [group, setGroup] = useState('srcIP');
  const [windowMode, setWindowMode] = useState('overlap');
  const [bucketNs, setBucketNs] = useState('');
  const [report, setReport] = useState<FlowReport | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [switching, setSwitching] = useState(false);
  const generation = useRef(0);
  useEffect(() => { generation.current++; setReport(null); setError(''); setBusy(false); setStart(''); setEnd(''); }, [selection]);
  useEffect(() => { if (capture) { setStart(capture.firstNs ?? ''); setEnd(capture.lastNs ?? ''); } }, [capture]);
  const changeCapture = async (path: string) => {
    setSwitching(true);
    try { const result = await api.setActiveDirectory(path); await refreshStatus(); window.dispatchEvent(new CustomEvent('directory-changed', { detail: result })); }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'Capture switch failed'); }
    finally { setSwitching(false); }
  };
  const query = async () => {
    const requestGeneration = ++generation.current;
    setReport(null); setError(''); setBusy(true);
    try {
      if (!/^-?\d+$/.test(start) || !/^-?\d+$/.test(end) || BigInt(start) > BigInt(end)) throw new Error('Enter an ordered pair of UTC nanosecond integers.');
      const params = new URLSearchParams(selection.replace(/^\?/, ''));
      params.set('startNs', start); params.set('endNs', end); params.set('groupBy', group); params.set('limit', '100');
      let endpoint = 'flows/query';
      if (source === 'export') {
        if (!exporter || !/^\d+$/.test(domain)) throw new Error('Exporter IP:port and observation domain are required.');
        endpoint = 'flows/exports/query'; params.set('exporter', exporter); params.set('domain', domain); params.set('format', format); params.set('timeBasis', basis);
      } else { params.set('filter', expression); params.set('sortBy', 'bytes'); params.set('windowMode', windowMode); if (bucketNs) params.set('bucketNs', bucketNs); }
      const result = await behaviorRequest<FlowReport>(fetcher, `${config.apiBaseUrl}/${endpoint}?${params}`);
      if (generation.current === requestGeneration) setReport(result);
    } catch (failure) { if (generation.current === requestGeneration) setError(failure instanceof Error ? failure.message : 'Query failed'); }
    finally { if (generation.current === requestGeneration) setBusy(false); }
  };
  const download = async (id: string, direction: string) => {
    try {
      const params = new URLSearchParams(selection.replace(/^\?/, '')); params.set('id', id); params.set('direction', direction);
      const response = await fetcher(`${config.apiBaseUrl}/investigation/streams?${params}`);
      if (!response.ok) throw new Error(await response.text());
      const url = URL.createObjectURL(await response.blob()); const anchor = document.createElement('a');
      anchor.href = url; anchor.download = `${id}-${direction}.${direction === 'manifest' ? 'json' : 'bin'}`; anchor.click(); URL.revokeObjectURL(url);
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'Download failed'); }
  };
  return <Layout title="Investigation evidence" headerAction={<FileSelectorHeader inputFiles={files ?? []} status={status} switchingFile={switching} onFileChange={changeCapture} />}>
    <Stack spacing={3}>
      {error && <Alert severity="error">{error}</Alert>}
      <Paper sx={{ p: 2 }}><Stack spacing={2}>
        <Typography variant="h6" component="h2">Capture provenance and coverage</Typography>
        {captureError && <Alert severity="warning">{captureError.message}</Alert>}
        {!capture && !captureError && <CircularProgress aria-label="Loading capture provenance" />}
        {capture && <>
          <Typography>Status: {capture.status} · Ingress: {capture.ingressPackets} · Admitted: {capture.admittedPackets} · Queue drops: {capture.queueDrops} · Truncated: {capture.truncatedPackets}</Typography>
          <Typography>Kernel received: {capture.kernelReceived ?? 'unavailable'} · Kernel drops: {capture.kernelDrops ?? 'unavailable'}</Typography>
          {capture.error && <Alert severity="error">{capture.error}</Alert>}
          <Typography sx={{ overflowWrap: 'anywhere' }}>Input SHA-256: {capture.inputSHA256 || 'unavailable for live input'}</Typography>
          <Typography sx={{ overflowWrap: 'anywhere' }}>Run: {capture.runId} · Configuration SHA-256: {capture.configSHA256}</Typography>
          {capture.limitations.map(text => <Typography key={text} variant="body2">{text}</Typography>)}
          <Typography>Packet segments: {capture.segments.filter(segment => segment.state === 'retained').length} retained, {capture.segments.filter(segment => segment.state === 'expired').length} expired</Typography>
        </>}
      </Stack></Paper>
      <Paper sx={{ p: 2 }}><Stack spacing={2}>
        <Typography variant="h6" component="h2">Scoped flow investigation</Typography>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <TextField select label="Data source" value={source} onChange={event => { setSource(event.target.value); setReport(null); setGroup('srcIP'); }}><MenuItem value="packet">Packet-derived connections</MenuItem><MenuItem value="export">Router-exported flows</MenuItem></TextField>
          <TextField label="Start UTC nanoseconds" value={start} onChange={event => setStart(event.target.value)} fullWidth />
          <TextField label="End UTC nanoseconds" value={end} onChange={event => setEnd(event.target.value)} fullWidth />
        </Stack>
        {source === 'packet' ? <TextField label="Connection filter expression" value={expression} onChange={event => setExpression(event.target.value)} fullWidth helperText={'Example: InSubnet(SrcIP, "192.0.2.0/24") && ParsePort(DstPort) == 443'} /> : <Stack spacing={2} direction={{ xs: 'column', md: 'row' }}>
          <TextField label="Exporter IP:port" value={exporter} onChange={event => setExporter(event.target.value)} />
          <TextField label="Observation domain" value={domain} onChange={event => setDomain(event.target.value)} />
          <TextField select label="Export format" value={format} onChange={event => setFormat(event.target.value)}>{['netflow-v5', 'netflow-v9', 'ipfix', 'sflow-v5'].map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}</TextField>
          <TextField select label="Time basis" value={basis} onChange={event => setBasis(event.target.value)}><MenuItem value="flow">Exported flow time</MenuItem><MenuItem value="receive">Datagram receive time</MenuItem></TextField>
        </Stack>}
        <TextField select label="Group by" value={group} onChange={event => setGroup(event.target.value)}>{(source === 'packet' ? ['srcIP', 'dstIP', 'dstPort', 'pair', 'protocol'] : ['srcIP', 'dstIP', 'dstPort', 'protocol', 'ingress', 'egress', 'srcAS', 'dstAS', 'nextHop']).map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}</TextField>
        {source === 'packet' && <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <TextField select label="Time-window match" value={windowMode} onChange={event => setWindowMode(event.target.value)}>{['overlap', 'contained', 'start', 'end'].map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}</TextField>
          <TextField label="Estimated series bin width (nanoseconds)" value={bucketNs} onChange={event => setBucketNs(event.target.value)} helperText="Optional; uniform-over-duration estimates, not observed packet-bin rates. Maximum 4096 bins." fullWidth />
        </Stack>}
        <Box><Button variant="contained" disabled={busy || switching || !status} onClick={query}>{busy ? 'Querying…' : 'Run scoped query'}</Button></Box>
        {report && <>
          <Typography role="status">Matched {report.matchedObservations ?? report.matchedRecords ?? 0} observations; {report.totalGroups} groups; {report.unquantifiableRecords ?? 0} unquantifiable records.</Typography>
          {report.query && <details><summary>Executed query</summary><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(report.query, null, 2)}</pre></details>}
          {report.limitations.map(text => <Alert key={text} severity="info">{text}</Alert>)}
          <Typography sx={{ overflowWrap: 'anywhere' }}>Record-file SHA-256: {report.recordFileSHA256 ?? report.sourceSHA256}</Typography>
          {report.statistics && <Typography>Observed byte distribution: minimum {report.statistics.bytes.min}, median {report.statistics.bytes.median}, 95th percentile {report.statistics.bytes.p95}, maximum {report.statistics.bytes.max} ({report.statistics.bytes.count} observations).</Typography>}
          <TableContainer><Table size="small" aria-label="Flow investigation results"><TableHead><TableRow><TableCell>Group</TableCell><TableCell>Bytes</TableCell><TableCell>Packets</TableCell><TableCell>Peers</TableCell><TableCell>Evidence identifiers</TableCell></TableRow></TableHead>
            <TableBody>{report.groups.map(row => <TableRow key={row.key}><TableCell>{row.key}</TableCell><TableCell>{row.bytes}</TableCell><TableCell>{row.packets}</TableCell><TableCell>{row.distinctPeers ?? row.peers}</TableCell><TableCell><details><summary>Record references</summary><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(row.members ?? row.observationIds, null, 2)}</pre></details></TableCell></TableRow>)}</TableBody>
          </Table></TableContainer>
          {!!report.series?.length && <TableContainer><Table size="small" aria-label="Estimated flow time series"><TableHead><TableRow><TableCell>Start (UTC ns)</TableCell><TableCell>End (UTC ns)</TableCell><TableCell>Estimated bytes</TableCell><TableCell>Estimated bit/s</TableCell><TableCell>Directional counters</TableCell></TableRow></TableHead><TableBody>{report.series.map(bin => <TableRow key={bin.startNs}><TableCell>{bin.startNs}</TableCell><TableCell>{bin.endNs}</TableCell><TableCell>{bin.estimatedBytes.toFixed(2)}</TableCell><TableCell>{bin.estimatedBitsPerSecond.toFixed(2)}</TableCell><TableCell>{bin.directionalComplete ? 'Available for matched observations' : 'Incomplete'}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}
        </>}
      </Stack></Paper>
      <Paper sx={{ p: 2 }}><Stack spacing={2}>
        <Typography variant="h6" component="h2">Directional stream artifacts</Typography>
        {streamError && <Alert severity="warning">{streamError.message}</Alert>}
        <Typography>Download byte-exact directions with the manifest. Gaps and datagram boundaries must be read from the manifest before parsing or replay.</Typography>
        {streams?.length === 0 && <Typography>No saved stream artifacts in this analysis.</Typography>}
        {streams?.map(row => <Box key={row.id}><Typography sx={{ overflowWrap: 'anywhere' }}>{row.manifest.protocol} · {row.manifest.connectionKey} · {row.manifest.status} · {row.spanCount} spans</Typography><Stack direction="row" spacing={1} flexWrap="wrap">{['client', 'server', 'manifest'].map(direction => <Button key={direction} onClick={() => download(row.id, direction)}>Download {direction}</Button>)}</Stack></Box>)}
      </Stack></Paper>
    </Stack>
  </Layout>;
}
