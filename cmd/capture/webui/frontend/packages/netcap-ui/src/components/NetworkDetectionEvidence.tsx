import { Alert as MuiAlert, Box, Button, Chip, Paper, Table, TableBody, TableCell, TableRow, Typography } from '@mui/material';
import type { Alert, NetworkDetectionStats } from '../lib/api';

interface Evidence {
  schema: number;
  detector: string;
  classification: 'indicator-match' | 'behavioral-suspicion' | 'policy-observation';
  scope: { sensor: string; interface: string; vlans?: number[] };
  firstSeen: number;
  lastSeen: number;
  observed: number;
  threshold: number;
  windowNS: number;
  samples: string[];
  limitations: string[];
  indicator?: { value: string; source: string; version: string; validFrom: number; validUntil: number };
}

export function parseNetworkEvidence(raw: string): Evidence | null {
  try {
    if (raw.length > 1 << 20) return null;
    const e = JSON.parse(raw);
    if (e.schema !== 1 || typeof e.detector !== 'string' || !['indicator-match', 'behavioral-suspicion', 'policy-observation'].includes(e.classification) ||
      typeof e.scope?.sensor !== 'string' || typeof e.scope?.interface !== 'string' ||
      ![e.firstSeen, e.lastSeen, e.observed, e.threshold, e.windowNS].every(v => typeof v === 'number' && Number.isFinite(v) && v >= 0) ||
      !Array.isArray(e.samples) || e.samples.length > 8 || !e.samples.every((v: unknown) => typeof v === 'string') ||
      !Array.isArray(e.limitations) || e.limitations.length > 16 || !e.limitations.every((v: unknown) => typeof v === 'string') ||
      ![e.firstSeen, e.lastSeen].every(v => Number.isFinite(new Date(v / 1e6).getTime())) ||
      (e.scope.vlans !== undefined && (!Array.isArray(e.scope.vlans) || e.scope.vlans.length > 4 || !e.scope.vlans.every((v: unknown) => Number.isInteger(v) && Number(v) >= 0 && Number(v) <= 4095)))) return null;
    if (e.indicator && (![e.indicator.value, e.indicator.source, e.indicator.version].every(v => typeof v === 'string') ||
      ![e.indicator.validFrom, e.indicator.validUntil].every(v => typeof v === 'number' && Number.isFinite(new Date(v / 1e6).getTime())))) return null;
    return e;
  } catch { return null; }
}

const utc = (ns: number) => new Date(ns / 1e6).toISOString();
const labels = { 'indicator-match': 'Indicator match', 'behavioral-suspicion': 'Behavioral suspicion', 'policy-observation': 'Policy observation' };
const endpoint = (ip: string, port?: string) => `${ip.includes(':') ? `[${ip}]` : ip}:${port && port !== '0' ? port : 'unavailable'}`;

export function NetworkDetectionCoverage({ stats, unavailable }: { stats?: NetworkDetectionStats; unavailable: boolean }) {
  if (!stats) return <MuiAlert severity="info">Network detection coverage {unavailable ? 'unavailable for this capture' : 'is loading'}. Absence of alerts does not establish a clean capture.</MuiAlert>;
  return <Paper variant="outlined" sx={{ p: 2 }} aria-label="Network detection coverage">
    <Typography variant="subtitle1" component="h2">Network detection coverage</Typography>
    <Typography variant="body2">{stats.active ? 'Capturing' : 'Retained replay status'} · {stats.events.toLocaleString()} evaluated events · {stats.alerts.toLocaleString()} findings</Typography>
    <Typography variant="body2">{stats.indicators ? `${stats.indicators} configured indicators; validity is checked against capture time` : 'No indicators configured: C2, sinkhole and imposter intelligence coverage is unavailable.'}</Typography>
    <Typography variant="body2">State overflow: {stats.overflow} · Late events skipped: {stats.late} · Stream gaps: {stats.streamGaps}</Typography>
    {(stats.error || stats.overflow || stats.late || stats.streamGaps) ? <MuiAlert severity="warning" sx={{ mt: 1 }}>{stats.error || 'Evidence is incomplete; review capture loss, ordering and detector limits.'}</MuiAlert> : null}
  </Paper>;
}

export default function NetworkDetectionEvidence({ alert }: { alert: Alert }) {
  if (alert.recordType !== 'NetworkDetection') return null;
  const evidence = parseNetworkEvidence(alert.matchedRecord);
  if (!evidence) return <MuiAlert severity="warning">Network detection evidence is unavailable or uses an unsupported schema. The original alert remains available below.</MuiAlert>;
  const rows = [
    [evidence.detector === 'ssh.nonstandard-port' ? 'Observed / expected service port' : 'Observed / threshold', `${evidence.observed.toLocaleString()} / ${evidence.threshold.toLocaleString()}`],
    ['Capture-time window', `${evidence.windowNS / 1e9} seconds`],
    ['First / last seen (UTC)', `${utc(evidence.firstSeen)} / ${utc(evidence.lastSeen)}`],
    ['Capture scope', `${evidence.scope.sensor} / ${evidence.scope.interface} / VLANs ${evidence.scope.vlans?.join(', ') || 'untagged'}`],
    ['Source endpoint', endpoint(alert.srcIP, alert.srcPort)],
    ['Destination endpoint', endpoint(alert.dstIP, alert.dstPort)],
    ['Domain', alert.domain || 'Unavailable'],
  ];
  const download = () => {
    // Keep the original JSON string, including exact nanosecond integers.
    const blob = new Blob([JSON.stringify({ alertId: alert.alertId, detector: alert.ruleName, evidenceJSON: alert.matchedRecord }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = 'netcap-detection-evidence.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <Paper variant="outlined" sx={{ p: 2 }}>
    <Typography variant="h6" component="h2">Why this finding fired</Typography>
    <Chip variant="outlined" label={labels[evidence.classification]} sx={{ mt: 1, mb: 1 }} />
    <Table size="small" aria-label="Detection evidence"><TableBody>{rows.map(([label, value]) => <TableRow key={label}><TableCell component="th" scope="row">{label}</TableCell><TableCell sx={{ overflowWrap: 'anywhere' }}>{value}</TableCell></TableRow>)}</TableBody></Table>
    {evidence.indicator && <Box sx={{ mt: 2 }}><Typography variant="subtitle2">Indicator provenance</Typography><Typography variant="body2">{evidence.indicator.value} · {evidence.indicator.source} · version {evidence.indicator.version}</Typography><Typography variant="body2">Valid {utc(evidence.indicator.validFrom)} to {utc(evidence.indicator.validUntil)} (capture time)</Typography></Box>}
    <Typography variant="subtitle2" sx={{ mt: 2 }}>Evidence samples (up to 8)</Typography>
    <Box component="ul" sx={{ my: 1, pl: 3 }}>{evidence.samples.map(sample => <Typography component="li" variant="body2" key={sample} sx={{ overflowWrap: 'anywhere' }}>{sample}</Typography>)}</Box>
    <Typography variant="subtitle2">Interpretation limits</Typography>
    <Box component="ul" sx={{ my: 1, pl: 3 }}>{evidence.limitations.map(limit => <Typography component="li" variant="body2" key={limit}>{limit}</Typography>)}</Box>
    <Button onClick={download}>Export original evidence JSON</Button>
  </Paper>;
}
