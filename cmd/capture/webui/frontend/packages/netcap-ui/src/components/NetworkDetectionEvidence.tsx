import { Alert as MuiAlert, Box, Button, Chip, Paper, Table, TableBody, TableCell, TableRow, Typography } from '@mui/material';
import type { Alert, NetworkDetectionStats } from '../lib/api';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { getLocale } from "../lib/i18n";
import { translate, formatQuantity, enumLabel } from "../lib/i18n";




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
  const __uiLocale = useUILocale();
  if (!stats) return <MuiAlert severity="info">{i18nRichText("ui:m_23abebd8a491c14760d3", { arg0: unavailable ? i18nText("ui:m_b36083a05d85f96160a2") : i18nText("ui:m_aa8290a1ba5668712897") })}</MuiAlert>;
  return <Paper variant="outlined" sx={{ p: 2 }} aria-label={i18nText("ui:m_9f45548af765955760a4")}><Typography variant="subtitle1" component="h2">{i18nText("ui:m_9f45548af765955760a4")}</Typography><Typography variant="body2">{i18nRichText("ui:m_f1e55d3053e42e6d01f9", { arg0: stats.active ? i18nText("ui:m_c6be2cc3788dab45d1c0") : i18nText("ui:m_37c1ee06fa9cd4e57570"), arg1: stats.events.toLocaleString(getUILocale()), arg2: stats.alerts.toLocaleString(getUILocale()) })}</Typography><Typography variant="body2">{stats.indicators ? i18nText("ui:m_6f8294e2bcf5aada2fb1", { arg0: stats.indicators }) : i18nText("ui:m_f42b4ee260ab536d98f2")}</Typography><Typography variant="body2">{i18nRichText("ui:m_3b67c06471a9a6d4415d", { arg0: stats.overflow, arg1: stats.late, arg2: stats.streamGaps })}</Typography>{(stats.error || stats.overflow || stats.late || stats.streamGaps) ? <MuiAlert severity="warning" sx={{ mt: 1 }}>{stats.error || i18nText("ui:m_5bb0f59593597eab326a")}</MuiAlert> : null}</Paper>;
}

export default function NetworkDetectionEvidence({ alert }: { alert: Alert }) {
  const __uiLocale = useUILocale();
  if (alert.recordType !== 'NetworkDetection') return null;
  const evidence = parseNetworkEvidence(alert.matchedRecord);
  if (!evidence) return <MuiAlert severity="warning">{i18nText("ui:m_8e6ea92dbb925f15fd01")}</MuiAlert>;
  const rows = [
    [evidence.detector === 'ssh.nonstandard-port' ? 'Observed / expected service port' : evidence.detector === 'c2.beacon' ? 'Connection starts examined / required' : 'Observed / threshold', `${evidence.observed.toLocaleString(getLocale())} / ${evidence.threshold.toLocaleString(getLocale())}`],
    ['Capture-time window', formatQuantity(evidence.windowNS / 1e9, 's')],
    ['First / last seen (UTC)', `${utc(evidence.firstSeen)} / ${utc(evidence.lastSeen)}`],
    ['Capture scope', translate("ui:m_02d809f066b91d07ca2f", { arg0: evidence.scope.sensor, arg1: evidence.scope.interface, arg2: evidence.scope.vlans?.join(', ') || enumLabel('untagged') })],
    ['Source endpoint', endpoint(alert.srcIP, alert.srcPort)],
    ['Destination endpoint', endpoint(alert.dstIP, alert.dstPort)],
    ['Domain', alert.domain || translate("ui:m_b6f62be183440dfdc4c4")],
  ];
  const download = () => {
    // Keep the original JSON string, including exact nanosecond integers.
    const blob = new Blob([JSON.stringify({ alertId: alert.alertId, detector: alert.ruleName, evidenceJSON: alert.matchedRecord }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = 'netcap-detection-evidence.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <Paper variant="outlined" sx={{ p: 2 }}><Typography variant="h6" component="h2">{i18nText("ui:m_5470d94a054f482f6df1")}</Typography><Chip variant="outlined" label={i18nText(labels[evidence.classification])} sx={{ mt: 1, mb: 1 }} /><Table size="small" aria-label={i18nText("ui:m_9bd518a741bae786f019")}><TableBody>{rows.map(([label, value]) => <TableRow key={label}><TableCell component="th" scope="row">{i18nText(label)}</TableCell><TableCell sx={{ overflowWrap: 'anywhere' }}>{value}</TableCell></TableRow>)}</TableBody></Table>{evidence.indicator && <Box sx={{ mt: 2 }}><Typography variant="subtitle2">{i18nText("ui:m_151c7aef90250f24b404")}</Typography><Typography variant="body2">{i18nRichText("ui:m_5c2da4cca4cee0af647e", { arg0: evidence.indicator.value, arg1: evidence.indicator.source, arg2: String(evidence.indicator.version) })}</Typography><Typography variant="body2">{i18nRichText("ui:m_118c695f04e68b58338d", { arg0: utc(evidence.indicator.validFrom), arg1: utc(evidence.indicator.validUntil) })}</Typography></Box>}<Typography variant="subtitle2" sx={{ mt: 2 }}>{i18nText("ui:m_92b9da41fab19e324075")}</Typography><Box component="ul" sx={{ my: 1, pl: 3 }}>{evidence.samples.map(sample => <Typography component="li" variant="body2" key={sample} sx={{ overflowWrap: 'anywhere' }}>{sample}</Typography>)}</Box><Typography variant="subtitle2">{i18nText("ui:m_1e675223a0a9e4a171ce")}</Typography><Box component="ul" sx={{ my: 1, pl: 3 }}>{evidence.limitations.map(limit => <Typography component="li" variant="body2" key={limit}>{limit}</Typography>)}</Box><Button onClick={download}>{i18nText("ui:m_e678f5e3a63330d20973")}</Button></Paper>;
}
