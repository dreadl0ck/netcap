import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Alert, Box, Button, Checkbox, Chip, CircularProgress, Dialog, DialogActions, DialogContent,
  DialogTitle, FormControl, InputLabel, MenuItem, Paper, Select, Stack, Tab, Table, TableBody,
  TableCell, TableContainer, TableHead, TablePagination, TableRow, Tabs, TextField, Typography } from '@mui/material';

import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import BehaviorRecordContext from '../components/BehaviorRecordContext';
import { ChartFrame } from '../components/ChartFrame';
import { useNetcapApi, useNetcapRouter } from '../hooks';
import { useNetcapConfig } from '../providers';
import { useLiveAlerts } from '../hooks/useLiveAlerts';
import { assetObservations, behaviorRequest, behaviorSelection, factLabel, learningReady, scopeLabel } from '../lib/behavior';
import type { BehaviorAction, BehaviorHealth, BehaviorSnapshot, BehaviorTopology } from '../lib/behavior';
import { message as i18nMessage, translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, getLocale as getUILocale, formatNumber as i18nNumber, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { translate, renderError } from "../lib/i18n";
import { getLocale } from "../lib/i18n";
import { errorText, enumLabel } from "../lib/i18n";
import { behaviorActionLabel } from '../lib/i18n';







const timeLabel = (ns: number) => ns > 0 ? new Date(ns / 1e6).toLocaleString(getLocale()) : translate("ui:m_0d9c20aba60b11767d16");

export interface BehaviorPageProps {
  renderEvidenceActions?: (evidence: string) => ReactNode;
}

export default function BehaviorPage({ renderEvidenceActions }: BehaviorPageProps = {}) {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const router = useNetcapRouter();
  const config = useNetcapConfig();
  const fetcher = config.fetch ?? fetch;
  const { data: status, mutate: refreshStatus } = useSWR('status', () => api.getStatus(), { refreshInterval: 1000 });
  const { data: files } = useSWR('inputFiles', () => api.getInputFiles());
  const selection = behaviorSelection(status, files);
  const url = `${config.apiBaseUrl}/behavior${selection}`;
  const { data, error, mutate } = useSWR<BehaviorSnapshot>(status ? url : null,
    () => behaviorRequest(fetcher, url), { refreshInterval: 1000, keepPreviousData: false });
  const [tab, setTab] = useState(0);
  const [scope, setScope] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [action, setAction] = useState<BehaviorAction | null>(null);
  const [decisionVersion, setDecisionVersion] = useState<number | null>(null);
  const [decisionIDs, setDecisionIDs] = useState<string[]>([]);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [switching, setSwitching] = useState(false);
  const [failure, setFailure] = useState<UIMessageText>('');
  const [restart, setRestart] = useState(0);
  const [evidence, setEvidence] = useState<string | null>(null);
  const [evidenceAlertID, setEvidenceAlertID] = useState<string | null>(null);
  const [graphGeneration, setGraphGeneration] = useState(0);
  const [inventory, setInventory] = useState<{ id: string; version: number; name: string; role: string; notes: string; prefix: string; isPrefix: boolean; reason: string } | null>(null);
  const live = useLiveAlerts(status && tab === 2 ? `${config.apiBaseUrl}/alerts/stream${selection}` : null, restart);

  useEffect(() => { setSelected([]); setPage(0); setScope(''); setAction(null); setInventory(null); setFailure(''); setEvidence(null); setEvidenceAlertID(null); }, [selection]);
  useEffect(() => { setSelected([]); }, [data?.version]);

  const asset = typeof router.query.asset === 'string' ? router.query.asset : '';
  useEffect(() => { setPage(0); setSelected([]); setScope(''); setSearch(''); }, [asset]);
  const rows = useMemo(() => (data ? assetObservations(data, asset) : []).sort(([a], [b]) => a.localeCompare(b)), [data, asset]);
  const scopes = useMemo(() => [...new Set(rows.map(([, observation]) => scopeLabel(observation.fact.scope)))].sort(), [rows]);
  const visible = useMemo(() => rows.filter(([id, observation]) => {
    if (scope && scopeLabel(observation.fact.scope) !== scope) return false;
    if (tab === 1 && (data?.approved[id] || data?.suppressed[id])) return false;
    return `${observation.fact.kind} ${factLabel(observation.fact)} ${scopeLabel(observation.fact.scope)}`.toLowerCase().includes(search.toLowerCase());
  }), [rows, scope, search, tab, data?.approved, data?.suppressed]);
  const elapsed = data ? Math.max(0, (data.watermark - data.learningStarted) / 1e9) : 0;
  const graphScope = scope ? rows.find(([, observation]) => scopeLabel(observation.fact.scope) === scope)?.[1].fact.scope : undefined;
  const graphURL = `${config.apiBaseUrl}/behavior/topology${selection || '?'}${selection ? '&' : ''}maxNodes=100${graphScope ? `&scope=${encodeURIComponent(JSON.stringify(graphScope))}` : ''}`;
  const { data: topology } = useSWR<BehaviorTopology>(status && tab === 4 ? [graphURL, graphGeneration, data?.version] : null,
    () => behaviorRequest(fetcher, graphURL), { refreshInterval: 30000 });
  const healthURL = `${config.apiBaseUrl}/behavior/health${selection}`;
  const { data: health, error: healthError } = useSWR<BehaviorHealth>(status && tab === 5 ? healthURL : null,
    () => behaviorRequest(fetcher, healthURL), { refreshInterval: 1000, keepPreviousData: false });

  const changeCapture = async (path: string) => {
    setSwitching(true);
    try {
      const result = await api.setActiveDirectory(path);
      await refreshStatus();
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
    } catch (error) { setFailure(error instanceof Error ? errorText(error) : i18nMessage("ui:m_05bbfcab9a0907cba25b")); }
    finally { setSwitching(false); }
  };

  const apply = async () => {
    if (!data || !action || decisionVersion === null || !reason.trim()) return;
    setBusy(true);
    setFailure('');
    try {
      const snapshot = await behaviorRequest<BehaviorSnapshot>(fetcher, `${config.apiBaseUrl}/behavior/change${selection}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, ids: decisionIDs, reason: reason.trim(), version: decisionVersion }),
      });
      await mutate(snapshot, false);
      setAction(null); setReason(''); setSelected([]);
    } catch (error) {
      setFailure(error instanceof Error ? errorText(error) : i18nMessage("ui:m_33247a0a32851dd47b8f"));
      await mutate();
    } finally { setBusy(false); }
  };

  const openAction = (next: BehaviorAction, ids = selected) => {
    if (!data) return;
    setReason(''); setAction(next); setDecisionVersion(data.version); setDecisionIDs([...ids]); setFailure('');
  };
  const selectionAction = (next: BehaviorAction, label: string) => <Button disabled={!selected.length || data?.mode !== 'monitoring' || busy}
    onClick={() => openAction(next)}>{label}</Button>;
  const saveInventory = async () => {
    if (!inventory || !inventory.reason.trim()) return;
    setBusy(true); setFailure('');
    try {
      const snapshot = await behaviorRequest<BehaviorSnapshot>(fetcher, `${config.apiBaseUrl}/behavior/change${selection}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
          action: 'inventory', version: inventory.version, reason: inventory.reason.trim(),
          inventory: { id: inventory.id, name: inventory.name, role: inventory.role, notes: inventory.notes, ...(inventory.isPrefix ? { prefix: inventory.prefix } : {}) },
        }),
      });
      await mutate(snapshot, false); setInventory(null); setGraphGeneration(value => value + 1);
    } catch (error) { setFailure(error instanceof Error ? errorText(error) : i18nMessage("ui:m_c5b2866d4db0db99a061")); }
    finally { setBusy(false); }
  };

  return <Layout title={i18nText("ui:m_4f83f7579546155ba5c9")} headerAction={<FileSelectorHeader inputFiles={files ?? []} status={status}
    switchingFile={switching} onFileChange={changeCapture} />}><Stack spacing={2} sx={{ minWidth: 0 }}><Typography color="text.secondary">{i18nText("ui:m_b90c6a1e56dc4194dfe8")}</Typography>{asset && <Alert severity="info">{i18nRichText("ui:m_9aeccb7dcc417d508602", { arg0: asset })}</Alert>}{i18nRenderText(failure) && <Alert severity="error">{i18nRenderText(failure)}</Alert>}{error && <Alert severity="warning">{renderError(error)}</Alert>}{!data && !error && <CircularProgress aria-label={i18nText("ui:m_e4101613aba3e8656c27")} />}{data && <>{data.error && <Alert severity="error">{i18nRichText("ui:m_36e6f9336c6907873e9f", { arg0: data.error })}</Alert>}{!!data.overflow && <Alert severity="warning">{i18nRichText("ui:m_6bd730030a691415627f", { arg0: data.overflow })}</Alert>}{!!data.windowOverflow && <Alert severity="warning">{i18nRichText("ui:m_f05340cd2371fdaafdfd", { arg0: data.windowOverflow })}</Alert>}<Paper sx={{ p: 2 }}><Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" alignItems="center"><Chip label={enumLabel(data.mode)} color={data.mode === 'monitoring' && !data.error ? 'success' : 'default'} /><Chip label={i18nText("ui:m_a95ce61029ee56b79b22", { arg0: String(data.version) })} variant="outlined" /><Typography variant="body2">{i18nRichText("ui:m_dfe981d156352ba02d6a", { arg0: data.samples, arg1: Object.keys(data.observed).length.toLocaleString(getUILocale()), arg2: data.maxFacts.toLocaleString(getUILocale()), arg3: Object.keys(data.approved).length.toLocaleString(getUILocale()) })}</Typography></Stack><Typography variant="body2" sx={{ mt: 1 }}>{i18nRichText("ui:m_79b0e054d2adeaa81442", { arg0: i18nNumber((elapsed / 3600), { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false }), arg1: i18nNumber((data.minLearningNS / 3.6e12), { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false }), arg2: data.samples, arg3: data.minSamples })}</Typography><Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>{i18nRichText("ui:m_edabc107fa632585b3ac", { arg0: data.baselineId || i18nText("ui:m_8f1b9f09467cf58b5b46"), arg1: data.outOfOrder })}</Typography>{data.policy && <Typography variant="body2">{i18nRichText("ui:m_43589f8c471c43e5e0f1", { arg0: data.policy.windowNS / 1e9, arg1: data.policy.fanout, arg2: data.policy.rdpAttempts, arg3: Object.keys(data.approvedRates ?? {}).length })}</Typography>}{data.policy && <Box sx={{ mt: 1 }}><Typography variant="subtitle2">{i18nText("ui:m_d3b94eedb5e16b320702")}</Typography><Typography variant="body2">{i18nRichText("ui:m_f87ed2ecd6f5c5c088a8", { arg0: data.policy.deniedCountries?.join(', ') || i18nText("ui:m_7f34e5ba4975f4edbf68"), arg1: data.policy.deniedASNs?.join(', ') || i18nText("ui:m_7f34e5ba4975f4edbf68") })}</Typography><Typography variant="body2">{i18nRichText("ui:m_b390c199782a13f8aae9", { arg0: data.policy.approvedSources?.join(', ') || i18nText("ui:m_7f34e5ba4975f4edbf68") })}</Typography>{data.policy.maintenance?.map((window, index) => <Typography key={index} variant="body2">{i18nRichText("ui:m_fa02fb666e8d7ec5a62e", { arg0: window.source || i18nText("ui:m_cf67178df4e27c6c6a9f"), arg1: new Date(window.start / 1e6).toISOString(), arg2: new Date(window.end / 1e6).toISOString() })}</Typography>)}<Typography variant="caption">{i18nText("ui:m_298cb4a7019b3d49b80d")}</Typography></Box>}<Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 1 }}><Button variant="contained" disabled={!learningReady(data) || busy} onClick={() => openAction('approve')}>{i18nText("ui:m_142c9578d24a21a3a135")}</Button><Button disabled={busy || !!data.error} onClick={() => openAction(data.mode === 'paused' ? 'resume' : 'pause')}>{data.mode === 'paused' ? i18nText("ui:m_de36964e435045200477") : i18nText("ui:m_eb0ab641d711f8bc7343")}</Button><Button disabled={busy || !!data.error} onClick={() => openAction('relearn')}>{i18nText("ui:m_989b1f907789f9c792e5")}</Button><Button color="warning" disabled={busy || !!data.error} onClick={() => openAction('reset')}>{i18nText("ui:m_615d762229e917ced070")}</Button><Button onClick={() => void mutate()}>{i18nText("ui:m_230fc1b63eb3ef4e6a34")}</Button></Stack></Paper><Tabs value={tab} onChange={(_, value: number) => { setTab(value); setPage(0); }} variant="scrollable" scrollButtons="auto" aria-label={i18nText("ui:m_a8b58ccb8992eb9f4591")}><Tab label={i18nText("ui:m_ec7aaa87e7ec86903755")} /><Tab label={i18nText("ui:m_52acb88499c575ba46dd")} /><Tab label={i18nText("ui:m_55e0ebdd1513df968ae5")} /><Tab label={i18nText("ui:m_18b0762f50433aa2eac7")} /><Tab label={i18nText("ui:m_a70e97f3ef54a82d5cdd")} /><Tab label={i18nText("ui:m_c11a4aac1eb42be5ff73")} /></Tabs>{tab < 2 && <><Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}><TextField label={i18nText("ui:m_352f1bf041976a36b804")} value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} size="small" /><FormControl size="small" sx={{ minWidth: 240 }}><InputLabel id="behavior-scope-label">{i18nText("ui:m_a8b5eb7ab131963a7007")}</InputLabel><Select labelId="behavior-scope-label" label={i18nText("ui:m_a8b5eb7ab131963a7007")} value={scope} onChange={event => { setScope(event.target.value); setPage(0); }}><MenuItem value="">{i18nText("ui:m_8a69bd170bb418d6084a")}</MenuItem>{scopes.map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}</Select></FormControl></Stack><Stack direction="row" useFlexGap flexWrap="wrap" spacing={1}><Typography variant="body2" sx={{ alignSelf: 'center' }}>{i18nRichText("ui:m_886d890955da8ab7b08b", { arg0: selected.length })}</Typography>{selectionAction('acknowledge', translate("ui:m_2dc65b9fbcd55d0daefc"))}{selectionAction('approve-changes', translate("ui:m_2b75b26e612e971c1990"))}{selectionAction('suppress', translate("ui:m_a8015b7b23016f8e992e"))}{selectionAction('unsuppress', translate("ui:m_0d45c3f5e69348aa090c"))}</Stack><TableContainer component={Paper}><Table size="small" aria-label={i18nText("ui:m_dfd18162585a4f4bd349")}><TableHead><TableRow><TableCell>{i18nText("ui:m_4330263f08017d328afb")}</TableCell><TableCell>{i18nText("ui:m_db0a5b964187d4e8da80")}</TableCell><TableCell>{i18nText("ui:m_a8b5eb7ab131963a7007")}</TableCell><TableCell>{i18nText("ui:m_cf025c2b66b1d8e97700")}</TableCell><TableCell>{i18nText("ui:m_f076d4d5af9ae08ee32e")}</TableCell><TableCell align="right">{i18nText("ui:m_fb5a81ab73261d83d6a8")}</TableCell><TableCell>{i18nText("ui:m_eacbc50b92d8ceaa5fa6")}</TableCell><TableCell>{i18nText("ui:m_5ecc9e41cd95e17be85f")}</TableCell></TableRow></TableHead><TableBody>{visible.slice(page * rowsPerPage, (page + 1) * rowsPerPage).map(([id, observation]) => {
              const fact = observation.fact;
              const approved = !!data.approved[id];
              const suppressed = !!data.suppressed[id];
              return <TableRow key={id}><TableCell><Checkbox checked={selected.includes(id)} inputProps={{ 'aria-label': i18nText("ui:m_c09b8183b627ee6cc13b", { arg0: factLabel(fact) }) }}
                  onChange={(_, checked) => setSelected(previous => checked ? [...previous, id] : previous.filter(value => value !== id))} /></TableCell><TableCell><Typography variant="body2">{data.labels?.[id]?.name || `${fact.kind}: ${factLabel(fact)}`}</Typography>{data.labels?.[id] && <Typography variant="caption" display="block">{factLabel(fact)}· {data.labels[id].role}</Typography>}<Typography variant="caption">{data.corrections?.[id] ? i18nText("ui:m_ce87e769857f337eb94c", { arg0: data.corrections[id].value }) : fact.provenance || i18nText("ui:m_17d36cb0fe3c25c4df0a")}</Typography></TableCell><TableCell>{scopeLabel(fact.scope)}</TableCell><TableCell><Chip size="small" label={approved ? i18nText("ui:m_b8a3f06875ca6f829221") : suppressed ? i18nText("ui:m_a436bdc609908fe94080") : i18nText("ui:m_448f0fe3eae5b97196ce")} color={approved ? 'success' : 'default'} />{suppressed && <Typography variant="caption" display="block">{data.suppressed[id]}</Typography>}</TableCell><TableCell>{timeLabel(observation.firstSeen)}<br />{timeLabel(observation.lastSeen)}</TableCell><TableCell align="right">{observation.samples.toLocaleString(getUILocale())}</TableCell><TableCell>{fact.mac && <Button size="small" onClick={() => router.push(`/devices?search=${encodeURIComponent(fact.mac!)}`)}>{i18nText("ui:m_e9e811f9506bb5acac28")}</Button>}{fact.srcIP && <Button size="small" onClick={() => router.push(`/hosts?search=${encodeURIComponent(fact.srcIP!)}`)}>{i18nText("ui:m_d36e3ee418e39309c3c7")}</Button>}<Button size="small" onClick={() => setEvidence(JSON.stringify({ id, ...observation }, null, 2))}>{i18nText("ui:m_8d89db0e0238614d3569")}</Button></TableCell><TableCell><Button size="small" onClick={() => setInventory({ id, version: data.version, name: data.labels?.[id]?.name ?? '', role: data.labels?.[id]?.role ?? '',
                  notes: data.labels?.[id]?.notes ?? '', prefix: fact.value ?? '', isPrefix: fact.kind === 'prefix', reason: '' })}>{fact.kind === 'prefix' ? i18nText("ui:m_dac56592487397af0656") : i18nText("ui:m_a2eafa5f1d6707660144")}</Button></TableCell></TableRow>;
            })}</TableBody></Table><TablePagination component="div" count={visible.length} page={page} rowsPerPage={rowsPerPage} rowsPerPageOptions={[25, 50, 100]}
            onPageChange={(_, value) => setPage(value)} onRowsPerPageChange={event => { setRowsPerPage(Number(event.target.value)); setPage(0); }} /></TableContainer>{!visible.length && <Typography color="text.secondary">{i18nText("ui:m_5a23276332339c9bf2f3")}</Typography>}</>}{tab === 2 && <><Stack direction="row" spacing={2} alignItems="center"><Chip label={i18nText("ui:m_c5f7bf3917d2941afb4a", { arg0: enumLabel(live.state) })} color={live.state === 'connected' ? 'success' : 'default'} /><Button onClick={() => setRestart(value => value + 1)}>{i18nText("ui:m_bf2a06504c85c93d3421")}</Button></Stack>{i18nRenderText(live.error) && <Alert severity="warning">{i18nRenderText(live.error)}</Alert>}<Typography variant="body2" color="text.secondary">{i18nText("ui:m_a880f9323389f9cb31d0")}</Typography><TableContainer component={Paper}><Table size="small" aria-label={i18nText("ui:m_58023ae59c88ac493b15")}><TableHead><TableRow><TableCell>{i18nText("ui:m_b62418ba3d29bf760ea0")}</TableCell><TableCell>{i18nText("ui:m_47badcebb200289655b3")}</TableCell><TableCell>{i18nText("ui:m_d1de98cbf475009ee57d")}</TableCell><TableCell>{i18nText("ui:m_3138a35abbc267016505")}</TableCell><TableCell>{i18nText("ui:m_8d89db0e0238614d3569")}</TableCell></TableRow></TableHead><TableBody>{live.alerts.map(alert => {
              let factId = '';
              try { const parsed = JSON.parse(alert.matchedRecord); if (typeof parsed.factId === 'string') factId = parsed.factId; } catch { /* Non-behavioral evidence remains readable. */ }
              return <TableRow key={alert.alertId}><TableCell>{new Date(alert.timestamp).toLocaleString(getUILocale())}</TableCell><TableCell>{alert.ruleName || alert.name}</TableCell><TableCell>{enumLabel(alert.severity)}</TableCell><TableCell>{alert.srcIP}→ {alert.dstIP}</TableCell><TableCell><Button size="small" onClick={() => { setEvidence(alert.matchedRecord); setEvidenceAlertID(alert.ruleName.startsWith('lateral.') ? alert.alertId : null); }}>{i18nText("ui:m_c2b40dcabb2846ae13b4")}</Button>{factId && data.observed[factId] && <Button size="small" disabled={busy || data.mode !== 'monitoring'} onClick={() => openAction('acknowledge', [factId])}>{i18nText("ui:m_7522fbc377de7a117dcf")}</Button>}</TableCell></TableRow>;
            })}</TableBody></Table></TableContainer></>}{tab === 3 && <TableContainer component={Paper}><Table size="small" aria-label={i18nText("ui:m_b702194f323fe4d4e34e")}><TableHead><TableRow><TableCell>{i18nText("ui:m_b62418ba3d29bf760ea0")}</TableCell><TableCell>{i18nText("ui:m_1a3caa8a333177645dfb")}</TableCell><TableCell>{i18nText("ui:m_12ea75cc25db6c5fb626")}</TableCell><TableCell>{i18nText("ui:m_37b931c3ef2914c51753")}</TableCell><TableCell>{i18nText("ui:m_d95f41a6bbbd1003d3e4")}</TableCell></TableRow></TableHead><TableBody>{[...(data.decisions ?? [])].reverse().map((decision, index) => <TableRow key={`${decision.at}-${index}`}><TableCell>{timeLabel(decision.at)}</TableCell><TableCell>{behaviorActionLabel(decision.action)}</TableCell><TableCell>{decision.reason}</TableCell><TableCell>{decision.version}</TableCell><TableCell>{decision.ids?.map(id => data.observed[id] ? factLabel(data.observed[id].fact) : id).join(', ')}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}{tab === 4 && <><FormControl size="small" sx={{ minWidth: 240 }}><InputLabel id="topology-scope-label">{i18nText("ui:m_e6e514bc625b7d78a019")}</InputLabel><Select labelId="topology-scope-label" label={i18nText("ui:m_e6e514bc625b7d78a019")} value={scope} onChange={event => setScope(event.target.value)}><MenuItem value="">{i18nText("ui:m_8a69bd170bb418d6084a")}</MenuItem>{scopes.map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}</Select></FormControl><Alert severity="info">{i18nText("ui:m_b8fd65119f7ac71c69fd")}</Alert><Stack direction="row" spacing={2} alignItems="center"><Button onClick={() => setGraphGeneration(value => value + 1)}>{i18nText("ui:m_d5797fe54ac7bdaf62e5")}</Button><Typography variant="body2">{i18nRichText("ui:m_e2c874732bb09499ee69", { arg0: topology?.nodes.length ?? 0, arg1: topology?.totalNodes ?? 0, arg2: topology?.truncated ? i18nText("ui:m_a2636cd1820e84880974") : '' })}</Typography></Stack><ChartFrame key={`${graphURL}-${graphGeneration}-${data.version}`} src={`${graphURL}&format=html`} title={i18nText("ui:m_9c160ef00e0b536549f6")} style={{ width: '100%', height: 560, border: 0 }} /></>}{tab === 5 && <Paper sx={{ p: 2 }}><Typography variant="h6">{i18nText("ui:m_c11a4aac1eb42be5ff73")}</Typography>{healthError && <Alert severity="warning">{i18nRichText("ui:m_a2eae364496b65720e6c", { arg0: renderError(healthError) })}</Alert>}{!health && !healthError && <CircularProgress aria-label={i18nText("ui:m_ae3279bd3f9816667f54")} />}{health && <Stack spacing={1}><Typography variant="body2">{i18nRichText("ui:m_9a98e5fde7f4f02b9993", { arg0: health.active ? i18nText("ui:m_1b4d2981c45b2bb53147") : i18nText("ui:m_8c55cd6caba9a190cd86"), arg1: new Date(health.sampledAt).toLocaleString(getUILocale()) })}</Typography><Typography variant="body2">{i18nRichText("ui:m_f8bbd73929500119e78f", { arg0: health.scopes.map(scopeLabel).join('; ') || i18nText("ui:m_4cf831b382f5ad00e06d"), arg1: health.scopesTruncated ? i18nText("ui:m_5da41639ae063c9d3717") : '' })}</Typography><Typography variant="body2">{i18nRichText("ui:m_d6488a97f4da12bdc833", { arg0: health.observations, arg1: health.factOverflow, arg2: health.windowOverflow })}</Typography>{health.detectorError && <Alert severity="error">{i18nRichText("ui:m_984816b433ae5e717580", { arg0: health.detectorError })}</Alert>}{health.capture ? <><Typography variant="body2">{i18nRichText("ui:m_8ca35a9bec1eced5269d", { arg0: scopeLabel(health.capture.scope) })}</Typography><Typography variant="body2">{i18nRichText("ui:m_1ca6d90c22b9d3824685", { arg0: health.capture.packets.toLocaleString(getUILocale()), arg1: health.capture.workers, arg2: health.capture.queued, arg3: health.capture.queueCapacity })}</Typography><Typography variant="body2">{i18nRichText("ui:m_a608cd606c151242d2b9", { arg0: health.capture.queueDrops ?? i18nText("ui:m_b6f62be183440dfdc4c4"), arg1: health.capture.kernelDrops ?? i18nText("ui:m_b6f62be183440dfdc4c4"), arg2: health.capture.kernelReceived ?? i18nText("ui:m_b6f62be183440dfdc4c4") })}</Typography>{health.capture.statsAt > 0 && <Typography variant="caption">{i18nRichText("ui:m_3faa8d853c86d0b6c598", { arg0: new Date(health.capture.statsAt).toLocaleString(getUILocale()) })}</Typography>}{health.capture.statsError && <Alert severity="warning">{i18nRichText("ui:m_7bbc7d1f9e4d5739ae52", { arg0: health.capture.statsError })}</Alert>}</> : <Typography variant="body2">{i18nText("ui:m_3ecfbba4ad9e670170bb")}</Typography>}<Typography variant="body2">{i18nRichText("ui:m_a0557f0ab69d535fcfb3", { arg0: health.baselineBytes ?? i18nText("ui:m_b6f62be183440dfdc4c4"), arg1: health.alertBytes ?? i18nText("ui:m_d3cbbc19b33fbf3938f8"), arg2: health.baselineWrittenAt ? new Date(health.baselineWrittenAt).toLocaleString(getUILocale()) : i18nText("ui:m_b6f62be183440dfdc4c4") })}</Typography>{health.storageError && <Alert severity="error">{i18nRichText("ui:m_973ca7b4cb975019bd67", { arg0: health.storageError })}</Alert>}{health.delivery ? <><Typography variant="body2">{i18nRichText("ui:m_cd977fafc6dc2deb3583", { arg0: health.delivery.acked, arg1: health.delivery.pending ?? i18nText("ui:m_b6f62be183440dfdc4c4"), arg2: health.delivery.rejected, arg3: health.delivery.dropped, arg4: health.delivery.pendingBytes !== undefined ? i18nText("ui:m_89d1a276d80e327fe6cb", { arg0: health.delivery.pendingBytes }) : '' })}</Typography>{health.delivery.error && <Alert severity="warning">{i18nRichText("ui:m_980221635fb76914714e", { arg0: health.delivery.error })}</Alert>}</> : <Typography variant="body2">{i18nText("ui:m_e9a315dae15291ea2635")}</Typography>}<Alert severity="info">{i18nText("ui:m_5001d9f9f5aeb449c01c")}</Alert></Stack>}</Paper>}</>}</Stack><Dialog open={action !== null} onClose={() => { if (!busy) setAction(null); }} maxWidth="sm" fullWidth><DialogTitle>{i18nRichText("ui:m_d3bc8fb23e36bda13427", { arg0: action })}</DialogTitle><DialogContent><Typography variant="body2" sx={{ mb: 1 }}>{i18nRichText("ui:m_0e149d0ef0f9c2f9d0d8", { arg0: decisionVersion, arg1: decisionIDs.length })}</Typography><Typography variant="body2" sx={{ mb: 2 }}>{action === 'reset' ? i18nText("ui:m_32f2ca1b4bc96c00280b") : action === 'acknowledge' ? i18nText("ui:m_4fba7985c82079174d71") : i18nText("ui:m_5d6beb1e037bf40622f5")}</Typography><TextField autoFocus fullWidth required label={i18nText("ui:m_4bb89a29986fe33d428f")} value={reason} onChange={event => setReason(event.target.value)} slotProps={{ htmlInput: { maxLength: 1024 } }} />{i18nRenderText(failure) && <Alert severity="error" sx={{ mt: 2 }}>{i18nRenderText(failure)}</Alert>}</DialogContent><DialogActions><Button disabled={busy} onClick={() => setAction(null)}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button variant="contained" disabled={busy || !reason.trim()} onClick={() => void apply()}>{i18nText("ui:m_e366466d2f8cbdf81a5e")}</Button></DialogActions></Dialog><Dialog open={evidence !== null} onClose={() => setEvidence(null)} maxWidth="md" fullWidth><DialogTitle>{i18nText("ui:m_9a1fd570ac49758871a8")}</DialogTitle><DialogContent><Box component="pre" sx={{ overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{evidence}</Box>{evidenceAlertID && <BehaviorRecordContext alertId={evidenceAlertID} selection={selection} />}</DialogContent><DialogActions>{evidence && renderEvidenceActions?.(evidence)}<Button onClick={() => setEvidence(null)}>{i18nText("ui:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog><Dialog open={inventory !== null} onClose={() => { if (!busy) setInventory(null); }} maxWidth="sm" fullWidth><DialogTitle>{inventory?.isPrefix ? i18nText("ui:m_2bf756c5c7aa85dcefa3") : i18nText("ui:m_decf4a888728976a4486")}</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}><Typography variant="body2">{i18nRichText("ui:m_fdf082e9dfef7e9b7d5e", { arg0: String(inventory?.version) })}</Typography>{inventory?.isPrefix ? <TextField label={i18nText("ui:m_1d60ab19625925a5415e")} value={inventory.prefix} onChange={event => setInventory({ ...inventory, prefix: event.target.value })} /> : <><TextField label={i18nText("ui:m_41772ebb4294d360c1ac")} value={inventory?.name ?? ''} slotProps={{ htmlInput: { maxLength: 128 } }} onChange={event => inventory && setInventory({ ...inventory, name: event.target.value })} /><TextField label={i18nText("ui:m_5b075e34f4ead6632ae6")} value={inventory?.role ?? ''} slotProps={{ htmlInput: { maxLength: 128 } }} onChange={event => inventory && setInventory({ ...inventory, role: event.target.value })} /><TextField label={i18nText("ui:m_e9be1322e705411f2123")} value={inventory?.notes ?? ''} multiline slotProps={{ htmlInput: { maxLength: 1024 } }} onChange={event => inventory && setInventory({ ...inventory, notes: event.target.value })} /></>}<TextField label={i18nText("ui:m_ed5df0f06ccca9c41291")} required value={inventory?.reason ?? ''} slotProps={{ htmlInput: { maxLength: 1024 } }} onChange={event => inventory && setInventory({ ...inventory, reason: event.target.value })} />{i18nRenderText(failure) && <Alert severity="error">{i18nRenderText(failure)}</Alert>}</Stack></DialogContent><DialogActions><Button disabled={busy} onClick={() => setInventory(null)}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button variant="contained" disabled={busy || !inventory?.reason.trim()} onClick={() => void saveInventory()}>{i18nText("ui:m_98fdc9fe193bec36413f")}</Button></DialogActions></Dialog></Layout>;
}
