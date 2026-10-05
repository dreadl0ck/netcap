import { useEffect, useMemo, useState } from 'react';
import { Alert, Box, Button, Checkbox, Chip, CircularProgress, Dialog, DialogActions, DialogContent,
  DialogTitle, FormControl, InputLabel, MenuItem, Paper, Select, Stack, Tab, Table, TableBody,
  TableCell, TableContainer, TableHead, TablePagination, TableRow, Tabs, TextField, Typography } from '@mui/material';
import useSWR from 'swr';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { useNetcapApi, useNetcapRouter } from '../hooks';
import { useNetcapConfig } from '../providers';
import { useLiveAlerts } from '../hooks/useLiveAlerts';
import { behaviorRequest, behaviorSelection, factLabel, learningReady, scopeLabel } from '../lib/behavior';
import type { BehaviorAction, BehaviorSnapshot } from '../lib/behavior';

const timeLabel = (ns: number) => ns > 0 ? new Date(ns / 1e6).toLocaleString() : 'Not observed';

export default function BehaviorPage() {
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
  const [failure, setFailure] = useState('');
  const [restart, setRestart] = useState(0);
  const [evidence, setEvidence] = useState<string | null>(null);
  const live = useLiveAlerts(status && tab === 2 ? `${config.apiBaseUrl}/alerts/stream${selection}` : null, restart);

  useEffect(() => { setSelected([]); setPage(0); setScope(''); setAction(null); setFailure(''); }, [selection]);
  useEffect(() => { setSelected([]); }, [data?.version]);

  const rows = useMemo(() => Object.entries(data?.observed ?? {}).sort(([a], [b]) => a.localeCompare(b)), [data?.observed]);
  const scopes = useMemo(() => [...new Set(rows.map(([, observation]) => scopeLabel(observation.fact.scope)))].sort(), [rows]);
  const visible = useMemo(() => rows.filter(([id, observation]) => {
    if (scope && scopeLabel(observation.fact.scope) !== scope) return false;
    if (tab === 1 && (data?.approved[id] || data?.suppressed[id])) return false;
    return `${observation.fact.kind} ${factLabel(observation.fact)} ${scopeLabel(observation.fact.scope)}`.toLowerCase().includes(search.toLowerCase());
  }), [rows, scope, search, tab, data?.approved, data?.suppressed]);
  const elapsed = data ? Math.max(0, (data.watermark - data.learningStarted) / 1e9) : 0;

  const changeCapture = async (path: string) => {
    setSwitching(true);
    try {
      const result = await api.setActiveDirectory(path);
      await refreshStatus();
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
    } catch (error) { setFailure(error instanceof Error ? error.message : 'Capture switch failed'); }
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
      setFailure(error instanceof Error ? error.message : 'Baseline decision failed');
      await mutate();
    } finally { setBusy(false); }
  };

  const openAction = (next: BehaviorAction) => {
    if (!data) return;
    setReason(''); setAction(next); setDecisionVersion(data.version); setDecisionIDs([...selected]); setFailure('');
  };
  const selectionAction = (next: BehaviorAction, label: string) => <Button disabled={!selected.length || data?.mode !== 'monitoring' || busy}
    onClick={() => openAction(next)}>{label}</Button>;

  return <Layout title="Behavioral monitoring" headerAction={<FileSelectorHeader inputFiles={files ?? []} status={status}
    switchingFile={switching} onFileChange={changeCapture} />}>
    <Stack spacing={2} sx={{ minWidth: 0 }}>
      <Typography color="text.secondary">Passive observations are scoped by sensor, interface and VLAN. Coverage is limited to traffic visible at the sensor.</Typography>
      {failure && <Alert severity="error">{failure}</Alert>}
      {error && <Alert severity="warning">{error.message}</Alert>}
      {!data && !error && <CircularProgress aria-label="Loading behavioral baseline" />}
      {data && <>
        {data.error && <Alert severity="error">Monitoring failure: {data.error}</Alert>}
        {!!data.overflow && <Alert severity="warning">{data.overflow.toLocaleString()} observations exceeded the fact limit. Learning approval is disabled; archive/reset or increase the configured limit.</Alert>}
        {!!data.windowOverflow && <Alert severity="warning">{data.windowOverflow.toLocaleString()} events exceeded rolling-state capacity. Correlation coverage is incomplete.</Alert>}
        <Paper sx={{ p: 2 }}>
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" alignItems="center">
            <Chip label={data.mode} color={data.mode === 'monitoring' && !data.error ? 'success' : 'default'} />
            <Chip label={`Baseline v${data.version}`} variant="outlined" />
            <Typography variant="body2">{data.samples.toLocaleString()} observations · {rows.length.toLocaleString()}/{data.maxFacts.toLocaleString()} facts · {Object.keys(data.approved).length.toLocaleString()} approved</Typography>
          </Stack>
          <Typography variant="body2" sx={{ mt: 1 }}>Capture-time learning coverage: {(elapsed / 3600).toFixed(2)} h / {(data.minLearningNS / 3.6e12).toFixed(2)} h minimum; {data.samples}/{data.minSamples} minimum observations.</Typography>
          <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>Baseline identity: {data.baselineId || 'Not approved'} · Reordered observations: {data.outOfOrder}</Typography>
          {data.policy && <Typography variant="body2">Detector window: {data.policy.windowNS / 1e9} s · SMB fan-out: {data.policy.fanout} hosts · RDP pattern: {data.policy.rdpAttempts} attempts · Calibrated traffic sources: {Object.keys(data.approvedRates ?? {}).length}</Typography>}
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 1 }}>
            <Button variant="contained" disabled={!learningReady(data) || busy} onClick={() => openAction('approve')}>Approve learned baseline</Button>
            <Button disabled={busy || !!data.error} onClick={() => openAction(data.mode === 'paused' ? 'resume' : 'pause')}>{data.mode === 'paused' ? 'Resume' : 'Pause'}</Button>
            <Button disabled={busy || !!data.error} onClick={() => openAction('relearn')}>Relearn</Button>
            <Button color="warning" disabled={busy || !!data.error} onClick={() => openAction('reset')}>Reset</Button>
            <Button onClick={() => void mutate()}>Refresh</Button>
          </Stack>
        </Paper>
        <Tabs value={tab} onChange={(_, value: number) => { setTab(value); setPage(0); }} variant="scrollable" scrollButtons="auto" aria-label="Behavioral monitoring views">
          <Tab label="Network inventory" /><Tab label="Baseline candidates" /><Tab label="Live alerts" /><Tab label="Decision history" />
        </Tabs>
        {tab < 2 && <>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField label="Search observed facts" value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} size="small" />
            <FormControl size="small" sx={{ minWidth: 240 }}><InputLabel id="behavior-scope-label">Network scope</InputLabel>
              <Select labelId="behavior-scope-label" label="Network scope" value={scope} onChange={event => { setScope(event.target.value); setPage(0); }}>
                <MenuItem value="">All scopes</MenuItem>{scopes.map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}
              </Select>
            </FormControl>
          </Stack>
          <Stack direction="row" useFlexGap flexWrap="wrap" spacing={1}>
            <Typography variant="body2" sx={{ alignSelf: 'center' }}>{selected.length} selected</Typography>
            {selectionAction('approve-changes', 'Approve selected changes')}{selectionAction('suppress', 'Suppress selected')}{selectionAction('unsuppress', 'Remove suppression')}
          </Stack>
          <TableContainer component={Paper}><Table size="small" aria-label="Observed network facts">
            <TableHead><TableRow><TableCell>Select</TableCell><TableCell>Kind / evidence</TableCell><TableCell>Network scope</TableCell><TableCell>Status</TableCell><TableCell>First / last seen</TableCell><TableCell align="right">Samples</TableCell><TableCell>Pivot</TableCell></TableRow></TableHead>
            <TableBody>{visible.slice(page * rowsPerPage, (page + 1) * rowsPerPage).map(([id, observation]) => {
              const fact = observation.fact;
              const approved = !!data.approved[id];
              const suppressed = !!data.suppressed[id];
              return <TableRow key={id}>
                <TableCell><Checkbox checked={selected.includes(id)} inputProps={{ 'aria-label': `Select ${factLabel(fact)}` }}
                  onChange={(_, checked) => setSelected(previous => checked ? [...previous, id] : previous.filter(value => value !== id))} /></TableCell>
                <TableCell><Typography variant="body2">{fact.kind}: {factLabel(fact)}</Typography><Typography variant="caption">{fact.provenance || 'Observed traffic'}</Typography></TableCell>
                <TableCell>{scopeLabel(fact.scope)}</TableCell>
                <TableCell><Chip size="small" label={approved ? 'Approved' : suppressed ? 'Suppressed' : 'Candidate'} color={approved ? 'success' : 'default'} />{suppressed && <Typography variant="caption" display="block">{data.suppressed[id]}</Typography>}</TableCell>
                <TableCell>{timeLabel(observation.firstSeen)}<br />{timeLabel(observation.lastSeen)}</TableCell>
                <TableCell align="right">{observation.samples.toLocaleString()}</TableCell>
                <TableCell>{fact.mac && <Button size="small" onClick={() => router.push(`/devices?search=${encodeURIComponent(fact.mac!)}`)}>Device</Button>}
                  {fact.srcIP && <Button size="small" onClick={() => router.push(`/hosts?search=${encodeURIComponent(fact.srcIP!)}`)}>Host</Button>}
                  <Button size="small" onClick={() => setEvidence(JSON.stringify({ id, ...observation }, null, 2))}>Evidence</Button></TableCell>
              </TableRow>;
            })}</TableBody>
          </Table><TablePagination component="div" count={visible.length} page={page} rowsPerPage={rowsPerPage} rowsPerPageOptions={[25, 50, 100]}
            onPageChange={(_, value) => setPage(value)} onRowsPerPageChange={event => { setRowsPerPage(Number(event.target.value)); setPage(0); }} /></TableContainer>
          {!visible.length && <Typography color="text.secondary">No matching observations.</Typography>}
        </>}
        {tab === 2 && <>
          <Stack direction="row" spacing={2} alignItems="center"><Chip label={`Stream: ${live.state}`} color={live.state === 'connected' ? 'success' : 'default'} />
            <Button onClick={() => setRestart(value => value + 1)}>Reconnect from retained history</Button></Stack>
          {live.error && <Alert severity="warning">{live.error}</Alert>}
          <Typography variant="body2" color="text.secondary">Latest 200 retained/live alerts. Encrypted SSH/RDP connection patterns do not prove failed logins.</Typography>
          <TableContainer component={Paper}><Table size="small" aria-label="Live security alerts"><TableHead><TableRow><TableCell>Time</TableCell><TableCell>Detector</TableCell><TableCell>Severity</TableCell><TableCell>Endpoints</TableCell><TableCell>Evidence</TableCell></TableRow></TableHead>
            <TableBody>{live.alerts.map(alert => <TableRow key={alert.alertId}><TableCell>{new Date(alert.timestamp).toLocaleString()}</TableCell><TableCell>{alert.ruleName || alert.name}</TableCell><TableCell>{alert.severity}</TableCell>
              <TableCell>{alert.srcIP} → {alert.dstIP}</TableCell><TableCell><Button size="small" onClick={() => setEvidence(alert.matchedRecord)}>Expected / observed</Button></TableCell></TableRow>)}</TableBody>
          </Table></TableContainer>
        </>}
        {tab === 3 && <TableContainer component={Paper}><Table size="small" aria-label="Baseline decision history"><TableHead><TableRow><TableCell>Time</TableCell><TableCell>Action</TableCell><TableCell>Reason</TableCell><TableCell>Version</TableCell></TableRow></TableHead>
          <TableBody>{[...(data.decisions ?? [])].reverse().map((decision, index) => <TableRow key={`${decision.at}-${index}`}><TableCell>{timeLabel(decision.at)}</TableCell><TableCell>{decision.action}</TableCell><TableCell>{decision.reason}</TableCell><TableCell>{decision.version}</TableCell></TableRow>)}</TableBody>
        </Table></TableContainer>}
      </>}
    </Stack>
    <Dialog open={action !== null} onClose={() => { if (!busy) setAction(null); }} maxWidth="sm" fullWidth>
      <DialogTitle>Baseline decision: {action}</DialogTitle><DialogContent>
        <Typography variant="body2" sx={{ mb: 1 }}>Reviewing baseline v{decisionVersion}. Selected facts: {decisionIDs.length}.</Typography>
        <Typography variant="body2" sx={{ mb: 2 }}>{action === 'reset' ? 'Reset removes the approved baseline and current observations; recorded alert evidence remains unchanged.' : 'This decision is recorded with the current baseline version. Newly observed traffic is not automatically trusted.'}</Typography>
        <TextField autoFocus fullWidth required label="Decision reason" value={reason} onChange={event => setReason(event.target.value)} slotProps={{ htmlInput: { maxLength: 1024 } }} />
        {failure && <Alert severity="error" sx={{ mt: 2 }}>{failure}</Alert>}
      </DialogContent><DialogActions><Button disabled={busy} onClick={() => setAction(null)}>Cancel</Button><Button variant="contained" disabled={busy || !reason.trim()} onClick={() => void apply()}>Apply decision</Button></DialogActions>
    </Dialog>
    <Dialog open={evidence !== null} onClose={() => setEvidence(null)} maxWidth="md" fullWidth><DialogTitle>Observation evidence</DialogTitle>
      <DialogContent><Box component="pre" sx={{ overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{evidence}</Box></DialogContent>
      <DialogActions><Button onClick={() => setEvidence(null)}>Close</Button></DialogActions></Dialog>
  </Layout>;
}
