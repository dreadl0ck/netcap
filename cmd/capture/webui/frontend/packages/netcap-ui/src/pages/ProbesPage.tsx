import { useEffect, useState } from 'react';
import { Alert, Box, Button, Chip, CircularProgress, Link, Paper, Stack, TextField, Typography } from '@mui/material';
import useSWR from 'swr';
import Layout from '../components/Layout';
import { useNetcapApi, useNetcapRouter } from '../hooks';
import { behaviorSelection } from '../lib/behavior';
import type { ServiceSignatureInventory } from '../lib/api';

function Inventory({ title, inventory }: { title: string; inventory: ServiceSignatureInventory }) {
  return <Paper variant="outlined" sx={{ p: 2, overflowWrap: 'anywhere' }}>
    <Stack spacing={1}>
      <Typography variant="h6">{title}</Typography>
      <Typography>{inventory.state} · Source: {inventory.source} · {inventory.rule_count} rules · {inventory.protocols.join(', ') || 'No coverage recorded'}</Typography>
      {inventory.warning && <Alert severity="warning">{inventory.warning}</Alert>}
      <Typography variant="body2">Inventory checked: {new Date(inventory.checked_at).toLocaleString()}</Typography>
      {inventory.source_sha256 && <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>Source SHA-256: {inventory.source_sha256}</Typography>}
      {inventory.limitations.map(text => <Typography key={text} variant="body2" color="text.secondary">{text}</Typography>)}
    </Stack>
  </Paper>;
}

export default function ServiceSignatures() {
  const api = useNetcapApi();
  const router = useNetcapRouter();
  const query = router.getQueryParam('search') ?? '';
  const [search, setSearch] = useState(query);
  useEffect(() => setSearch(query), [query]);
  const { data, error, mutate } = useSWR('service-signatures', () => api.getServiceSignatures());
  const { data: status } = useSWR('status', () => api.getStatus());
  const { data: files } = useSWR('inputFiles', () => api.getInputFiles());
  const selection = behaviorSelection(status, files);
  const { data: run, error: runError, mutate: refreshRun } = useSWR(
    ['service-signature-status', selection], () => api.getServiceSignatureStatus(selection), { keepPreviousData: false },
  );
  const displayedCatalogue = run?.catalogue ?? data?.catalogue;
  const rules = displayedCatalogue?.rules.filter(rule => `${rule.id} ${rule.protocol} ${rule.kind}`.toLowerCase().includes(search.toLowerCase())) ?? [];

  return <Layout title="Service Signatures">
    <Stack spacing={2} sx={{ p: 3 }}>
      <Typography variant="body2">Read-only independently authored protocol catalogue with source evidence. Provenance does not assert human approval.</Typography>
      <Alert severity="info">Legacy probe editing, regex testing, imports and exports are retired. Existing probe files are not loaded or translated. All rules in a valid v1 catalogue are active; there is no enabled flag.</Alert>
      <Box><Button variant="outlined" onClick={() => { void mutate(); void refreshRun(); }}>Refresh catalogue and capture diagnostics</Button></Box>
      {error && <Alert severity="error">Catalogue unavailable: {error instanceof Error ? error.message : 'Unknown error'}</Alert>}
      {!data && !error && <Box role="status" aria-label="Loading service signature catalogue"><CircularProgress /></Box>}
      {data?.inventory && <Inventory title="Catalogue available for the next capture" inventory={data.inventory} />}
      <Typography variant="body2" color="text.secondary">The catalogue on disk may differ from the snapshot recorded when the selected capture initialized.</Typography>
      {run && <Inventory title="Selected capture: recorded signature inventory" inventory={run} />}
      {runError && <Alert severity="warning">Capture diagnostics unavailable: {runError instanceof Error ? runError.message : 'No capture status'}. This does not establish which catalogue a previous run used.</Alert>}
      <TextField label="Search signature IDs, protocols or parser kinds" value={search} onChange={e => setSearch(e.target.value)} fullWidth />
      {displayedCatalogue && <Typography>{rules.length} of {displayedCatalogue.rules.length} signatures · Format v{displayedCatalogue.schema_version} · {run?.catalogue ? 'Recorded capture catalogue' : 'Next-capture catalogue'}</Typography>}
      {displayedCatalogue && rules.length === 0 && <Alert severity="info">No catalogue signature matches this ID or search. Historical matches may refer to a different catalogue; use the capture inventory to check its source.</Alert>}
      {rules.map(rule => <Paper component="article" key={rule.id} variant="outlined" sx={{ p: 2, overflowWrap: 'anywhere' }}>
        <Stack spacing={1}>
          <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>{rule.id}</Typography>
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap"><Chip label={rule.protocol} /><Chip label={rule.transport} /><Chip label={rule.direction} /></Stack>
          <Typography>Parser: {rule.kind}</Typography>
          <Typography variant="subtitle2">Source evidence</Typography>
          {rule.provenance.map((source, index) => <Typography key={`${source.url}-${index}`} variant="body2">
            {source.url.startsWith('https://')
              ? <Link href={source.url} target="_blank" rel="noopener noreferrer">{source.section}</Link>
              : source.section} — {source.url}
          </Typography>)}
        </Stack>
      </Paper>)}
    </Stack>
  </Layout>;
}
