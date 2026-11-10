import { Accordion, AccordionSummary, AccordionDetails, Box, Button, Chip, Stack, Table, TableBody, TableCell, TableHead, TableRow, Tooltip, Typography } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import useSWR from 'swr';
import { useNetcapApi, useNetcapRouter } from '../hooks';
import { useNetcapConfig } from '../providers';
import { behaviorRequest, behaviorSelection, factLabel, scopeLabel } from '../lib/behavior';
import type { BehaviorObservation } from '../lib/behavior';

interface AssetContext {
  asset: string;
  records: { id: string; observation: BehaviorObservation; label?: { name: string; role?: string; notes?: string };
    direction: string; prefixes?: string[]; prefixesTruncated?: boolean }[];
  totalRecords: number;
  truncated: boolean;
}

export default function BehaviorAssetContext({ asset }: { asset: string }) {
  const api = useNetcapApi();
  const router = useNetcapRouter();
  const config = useNetcapConfig();
  const { data: status } = useSWR('status', () => api.getStatus(), { refreshInterval: 1000 });
  const { data: files } = useSWR('inputFiles', () => api.getInputFiles());
  const selection = behaviorSelection(status, files);
  const url = `${config.apiBaseUrl}/behavior/asset${selection || '?'}${selection ? '&' : ''}asset=${encodeURIComponent(asset)}`;
  const { data, error } = useSWR<AssetContext>(status && asset ? url : null,
    () => behaviorRequest(config.fetch ?? fetch, url), { refreshInterval: 5000, keepPreviousData: false });
  return <Accordion disableGutters variant="outlined" sx={{ my: 1, '&:before': { display: 'none' } }}>
    <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ '&:hover': { bgcolor: 'action.hover' }, '&.Mui-focusVisible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: -2 } }}>
      <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: 'wrap', gap: 0.5 }}>
        <Typography variant="subtitle2">Behavioral context</Typography>
        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{asset}</Typography>
        {data && <Chip size="small" variant="outlined" label={`${data.totalRecords} observations`} />}
      </Stack>
    </AccordionSummary>
    <AccordionDetails role="region" aria-label={`Behavioral context for ${asset}`} sx={{ pt: 0 }}><Stack spacing={1}>
      {error && <Typography variant="body2" color="text.secondary">{error.message}</Typography>}
      {!data && !error && <Typography variant="body2" color="text.secondary">Loading observations…</Typography>}
      {data && <>
        {data.truncated && <Typography variant="caption" color="text.secondary">Showing {data.records.length} of {data.totalRecords}</Typography>}
        {data.records.length === 0 ? <Typography variant="body2" color="text.secondary">No observations for this asset.</Typography> : <Box sx={{ overflowX: 'auto' }}><Table size="small" aria-label={`Observations for ${asset}`}>
          <TableHead><TableRow><TableCell>Observation</TableCell><TableCell>Direction</TableCell><TableCell>Source</TableCell><TableCell>First / last seen</TableCell></TableRow></TableHead>
          <TableBody>{data.records.map(record => <TableRow key={record.id}>
            <TableCell><Typography variant="caption" color="text.secondary">{record.observation.fact.kind === 'edge' ? 'Peer' : record.observation.fact.kind}</Typography><Typography variant="body2">{factLabel(record.observation.fact)}</Typography>
              {record.label?.name && <Typography variant="caption">{record.label.name}{record.label.role ? ` · ${record.label.role}` : ''}</Typography>}
              {record.label?.notes && <Typography variant="caption" display="block">{record.label.notes}</Typography>}
            </TableCell>
            <TableCell><Tooltip title={record.prefixes?.length ? `Prefixes: ${record.prefixes.join(', ')}${record.prefixesTruncated ? ' (more in inventory)' : ''}` : 'Direction relative to local network prefixes'}><Typography variant="body2">{record.direction === 'unknown' ? 'Unknown' : record.direction}</Typography></Tooltip></TableCell>
            <TableCell><Tooltip title={scopeLabel(record.observation.fact.scope)}><Typography variant="caption">{record.observation.fact.provenance || 'Captured traffic'}</Typography></Tooltip></TableCell>
            <TableCell sx={{ whiteSpace: 'nowrap' }}><Typography variant="caption" display="block">{new Date(record.observation.firstSeen / 1e6).toLocaleString()}</Typography><Typography variant="caption" color="text.secondary">{new Date(record.observation.lastSeen / 1e6).toLocaleString()}</Typography></TableCell>
          </TableRow>)}</TableBody>
        </Table></Box>}
      </>}
      <Button size="small" sx={{ alignSelf: 'flex-start' }} onClick={() => router.push(`/behavior?asset=${encodeURIComponent(asset)}`)}>View asset history</Button>
    </Stack></AccordionDetails>
  </Accordion>;
}
