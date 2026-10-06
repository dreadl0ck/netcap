import { Button, Paper, Stack, Typography } from '@mui/material';
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
  return <Paper variant="outlined" sx={{ p: 2, my: 1 }} role="region" aria-label={`Behavioral context for ${asset}`}>
    <Stack spacing={1}>
      <Typography variant="subtitle2">Behavioral context: {asset}</Typography>
      {error && <Typography variant="body2" color="text.secondary">{error.message}</Typography>}
      {data && <>
        <Typography variant="caption">{data.records.length} shown / {data.totalRecords} observations{data.truncated ? ' · Display capped' : ''}. Local/external direction is relative to observed/configured prefixes; unknown means insufficient prefix evidence.</Typography>
        <Typography variant="caption">Destination country/ASN context: {data.records.some(record => record.observation.fact.kind === 'geo') ? 'Enriched observations below' : 'Unknown/private; no enrichment observed'}</Typography>
        {data.records.map(record => <Stack key={record.id} spacing={0.25}>
          <Typography variant="body2">{record.label?.name ? `${record.label.name} · ${record.label.role || 'Unspecified role'} · ` : ''}{record.observation.fact.kind === 'edge' ? 'peer' : record.observation.fact.kind}: {factLabel(record.observation.fact)}</Typography>
          <Typography variant="caption">{scopeLabel(record.observation.fact.scope)} · {record.direction} · {record.observation.fact.provenance || 'Observed traffic'} · {new Date(record.observation.firstSeen / 1e6).toLocaleString()} to {new Date(record.observation.lastSeen / 1e6).toLocaleString()}</Typography>
          {record.prefixes?.length ? <Typography variant="caption">Prefix evidence: {record.prefixes.join(', ')}{record.prefixesTruncated ? ' · More in inventory' : ''}</Typography> : null}
          {record.label?.notes && <Typography variant="caption">{record.label.notes}</Typography>}
        </Stack>)}
      </>}
      <Button size="small" onClick={() => router.push(`/behavior?asset=${encodeURIComponent(asset)}`)}>Open scoped asset history</Button>
    </Stack>
  </Paper>;
}
