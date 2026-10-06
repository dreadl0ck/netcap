import { Alert, Stack, Typography } from '@mui/material';
import useSWR from 'swr';
import { useNetcapConfig } from '../providers';
import { behaviorRequest } from '../lib/behavior';

interface RecordContext {
  records: { type: string; index: number; sha256: string; firstSeen: number; lastSeen: number;
    captureLagNS: number; outcome: string; authentication: string; status?: number; command?: number; encrypted?: boolean }[];
  unavailable: string[];
  scanned: number;
  truncated: boolean;
  qualification: string;
}

export default function BehaviorRecordContext({ alertId, selection }: { alertId: string; selection: string }) {
  const config = useNetcapConfig();
  const url = `${config.apiBaseUrl}/behavior/records${selection || '?'}${selection ? '&' : ''}alertId=${encodeURIComponent(alertId)}`;
  const { data, error } = useSWR<RecordContext>(url, () => behaviorRequest(config.fetch ?? fetch, url),
    { refreshInterval: 5000, keepPreviousData: false });
  return <Stack spacing={1} role="region" aria-label="Later connection and SMB evidence">
    <Typography variant="subtitle2">Later connection and SMB evidence</Typography>
    {error && <Alert severity="warning">{error.message}</Alert>}
    {!data && !error && <Typography variant="body2">Loading retained audit records…</Typography>}
    {data && <>
      <Alert severity="info">{data.qualification}</Alert>
      <Typography variant="caption">{data.records.length} tuple/time candidates · {data.scanned} records examined{data.truncated ? ' · Scan/display capped' : ''}</Typography>
      {data.unavailable.map(message => <Typography key={message} variant="body2" color="text.secondary">{message}</Typography>)}
      {!data.records.length && <Typography variant="body2">No matching retained records within scan limits. This does not establish a connection or authentication outcome.</Typography>}
      {data.records.map(record => <Stack key={`${record.type}:${record.index}:${record.sha256}`} spacing={0.25}>
        <Typography variant="body2">{record.type} record #{record.index} · {record.outcome} · Authentication: {record.authentication}</Typography>
        <Typography variant="caption">{new Date(record.firstSeen / 1e6).toLocaleString()} to {new Date(record.lastSeen / 1e6).toLocaleString()} · Capture-time lag {(record.captureLagNS / 1e9).toFixed(3)} s</Typography>
        {record.type === 'SMB' && <Typography variant="caption">Command {record.command ?? 0} · NT status {record.status ?? 0}{record.encrypted ? ' · Encrypted' : ''}</Typography>}
        <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>Canonical protobuf SHA-256: {record.sha256}</Typography>
      </Stack>)}
    </>}
  </Stack>;
}
