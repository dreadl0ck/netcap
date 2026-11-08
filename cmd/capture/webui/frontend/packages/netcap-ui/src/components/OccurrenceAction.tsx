import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, Dialog, DialogContent, DialogTitle } from '@mui/material';
import { useNetcapConfig } from '../providers';
import { resolveOccurrence, type AnalystSource, type OccurrenceReference } from '../lib/analyst';

export default function OccurrenceAction({ data }: { data: Record<string, unknown> }) {
  const config = useNetcapConfig();
  const [error, setError] = useState(''), [record, setRecord] = useState<unknown>(null);
  const operation = useRef<AbortController | null>(null);
  useEffect(() => () => operation.current?.abort(), []);
  const reference = data._netcapOccurrence as OccurrenceReference | undefined;
  const source = data._netcapSource as AnalystSource | undefined;
  if (!reference || !source) return null;
  return <Box onClick={event => event.stopPropagation()}>
    <Button onClick={async () => { operation.current?.abort(); const controller = new AbortController(); operation.current = controller; setError(''); try { const result = await resolveOccurrence(config.fetch ?? fetch, config.apiBaseUrl, source, reference, controller.signal); if (!controller.signal.aborted) setRecord(result); } catch (failure) { if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : 'Occurrence resolution failed'); } }}>Resolve exact occurrence</Button>
    {error && <Alert severity="error">{error}</Alert>}
    <Dialog open={record !== null} onClose={() => setRecord(null)} fullWidth maxWidth="lg"><DialogTitle>Verified content-bound occurrence</DialogTitle><DialogContent><Button onClick={() => setRecord(null)}>Close occurrence</Button><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(record, null, 2).slice(0, 40000)}</pre></DialogContent></Dialog>
  </Box>;
}
