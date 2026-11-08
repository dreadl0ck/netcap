import { useState } from 'react';
import { Alert, Box, Button } from '@mui/material';
import { useNetcapConfig } from '../providers';
import type { OfflineSelection } from '../lib/api';

export default function ReproductionDownload({ selection }: { selection: OfflineSelection & { runId?: string } }) {
  const config = useNetcapConfig();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true); setError('');
    try {
      if (!selection.sessionId && !selection.inputFile) throw new Error('Select a capture before exporting reproduction metadata.');
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(selection)) if (value) query.set(key, value);
      const response = await (config.fetch || fetch)(`${config.apiBaseUrl}/investigation/reproduction?${query}`);
      if (!response.ok) throw new Error(`Reproduction metadata unavailable (HTTP ${response.status}).`);
      const bundle = await response.json();
      if (bundle.schema !== 'netcap-reproduction-metadata/v1' || bundle.state !== 'metadata-only') throw new Error('Unsupported reproduction metadata response.');
      const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }));
      try {
        const link = document.createElement('a');
        link.href = url; link.download = 'netcap-reproduction-metadata.json'; link.click();
      } finally { URL.revokeObjectURL(url); }
    } catch (error) { setError(error instanceof Error ? error.message : 'Reproduction metadata download failed.'); }
    finally { setBusy(false); }
  };
  return <Box onClick={event => event.stopPropagation()}>
    <Button size="small" disabled={busy} onClick={download}>Download reproduction metadata</Button>
    {error && <Alert severity="error">{error}</Alert>}
  </Box>;
}
