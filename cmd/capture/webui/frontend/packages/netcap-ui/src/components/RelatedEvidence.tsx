import { useEffect, useState } from 'react';
import { Alert as MuiAlert, Box, Chip, CircularProgress, Paper, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { useNetcapApi } from '../hooks';
import type { RelatedEvidenceResponse } from '../lib/api';
import { linkKindLabels, type EvidenceRecord, type EvidenceSelector } from '../lib/evidenceLinks';

const utc = (ns: number) => new Date(ns / 1e6).toISOString().replace('T', ' ').replace('Z', '');
const offset = (ns: number, base: number) => {
  const ms = (ns - base) / 1e6;
  return `${ms >= 0 ? '+' : '−'}${Math.abs(ms) >= 1000 ? `${(Math.abs(ms) / 1000).toFixed(2)} s` : `${Math.abs(ms).toFixed(1)} ms`}`;
};
const summary = (record: EvidenceRecord) => (record.summary || []).map(f => `${f.name}=${f.value}`).join('  ');
const kindColor = { 'same-connection': 'default', 'same-flow': 'default', alert: 'error', 'dns-resolution': 'info', 'resolved-connection': 'info' } as const;

/** Records linked to one record across protocols, as a session timeline. */
export function RelatedEvidence({ selector, inputFile }: { selector: EvidenceSelector | null; inputFile?: string }) {
  const api = useNetcapApi();
  const [response, setResponse] = useState<RelatedEvidenceResponse | null>(null);
  const key = JSON.stringify(selector);
  useEffect(() => {
    if (!selector) return;
    let current = true;
    setResponse(null);
    api.getRelatedEvidence(selector, inputFile)
      .then(r => { if (current) setResponse(r); })
      .catch(e => { if (current) setResponse({ status: 'unavailable', error: String(e?.message || e) }); });
    return () => { current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, inputFile]);
  if (!selector) return null;
  return (
    <Paper variant="outlined" sx={{ p: 1.5 }} data-testid="related-evidence"
      data-learn="Related evidence: records of the same connection (Community ID within the connection's time span), the DNS answer that resolved its destination, connections opened to an answered address, and alerts. Each row states how the link was made.">
      <Typography variant="subtitle2" gutterBottom>Related evidence</Typography>
      {!response && <CircularProgress size={18} />}
      {response?.status === 'disabled' && <MuiAlert severity="info">Evidence linking is disabled. Enable it in Settings → Features.</MuiAlert>}
      {response && response.status !== 'ok' && response.status !== 'disabled' &&
        <Typography variant="body2" color="text.secondary">{response.status === 'not-found' ? 'No linkable record: it has no Community ID or is beyond the index limits.' : `Unavailable: ${response.error}`}</Typography>}
      {response?.status === 'ok' && (() => {
        const { result } = response;
        const base = result.session?.first ?? result.target.timestamp;
        const rows = [...result.links.map(l => ({ ...l, target: false })), { kind: 'target' as const, basis: 'selected record', record: result.target, target: true }]
          .sort((a, b) => a.record.timestamp - b.record.timestamp);
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {result.session ? (
              <Typography variant="body2" color="text.secondary">
                Connection {result.session.srcIp}:{result.session.srcPort} → {result.session.dstIp}:{result.session.dstPort}, {utc(result.session.first)} – {utc(result.session.last)}
              </Typography>
            ) : <Typography variant="body2" color="text.secondary">No connection contains this record; flow links use the ±{result.limits.windowNs / 1e9} s window.</Typography>}
            {result.links.length === 0 && <Typography variant="body2">No related records.</Typography>}
            {result.links.length > 0 && (
              <Box sx={{ overflowX: 'auto' }}>
                <Table size="small" aria-label="Related evidence timeline">
                  <TableHead><TableRow><TableCell>Time (UTC)</TableCell><TableCell>Offset</TableCell><TableCell>Link</TableCell><TableCell>Record</TableCell><TableCell>Details</TableCell></TableRow></TableHead>
                  <TableBody>
                    {rows.map(row => (
                      <TableRow key={`${row.record.type}-${row.record.ordinal}`} selected={row.target}>
                        <TableCell sx={{ whiteSpace: 'nowrap', fontFamily: 'monospace' }}>{utc(row.record.timestamp)}</TableCell>
                        <TableCell sx={{ whiteSpace: 'nowrap', fontFamily: 'monospace' }}>{offset(row.record.timestamp, base)}</TableCell>
                        <TableCell>{row.target ? <Chip size="small" label="Selected" color="primary" /> :
                          <Chip size="small" label={linkKindLabels[row.kind as keyof typeof linkKindLabels]} color={kindColor[row.kind as keyof typeof kindColor]} title={row.basis} />}</TableCell>
                        <TableCell>{row.record.type}</TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all' }}>{summary(row.record)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Box>
            )}
            {result.notes.map(note => <Typography key={note} variant="caption" color="text.secondary">{note}</Typography>)}
          </Box>
        );
      })()}
    </Paper>
  );
}

export default RelatedEvidence;
