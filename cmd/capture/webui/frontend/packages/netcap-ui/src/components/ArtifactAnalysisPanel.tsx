import { Alert, Box, Typography } from '@mui/material';
import useSWR from 'swr';
import { useNetcapApi } from '../hooks';
import type { ArtifactAnalysisReport, OfflineSelection } from '../lib/api';

export function ArtifactAnalysisSummary({ report, sha256 }: { report: ArtifactAnalysisReport; sha256?: string }) {
  const selected = sha256 ? report.results[sha256] : undefined;
  return <Box sx={{ mb: 2 }}>
    <Alert severity={report.state === 'complete' ? 'info' : 'warning'}>
      Artifact processing: {report.state}. {Object.keys(report.results).length} content analysis results; {report.rejected} rejected.
      {report.state === 'partial' && ' Coverage is incomplete; this is not a clean scan.'}
    </Alert>
    {report.analyzers?.map(engine => <Typography key={engine.engine} variant="body2">{engine.engine}: {engine.state}</Typography>)}
    {report.extractionIssues?.length ? <details><summary>Extraction issues</summary>{report.extractionIssues.map((issue, i) => <Typography key={i} variant="body2">{issue}</Typography>)}</details> : null}
    {sha256 && !selected && <Typography variant="body2">No analysis result for the selected artifact. Disabled, legacy or rejected analysis is not a no-match.</Typography>}
    {selected?.analyzers.map(result => <Alert key={result.engine} sx={{ mt: 1 }} severity={result.state === 'completed' ? (result.outcome === 'matched' ? 'warning' : 'info') : 'error'}>
      {result.engine}: {result.state}{result.outcome ? ` · ${result.outcome}` : ''}
      {result.matches?.length ? ` · ${result.matches.join(', ')}` : ''}
      {result.classification ? ` · ${result.classification.Label}` : ''}
      {result.error ? ` · ${result.error}` : ''}
    </Alert>)}
  </Box>;
}

export default function ArtifactAnalysisPanel({ selection, sha256 }: { selection: OfflineSelection; sha256?: string }) {
  const api = useNetcapApi();
  const { data, error } = useSWR(['artifact-analysis', selection.inputFile, selection.sessionId], () => api.getArtifactAnalysis(selection), { refreshInterval: 5000, shouldRetryOnError: false });
  if (error) return <Alert severity={error.status === 404 ? 'info' : 'error'} sx={{ mb: 2 }}>{error.status === 404 ? 'Artifact analysis coverage is unavailable for this capture.' : `Artifact analysis report could not be read: ${error.message}`}</Alert>;
  if (!data) return <Typography variant="body2">Loading artifact analysis coverage…</Typography>;
  return <ArtifactAnalysisSummary report={data} sha256={sha256} />;
}
