import { Alert, Box, Typography } from '@mui/material';

import { useNetcapApi } from '../hooks';
import type { ArtifactAnalysisReport, OfflineSelection } from '../lib/api';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";



export function ArtifactAnalysisSummary({ report, sha256 }: { report: ArtifactAnalysisReport; sha256?: string }) {
  const __uiLocale = useUILocale();
  const selected = sha256 ? report.results[sha256] : undefined;
  return <Box sx={{ mb: 2 }}><Alert severity={report.state === 'complete' ? 'info' : 'warning'}>
      {i18nRichText("ui:m_1d9597d0f9db96b2f931", { arg0: report.state, arg1: Object.keys(report.results).length, arg2: report.rejected, arg3: report.state === 'partial' && i18nText("ui:m_0718bc6022666d0999ff") })}
    </Alert>{report.analyzers?.map(engine => <Typography key={engine.engine} variant="body2">{engine.engine}: {engine.state}</Typography>)}{report.extractionIssues?.length ? <details><summary>{i18nText("ui:m_66739c3f3664cefa0699")}</summary>{report.extractionIssues.map((issue, i) => <Typography key={i} variant="body2">{issue}</Typography>)}</details> : null}{sha256 && !selected && <Typography variant="body2">{i18nText("ui:m_6dc6f23642411245fab7")}</Typography>}{selected?.analyzers.map(result => <Alert key={result.engine} sx={{ mt: 1 }} severity={result.state === 'completed' ? (result.outcome === 'matched' ? 'warning' : 'info') : 'error'}>{result.engine}: {result.state}{result.outcome ? ` · ${result.outcome}` : ''}{result.matches?.length ? ` · ${result.matches.join(', ')}` : ''}{result.classification ? ` · ${result.classification.Label}` : ''}{result.error ? ` · ${result.error}` : ''}</Alert>)}</Box>;
}

export default function ArtifactAnalysisPanel({ selection, sha256 }: { selection: OfflineSelection; sha256?: string }) {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { data, error } = useSWR(['artifact-analysis', selection.inputFile, selection.sessionId], () => api.getArtifactAnalysis(selection), { refreshInterval: 5000, shouldRetryOnError: false });
  if (error) return <Alert severity={error.status === 404 ? 'info' : 'error'} sx={{ mb: 2 }}>{error.status === 404 ? i18nText("ui:m_89fc5a1dcf535dd15fbe") : i18nText("ui:m_134411e40a6641adb4a0", { arg0: error.message })}</Alert>;
  if (!data) return <Typography variant="body2">{i18nText("ui:m_d4dc58ff9032458f4cee")}</Typography>;
  return <ArtifactAnalysisSummary report={data} sha256={sha256} />;
}
