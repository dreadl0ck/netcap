/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useEffect } from 'react';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/GridLegacy';
import LinearProgress from '@mui/material/LinearProgress';
import Typography from '@mui/material/Typography';
import SpeedIcon from '@mui/icons-material/Speed';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import MemoryIcon from '@mui/icons-material/Memory';
import PublicIcon from '@mui/icons-material/Public';
import StorageIcon from '@mui/icons-material/Storage';
import DatasetIcon from '@mui/icons-material/Dataset';
import TerminalIcon from '@mui/icons-material/Terminal';

import { formatBytes, getBackendUrl } from '../lib/api';

import { useNetcapApi } from '../hooks';
import { ALL_PCAPS_SCOPE } from './DashboardPcapScopeSelector';

import { ChartFrame } from './ChartFrame';
import { ShowcaseStory } from './ShowcaseStory';
import { useNetcapLink } from '../providers/NetcapProvider';
import { translate as i18nText, richText as i18nRichText, formatNumber as i18nNumber, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";


interface Props {
  scope: string;
}

export default function OverviewView({ scope }: Props) {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const Link = useNetcapLink();

  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus(), { refreshInterval: 2000 });
  const { data: stats, mutate: mutateStats } = useSWR(['stats', scope], () => api.getStats(), {
    refreshInterval: status?.isProcessing ? 1000 : 0,
  });
  // Scope is forwarded to audit-stats / audit-files; "all" maps to backend's
  // aggregate path, anything else to a per-pcap subset.
  const auditScope = scope;
  const { data: auditStats, mutate: mutateAuditStats } = useSWR(['auditStats', scope], () => api.getAuditStats(scope), {
    refreshInterval: status?.isProcessing ? 5000 : 10000,
  });
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: auditFiles, mutate: mutateAuditFiles } = useSWR(['auditFiles', scope], () => api.getAuditFiles(scope));
  const { data: logFiles, mutate: mutateLogFiles } = useSWR('logFiles', () => api.getLogFiles());
  const { data: systemInfo } = useSWR('systemInfo', () => api.getSystemInfo());

  // Refresh on directory change events fired by other parts of the UI.
  useEffect(() => {
    const handler = () => {
      mutateStatus();
      mutateStats();
      mutateAuditStats();
      mutateAuditFiles();
      mutateLogFiles();
    };
    window.addEventListener('directory-changed', handler);
    return () => window.removeEventListener('directory-changed', handler);
  }, [mutateStatus, mutateStats, mutateAuditStats, mutateAuditFiles, mutateLogFiles]);

  const totalAuditRecords = (auditFiles || []).reduce((sum, file) => sum + (file.recordCount || 0), 0);

  // Only count input files relevant to the current scope. For "all" or per-PCAP
  // we still report total registered captures so the user has context.
  const inputFilesCount = inputFiles?.length || 0;

  // Geo-all already aggregates across all sessions; per-pcap scope forwards.
  const geoSrc = `${getBackendUrl()}/api/visualize/geo-all?showLegend=false${auditScope ? `&scope=${encodeURIComponent(auditScope)}` : ''}`;

  if (status?.isServiceMode && !status.sessionId && (!scope || scope === 'current')) {
    return <Typography color="text.secondary">Choose a <Link href="/pcaps">capture</Link> to open its findings.</Typography>;
  }

  return (
    <Box>{scope === 'current' && <ShowcaseStory sessionId={status?.sessionId} />}{status?.isProcessing && stats?.processingStats && (
        <Box mb={3}><Card data-learn={i18nText("ui:m_84c137a7305554d87b6c")} sx={{ borderColor: 'rgba(59,130,246,.42)', boxShadow: '0 16px 50px rgba(59,130,246,.08)' }}><CardContent><Box display="flex" alignItems="center" gap={1} mb={2}><SpeedIcon color="primary" /><Typography variant="h6">{i18nText("ui:m_edb9732a0e38a2035859")}</Typography><Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 0.75, color: 'success.main', fontFamily: 'var(--netcap-mono)', fontSize: '0.68rem' }}><Box sx={{ width: 7, height: 7, borderRadius: '50%', bgcolor: 'success.main', boxShadow: '0 0 12px currentColor' }} />{i18nText("ui:m_1c60a0eefc2b38261cab")}
                </Box></Box>{status.isServiceMode ? (
                <Grid container spacing={3}><Grid item xs={12} md={6}><Box display="flex" alignItems="center" gap={2} mb={1}><InsertDriveFileIcon fontSize="small" color="action" /><Typography variant="body2">{i18nRichText("ui:m_450817484cf1f3043c75", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</Typography></Box><Typography variant="h6" sx={{ ml: 4, fontFamily: 'monospace' }}>{stats.processingStats.currentFile || i18nText("ui:m_a5d19b9b86ff54945f03")}</Typography></Grid><Grid item xs={12} md={6}><Box display="flex" alignItems="center" gap={2} mb={1}><Typography variant="body2">{i18nRichText("ui:m_b2eca18914dff22e0975", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</Typography></Box><Typography variant="h6" sx={{ ml: 4 }}>
                      {i18nRichText("ui:m_4e3fae4e355d1e536caa", { arg0: stats.processingStats.queueLength || 0 })}
                    </Typography><Typography variant="caption" color="text.secondary" sx={{ ml: 4 }}>
                      {i18nRichText("ui:m_779d16815bd54b46486a", { arg0: stats.processingStats.jobsProcessed || 0, arg1: stats.processingStats.jobsScheduled || 0 })}
                    </Typography></Grid></Grid>
              ) : (
                <Grid container spacing={2}><Grid item xs={12}><Box display="flex" alignItems="center" gap={2} mb={1}><InsertDriveFileIcon fontSize="small" color="action" /><Typography variant="body2">{i18nRichText("ui:m_eeb29dafec063150220b", { arg0: stats.processingStats.currentFile || i18nText("ui:m_8dc598ebf1e055830140"), tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</Typography></Box><Typography variant="body2" color="text.secondary" sx={{ ml: 4 }}>
                      {i18nRichText("ui:m_e05e0568969bdbcfd997", { arg0: stats.processingStats.fileIndex, arg1: stats.processingStats.totalFiles })}
                    </Typography></Grid><Grid item xs={12}><Box mb={1}><Box display="flex" justifyContent="space-between" mb={0.5}><Typography variant="body2" color="text.secondary">{i18nText("ui:m_3655e2cfacf3ff0820fd")}</Typography><Typography variant="body2" fontWeight="bold">{i18nNumber(stats.processingStats.progressPercent, { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false })}%</Typography></Box><LinearProgress variant="determinate" value={stats.processingStats.progressPercent} sx={{ height: 8, borderRadius: 1 }} /></Box><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_6f1bb631d0132e391ea4", { arg0: stats.processingStats.packetsProcessed.toLocaleString(getUILocale()), arg1: stats.processingStats.totalPackets })}
                    </Typography></Grid></Grid>
              )}</CardContent></Card></Box>
      )}{auditStats && (auditStats.exploitCount > 0 || auditStats.vulnerabilityCount > 0 || auditStats.secretCount > 0 || auditStats.softwareCount > 0) && (
        <Box mb={3}><Card><CardContent><Box display="flex" alignItems="center" justifyContent="space-between" mb={2.5}><Typography variant="h6">{i18nText("ui:m_1a81d5d40ef6e910ccad")}</Typography><Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'var(--netcap-mono)' }}>{i18nText("ui:m_a863fe3c4de652e7b74e")}</Typography></Box><Grid container spacing={2}>{[
                  { label: 'Exploits', count: auditStats.exploitCount, bg: 'rgba(251,113,133,.08)', border: 'rgba(251,113,133,.25)' },
                  { label: 'Vulnerabilities', count: auditStats.vulnerabilityCount, bg: 'rgba(251,191,36,.08)', border: 'rgba(251,191,36,.25)' },
                  { label: 'Secrets', count: auditStats.secretCount, bg: 'rgba(56,189,248,.08)', border: 'rgba(56,189,248,.25)' },
                  { label: 'Software', count: auditStats.softwareCount, bg: 'rgba(52,211,153,.08)', border: 'rgba(52,211,153,.25)' },
                ].map((m) => (
                  <Grid key={m.label} item xs={12} sm={6} md={3}><Box sx={{ p: 2, borderRadius: 2, border: '1px solid', borderColor: m.border, backgroundColor: m.bg, color: 'text.primary' }}><Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: '.06em' }}>{i18nText(m.label)}</Typography><Typography variant="h3" sx={{ mt: 1, fontFamily: 'var(--netcap-mono)', fontWeight: 600, fontSize: { xs: '1.6rem', md: '2rem' } }}>{m.count.toLocaleString(getUILocale())}</Typography></Box></Grid>
                ))}</Grid></CardContent></Card></Box>
      )}<Grid container spacing={2}><Grid item xs={12} sm={6} md={3}><Card sx={{ height: '100%' }}><CardContent><Box display="flex" justifyContent="space-between" alignItems="flex-start"><Box><Typography color="text.secondary" variant="caption" sx={{ textTransform: 'uppercase', letterSpacing: '.06em' }}>{i18nText("ui:m_e4f95cae6c8955928534")}</Typography><Typography variant="h3" sx={{ mt: 1, fontFamily: 'var(--netcap-mono)', fontSize: '2rem' }}>{inputFilesCount}</Typography></Box><Box sx={{ p: 1, borderRadius: 2, color: 'primary.main', bgcolor: 'rgba(59,130,246,.1)' }}><StorageIcon /></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={3}><Card sx={{ height: '100%' }}><CardContent><Box display="flex" justifyContent="space-between" alignItems="flex-start"><Box><Typography color="text.secondary" variant="caption" sx={{ textTransform: 'uppercase', letterSpacing: '.06em' }}>{i18nText("ui:m_2532227a0436e915130b")}</Typography><Typography variant="h3" sx={{ mt: 1, fontFamily: 'var(--netcap-mono)', fontSize: '2rem' }}>{auditFiles?.length || 0}</Typography></Box><Box sx={{ p: 1, borderRadius: 2, color: 'secondary.main', bgcolor: 'rgba(139,92,246,.1)' }}><DatasetIcon /></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={3}><Card sx={{ height: '100%' }}><CardContent><Box display="flex" justifyContent="space-between" alignItems="flex-start"><Box><Typography color="text.secondary" variant="caption" sx={{ textTransform: 'uppercase', letterSpacing: '.06em' }}>{i18nText("ui:m_8d0f39c8c61ddd849518")}</Typography><Typography variant="h3" sx={{ mt: 1, fontFamily: 'var(--netcap-mono)', fontSize: '2rem' }}>{totalAuditRecords.toLocaleString(getUILocale())}</Typography></Box><Box sx={{ p: 1, borderRadius: 2, color: 'info.main', bgcolor: 'rgba(56,189,248,.1)' }}><PublicIcon /></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={3}><Card sx={{ height: '100%' }}><CardContent><Box display="flex" justifyContent="space-between" alignItems="flex-start"><Box><Typography color="text.secondary" variant="caption" sx={{ textTransform: 'uppercase', letterSpacing: '.06em' }}>{i18nText("ui:m_645dd13a0d169310324b")}</Typography><Typography variant="h3" sx={{ mt: 1, fontFamily: 'var(--netcap-mono)', fontSize: '2rem' }}>{logFiles?.length || 0}</Typography></Box><Box sx={{ p: 1, borderRadius: 2, color: 'success.main', bgcolor: 'rgba(52,211,153,.1)' }}><TerminalIcon /></Box></Box></CardContent></Card></Grid></Grid>{totalAuditRecords > 0 && (
        <Box mt={3}><Card><CardContent><Box display="flex" alignItems="center" gap={1} mb={2}><PublicIcon color="primary" /><Box><Typography variant="h6">{i18nText("ui:m_0715ed77873d72a3b553")}</Typography><Typography variant="caption" color="text.secondary">{i18nText("ui:m_d4133c1acda7757fb799")}</Typography></Box></Box><Box sx={{ width: '100%', height: { xs: 300, sm: 450, md: 560 }, borderRadius: 2, overflow: 'hidden', backgroundColor: 'background.default', border: '1px solid', borderColor: 'divider' }}><ChartFrame key={scope}
                  src={geoSrc}
                  style={{ width: '100%', height: '100%', border: 'none', display: 'block' }}
                  title={i18nText("ui:m_26416df1cb50ccf4334b")} /></Box><Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>{scope === ALL_PCAPS_SCOPE ? i18nText("ui:m_5f8c99f4062e3d8d9481") : i18nText("ui:m_c1c6be061fca910c66ff")}</Typography></CardContent></Card></Box>
      )}{systemInfo && (
        <Box mt={3}><Card><CardContent><Box display="flex" alignItems="center" gap={1} mb={2}><MemoryIcon color="primary" /><Typography variant="h6">{i18nText("ui:m_f855538adb6dd2022390")}</Typography></Box><Grid container spacing={2}><Grid item xs={12} sm={6} md={3}><Box sx={{ p: 2, borderRadius: 2, bgcolor: 'rgba(59,130,246,.08)', border: '1px solid rgba(59,130,246,.2)', minHeight: 116, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}><Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>{i18nText("ui:m_2de24b8cc8d36a3fbfbb")}</Typography><Typography variant="h3" sx={{ fontFamily: 'var(--netcap-mono)', fontSize: '1.75rem' }}>{systemInfo.numCPU}</Typography></Box></Grid><Grid item xs={12} sm={6} md={3}><Box sx={{ p: 2, borderRadius: 2, bgcolor: 'rgba(52,211,153,.07)', border: '1px solid rgba(52,211,153,.18)', minHeight: 116, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}><Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>{i18nText("ui:m_3a51b8b38270acb52a17")}</Typography><Typography variant="h3" sx={{ fontFamily: 'var(--netcap-mono)', fontSize: '1.75rem' }}>{formatBytes(systemInfo.totalMemory)}</Typography></Box></Grid><Grid item xs={12} sm={6} md={3}><Box sx={{ p: 2, borderRadius: 2, bgcolor: 'rgba(56,189,248,.07)', border: '1px solid rgba(56,189,248,.18)', minHeight: 116, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}><Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>{i18nText("ui:m_6867473d4478413a0792")}</Typography><Typography variant="h3" sx={{ fontFamily: 'var(--netcap-mono)', fontSize: '1.75rem' }}>{formatBytes(systemInfo.freeMemory)}</Typography><Typography variant="caption" sx={{ opacity: 0.8, display: 'block', mt: 0.5 }}>
                      {i18nRichText("ui:m_605d85a25489fce4db34", { arg0: i18nNumber(((systemInfo.freeMemory / systemInfo.totalMemory) * 100), { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false }) })}
                    </Typography></Box></Grid><Grid item xs={12} sm={6} md={3}><Box sx={{ p: 2, borderRadius: 2, bgcolor: 'rgba(139,92,246,.08)', border: '1px solid rgba(139,92,246,.2)', minHeight: 116, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}><Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>{i18nText("ui:m_c40842521044a48c10eb")}</Typography><Typography variant="h6" sx={{ fontFamily: 'var(--netcap-mono)' }}>{systemInfo.goos}/{systemInfo.goarch}</Typography><Typography variant="caption" sx={{ opacity: 0.8, display: 'block', mt: 0.5 }}>{i18nRichText("ui:m_799cdcc01b403befa169", { arg0: systemInfo.numGoroutine })}</Typography></Box></Grid></Grid></CardContent></Card></Box>
      )}</Box>
  );
}
