/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useEffect } from 'react';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import LinearProgress from '@mui/material/LinearProgress';
import Typography from '@mui/material/Typography';
import SpeedIcon from '@mui/icons-material/Speed';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import MemoryIcon from '@mui/icons-material/Memory';
import PublicIcon from '@mui/icons-material/Public';

import { formatBytes, getBackendUrl } from '../lib/api';
import useSWR from 'swr';
import { useNetcapApi } from '../hooks';
import { ALL_PCAPS_SCOPE } from './DashboardPcapScopeSelector';

import { ChartFrame } from './ChartFrame';
interface Props {
  scope: string;
}

export default function OverviewView({ scope }: Props) {
  const api = useNetcapApi();

  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus(), { refreshInterval: 2000 });
  const { data: stats, mutate: mutateStats } = useSWR(['stats', scope], () => api.getStats(), {
    refreshInterval: status?.isProcessing ? 1000 : 0,
  });
  // Scope is forwarded to audit-stats / audit-files; "all" maps to backend's
  // aggregate path, anything else to a per-pcap subset.
  const auditScope = scope === ALL_PCAPS_SCOPE ? '' : scope; // empty -> server's "current" / "aggregate" default
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

  return (
    <Box>
      {status?.isProcessing && stats?.processingStats && (
        <Box mb={4}>
          <Card data-learn="Live Processing: Real-time statistics showing current PCAP analysis progress, packet counts, and processing speed.">
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <SpeedIcon color="primary" />
                <Typography variant="h6">Live Processing Statistics</Typography>
              </Box>
              {status.isServiceMode ? (
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Box display="flex" alignItems="center" gap={2} mb={1}>
                      <InsertDriveFileIcon fontSize="small" color="action" />
                      <Typography variant="body2"><strong>Currently Processing:</strong></Typography>
                    </Box>
                    <Typography variant="h6" sx={{ ml: 4, fontFamily: 'monospace' }}>
                      {stats.processingStats.currentFile || 'Idle'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Box display="flex" alignItems="center" gap={2} mb={1}>
                      <Typography variant="body2"><strong>Queue Status:</strong></Typography>
                    </Box>
                    <Typography variant="h6" sx={{ ml: 4 }}>
                      {stats.processingStats.queueLength || 0} files waiting
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ ml: 4 }}>
                      {stats.processingStats.jobsProcessed || 0} / {stats.processingStats.jobsScheduled || 0} jobs completed
                    </Typography>
                  </Grid>
                </Grid>
              ) : (
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <Box display="flex" alignItems="center" gap={2} mb={1}>
                      <InsertDriveFileIcon fontSize="small" color="action" />
                      <Typography variant="body2"><strong>Current File:</strong> {stats.processingStats.currentFile || 'N/A'}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ ml: 4 }}>
                      File {stats.processingStats.fileIndex} of {stats.processingStats.totalFiles}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Box mb={1}>
                      <Box display="flex" justifyContent="space-between" mb={0.5}>
                        <Typography variant="body2" color="text.secondary">Progress</Typography>
                        <Typography variant="body2" fontWeight="bold">{stats.processingStats.progressPercent.toFixed(1)}%</Typography>
                      </Box>
                      <LinearProgress variant="determinate" value={stats.processingStats.progressPercent} sx={{ height: 8, borderRadius: 1 }} />
                    </Box>
                    <Typography variant="caption" color="text.secondary">
                      {stats.processingStats.packetsProcessed.toLocaleString()} / {stats.processingStats.totalPackets.toLocaleString()} packets
                    </Typography>
                  </Grid>
                </Grid>
              )}
            </CardContent>
          </Card>
        </Box>
      )}

      {auditStats && (auditStats.exploitCount > 0 || auditStats.vulnerabilityCount > 0 || auditStats.secretCount > 0 || auditStats.softwareCount > 0) && (
        <Box mb={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>Security Audit Records</Typography>
              <Grid container spacing={3}>
                {[
                  { label: 'Exploits', count: auditStats.exploitCount, bg: 'error.dark' },
                  { label: 'Vulnerabilities', count: auditStats.vulnerabilityCount, bg: 'warning.dark' },
                  { label: 'Secrets', count: auditStats.secretCount, bg: 'info.dark' },
                  { label: 'Software', count: auditStats.softwareCount, bg: 'success.dark' },
                ].map((m) => (
                  <Grid key={m.label} item xs={12} sm={6} md={3}>
                    <Box sx={{ p: 2, borderRadius: 2, backgroundColor: m.bg, color: 'white', textAlign: 'center' }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>{m.label}</Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold', fontSize: { xs: '1.75rem', sm: '2.5rem', md: '3rem' } }}>{m.count.toLocaleString()}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Box>
      )}

      <Grid container spacing={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>Data Sources</Typography>
              <Typography variant="h3" sx={{ fontSize: { xs: '1.75rem', sm: '2.5rem', md: '3rem' } }}>{inputFilesCount}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>Audit Record Types</Typography>
              <Typography variant="h3" sx={{ fontSize: { xs: '1.75rem', sm: '2.5rem', md: '3rem' } }}>{auditFiles?.length || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>Total Records</Typography>
              <Typography variant="h3" sx={{ fontSize: { xs: '1.75rem', sm: '2.5rem', md: '3rem' } }}>{totalAuditRecords.toLocaleString()}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>Log Files</Typography>
              <Typography variant="h3" sx={{ fontSize: { xs: '1.75rem', sm: '2.5rem', md: '3rem' } }}>{logFiles?.length || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {totalAuditRecords > 0 && (
        <Box mt={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <PublicIcon color="primary" />
                <Typography variant="h6">Global IP Geolocation Distribution</Typography>
              </Box>
              <Box sx={{ width: '100%', height: { xs: 300, sm: 450, md: 600 }, borderRadius: 1, overflow: 'hidden', backgroundColor: '#1e1e1e' }}>
                <ChartFrame
                  key={scope}
                  src={geoSrc}
                  style={{ width: '100%', height: '100%', border: 'none', display: 'block' }}
                  title="Global Geolocation Chart"
                />
              </Box>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                {scope === ALL_PCAPS_SCOPE
                  ? 'Aggregated geolocation data from all hosts across all captures'
                  : 'Geolocation data from the selected capture'}
              </Typography>
            </CardContent>
          </Card>
        </Box>
      )}

      {systemInfo && (
        <Box mt={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={2}>
                <MemoryIcon color="primary" />
                <Typography variant="h6">System Information</Typography>
              </Box>
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6} md={3}>
                  <Box sx={{ p: 2, borderRadius: 2, backgroundColor: 'primary.dark', color: 'white', textAlign: 'center', minHeight: 140, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                    <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>CPU Cores</Typography>
                    <Typography variant="h3" sx={{ fontWeight: 'bold', fontSize: { xs: '1.75rem', sm: '2.5rem', md: '3rem' } }}>{systemInfo.numCPU}</Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box sx={{ p: 2, borderRadius: 2, backgroundColor: 'success.dark', color: 'white', textAlign: 'center', minHeight: 140, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                    <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>Total Memory</Typography>
                    <Typography variant="h3" sx={{ fontWeight: 'bold', fontSize: { xs: '1.75rem', sm: '2.5rem', md: '3rem' } }}>{formatBytes(systemInfo.totalMemory)}</Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box sx={{ p: 2, borderRadius: 2, backgroundColor: 'info.dark', color: 'white', textAlign: 'center', minHeight: 140, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                    <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>Free Memory</Typography>
                    <Typography variant="h3" sx={{ fontWeight: 'bold', fontSize: { xs: '1.75rem', sm: '2.5rem', md: '3rem' } }}>{formatBytes(systemInfo.freeMemory)}</Typography>
                    <Typography variant="caption" sx={{ opacity: 0.8, display: 'block', mt: 0.5 }}>
                      {((systemInfo.freeMemory / systemInfo.totalMemory) * 100).toFixed(1)}% free
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box sx={{ p: 2, borderRadius: 2, backgroundColor: 'secondary.dark', color: 'white', textAlign: 'center', minHeight: 140, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                    <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>Platform</Typography>
                    <Typography variant="h6" sx={{ fontWeight: 'bold' }}>{systemInfo.goos}/{systemInfo.goarch}</Typography>
                    <Typography variant="caption" sx={{ opacity: 0.8, display: 'block', mt: 0.5 }}>{systemInfo.numGoroutine} goroutines</Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Box>
      )}
    </Box>
  );
}
