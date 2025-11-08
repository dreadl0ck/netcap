import { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  CircularProgress,
  Grid,
  LinearProgress,
  Typography,
  Chip,
  Button,
  Alert,
} from '@mui/material';
import Layout from '@/components/Layout';
import { api, formatTimestamp, formatBytes } from '@/lib/api';
import useSWR from 'swr';
import { useRouter } from 'next/router';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';
import SpeedIcon from '@mui/icons-material/Speed';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import MemoryIcon from '@mui/icons-material/Memory';
import StopIcon from '@mui/icons-material/Stop';
import RadioButtonCheckedIcon from '@mui/icons-material/RadioButtonChecked';
import PublicIcon from '@mui/icons-material/Public';

export default function Dashboard() {
  const router = useRouter();
  const [stopping, setStopping] = useState(false);
  const [stopMessage, setStopMessage] = useState<string | null>(null);
  const { data: status, error: statusError, mutate: mutateStatus } = useSWR('status', () => api.getStatus(), {
    refreshInterval: 2000,
  });
  const { data: stats, mutate: mutateStats } = useSWR('stats', () => api.getStats(), {
    refreshInterval: status?.isProcessing ? 1000 : 0, // Poll every second when processing
  });
  const { data: auditStats, error: auditStatsError, mutate: mutateAuditStats } = useSWR('auditStats', () => api.getAuditStats(), {
    refreshInterval: status?.isProcessing ? 5000 : 10000, // Poll every 5 seconds when processing, every 10 seconds otherwise
  });
  const { data: inputFiles, error: inputError, mutate: mutateInputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: auditFiles, error: auditError, mutate: mutateAuditFiles } = useSWR('auditFiles', () => api.getAuditFiles());
  const { data: logFiles, error: logError, mutate: mutateLogFiles } = useSWR('logFiles', () => api.getLogFiles());
  const { data: systemInfo, error: systemInfoError } = useSWR('systemInfo', () => api.getSystemInfo());

  const handleStopCapture = async () => {
    try {
      setStopping(true);
      setStopMessage(null);
      const response = await api.stopCapture();
      setStopMessage(response.message);
      // Refresh status after stopping
      setTimeout(() => {
        mutateStatus();
      }, 1000);
    } catch (err) {
      console.error('Failed to stop capture:', err);
      setStopMessage('Failed to stop capture: ' + (err as Error).message);
    } finally {
      setStopping(false);
    }
  };

  // Redirect to upload page if in try service mode and no active session
  useEffect(() => {
    // Only redirect if we have status data and confirmed no session/files
    if (status && status.isServiceMode && !status.sessionId && inputFiles && inputFiles.length === 0) {
      router.push('/analyze');
    }
  }, [status, inputFiles, router]);

  // Refresh stats periodically when processing
  useEffect(() => {
    if (!status?.isProcessing) return;
    
    const interval = setInterval(() => {
      mutateStats();
    }, 1000);
    
    return () => clearInterval(interval);
  }, [status?.isProcessing, mutateStats]);

  // Listen for directory changes and refresh all data
  useEffect(() => {
    const handleDirectoryChange = () => {
      console.log('Directory changed, refreshing dashboard...');
      mutateStatus();
      mutateAuditFiles();
      mutateLogFiles();
      mutateStats();
      mutateAuditStats();
    };
    
    window.addEventListener('directory-changed', handleDirectoryChange);
    return () => window.removeEventListener('directory-changed', handleDirectoryChange);
  }, [mutateStatus, mutateAuditFiles, mutateLogFiles, mutateStats, mutateAuditStats]);

  const isLoading = !status && !statusError;
  const hasError = statusError || inputError || auditError || logError || auditStatsError || systemInfoError;

  if (isLoading) {
    return (
      <Layout title="Dashboard">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (hasError) {
    return (
      <Layout title="Dashboard">
        <Box>
          <Typography color="error" variant="h6" gutterBottom>
            Error loading dashboard data
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Make sure the backend server is running and accessible.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Check the browser console for detailed error messages.
          </Typography>
          {statusError && (
            <Typography variant="body2" sx={{ mt: 2, fontFamily: 'monospace', color: 'error.light' }}>
              {statusError.toString()}
            </Typography>
          )}
        </Box>
      </Layout>
    );
  }

  const totalAuditRecords = auditFiles?.reduce((sum, file) => sum + (file.recordCount || 0), 0) || 0;

  return (
    <Layout title="Dashboard">
      <Box>
        <Box mb={4}>
          <Box display="flex" alignItems="center" gap={2} flexWrap="wrap">
            {status?.isProcessing ? (
              <>
                <Chip
                  icon={status?.isLiveMode ? <RadioButtonCheckedIcon /> : <HourglassEmptyIcon />}
                  label={status?.isLiveMode ? "Live Capture" : "Processing"}
                  color="warning"
                  variant="outlined"
                />
                <Typography variant="body2" color="text.secondary">
                  {status?.isLiveMode ? "Capturing packets live..." : "Capture is currently running..."}
                </Typography>
                {status?.isLiveMode && (
                  <Button
                    variant="contained"
                    color="error"
                    startIcon={<StopIcon />}
                    onClick={handleStopCapture}
                    disabled={stopping}
                    size="small"
                  >
                    {stopping ? 'Stopping...' : 'Stop Capture'}
                  </Button>
                )}
              </>
            ) : (
              <>
                <Chip
                  icon={<CheckCircleIcon />}
                  label="Complete"
                  color="success"
                  variant="outlined"
                />
                <Typography variant="body2" color="text.secondary">
                  Processing completed
                </Typography>
              </>
            )}
          </Box>
          {stopMessage && (
            <Alert severity="info" sx={{ mt: 2 }} onClose={() => setStopMessage(null)}>
              {stopMessage}
            </Alert>
          )}
        </Box>

        {/* Live Processing Stats */}
        {status?.isProcessing && stats?.processingStats && (
          <Box mb={4}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" gap={1} mb={2}>
                  <SpeedIcon color="primary" />
                  <Typography variant="h6">
                    Live Processing Statistics
                  </Typography>
                </Box>
                
                {status.isServiceMode ? (
                  // Service mode: simplified view with queue and current file
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                      <Box display="flex" alignItems="center" gap={2} mb={1}>
                        <InsertDriveFileIcon fontSize="small" color="action" />
                        <Typography variant="body2">
                          <strong>Currently Processing:</strong>
                        </Typography>
                      </Box>
                      <Typography variant="h6" sx={{ ml: 4, fontFamily: 'monospace' }}>
                        {stats.processingStats.currentFile || 'Idle'}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} md={6}>
                      <Box display="flex" alignItems="center" gap={2} mb={1}>
                        <Typography variant="body2">
                          <strong>Queue Status:</strong>
                        </Typography>
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
                  // Local mode: detailed view with progress
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <Box display="flex" alignItems="center" gap={2} mb={1}>
                        <InsertDriveFileIcon fontSize="small" color="action" />
                        <Typography variant="body2">
                          <strong>Current File:</strong> {stats.processingStats.currentFile || 'N/A'}
                        </Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ ml: 4 }}>
                        File {stats.processingStats.fileIndex} of {stats.processingStats.totalFiles}
                      </Typography>
                    </Grid>

                    <Grid item xs={12}>
                      <Box mb={1}>
                        <Box display="flex" justifyContent="space-between" mb={0.5}>
                          <Typography variant="body2" color="text.secondary">
                            Progress
                          </Typography>
                          <Typography variant="body2" fontWeight="bold">
                            {stats.processingStats.progressPercent.toFixed(1)}%
                          </Typography>
                        </Box>
                        <LinearProgress 
                          variant="determinate" 
                          value={stats.processingStats.progressPercent} 
                          sx={{ height: 8, borderRadius: 1 }}
                        />
                      </Box>
                      <Typography variant="caption" color="text.secondary">
                        {stats.processingStats.packetsProcessed.toLocaleString()} / {stats.processingStats.totalPackets.toLocaleString()} packets
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={6} md={3}>
                      <Typography variant="body2" color="text.secondary">
                        Packets/Second
                      </Typography>
                      <Typography variant="h5">
                        {stats.processingStats.packetsPerSecond.toLocaleString()}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={6} md={3}>
                      <Typography variant="body2" color="text.secondary">
                        Profiles
                      </Typography>
                      <Typography variant="h5">
                        {stats.processingStats.profilesCount}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={6} md={3}>
                      <Typography variant="body2" color="text.secondary">
                        Services
                      </Typography>
                      <Typography variant="h5">
                        {stats.processingStats.servicesCount}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} sm={6} md={3}>
                      <Typography variant="body2" color="text.secondary">
                        Last Update
                      </Typography>
                      <Typography variant="body1">
                        {new Date(stats.processingStats.lastUpdate * 1000).toLocaleTimeString()}
                      </Typography>
                    </Grid>
                  </Grid>
                )}
              </CardContent>
            </Card>
          </Box>
        )}

        {/* Audit Statistics Section */}
        {auditStats && (auditStats.exploitCount > 0 || auditStats.vulnerabilityCount > 0 || auditStats.credentialsCount > 0 || auditStats.softwareCount > 0) && (
          <Box mb={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>
                  Security Audit Records
                </Typography>
                <Grid container spacing={3}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 2, 
                      backgroundColor: 'error.dark',
                      color: 'white',
                      textAlign: 'center'
                    }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                        Exploits
                      </Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                        {auditStats.exploitCount.toLocaleString()}
                      </Typography>
                    </Box>
                  </Grid>

                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 2, 
                      backgroundColor: 'warning.dark',
                      color: 'white',
                      textAlign: 'center'
                    }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                        Vulnerabilities
                      </Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                        {auditStats.vulnerabilityCount.toLocaleString()}
                      </Typography>
                    </Box>
                  </Grid>

                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 2, 
                      backgroundColor: 'info.dark',
                      color: 'white',
                      textAlign: 'center'
                    }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                        Credentials
                      </Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                        {auditStats.credentialsCount.toLocaleString()}
                      </Typography>
                    </Box>
                  </Grid>

                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 2, 
                      backgroundColor: 'success.dark',
                      color: 'white',
                      textAlign: 'center'
                    }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                        Software
                      </Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                        {auditStats.softwareCount.toLocaleString()}
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Box>
        )}

        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Data Sources
                </Typography>
                <Typography variant="h3">{inputFiles?.length || 0}</Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Audit Record Types
                </Typography>
                <Typography variant="h3">{auditFiles?.length || 0}</Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Total Records
                </Typography>
                <Typography variant="h3">{totalAuditRecords.toLocaleString()}</Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Log Files
                </Typography>
                <Typography variant="h3">{logFiles?.length || 0}</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Geolocation Chart Section */}
        {totalAuditRecords > 0 && (
          <Box mt={4}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" gap={1} mb={2}>
                  <PublicIcon color="primary" />
                  <Typography variant="h6">
                    Global IP Geolocation Distribution
                  </Typography>
                </Box>
                <Box 
                  sx={{ 
                    width: '100%', 
                    height: 600,
                    borderRadius: 1,
                    overflow: 'hidden',
                    backgroundColor: '#1e1e1e'
                  }}
                >
                  <iframe
                    src="/api/visualize/geo-all?showLegend=false"
                    style={{
                      width: '100%',
                      height: '100%',
                      border: 'none',
                      display: 'block'
                    }}
                    title="Global Geolocation Chart"
                  />
                </Box>
                <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                  Aggregated geolocation data from all IPProfiles across all captures
                </Typography>
              </CardContent>
            </Card>
          </Box>
        )}

        {/* System Information Section */}
        {systemInfo && (
          <Box mt={4}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" gap={1} mb={2}>
                  <MemoryIcon color="primary" />
                  <Typography variant="h6">
                    System Information
                  </Typography>
                </Box>
                <Grid container spacing={3}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 2, 
                      backgroundColor: 'primary.dark',
                      color: 'white',
                      textAlign: 'center',
                      height: '100%',
                      minHeight: 140,
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'center'
                    }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                        CPU Cores
                      </Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                        {systemInfo.numCPU}
                      </Typography>
                    </Box>
                  </Grid>

                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 2, 
                      backgroundColor: 'success.dark',
                      color: 'white',
                      textAlign: 'center',
                      height: '100%',
                      minHeight: 140,
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'center'
                    }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                        Total Memory
                      </Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                        {formatBytes(systemInfo.totalMemory)}
                      </Typography>
                    </Box>
                  </Grid>

                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 2, 
                      backgroundColor: 'info.dark',
                      color: 'white',
                      textAlign: 'center',
                      height: '100%',
                      minHeight: 140,
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'center'
                    }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                        Free Memory
                      </Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                        {formatBytes(systemInfo.freeMemory)}
                      </Typography>
                      <Typography variant="caption" sx={{ opacity: 0.8, display: 'block', mt: 0.5 }}>
                        {((systemInfo.freeMemory / systemInfo.totalMemory) * 100).toFixed(1)}% free
                      </Typography>
                    </Box>
                  </Grid>

                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 2, 
                      backgroundColor: 'secondary.dark',
                      color: 'white',
                      textAlign: 'center',
                      height: '100%',
                      minHeight: 140,
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'center'
                    }}>
                      <Typography variant="body2" sx={{ opacity: 0.9, mb: 1 }}>
                        Platform
                      </Typography>
                      <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                        {systemInfo.goos}/{systemInfo.goarch}
                      </Typography>
                      <Typography variant="caption" sx={{ opacity: 0.8, display: 'block', mt: 0.5 }}>
                        {systemInfo.numGoroutine} goroutines
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Box>
        )}
      </Box>
    </Layout>
  );
}

