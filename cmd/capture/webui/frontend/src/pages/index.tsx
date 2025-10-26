import React, { useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  CircularProgress,
  Grid,
  LinearProgress,
  Typography,
  Chip,
} from '@mui/material';
import Layout from '@/components/Layout';
import { api, formatTimestamp } from '@/lib/api';
import useSWR from 'swr';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';
import SpeedIcon from '@mui/icons-material/Speed';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';

export default function Dashboard() {
  const { data: status, error: statusError } = useSWR('status', () => api.getStatus(), {
    refreshInterval: 2000,
  });
  const { data: stats, mutate: mutateStats } = useSWR('stats', () => api.getStats(), {
    refreshInterval: status?.isProcessing ? 1000 : 0, // Poll every second when processing
  });
  const { data: inputFiles, error: inputError } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: auditFiles, error: auditError } = useSWR('auditFiles', () => api.getAuditFiles());
  const { data: logFiles, error: logError } = useSWR('logFiles', () => api.getLogFiles());

  // Refresh stats periodically when processing
  useEffect(() => {
    if (!status?.isProcessing) return;
    
    const interval = setInterval(() => {
      mutateStats();
    }, 1000);
    
    return () => clearInterval(interval);
  }, [status?.isProcessing, mutateStats]);

  const isLoading = !status && !statusError;
  const hasError = statusError || inputError || auditError || logError;

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
          <Typography variant="h4" gutterBottom>
            Netcap Capture Dashboard
          </Typography>
          <Box display="flex" alignItems="center" gap={2}>
            {status?.isProcessing ? (
              <>
                <Chip
                  icon={<HourglassEmptyIcon />}
                  label="Processing"
                  color="warning"
                  variant="outlined"
                />
                <Typography variant="body2" color="text.secondary">
                  Capture is currently running...
                </Typography>
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
              </CardContent>
            </Card>
          </Box>
        )}

        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Input Files
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

        <Box mt={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Capture Information
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="body2" color="text.secondary">
                    Output Directory:
                  </Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {status?.outputDir || 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="body2" color="text.secondary">
                    Server Started:
                  </Typography>
                  <Typography variant="body1">
                    {status?.serverStarted ? formatTimestamp(new Date(status.serverStarted).getTime() / 1000) : 'N/A'}
                  </Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Box>
      </Box>
    </Layout>
  );
}

