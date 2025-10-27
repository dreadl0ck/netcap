import {
  Box,
  Card,
  CardContent,
  CircularProgress,
  Typography,
  Chip,
  Grid,
  Alert,
  AlertTitle,
  Link as MuiLink,
  Divider,
  List,
  ListItem,
  ListItemText,
  Paper,
} from '@mui/material';
import Layout from '@/components/Layout';
import { api } from '@/lib/api';
import useSWR from 'swr';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import InfoIcon from '@mui/icons-material/Info';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import SecurityIcon from '@mui/icons-material/Security';

export default function DPIPage() {
  const { data: dpiInfo, error, isLoading } = useSWR('dpi', () => api.getDPIInfo(), {
    refreshInterval: 0, // Only fetch once
  });

  // Check if running in try service mode
  const { data: status } = useSWR('status', () => api.getStatus(), {
    refreshInterval: 0,
  });

  if (isLoading) {
    return (
      <Layout title="Deep Packet Inspection">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Deep Packet Inspection">
        <Box>
          <Alert severity="error">
            <AlertTitle>Error loading DPI information</AlertTitle>
            <Typography variant="body2">
              Make sure the backend server is running and accessible.
            </Typography>
            <Typography variant="body2" sx={{ mt: 1, fontFamily: 'monospace' }}>
              {error.toString()}
            </Typography>
          </Alert>
        </Box>
      </Layout>
    );
  }

  if (!dpiInfo) {
    return (
      <Layout title="Deep Packet Inspection">
        <Box>
          <Alert severity="warning">
            <AlertTitle>No DPI information available</AlertTitle>
          </Alert>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Deep Packet Inspection">
      <Box>
        <Box mb={4}>
          <Box display="flex" alignItems="center" gap={2} mb={2}>
            <SecurityIcon color="primary" fontSize="large" />
            <Typography variant="h4" gutterBottom>
              Deep Packet Inspection Configuration
            </Typography>
          </Box>
          <Typography variant="body1" color="text.secondary">
            {status?.isTryService 
              ? 'View DPI configuration and supported protocols'
              : 'Configure and monitor DPI modules for application layer protocol identification'}
          </Typography>
        </Box>

        {/* Try Service Mode Alert */}
        {status?.isTryService && (
          <Alert severity="info" sx={{ mb: 4 }}>
            <AlertTitle>Try Service Mode</AlertTitle>
            <Typography variant="body2">
              You are viewing the DPI configuration in try service mode. 
              This page is read-only and shows the current DPI settings configured by the service administrator.
              DPI is {dpiInfo?.enabled ? 'enabled' : 'disabled'} for your analysis sessions.
            </Typography>
          </Alert>
        )}

        {/* DPI Support Status */}
        <Grid container spacing={3} mb={4}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" gap={2} mb={2}>
                  {dpiInfo.hasSupport ? (
                    <CheckCircleIcon color="success" fontSize="large" />
                  ) : (
                    <CancelIcon color="error" fontSize="large" />
                  )}
                  <Box>
                    <Typography variant="h6">DPI Support</Typography>
                    <Chip
                      label={dpiInfo.hasSupport ? 'Compiled In' : 'Not Available'}
                      color={dpiInfo.hasSupport ? 'success' : 'error'}
                      size="small"
                    />
                  </Box>
                </Box>
                {!dpiInfo.hasSupport && (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      DPI support is not compiled into this build. Rebuild with DPI libraries to enable.
                    </Typography>
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" gap={2} mb={2}>
                  {dpiInfo.enabled ? (
                    <CheckCircleIcon color="success" fontSize="large" />
                  ) : (
                    <InfoIcon color="warning" fontSize="large" />
                  )}
                  <Box>
                    <Typography variant="h6">DPI Status</Typography>
                    <Chip
                      label={dpiInfo.enabled ? 'Enabled' : 'Disabled'}
                      color={dpiInfo.enabled ? 'success' : 'default'}
                      size="small"
                    />
                  </Box>
                </Box>
                <Alert severity="info" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    {status?.isTryService 
                      ? 'DPI is configured by the service administrator and applies to all analysis sessions.'
                      : 'DPI is configured at capture startup using the -dpi flag. Modules can be specified with the -dpi-modules flag (e.g., "ndpi,lpi,go").'}
                  </Typography>
                </Alert>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Library Versions */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Library Versions
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    nDPI Version
                  </Typography>
                  <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                    {dpiInfo.ndpiVersion || 'N/A'}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Network Deep Packet Inspection library
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Libprotoident Version
                  </Typography>
                  <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                    {dpiInfo.libprotoidentVersion || 'N/A'}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Lightweight protocol identification library
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    go-dpi Version
                  </Typography>
                  <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                    {dpiInfo.goDpiVersion || 'N/A'}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Go wrapper for DPI libraries
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {/* Active Modules */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              DPI Modules
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Available Modules
                </Typography>
                <List dense>
                  {dpiInfo.availableModules.map((module) => (
                    <ListItem key={module}>
                      <ListItemText
                        primary={
                          <Box display="flex" alignItems="center" gap={1}>
                            <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                              {module}
                            </Typography>
                            <Chip
                              label={dpiInfo.activeModules.includes(module) ? 'Active' : 'Inactive'}
                              color={dpiInfo.activeModules.includes(module) ? 'success' : 'default'}
                              size="small"
                            />
                          </Box>
                        }
                        secondary={getModuleDescription(module)}
                      />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <Alert severity="info" icon={<InfoIcon />}>
                  <AlertTitle>Module Configuration</AlertTitle>
                  {status?.isTryService ? (
                    <Typography variant="body2">
                      The DPI modules shown are configured by the service administrator and are applied automatically to your analysis sessions.
                    </Typography>
                  ) : (
                    <>
                      <Typography variant="body2" gutterBottom>
                        To enable specific DPI modules, use the <code>-dpi-modules</code> flag when starting capture:
                      </Typography>
                      <Box
                        component="pre"
                        sx={{
                          mt: 1,
                          p: 1,
                          bgcolor: 'background.paper',
                          borderRadius: 1,
                          fontSize: '0.875rem',
                          overflowX: 'auto',
                        }}
                      >
                        net capture -r input.pcap -dpi -dpi-modules "ndpi,lpi,go"
                      </Box>
                    </>
                  )}
                </Alert>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {/* Supported Protocols */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Supported Protocols & Applications
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper elevation={0} sx={{ p: 3, bgcolor: 'background.default' }}>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <SecurityIcon color="primary" />
                    <Typography variant="h6">nDPI</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    nDPI (Network Deep Packet Inspection) identifies 244+ applications and protocols.
                  </Typography>
                  <MuiLink
                    href={dpiInfo.ndpiProtocolsUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
                  >
                    View Supported Protocols
                    <OpenInNewIcon fontSize="small" />
                  </MuiLink>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper elevation={0} sx={{ p: 3, bgcolor: 'background.default' }}>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <SecurityIcon color="primary" />
                    <Typography variant="h6">Libprotoident</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    Libprotoident (LPI) identifies 500+ applications and 45 protocol categories using lightweight pattern matching.
                  </Typography>
                  <MuiLink
                    href={dpiInfo.libprotoidentProtocolsUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
                  >
                    View Supported Protocols
                    <OpenInNewIcon fontSize="small" />
                  </MuiLink>
                </Paper>
              </Grid>
              <Grid item xs={12}>
                <Alert severity="info">
                  <Typography variant="body2">
                    DPI results are available in the <strong>Connection</strong>, <strong>Service</strong>, 
                    <strong> DeviceProfile</strong>, and <strong>IPProfile</strong> audit records in the{' '}
                    <code>Applications</code> field.
                  </Typography>
                </Alert>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Box>
    </Layout>
  );
}

function getModuleDescription(module: string): string {
  switch (module) {
    case 'ndpi':
      return 'nDPI library for deep packet inspection and protocol identification';
    case 'lpi':
      return 'Libprotoident for lightweight protocol identification';
    case 'go':
      return 'Go-based heuristic classifiers';
    default:
      return 'Unknown module';
  }
}

