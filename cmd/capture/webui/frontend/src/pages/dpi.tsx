import { useState, useEffect } from 'react';
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
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  InputAdornment,
  Switch,
  FormControlLabel,
  Tooltip,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SearchIcon from '@mui/icons-material/Search';
import Layout from '@/components/Layout';
import { api } from '@/lib/api';
import useSWR from 'swr';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import InfoIcon from '@mui/icons-material/Info';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import SecurityIcon from '@mui/icons-material/Security';

const LOCAL_STORAGE_KEY = 'netcap_dpi_enabled_modules';

export default function DPIPage() {
  const { data: dpiInfo, error, isLoading } = useSWR('dpi', () => api.getDPIInfo(), {
    refreshInterval: 0, // Only fetch once
  });
  const [expandedModule, setExpandedModule] = useState<string | null>(null);
  const [searchQueries, setSearchQueries] = useState<Record<string, string>>({});
  const [enabledModules, setEnabledModules] = useState<Set<string>>(new Set());
  const [isSaving, setIsSaving] = useState(false);

  // Check if running in try service mode
  const { data: status } = useSWR('status', () => api.getStatus(), {
    refreshInterval: 0,
  });

  // Load enabled modules from server on mount
  useEffect(() => {
    if (typeof window !== 'undefined' && dpiInfo?.availableModules) {
      const loadPreferences = async () => {
        try {
          // Try to load from server first
          const serverPrefs = await api.getDPIPreferences();
          setEnabledModules(new Set(serverPrefs.enabledModules));
          // Also save to localStorage as cache
          localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(serverPrefs.enabledModules));
        } catch (e) {
          console.warn('Failed to load DPI preferences from server, using local cache:', e);
          // Fall back to localStorage
          const stored = localStorage.getItem(LOCAL_STORAGE_KEY);
          if (stored) {
            try {
              const parsed = JSON.parse(stored);
              setEnabledModules(new Set(parsed));
            } catch (parseError) {
              // If parsing fails, initialize with active modules
              setEnabledModules(new Set(dpiInfo.activeModules));
            }
          } else {
            // Initialize with active modules if nothing is stored
            setEnabledModules(new Set(dpiInfo.activeModules));
          }
        }
      };
      loadPreferences();
    }
  }, [dpiInfo]);

  // Save enabled modules to localStorage and server whenever they change
  useEffect(() => {
    if (typeof window !== 'undefined' && enabledModules.size > 0 && dpiInfo) {
      const modulesArray = Array.from(enabledModules);
      // Save to localStorage immediately
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(modulesArray));
      
      // Debounce server save to avoid too many requests
      const saveTimeout = setTimeout(async () => {
        if (!status?.isServiceMode) {
          setIsSaving(true);
          try {
            await api.setDPIPreferences(modulesArray);
            console.log('DPI preferences saved to server');
          } catch (e) {
            console.error('Failed to save DPI preferences to server:', e);
          } finally {
            setIsSaving(false);
          }
        }
      }, 500);

      return () => clearTimeout(saveTimeout);
    }
  }, [enabledModules, dpiInfo, status]);

  const handleModuleToggle = (module: string) => {
    setEnabledModules(prev => {
      const newSet = new Set(prev);
      if (newSet.has(module)) {
        newSet.delete(module);
      } else {
        newSet.add(module);
      }
      return newSet;
    });
  };

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
            {status?.isServiceMode 
              ? 'View DPI configuration and supported protocols'
              : 'Configure and monitor DPI modules for application layer protocol identification'}
          </Typography>
        </Box>

        {/* Try Service Mode Alert */}
        {status?.isServiceMode && (
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
            <Card sx={{ height: '100%' }}>
              <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
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
                <Alert severity="info" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    {dpiInfo.hasSupport 
                      ? 'DPI support is compiled into this build and ready to use.'
                      : 'DPI support is not compiled into this build. Rebuild with DPI libraries to enable.'}
                  </Typography>
                </Alert>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card sx={{ height: '100%' }}>
              <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
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
                    {status?.isServiceMode 
                      ? 'DPI is configured by the service administrator and applies to all analysis sessions.'
                      : 'DPI is configured at capture startup using the -dpi flag. Modules can be specified with the -dpi-modules flag (e.g., "ndpi,lpi,go").'}
                  </Typography>
                </Alert>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* User DPI Preferences Summary */}
        {!status?.isServiceMode && (
          <Card sx={{ mb: 4 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Your DPI Configuration
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Enabled Modules for Future Analysis:
                </Typography>
                <Box display="flex" flexWrap="wrap" gap={1} mt={1} alignItems="center">
                  {enabledModules.size > 0 ? (
                    <>
                      {Array.from(enabledModules).map((module) => (
                        <Chip
                          key={module}
                          label={module}
                          color="primary"
                          variant="filled"
                          size="medium"
                          onDelete={() => handleModuleToggle(module)}
                        />
                      ))}
                      {isSaving && (
                        <Chip
                          label="Saving..."
                          size="small"
                          variant="outlined"
                          sx={{ ml: 1 }}
                        />
                      )}
                    </>
                  ) : (
                    <Alert severity="warning" sx={{ width: '100%' }}>
                      <Typography variant="body2">
                        No modules are currently enabled. Enable modules below to use DPI features in your analysis uploads.
                      </Typography>
                    </Alert>
                  )}
                </Box>
                <Alert severity="info" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    These settings are saved automatically and will be applied to all your future file uploads and analysis sessions.
                  </Typography>
                </Alert>
              </Box>
            </CardContent>
          </Card>
        )}

        {/* Library Versions */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Library Versions
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Paper 
                  elevation={0} 
                  sx={{ 
                    p: 2, 
                    bgcolor: 'background.default',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    '&:hover': {
                      bgcolor: 'action.hover',
                      transform: 'translateY(-2px)',
                      boxShadow: 1,
                    }
                  }}
                  onClick={() => window.open('https://github.com/ntop/nDPI', '_blank', 'noopener,noreferrer')}
                >
                  <Box display="flex" justifyContent="space-between" alignItems="start">
                    <Box flex={1}>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        nDPI Version
                      </Typography>
                      <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                        {dpiInfo.ndpiVersion || 'N/A'}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Network Deep Packet Inspection library
                      </Typography>
                    </Box>
                    <OpenInNewIcon fontSize="small" sx={{ color: 'text.secondary', ml: 1 }} />
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper 
                  elevation={0} 
                  sx={{ 
                    p: 2, 
                    bgcolor: 'background.default',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    '&:hover': {
                      bgcolor: 'action.hover',
                      transform: 'translateY(-2px)',
                      boxShadow: 1,
                    }
                  }}
                  onClick={() => window.open('https://github.com/wanduow/libprotoident', '_blank', 'noopener,noreferrer')}
                >
                  <Box display="flex" justifyContent="space-between" alignItems="start">
                    <Box flex={1}>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        Libprotoident Version
                      </Typography>
                      <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                        {dpiInfo.libprotoidentVersion || 'N/A'}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Lightweight protocol identification library
                      </Typography>
                    </Box>
                    <OpenInNewIcon fontSize="small" sx={{ color: 'text.secondary', ml: 1 }} />
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper 
                  elevation={0} 
                  sx={{ 
                    p: 2, 
                    bgcolor: 'background.default',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    '&:hover': {
                      bgcolor: 'action.hover',
                      transform: 'translateY(-2px)',
                      boxShadow: 1,
                    }
                  }}
                  onClick={() => window.open('https://github.com/dreadl0ck/go-dpi', '_blank', 'noopener,noreferrer')}
                >
                  <Box display="flex" justifyContent="space-between" alignItems="start">
                    <Box flex={1}>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        go-dpi Version
                      </Typography>
                      <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                        {dpiInfo.goDpiVersion || 'N/A'}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Go wrapper for DPI libraries
                      </Typography>
                    </Box>
                    <OpenInNewIcon fontSize="small" sx={{ color: 'text.secondary', ml: 1 }} />
                  </Box>
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
              <Grid item xs={12}>
                <Typography variant="subtitle2" gutterBottom sx={{ mb: 2 }}>
                  Available Modules
                </Typography>
                {dpiInfo.availableModules.map((module) => {
                  const isActive = dpiInfo.activeModules.includes(module);
                  const isEnabledInSession = enabledModules.has(module);
                  const protocols = dpiInfo.moduleProtocols?.[module] || [];
                  
                  return (
                    <Accordion 
                      key={module}
                      expanded={expandedModule === module}
                      onChange={() => setExpandedModule(expandedModule === module ? null : module)}
                      sx={{ 
                        mb: 1,
                        opacity: isEnabledInSession ? 1 : 0.6,
                        transition: 'opacity 0.3s',
                      }}
                    >
                      <AccordionSummary
                        expandIcon={<ExpandMoreIcon />}
                        sx={{
                          bgcolor: isEnabledInSession ? 'action.selected' : 'background.default',
                          '&:hover': { bgcolor: 'action.hover' },
                        }}
                      >
                        <Box display="flex" alignItems="center" gap={2} width="100%">
                          <Typography variant="h6" sx={{ fontFamily: 'monospace', flex: 1 }}>
                            {module}
                          </Typography>
                          <Box display="flex" alignItems="center" gap={1}>
                            <Chip
                              label={isActive ? 'Available' : 'Unavailable'}
                              color={isActive ? 'success' : 'default'}
                              size="small"
                              variant="outlined"
                            />
                            <Chip
                              label={isEnabledInSession ? 'Enabled' : 'Disabled'}
                              color={isEnabledInSession ? 'success' : 'default'}
                              size="small"
                            />
                            {protocols.length > 0 && (
                              <Chip
                                label={`${protocols.length} protocols`}
                                size="small"
                                variant="outlined"
                              />
                            )}
                            <Tooltip title={isEnabledInSession ? `Disable ${module} for future analysis` : `Enable ${module} for future analysis`}>
                              <FormControlLabel
                                control={
                                  <Switch
                                    checked={isEnabledInSession}
                                    onChange={(e) => {
                                      e.stopPropagation();
                                      handleModuleToggle(module);
                                    }}
                                    onClick={(e) => e.stopPropagation()}
                                    color="primary"
                                    disabled={status?.isServiceMode}
                                  />
                                }
                                label=""
                                sx={{ m: 0 }}
                              />
                            </Tooltip>
                          </Box>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Typography variant="body2" color="text.secondary" paragraph>
                          {getModuleDescription(module)}
                        </Typography>
                        {protocols.length > 0 ? (
                          <Box>
                            <Box sx={{ mb: 2 }}>
                              <TextField
                                fullWidth
                                size="small"
                                placeholder={`Search protocols...`}
                                value={searchQueries[module] || ''}
                                onChange={(e) => setSearchQueries({ ...searchQueries, [module]: e.target.value })}
                                InputProps={{
                                  startAdornment: (
                                    <InputAdornment position="start">
                                      <SearchIcon />
                                    </InputAdornment>
                                  ),
                                }}
                              />
                            </Box>
                            {(() => {
                              const searchQuery = (searchQueries[module] || '').toLowerCase();
                              const filteredProtocols = protocols.filter(protocol => 
                                protocol.toLowerCase().includes(searchQuery)
                              );
                              
                              return (
                                <>
                                  <Typography variant="subtitle2" gutterBottom sx={{ mb: 1 }}>
                                    Supported Protocols ({filteredProtocols.length}{searchQuery && ` of ${protocols.length}`})
                                  </Typography>
                                  {filteredProtocols.length > 0 ? (
                                    <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 400 }}>
                                      <Table size="small" stickyHeader>
                                        <TableHead>
                                          <TableRow>
                                            <TableCell sx={{ fontWeight: 600, width: 80 }}>#</TableCell>
                                            <TableCell sx={{ fontWeight: 600 }}>Protocol Name</TableCell>
                                            <TableCell sx={{ fontWeight: 600, width: 100, textAlign: 'center' }}>Source</TableCell>
                                          </TableRow>
                                        </TableHead>
                                        <TableBody>
                                          {filteredProtocols.map((protocol, idx) => (
                                            <TableRow 
                                              key={protocol}
                                              sx={{ '&:last-child td': { border: 0 } }}
                                            >
                                              <TableCell sx={{ color: 'text.secondary' }}>
                                                {protocols.indexOf(protocol) + 1}
                                              </TableCell>
                                              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>
                                                {protocol}
                                              </TableCell>
                                              <TableCell sx={{ textAlign: 'center' }}>
                                                <MuiLink
                                                  href={getProtocolSourceUrl(module, protocol)}
                                                  target="_blank"
                                                  rel="noopener noreferrer"
                                                  onClick={(e) => e.stopPropagation()}
                                                  sx={{ 
                                                    display: 'inline-flex', 
                                                    alignItems: 'center',
                                                    gap: 0.5,
                                                    textDecoration: 'none',
                                                    '&:hover': { textDecoration: 'underline' }
                                                  }}
                                                >
                                                  View
                                                  <OpenInNewIcon fontSize="small" />
                                                </MuiLink>
                                              </TableCell>
                                            </TableRow>
                                          ))}
                                        </TableBody>
                                      </Table>
                                    </TableContainer>
                                  ) : (
                                    <Alert severity="info">
                                      <Typography variant="body2">
                                        No protocols found matching &quot;{searchQueries[module]}&quot;
                                      </Typography>
                                    </Alert>
                                  )}
                                </>
                              );
                            })()}
                          </Box>
                        ) : (
                          <Alert severity="info" sx={{ mt: 2 }}>
                            <Typography variant="body2">
                              No protocol information available for this module.
                              {!isActive && ' This module is not currently active.'}
                            </Typography>
                          </Alert>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  );
                })}
              </Grid>
              <Grid item xs={12}>
                <Alert severity="info" icon={<InfoIcon />}>
                  <AlertTitle>Module Configuration</AlertTitle>
                  {status?.isServiceMode ? (
                    <Typography variant="body2">
                      The DPI modules shown are configured by the service administrator.
                      Toggle functionality is disabled in try service mode.
                      Click on each module to view its supported protocols.
                    </Typography>
                  ) : (
                    <>
                      <Typography variant="body2" gutterBottom>
                        Use the toggle switches to enable or disable individual DPI modules.
                        Your preferences are saved automatically and will be applied to all future file uploads and analysis sessions.
                        Click on each module to view its supported protocols.
                      </Typography>
                      <Typography variant="body2" gutterBottom sx={{ mt: 1 }}>
                        When you upload a PCAP file, these DPI module preferences will be automatically applied during analysis.
                        You can change these settings at any time, and they will be used for subsequent uploads.
                      </Typography>
                      <Typography variant="body2" gutterBottom sx={{ mt: 1 }}>
                        Modules can also be configured at capture startup using the <code>-dpi-modules</code> flag:
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
                        net capture -r input.pcap -dpi -dpi-modules &quot;ndpi,lpi,go&quot;
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

function getProtocolSourceUrl(module: string, protocol: string): string {
  const protocolLower = protocol.toLowerCase();
  switch (module) {
    case 'go':
      return `https://github.com/dreadl0ck/go-dpi/blob/master/modules/classifiers/${protocolLower}.go`;
    case 'ndpi':
      return `https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/${protocolLower}.c`;
    case 'lpi':
      return `https://github.com/LibtraceTeam/libprotoident/blob/master/lib/tcp/lpi_${protocolLower}.cc`;
    default:
      return '#';
  }
}

