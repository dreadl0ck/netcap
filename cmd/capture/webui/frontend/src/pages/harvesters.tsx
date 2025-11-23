import { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  TextField,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Button,
  Switch,
  Collapse,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControlLabel,
  Tabs,
  Tab,
  Grid,
  Alert,
  Snackbar,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import {
  OpenInNew as OpenInNewIcon,
  Code as CodeIcon,
  Save as SaveIcon,
  FileUpload as FileUploadIcon,
  FileDownload as FileDownloadIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Add as AddIcon,
  Remove as RemoveIcon,
} from '@mui/icons-material';
import useSWR from 'swr';
import Layout from '@/components/Layout';
import type { HarvesterInfo, HarvestersConfig, HarvesterConfigItem, HarvesterPresetInfo } from '@/lib/api';
import { api } from '@/lib/api';

const getHarvesterGitHubUrl = (harvesterName: string): string => {
  const baseUrl = 'https://github.com/dreadl0ck/netcap/blob/master/decoder/stream/credentials';
  
  const nameToFile: Record<string, string> = {
    'FTP': 'ftp.go',
    'HTTP': 'http.go',
    'HTTP NTLM': 'http_ntlm.go',
    'SMTP': 'smtp.go',
    'Telnet': 'telnet.go',
    'IMAP': 'imap.go',
    'POP3': 'pop3.go',
    'NTLMSSP': 'ntlmssp.go',
    'Kerberos AS-REQ': 'kerberos_asreq.go',
    'Kerberos AS-REP': 'kerberos_asrep.go',
    'Kerberos TGS-REP': 'kerberos_tgsrep.go',
    'LDAP': 'ldap.go',
    'PostgreSQL': 'postgres.go',
    'PostgreSQL Hash': 'postgres.go',
    'MySQL': 'mysql.go',
    'MongoDB': 'mongodb.go',
    'MongoDB Challenge Response': 'mongodb.go',
    'Redis': 'redis.go',
    'SNMP': 'snmp.go',
    'VNC': 'vnc.go',
  };

  const fileName = nameToFile[harvesterName];
  if (fileName) {
    return `${baseUrl}/${fileName}`;
  }

  return baseUrl;
};

export default function Harvesters() {
  const { data: harvestersData, error: harvestersError } = useSWR('harvesters', () => api.getHarvesters());
  const { data: configData, mutate: mutateConfig } = useSWR('harvesters-config', () => api.getHarvestersConfig());
  const { data: presetsData, mutate: mutatePresets } = useSWR('harvester-presets', () => api.getHarvesterPresets());
  
  const [tabValue, setTabValue] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedHarvester, setExpandedHarvester] = useState<string | null>(null);
  const [config, setConfig] = useState<HarvestersConfig | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });
  const [savePresetDialogOpen, setSavePresetDialogOpen] = useState(false);
  const [presetName, setPresetName] = useState('');
  const [selectedPreset, setSelectedPreset] = useState('');
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [uploadFile, setUploadFile] = useState<File | null>(null);

  useEffect(() => {
    if (configData) {
      setConfig(configData);
    }
  }, [configData]);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleToggleHarvester = (name: string) => {
    if (!config) return;
    
    const updatedHarvesters = config.harvesters.map(h =>
      h.name === name ? { ...h, enabled: !h.enabled } : h
    );
    
    setConfig({ ...config, harvesters: updatedHarvesters });
  };

  const handlePortsChange = (name: string, portsStr: string) => {
    if (!config) return;
    
    const ports = portsStr.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    const updatedHarvesters = config.harvesters.map(h =>
      h.name === name ? { ...h, ports } : h
    );
    
    setConfig({ ...config, harvesters: updatedHarvesters });
  };

  const handleParameterChange = (harvesterName: string, paramKey: string, paramValue: string) => {
    if (!config) return;
    
    const updatedHarvesters = config.harvesters.map(h => {
      if (h.name === harvesterName) {
        const params = h.parameters || {};
        // Try to parse as array if it looks like one
        let value: any = paramValue;
        if (paramValue.trim().startsWith('[') || paramValue.includes(',')) {
          try {
            value = paramValue.split(',').map(v => v.trim().replace(/^\[|\]$/g, ''));
          } catch (e) {
            value = paramValue;
          }
        }
        
        return {
          ...h,
          parameters: {
            ...params,
            [paramKey]: value,
          },
        };
      }
      return h;
    });
    
    setConfig({ ...config, harvesters: updatedHarvesters });
  };

  const handleSaveConfig = async () => {
    if (!config) return;
    
    try {
      const result = await api.saveHarvestersConfig(config);
      setSnackbar({ open: true, message: result.message, severity: 'success' });
      mutateConfig();
    } catch (error) {
      setSnackbar({ open: true, message: `Failed to save config: ${error}`, severity: 'error' });
    }
  };

  const handleSavePreset = async () => {
    if (!config || !presetName.trim()) {
      setSnackbar({ open: true, message: 'Please enter a preset name', severity: 'error' });
      return;
    }
    
    try {
      const result = await api.saveHarvesterPreset(presetName, config);
      setSnackbar({ open: true, message: result.message, severity: 'success' });
      setSavePresetDialogOpen(false);
      setPresetName('');
      mutatePresets();
    } catch (error) {
      setSnackbar({ open: true, message: `Failed to save preset: ${error}`, severity: 'error' });
    }
  };

  const handleLoadPreset = async () => {
    if (!selectedPreset) {
      setSnackbar({ open: true, message: 'Please select a preset', severity: 'error' });
      return;
    }
    
    try {
      const result = await api.loadHarvesterPreset(selectedPreset);
      setSnackbar({ open: true, message: result.message, severity: 'success' });
      setConfig(result.config);
      mutateConfig();
    } catch (error) {
      setSnackbar({ open: true, message: `Failed to load preset: ${error}`, severity: 'error' });
    }
  };

  const handleDeletePreset = async (name: string) => {
    if (!confirm(`Are you sure you want to delete the preset "${name}"?`)) return;
    
    try {
      const result = await api.deleteHarvesterPreset(name);
      setSnackbar({ open: true, message: result.message, severity: 'success' });
      mutatePresets();
    } catch (error) {
      setSnackbar({ open: true, message: `Failed to delete preset: ${error}`, severity: 'error' });
    }
  };

  const handleDownloadPreset = async (name: string) => {
    try {
      const blob = await api.downloadHarvesterPreset(name);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${name}.yml`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setSnackbar({ open: true, message: 'Preset downloaded successfully', severity: 'success' });
    } catch (error) {
      setSnackbar({ open: true, message: `Failed to download preset: ${error}`, severity: 'error' });
    }
  };

  const handleUploadPreset = async () => {
    if (!uploadFile) {
      setSnackbar({ open: true, message: 'Please select a file', severity: 'error' });
      return;
    }
    
    try {
      const result = await api.uploadHarvesterPreset(uploadFile);
      setSnackbar({ open: true, message: result.message, severity: 'success' });
      setUploadDialogOpen(false);
      setUploadFile(null);
      mutatePresets();
    } catch (error) {
      setSnackbar({ open: true, message: `Failed to upload preset: ${error}`, severity: 'error' });
    }
  };

  const filteredHarvesters = harvestersData?.harvesters.filter((harvester) => {
    const searchLower = searchTerm.toLowerCase();
    return (
      harvester.name.toLowerCase().includes(searchLower) ||
      harvester.description.toLowerCase().includes(searchLower) ||
      harvester.ports.some(port => port.toString().includes(searchTerm))
    );
  });

  if (harvestersError) {
    return (
      <Layout title="Credential Harvesters">
        <Box sx={{ p: 3 }}>
          <Typography color="error">Failed to load harvesters: {harvestersError.message}</Typography>
        </Box>
      </Layout>
    );
  }

  if (!harvestersData || !config) {
    return (
      <Layout title="Credential Harvesters">
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Credential Harvesters">
      <Box sx={{ p: 3 }}>
        <Typography variant="h4" gutterBottom>
          Credential Harvesters
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Configure credential harvesters to extract authentication data from network traffic.
          Changes require capture restart to take effect.
        </Typography>

        <Tabs value={tabValue} onChange={handleTabChange} sx={{ mb: 3 }}>
          <Tab label="Configure" />
          <Tab label="Available Harvesters" />
          <Tab label="Presets" />
        </Tabs>

        {/* Configure Tab */}
        {tabValue === 0 && (
          <Box>
            <Box sx={{ mb: 3, display: 'flex', gap: 2 }}>
              <Button
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={handleSaveConfig}
              >
                Save Configuration
              </Button>
              <Button
                variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={() => mutateConfig()}
              >
                Reload
              </Button>
            </Box>

            <Alert severity="info" sx={{ mb: 3 }}>
              Configuration changes will take effect when you restart the capture. 
              Toggle harvesters on/off, configure ports, and set parameters below.
            </Alert>

            <Grid container spacing={2}>
              {config.harvesters.map((harvester) => (
                <Grid item xs={12} key={harvester.name}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={harvester.enabled}
                                onChange={() => handleToggleHarvester(harvester.name)}
                              />
                            }
                            label={<Typography variant="h6">{harvester.name}</Typography>}
                          />
                          <Typography variant="body2" color="text.secondary">
                            {harvester.description}
                          </Typography>
                        </Box>
                        <IconButton
                          onClick={() => setExpandedHarvester(expandedHarvester === harvester.name ? null : harvester.name)}
                        >
                          {expandedHarvester === harvester.name ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                        </IconButton>
                      </Box>

                      <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                        <TextField
                          label="Ports (comma-separated)"
                          value={harvester.ports.join(', ')}
                          onChange={(e) => handlePortsChange(harvester.name, e.target.value)}
                          fullWidth
                          size="small"
                          disabled={!harvester.enabled}
                        />
                      </Box>

                      <Collapse in={expandedHarvester === harvester.name}>
                        <Box sx={{ mt: 2, p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
                          <Typography variant="subtitle2" gutterBottom>
                            Parameters
                          </Typography>
                          
                          {harvester.parameters && Object.keys(harvester.parameters).length > 0 ? (
                            Object.entries(harvester.parameters).map(([key, value]) => (
                              <TextField
                                key={key}
                                label={key}
                                value={Array.isArray(value) ? value.join(', ') : String(value)}
                                onChange={(e) => handleParameterChange(harvester.name, key, e.target.value)}
                                fullWidth
                                size="small"
                                sx={{ mb: 2 }}
                                disabled={!harvester.enabled}
                                helperText={Array.isArray(value) ? 'Comma-separated list' : ''}
                              />
                            ))
                          ) : (
                            <Typography variant="body2" color="text.secondary">
                              No configurable parameters for this harvester
                            </Typography>
                          )}
                        </Box>
                      </Collapse>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}

        {/* Available Harvesters Tab */}
        {tabValue === 1 && (
          <Box>
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <TextField
                  fullWidth
                  label="Search Harvesters"
                  variant="outlined"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search by name, description, or port..."
                  size="small"
                />
              </CardContent>
            </Card>

            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell><strong>Protocol</strong></TableCell>
                    <TableCell><strong>Description</strong></TableCell>
                    <TableCell><strong>Ports</strong></TableCell>
                    <TableCell align="right"><strong>Actions</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredHarvesters && filteredHarvesters.length > 0 ? (
                    filteredHarvesters.map((harvester) => (
                      <TableRow key={harvester.name} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {harvester.name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {harvester.description}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                            {harvester.ports && harvester.ports.length > 0 ? (
                              harvester.ports.map((port) => (
                                <Chip
                                  key={port}
                                  label={port}
                                  size="small"
                                  color="primary"
                                  variant="outlined"
                                />
                              ))
                            ) : (
                              <Typography variant="body2" color="text.secondary">
                                No specific ports
                              </Typography>
                            )}
                          </Box>
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="View source code on GitHub">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={() => window.open(getHarvesterGitHubUrl(harvester.name), '_blank')}
                            >
                              <CodeIcon />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={4} align="center">
                        <Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                          {searchTerm ? 'No harvesters match your search criteria' : 'No harvesters available'}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Presets Tab */}
        {tabValue === 2 && (
          <Box>
            <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Button
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={() => setSavePresetDialogOpen(true)}
              >
                Save as Preset
              </Button>
              <Button
                variant="outlined"
                startIcon={<FileUploadIcon />}
                onClick={() => setUploadDialogOpen(true)}
              >
                Upload Preset
              </Button>
              <FormControl variant="outlined" size="small" sx={{ minWidth: 200 }}>
                <InputLabel>Load Preset</InputLabel>
                <Select
                  value={selectedPreset}
                  onChange={(e) => setSelectedPreset(e.target.value)}
                  label="Load Preset"
                >
                  <MenuItem value="">
                    <em>Select a preset</em>
                  </MenuItem>
                  {presetsData?.presets.map((preset) => (
                    <MenuItem key={preset.name} value={preset.name}>
                      {preset.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <Button
                variant="contained"
                onClick={handleLoadPreset}
                disabled={!selectedPreset}
              >
                Load
              </Button>
            </Box>

            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell><strong>Name</strong></TableCell>
                    <TableCell><strong>Description</strong></TableCell>
                    <TableCell><strong>Harvesters</strong></TableCell>
                    <TableCell><strong>Modified</strong></TableCell>
                    <TableCell align="right"><strong>Actions</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {presetsData?.presets && presetsData.presets.length > 0 ? (
                    presetsData.presets.map((preset) => (
                      <TableRow key={preset.name} hover>
                        <TableCell>{preset.name}</TableCell>
                        <TableCell>{preset.description}</TableCell>
                        <TableCell>{preset.harvester_count}</TableCell>
                        <TableCell>{new Date(preset.modified_at).toLocaleDateString()}</TableCell>
                        <TableCell align="right">
                          <Tooltip title="Download">
                            <IconButton
                              size="small"
                              onClick={() => handleDownloadPreset(preset.name)}
                            >
                              <FileDownloadIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => handleDeletePreset(preset.name)}
                            >
                              <DeleteIcon />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={5} align="center">
                        <Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                          No saved presets
                        </Typography>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Save Preset Dialog */}
        <Dialog open={savePresetDialogOpen} onClose={() => setSavePresetDialogOpen(false)}>
          <DialogTitle>Save Configuration as Preset</DialogTitle>
          <DialogContent>
            <TextField
              autoFocus
              margin="dense"
              label="Preset Name"
              fullWidth
              value={presetName}
              onChange={(e) => setPresetName(e.target.value)}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSavePresetDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleSavePreset} variant="contained">Save</Button>
          </DialogActions>
        </Dialog>

        {/* Upload Preset Dialog */}
        <Dialog open={uploadDialogOpen} onClose={() => setUploadDialogOpen(false)}>
          <DialogTitle>Upload Preset File</DialogTitle>
          <DialogContent>
            <input
              type="file"
              accept=".yml,.yaml"
              onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
              style={{ marginTop: 16 }}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setUploadDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleUploadPreset} variant="contained" disabled={!uploadFile}>
              Upload
            </Button>
          </DialogActions>
        </Dialog>

        {/* Snackbar */}
        <Snackbar
          open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
        >
          <Alert onClose={() => setSnackbar({ ...snackbar, open: false })} severity={snackbar.severity}>
            {snackbar.message}
          </Alert>
        </Snackbar>
      </Box>
    </Layout>
  );
}
