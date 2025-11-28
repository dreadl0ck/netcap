import { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  TextField,
  Typography,
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
  TableContainer,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Paper,
  Tooltip,
  IconButton,
} from '@mui/material';
import {
  Save as SaveIcon,
  FileUpload as FileUploadIcon,
  FileDownload as FileDownloadIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import useSWR from 'swr';
import Layout from '../components/Layout';
import type { HarvestersConfig, HarvesterConfigItem, HarvesterPresetInfo } from '../lib/api';
import { useNetcapApi } from '../hooks';

// Helper function to convert harvester name to snake_case filename
const toSnakeCase = (str: string): string => {
  return str
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/\s+/g, '_')
    .toLowerCase();
};

// Helper function to get GitHub URL for harvester implementation
const getHarvesterGitHubUrl = (harvesterName: string): string => {
  const baseUrl = 'https://github.com/dreadl0ck/netcap/blob/master/decoder/stream/credentials';
  
  // Map harvester names to their actual filenames
  const harvesterFilenames: Record<string, string> = {
    'FTP': 'ftp',
    'HTTP': 'http',
    'SMTP': 'smtp',
    'Telnet': 'telnet',
    'IMAP': 'imap',
    'NTLMSSP': 'ntlmssp',
    'Kerberos AS-REQ': 'kerberos_asreq',
    'Kerberos AS-REP': 'kerberos_asrep',
    'Kerberos TGS-REP': 'kerberos_tgsrep',
    'HTTP NTLM': 'http_ntlm',
    'POP3': 'pop3',
    'Redis': 'redis',
    'SNMP': 'snmp',
    'LDAP': 'ldap',
    'PostgreSQL': 'postgres',
    'PostgreSQL Hash': 'postgres',
    'MySQL': 'mysql',
    'VNC': 'vnc',
    'MongoDB': 'mongodb',
    'MongoDB Challenge Response': 'mongodb',
  };
  
  // Get the filename or fallback to snake_case conversion
  const filename = harvesterFilenames[harvesterName] || toSnakeCase(harvesterName);
  
  return `${baseUrl}/${filename}.go`;
};


export default function Harvesters() {
  const api = useNetcapApi();
  const { data: configData, mutate: mutateConfig } = useSWR('harvesters-config', () => api.getHarvestersConfig());
  const { data: presetsData, mutate: mutatePresets } = useSWR('harvester-presets', () => api.getHarvesterPresets());
  
  const [tabValue, setTabValue] = useState(0);
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

  if (!config) {
    return (
      <Layout title="Credential Harvesters">
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  // Tab selector for header
  const tabSelector = (
    <Tabs 
      value={tabValue} 
      onChange={handleTabChange}
      sx={{ 
        minHeight: 40,
        '& .MuiTab-root': { 
          minHeight: 40,
          py: 1,
        }
      }}
      data-learn="Tab Selector: Switch between Configure (edit harvester settings) and Presets (manage saved configurations)."
    >
      <Tab label="Configure" data-learn="Configure Tab: Manage individual harvester settings including enabling/disabling, configuring ports, and setting parameters." />
      <Tab label="Presets" data-learn="Presets Tab: Save, load, and manage harvester configuration presets for different security scenarios." />
    </Tabs>
  );

  return (
    <Layout title="Credential Harvesters" headerAction={tabSelector}>
      <Box sx={{ p: 3 }}>
        {/* Configure Tab */}
        {tabValue === 0 && (
          <Box>
            <Box sx={{ mb: 3, display: 'flex', gap: 2 }}>
              <Button
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={handleSaveConfig}
                data-learn="Save Configuration: Apply and save the current harvester settings to disk. Changes take effect after restarting capture."
              >
                Save Configuration
              </Button>
              <Button
                variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={() => mutateConfig()}
                data-learn="Reload Configuration: Discard unsaved changes and reload the harvester configuration from disk."
              >
                Reload
              </Button>
            </Box>

            <Grid container spacing={2}>
              {config.harvesters.map((harvester) => (
                <Grid item xs={12} key={harvester.name}>
                  <Card>
                    <CardContent 
                      sx={{ 
                        cursor: harvester.parameters && Object.keys(harvester.parameters).length > 0 ? 'pointer' : 'default',
                        '&:hover': {
                          bgcolor: harvester.parameters && Object.keys(harvester.parameters).length > 0 ? 'action.hover' : 'transparent',
                        },
                      }}
                      onClick={() => {
                        if (harvester.parameters && Object.keys(harvester.parameters).length > 0) {
                          setExpandedHarvester(expandedHarvester === harvester.name ? null : harvester.name);
                        }
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={harvester.enabled}
                                onChange={(e) => {
                                  e.stopPropagation();
                                  handleToggleHarvester(harvester.name);
                                }}
                                onClick={(e) => e.stopPropagation()}
                                data-learn="Toggle Harvester: Enable or disable this credential harvester. When enabled, it will extract authentication data from matching network traffic."
                              />
                            }
                            label={<Typography variant="h6">{harvester.name}</Typography>}
                            onClick={(e) => e.stopPropagation()}
                          />
                          <Typography variant="body2" color="text.secondary">
                            {harvester.description}
                          </Typography>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <IconButton
                            data-learn="View Source Code: Open the harvester's implementation on GitHub to see how it extracts credentials from network traffic."
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              window.open(getHarvesterGitHubUrl(harvester.name), '_blank', 'noopener,noreferrer');
                            }}
                            sx={{ color: 'text.secondary' }}
                            title="View source code on GitHub"
                          >
                            <CodeIcon />
                          </IconButton>
                          {harvester.parameters && Object.keys(harvester.parameters).length > 0 && (
                            <Chip 
                              label={expandedHarvester === harvester.name ? 'Hide Parameters' : 'Show Parameters'}
                              size="small"
                              variant="outlined"
                              icon={expandedHarvester === harvester.name ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                              data-learn="Show Parameters: Expand to view and configure advanced parameters for this harvester such as authentication schemes, encoding, and protocol-specific settings."
                            />
                          )}
                        </Box>
                      </Box>

                      <Box 
                        sx={{ display: 'flex', gap: 2, mb: 2 }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <TextField
                          label="Ports (comma-separated)"
                          value={harvester.ports.join(', ')}
                          onChange={(e) => handlePortsChange(harvester.name, e.target.value)}
                          fullWidth
                          size="small"
                          disabled={!harvester.enabled}
                          data-learn="Harvester Ports: Comma-separated list of TCP/UDP ports where this harvester will monitor for credentials. Add custom ports if services run on non-standard ports."
                        />
                      </Box>

                      <Collapse in={expandedHarvester === harvester.name}>
                        <Box 
                          sx={{ mt: 2, p: 2, bgcolor: 'background.default', borderRadius: 1 }}
                          onClick={(e) => e.stopPropagation()}
                        >
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

        {/* Presets Tab */}
        {tabValue === 1 && (
          <Box>
            <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Button
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={() => setSavePresetDialogOpen(true)}
                data-learn="Save as Preset: Save the current harvester configuration as a named preset for reuse in different scenarios (e.g., 'Web Only', 'Full Monitoring', 'Database Servers')."
              >
                Save as Preset
              </Button>
              <Button
                variant="outlined"
                startIcon={<FileUploadIcon />}
                onClick={() => setUploadDialogOpen(true)}
                data-learn="Upload Preset: Import a harvester configuration preset file (YAML format) from disk to add it to available presets."
              >
                Upload Preset
              </Button>
              <FormControl variant="outlined" size="small" sx={{ minWidth: 200 }}>
                <InputLabel>Load Preset</InputLabel>
                <Select
                  value={selectedPreset}
                  onChange={(e) => setSelectedPreset(e.target.value)}
                  label="Load Preset"
                  data-learn="Select Preset: Choose a saved harvester configuration preset to load its settings."
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
                data-learn="Load Preset: Apply the selected preset's harvester configuration, replacing the current settings."
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
                              data-learn="Download Preset: Export this harvester preset as a YAML file for backup, sharing, or version control."
                            >
                              <FileDownloadIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => handleDeletePreset(preset.name)}
                              data-learn="Delete Preset: Permanently remove this harvester preset from the system."
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
