/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
import {
  Save as SaveIcon,
  FileUpload as FileUploadIcon,
  FileDownload as FileDownloadIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Code as CodeIcon,
  Close as CloseIcon,
} from '@mui/icons-material';

import Layout from '../components/Layout';
import type { HarvestersConfig, HarvesterConfigItem, HarvesterPresetInfo } from '../lib/api';
import { useNetcapApi, useIsMobile } from '../hooks';
import { message as i18nMessage, translate as i18nText, richText as i18nRichText, getLocale as getUILocale, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, metadataText } from "../lib/i18n";
import { metadataMessage, suppliedMetadataText } from "../lib/i18n";




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
  const baseUrl = 'https://github.com/dreadl0ck/netcap/blob/master/internal/decoder/stream/secret';
  
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
    // Network discovery protocols
    'TeamViewer': 'teamviewer',
    'mDNS': 'mdns',
    'NBNS': 'nbns',
    'UPnP': 'upnp',
    'WSD': 'upnp', // WSD is defined in the same file as UPnP
  };
  
  // Get the filename or fallback to snake_case conversion
  const filename = harvesterFilenames[harvesterName] || toSnakeCase(harvesterName);
  
  return `${baseUrl}/${filename}.go`;
};


export default function Harvesters() {
  const __uiLocale = useUILocale();
  const isMobile = useIsMobile();
  const api = useNetcapApi();
  const { data: configData, mutate: mutateConfig } = useSWR('harvesters-config', () => api.getHarvestersConfig());
  const { data: presetsData, mutate: mutatePresets } = useSWR('harvester-presets', () => api.getHarvesterPresets());
  
  const [tabValue, setTabValue] = useState(0);
  const [expandedHarvester, setExpandedHarvester] = useState<string | null>(null);
  const [config, setConfig] = useState<HarvestersConfig | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: UIMessageText; severity: 'success' | 'error' }>({
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
      setSnackbar({ open: true, message: metadataMessage(result, 'message'), severity: 'success' });
      mutateConfig();
    } catch (error) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_bbe38aefd68b2e4fd9fc", { arg0: error }), severity: 'error' });
    }
  };

  const handleSavePreset = async () => {
    if (!config || !presetName.trim()) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_087aa9d83505b465a2b4"), severity: 'error' });
      return;
    }
    
    try {
      const result = await api.saveHarvesterPreset(presetName, config);
      setSnackbar({ open: true, message: metadataMessage(result, 'message'), severity: 'success' });
      setSavePresetDialogOpen(false);
      setPresetName('');
      mutatePresets();
    } catch (error) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_3e6809bba96f4735a732", { arg0: error }), severity: 'error' });
    }
  };

  const handleLoadPreset = async () => {
    if (!selectedPreset) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_b65da8d4585e15726659"), severity: 'error' });
      return;
    }
    
    try {
      const result = await api.loadHarvesterPreset(selectedPreset);
      setSnackbar({ open: true, message: metadataMessage(result, 'message'), severity: 'success' });
      setConfig(result.config);
      mutateConfig();
    } catch (error) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_c67c0437ce3e7c06ebdd", { arg0: error }), severity: 'error' });
    }
  };

  const handleDeletePreset = async (name: string) => {
    if (!confirm(i18nText("ui:m_921cfc36b766ba3fedea", { arg0: name }))) return;
    
    try {
      const result = await api.deleteHarvesterPreset(name);
      setSnackbar({ open: true, message: metadataMessage(result, 'message'), severity: 'success' });
      mutatePresets();
    } catch (error) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_79fb9cda1aaf6e76a843", { arg0: error }), severity: 'error' });
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
      setSnackbar({ open: true, message: i18nMessage("ui:m_3548b15f089bc5679e6f"), severity: 'success' });
    } catch (error) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_c8c5177f336de7b4da90", { arg0: error }), severity: 'error' });
    }
  };

  const handleUploadPreset = async () => {
    if (!uploadFile) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_0b9eca19d4b2918f07b5"), severity: 'error' });
      return;
    }
    
    try {
      const result = await api.uploadHarvesterPreset(uploadFile);
      setSnackbar({ open: true, message: metadataMessage(result, 'message'), severity: 'success' });
      setUploadDialogOpen(false);
      setUploadFile(null);
      mutatePresets();
    } catch (error) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_3438c186f4a09b771d49", { arg0: error }), severity: 'error' });
    }
  };

  if (!config) {
    return (
      <Layout title={i18nText("ui:m_e2442b5dd37ddc7b11e6")}><Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}><CircularProgress /></Box></Layout>
    );
  }

  // Tab selector for header
  const tabSelector = (
    <Tabs value={tabValue} 
      onChange={handleTabChange}
      sx={{ 
        minHeight: 40,
        '& .MuiTab-root': { 
          minHeight: 40,
          py: 1,
        }
      }}
      data-learn={i18nText("ui:m_1856b8efc027bc074149")}><Tab label={i18nText("ui:m_06a7293de01a97a595f2")} data-learn={i18nText("ui:m_6715955d96aa02931b17")} /><Tab label={i18nText("ui:m_62cc21c9361cc5522c75")} data-learn={i18nText("ui:m_8128793b4e3436919dc5")} /></Tabs>
  );

  return (
    <Layout title={i18nText("ui:m_e2442b5dd37ddc7b11e6")} headerAction={tabSelector}><Box sx={{ p: 3 }}>{/* Configure Tab */}{tabValue === 0 && (
          <Box><Box sx={{ mb: 3, display: 'flex', gap: 2 }}><Button variant="contained"
                startIcon={<SaveIcon />}
                onClick={handleSaveConfig}
                data-learn={i18nText("ui:m_c81c5a838b875cd07cdf")}>
                {i18nText("ui:m_b617272e2b94c43ecd5c")}
              </Button><Button variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={() => mutateConfig()}
                data-learn={i18nText("ui:m_785179cbe7f2be4602dc")}>
                {i18nText("ui:m_968e965258fb0c0320c3")}
              </Button></Box><Grid container spacing={2}>{config.harvesters.map((harvester) => (
                <Grid item xs={12} key={harvester.name}><Card><CardContent sx={{ 
                        cursor: harvester.parameters && Object.keys(harvester.parameters).length > 0 ? 'pointer' : 'default',
                        '&:hover': {
                          bgcolor: harvester.parameters && Object.keys(harvester.parameters).length > 0 ? 'action.hover' : 'transparent',
                        },
                      }}
                      onClick={() => {
                        if (harvester.parameters && Object.keys(harvester.parameters).length > 0) {
                          setExpandedHarvester(expandedHarvester === harvester.name ? null : harvester.name);
                        }
                      }}><Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}><FormControlLabel control={<Switch checked={harvester.enabled}
                                onChange={(e) => {
                                  e.stopPropagation();
                                  handleToggleHarvester(harvester.name);
                                }}
                                onClick={(e) => e.stopPropagation()}
                                data-learn={i18nText("ui:m_153cd8a880e5249a8fc2")} />}
                            label={<Typography variant="h6">{harvester.name}</Typography>}
                            onClick={(e) => e.stopPropagation()} /><Typography variant="body2" color="text.secondary">{metadataText(harvester, "description")}</Typography></Box><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><IconButton data-learn={i18nText("ui:m_2a638f54fa2f3c708730")}
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              window.open(getHarvesterGitHubUrl(harvester.name), '_blank', 'noopener,noreferrer');
                            }}
                            sx={{ color: 'text.secondary' }}
                            title={i18nText("ui:m_737c7db97490030e51b8")}><CodeIcon /></IconButton>{harvester.parameters && Object.keys(harvester.parameters).length > 0 && (
                            <Chip label={expandedHarvester === harvester.name ? i18nText("ui:m_018818ff509419cdc48f") : i18nText("ui:m_98baf5dad281a649b811")}
                              size="small"
                              variant="outlined"
                              icon={expandedHarvester === harvester.name ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                              data-learn={i18nText("ui:m_218c43b671a631ca9fdd")} />
                          )}</Box></Box><Box sx={{ display: 'flex', gap: 2, mb: 2 }}
                        onClick={(e) => e.stopPropagation()}><TextField label={i18nText("ui:m_b3e29ec6818ddd1de87d")}
                          value={harvester.ports.join(', ')}
                          onChange={(e) => handlePortsChange(harvester.name, e.target.value)}
                          fullWidth
                          size="small"
                          disabled={!harvester.enabled}
                          data-learn={i18nText("ui:m_b5b5807c3e3eaabcf173")} /></Box><Collapse in={expandedHarvester === harvester.name}><Box sx={{ mt: 2, p: 2, bgcolor: 'background.default', borderRadius: 1 }}
                          onClick={(e) => e.stopPropagation()}><Typography variant="subtitle2" gutterBottom>
                            {i18nText("ui:m_d9c69a067ca68ac70522")}
                          </Typography>{harvester.parameters && Object.keys(harvester.parameters).length > 0 ? (
                            Object.entries(harvester.parameters).map(([key, value]) => (
                              <TextField key={key}
                                label={key}
                                value={Array.isArray(value) ? value.join(', ') : String(value)}
                                onChange={(e) => handleParameterChange(harvester.name, key, e.target.value)}
                                fullWidth
                                size="small"
                                sx={{ mb: 2 }}
                                disabled={!harvester.enabled}
                                helperText={Array.isArray(value) ? i18nText("ui:m_51a72a4c933bf8272859") : ''} />
                            ))
                          ) : (
                            <Typography variant="body2" color="text.secondary">
                              {i18nText("ui:m_88abec48c819b7f3e5e9")}
                            </Typography>
                          )}</Box></Collapse></CardContent></Card></Grid>
              ))}</Grid></Box>
        )}{/* Presets Tab */}{tabValue === 1 && (
          <Box><Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }}><Button variant="contained"
                startIcon={<SaveIcon />}
                onClick={() => setSavePresetDialogOpen(true)}
                data-learn={i18nText("ui:m_cc8fb5fd1e07e191fbc3")}>
                {i18nText("ui:m_458a67b5665a3f05b4f2")}
              </Button><Button variant="outlined"
                startIcon={<FileUploadIcon />}
                onClick={() => setUploadDialogOpen(true)}
                data-learn={i18nText("ui:m_62a4e468604cd2dfb1cb")}>
                {i18nText("ui:m_38162fad63316cde8945")}
              </Button><FormControl variant="outlined" size="small" sx={{ minWidth: 200 }}><InputLabel>{i18nText("ui:m_3f437c17f859ea9e5f59")}</InputLabel><Select value={selectedPreset}
                  onChange={(e) => setSelectedPreset(e.target.value)}
                  label={i18nText("ui:m_3f437c17f859ea9e5f59")}
                  data-learn={i18nText("ui:m_63a185172100875b8160")}><MenuItem value="">
                    {i18nRichText("ui:m_cd4faa72a1e95a4f6646", { tag0: (chunks: import('react').ReactNode[]) => <em>{chunks}</em> })}
                  </MenuItem>{presetsData?.presets.map((preset) => (
                    <MenuItem key={preset.name} value={preset.name}>{preset.name}</MenuItem>
                  ))}</Select></FormControl><Button variant="contained"
                onClick={handleLoadPreset}
                disabled={!selectedPreset}
                data-learn={i18nText("ui:m_9ea7a3532a015efad13a")}>
                {i18nText("ui:m_1b14081bb43e75a26c36")}
              </Button></Box><TableContainer component={Paper}><Table><TableHead><TableRow><TableCell>{i18nRichText("ui:m_59199fd72f93edc668a9", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell><TableCell>{i18nRichText("ui:m_055b4c5cb3abb7dceac0", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell><TableCell>{i18nRichText("ui:m_1b4640b3609487eb9907", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell><TableCell>{i18nRichText("ui:m_3bbafe2c2d010ec8fed7", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell><TableCell align="right">{i18nRichText("ui:m_1df8def1c6510bcea102", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell></TableRow></TableHead><TableBody>{presetsData?.presets && presetsData.presets.length > 0 ? (
                    presetsData.presets.map((preset) => (
                      <TableRow key={preset.name} hover><TableCell>{preset.name}</TableCell><TableCell>{suppliedMetadataText(preset, "description")}</TableCell><TableCell>{preset.harvester_count}</TableCell><TableCell>{new Date(preset.modified_at).toLocaleDateString(getUILocale())}</TableCell><TableCell align="right"><Tooltip title={i18nText("ui:m_5f1c36a45f9be850c2ff")}><IconButton size="small"
                              onClick={() => handleDownloadPreset(preset.name)}
                              data-learn={i18nText("ui:m_072bdbc647eb8bca5d52")}><FileDownloadIcon /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_c1be408539d8c22dfb4a")}><IconButton size="small"
                              color="error"
                              onClick={() => handleDeletePreset(preset.name)}
                              data-learn={i18nText("ui:m_4905d2cc8524531d235b")}><DeleteIcon /></IconButton></Tooltip></TableCell></TableRow>
                    ))
                  ) : (
                    <TableRow><TableCell colSpan={5} align="center"><Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                          {i18nText("ui:m_f9f38c912294be90a06a")}
                        </Typography></TableCell></TableRow>
                  )}</TableBody></Table></TableContainer></Box>
        )}{/* Save Preset Dialog */}<Dialog open={savePresetDialogOpen} onClose={() => setSavePresetDialogOpen(false)} fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">
              {i18nRichText("ui:m_592ef1fb4089f2d4dc92", { arg0: isMobile && (
                <IconButton onClick={() => setSavePresetDialogOpen(false)} edge="end"><CloseIcon /></IconButton>
              ) })}
            </Box></DialogTitle><DialogContent><TextField autoFocus
              margin="dense"
              label={i18nText("ui:m_64dcc8702411c9b0e675")}
              fullWidth
              value={presetName}
              onChange={(e) => setPresetName(e.target.value)} /></DialogContent><DialogActions><Button onClick={() => setSavePresetDialogOpen(false)}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button onClick={handleSavePreset} variant="contained">{i18nText("ui:m_72bba814ee286eb80909")}</Button></DialogActions></Dialog>{/* Upload Preset Dialog */}<Dialog open={uploadDialogOpen} onClose={() => setUploadDialogOpen(false)} fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">
              {i18nRichText("ui:m_21f638a349e2d25fd231", { arg0: isMobile && (
                <IconButton onClick={() => setUploadDialogOpen(false)} edge="end"><CloseIcon /></IconButton>
              ) })}
            </Box></DialogTitle><DialogContent><input type="file"
              accept=".yml,.yaml"
              onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
              style={{ marginTop: 16 }} /></DialogContent><DialogActions><Button onClick={() => setUploadDialogOpen(false)}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button onClick={handleUploadPreset} variant="contained" disabled={!uploadFile}>
              {i18nText("ui:m_7f177ccee7151e5c9275")}
            </Button></DialogActions></Dialog>{/* Snackbar */}<Snackbar open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}><Alert onClose={() => setSnackbar({ ...snackbar, open: false })} severity={snackbar.severity}>{i18nRenderText(snackbar.message)}</Alert></Snackbar></Box></Layout>
  );
}
