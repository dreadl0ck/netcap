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

import { useEffect, useState, useRef } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Switch,
  TextField,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  ChevronRight as ChevronRightIcon,
  ExpandMore as ExpandMoreIcon,
  Save as SaveIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  KeyboardArrowDown as KeyboardArrowDownIcon,
  KeyboardArrowUp as KeyboardArrowUpIcon,
  FolderOpen as FolderOpenIcon,
  Upload as UploadIcon,
  SaveAs as SaveAsIcon,
  Delete as DeleteIcon,
  GetApp as GetAppIcon,
  OpenInNew as OpenInNewIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import useSWR from 'swr';
import Layout from '../components/Layout';
import type { DecoderInfo, DecoderConfig, FieldInfo, DecoderConfigFile } from '../lib/api';
import { formatTimestamp } from '../lib/api';
import { useNetcapApi } from '../hooks';

interface DecoderCategory {
  name: string;
  key: string;
  decoders: DecoderInfo[];
  color: string;
}

const getCategoryColor = (categoryKey: string): string => {
  const colors: Record<string, string> = {
    packet: '#2196f3',    // Blue
    gopacket: '#9c27b0',  // Purple
    stream: '#ff9800',    // Orange
    abstract: '#4caf50',  // Green
  };
  return colors[categoryKey] || '#757575';
};

// Convert PascalCase/camelCase to snake_case
const toSnakeCase = (str: string): string => {
  // If the string is all uppercase (e.g., MPLS, DNS), just convert to lowercase
  if (str === str.toUpperCase() && str.match(/^[A-Z0-9]+$/)) {
    return str.toLowerCase();
  }
  
  // Handle consecutive uppercase letters (acronyms) followed by lowercase letters
  // E.g., "TLSServerHello" -> "tls_server_hello", not "t_l_s_server_hello"
  return str
    // Insert underscore before an uppercase letter that follows a lowercase letter or digit
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    // Insert underscore between acronym and PascalCase word
    // E.g., "TLSServer" -> "TLS_Server" (not "TL_SServer")
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .toLowerCase();
};

const getDecoderGitHubUrl = (categoryKey: string, decoderName: string): string => {
  const baseUrl = 'https://github.com/dreadl0ck/netcap/blob/master/decoder';
  
  // Special case mappings for abbreviated decoder filenames
  const specialCases: Record<string, string> = {
    // ICMPv6 variants (abbreviated)
    'ICMPv6NeighborSolicitation': 'icmp6ns',
    'ICMPv6RouterSolicitation': 'icmp6rs',
    'ICMPv6RouterAdvertisement': 'icmp6ra',
    'ICMPv6NeighborAdvertisement': 'icmp6na',
    'ICMPv6Echo': 'icmp6e',
    // DHCP variants (v -> version number)
    'DHCPv6': 'dhcp6',
    'DHCPv4': 'dhcp4',
    // Ethernet CTP
    'EthernetCTP': 'ethctp',
    'EthernetCTPReply': 'ethctpr',
    // USB
    'USBRequestBlockSetup': 'usb_request_block_setup',
    // Versioned protocols (no underscore before version)
    'OSPFv2': 'ospfv2',
    'OSPFv3': 'ospfv3',
    'VRRPv2': 'vrrpv2',
    // Numbered protocols (no underscore before number)
    'Dot1Q': 'dot1q',
    'Dot11': 'dot11',
    // IPv6 variants (no underscore)
    'IP6Hop': 'ip6hop',
    'IPv6Fragment': 'ipv6fragment',
    // IPSec variants (no underscores)
    'IPSecAH': 'ipsecah',
    'IPSecESP': 'ipsecesp',
    // EAPOL variants (no underscores)
    'EAPOLKey': 'eapolkey',
  };
  
  // Check if there's a special case mapping
  let filename = specialCases[decoderName];
  if (!filename) {
    // Otherwise use snake_case conversion
    filename = toSnakeCase(decoderName);
  }
  
  switch (categoryKey) {
    case 'stream':
      // Stream decoders are in subdirectories: decoder/stream/{name}/{name}.go
      return `${baseUrl}/stream/${filename}/${filename}.go`;
    case 'packet':
    case 'gopacket':
      // Packet decoders are directly in the packet directory: decoder/packet/{name}.go
      return `${baseUrl}/packet/${filename}.go`;
    case 'abstract':
      // Abstract decoders are in the abstract_decoder.go file or subdirectories
      return `${baseUrl}/abstract_decoder.go`;
    default:
      return baseUrl;
  }
};

export default function Decoders() {
  const api = useNetcapApi();
  const { data: decodersData, error: decodersError } = useSWR('decoders', () => api.getDecoders());
  const { data: configData, mutate: mutateConfig } = useSWR('decoderConfig', () => api.getDecoderConfig());
  const { data: savedConfigs, mutate: mutateSavedConfigs } = useSWR('savedDecoderConfigs', () => api.listDecoderConfigs());
  const { data: versionInfo } = useSWR('version', () => api.getVersion());
  const [searchTerm, setSearchTerm] = useState('');
  const [enabledDecoders, setEnabledDecoders] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(['packet', 'gopacket', 'stream', 'abstract'])
  );
  const [expandedDecoder, setExpandedDecoder] = useState<string | null>(null);
  const [decoderFields, setDecoderFields] = useState<Record<string, FieldInfo[]>>({});
  const [loadingAllFields, setLoadingAllFields] = useState(true);
  
  // Dialog states
  const [loadDialogOpen, setLoadDialogOpen] = useState(false);
  const [saveAsDialogOpen, setSaveAsDialogOpen] = useState(false);
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [configName, setConfigName] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [applyOnUpload, setApplyOnUpload] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Initialize enabled decoders state from fetched data
  useEffect(() => {
    if (decodersData) {
      const enabled: Record<string, boolean> = {};
      
      [...decodersData.packet, ...decodersData.gopacket, ...decodersData.stream, ...decodersData.abstract].forEach(
        (decoder) => {
          enabled[decoder.name] = decoder.enabled;
        }
      );
      
      setEnabledDecoders(enabled);
    }
  }, [decodersData]);

  // Fetch ALL decoder fields on mount
  useEffect(() => {
    const fetchAllFields = async () => {
      try {
        setLoadingAllFields(true);
        const allFields = await api.getAllDecoderFields();
        setDecoderFields(allFields);
      } catch (error) {
        console.error('Failed to fetch decoder fields:', error);
      } finally {
        setLoadingAllFields(false);
      }
    };

    fetchAllFields();
  }, []);

  const toggleCategory = (categoryKey: string) => {
    setExpandedCategories((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(categoryKey)) {
        newSet.delete(categoryKey);
      } else {
        newSet.add(categoryKey);
      }
      return newSet;
    });
  };

  const handleToggle = (decoderName: string) => {
    setEnabledDecoders((prev) => ({
      ...prev,
      [decoderName]: !prev[decoderName],
    }));
  };

  const handleDecoderClick = (decoderName: string) => {
    // Toggle expansion - fields are already loaded
    if (expandedDecoder === decoderName) {
      setExpandedDecoder(null);
    } else {
      setExpandedDecoder(decoderName);
    }
  };

  const handleToggleAll = (category: string, enabled: boolean) => {
    if (!decodersData) return;

    const decoders = category === 'packet' 
      ? decodersData.packet
      : category === 'gopacket'
      ? decodersData.gopacket
      : category === 'stream'
      ? decodersData.stream
      : decodersData.abstract;

    const updates: Record<string, boolean> = {};
    decoders.forEach((decoder) => {
      updates[decoder.name] = enabled;
    });

    setEnabledDecoders((prev) => ({
      ...prev,
      ...updates,
    }));
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveError(null);
    setSaveSuccess(null);

    try {
      // Get list of enabled and disabled decoders
      const enabled = Object.entries(enabledDecoders)
        .filter(([_, isEnabled]) => isEnabled)
        .map(([name]) => name);
      
      const disabled = Object.entries(enabledDecoders)
        .filter(([_, isEnabled]) => !isEnabled)
        .map(([name]) => name);

      // Determine whether to use include or exclude mode
      // If more than half are enabled, use exclude mode; otherwise use include mode
      const totalCount = Object.keys(enabledDecoders).length;
      const enabledCount = enabled.length;
      
      let config: DecoderConfig;
      if (enabledCount > totalCount / 2) {
        // Most decoders enabled, use exclude list
        config = {
          includeDecoders: '',
          excludeDecoders: disabled.join(','),
          enabledDecoders: enabled,
        };
      } else {
        // Fewer decoders enabled, use include list
        config = {
          includeDecoders: enabled.join(','),
          excludeDecoders: '',
          enabledDecoders: enabled,
        };
      }

      const result = await api.saveDecoderConfig(config);
      setSaveSuccess(result.message);
      mutateConfig();

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleLoadConfig = async (name: string) => {
    setSaving(true);
    setSaveError(null);
    setSaveSuccess(null);

    try {
      const result = await api.loadDecoderConfig(name);
      setSaveSuccess(result.message);
      if (result.warning) {
        setSaveSuccess(result.message + ' - ' + result.warning);
      }
      
      // Update enabled decoders from loaded config
      if (result.config) {
        const newEnabled: Record<string, boolean> = {};
        
        // If include list is set, only those decoders are enabled
        if (result.config.includeDecoders) {
          const included = result.config.includeDecoders.split(',').map(s => s.trim());
          Object.keys(enabledDecoders).forEach(name => {
            newEnabled[name] = included.includes(name);
          });
        } else if (result.config.excludeDecoders) {
          // If exclude list is set, all except those are enabled
          const excluded = result.config.excludeDecoders.split(',').map(s => s.trim());
          Object.keys(enabledDecoders).forEach(name => {
            newEnabled[name] = !excluded.includes(name);
          });
        } else {
          // No lists set, all enabled
          Object.keys(enabledDecoders).forEach(name => {
            newEnabled[name] = true;
          });
        }
        
        setEnabledDecoders(newEnabled);
      }
      
      mutateConfig();
      setLoadDialogOpen(false);

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to load configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleSaveAs = async () => {
    if (!configName.trim()) {
      setSaveError('Configuration name is required');
      return;
    }

    setSaving(true);
    setSaveError(null);
    setSaveSuccess(null);

    try {
      // Build config from current enabled decoders
      const enabled = Object.entries(enabledDecoders)
        .filter(([_, isEnabled]) => isEnabled)
        .map(([name]) => name);
      
      const disabled = Object.entries(enabledDecoders)
        .filter(([_, isEnabled]) => !isEnabled)
        .map(([name]) => name);

      const totalCount = Object.keys(enabledDecoders).length;
      const enabledCount = enabled.length;
      
      let config: DecoderConfig;
      if (enabledCount > totalCount / 2) {
        config = {
          includeDecoders: '',
          excludeDecoders: disabled.join(','),
          enabledDecoders: enabled,
        };
      } else {
        config = {
          includeDecoders: enabled.join(','),
          excludeDecoders: '',
          enabledDecoders: enabled,
        };
      }

      const result = await api.saveDecoderConfigAs(configName, config);
      setSaveSuccess(result.message);
      mutateSavedConfigs();
      setSaveAsDialogOpen(false);
      setConfigName('');

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleUpload = async () => {
    if (!uploadFile) {
      setSaveError('Please select a file to upload');
      return;
    }

    setSaving(true);
    setSaveError(null);
    setSaveSuccess(null);

    try {
      const result = await api.uploadDecoderConfig(uploadFile, configName || undefined, applyOnUpload);
      setSaveSuccess(result.message);
      mutateSavedConfigs();
      
      if (result.applied) {
        mutateConfig();
        // Reload the page to reflect changes
        window.location.reload();
      }
      
      setUploadDialogOpen(false);
      setUploadFile(null);
      setConfigName('');

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to upload configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteConfig = async (name: string) => {
    if (!confirm(`Are you sure you want to delete the configuration "${name}"?`)) {
      return;
    }

    setSaving(true);
    setSaveError(null);
    setSaveSuccess(null);

    try {
      const result = await api.deleteDecoderConfig(name);
      setSaveSuccess(result.message);
      mutateSavedConfigs();

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to delete configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setUploadFile(file);
    }
  };

  if (decodersError) {
    return (
      <Layout title="Decoders">
        <Alert severity="error">
          Failed to load decoders: {decodersError.message}
        </Alert>
      </Layout>
    );
  }

  if (!decodersData || !configData) {
    return (
      <Layout title="Decoders">
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  // Filter decoders by search term
  const filterDecoders = (decoders: DecoderInfo[]) => {
    if (!searchTerm) return decoders;
    const term = searchTerm.toLowerCase();
    return decoders.filter(
      (decoder) =>
        decoder.name.toLowerCase().includes(term) ||
        decoder.description.toLowerCase().includes(term)
    );
  };

  // Build category groups
  const categories: DecoderCategory[] = decodersData ? [
    {
      name: 'Packet Decoders',
      key: 'packet',
      decoders: filterDecoders(decodersData.packet),
      color: getCategoryColor('packet'),
    },
    {
      name: 'GoPacket Layer Decoders',
      key: 'gopacket',
      decoders: filterDecoders(decodersData.gopacket),
      color: getCategoryColor('gopacket'),
    },
    {
      name: 'Stream Decoders',
      key: 'stream',
      decoders: filterDecoders(decodersData.stream),
      color: getCategoryColor('stream'),
    },
    {
      name: 'Abstract Decoders',
      key: 'abstract',
      decoders: filterDecoders(decodersData.abstract),
      color: getCategoryColor('abstract'),
    },
  ].filter(cat => cat.decoders.length > 0) : [];

  const totalDecoders = categories.reduce((sum, cat) => sum + cat.decoders.length, 0);
  const enabledCount = Object.values(enabledDecoders).filter(Boolean).length;

  return (
    <Layout title="Decoders">
      {saveSuccess && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {saveSuccess}
        </Alert>
      )}
      {saveError && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setSaveError(null)}>
          {saveError}
        </Alert>
      )}

      <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={3} gap={2}>
        <Typography variant="body2" color="text.secondary">
          {totalDecoders} decoder(s) available • {enabledCount} enabled • Hierarchical by type
        </Typography>
        <Box display="flex" gap={1}>
          <Button
            data-learn="Load Configuration: Load a previously saved decoder configuration to quickly switch between different decoder setups."
            variant="outlined"
            startIcon={<FolderOpenIcon />}
            onClick={() => setLoadDialogOpen(true)}
            disabled={saving}
          >
            Load
          </Button>
          <Button
            data-learn="Upload Configuration: Upload a decoder configuration JSON file from your computer to import custom decoder settings."
            variant="outlined"
            startIcon={<UploadIcon />}
            onClick={() => setUploadDialogOpen(true)}
            disabled={saving}
          >
            Upload
          </Button>
          <Button
            data-learn="Save As: Save the current decoder configuration with a custom name for later reuse without overwriting the active configuration."
            variant="outlined"
            startIcon={<SaveAsIcon />}
            onClick={() => setSaveAsDialogOpen(true)}
            disabled={saving}
          >
            Save As
          </Button>
          <Button
            data-learn="Save Configuration: Apply and save the current decoder settings to make them active for packet analysis."
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSave}
            disabled={saving}
            sx={{ minWidth: '140px' }}
          >
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </Box>
      </Box>

      {/* Library Version Section */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            Library Version
          </Typography>
          <Paper 
            data-learn="GoPacket Library: View the gopacket library repository on GitHub - the high-performance packet decoding library that powers Netcap's decoder infrastructure."
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
            onClick={() => window.open('https://github.com/gopacket/gopacket', '_blank', 'noopener,noreferrer')}
          >
            <Box display="flex" justifyContent="space-between" alignItems="start">
              <Box flex={1}>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  gopacket Version
                </Typography>
                <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                  {versionInfo?.gopacketVersion || 'Loading...'}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  High-performance packet decoding library for Go
                </Typography>
              </Box>
              <OpenInNewIcon fontSize="small" sx={{ color: 'text.secondary', ml: 1 }} />
            </Box>
          </Paper>
        </CardContent>
      </Card>

      <Box sx={{ mb: 3 }}>
        <TextField
          data-learn="Search Decoders: Filter the decoder list by name or description to quickly find specific protocol decoders."
          fullWidth
          placeholder="Search decoders by name or description..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          size="small"
        />
      </Box>

      {categories.length > 0 ? (
        <Paper sx={{ p: 2 }}>
          {categories.map((category, catIdx) => {
            const enabledInCategory = category.decoders.filter((d) => enabledDecoders[d.name]).length;
            const totalInCategory = category.decoders.length;
            const allEnabled = enabledInCategory === totalInCategory;
            const noneEnabled = enabledInCategory === 0;

            return (
              <Box key={category.key} sx={{ mb: catIdx < categories.length - 1 ? 2 : 0 }}>
                {/* Category Header */}
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    cursor: 'pointer',
                    p: 1,
                    borderRadius: 1,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                  onClick={() => toggleCategory(category.key)}
                >
                  <IconButton size="small" sx={{ mr: 1 }}>
                    {expandedCategories.has(category.key) ? <ExpandMoreIcon /> : <ChevronRightIcon />}
                  </IconButton>
                  <Box
                    sx={{
                      width: 3,
                      height: 24,
                      bgcolor: category.color,
                      mr: 2,
                      borderRadius: 1,
                    }}
                  />
                  <Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>
                    {category.name}
                  </Typography>
                  <Chip
                    label={`${enabledInCategory}/${totalInCategory} enabled`}
                    size="small"
                    color={allEnabled ? 'success' : noneEnabled ? 'default' : 'warning'}
                    sx={{ mr: 2 }}
                  />
                  <Button
                    data-learn="Enable All Decoders: Enable all decoders in this category to capture comprehensive data for all protocols in this group."
                    size="small"
                    variant="outlined"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleAll(category.key, true);
                    }}
                    sx={{ mr: 1 }}
                  >
                    Enable All
                  </Button>
                  <Button
                    data-learn="Disable All Decoders: Disable all decoders in this category to skip processing these protocol types and improve performance."
                    size="small"
                    variant="outlined"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleAll(category.key, false);
                    }}
                  >
                    Disable All
                  </Button>
                </Box>

                {/* Category Content */}
                <Collapse in={expandedCategories.has(category.key)}>
                  <Box sx={{ ml: 6, mt: 1 }}>
                    {category.decoders.map((decoder, decoderIdx) => {
                      const isEnabled = enabledDecoders[decoder.name] || false;
                      const isExpanded = expandedDecoder === decoder.name;
                      const fields = decoderFields[decoder.name] || [];
                      
                      return (
                        <Box key={decoder.name} sx={{ mb: decoderIdx < category.decoders.length - 1 ? 1 : 0 }}>
                          <Box
                            data-learn="Decoder Row: Click to expand and view the data fields that this decoder extracts from network packets (e.g., source/destination addresses, ports, protocol-specific data)."
                            sx={{
                              display: 'flex',
                              alignItems: 'center',
                              p: 1.5,
                              borderLeft: 2,
                              borderColor: isExpanded ? category.color : 'divider',
                              bgcolor: isExpanded ? 'action.selected' : 'background.default',
                              borderRadius: 1,
                              cursor: 'pointer',
                              transition: 'all 0.2s',
                              '&:hover': {
                                bgcolor: isExpanded ? 'action.selected' : 'action.hover',
                                borderLeftColor: category.color,
                              },
                            }}
                            onClick={() => handleDecoderClick(decoder.name)}
                          >
                            <Box sx={{ mr: 2 }}>
                              {isEnabled ? (
                                <CheckCircleIcon sx={{ color: 'success.main', fontSize: 20 }} />
                              ) : (
                                <CancelIcon sx={{ color: 'text.disabled', fontSize: 20 }} />
                              )}
                            </Box>
                            <Box sx={{ flex: 1 }}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                <Typography
                                  component="code"
                                  sx={{
                                    fontFamily: 'monospace',
                                    fontSize: '0.9rem',
                                    fontWeight: 600,
                                    color: isEnabled ? 'text.primary' : 'text.disabled',
                                  }}
                                >
                                  {decoder.name}
                                </Typography>
                                {decoder.port && (
                                  <Chip
                                    label={`Port ${decoder.port}`}
                                    size="small"
                                    sx={{
                                      height: 20,
                                      fontSize: '0.7rem',
                                      bgcolor: category.color + '20',
                                      color: category.color,
                                    }}
                                  />
                                )}
                              </Box>
                              <Typography
                                variant="body2"
                                color="text.secondary"
                                sx={{ fontSize: '0.85rem' }}
                              >
                                {decoder.description}
                              </Typography>
                            </Box>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <IconButton
                                data-learn="View Source Code: Open the decoder's implementation on GitHub to see how it parses and extracts data from network packets."
                                size="small"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  window.open(getDecoderGitHubUrl(category.key, decoder.name), '_blank', 'noopener,noreferrer');
                                }}
                                sx={{ color: 'text.secondary' }}
                                title="View source code on GitHub"
                              >
                                <CodeIcon />
                              </IconButton>
                              <IconButton
                                size="small"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleDecoderClick(decoder.name);
                                }}
                                sx={{ color: 'text.secondary' }}
                              >
                                {isExpanded ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}
                              </IconButton>
                              <FormControlLabel
                                data-learn="Decoder Toggle: Enable or disable this decoder to control whether this protocol type is analyzed and logged during packet capture."
                                control={
                                  <Switch
                                    checked={isEnabled}
                                    onChange={(e) => {
                                      e.stopPropagation();
                                      handleToggle(decoder.name);
                                    }}
                                    color="primary"
                                  />
                                }
                                label=""
                                onClick={(e) => e.stopPropagation()}
                              />
                            </Box>
                          </Box>
                          
                          <Collapse in={isExpanded}>
                            <Box sx={{ pl: 8, pr: 2, pb: 2, pt: 1 }}>
                              {loadingAllFields ? (
                                <Box sx={{ display: 'flex', justifyContent: 'center', p: 2 }}>
                                  <CircularProgress size={24} />
                                  <Typography variant="body2" color="text.secondary" sx={{ ml: 2 }}>
                                    Loading field information...
                                  </Typography>
                                </Box>
                              ) : fields.length > 0 ? (
                                <TableContainer component={Paper} variant="outlined">
                                  <Table size="small">
                                    <TableHead>
                                      <TableRow>
                                        <TableCell sx={{ fontWeight: 600 }}>Field Name</TableCell>
                                        <TableCell sx={{ fontWeight: 600 }}>Type</TableCell>
                                      </TableRow>
                                    </TableHead>
                                    <TableBody>
                                      {fields.map((field) => (
                                        <TableRow key={field.name} sx={{ '&:last-child td': { border: 0 } }}>
                                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                                            {field.name}
                                          </TableCell>
                                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'text.secondary' }}>
                                            {field.type}
                                          </TableCell>
                                        </TableRow>
                                      ))}
                                    </TableBody>
                                  </Table>
                                </TableContainer>
                              ) : (
                                <Typography variant="body2" color="text.secondary" sx={{ p: 2, textAlign: 'center' }}>
                                  No field information available for this decoder.
                                </Typography>
                              )}
                            </Box>
                          </Collapse>
                        </Box>
                      );
                    })}
                  </Box>
                </Collapse>
              </Box>
            );
          })}
        </Paper>
      ) : (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography color="text.secondary">
            {searchTerm ? 'No decoders match your search.' : 'No decoders available.'}
          </Typography>
        </Paper>
      )}

      {/* Load Configuration Dialog */}
      <Dialog open={loadDialogOpen} onClose={() => setLoadDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Load Decoder Configuration</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Select a saved configuration to load:
          </Typography>
          {!savedConfigs || savedConfigs.length === 0 ? (
            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
              No saved configurations found.
            </Typography>
          ) : (
            <List>
              {savedConfigs.map((config) => (
                <ListItem
                  key={config.name}
                  sx={{
                    border: 1,
                    borderColor: 'divider',
                    borderRadius: 1,
                    mb: 1,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                >
                  <ListItemText
                    primary={config.name}
                    secondary={`Modified: ${formatTimestamp(config.modifiedTime)}`}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      edge="end"
                      aria-label="load"
                      onClick={() => handleLoadConfig(config.name)}
                      disabled={saving}
                      sx={{ mr: 1 }}
                    >
                      <GetAppIcon />
                    </IconButton>
                    <IconButton
                      edge="end"
                      aria-label="delete"
                      onClick={() => handleDeleteConfig(config.name)}
                      disabled={saving}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
          )}
        </DialogContent>
        <DialogActions>
          <Button data-learn="Cancel: Close the load configuration dialog without loading." onClick={() => setLoadDialogOpen(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>

      {/* Save As Dialog */}
      <Dialog open={saveAsDialogOpen} onClose={() => setSaveAsDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Save Configuration As</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Enter a name for this configuration:
          </Typography>
          <TextField
            autoFocus
            fullWidth
            label="Configuration Name"
            value={configName}
            onChange={(e) => setConfigName(e.target.value)}
            placeholder="e.g., http-only, minimal-decoders"
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button data-learn="Cancel: Close the save dialog without saving." onClick={() => { setSaveAsDialogOpen(false); setConfigName(''); }}>Cancel</Button>
          <Button data-learn="Save Configuration: Save the current decoder configuration with the specified name." onClick={handleSaveAs} variant="contained" disabled={saving || !configName.trim()}>
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Upload Configuration Dialog */}
      <Dialog open={uploadDialogOpen} onClose={() => setUploadDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Upload Decoder Configuration</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Upload a decoder configuration JSON file:
          </Typography>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json"
            style={{ display: 'none' }}
            onChange={handleFileSelect}
          />
          <Box sx={{ mb: 2 }}>
            <Button
              variant="outlined"
              startIcon={<UploadIcon />}
              onClick={() => fileInputRef.current?.click()}
              fullWidth
            >
              {uploadFile ? uploadFile.name : 'Select File'}
            </Button>
          </Box>
          <TextField
            fullWidth
            label="Configuration Name (Optional)"
            value={configName}
            onChange={(e) => setConfigName(e.target.value)}
            placeholder="Leave empty to use filename"
            sx={{ mb: 2 }}
          />
          <FormControlLabel
            control={
              <Switch
                checked={applyOnUpload}
                onChange={(e) => setApplyOnUpload(e.target.checked)}
              />
            }
            label="Apply this configuration immediately"
          />
        </DialogContent>
        <DialogActions>
          <Button data-learn="Cancel: Close the upload dialog without uploading." onClick={() => { setUploadDialogOpen(false); setUploadFile(null); setConfigName(''); }}>
            Cancel
          </Button>
          <Button data-learn="Upload Configuration File: Upload the selected configuration file to import decoder settings." onClick={handleUpload} variant="contained" disabled={saving || !uploadFile}>
            {saving ? 'Uploading...' : 'Upload'}
          </Button>
        </DialogActions>
      </Dialog>
    </Layout>
  );
}

