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
  Close as CloseIcon,
} from '@mui/icons-material';

import Layout from '../components/Layout';
import type { DecoderInfo, DecoderConfig, FieldInfo, DecoderConfigFile } from '../lib/api';
import { formatTimestamp } from '../lib/api';
import { useNetcapApi, useIsMobile } from '../hooks';
import { useTheme } from '@mui/material/styles';
import { appearanceTokens, type AppearanceMode } from '../lib/appearance';
import { message as i18nMessage, translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, metadataText } from "../lib/i18n";
import { renderError } from "../lib/i18n";
import { errorText, fieldLabel, recordTypeLabel } from "../lib/i18n";
import { metadataMessage, joinMessages } from "../lib/i18n";






interface DecoderCategory {
  name: string;
  key: string;
  decoders: DecoderInfo[];
  color: string;
}

const getCategoryColor = (categoryKey: string, mode: AppearanceMode): string => {
  const c = appearanceTokens(mode);
  const colors: Record<string, string> = {
    packet: c.primary,
    gopacket: c.secondary,
    stream: c.warning,
    abstract: c.success,
  };
  return colors[categoryKey] || c.muted;
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
  const baseUrl = 'https://github.com/dreadl0ck/netcap/blob/master/internal/decoder';
  
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
  const __uiLocale = useUILocale();
  const mode = useTheme().palette.mode;
  const isMobile = useIsMobile();
  const api = useNetcapApi();
  const { data: decodersData, error: decodersError } = useSWR('decoders', () => api.getDecoders());
  const { data: configData, mutate: mutateConfig } = useSWR('decoderConfig', () => api.getDecoderConfig());
  const { data: savedConfigs, mutate: mutateSavedConfigs } = useSWR('savedDecoderConfigs', () => api.listDecoderConfigs());
  const { data: versionInfo } = useSWR('version', () => api.getVersion());
  const [searchTerm, setSearchTerm] = useState('');
  const [enabledDecoders, setEnabledDecoders] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<UIMessageText | null>(null);
  const [saveSuccess, setSaveSuccess] = useState<UIMessageText | null>(null);
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
      setSaveSuccess(metadataMessage(result, 'message'));
      mutateConfig();

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? errorText(err) : i18nMessage("ui:m_0475bdfeacbe6871348c"));
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
      setSaveSuccess(joinMessages([metadataMessage(result, 'message'), ...(result.warning ? [metadataMessage(result, 'warning')] : [])], ' - '));
      
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
      setSaveError(err instanceof Error ? errorText(err) : i18nMessage("ui:m_9f40c76e71eaa1248bb5"));
    } finally {
      setSaving(false);
    }
  };

  const handleSaveAs = async () => {
    if (!configName.trim()) {
      setSaveError(i18nMessage("ui:m_ce6b1f0cdcd1c6bf9d1d"));
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
      setSaveSuccess(metadataMessage(result, 'message'));
      mutateSavedConfigs();
      setSaveAsDialogOpen(false);
      setConfigName('');

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? errorText(err) : i18nMessage("ui:m_0475bdfeacbe6871348c"));
    } finally {
      setSaving(false);
    }
  };

  const handleUpload = async () => {
    if (!uploadFile) {
      setSaveError(i18nMessage("ui:m_555eae656d88a606361c"));
      return;
    }

    setSaving(true);
    setSaveError(null);
    setSaveSuccess(null);

    try {
      const result = await api.uploadDecoderConfig(uploadFile, configName || undefined, applyOnUpload);
      setSaveSuccess(metadataMessage(result, 'message'));
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
      setSaveError(err instanceof Error ? errorText(err) : i18nMessage("ui:m_32ad5dd4aba918be58b0"));
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteConfig = async (name: string) => {
    if (!confirm(i18nText("ui:m_2f73b9e7e76f77d51ed1", { arg0: name }))) {
      return;
    }

    setSaving(true);
    setSaveError(null);
    setSaveSuccess(null);

    try {
      const result = await api.deleteDecoderConfig(name);
      setSaveSuccess(metadataMessage(result, 'message'));
      mutateSavedConfigs();

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? errorText(err) : i18nMessage("ui:m_b1f44a6b6dff579bc041"));
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
      <Layout title={i18nText("ui:m_307fc00184a143bc2caf")}><Alert severity="error">
          {i18nRichText("ui:m_6edb0988698f5e4e1b2c", { arg0: renderError(decodersError) })}
        </Alert></Layout>
    );
  }

  if (!decodersData || !configData) {
    return (
      <Layout title={i18nText("ui:m_307fc00184a143bc2caf")}><Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}><CircularProgress /></Box></Layout>
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
      color: getCategoryColor('packet', mode),
    },
    {
      name: 'GoPacket Layer Decoders',
      key: 'gopacket',
      decoders: filterDecoders(decodersData.gopacket),
      color: getCategoryColor('gopacket', mode),
    },
    {
      name: 'Stream Decoders',
      key: 'stream',
      decoders: filterDecoders(decodersData.stream),
      color: getCategoryColor('stream', mode),
    },
    {
      name: 'Abstract Decoders',
      key: 'abstract',
      decoders: filterDecoders(decodersData.abstract),
      color: getCategoryColor('abstract', mode),
    },
  ].filter(cat => cat.decoders.length > 0) : [];

  const totalDecoders = categories.reduce((sum, cat) => sum + cat.decoders.length, 0);
  const enabledCount = Object.values(enabledDecoders).filter(Boolean).length;

  return (
    <Layout title={i18nText("ui:m_307fc00184a143bc2caf")}>{i18nRenderText(saveSuccess) && (
        <Alert severity="success" sx={{ mb: 2 }}>{i18nRenderText(saveSuccess)}</Alert>
      )}{i18nRenderText(saveError) && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setSaveError(null)}>{i18nRenderText(saveError)}</Alert>
      )}<Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={3} gap={2}><Typography variant="body2" color="text.secondary">
          {i18nRichText("ui:m_328a60fd7a316c848623", { arg0: totalDecoders, arg1: enabledCount })}
        </Typography><Box display="flex" gap={1}><Button data-learn={i18nText("ui:m_095864f179d5d4c56fad")}
            variant="outlined"
            startIcon={<FolderOpenIcon />}
            onClick={() => setLoadDialogOpen(true)}
            disabled={saving}>
            {i18nText("ui:m_1b14081bb43e75a26c36")}
          </Button><Button data-learn={i18nText("ui:m_303953937a3ce9047517")}
            variant="outlined"
            startIcon={<UploadIcon />}
            onClick={() => setUploadDialogOpen(true)}
            disabled={saving}>
            {i18nText("ui:m_7f177ccee7151e5c9275")}
          </Button><Button data-learn={i18nText("ui:m_436ca25503e1113004af")}
            variant="outlined"
            startIcon={<SaveAsIcon />}
            onClick={() => setSaveAsDialogOpen(true)}
            disabled={saving}>
            {i18nText("ui:m_6efb24337c3d7f4b7914")}
          </Button><Button data-learn={i18nText("ui:m_ad41d631905dc649e00b")}
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSave}
            disabled={saving}
            sx={{ minWidth: '140px' }}>{saving ? i18nText("ui:m_84d67cc7cab845a90ab6") : i18nText("ui:m_72bba814ee286eb80909")}</Button></Box></Box>{/* Library Version Section */}<Card sx={{ mb: 3 }}><CardContent><Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {i18nText("ui:m_8a57d8b6a81b7461f02a")}
          </Typography><Paper data-learn={i18nText("ui:m_41807e8f17fe32c9dfa0")}
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
            onClick={() => window.open('https://github.com/gopacket/gopacket', '_blank', 'noopener,noreferrer')}><Box display="flex" justifyContent="space-between" alignItems="start"><Box flex={1}><Typography variant="body2" color="text.secondary" gutterBottom>
                  {i18nText("ui:m_1285a9935ce275aaeb2e")}
                </Typography><Typography variant="h6" sx={{ fontFamily: 'monospace' }}>{versionInfo?.gopacketVersion || i18nText("ui:m_2d645f98b7feb0dbe272")}</Typography><Typography variant="caption" color="text.secondary">
                  {i18nText("ui:m_9cbc2f6c0a72a75a86c6")}
                </Typography></Box><OpenInNewIcon fontSize="small" sx={{ color: 'text.secondary', ml: 1 }} /></Box></Paper></CardContent></Card><Box sx={{ mb: 3 }}><TextField data-learn={i18nText("ui:m_6af94f437dcc298c1965")}
          fullWidth
          placeholder={i18nText("ui:m_13d6670e20a18464cbf5")}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          size="small" /></Box>{categories.length > 0 ? (
        <Paper sx={{ p: 2 }}>{categories.map((category, catIdx) => {
            const enabledInCategory = category.decoders.filter((d) => enabledDecoders[d.name]).length;
            const totalInCategory = category.decoders.length;
            const allEnabled = enabledInCategory === totalInCategory;
            const noneEnabled = enabledInCategory === 0;

            return (
              <Box key={category.key} sx={{ mb: catIdx < categories.length - 1 ? 2 : 0 }}>{/* Category Header */}<Box sx={{
                    display: 'flex',
                    alignItems: 'center',
                    cursor: 'pointer',
                    p: 1,
                    borderRadius: 1,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                  onClick={() => toggleCategory(category.key)}><IconButton size="small" sx={{ mr: 1 }}>{expandedCategories.has(category.key) ? <ExpandMoreIcon /> : <ChevronRightIcon />}</IconButton><Box sx={{
                      width: 3,
                      height: 24,
                      bgcolor: category.color,
                      mr: 2,
                      borderRadius: 1,
                    }} /><Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>{category.name}</Typography><Chip label={i18nText("ui:m_716c85f2bc88cffce5db", { arg0: enabledInCategory, arg1: totalInCategory })}
                    size="small"
                    color={allEnabled ? 'success' : noneEnabled ? 'default' : 'warning'}
                    sx={{ mr: 2 }} /><Button data-learn={i18nText("ui:m_adc48e0927b90034a4eb")}
                    size="small"
                    variant="outlined"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleAll(category.key, true);
                    }}
                    sx={{ mr: 1 }}>
                    {i18nText("ui:m_594e264e620a748e7fb1")}
                  </Button><Button data-learn={i18nText("ui:m_65235d94f93025474f60")}
                    size="small"
                    variant="outlined"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleAll(category.key, false);
                    }}>
                    {i18nText("ui:m_29eb7b2544bc7d22f6d3")}
                  </Button></Box>{/* Category Content */}<Collapse in={expandedCategories.has(category.key)}><Box sx={{ ml: 6, mt: 1 }}>{category.decoders.map((decoder, decoderIdx) => {
                      const isEnabled = enabledDecoders[decoder.name] || false;
                      const isExpanded = expandedDecoder === decoder.name;
                      const fields = decoderFields[decoder.name] || [];
                      
                      return (
                        <Box key={decoder.name} sx={{ mb: decoderIdx < category.decoders.length - 1 ? 1 : 0 }}><Box data-learn={i18nText("ui:m_7ca18772ca7d7354a850")}
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
                            onClick={() => handleDecoderClick(decoder.name)}><Box sx={{ mr: 2 }}>{isEnabled ? (
                                <CheckCircleIcon sx={{ color: 'success.main', fontSize: 20 }} />
                              ) : (
                                <CancelIcon sx={{ color: 'text.disabled', fontSize: 20 }} />
                              )}</Box><Box sx={{ flex: 1 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}><Typography component="code"
                                  sx={{
                                    fontFamily: 'monospace',
                                    fontSize: '0.9rem',
                                    fontWeight: 600,
                                    color: isEnabled ? 'text.primary' : 'text.disabled',
                                  }}>{decoder.name}</Typography>{decoder.port && (
                                  <Chip label={i18nText("ui:m_63d9080de503779cf1ba", { arg0: String(decoder.port) })}
                                    size="small"
                                    sx={{
                                      height: 20,
                                      fontSize: '0.7rem',
                                      bgcolor: category.color + '20',
                                      color: category.color,
                                    }} />
                                )}</Box><Typography variant="body2"
                                color="text.secondary"
                                sx={{ fontSize: '0.85rem' }}>{metadataText(decoder, "description")}</Typography></Box><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><IconButton data-learn={i18nText("ui:m_edf5b1e2ab694637f6e6")}
                                size="small"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  window.open(getDecoderGitHubUrl(category.key, decoder.name), '_blank', 'noopener,noreferrer');
                                }}
                                sx={{ color: 'text.secondary' }}
                                title={i18nText("ui:m_737c7db97490030e51b8")}><CodeIcon /></IconButton><IconButton size="small"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleDecoderClick(decoder.name);
                                }}
                                sx={{ color: 'text.secondary' }}>{isExpanded ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}</IconButton><FormControlLabel data-learn={i18nText("ui:m_f64eef350f55d917f27d")}
                                control={<Switch checked={isEnabled}
                                    onChange={(e) => {
                                      e.stopPropagation();
                                      handleToggle(decoder.name);
                                    }}
                                    color="primary" />}
                                label={""}
                                onClick={(e) => e.stopPropagation()} /></Box></Box><Collapse in={isExpanded}><Box sx={{ pl: 8, pr: 2, pb: 2, pt: 1 }}>{loadingAllFields ? (
                                <Box sx={{ display: 'flex', justifyContent: 'center', p: 2 }}><CircularProgress size={24} /><Typography variant="body2" color="text.secondary" sx={{ ml: 2 }}>
                                    {i18nText("ui:m_ca881ff6d4d87d362257")}
                                  </Typography></Box>
                              ) : fields.length > 0 ? (
                                <TableContainer component={Paper} variant="outlined"><Table size="small"><TableHead><TableRow><TableCell sx={{ fontWeight: 600 }}>{i18nText("ui:m_2dabd790bfcb9bb01fba")}</TableCell><TableCell sx={{ fontWeight: 600 }}>{i18nText("ui:m_3da346bd3b7d84ce65d6")}</TableCell></TableRow></TableHead><TableBody>{fields.map((field) => (
                                        <TableRow key={field.name} sx={{ '&:last-child td': { border: 0 } }}><TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{fieldLabel(field.name)}</TableCell><TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'text.secondary' }}>{recordTypeLabel(field.type)}</TableCell></TableRow>
                                      ))}</TableBody></Table></TableContainer>
                              ) : (
                                <Typography variant="body2" color="text.secondary" sx={{ p: 2, textAlign: 'center' }}>
                                  {i18nText("ui:m_3e587b569fa83f8c36e1")}
                                </Typography>
                              )}</Box></Collapse></Box>
                      );
                    })}</Box></Collapse></Box>
            );
          })}</Paper>
      ) : (
        <Paper sx={{ p: 4, textAlign: 'center' }}><Typography color="text.secondary">{searchTerm ? i18nText("ui:m_9d9831dc113de7188a35") : i18nText("ui:m_2b8428d7c08316aaf3e0")}</Typography></Paper>
      )}{/* Load Configuration Dialog */}<Dialog open={loadDialogOpen} onClose={() => setLoadDialogOpen(false)} maxWidth="sm" fullWidth fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">
            {i18nRichText("ui:m_1b34fd8f902c0facfe4e", { arg0: isMobile && (
              <IconButton onClick={() => setLoadDialogOpen(false)} edge="end"><CloseIcon /></IconButton>
            ) })}
          </Box></DialogTitle><DialogContent><Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {i18nText("ui:m_85a3e134d6e822413957")}
          </Typography>{!savedConfigs || savedConfigs.length === 0 ? (
            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
              {i18nText("ui:m_d27813c421e58b0b82f3")}
            </Typography>
          ) : (
            <List>{savedConfigs.map((config) => (
                <ListItem key={config.name}
                  sx={{
                    border: 1,
                    borderColor: 'divider',
                    borderRadius: 1,
                    mb: 1,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}><ListItemText primary={config.name}
                    secondary={i18nText("ui:m_334433e3d88e0a01c10c", { arg0: formatTimestamp(config.modifiedTime, 'seconds') })} /><ListItemSecondaryAction><IconButton edge="end"
                      aria-label={i18nText("ui:m_edf4fc6d7b5f54a5c144")}
                      onClick={() => handleLoadConfig(config.name)}
                      disabled={saving}
                      sx={{ mr: 1 }}><GetAppIcon /></IconButton><IconButton edge="end"
                      aria-label={i18nText("ui:m_800d457ec03b4d702058")}
                      onClick={() => handleDeleteConfig(config.name)}
                      disabled={saving}><DeleteIcon /></IconButton></ListItemSecondaryAction></ListItem>
              ))}</List>
          )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_89f801ad2e2a00a917ed")} onClick={() => setLoadDialogOpen(false)}>{i18nText("ui:m_0095547326bed510a824")}</Button></DialogActions></Dialog>{/* Save As Dialog */}<Dialog open={saveAsDialogOpen} onClose={() => setSaveAsDialogOpen(false)} maxWidth="sm" fullWidth fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">
            {i18nRichText("ui:m_5962bad8997b121bcff1", { arg0: isMobile && (
              <IconButton onClick={() => setSaveAsDialogOpen(false)} edge="end"><CloseIcon /></IconButton>
            ) })}
          </Box></DialogTitle><DialogContent><Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {i18nText("ui:m_ed1be4c9a20e3c5358b0")}
          </Typography><TextField autoFocus
            fullWidth
            label={i18nText("ui:m_644b24a0ac6e41056f71")}
            value={configName}
            onChange={(e) => setConfigName(e.target.value)}
            placeholder={i18nText("ui:m_191bcc7d1924a018f41d")}
            sx={{ mt: 1 }} /></DialogContent><DialogActions><Button data-learn={i18nText("ui:m_30b500389cb6f6b0f70c")} onClick={() => { setSaveAsDialogOpen(false); setConfigName(''); }}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button data-learn={i18nText("ui:m_c040f30b8e64174a1fa0")} onClick={handleSaveAs} variant="contained" disabled={saving || !configName.trim()}>{saving ? i18nText("ui:m_84d67cc7cab845a90ab6") : i18nText("ui:m_72bba814ee286eb80909")}</Button></DialogActions></Dialog>{/* Upload Configuration Dialog */}<Dialog open={uploadDialogOpen} onClose={() => setUploadDialogOpen(false)} maxWidth="sm" fullWidth fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">
            {i18nRichText("ui:m_1c4456febeef5343862e", { arg0: isMobile && (
              <IconButton onClick={() => setUploadDialogOpen(false)} edge="end"><CloseIcon /></IconButton>
            ) })}
          </Box></DialogTitle><DialogContent><Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {i18nText("ui:m_29b80fa006117b43ac69")}
          </Typography><input ref={fileInputRef}
            type="file"
            accept=".json"
            style={{ display: 'none' }}
            onChange={handleFileSelect} /><Box sx={{ mb: 2 }}><Button variant="outlined"
              startIcon={<UploadIcon />}
              onClick={() => fileInputRef.current?.click()}
              fullWidth>{uploadFile ? uploadFile.name : i18nText("ui:m_9ac57c26cadaa5202d1b")}</Button></Box><TextField fullWidth
            label={i18nText("ui:m_a262bf51ad10b00b4a79")}
            value={configName}
            onChange={(e) => setConfigName(e.target.value)}
            placeholder={i18nText("ui:m_469007e71ebc99694de5")}
            sx={{ mb: 2 }} /><FormControlLabel control={<Switch checked={applyOnUpload}
                onChange={(e) => setApplyOnUpload(e.target.checked)} />}
            label={i18nText("ui:m_1a0b1241db323d277dc6")} /></DialogContent><DialogActions><Button data-learn={i18nText("ui:m_de72e79baaa1cf5feaa8")} onClick={() => { setUploadDialogOpen(false); setUploadFile(null); setConfigName(''); }}>
            {i18nText("ui:m_0095547326bed510a824")}
          </Button><Button data-learn={i18nText("ui:m_3931a1780dc6ed72d7d0")} onClick={handleUpload} variant="contained" disabled={saving || !uploadFile}>{saving ? i18nText("ui:m_16b31c4d7a139eb0417b") : i18nText("ui:m_7f177ccee7151e5c9275")}</Button></DialogActions></Dialog></Layout>
  );
}
