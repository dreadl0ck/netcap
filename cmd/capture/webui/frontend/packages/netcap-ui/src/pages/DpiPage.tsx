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
  CircularProgress,
  Typography,
  Chip,
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
  Switch,
  FormControlLabel,
  Tooltip,
} from '@mui/material';
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import { useNetcapApi } from '../hooks';
import { parseSearchQuery, matchesSingleValue } from '../lib/tableSearch';

import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import InfoIcon from '@mui/icons-material/Info';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import SecurityIcon from '@mui/icons-material/Security';
import SearchInput from '../components/SearchInput';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { translate } from "../lib/i18n";
import { rawCode } from "../lib/i18n";





const LOCAL_STORAGE_KEY = 'netcap_dpi_enabled_modules';

export default function DPIPage() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { data: dpiInfo, error, isLoading } = useSWR('dpi', () => api.getDPIInfo(), {
    refreshInterval: 0, // Only fetch once
  });
  const [expandedModule, setExpandedModule] = useState<string | null>(null);
  const [searchQueries, setSearchQueries] = useState<Record<string, string>>({});
  const [enabledModules, setEnabledModules] = useState<Set<string>>(new Set());
  const [isSaving, setIsSaving] = useState(false);
  const [protocolPage, setProtocolPage] = useState(0);
  const [protocolRowsPerPage, setProtocolRowsPerPage] = useState(50);

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
      <Layout title={i18nText("removed:m_8f86b33449b0b497cfbd")}><Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh"><CircularProgress /></Box></Layout>
    );
  }

  if (error) {
    return (
      <Layout title={i18nText("removed:m_8f86b33449b0b497cfbd")}><Box><Alert severity="error"><AlertTitle>{i18nText("removed:m_1d3e2693cceb5b59e2bb")}</AlertTitle><Typography variant="body2">
              {i18nText("removed:m_735f2b59675107cdd613")}
            </Typography><Typography variant="body2" sx={{ mt: 1, fontFamily: 'monospace' }}>{error.toString()}</Typography></Alert></Box></Layout>
    );
  }

  if (!dpiInfo) {
    return (
      <Layout title={i18nText("removed:m_8f86b33449b0b497cfbd")}><Box><Alert severity="warning"><AlertTitle>{i18nText("removed:m_0ebcb5611b91830da53d")}</AlertTitle></Alert></Box></Layout>
    );
  }

  return (
    <Layout title={i18nText("removed:m_8f86b33449b0b497cfbd")}><Box sx={{ minWidth: 0 }}>{/* DPI Support Status */}<Grid container spacing={3} mb={4}><Grid item xs={12} md={6}><Card sx={{ height: '100%' }}><CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}><Box display="flex" alignItems="center" gap={2} mb={2}>{dpiInfo.hasSupport ? (
                    <CheckCircleIcon color="success" fontSize="large" />
                  ) : (
                    <CancelIcon color="error" fontSize="large" />
                  )}<Box><Typography variant="h6">{i18nText("removed:m_fbfa4ecea3349220457f")}</Typography><Chip label={dpiInfo.hasSupport ? i18nText("removed:m_0a86bacb5725a0c1f0b2") : i18nText("removed:m_7a36b8bba38afa4d0f3d")}
                      color={dpiInfo.hasSupport ? 'success' : 'error'}
                      size="small" /></Box></Box></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: '100%' }}><CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}><Box display="flex" alignItems="center" gap={2} mb={2}>{dpiInfo.enabled ? (
                    <CheckCircleIcon color="success" fontSize="large" />
                  ) : (
                    <InfoIcon color="warning" fontSize="large" />
                  )}<Box><Typography variant="h6">{i18nText("removed:m_fb0d9bfe51b50bd8cc66")}</Typography><Chip label={dpiInfo.enabled ? i18nText("removed:m_23052c4fec9eb3ac70e9") : i18nText("removed:m_5e51003ed903b62900ec")}
                      color={dpiInfo.enabled ? 'success' : 'default'}
                      size="small" /></Box></Box></CardContent></Card></Grid></Grid>{/* User DPI Preferences Summary */}{!status?.isServiceMode && (
          <Card sx={{ mb: 4 }}><CardContent><Typography variant="h6" gutterBottom>
                {i18nText("removed:m_f715477701eb7e61b801")}
              </Typography><Divider sx={{ mb: 2 }} /><Box><Typography variant="body2" color="text.secondary" gutterBottom>
                  {i18nText("removed:m_a2870cfd9250c7da6eb7")}
                </Typography><Box display="flex" flexWrap="wrap" gap={1} mt={1} alignItems="center">{enabledModules.size > 0 ? (
                    <>{Array.from(enabledModules).map((module) => (
                        <Chip key={module}
                          label={module}
                          color="primary"
                          variant="filled"
                          size="medium"
                          onDelete={() => handleModuleToggle(module)} />
                      ))}{isSaving && (
                        <Chip label={i18nText("removed:m_84d67cc7cab845a90ab6")}
                          size="small"
                          variant="outlined"
                          sx={{ ml: 1 }} />
                      )}</>
                  ) : (
                    <Alert severity="warning" sx={{ width: '100%' }}><Typography variant="body2">
                        {i18nText("removed:m_18c5a7fcf891c86bab10")}
                      </Typography></Alert>
                  )}</Box><Alert severity="info" sx={{ mt: 2 }}><Typography variant="body2">
                    {i18nText("removed:m_d42d8ce4d90a82b8f2fd")}
                  </Typography></Alert></Box></CardContent></Card>
        )}{/* Library Versions */}<Card sx={{ mb: 4 }}><CardContent><Typography variant="h6" gutterBottom>
              {i18nText("removed:m_96574762d51772a76e31")}
            </Typography><Divider sx={{ mb: 2 }} /><Grid container spacing={3}><Grid item xs={12} md={4}><Paper data-learn={i18nText("removed:m_07c6c81f7ea59e4f154e")}
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
                  onClick={() => window.open('https://github.com/ntop/nDPI', '_blank', 'noopener,noreferrer')}><Box display="flex" justifyContent="space-between" alignItems="start"><Box flex={1}><Typography variant="body2" color="text.secondary" gutterBottom>
                        {i18nText("removed:m_494157c42e8d51ff6c1c")}
                      </Typography><Typography variant="h6" sx={{ fontFamily: 'monospace' }}>{dpiInfo.ndpiVersion || i18nText("removed:m_8dc598ebf1e055830140")}</Typography><Typography variant="caption" color="text.secondary">
                        {i18nText("removed:m_f7d1c7b7a6edaa1778dd")}
                      </Typography></Box><OpenInNewIcon fontSize="small" sx={{ color: 'text.secondary', ml: 1 }} /></Box></Paper></Grid><Grid item xs={12} md={4}><Paper data-learn={i18nText("removed:m_31e14393722ebdacd3f8")}
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
                  onClick={() => window.open('https://github.com/wanduow/libprotoident', '_blank', 'noopener,noreferrer')}><Box display="flex" justifyContent="space-between" alignItems="start"><Box flex={1}><Typography variant="body2" color="text.secondary" gutterBottom>
                        {i18nText("removed:m_c6e32fad4229f9e9bdea")}
                      </Typography><Typography variant="h6" sx={{ fontFamily: 'monospace' }}>{dpiInfo.libprotoidentVersion || i18nText("removed:m_8dc598ebf1e055830140")}</Typography><Typography variant="caption" color="text.secondary">
                        {i18nText("removed:m_bfe005ea50b7bac43eb2")}
                      </Typography></Box><OpenInNewIcon fontSize="small" sx={{ color: 'text.secondary', ml: 1 }} /></Box></Paper></Grid><Grid item xs={12} md={4}><Paper data-learn={i18nText("removed:m_506c7d3bd491dcc8aa87")}
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
                  onClick={() => window.open('https://github.com/dreadl0ck/go-dpi', '_blank', 'noopener,noreferrer')}><Box display="flex" justifyContent="space-between" alignItems="start"><Box flex={1}><Typography variant="body2" color="text.secondary" gutterBottom>
                        {i18nText("removed:m_1a5bd81199b50e59425a")}
                      </Typography><Typography variant="h6" sx={{ fontFamily: 'monospace' }}>{dpiInfo.goDpiVersion || i18nText("removed:m_8dc598ebf1e055830140")}</Typography><Typography variant="caption" color="text.secondary">
                        {i18nText("removed:m_2baea7a2685de392d91f")}
                      </Typography></Box><OpenInNewIcon fontSize="small" sx={{ color: 'text.secondary', ml: 1 }} /></Box></Paper></Grid></Grid></CardContent></Card>{/* Active Modules */}<Card sx={{ mb: 4 }}><CardContent><Typography variant="h6" gutterBottom>
              {i18nText("removed:m_a3e055f44fee93535499")}
            </Typography><Divider sx={{ mb: 2 }} /><Grid container spacing={3}><Grid item xs={12}><Typography variant="subtitle2" gutterBottom sx={{ mb: 2 }}>
                  {i18nText("removed:m_36dfaa4777627fc334ea")}
                </Typography>{dpiInfo.availableModules.map((module) => {
                  const isActive = dpiInfo.activeModules.includes(module);
                  const isEnabledInSession = enabledModules.has(module);
                  const protocols = dpiInfo.moduleProtocols?.[module] || [];
                  
                  return (
                    <Accordion key={module}
                      expanded={expandedModule === module}
                      onChange={() => {
                        setExpandedModule(expandedModule === module ? null : module);
                        setProtocolPage(0);
                      }}
                      sx={{ 
                        mb: 1,
                        opacity: isEnabledInSession ? 1 : 0.6,
                        transition: 'opacity 0.3s',
                      }}><AccordionSummary expandIcon={<ExpandMoreIcon />}
                        sx={{
                          bgcolor: isEnabledInSession ? 'action.selected' : 'background.default',
                          '&:hover': { bgcolor: 'action.hover' },
                        }}><Box display="flex" alignItems="center" gap={2} width="100%"><Typography variant="h6" sx={{ fontFamily: 'monospace', flex: 1 }}>{module}</Typography><Box display="flex" alignItems="center" gap={1}><Chip label={isActive ? i18nText("removed:m_dfbe2b428afc27e67adf") : i18nText("removed:m_b6f62be183440dfdc4c4")}
                              color={isActive ? 'success' : 'default'}
                              size="small"
                              variant="outlined" /><Chip label={isEnabledInSession ? i18nText("removed:m_23052c4fec9eb3ac70e9") : i18nText("removed:m_5e51003ed903b62900ec")}
                              color={isEnabledInSession ? 'success' : 'default'}
                              size="small" />{protocols.length > 0 && (
                              <Chip label={i18nText("removed:m_febbab2932bfc6ed2abe", { arg0: protocols.length })}
                                size="small"
                                variant="outlined" />
                            )}<Tooltip title={isEnabledInSession ? i18nText("removed:m_c22665957b5c5ddbabc6", { arg0: module }) : i18nText("removed:m_71425c1fcfc3f949524c", { arg0: module })}><FormControlLabel data-learn={i18nText("removed:m_ad810656438ca0534cee")}
                                control={<Switch checked={isEnabledInSession}
                                    onChange={(e) => {
                                      e.stopPropagation();
                                      handleModuleToggle(module);
                                    }}
                                    onClick={(e) => e.stopPropagation()}
                                    color="primary"
                                    disabled={status?.isServiceMode} />}
                                label={""}
                                sx={{ m: 0 }} /></Tooltip></Box></Box></AccordionSummary><AccordionDetails><Typography variant="body2" color="text.secondary" paragraph>{getModuleDescription(module)}</Typography>{protocols.length > 0 ? (
                          <Box><Box sx={{ mb: 2 }}><SearchInput value={searchQueries[module] || ''}
                                onChange={(value) => setSearchQueries({ ...searchQueries, [module]: value })}
                                placeholder={i18nText("removed:m_80a54da632e66d1e7c87")}
                                learnHint={translate("removed:m_fa8508127760d7930c99")}
                                sx={{ width: '100%' }} /></Box>{(() => {
                              const searchQuery = searchQueries[module] || '';
                              const searchTerms = parseSearchQuery(searchQuery);
                              const filteredProtocols = protocols.filter(protocol =>
                                matchesSingleValue(protocol, searchTerms)
                              );
                              const paginatedProtocols = filteredProtocols.slice(
                                protocolPage * protocolRowsPerPage,
                                protocolPage * protocolRowsPerPage + protocolRowsPerPage
                              );

                              return (
                                <><Typography variant="subtitle2" gutterBottom sx={{ mb: 1 }}>
                                    {i18nRichText("removed:m_9bcfa1f9913d7222cbea", { arg0: filteredProtocols.length, arg1: searchQuery && i18nText("removed:m_b800076b72d4cbbd7d38", { arg0: protocols.length }) })}
                                  </Typography>{filteredProtocols.length > 0 ? (
                                    <ResponsiveDataView data={paginatedProtocols}
                                      totalCount={filteredProtocols.length}
                                      page={protocolPage}
                                      rowsPerPage={protocolRowsPerPage}
                                      onPageChange={(_e, newPage) => setProtocolPage(newPage)}
                                      onRowsPerPageChange={(e) => {
                                        setProtocolRowsPerPage(parseInt(e.target.value, 10));
                                        setProtocolPage(0);
                                      }}
                                      rowsPerPageOptions={[25, 50, 100]}
                                      renderCard={(protocol) => (
                                        <Card variant="outlined"><CardContent sx={{ py: 1, '&:last-child': { pb: 1 } }}><Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>{protocol}</Typography><Box display="flex" gap={1} mt={0.5} alignItems="center"><Chip label={module} size="small" variant="outlined" sx={{ fontSize: '0.7rem' }} /><MuiLink href={getProtocolSourceUrl(module, protocol)}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                onClick={(e) => e.stopPropagation()}
                                                sx={{
                                                  display: 'inline-flex',
                                                  alignItems: 'center',
                                                  gap: 0.5,
                                                  fontSize: '0.75rem',
                                                  textDecoration: 'none',
                                                  '&:hover': { textDecoration: 'underline' }
                                                }}>
                                                {i18nText("removed:m_4113167561ccea5b6c6b")}
                                                <OpenInNewIcon sx={{ fontSize: 14 }} /></MuiLink></Box></CardContent></Card>
                                      )}
                                      desktopTable={<TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 400 }}><Table size="small" stickyHeader><TableHead><TableRow><TableCell sx={{ fontWeight: 600, width: 80 }}>#</TableCell><TableCell sx={{ fontWeight: 600 }}>{i18nText("removed:m_cd1fc0e505d8ef57579a")}</TableCell><TableCell sx={{ fontWeight: 600, width: 100, textAlign: 'center' }}>{i18nText("removed:m_4113167561ccea5b6c6b")}</TableCell></TableRow></TableHead><TableBody>{paginatedProtocols.map((protocol) => (
                                            <TableRow key={protocol}
                                              sx={{ '&:last-child td': { border: 0 } }}><TableCell sx={{ color: 'text.secondary' }}>{protocols.indexOf(protocol) + 1}</TableCell><TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>{protocol}</TableCell><TableCell sx={{ textAlign: 'center' }}><MuiLink href={getProtocolSourceUrl(module, protocol)}
                                                  target="_blank"
                                                  rel="noopener noreferrer"
                                                  onClick={(e) => e.stopPropagation()}
                                                  sx={{
                                                    display: 'inline-flex',
                                                    alignItems: 'center',
                                                    gap: 0.5,
                                                    textDecoration: 'none',
                                                    '&:hover': { textDecoration: 'underline' }
                                                  }}>
                                                  {i18nText("removed:m_0184294accd8324999a3")}
                                                  <OpenInNewIcon fontSize="small" /></MuiLink></TableCell></TableRow>
                                          ))}</TableBody></Table></TableContainer>} />
                                  ) : (
                                    <Alert severity="info"><Typography variant="body2">
                                        {i18nRichText("removed:m_8f6bf90e289e00b79bbc", { arg0: searchQueries[module] })}
                                      </Typography></Alert>
                                  )}</>
                              );
                            })()}</Box>
                        ) : (
                          <Alert severity="info" sx={{ mt: 2 }}><Typography variant="body2">
                              {i18nRichText("removed:m_c82f5272b34aba19b72e", { arg0: !isActive && i18nText("removed:m_7f879f32044f1c3b98be") })}
                            </Typography></Alert>
                        )}</AccordionDetails></Accordion>
                  );
                })}</Grid></Grid></CardContent></Card>{/* Supported Protocols */}<Card><CardContent><Typography variant="h6" gutterBottom>
              {i18nText("removed:m_7efcafbd42440b54f742")}
            </Typography><Divider sx={{ mb: 2 }} /><Grid container spacing={3}><Grid item xs={12} md={6}><Paper elevation={0} sx={{ p: 3, bgcolor: 'background.default' }}><Box display="flex" alignItems="center" gap={2} mb={2}><SecurityIcon color="primary" /><Typography variant="h6">nDPI</Typography></Box><Typography variant="body2" color="text.secondary" paragraph>
                    {i18nText("removed:m_18069bb0552abe1484bd")}
                  </Typography><MuiLink data-learn={i18nText("removed:m_69246c35e5f81193bf3b")}
                    href={dpiInfo.ndpiProtocolsUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    {i18nText("removed:m_279cf062602af182b58f")}
                    <OpenInNewIcon fontSize="small" /></MuiLink></Paper></Grid><Grid item xs={12} md={6}><Paper elevation={0} sx={{ p: 3, bgcolor: 'background.default' }}><Box display="flex" alignItems="center" gap={2} mb={2}><SecurityIcon color="primary" /><Typography variant="h6">{i18nText("removed:m_9a5d58cd4ac8be7a256f")}</Typography></Box><Typography variant="body2" color="text.secondary" paragraph>
                    {i18nText("removed:m_cdbcb2c11927401b6720")}
                  </Typography><MuiLink data-learn={i18nText("removed:m_394c5778ace2348ea7b3")}
                    href={dpiInfo.libprotoidentProtocolsUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    {i18nText("removed:m_279cf062602af182b58f")}
                    <OpenInNewIcon fontSize="small" /></MuiLink></Paper></Grid><Grid item xs={12}><Alert severity="info"><Typography variant="body2">
                    {((__codeValues: Record<string, unknown>) => i18nRichText("removed:m_f0313859baa87752a78d", { ...__codeValues, code0: rawCode("Applications", __codeValues) }))({ tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong>, tag1: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong>, tag2: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong>, tag3: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong>, tag4: (chunks: import('react').ReactNode[]) => <code>{chunks}</code> })}
                  </Typography></Alert></Grid></Grid></CardContent></Card></Box></Layout>
  );
}

function getModuleDescription(module: string): string {
  switch (module) {
    case 'ndpi':
      return translate("removed:m_f1a29c9b0860909e0655");
    case 'lpi':
      return translate("removed:m_fab159ae980e89ee717c");
    case 'go':
      return translate("removed:m_5382a7c4645b83e1e1ca");
    default:
      return translate("removed:m_a2e6429e413f55e38cc8");
  }
}

// Helper function to check if a protocol is likely implemented via IP lists
function isLikelyIPListProtocol(protocol: string): boolean {
  const ipListProtocols = new Set([
    // Cloud providers with IP-based detection (not in ndpi_content_match.c.inc)
    'MICROSOFT_AZURE',
    'AWS_CLOUDFRONT', 'AWS_API_GATEWAY', 'AWS_COGNITO',
    'AWS_DYNAMODB', 'AWS_KINESIS', 'AWS_EC2', 'AWS_S3', 'AWS_EMR',
    'GOOGLE_CLOUD',
    'DIGITALOCEAN', 'HUAWEI_CLOUD',
    'YANDEX_CLOUD',
    
    // VPN/Security services that use IP lists (not domain-based)
    'TOR', 'OPENVPN',
  ]);
  
  return ipListProtocols.has(protocol.toUpperCase());
}

// Helper function to check if a protocol is likely detected via hardcoded IPs/domains
// in ndpi_content_match.c.inc file
function isLikelyContentMatchProtocol(protocol: string): boolean {
  const contentMatchProtocols = new Set([
    // Services detected via hardcoded IPs/domains in ndpi_content_match.c.inc
    'OCS',         // Orange Cinéma Séries
    'TEAMVIEWER',  // TeamViewer (many hardcoded IPs)
    
    // Advertising/tracking networks (detected via domain matching)
    'TRACKER_ADS', // Generic ad tracking
    
    // Streaming services (detected via domain matching in ndpi_content_match.c.inc)
    'SOUNDCLOUD',   // soundcloud.com
    'SPOTIFY',      // spotify.com
    'PANDORA',      // pandora.com
    'TIDAL',        // tidal.com
    'IHEARTRADIO',  // iheartradio.com
    'LASTFM',       // last.fm
    'DEEZER',       // deezer.com
    'NETFLIX',      // netflix.com
    'HULU',         // hulu.com
    'DISNEYPLUS',   // disneyplus.com
    'HBO',          // hbo.com
    'PARAMOUNTPLUS',// paramountplus.com
    'YOUTUBE',      // youtube.com
    'YOUTUBE_UPLOAD', // youtube.com
    'TWITCH',       // twitch.tv
    'VIMEO',        // vimeo.com
    
    // Social media (detected via domain matching in ndpi_content_match.c.inc)
    'FACEBOOK',     // facebook.com
    'FACEBOOK_MESSENGER', // messenger.com
    'FACEBOOK_VOIP',
    'FACEBOOK_REEL_STORY',
    'INSTAGRAM',    // instagram.com
    'TWITTER',      // twitter.com, x.com
    'LINKEDIN',     // linkedin.com
    'REDDIT',       // reddit.com
    'PINTEREST',    // pinterest.com
    'TIKTOK',       // tiktok.com
    'SNAPCHAT',     // snapchat.com
    'SNAPCHAT_CALL',
    'THREADS',      // threads.net
    'TUMBLR',       // tumblr.com
    'VK',           // vk.com
    'MASTODON',     // mastodon instances
    
    // Enterprise/Corporate (detected via domain matching in ndpi_content_match.c.inc)
    'SLACK',        // slack.com
    'MSTEAMS',      // teams.microsoft.com
    'MSTEAMS_CALL',
    'ZOOM',         // zoom.us
    'WEBEX',        // webex.com
    'GOTO',         // goto.com
    'FUZE',         // fuze.com
    
    // Cloud services (detected via domain matching in ndpi_content_match.c.inc)
    'MICROSOFT',    // microsoft.com
    'MICROSOFT_365', // office.com, outlook.com
    'MS_OUTLOOK',   // outlook.com
    'MS_ONE_DRIVE', // onedrive.com
    'GOOGLE',       // google.com
    'GOOGLE_SERVICES', // googleapis.com
    'GOOGLE_DOCS',  // docs.google.com
    'GOOGLE_DRIVE', // drive.google.com
    'GOOGLE_MAPS',  // maps.google.com
    'GOOGLE_MEET',  // meet.google.com
    'GOOGLE_CHAT',  // chat.google.com
    'GOOGLE_CALL',
    'GOOGLE_CLASSROOM', // classroom.google.com
    'GMAIL',        // gmail.com
    'APPLE',        // apple.com
    'APPLE_ICLOUD', // icloud.com
    'APPLE_ITUNES', // itunes.apple.com
    'APPLE_SIRI',   // siri.apple.com
    'APPLESTORE',   // apps.apple.com
    'APPLETVPLUS',  // tv.apple.com
    
    // VoIP/calling services (detected via domain/IP matching in ndpi_content_match.c.inc)
    'TRUPHONE',
    'VIBER_VOIP',   // viber.com
    'TELEGRAM_VOIP', // telegram.org
    'WHATSAPP_CALL', // whatsapp.com
    'WHATSAPP_FILES',
    'SIGNAL_VOIP',  // signal.org
    'KAKAOTALK_VOICE', // kakao.com
    'WECHAT',       // wechat.com
    
    // Gaming platforms (detected via domain matching in ndpi_content_match.c.inc)
    'PLAYSTATION',  // playstation.com
    'XBOX',         // xbox.com
    'NINTENDO',     // nintendo.com
    'EPICGAMES',    // epicgames.com
    'VALVE_SDR',    // steampowered.com
    'RIOTGAMES',    // riotgames.com
    'ELECTRONICARTS', // ea.com
    'ACTIVISION',   // activision.com
    'BLIZZARD',     // blizzard.com
    'ROCKSTAR_GAMES', // rockstargames.com
    
    // CDN/Infrastructure (detected via domain matching in ndpi_content_match.c.inc)
    'CLOUDFLARE',   // cloudflare.com
    'CLOUDFLARE_WARP',
    'AKAMAI',       // akamai.com
    'EDGECAST',     // edgecast.com
    'CACHEFLY',     // cachefly.com
    
    // Chinese services (detected via domain matching in ndpi_content_match.c.inc)
    'TENCENT',      // tencent.com
    'TENCENTVIDEO', // v.qq.com
    'TENCENTGAMES',
    'ALIBABA',      // alibaba.com
    'ALICLOUD',     // aliyun.com
    'TAOBAO',       // taobao.com
    'KAKAOTALK',    // kakao.com
    'NAVER',        // naver.com
    
    // VPN services (detected via domain matching in ndpi_content_match.c.inc)
    'NORDVPN',      // nordvpn.com
    'PROTONVPN',    // protonvpn.com
    'MULLVAD',      // mullvad.net
    'SURFSHARK',    // surfshark.com
    'TUNNELBEAR',   // tunnelbear.com
    'OPERA_VPN',    // opera.com
    'PSIPHON',      // psiphon.ca
    'WINDSCRIBE',   // windscribe.com
    'CACTUSVPN',    // cactusvpn.com
    'HOTSPOT_SHIELD', // hotspotshield.com
    'ULTRASURF',    // ultrasurf.us
    
    // Other web services (detected via domain matching in ndpi_content_match.c.inc)
    'GITHUB',       // github.com
    'GITLAB',       // gitlab.com
    'WIKIPEDIA',    // wikipedia.org
    'MOZILLA',      // mozilla.org
    'YAHOO',        // yahoo.com
    'EBAY',         // ebay.com
    'CNN',          // cnn.com
    'ESPN',         // espn.com
    
    // Networking equipment (detected via domain matching in ndpi_content_match.c.inc)
    'UBIQUITI',     // ubiquiti.com, ui.com
  ]);
  
  return contentMatchProtocols.has(protocol.toUpperCase());
}

function getProtocolSourceUrl(module: string, protocol: string): string {
  const protocolLower = protocol.toLowerCase();
  
  switch (module) {
    case 'go':
      return `https://github.com/dreadl0ck/go-dpi/blob/master/modules/classifiers/${protocolLower}.go`;
      
    case 'ndpi':
      // Special case: Salesforce has its own dedicated IP list file
      if (protocol.toUpperCase() === 'SALESFORCE') {
        return `https://github.com/ntop/nDPI/blob/dev/lists/protocols/266_salesforce.list`;
      }
      // For protocols detected via hardcoded IPs/domains in ndpi_content_match.c.inc
      if (isLikelyContentMatchProtocol(protocol)) {
        return `https://github.com/ntop/nDPI/blob/dev/src/lib/ndpi_content_match.c.inc`;
      }
      // For IP-list based protocols, link to the lists directory where they can search
      if (isLikelyIPListProtocol(protocol)) {
        return `https://github.com/ntop/nDPI/tree/dev/lists/protocols`;
      }
      // Otherwise, link to the traditional C implementation
      return `https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/${protocolLower}.c`;
      
    case 'lpi':
      // UDP protocols are in a separate directory
      if (protocol.toUpperCase().startsWith('UDP_')) {
        return `https://github.com/LibtraceTeam/libprotoident/blob/master/lib/udp/lpi_${protocolLower}.cc`;
      }
      // TCP protocols
      return `https://github.com/LibtraceTeam/libprotoident/blob/master/lib/tcp/lpi_${protocolLower}.cc`;
      
    default:
      return '#';
  }
}

