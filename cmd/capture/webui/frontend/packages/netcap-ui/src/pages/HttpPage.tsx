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

import { useState, useMemo, useCallback, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Typography,
  Alert,
  Collapse,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Http as HttpIcon,
  Download as DownloadIcon,
  Cable as CableIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Error as ErrorIcon,
  Shield as ShieldIcon,
  Lock as LockIcon,
  VpnKey as VpnKeyIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import ConversationModal from '../components/ConversationModal';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';
import { HTTPReassemblyNotice } from '../components/RecordSemantics';

import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, formatNumber as i18nNumber, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";




interface HTTPSummary {
  timestampNs?: string;
  reassemblyStatus?: string;
  timestamp: number;
  proto: string;
  method: string;
  host: string;
  url: string;
  userAgent: string;
  referer: string;
  reqContentLength: number;
  resContentLength: number;
  contentType: string;
  statusCode: number;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  flow: string;
  reqContentEncoding: string;
  resContentEncoding: string;
  serverName: string;
  resContentType: string;
  contentTypeDetected: string;
  resContentTypeDetected: string;
  doneAfter: number;
  dnsDoneAfter: number;
  firstByteAfter: number;
  tlsDoneAfter: number;
  requestHeader: { [key: string]: string };
  responseHeader: { [key: string]: string };
  parameters: { [key: string]: string };
  // Security headers
  strictTransportSecurity: string;
  contentSecurityPolicy: string;
  xContentTypeOptions: string;
  xFrameOptions: string;
  xXSSProtection: string;
  referrerPolicy: string;
  accessControlAllowOrigin: string;
  hasServerTiming: boolean;
  // Authentication and server info
  authorizationType: string;
  xForwardedFor: string;
  xRealIP: string;
  server: string;
  xPoweredBy: string;
  // JA4H fingerprinting
  ja4h: string;
  ja4hDescription: string;
  // Community ID for cross-tool correlation
  communityId: string;
}

interface HTTPResponse {
  http: HTTPSummary[];
  totalCount: number;
}

interface SecretSummary {
  timestamp: number;
  service: string;
  flow: string;
  user: string;
  password: string;
  communityId: string;
}

interface SecretsResponse {
  secrets: SecretSummary[];
  totalCount: number;
}

type HTTPSortField = 'timestamp' | 'method' | 'host' | 'statusCode' | 'size';
type SortOrder = 'asc' | 'desc';
type HTTPFilterType = 'all' | 'errors' | 'missingSecurityHeaders' | 'hasAuth';

export default function HTTPPage() {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<HTTPFilterType>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<HTTPSortField>('timestamp');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();
  const [conversationModalOpen, setConversationModalOpen] = useState(false);
  const [selectedHTTP, setSelectedHTTP] = useState<HTTPSummary | null>(null);

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Initialize search query from URL parameter
  useEffect(() => {
    if (router.isReady && router.query.search) {
      setSearchQuery(router.query.search as string);
    }
  }, [router.isReady, router.query.search]);

  // Fetch HTTP data
  const { data: httpData, error, mutate } = useSWR<HTTPResponse>(
    'http',
    () => fetch(`${getBackendUrl()}/api/http`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  // Fetch credentials to check which HTTP requests have secrets
  const { data: credentialsData, mutate: mutateSecrets } = useSWR<SecretsResponse>(
    'secrets',
    () => fetch(`${getBackendUrl()}/api/secrets`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const httpRecords = httpData?.http || [];
  const totalCount = httpData?.totalCount || 0;

  // Build a set of community IDs that have credentials for quick lookup
  const credentialCommunityIds = useMemo(() => {
    const ids = new Set<string>();
    if (credentialsData?.secrets) {
      for (const cred of credentialsData.secrets) {
        if (cred.communityId) {
          ids.add(cred.communityId);
        }
      }
    }
    return ids;
  }, [credentialsData]);

  // Helper function to check if an HTTP request has credentials
  const hasSecrets = useCallback((http: HTTPSummary): boolean => {
    return http.communityId ? credentialCommunityIds.has(http.communityId) : false;
  }, [credentialCommunityIds]);

  // Handle sort column click
  const handleSort = (field: HTTPSortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0);
  };

  // Apply filters and sorting
  const filteredHTTP = useMemo(() => {
    let filtered = httpRecords;

    // Apply Community ID filter first (if active)
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(h => 
        h.communityId && selectedCommunityIDs.has(h.communityId)
      );
    }

    // Apply HTTP filter type
    if (filterType !== 'all') {
      filtered = filtered.filter(http => {
        switch (filterType) {
          case 'errors':
            return http.statusCode >= 400;
          case 'missingSecurityHeaders':
            // Check if ANY of the important security headers are missing
            return !http.strictTransportSecurity && !http.contentSecurityPolicy && 
                   !http.xFrameOptions && !http.xContentTypeOptions;
          case 'hasAuth':
            return Boolean(http.authorizationType);
          default:
            return true;
        }
      });
    }

    // Apply search filter
    if (searchQuery) {
      // Handle special filters for threat hunting
      const queryLower = searchQuery.toLowerCase();
      
      if (queryLower === 'errors') {
        // Filter for error status codes (4xx/5xx)
        filtered = filtered.filter(h => h.statusCode >= 400);
      } else if (queryLower === 'ip-host') {
        // Filter for requests to IP addresses instead of domains
        filtered = filtered.filter(h => {
          const host = h.host || '';
          // Check if host is an IP address (simple regex)
          return /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(host);
        });
      } else {
        const searchTerms = searchQuery
          .split(/[,\s]+/)
          .map(term => term.trim())
          .filter(term => term.length > 0);
        
        filtered = filtered.filter(h => {
          return searchTerms.some(query => {
            const termLower = query.toLowerCase();
            return (
              h.srcIP.toLowerCase().includes(termLower) ||
              h.dstIP.toLowerCase().includes(termLower) ||
              (h.host || '').toLowerCase().includes(termLower) ||
              (h.url || '').toLowerCase().includes(termLower) ||
              (h.method || '').toLowerCase().includes(termLower) ||
              (h.userAgent || '').toLowerCase().includes(termLower) ||
              (h.statusCode.toString()).includes(query) ||
              // Also search in request/response headers for Authorization etc.
              Object.keys(h.requestHeader || {}).some(k => k.toLowerCase().includes(termLower)) ||
              Object.values(h.requestHeader || {}).some(v => v.toLowerCase().includes(termLower))
            );
          });
        });
      }
    }

    // Apply sorting with stable secondary sort by timestamp and communityId
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'timestamp':
          comparison = a.timestamp - b.timestamp;
          break;
        case 'method':
          comparison = (a.method || '').localeCompare(b.method || '');
          break;
        case 'host':
          comparison = (a.host || '').localeCompare(b.host || '');
          break;
        case 'statusCode':
          comparison = a.statusCode - b.statusCode;
          break;
        case 'size':
          comparison = (a.reqContentLength + a.resContentLength) - (b.reqContentLength + b.resContentLength);
          break;
      }
      // Stable secondary sort by timestamp then communityId for consistent ordering
      if (comparison === 0) {
        comparison = a.timestamp - b.timestamp;
        if (comparison === 0) {
          comparison = (a.communityId || '').localeCompare(b.communityId || '');
        }
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [httpRecords, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs, filterType]);

  // Paginate HTTP records
  const paginatedHTTP = filteredHTTP.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedHTTP.map((http, idx) => `${http.srcIP}-${http.dstIP}-${http.timestamp}-${idx}`),
    [paginatedHTTP]
  );

  // Enable keyboard navigation for detail views (UP/DOWN arrows)
  useTableKeyboardNavigation(expandedRow, rowKeys, setExpandedRow);

  const handleChangePage = (_event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleRefresh = useCallback(() => {
    mutate();
    mutateSecrets();
    setChartRefreshKey(prev => prev + 1);
  }, [mutate, mutateSecrets]);

  const handleFileChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      
      await mutateStatus();
      await mutate();
      await globalMutate('status');
      
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      setChartRefreshKey(prev => prev + 1);
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert(i18nText("ui:m_7ab800e4d59917b1d34c"));
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate, __uiLocale]);

  const handleRowClick = useCallback((key: string) => {
    setExpandedRow(prev => prev === key ? null : key);
  }, []);

  const handleViewConversation = useCallback((http: HTTPSummary) => {
    setSelectedHTTP(http);
    setConversationModalOpen(true);
  }, []);

  const handleCloseConversationModal = useCallback(() => {
    setConversationModalOpen(false);
    setSelectedHTTP(null);
  }, []);

  const handleDownloadPCAP = useCallback(async (http: HTTPSummary) => {
    try {
      const params = new URLSearchParams({
        srcIP: http.srcIP,
        dstIP: http.dstIP,
        srcPort: String(http.srcPort),
        dstPort: String(http.dstPort),
        protocol: 'TCP',
      });
      const downloadUrl = `${getBackendUrl()}/api/http/download-pcap?${params}`;
      
      const response = await fetch(downloadUrl);
      
      if (!response.ok) {
        const errorText = await response.text();
        alert(i18nText("ui:m_c63b36b2fde6b1f5d69c", { arg0: errorText }));
        return;
      }
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      
      const a = document.createElement('a');
      a.href = url;
      a.download = `http_${http.srcIP}_${http.dstIP}_${http.method}_${http.statusCode}.pcap`;
      document.body.appendChild(a);
      a.click();
      
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
      alert(i18nText("ui:m_c63b36b2fde6b1f5d69c", { arg0: error }));
    }
  }, [__uiLocale]);

  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_b66515a7437127928b61")} />
  );

  // Calculate statistics
  const stats = useMemo(() => ({
    statusErrors: httpRecords.filter(h => h.statusCode >= 400).length,
    missingSecurityHeaders: httpRecords.filter(h => 
      !h.strictTransportSecurity && !h.contentSecurityPolicy && 
      !h.xFrameOptions && !h.xContentTypeOptions
    ).length,
    hasAuthCount: httpRecords.filter(h => Boolean(h.authorizationType)).length,
  }), [httpRecords]);

  // Get status code color
  const getStatusCodeColor = (code: number) => {
    if (code >= 200 && code < 300) return 'success';
    if (code >= 300 && code < 400) return 'info';
    if (code >= 400 && code < 500) return 'warning';
    if (code >= 500) return 'error';
    return 'default';
  };

  if (error) {
    return (
      <Layout title={"HTTP"} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_7eadb535f403cd92aaa7", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={"HTTP"} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
            exclusive
            onChange={(_e, newValue) => {
              if (newValue !== null) {
                setViewMode(newValue);
              }
            }}
            size="small"
            data-learn={i18nText("ui:m_4f46daf2537ea500313b")}><ToggleButton value="table"><TableChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              {i18nRichText("ui:m_b65e2110701259d5e7dc", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
            </ToggleButton><ToggleButton value="chart"><BarChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              {i18nRichText("ui:m_da105eec6af81877e667", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
            </ToggleButton></ToggleButtonGroup></Box>{/* Summary Cards - Clickable Security Filters - Only show in table mode */}{viewMode === 'table' && (
        <StatBoxGrid><StatBox icon={<HttpIcon color="primary" />}
            label={i18nText("ui:m_d6075543365b498d5c08")}
            value={totalCount}
            onClick={() => { setFilterType('all'); setPage(0); }}
            isActive={filterType === 'all'}
            activeColor="primary"
            learnHint={translate("ui:m_3603d68dadd01a7bd7ef")} /><StatBox icon={<ErrorIcon color="error" />}
            label={i18nText("ui:m_2d40589104e90eeba42e")}
            value={stats.statusErrors}
            onClick={() => { setFilterType('errors'); setPage(0); }}
            isActive={filterType === 'errors'}
            activeColor="error"
            learnHint={translate("ui:m_9b8b016d042212e37195")} /><StatBox icon={<ShieldIcon color="warning" />}
            label={i18nText("ui:m_54533e5e816000d4e290")}
            value={stats.missingSecurityHeaders}
            onClick={() => { setFilterType('missingSecurityHeaders'); setPage(0); }}
            isActive={filterType === 'missingSecurityHeaders'}
            activeColor="warning"
            learnHint={translate("ui:m_d26c11a0940f9dbb367a")} /><StatBox icon={<LockIcon color="info" />}
            label={i18nText("ui:m_25d77f952ecc073bffe0")}
            value={stats.hasAuthCount}
            onClick={() => { setFilterType('hasAuth'); setPage(0); }}
            isActive={filterType === 'hasAuth'}
            activeColor="info"
            learnHint={translate("ui:m_0e95c061718a66443b9d")} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_adfbb23273127fe61e8a")}
                  key={`top-hosts-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/top-hosts?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_64c1baac22f62147ad48")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_c204cf4d258567a0d78f")}
                  key={`status-codes-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/status-codes?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_73205499ce6d2b6cfdfb")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_e57a9af6dfbbd7c10b71")}
                  key={`methods-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/methods?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_efaa696fba884833bdcb")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_fd4a82208acb13e714f7")}
                  key={`content-types-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/content-types?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_a5dbd36cd287cf3bd07f")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_5e75165203fb3943b6b7")}
            learnHint={translate("ui:m_f575e1f6fa2abba00d5a")} /><Button data-learn={i18nText("ui:m_58efd325679666102ff4")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{(searchQuery || filterType !== 'all') ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_37869901e6712bf04af1", { arg0: filteredHTTP.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Quick Filters for HTTP Threat Hunting */}<Box sx={{ mb: 2 }} data-learn={i18nText("ui:m_70dc7a715e784c626437")}><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            {i18nText("ui:m_d1ed1037b4c89f1fda3a")}
          </Typography><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}><Chip label={i18nText("ui:m_5063013991b2a87d0f60")}
              size="small"
              color={searchQuery.includes('4') || searchQuery.includes('5') ? 'error' : 'default'}
              variant={searchQuery.includes('400') || searchQuery.includes('500') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev === 'errors' ? '' : 'errors');
                setPage(0);
              }}
              title={i18nText("ui:m_0a20d58440f2a746de33")} /><Chip label={i18nText("ui:m_5f0cf0654a395848f8aa")}
              size="small"
              color={searchQuery.toLowerCase() === 'post' ? 'warning' : 'default'}
              variant={searchQuery.toLowerCase() === 'post' ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.toLowerCase() === 'post' ? '' : 'POST');
                setPage(0);
              }}
              title={i18nText("ui:m_5f1a2d78d3d95e998c2b")} /><Chip label={i18nText("ui:m_58b8b229044d309e46f7")}
              size="small"
              color={searchQuery.toLowerCase().includes('put') || searchQuery.toLowerCase().includes('patch') ? 'warning' : 'default'}
              variant={searchQuery.toLowerCase().includes('put') || searchQuery.toLowerCase().includes('patch') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasPut = searchQuery.toLowerCase().includes('put') || searchQuery.toLowerCase().includes('patch');
                setSearchQuery(hasPut ? '' : translate("ui:m_8194d186cf6998939347"));
                setPage(0);
              }}
              title={i18nText("ui:m_c39ffe28059db43c3092")} /><Chip label={i18nText("ui:m_0cabfd859031314aefc7")}
              size="small"
              color={searchQuery.toLowerCase() === 'delete' ? 'error' : 'default'}
              variant={searchQuery.toLowerCase() === 'delete' ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.toLowerCase() === 'delete' ? '' : 'DELETE');
                setPage(0);
              }}
              title={i18nText("ui:m_1dc5604235088ee0f5fe")} /><Chip label={i18nText("ui:m_9e62bcefe8243906a204")}
              size="small"
              color={searchQuery.includes('curl') || searchQuery.includes('wget') || searchQuery.includes('python') ? 'info' : 'default'}
              variant={searchQuery.includes('curl') || searchQuery.includes('wget') || searchQuery.includes('python') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasScript = searchQuery.includes('curl') || searchQuery.includes('wget') || searchQuery.includes('python');
                setSearchQuery(hasScript ? '' : translate("ui:m_3be420d327a79f6fe0d4"));
                setPage(0);
              }}
              title={i18nText("ui:m_adf4a880307656d1ea02")} /><Chip label={i18nText("ui:m_7939c4810955a2bba77c")}
              size="small"
              color={searchQuery.includes('.exe') || searchQuery.includes('.dll') ? 'error' : 'default'}
              variant={searchQuery.includes('.exe') || searchQuery.includes('.dll') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasSuspicious = searchQuery.includes('.exe') || searchQuery.includes('.dll');
                setSearchQuery(hasSuspicious ? '' : translate("ui:m_30c6737cada6c903e020"));
                setPage(0);
              }}
              title={i18nText("ui:m_99e0b3b783b63faa9bb4")} /><Chip label={i18nText("ui:m_06837b6977a5c1a42f37")}
              size="small"
              color={searchQuery === 'ip-host' ? 'warning' : 'default'}
              variant={searchQuery === 'ip-host' ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev === 'ip-host' ? '' : 'ip-host');
                setPage(0);
              }}
              title={i18nText("ui:m_999177702ebf2a1eaaf5")} /><Chip label={i18nText("ui:m_87d7a010e0711f647f67")}
              size="small"
              color={searchQuery.toLowerCase().includes('authorization') ? 'warning' : 'default'}
              variant={searchQuery.toLowerCase().includes('authorization') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.toLowerCase().includes('authorization') ? '' : 'authorization');
                setPage(0);
              }}
              title={i18nText("ui:m_5457d87735acbc861c2a")} />{searchQuery && (
              <Chip label={i18nText("ui:m_0cb3d73ec88de1474e7b")}
                size="small"
                color="secondary"
                onClick={() => {
                  setSearchQuery('');
                  setPage(0);
                }} />
            )}</Box></Box>{/* HTTP Table */}{!httpData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><HttpIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_5805efd383c802f3e975")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_622695ca9e854ab8c713")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedHTTP}
            totalCount={filteredHTTP.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            renderCard={(http) => {
              const totalSize = http.reqContentLength + http.resContentLength;
              return (
                <Card variant="outlined"><CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}><Chip label={http.method || i18nText("ui:m_8dc598ebf1e055830140")}
                        size="small"
                        color="primary"
                        sx={{ fontSize: '0.7rem', fontWeight: 'bold' }} /><Chip label={http.statusCode || i18nText("ui:m_8dc598ebf1e055830140")}
                        size="small"
                        color={getStatusCodeColor(http.statusCode) as any}
                        sx={{ fontSize: '0.7rem' }} /><Typography variant="caption" color="text.secondary" sx={{ ml: 'auto' }}>{formatBytes(totalSize)}</Typography></Box><Typography variant="body2"
                      sx={{
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                        fontWeight: 500,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        mb: 0.5,
                      }}>{http.host || i18nText("ui:m_8dc598ebf1e055830140")}</Typography><Typography variant="body2"
                      color="text.secondary"
                      sx={{
                        fontFamily: 'monospace',
                        fontSize: '0.75rem',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        mb: 0.5,
                      }}>{http.url || '/'}</Typography><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>{http.contentType && (
                        <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{http.contentType.length > 30 ? http.contentType.substring(0, 30) + '...' : http.contentType}</Typography>
                      )}<Typography variant="caption" color="text.secondary" sx={{ ml: 'auto', fontSize: '0.7rem' }}>{formatTimestamp(http.timestamp, 'nanoseconds')}</Typography></Box></CardContent></Card>
              );
            }}
            desktopTable={<TableContainer component={Paper}><Table size="small" data-learn={i18nText("ui:m_3f2c3b4d96198fbd73f6")}><TableHead><TableRow><TableCell width={40}></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_f9c2fb3afd05c2da57ab")}
                        active={sortField === 'timestamp'}
                        direction={sortField === 'timestamp' ? sortOrder : 'asc'}
                        onClick={() => handleSort('timestamp')}>
                        {i18nText("ui:m_b62418ba3d29bf760ea0")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_497ad32ef9ce1ad155c1")}
                        active={sortField === 'method'}
                        direction={sortField === 'method' ? sortOrder : 'asc'}
                        onClick={() => handleSort('method')}>
                        {i18nText("ui:m_883b3c5f63560e49dce6")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_c3ce3a58a77e74ac1fba")}
                        active={sortField === 'host'}
                        direction={sortField === 'host' ? sortOrder : 'asc'}
                        onClick={() => handleSort('host')}>
                        {i18nText("ui:m_d36e3ee418e39309c3c7")}
                      </TableSortLabel></TableCell><TableCell>URL</TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_9cbe49ddf764fd730534")}
                        active={sortField === 'statusCode'}
                        direction={sortField === 'statusCode' ? sortOrder : 'asc'}
                        onClick={() => handleSort('statusCode')}>
                        {i18nText("ui:m_cf025c2b66b1d8e97700")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_1a9f667d3c8cb20d64b1")}
                        active={sortField === 'size'}
                        direction={sortField === 'size' ? sortOrder : 'asc'}
                        onClick={() => handleSort('size')}>
                        {i18nText("ui:m_9f40c21a49494ff4c88e")}
                      </TableSortLabel></TableCell></TableRow></TableHead><TableBody>{paginatedHTTP.map((http, idx) => {
                    const rowKey = `${http.srcIP}-${http.dstIP}-${http.timestamp}-${idx}`;
                    const totalSize = http.reqContentLength + http.resContentLength;
                    return (
                      <><TableRow key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn={i18nText("ui:m_b83c8f5916373e924477")}><TableCell><IconButton size="small" data-learn={i18nText("ui:m_48499055a9d9b0c4f732")}><ExpandMoreIcon sx={{
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} /></IconButton></TableCell><TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{formatTimestamp(http.timestamp, 'nanoseconds')}</Typography></TableCell><TableCell><Chip data-learn={i18nText("ui:m_117abfafe1485850dd0d")}
                              label={http.method || i18nText("ui:m_8dc598ebf1e055830140")}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }} /></TableCell><TableCell><Typography variant="body2"
                              sx={{
                                fontFamily: 'monospace',
                                fontSize: '0.875rem',
                                maxWidth: 200,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                              data-learn={i18nText("ui:m_4dfd1c669d1381649fe1")}>{http.host || i18nText("ui:m_8dc598ebf1e055830140")}</Typography></TableCell><TableCell><Typography variant="body2"
                              sx={{
                                fontFamily: 'monospace',
                                fontSize: '0.75rem',
                                maxWidth: 250,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                              data-learn={i18nText("ui:m_26ad2040411f495259cb")}>{http.url || '/'}</Typography></TableCell><TableCell><Chip data-learn={i18nText("ui:m_e169e7a2352fd6a336a5")}
                              label={http.statusCode || i18nText("ui:m_8dc598ebf1e055830140")}
                              size="small"
                              color={getStatusCodeColor(http.statusCode) as any}
                              sx={{ fontSize: '0.7rem' }} /></TableCell><TableCell align="right"><Typography variant="body2">{formatBytes(totalSize)}</Typography></TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}><Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit><Box sx={{ py: 2 }} data-learn={i18nText("ui:m_1393c83dead26d4ab804")}><HTTPReassemblyNotice status={http.reassemblyStatus} timestampNs={http.timestampNs} /><Grid container spacing={2}>{/* Basic Info */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_ce00c1aeda86ee459920")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_326c105794a7961e3fb4", { arg0: formatTimestamp(http.timestamp, 'nanoseconds') })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_403dc33196d2e4799a40", { arg0: http.method })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_a6650874cb35a85bf637", { arg0: http.proto })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_5ab53c2d1275d584df71", { arg0: http.host })}
                                    </Typography><Typography variant="body2"
                                      color="text.secondary"
                                      sx={{
                                        wordBreak: 'break-all',
                                        maxWidth: '100%',
                                      }}>
                                      {i18nRichText("ui:m_74cef15c95249afb6367", { arg0: http.url })}
                                    </Typography></Grid>{/* Response Details */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_f0e6a5e18a88e3178f4c")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_32263e3ecfe604ed5b84", { arg0: http.statusCode })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_48e7d2b79bc01f8e10af", { arg0: http.contentType || i18nText("ui:m_8dc598ebf1e055830140") })}
                                    </Typography>{http.resContentType && http.resContentType !== http.contentType && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_9fe38942d5f02548cdb7", { arg0: http.resContentType })}
                                      </Typography>
                                    )}{http.contentTypeDetected && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_cedf6b0afc2a74398eca", { arg0: http.contentTypeDetected })}
                                      </Typography>
                                    )}{http.resContentTypeDetected && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_5ac86fc43768e71415c7", { arg0: http.resContentTypeDetected })}
                                      </Typography>
                                    )}<Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_62168a4442e488be3a91", { arg0: http.serverName || i18nText("ui:m_8dc598ebf1e055830140") })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_5e74a9f2f3e3776185e0", { arg0: formatBytes(http.reqContentLength) })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_732dc32ee3661ccc18c2", { arg0: formatBytes(http.resContentLength) })}
                                    </Typography></Grid>{/* Network Details */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_39560df0eef37733648e")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_396636cba40c741818f4", { arg0: http.srcIP })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_9c9522ee37013f51e0a2", { arg0: http.dstIP })}
                                    </Typography>{http.reqContentEncoding && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_87164e9a56bdbe93ee1b", { arg0: http.reqContentEncoding })}
                                      </Typography>
                                    )}{http.resContentEncoding && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_1706b5b5bbc20096aac1", { arg0: http.resContentEncoding })}
                                      </Typography>
                                    )}{http.communityId && (
                                      <Box sx={{ mt: 1 }}><Typography variant="body2" color="text.secondary" data-learn={i18nText("ui:m_6520556565357b546291")}>
                                          {i18nText("ui:m_de7926fe05b8c414b9cc")}
                                        </Typography><CommunityIDChip communityId={http.communityId} mode="text" /></Box>
                                    )}</Grid>{/* Timing Information */}{(http.doneAfter > 0 || http.dnsDoneAfter > 0 || http.tlsDoneAfter > 0 || http.firstByteAfter > 0) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                        {i18nText("ui:m_1909148409e789acb46d")}
                                      </Typography>{http.doneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          {i18nRichText("ui:m_7736a66f9e8b61068df8", { arg0: i18nNumber((http.doneAfter / 1e6), { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false }) })}
                                        </Typography>
                                      )}{http.dnsDoneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          {i18nRichText("ui:m_100a444a1f595eecdac1", { arg0: i18nNumber((http.dnsDoneAfter / 1e6), { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false }) })}
                                        </Typography>
                                      )}{http.tlsDoneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          {i18nRichText("ui:m_016826d6b095ddd35ae0", { arg0: i18nNumber((http.tlsDoneAfter / 1e6), { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false }) })}
                                        </Typography>
                                      )}{http.firstByteAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          {i18nRichText("ui:m_d2cb96f892c128657d2e", { arg0: i18nNumber((http.firstByteAfter / 1e6), { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false }) })}
                                        </Typography>
                                      )}</Grid>
                                  )}{/* Security Headers */}{(http.strictTransportSecurity || http.contentSecurityPolicy || http.xContentTypeOptions ||
                                    http.xFrameOptions || http.xXSSProtection || http.referrerPolicy || http.accessControlAllowOrigin) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_1629af46bf61acd4269b")}>
                                        {i18nText("ui:m_754df0b1d29785d2638c")}
                                      </Typography><Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>{http.strictTransportSecurity && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Chip label={i18nText("ui:m_42ce288c4eb3ecc32f74")} size="small" color="success" sx={{ fontSize: '0.65rem', height: 20 }} /><Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{http.strictTransportSecurity.substring(0, 50)}{http.strictTransportSecurity.length > 50 ? '...' : ''}</Typography></Box>
                                        )}{http.contentSecurityPolicy && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Chip label={i18nText("ui:m_919cc988ba34735547f5")} size="small" color="success" sx={{ fontSize: '0.65rem', height: 20 }} /><Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{http.contentSecurityPolicy.substring(0, 50)}{http.contentSecurityPolicy.length > 50 ? '...' : ''}</Typography></Box>
                                        )}{http.xContentTypeOptions && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Chip label={i18nText("ui:m_5cf96407160d8e4c7b4d")} size="small" color="success" sx={{ fontSize: '0.65rem', height: 20 }} /><Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{http.xContentTypeOptions}</Typography></Box>
                                        )}{http.xFrameOptions && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Chip label={i18nText("ui:m_42510cc07e851d7e2ef7")} size="small" color="success" sx={{ fontSize: '0.65rem', height: 20 }} /><Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{http.xFrameOptions}</Typography></Box>
                                        )}{http.xXSSProtection && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Chip label={i18nText("ui:m_c0969621109f258a6e5d")} size="small" color="info" sx={{ fontSize: '0.65rem', height: 20 }} /><Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{http.xXSSProtection}</Typography></Box>
                                        )}{http.referrerPolicy && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Chip label={i18nText("ui:m_7adec49a22c3af8bbb98")} size="small" color="info" sx={{ fontSize: '0.65rem', height: 20 }} /><Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{http.referrerPolicy}</Typography></Box>
                                        )}{http.accessControlAllowOrigin && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Chip label={i18nText("ui:m_c6a572573053eddc36fb")} size="small" color="warning" sx={{ fontSize: '0.65rem', height: 20 }} /><Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{http.accessControlAllowOrigin}</Typography></Box>
                                        )}</Box></Grid>
                                  )}{/* Server & Auth Info */}{(http.server || http.xPoweredBy || http.authorizationType || http.xForwardedFor || http.xRealIP || http.hasServerTiming) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_ac7cbcbe3ec76d14c5aa")}>
                                        {i18nText("ui:m_405a2e2b815e210a8125")}
                                      </Typography>{http.server && (
                                        <Typography variant="body2" color="text.secondary">
                                          {i18nRichText("ui:m_62168a4442e488be3a91", { arg0: http.server })}
                                        </Typography>
                                      )}{http.xPoweredBy && (
                                        <Typography variant="body2" color="text.secondary">
                                          {i18nRichText("ui:m_8d5c2592f93bfd154a22", { arg0: http.xPoweredBy })}
                                        </Typography>
                                      )}{http.authorizationType && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}><Typography variant="body2" color="text.secondary">
                                            {i18nText("ui:m_b6a7a4493a7831255c83")}
                                          </Typography><Chip label={http.authorizationType}
                                            size="small"
                                            color="primary"
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }} /></Box>
                                      )}{http.xForwardedFor && (
                                        <Typography variant="body2" color="text.secondary">
                                          {i18nRichText("ui:m_bc028eff0cf934e0dfa6", { arg0: http.xForwardedFor })}
                                        </Typography>
                                      )}{http.xRealIP && (
                                        <Typography variant="body2" color="text.secondary">
                                          {i18nRichText("ui:m_79ea3f50f18c5abcafd6", { arg0: http.xRealIP })}
                                        </Typography>
                                      )}{http.hasServerTiming && (
                                        <Chip label={i18nText("ui:m_a86712c887438c8d93d5")}
                                          size="small"
                                          color="warning"
                                          sx={{ fontSize: '0.7rem', mt: 0.5 }}
                                          data-learn={i18nText("ui:m_76839b0a5850ad5f7e28")} />
                                      )}</Grid>
                                  )}{/* JA4H Fingerprinting */}{http.ja4h && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_1507846a7dd54a007b80")}>
                                        {i18nText("ui:m_9ea951ef0f817db5ff12")}
                                      </Typography><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}><Chip label={http.ja4h}
                                          size="small"
                                          color="secondary"
                                          sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }} /></Box>{http.ja4hDescription && (
                                        <Typography variant="body2" color="text.secondary">{http.ja4hDescription}</Typography>
                                      )}</Grid>
                                  )}{/* User Agent & Referer */}<Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_c1d6bc6d55e4baaea935")}
                                    </Typography>{http.userAgent && (
                                      <Typography variant="body2"
                                        color="text.secondary"
                                        sx={{ wordBreak: 'break-all', mb: 1 }}>
                                        {i18nRichText("ui:m_eb1c6c4ed4449f684b8a", { arg0: http.userAgent })}
                                      </Typography>
                                    )}{http.referer && (
                                      <Typography variant="body2"
                                        color="text.secondary"
                                        sx={{ wordBreak: 'break-all' }}>
                                        {i18nRichText("ui:m_7d53b30a485462c7c5a7", { arg0: http.referer })}
                                      </Typography>
                                    )}</Grid>{/* URL Parameters */}{http.parameters && Object.keys(http.parameters).length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_7a1cd8b8360c70d4e3df", { arg0: Object.keys(http.parameters).length })}
                                      </Typography><Box sx={{ maxHeight: 200, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>{Object.entries(http.parameters).map(([key, value]) => (
                                          <Typography key={key}
                                            variant="body2"
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}><strong>{key}:</strong>{value}</Typography>
                                        ))}</Box></Grid>
                                  )}{/* Request Headers */}{http.requestHeader && Object.keys(http.requestHeader).length > 0 && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_85e6e6613cecb174e565", { arg0: Object.keys(http.requestHeader).length })}
                                      </Typography><Box sx={{ maxHeight: 300, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>{Object.entries(http.requestHeader).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => (
                                          <Typography key={key}
                                            variant="body2"
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}><strong>{key}:</strong>{value}</Typography>
                                        ))}</Box></Grid>
                                  )}{/* Response Headers */}{http.responseHeader && Object.keys(http.responseHeader).length > 0 && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_5e4d9bd40bb216ff70a5", { arg0: Object.keys(http.responseHeader).length })}
                                      </Typography><Box sx={{ maxHeight: 300, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>{Object.entries(http.responseHeader).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => (
                                          <Typography key={key}
                                            variant="body2"
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}><strong>{key}:</strong>{value}</Typography>
                                        ))}</Box></Grid>
                                  )}{/* Action Buttons */}<Grid item xs={12}><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}><Button data-learn={i18nText("ui:m_a6ed1e302f6363859c3b")}
                                        variant="outlined"
                                        startIcon={<CableIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          // Use flow identifier for exact connection matching, fallback to IP:port combination
                                          const searchTerm = http.flow || `${http.srcIP}:${http.srcPort}`;
                                          router.push(`/connections?search=${encodeURIComponent(searchTerm)}`);
                                        }}
                                        size="small">
                                        {i18nText("ui:m_6e4460fb915c45550838")}
                                      </Button>{hasSecrets(http) && (
                                        <Button data-learn={i18nText("ui:m_14829180aa81c29ee2c4")}
                                          variant="outlined"
                                          color="warning"
                                          startIcon={<VpnKeyIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            // Navigate to credentials page filtered by community ID
                                            if (http.communityId) {
                                              router.push(`/secrets?search=${encodeURIComponent(http.communityId)}`);
                                            } else {
                                              // Fallback to searching by IP/host
                                              router.push(`/secrets?search=${encodeURIComponent(http.srcIP)}`);
                                            }
                                          }}
                                          size="small">
                                          {i18nText("ui:m_adeca49d759ca345f2bf")}
                                        </Button>
                                      )}<Button data-learn={i18nText("ui:m_2363433387a6b291ae85")}
                                        variant="outlined"
                                        startIcon={<DownloadIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleDownloadPCAP(http);
                                        }}
                                        size="small">
                                        {i18nText("ui:m_866ab5d39a9b8045fa5c")}
                                      </Button></Box></Grid></Grid></Box></Collapse></TableCell></TableRow></>
                    );
                  })}</TableBody></Table></TableContainer>} />
        )}</>
        )}</Box>{/* Conversation Modal */}{selectedHTTP && (
        <ConversationModal open={conversationModalOpen}
          onClose={handleCloseConversationModal}
          srcIP={selectedHTTP.srcIP}
          srcPort="80"
          dstIP={selectedHTTP.dstIP}
          dstPort="80"
          protocol="TCP" />
      )}</Layout>
  );
}
