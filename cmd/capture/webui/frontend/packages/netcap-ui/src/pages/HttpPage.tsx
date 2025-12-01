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
  Grid,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  TextField,
  Typography,
  Alert,
  Collapse,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
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
import ConversationModal from '../components/ConversationModal';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

interface HTTPSummary {
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

interface CredentialSummary {
  timestamp: number;
  service: string;
  flow: string;
  user: string;
  password: string;
  communityId: string;
}

interface CredentialsResponse {
  credentials: CredentialSummary[];
  totalCount: number;
}

type HTTPSortField = 'timestamp' | 'method' | 'host' | 'statusCode' | 'size';
type SortOrder = 'asc' | 'desc';
type HTTPFilterType = 'all' | 'errors' | 'missingSecurityHeaders' | 'hasAuth';

export default function HTTPPage() {
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
  const [viewMode, setViewMode] = useState<'table' | 'chart'>('table');
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
  const { data: credentialsData, mutate: mutateCredentials } = useSWR<CredentialsResponse>(
    'credentials',
    () => fetch(`${getBackendUrl()}/api/credentials`).then(res => res.json()),
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
    if (credentialsData?.credentials) {
      for (const cred of credentialsData.credentials) {
        if (cred.communityId) {
          ids.add(cred.communityId);
        }
      }
    }
    return ids;
  }, [credentialsData]);

  // Helper function to check if an HTTP request has credentials
  const hasCredentials = useCallback((http: HTTPSummary): boolean => {
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
    mutateCredentials();
    setChartRefreshKey(prev => prev + 1);
  }, [mutate, mutateCredentials]);

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
      alert('Failed to switch to this capture');
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate]);

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
      });
      const downloadUrl = `${getBackendUrl()}/api/http/download-pcap?${params}`;
      
      const response = await fetch(downloadUrl);
      
      if (!response.ok) {
        const errorText = await response.text();
        alert(`Failed to download PCAP: ${errorText}`);
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
      alert(`Failed to download PCAP: ${error}`);
    }
  }, []);

  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their HTTP traffic records."
    />
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
      <Layout title="HTTP" headerAction={fileSelector}>
        <Alert severity="error">Error loading HTTP records: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="HTTP" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        {/* View Mode Toggle */}
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}>
          <ToggleButtonGroup
            value={viewMode}
            exclusive
            onChange={(_e, newValue) => {
              if (newValue !== null) {
                setViewMode(newValue);
              }
            }}
            size="small"
            data-learn="View Mode Toggle: Switch between Table mode (showing data in a table) and Chart mode (showing only visualization charts)."
          >
            <ToggleButton value="table">
              <TableChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                Table
              </Box>
            </ToggleButton>
            <ToggleButton value="chart">
              <BarChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                Chart
              </Box>
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>

        {/* Summary Cards - Clickable Security Filters - Only show in table mode */}
        {viewMode === 'table' && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              data-learn="Total Requests: Click to show all HTTP requests."
              onClick={() => { setFilterType('all'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'all' ? 2 : 0,
                borderColor: 'primary.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <HttpIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Requests
                    </Typography>
                    <Typography variant="h5">
                      {totalCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              data-learn="Error Responses: Click to filter table to only HTTP responses with status codes 400 or higher (client/server errors)."
              onClick={() => { setFilterType('errors'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'errors' ? 2 : 0,
                borderColor: 'error.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ErrorIcon color="error" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Error Responses
                    </Typography>
                    <Typography variant="h5">
                      {stats.statusErrors.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              data-learn="Missing Security Headers: Click to filter table to only responses missing critical security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)."
              onClick={() => { setFilterType('missingSecurityHeaders'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'missingSecurityHeaders' ? 2 : 0,
                borderColor: 'warning.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ShieldIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Missing Sec Headers
                    </Typography>
                    <Typography variant="h5">
                      {stats.missingSecurityHeaders.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              data-learn="Authentication Present: Click to filter table to only requests with authentication headers (Basic, Bearer, etc.)."
              onClick={() => { setFilterType('hasAuth'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'hasAuth' ? 2 : 0,
                borderColor: 'info.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <LockIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      With Authentication
                    </Typography>
                    <Typography variant="h5">
                      {stats.hasAuthCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        )}

        {/* Visualization Charts - Only show in chart mode */}
        {viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top Hosts Chart: Bar chart showing the hosts with the most HTTP requests."
                  key={`top-hosts-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/top-hosts`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top HTTP Hosts"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Status Codes: Pie chart showing the distribution of HTTP status codes."
                  key={`status-codes-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/status-codes`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="HTTP Status Codes"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Request Methods: Bar chart showing the distribution of HTTP request methods."
                  key={`methods-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/methods`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="HTTP Request Methods"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Content Types: Pie chart showing the distribution of response content types."
                  key={`content-types-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/content-types`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="HTTP Content Types"
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        )}

        {/* Filters and Actions - Only show in table mode */}
        {viewMode === 'table' && (
        <>
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField
            data-learn="HTTP Search: Filter HTTP requests by IP addresses, hosts, URLs, methods, user agents, or status codes. Multiple search terms can be separated by commas or spaces."
            size="small"
            placeholder="Search HTTP requests (comma or space separated)..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
          />
          
          <Button
            data-learn="Refresh Button: Reload HTTP data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {(searchQuery || filterType !== 'all') ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredHTTP.length} of {totalCount} requests
            </Typography>
          ) : null}
        </Box>

        {/* Quick Filters for HTTP Threat Hunting */}
        <Box sx={{ mb: 2 }} data-learn="Quick Filters: Click any filter chip to quickly narrow down HTTP requests based on common threat hunting patterns.">
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            🔍 Quick Filters (Threat Hunting):
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Chip
              label="Error Status (4xx/5xx)"
              size="small"
              color={searchQuery.includes('4') || searchQuery.includes('5') ? 'error' : 'default'}
              variant={searchQuery.includes('400') || searchQuery.includes('500') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev === 'errors' ? '' : 'errors');
                setPage(0);
              }}
              title="Show HTTP requests with error status codes (4xx/5xx)"
            />
            <Chip
              label="POST Requests"
              size="small"
              color={searchQuery.toLowerCase() === 'post' ? 'warning' : 'default'}
              variant={searchQuery.toLowerCase() === 'post' ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.toLowerCase() === 'post' ? '' : 'POST');
                setPage(0);
              }}
              title="Show only POST requests (potential data uploads)"
            />
            <Chip
              label="PUT/PATCH"
              size="small"
              color={searchQuery.toLowerCase().includes('put') || searchQuery.toLowerCase().includes('patch') ? 'warning' : 'default'}
              variant={searchQuery.toLowerCase().includes('put') || searchQuery.toLowerCase().includes('patch') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasPut = searchQuery.toLowerCase().includes('put') || searchQuery.toLowerCase().includes('patch');
                setSearchQuery(hasPut ? '' : 'PUT PATCH');
                setPage(0);
              }}
              title="Show PUT/PATCH requests (data modification)"
            />
            <Chip
              label="DELETE"
              size="small"
              color={searchQuery.toLowerCase() === 'delete' ? 'error' : 'default'}
              variant={searchQuery.toLowerCase() === 'delete' ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.toLowerCase() === 'delete' ? '' : 'DELETE');
                setPage(0);
              }}
              title="Show DELETE requests (data deletion)"
            />
            <Chip
              label="Scripting User-Agents"
              size="small"
              color={searchQuery.includes('curl') || searchQuery.includes('wget') || searchQuery.includes('python') ? 'info' : 'default'}
              variant={searchQuery.includes('curl') || searchQuery.includes('wget') || searchQuery.includes('python') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasScript = searchQuery.includes('curl') || searchQuery.includes('wget') || searchQuery.includes('python');
                setSearchQuery(hasScript ? '' : 'curl wget python powershell');
                setPage(0);
              }}
              title="Requests from scripting tools (curl, wget, Python, PowerShell)"
            />
            <Chip
              label="Suspicious Files"
              size="small"
              color={searchQuery.includes('.exe') || searchQuery.includes('.dll') ? 'error' : 'default'}
              variant={searchQuery.includes('.exe') || searchQuery.includes('.dll') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasSuspicious = searchQuery.includes('.exe') || searchQuery.includes('.dll');
                setSearchQuery(hasSuspicious ? '' : '.exe .dll .scr .bat .ps1 .vbs');
                setPage(0);
              }}
              title="Potentially malicious file downloads (executables, scripts)"
            />
            <Chip
              label="IP Hosts"
              size="small"
              color={searchQuery === 'ip-host' ? 'warning' : 'default'}
              variant={searchQuery === 'ip-host' ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev === 'ip-host' ? '' : 'ip-host');
                setPage(0);
              }}
              title="Requests to IP addresses instead of domains (potential C2)"
            />
            <Chip
              label="Base64 Auth"
              size="small"
              color={searchQuery.toLowerCase().includes('authorization') ? 'warning' : 'default'}
              variant={searchQuery.toLowerCase().includes('authorization') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.toLowerCase().includes('authorization') ? '' : 'authorization');
                setPage(0);
              }}
              title="Requests with Authorization header (Basic/Bearer auth)"
            />
            {searchQuery && (
              <Chip
                label="Clear All"
                size="small"
                color="secondary"
                onClick={() => {
                  setSearchQuery('');
                  setPage(0);
                }}
              />
            )}
          </Box>
        </Box>

        {/* HTTP Table */}
        {!httpData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <HttpIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No HTTP Records Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No HTTP traffic has been captured yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="HTTP Table: Detailed list of all captured HTTP requests and responses with sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Timestamp: Click to sort HTTP requests by when they occurred."
                        active={sortField === 'timestamp'}
                        direction={sortField === 'timestamp' ? sortOrder : 'asc'}
                        onClick={() => handleSort('timestamp')}
                      >
                        Time
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Method: Click to sort HTTP requests by HTTP method (GET, POST, etc.)."
                        active={sortField === 'method'}
                        direction={sortField === 'method' ? sortOrder : 'asc'}
                        onClick={() => handleSort('method')}
                      >
                        Method
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Host: Click to sort HTTP requests by destination host."
                        active={sortField === 'host'}
                        direction={sortField === 'host' ? sortOrder : 'asc'}
                        onClick={() => handleSort('host')}
                      >
                        Host
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>URL</TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Status: Click to sort HTTP requests by response status code."
                        active={sortField === 'statusCode'}
                        direction={sortField === 'statusCode' ? sortOrder : 'asc'}
                        onClick={() => handleSort('statusCode')}
                      >
                        Status
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Size: Click to sort HTTP requests by total data size (request + response)."
                        active={sortField === 'size'}
                        direction={sortField === 'size' ? sortOrder : 'asc'}
                        onClick={() => handleSort('size')}
                      >
                        Size
                      </TableSortLabel>
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedHTTP.map((http, idx) => {
                    const rowKey = `${http.srcIP}-${http.dstIP}-${http.timestamp}-${idx}`;
                    const totalSize = http.reqContentLength + http.resContentLength;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="HTTP Row: Click to expand and view detailed information about this HTTP request/response. Use ↑↓ arrows to navigate between rows when expanded."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed HTTP information.">
                              <ExpandMoreIcon 
                                sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} 
                              />
                            </IconButton>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                              {formatTimestamp(http.timestamp)}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="HTTP Method: The HTTP request method used (GET, POST, PUT, DELETE, etc.)."
                              label={http.method || 'N/A'}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                maxWidth: 200,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                              data-learn="Host: The destination host from the HTTP Host header."
                            >
                              {http.host || 'N/A'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.75rem',
                                maxWidth: 250,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                              data-learn="URL: The full request URL path and query string."
                            >
                              {http.url || '/'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="HTTP Status Code: The response status code (200 OK, 404 Not Found, etc.)."
                              label={http.statusCode || 'N/A'}
                              size="small"
                              color={getStatusCodeColor(http.statusCode) as any}
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {formatBytes(totalSize)}
                            </Typography>
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="HTTP Details: Extended information about this HTTP request and response including headers, cookies, encoding, and endpoints.">
                                <Grid container spacing={2}>
                                  {/* Basic Info */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Request Details
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Time: {formatTimestamp(http.timestamp)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Method: {http.method}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Protocol: {http.proto}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Host: {http.host}
                                    </Typography>
                                    <Typography 
                                      variant="body2" 
                                      color="text.secondary"
                                      sx={{ 
                                        wordBreak: 'break-all',
                                        maxWidth: '100%',
                                      }}
                                    >
                                      URL: {http.url}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Response Details */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Response Details
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Status Code: {http.statusCode}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Content Type: {http.contentType || 'N/A'}
                                    </Typography>
                                    {http.resContentType && http.resContentType !== http.contentType && (
                                      <Typography variant="body2" color="text.secondary">
                                        Response Content Type: {http.resContentType}
                                      </Typography>
                                    )}
                                    {http.contentTypeDetected && (
                                      <Typography variant="body2" color="text.secondary">
                                        Detected Content Type: {http.contentTypeDetected}
                                      </Typography>
                                    )}
                                    {http.resContentTypeDetected && (
                                      <Typography variant="body2" color="text.secondary">
                                        Detected Response Type: {http.resContentTypeDetected}
                                      </Typography>
                                    )}
                                    <Typography variant="body2" color="text.secondary">
                                      Server: {http.serverName || 'N/A'}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Request Size: {formatBytes(http.reqContentLength)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Response Size: {formatBytes(http.resContentLength)}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Network Details */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Network Information
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Source IP: {http.srcIP}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Destination IP: {http.dstIP}
                                    </Typography>
                                    {http.reqContentEncoding && (
                                      <Typography variant="body2" color="text.secondary">
                                        Request Encoding: {http.reqContentEncoding}
                                      </Typography>
                                    )}
                                    {http.resContentEncoding && (
                                      <Typography variant="body2" color="text.secondary">
                                        Response Encoding: {http.resContentEncoding}
                                      </Typography>
                                    )}
                                    {http.communityId && (
                                      <Box sx={{ mt: 1 }}>
                                        <Typography variant="body2" color="text.secondary" data-learn="Community ID: Corelight Community ID v1 for cross-tool correlation with Zeek, Suricata, and other network security tools. Click to filter all pages by this ID.">
                                          Community ID:
                                        </Typography>
                                        <CommunityIDChip communityId={http.communityId} mode="text" />
                                      </Box>
                                    )}
                                  </Grid>
                                  
                                  {/* Timing Information */}
                                  {(http.doneAfter > 0 || http.dnsDoneAfter > 0 || http.tlsDoneAfter > 0 || http.firstByteAfter > 0) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Timing (HTTP Proxy Mode)
                                      </Typography>
                                      {http.doneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          Total Duration: {(http.doneAfter / 1e6).toFixed(2)}ms
                                        </Typography>
                                      )}
                                      {http.dnsDoneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          DNS Lookup: {(http.dnsDoneAfter / 1e6).toFixed(2)}ms
                                        </Typography>
                                      )}
                                      {http.tlsDoneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          TLS Handshake: {(http.tlsDoneAfter / 1e6).toFixed(2)}ms
                                        </Typography>
                                      )}
                                      {http.firstByteAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          First Byte: {(http.firstByteAfter / 1e6).toFixed(2)}ms
                                        </Typography>
                                      )}
                                    </Grid>
                                  )}

                                  {/* Security Headers */}
                                  {(http.strictTransportSecurity || http.contentSecurityPolicy || http.xContentTypeOptions || 
                                    http.xFrameOptions || http.xXSSProtection || http.referrerPolicy || http.accessControlAllowOrigin) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Security Headers: HTTP response security headers that protect against common web vulnerabilities.">
                                        Security Headers
                                      </Typography>
                                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                                        {http.strictTransportSecurity && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Chip label="HSTS" size="small" color="success" sx={{ fontSize: '0.65rem', height: 20 }} />
                                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                              {http.strictTransportSecurity.substring(0, 50)}{http.strictTransportSecurity.length > 50 ? '...' : ''}
                                            </Typography>
                                          </Box>
                                        )}
                                        {http.contentSecurityPolicy && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Chip label="CSP" size="small" color="success" sx={{ fontSize: '0.65rem', height: 20 }} />
                                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                              {http.contentSecurityPolicy.substring(0, 50)}{http.contentSecurityPolicy.length > 50 ? '...' : ''}
                                            </Typography>
                                          </Box>
                                        )}
                                        {http.xContentTypeOptions && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Chip label="X-Content-Type-Options" size="small" color="success" sx={{ fontSize: '0.65rem', height: 20 }} />
                                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                              {http.xContentTypeOptions}
                                            </Typography>
                                          </Box>
                                        )}
                                        {http.xFrameOptions && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Chip label="X-Frame-Options" size="small" color="success" sx={{ fontSize: '0.65rem', height: 20 }} />
                                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                              {http.xFrameOptions}
                                            </Typography>
                                          </Box>
                                        )}
                                        {http.xXSSProtection && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Chip label="X-XSS-Protection" size="small" color="info" sx={{ fontSize: '0.65rem', height: 20 }} />
                                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                              {http.xXSSProtection}
                                            </Typography>
                                          </Box>
                                        )}
                                        {http.referrerPolicy && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Chip label="Referrer-Policy" size="small" color="info" sx={{ fontSize: '0.65rem', height: 20 }} />
                                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                              {http.referrerPolicy}
                                            </Typography>
                                          </Box>
                                        )}
                                        {http.accessControlAllowOrigin && (
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Chip label="CORS" size="small" color="warning" sx={{ fontSize: '0.65rem', height: 20 }} />
                                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                              {http.accessControlAllowOrigin}
                                            </Typography>
                                          </Box>
                                        )}
                                      </Box>
                                    </Grid>
                                  )}

                                  {/* Server & Auth Info */}
                                  {(http.server || http.xPoweredBy || http.authorizationType || http.xForwardedFor || http.xRealIP || http.hasServerTiming) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Server & Authentication: Server identification and authentication information.">
                                        Server & Authentication
                                      </Typography>
                                      {http.server && (
                                        <Typography variant="body2" color="text.secondary">
                                          Server: {http.server}
                                        </Typography>
                                      )}
                                      {http.xPoweredBy && (
                                        <Typography variant="body2" color="text.secondary">
                                          X-Powered-By: {http.xPoweredBy}
                                        </Typography>
                                      )}
                                      {http.authorizationType && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                                          <Typography variant="body2" color="text.secondary">
                                            Auth Type:
                                          </Typography>
                                          <Chip 
                                            label={http.authorizationType} 
                                            size="small" 
                                            color="primary"
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }}
                                          />
                                        </Box>
                                      )}
                                      {http.xForwardedFor && (
                                        <Typography variant="body2" color="text.secondary">
                                          X-Forwarded-For: {http.xForwardedFor}
                                        </Typography>
                                      )}
                                      {http.xRealIP && (
                                        <Typography variant="body2" color="text.secondary">
                                          X-Real-IP: {http.xRealIP}
                                        </Typography>
                                      )}
                                      {http.hasServerTiming && (
                                        <Chip 
                                          label="⚠️ Server-Timing present" 
                                          size="small" 
                                          color="warning"
                                          sx={{ fontSize: '0.7rem', mt: 0.5 }}
                                          data-learn="Server-Timing header may expose internal performance metrics."
                                        />
                                      )}
                                    </Grid>
                                  )}

                                  {/* JA4H Fingerprinting */}
                                  {http.ja4h && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="JA4H: HTTP client fingerprint based on request header ordering and values.">
                                        JA4H HTTP Fingerprint
                                      </Typography>
                                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                        <Chip 
                                          label={http.ja4h} 
                                          size="small" 
                                          color="secondary"
                                          sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                                        />
                                      </Box>
                                      {http.ja4hDescription && (
                                        <Typography variant="body2" color="text.secondary">
                                          {http.ja4hDescription}
                                        </Typography>
                                      )}
                                    </Grid>
                                  )}
                                  
                                  {/* User Agent & Referer */}
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Client Information
                                    </Typography>
                                    {http.userAgent && (
                                      <Typography 
                                        variant="body2" 
                                        color="text.secondary"
                                        sx={{ wordBreak: 'break-all', mb: 1 }}
                                      >
                                        User-Agent: {http.userAgent}
                                      </Typography>
                                    )}
                                    {http.referer && (
                                      <Typography 
                                        variant="body2" 
                                        color="text.secondary"
                                        sx={{ wordBreak: 'break-all' }}
                                      >
                                        Referer: {http.referer}
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* URL Parameters */}
                                  {http.parameters && Object.keys(http.parameters).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        URL Parameters ({Object.keys(http.parameters).length})
                                      </Typography>
                                      <Box sx={{ maxHeight: 200, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>
                                        {Object.entries(http.parameters).map(([key, value]) => (
                                          <Typography 
                                            key={key}
                                            variant="body2" 
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}
                                          >
                                            <strong>{key}:</strong> {value}
                                          </Typography>
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Request Headers */}
                                  {http.requestHeader && Object.keys(http.requestHeader).length > 0 && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Request Headers ({Object.keys(http.requestHeader).length})
                                      </Typography>
                                      <Box sx={{ maxHeight: 300, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>
                                        {Object.entries(http.requestHeader).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => (
                                          <Typography 
                                            key={key}
                                            variant="body2" 
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}
                                          >
                                            <strong>{key}:</strong> {value}
                                          </Typography>
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Response Headers */}
                                  {http.responseHeader && Object.keys(http.responseHeader).length > 0 && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Response Headers ({Object.keys(http.responseHeader).length})
                                      </Typography>
                                      <Box sx={{ maxHeight: 300, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>
                                        {Object.entries(http.responseHeader).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => (
                                          <Typography 
                                            key={key}
                                            variant="body2" 
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}
                                          >
                                            <strong>{key}:</strong> {value}
                                          </Typography>
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Action Buttons */}
                                  <Grid item xs={12}>
                                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                      <Button
                                        data-learn="Show Connection: Navigate to the Connections page to view the exact TCP/UDP connection for this HTTP request using the flow identifier."
                                        variant="outlined"
                                        startIcon={<CableIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          // Use flow identifier for exact connection matching, fallback to IP:port combination
                                          const searchTerm = http.flow || `${http.srcIP}:${http.srcPort}`;
                                          router.push(`/connections?search=${encodeURIComponent(searchTerm)}`);
                                        }}
                                        size="small"
                                      >
                                        Show Connection
                                      </Button>
                                      {hasCredentials(http) && (
                                        <Button
                                          data-learn="Show Secrets: Navigate to the Credentials page to view the captured credentials associated with this HTTP request."
                                          variant="outlined"
                                          color="warning"
                                          startIcon={<VpnKeyIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            // Navigate to credentials page filtered by community ID
                                            if (http.communityId) {
                                              router.push(`/credentials?search=${encodeURIComponent(http.communityId)}`);
                                            } else {
                                              // Fallback to searching by IP/host
                                              router.push(`/credentials?search=${encodeURIComponent(http.srcIP)}`);
                                            }
                                          }}
                                          size="small"
                                        >
                                          Show Secrets
                                        </Button>
                                      )}
                                      <Button
                                        data-learn="Download as PCAP: Download a filtered PCAP file containing only the packets from this HTTP request/response."
                                        variant="outlined"
                                        startIcon={<DownloadIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleDownloadPCAP(http);
                                        }}
                                        size="small"
                                      >
                                        Download PCAP
                                      </Button>
                                    </Box>
                                  </Grid>
                                </Grid>
                              </Box>
                            </Collapse>
                          </TableCell>
                        </TableRow>
                      </>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              data-learn="Table Pagination: Navigate through pages of HTTP requests and change how many rows to display per page."
              component="div"
              count={filteredHTTP.length}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
            />
          </>
        )}
        </>
        )}
      </Box>

      {/* Conversation Modal */}
      {selectedHTTP && (
        <ConversationModal
          open={conversationModalOpen}
          onClose={handleCloseConversationModal}
          srcIP={selectedHTTP.srcIP}
          srcPort="80"
          dstIP={selectedHTTP.dstIP}
          dstPort="80"
          protocol="TCP"
        />
      )}
    </Layout>
  );
}

