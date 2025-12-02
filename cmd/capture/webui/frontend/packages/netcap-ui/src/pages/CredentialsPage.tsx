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
  Typography,
  Alert,
  Collapse,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  VpnKey as VpnKeyIcon,
  Person as PersonIcon,
  Lock as LockIcon,
  Security as SecurityIcon,
  AccessTime as AccessTimeIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  SyncAlt as SyncAltIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Tag as TagIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

interface CredentialSummary {
  timestamp: number;
  service: string;
  flow: string;
  user: string;
  password: string;
  notes: string;
  // Hash-based credentials
  hash: string;
  hashType: string;
  domain: string;
  realm: string;
  challenge: string;
  serviceName: string;
  etype: number;
  hashcatFormat: string;
  // HTTP Digest specific
  method: string;
  nonce: string;
  uri: string;
  qop: string;
  nc: string;
  cnonce: string;
  // NTLM specific
  workstation: string;
  lmHash: string;
  ntHash: string;
  // Authentication result tracking
  authSuccess: boolean;
  authSuccessSet: boolean;
  authAttempts: number;
  // RADIUS specific
  macAddress: string;
  framedAddress: string;
  connectInfo: string;
  replyMessage: string;
  // SOCKS specific
  socksVersion: number;
  socksStatus: string;
  // SIP specific
  sipMethod: string;
  sipCallId: string;
  sipFrom: string;
  sipTo: string;
  // Community ID for cross-tool correlation
  communityId: string;
}

interface CredentialsResponse {
  credentials: CredentialSummary[];
  totalCount: number;
}

type CredentialSortField = 'timestamp' | 'service' | 'user' | 'password';
type SortOrder = 'asc' | 'desc';
type CredentialFilterType = 'all' | 'failed' | 'successful' | 'hashed';

// Service category mapping for color-coding and UI labels
const serviceCategories: Record<string, { category: 'auth' | 'discovery' | 'remote' | 'database' | 'network', color: 'primary' | 'secondary' | 'warning' | 'info' | 'success', userLabel: string, passLabel: string }> = {
  // Authentication protocols (traditional credentials)
  'FTP': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'HTTP': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'HTTP Basic': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'HTTP Digest': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Hash' },
  'HTTP NTLM': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'NTLM Hash' },
  'SMTP': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'POP3': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'IMAP': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'Telnet': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'NTLMSSP': { category: 'auth', color: 'warning', userLabel: 'Domain\\User', passLabel: 'NTLM Hash' },
  'Kerberos AS-REQ': { category: 'auth', color: 'warning', userLabel: 'Principal', passLabel: 'Ticket Hash' },
  'Kerberos AS-REP': { category: 'auth', color: 'warning', userLabel: 'Principal', passLabel: 'Encrypted Data' },
  'Kerberos TGS-REP': { category: 'auth', color: 'warning', userLabel: 'Service Principal', passLabel: 'Ticket Hash' },
  'LDAP': { category: 'auth', color: 'primary', userLabel: 'DN/User', passLabel: 'Password' },
  // Database protocols
  'PostgreSQL': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'Password' },
  'PostgreSQL Hash': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'MD5 Hash' },
  'MySQL': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'Password/Hash' },
  'MongoDB': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'SCRAM Data' },
  'MongoDB Challenge Response': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'Challenge/Response' },
  'Redis': { category: 'database', color: 'info', userLabel: 'Database', passLabel: 'Password' },
  // Remote access
  'VNC': { category: 'remote', color: 'warning', userLabel: 'Connection', passLabel: 'Challenge/Response' },
  'TeamViewer': { category: 'remote', color: 'warning', userLabel: 'Command', passLabel: '' },
  'TeamViewer Auth': { category: 'remote', color: 'warning', userLabel: 'Auth Event', passLabel: '' },
  // Network discovery (metadata, not credentials)
  'mDNS': { category: 'discovery', color: 'success', userLabel: 'Hostnames', passLabel: '' },
  'NBNS': { category: 'discovery', color: 'success', userLabel: 'NetBIOS Name', passLabel: '' },
  'UPnP': { category: 'discovery', color: 'success', userLabel: 'Device Info', passLabel: '' },
  'WSD': { category: 'discovery', color: 'success', userLabel: 'Device Address', passLabel: '' },
  // Network management
  'SNMP': { category: 'network', color: 'secondary', userLabel: 'Community String', passLabel: '' },
};

// Helper function to get service info with defaults
const getServiceInfo = (service: string) => {
  return serviceCategories[service] || { 
    category: 'auth' as const, 
    color: 'primary' as const, 
    userLabel: 'Username', 
    passLabel: 'Password' 
  };
};

// Helper function to truncate string with ellipsis
const truncateString = (str: string, maxLength: number) => {
  if (!str || str.length <= maxLength) return str;
  return str.substring(0, maxLength) + '…';
};

// Helper function to parse and render colorized flow identifier
// Expected format: "TCP:192.168.1.1:80->10.0.0.1:443" or similar
const renderColorizedFlow = (flow: string) => {
  if (!flow) return null;
  
  // Try to parse the flow string - typical format: "PROTO:srcIP:srcPort->dstIP:dstPort"
  // or "srcIP:srcPort->dstIP:dstPort"
  const arrowMatch = flow.match(/^(?:([A-Z]+):)?([^:]+):(\d+)->([^:]+):(\d+)$/);
  if (arrowMatch) {
    const [, proto, srcIP, srcPort, dstIP, dstPort] = arrowMatch;
    return (
      <Box 
        sx={{ 
          fontFamily: 'monospace', 
          fontSize: '0.8rem',
          display: 'flex',
          alignItems: 'center',
        }}
      >
        {proto && (
          <>
            <Box component="span" sx={{ color: 'text.secondary' }}>{proto}:</Box>
          </>
        )}
        <Box component="span" sx={{ color: '#f44336', fontWeight: 'bold' }}>{srcIP}</Box>
        <Box component="span" sx={{ color: 'text.secondary' }}>:</Box>
        <Box component="span" sx={{ color: '#FFB74D', fontWeight: 'medium' }}>{srcPort}</Box>
        <Box component="span" sx={{ color: 'text.secondary', mx: 0.5 }}>→</Box>
        <Box component="span" sx={{ color: '#2196f3', fontWeight: 'bold' }}>{dstIP}</Box>
        <Box component="span" sx={{ color: 'text.secondary' }}>:</Box>
        <Box component="span" sx={{ color: '#FFB74D', fontWeight: 'medium' }}>{dstPort}</Box>
      </Box>
    );
  }
  
  // Fallback: just display the flow as-is if it doesn't match the expected pattern
  return (
    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
      {flow}
    </Typography>
  );
};

export default function CredentialsPage() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<CredentialFilterType>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<CredentialSortField>('timestamp');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Initialize search query from URL parameter
  useEffect(() => {
    if (router.isReady && router.query.search) {
      setSearchQuery(router.query.search as string);
    }
  }, [router.isReady, router.query.search]);

  // Fetch credentials data
  const { data: credentialsData, error, mutate } = useSWR<CredentialsResponse>(
    'credentials',
    () => fetch(`${getBackendUrl()}/api/credentials`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const credentials = credentialsData?.credentials || [];
  const totalCount = credentialsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: CredentialSortField) => {
    if (sortField === field) {
      // Toggle sort order if clicking the same field
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new field and default to ascending
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0); // Reset to first page when sorting changes
  };

  // Apply filters and sorting
  const filteredCredentials = useMemo(() => {
    let filtered = credentials;

    // Apply Community ID filter first (if active)
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(c => 
        c.communityId && selectedCommunityIDs.has(c.communityId)
      );
    }

    // Apply credential type filter
    if (filterType !== 'all') {
      filtered = filtered.filter(cred => {
        switch (filterType) {
          case 'failed':
            return cred.authSuccessSet && !cred.authSuccess;
          case 'successful':
            return cred.authSuccessSet && cred.authSuccess;
          case 'hashed':
            return Boolean(cred.hash || cred.hashType || cred.hashcatFormat);
          default:
            return true;
        }
      });
    }

    // Apply search filter with negation support (e.g., "!FTP" excludes FTP)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(c =>
        matchesSearchTerms([
          c.service,
          c.user,
          c.password,
          c.flow,
          c.notes || '',
        ], searchTerms)
      );
    }

    // Apply sorting with stable secondary sort by flow identifier
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'timestamp':
          comparison = a.timestamp - b.timestamp;
          break;
        case 'service':
          comparison = a.service.localeCompare(b.service);
          break;
        case 'user':
          comparison = a.user.localeCompare(b.user);
          break;
        case 'password':
          comparison = a.password.localeCompare(b.password);
          break;
      }
      // Stable secondary sort by flow identifier for consistent ordering
      if (comparison === 0) {
        comparison = (a.flow || '').localeCompare(b.flow || '');
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [credentials, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs, filterType]);

  // Paginate credentials
  const paginatedCredentials = filteredCredentials.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedCredentials.map((cred, idx) => `${cred.timestamp}-${cred.service}-${cred.user}-${idx}`),
    [paginatedCredentials]
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

  // Memoize event handlers to prevent recreation on every render
  const handleRefresh = useCallback(() => {
    mutate();
    // Also refresh charts
    setChartRefreshKey(prev => prev + 1);
  }, [mutate]);

  const handleFileChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      await mutate();
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Refresh charts
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

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view captured credentials from network traffic."
    />
  );

  // Memoize summary statistics to avoid recalculation on every render
  const stats = useMemo(() => ({
    uniqueServices: new Set(credentials.map(c => c.service)).size,
    uniqueUsers: new Set(credentials.map(c => c.user)).size,
    uniquePasswords: new Set(credentials.map(c => c.password)).size,
    avgPerService: credentials.length > 0 
      ? credentials.length / new Set(credentials.map(c => c.service)).size
      : 0,
    failedCount: credentials.filter(c => c.authSuccessSet && !c.authSuccess).length,
    successfulCount: credentials.filter(c => c.authSuccessSet && c.authSuccess).length,
    hashedCount: credentials.filter(c => Boolean(c.hash || c.hashType || c.hashcatFormat)).length,
  }), [credentials]);

  if (error) {
    return (
      <Layout title="Credentials" headerAction={fileSelector}>
        <Alert severity="error">Error loading credentials: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Credentials" headerAction={fileSelector}>
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

        {/* Summary Cards - Row 1: Filters - Only show in table mode */}
        {viewMode === 'table' && (
        <StatBoxGrid>
          <StatBox
            icon={<VpnKeyIcon color="primary" />}
            label="Total Credentials"
            value={totalCount}
            onClick={() => { setFilterType('all'); setPage(0); }}
            isActive={filterType === 'all'}
            activeColor="primary"
            learnHint="Total Credentials: Click to show all credentials."
          />
          <StatBox
            icon={<ErrorIcon color="error" />}
            label="Failed Auth"
            value={stats.failedCount}
            onClick={() => { setFilterType('failed'); setPage(0); }}
            isActive={filterType === 'failed'}
            activeColor="error"
            learnHint="Failed Authentications: Click to filter table to only failed authentication attempts."
          />
          <StatBox
            icon={<CheckCircleIcon color="success" />}
            label="Successful Auth"
            value={stats.successfulCount}
            onClick={() => { setFilterType('successful'); setPage(0); }}
            isActive={filterType === 'successful'}
            activeColor="success"
            learnHint="Successful Authentications: Click to filter table to only successful authentication attempts."
          />
          <StatBox
            icon={<TagIcon color="warning" />}
            label="Hashed Credentials"
            value={stats.hashedCount}
            onClick={() => { setFilterType('hashed'); setPage(0); }}
            isActive={filterType === 'hashed'}
            activeColor="warning"
            learnHint="Hashed Credentials: Click to filter table to only credentials with password hashes (NTLM, Kerberos, etc.)."
          />
        </StatBoxGrid>
        )}

        {/* Summary Cards - Row 2: Statistics - Only show in table mode */}
        {viewMode === 'table' && (
        <StatBoxGrid>
          <StatBox
            icon={<SecurityIcon color="success" />}
            label="Unique Services"
            value={stats.uniqueServices}
            learnHint="Unique Services: Number of different services/protocols that had credentials captured."
          />
          <StatBox
            icon={<PersonIcon color="warning" />}
            label="Unique Users"
            value={stats.uniqueUsers}
            learnHint="Unique Users: Number of different usernames found in captured credentials."
          />
          <StatBox
            icon={<LockIcon color="info" />}
            label="Unique Passwords"
            value={stats.uniquePasswords}
            learnHint="Unique Passwords: Number of different passwords found in captured credentials."
          />
        </StatBoxGrid>
        )}

        {/* Visualization Charts - Only show in chart mode */}
        {viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Credentials by Service: Bar chart showing which services/protocols had the most credentials captured."
                  key={`by-service-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/credentials/by-service`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Credentials by Service"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Credentials Timeline: Line chart showing when credentials were captured over time."
                  key={`timeline-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/credentials/timeline`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Credentials Timeline"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top Usernames: Bar chart showing the most common usernames in captured credentials."
                  key={`usernames-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/credentials/usernames`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Usernames"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Credentials by Flow: Pie chart showing the distribution of credentials across network flows."
                  key={`flows-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/credentials/flows?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Credentials by Flow"
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
          <SearchInput
            value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder="Search credentials..."
            learnHint="Credential Search: Filter credentials by service, username, password, flow, or notes. Use !term to exclude matches (e.g., !FTP excludes FTP)."
          />
          
          <Button
            data-learn="Refresh Button: Reload credential data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {(searchQuery || filterType !== 'all') ? (
            <Typography variant="body2" color="text.secondary" data-learn="Filter Count: Shows how many credentials match the current filter and search out of the total.">
              Showing {filteredCredentials.length} of {totalCount} credentials
            </Typography>
          ) : null}
        </Box>

        {/* Credentials Table */}
        {!credentialsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }} data-learn="No Credentials: No credentials were found in this capture. This could mean secure protocols were used or harvesters weren't configured for the traffic.">
            <VpnKeyIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Credentials Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No credentials have been captured from network traffic yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Credentials Table: Detailed list of all captured credentials with sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                      <TableSortLabel
                        data-learn="Sort by Timestamp: Click to sort credentials by capture time."
                        active={sortField === 'timestamp'}
                        direction={sortField === 'timestamp' ? sortOrder : 'asc'}
                        onClick={() => handleSort('timestamp')}
                      >
                        Time
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Service: Click to sort credentials by service/protocol."
                        active={sortField === 'service'}
                        direction={sortField === 'service' ? sortOrder : 'asc'}
                        onClick={() => handleSort('service')}
                      >
                        Service
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Username: Click to sort credentials by username."
                        active={sortField === 'user'}
                        direction={sortField === 'user' ? sortOrder : 'asc'}
                        onClick={() => handleSort('user')}
                      >
                        Username
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Password: Click to sort credentials by password."
                        active={sortField === 'password'}
                        direction={sortField === 'password' ? sortOrder : 'asc'}
                        onClick={() => handleSort('password')}
                      >
                        Password
                      </TableSortLabel>
                    </TableCell>
                    <TableCell data-learn="Flow Identifier: Network flow where this credential was captured.">
                      Flow
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedCredentials.map((cred, idx) => {
                    const rowKey = `${cred.timestamp}-${cred.service}-${cred.user}-${idx}`;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Credential Row: Click to expand and view detailed information about this captured credential. Use ↑↓ arrows to navigate between rows when expanded."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed credential information.">
                              <ExpandMoreIcon 
                                sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} 
                              />
                            </IconButton>
                          </TableCell>
                          <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }} data-learn="Capture Time: Exact timestamp when this credential was captured from network traffic.">
                              {formatTimestamp(cred.timestamp)}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="Service Tag: Protocol or service where this credential was captured. Colors indicate type: blue=auth, teal=database, orange=remote, green=discovery, purple=network."
                              label={cred.service || 'Unknown'}
                              size="small"
                              color={getServiceInfo(cred.service).color}
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }} 
                              data-learn="Username: The captured username from the authentication attempt."
                              title={cred.user.length > 25 ? cred.user : undefined}
                            >
                              {truncateString(cred.user, 25)}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                fontFamily: 'monospace',
                                fontSize: '0.875rem',
                              }}
                              data-learn="Password: The captured password from the authentication attempt."
                              title={cred.password.length > 25 ? cred.password : undefined}
                            >
                              {truncateString(cred.password, 25)}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {cred.flow ? renderColorizedFlow(cred.flow) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.8rem' }}>
                                -
                              </Typography>
                            )}
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="Credential Details: Extended information about this captured credential including full flow information and notes.">
                                <Grid container spacing={2}>
                                  {/* Timestamp */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Capture Time Field: Full timestamp showing when this credential was captured from the network.">
                                      Capture Time
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      {formatTimestamp(cred.timestamp)}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Service */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Service/Protocol Field: The application-layer protocol where this credential was harvested (e.g., HTTP Basic Auth, FTP, POP3).">
                                      Service/Protocol
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      {cred.service || 'Unknown'}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Username/Primary Data */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn={`${getServiceInfo(cred.service).userLabel} Field: Primary data captured for this service type.`}>
                                      {getServiceInfo(cred.service).userLabel}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                                      {cred.user}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Password/Secondary Data - only show if service has password field */}
                                  {getServiceInfo(cred.service).passLabel && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn={`${getServiceInfo(cred.service).passLabel} Field: Secondary data or credential captured for this service type.`}>
                                      {getServiceInfo(cred.service).passLabel}
                                    </Typography>
                                    <Typography 
                                      variant="body2" 
                                      sx={{ 
                                        fontFamily: 'monospace',
                                        color: getServiceInfo(cred.service).category === 'discovery' ? 'text.secondary' : 'error.main',
                                        fontWeight: getServiceInfo(cred.service).category === 'discovery' ? 'normal' : 'bold',
                                        wordBreak: 'break-all',
                                      }}
                                    >
                                      {cred.password}
                                    </Typography>
                                  </Grid>
                                  )}
                                  
                                  {/* Flow */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Network Flow Field: Complete 5-tuple flow identifier (protocol, src IP:port, dst IP:port) showing the network connection where credential was captured.">
                                      Network Flow
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all', mb: 2 }}>
                                      {cred.flow || 'N/A'}
                                    </Typography>
                                    {cred.flow && (
                                      <Button
                                        data-learn="View Connection: Navigate to the Connections page to see detailed information about this network flow."
                                        variant="outlined"
                                        size="small"
                                        startIcon={<SyncAltIcon />}
                                        onClick={() => router.push(`/connections?search=${encodeURIComponent(cred.flow)}`)}
                                        sx={{ mt: 1 }}
                                      >
                                        View Connection Details
                                      </Button>
                                    )}
                                  </Grid>
                                  
                                  {/* Community ID for Cross-Tool Correlation */}
                                  {cred.communityId && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Community ID: Corelight Community ID v1 for cross-tool correlation with Zeek, Suricata, and other network security tools. Click to filter all pages by this ID.">
                                        Community ID
                                      </Typography>
                                      <CommunityIDChip communityId={cred.communityId} mode="text" />
                                    </Grid>
                                  )}
                                  
                                  {/* Notes */}
                                  {cred.notes && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Notes Field: Additional context about the credential capture including authentication method, encoding, or protocol-specific details.">
                                        Notes
                                      </Typography>
                                      <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                        {cred.notes}
                                      </Typography>
                                    </Grid>
                                  )}

                                  {/* Authentication Result */}
                                  {cred.authSuccessSet && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Authentication Result: Shows whether the authentication attempt succeeded or failed.">
                                        Authentication Result
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                                        <Chip 
                                          label={cred.authSuccess ? '✓ Success' : '✗ Failed'} 
                                          size="small" 
                                          color={cred.authSuccess ? 'success' : 'error'}
                                          sx={{ fontWeight: 'bold' }}
                                        />
                                        {cred.authAttempts > 0 && (
                                          <Typography variant="body2" color="text.secondary">
                                            ({cred.authAttempts} attempt{cred.authAttempts > 1 ? 's' : ''})
                                          </Typography>
                                        )}
                                      </Box>
                                    </Grid>
                                  )}

                                  {/* Hash Information */}
                                  {(cred.hash || cred.hashType || cred.hashcatFormat) && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Hash Information: Details about captured password hash for offline cracking.">
                                        Hash Information
                                      </Typography>
                                      {cred.hashType && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                          <Typography variant="body2" color="text.secondary">Type:</Typography>
                                          <Chip label={cred.hashType} size="small" color="warning" variant="outlined" sx={{ fontSize: '0.7rem' }} />
                                        </Box>
                                      )}
                                      {cred.hash && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all', mb: 0.5 }}>
                                          Hash: {cred.hash}
                                        </Typography>
                                      )}
                                      {cred.hashcatFormat && (
                                        <Box sx={{ mt: 1 }}>
                                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                            Hashcat Format (ready for cracking):
                                          </Typography>
                                          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all', bgcolor: 'background.paper', p: 1, borderRadius: 1, border: '1px solid', borderColor: 'divider' }}>
                                            {cred.hashcatFormat}
                                          </Typography>
                                        </Box>
                                      )}
                                    </Grid>
                                  )}

                                  {/* Domain/NTLM Information */}
                                  {(cred.domain || cred.realm || cred.workstation || cred.ntHash || cred.lmHash) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Windows/Kerberos Info: Domain, realm, and workstation details for enterprise authentication.">
                                        Domain/Enterprise Info
                                      </Typography>
                                      {cred.domain && (
                                        <Typography variant="body2" color="text.secondary">Domain: {cred.domain}</Typography>
                                      )}
                                      {cred.realm && (
                                        <Typography variant="body2" color="text.secondary">Realm: {cred.realm}</Typography>
                                      )}
                                      {cred.workstation && (
                                        <Typography variant="body2" color="text.secondary">Workstation: {cred.workstation}</Typography>
                                      )}
                                      {cred.serviceName && (
                                        <Typography variant="body2" color="text.secondary">SPN: {cred.serviceName}</Typography>
                                      )}
                                      {cred.ntHash && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          NT Hash: {cred.ntHash}
                                        </Typography>
                                      )}
                                      {cred.lmHash && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          LM Hash: {cred.lmHash}
                                        </Typography>
                                      )}
                                    </Grid>
                                  )}

                                  {/* HTTP Digest Info */}
                                  {(cred.nonce || cred.uri || cred.qop) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="HTTP Digest Info: Challenge-response details for HTTP Digest authentication.">
                                        HTTP Digest Details
                                      </Typography>
                                      {cred.method && (
                                        <Typography variant="body2" color="text.secondary">Method: {cred.method}</Typography>
                                      )}
                                      {cred.uri && (
                                        <Typography variant="body2" color="text.secondary" sx={{ wordBreak: 'break-all' }}>URI: {cred.uri}</Typography>
                                      )}
                                      {cred.qop && (
                                        <Typography variant="body2" color="text.secondary">QoP: {cred.qop}</Typography>
                                      )}
                                      {cred.nonce && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          Nonce: {cred.nonce}
                                        </Typography>
                                      )}
                                    </Grid>
                                  )}

                                  {/* RADIUS Info */}
                                  {(cred.macAddress || cred.framedAddress || cred.connectInfo || cred.replyMessage) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="RADIUS Info: Network access details from RADIUS authentication.">
                                        RADIUS Details
                                      </Typography>
                                      {cred.macAddress && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                                          MAC: {cred.macAddress}
                                        </Typography>
                                      )}
                                      {cred.framedAddress && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                                          Assigned IP: {cred.framedAddress}
                                        </Typography>
                                      )}
                                      {cred.connectInfo && (
                                        <Typography variant="body2" color="text.secondary">Connection: {cred.connectInfo}</Typography>
                                      )}
                                      {cred.replyMessage && (
                                        <Typography variant="body2" color="text.secondary">Reply: {cred.replyMessage}</Typography>
                                      )}
                                    </Grid>
                                  )}

                                  {/* SIP Info */}
                                  {(cred.sipMethod || cred.sipCallId || cred.sipFrom || cred.sipTo) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="SIP Info: VoIP session details from SIP authentication.">
                                        SIP Details
                                      </Typography>
                                      {cred.sipMethod && (
                                        <Chip label={cred.sipMethod} size="small" color="info" variant="outlined" sx={{ mb: 0.5, fontSize: '0.7rem' }} />
                                      )}
                                      {cred.sipFrom && (
                                        <Typography variant="body2" color="text.secondary">From: {cred.sipFrom}</Typography>
                                      )}
                                      {cred.sipTo && (
                                        <Typography variant="body2" color="text.secondary">To: {cred.sipTo}</Typography>
                                      )}
                                      {cred.sipCallId && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          Call-ID: {cred.sipCallId}
                                        </Typography>
                                      )}
                                    </Grid>
                                  )}

                                  {/* SOCKS Info */}
                                  {(cred.socksVersion > 0 || cred.socksStatus) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="SOCKS Info: SOCKS proxy authentication details.">
                                        SOCKS Details
                                      </Typography>
                                      {cred.socksVersion > 0 && (
                                        <Typography variant="body2" color="text.secondary">Version: SOCKS{cred.socksVersion}</Typography>
                                      )}
                                      {cred.socksStatus && (
                                        <Typography variant="body2" color="text.secondary">Status: {cred.socksStatus}</Typography>
                                      )}
                                    </Grid>
                                  )}
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
              data-learn="Table Pagination: Navigate through pages of credentials and change how many rows to display per page."
              component="div"
              count={filteredCredentials.length}
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
    </Layout>
  );
}

