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

import { useState, useMemo, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  FormControl,
  Grid,
  IconButton,
  MenuItem,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  Tooltip,
  Typography,
  Alert,
  Collapse,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Fingerprint as FingerprintIcon,
  Security as SecurityIcon,
  VpnLock as VpnLockIcon,
  Router as RouterIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Http as HttpIcon,
  VerifiedUser as VerifiedUserIcon,
  Memory as MemoryIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import SearchInput from '../components/SearchInput';
import { CommunityIDChip } from '../components/CommunityIDChip';
import { formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';
import { useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';
import useSWR, { mutate as globalMutate } from 'swr';

interface FingerprintSummary {
  fingerprint: string;
  type: string;
  count: number;
  hosts: string[];
  description: string;
  firstSeen: number;
  lastSeen: number;
  communityIds: string[];
}

interface FingerprintsResponse {
  fingerprints: FingerprintSummary[];
  totalCount: number;
}

type FingerprintSortField = 'fingerprint' | 'type' | 'count' | 'hosts';
type SortOrder = 'asc' | 'desc';

export default function FingerprintsPage() {
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'JA4' | 'JA4S' | 'JA4H' | 'JA4X' | 'JA4T' | 'JA4TS' | 'JA4SSH' | 'DHCP'>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<FingerprintSortField>('count');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch fingerprints data
  const { data: fingerprintsData, error, mutate } = useSWR<FingerprintsResponse>(
    'fingerprints',
    () => fetch(`${getBackendUrl()}/api/fingerprints`).then(res => res.json()),
    {
      refreshInterval: 0,
    }
  );

  const fingerprints = fingerprintsData?.fingerprints || [];
  const totalCount = fingerprintsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: FingerprintSortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0);
  };

  // Apply filters and sorting
  const filteredFingerprints = useMemo(() => {
    let filtered = fingerprints;

    // Apply Community ID filter
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(fp =>
        fp.communityIds && fp.communityIds.some(cid => selectedCommunityIDs.has(cid))
      );
    }

    // Apply type filter
    if (filterType !== 'all') {
      filtered = filtered.filter(fp => fp.type === filterType);
    }

    // Apply search filter with negation support (e.g., "!JA3" excludes JA3 fingerprints)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(fp =>
        matchesSearchTerms([
          fp.fingerprint,
          fp.type,
          fp.description || '',
          ...(fp.hosts || []),
        ], searchTerms)
      );
    }

    // Apply sorting with stable secondary sort by fingerprint
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'fingerprint':
          comparison = a.fingerprint.localeCompare(b.fingerprint);
          break;
        case 'type':
          comparison = a.type.localeCompare(b.type);
          break;
        case 'count':
          comparison = a.count - b.count;
          break;
        case 'hosts':
          comparison = a.hosts.length - b.hosts.length;
          break;
      }
      // Stable secondary sort by fingerprint for consistent ordering
      if (comparison === 0) {
        comparison = a.fingerprint.localeCompare(b.fingerprint);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [fingerprints, filterType, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs]);

  const paginatedFingerprints = filteredFingerprints.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedFingerprints.map((fp, idx) => `${fp.type}-${fp.fingerprint}-${idx}`),
    [paginatedFingerprints]
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
    setChartRefreshKey(prev => prev + 1);
  }, [mutate]);

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

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view device and application fingerprints."
    />
  );

  // Calculate summary statistics
  const ja4Count = fingerprints.filter(fp => fp.type === 'JA4').length;
  const ja4sCount = fingerprints.filter(fp => fp.type === 'JA4S').length;
  const ja4hCount = fingerprints.filter(fp => fp.type === 'JA4H').length;
  const ja4xCount = fingerprints.filter(fp => fp.type === 'JA4X').length;
  const ja4tCount = fingerprints.filter(fp => fp.type === 'JA4T').length;
  const ja4tsCount = fingerprints.filter(fp => fp.type === 'JA4TS').length;
  const ja4sshCount = fingerprints.filter(fp => fp.type === 'JA4SSH').length;
  const dhcpCount = fingerprints.filter(fp => fp.type === 'DHCP').length;
  const totalOccurrences = fingerprints.reduce((sum, fp) => sum + fp.count, 0);

  if (error) {
    return (
      <Layout title="Fingerprints" headerAction={fileSelector}>
        <Alert severity="error">Error loading fingerprints: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Fingerprints" headerAction={fileSelector}>
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

        {/* Summary Cards - Row 1: Core TLS fingerprints - Only show in table mode */}
        {viewMode === 'table' && (
        <Grid container spacing={2} sx={{ mb: 2 }}>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="Total Fingerprints: Click to show all fingerprints."
              onClick={() => { setFilterType('all'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'all' ? 2 : 0,
                borderColor: 'primary.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <FingerprintIcon color="primary" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      Total Fingerprints
                    </Typography>
                    <Typography variant="h6">
                      {totalCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="JA4 Fingerprints: Click to filter table to JA4 (TLS client) fingerprints."
              onClick={() => { setFilterType('JA4'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4' ? 2 : 0,
                borderColor: 'success.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <VpnLockIcon color="success" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      JA4 (TLS Client)
                    </Typography>
                    <Typography variant="h6">
                      {ja4Count.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="JA4S Fingerprints: Click to filter table to JA4S (TLS server) fingerprints."
              onClick={() => { setFilterType('JA4S'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4S' ? 2 : 0,
                borderColor: 'info.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <VpnLockIcon color="info" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      JA4S (TLS Server)
                    </Typography>
                    <Typography variant="h6">
                      {ja4sCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="JA4H Fingerprints: Click to filter table to JA4H (HTTP) fingerprints."
              onClick={() => { setFilterType('JA4H'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4H' ? 2 : 0,
                borderColor: 'secondary.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <HttpIcon color="secondary" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      JA4H (HTTP)
                    </Typography>
                    <Typography variant="h6">
                      {ja4hCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="JA4X Fingerprints: Click to filter table to JA4X (certificate) fingerprints."
              onClick={() => { setFilterType('JA4X'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4X' ? 2 : 0,
                borderColor: '#9c27b0',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <VerifiedUserIcon sx={{ color: '#9c27b0' }} />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      JA4X (Certificate)
                    </Typography>
                    <Typography variant="h6">
                      {ja4xCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        )}
        
        {/* Summary Cards - Row 2: TCP, SSH, and DHCP fingerprints - Only show in table mode */}
        {viewMode === 'table' && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="JA4T Fingerprints: Click to filter table to JA4T (TCP client) fingerprints."
              onClick={() => { setFilterType('JA4T'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4T' ? 2 : 0,
                borderColor: '#ff5722',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <MemoryIcon sx={{ color: '#ff5722' }} />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      JA4T (TCP Client)
                    </Typography>
                    <Typography variant="h6">
                      {ja4tCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="JA4TS Fingerprints: Click to filter table to JA4TS (TCP server) fingerprints."
              onClick={() => { setFilterType('JA4TS'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4TS' ? 2 : 0,
                borderColor: '#795548',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <MemoryIcon sx={{ color: '#795548' }} />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      JA4TS (TCP Server)
                    </Typography>
                    <Typography variant="h6">
                      {ja4tsCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="JA4SSH Fingerprints: Click to filter table to JA4SSH (SSH) fingerprints."
              onClick={() => { setFilterType('JA4SSH'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4SSH' ? 2 : 0,
                borderColor: 'warning.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SecurityIcon color="warning" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      JA4SSH (SSH)
                    </Typography>
                    <Typography variant="h6">
                      {ja4sshCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={2.4}>
            <Card 
              data-learn="DHCP Fingerprints: Click to filter table to DHCP fingerprints."
              onClick={() => { setFilterType('DHCP'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'DHCP' ? 2 : 0,
                borderColor: 'info.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <RouterIcon color="info" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      DHCP
                    </Typography>
                    <Typography variant="h6">
                      {dhcpCount.toLocaleString()}
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
                  data-learn="Type Distribution: Pie chart showing distribution of JA4, JA4S, JA4SSH, and DHCP fingerprints."
                  key={`type-distribution-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/type-distribution?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Fingerprint Type Distribution"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top JA4: Bar chart showing the most common TLS client fingerprints."
                  key={`top-ja4-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/top-ja4`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top JA4 Fingerprints"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top JA4SSH: Bar chart showing the most common SSH client/server fingerprints."
                  key={`top-ja4ssh-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/top-ja4ssh`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top JA4SSH Fingerprints"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Usage Patterns: Scatter plot showing relationship between fingerprint occurrences and unique hosts."
                  key={`hosts-per-fingerprint-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/hosts-per-fingerprint`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Fingerprint Usage Patterns"
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
            placeholder="Search fingerprints..."
            learnHint="Fingerprint Search: Filter by fingerprint hash, type, description, or associated host. Use !term to exclude matches."
          />
          
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <Select
              data-learn="Type Filter: Filter to show all fingerprints or only specific types (JA4, JA4S, JA4H, JA4X, JA4T, JA4TS, JA4SSH, DHCP)."
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as 'all' | 'JA4' | 'JA4S' | 'JA4H' | 'JA4X' | 'JA4T' | 'JA4TS' | 'JA4SSH' | 'DHCP');
                setPage(0);
              }}
            >
              <MenuItem value="all">All Types</MenuItem>
              <MenuItem value="JA4">JA4 (TLS Client)</MenuItem>
              <MenuItem value="JA4S">JA4S (TLS Server)</MenuItem>
              <MenuItem value="JA4H">JA4H (HTTP)</MenuItem>
              <MenuItem value="JA4X">JA4X (Certificate)</MenuItem>
              <MenuItem value="JA4T">JA4T (TCP Client)</MenuItem>
              <MenuItem value="JA4TS">JA4TS (TCP Server)</MenuItem>
              <MenuItem value="JA4SSH">JA4SSH (SSH)</MenuItem>
              <MenuItem value="DHCP">DHCP</MenuItem>
            </Select>
          </FormControl>
          
          <Button
            data-learn="Refresh Button: Reload fingerprint data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {(searchQuery || filterType !== 'all' || isCommunityIDFilterActive) ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredFingerprints.length} of {totalCount} fingerprints
            </Typography>
          ) : null}
        </Box>

        {/* Fingerprints Table */}
        {!fingerprintsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <FingerprintIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Fingerprints Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No fingerprinting data has been captured yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Fingerprints Table: Detailed list of all discovered fingerprints with occurrence counts and associated hosts.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Fingerprint: Click to sort fingerprints by their hash value."
                        active={sortField === 'fingerprint'}
                        direction={sortField === 'fingerprint' ? sortOrder : 'asc'}
                        onClick={() => handleSort('fingerprint')}
                      >
                        Fingerprint Hash
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Type: Click to sort by fingerprint type (JA3, HASSH, DHCP)."
                        active={sortField === 'type'}
                        direction={sortField === 'type' ? sortOrder : 'asc'}
                        onClick={() => handleSort('type')}
                      >
                        Type
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Count: Click to sort by number of times this fingerprint was seen."
                        active={sortField === 'count'}
                        direction={sortField === 'count' ? sortOrder : 'asc'}
                        onClick={() => handleSort('count')}
                      >
                        Count
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Hosts: Click to sort by number of unique hosts using this fingerprint."
                        active={sortField === 'hosts'}
                        direction={sortField === 'hosts' ? sortOrder : 'asc'}
                        onClick={() => handleSort('hosts')}
                      >
                        Hosts
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>Description</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedFingerprints.map((fp, idx) => {
                    const rowKey = `${fp.type}-${fp.fingerprint}-${idx}`;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Fingerprint Row: Click to expand and view detailed information about this fingerprint. Use ↑↓ arrows to navigate between rows when expanded."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed fingerprint information.">
                              <ExpandMoreIcon 
                                sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} 
                              />
                            </IconButton>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                fontWeight: 'medium',
                                wordBreak: 'break-all'
                              }}
                              data-learn="Fingerprint Hash: Unique hash identifying this specific fingerprint pattern."
                            >
                              {fp.fingerprint}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="Fingerprint Type: Protocol or method used for this fingerprint (JA4/JA4S for TLS, JA4H for HTTP, JA4X for certificates, JA4T/JA4TS for TCP, JA4SSH for SSH, DHCP for device identification)."
                              label={fp.type}
                              size="small"
                              color={
                                fp.type === 'JA4' ? 'success' : 
                                fp.type === 'JA4S' ? 'primary' : 
                                fp.type === 'JA4H' ? 'secondary' :
                                fp.type === 'JA4X' ? 'default' :
                                fp.type === 'JA4T' ? 'error' :
                                fp.type === 'JA4TS' ? 'error' :
                                fp.type === 'JA4SSH' ? 'warning' : 
                                'info'
                              }
                              sx={{ 
                                fontSize: '0.7rem',
                                ...(fp.type === 'JA4X' && { backgroundColor: '#9c27b0', color: 'white' }),
                                ...(fp.type === 'JA4TS' && { backgroundColor: '#795548', color: 'white' }),
                              }}
                            />
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {fp.count.toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {fp.hosts.length.toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" color="text.secondary" sx={{ 
                              maxWidth: 300,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}>
                              {fp.description}
                            </Typography>
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="Fingerprint Details: Extended information including timeline, full description, and all associated hosts.">
                                <Grid container spacing={2}>
                                  {/* Time Range */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Timeline
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      First Seen: {formatTimestamp(fp.firstSeen)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Last Seen: {formatTimestamp(fp.lastSeen)}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Statistics */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Statistics
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Total Occurrences: {fp.count.toLocaleString()}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Unique Hosts: {fp.hosts.length.toLocaleString()}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Full Description */}
                                  {fp.description && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Full Description
                                      </Typography>
                                      <Typography variant="body2" color="text.secondary">
                                        {fp.description}
                                      </Typography>
                                    </Grid>
                                  )}
                                  
                                  {/* Associated Hosts */}
                                  {fp.hosts.length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Associated Hosts ({fp.hosts.length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {fp.hosts.map((host) => (
                                          <Chip
                                            key={host}
                                            label={host}
                                            size="small"
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }}
                                          />
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}

                                  {/* Community IDs */}
                                  {fp.communityIds && fp.communityIds.length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Community IDs ({fp.communityIds.length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {fp.communityIds.map((cid) => (
                                          <CommunityIDChip
                                            key={cid}
                                            communityId={cid}
                                            mode="chip"
                                            truncate={false}
                                          />
                                        ))}
                                      </Box>
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
              data-learn="Table Pagination: Navigate through pages of fingerprints and change how many rows to display per page."
              component="div"
              count={filteredFingerprints.length}
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

