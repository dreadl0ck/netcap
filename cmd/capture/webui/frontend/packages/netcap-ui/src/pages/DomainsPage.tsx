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

import React, { useState, useMemo, useCallback } from 'react';
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
  Language as LanguageIcon,
  TrendingUp as TrendingUpIcon,
  Public as PublicIcon,
  AccountTree as AccountTreeIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';
import { useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import useSWR, { mutate as globalMutate } from 'swr';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

import { ChartFrame } from '../components/ChartFrame';
export interface DomainSummary {
  domain: string;
  queryCount: number;
  uniqueClients: number;
  recordTypes: string[];
  responseCodes: number[];
  firstSeen: number;
  lastSeen: number;
  isSubdomain: boolean;
  parentDomain: string;
  resolvedIPs: string[];
  source: string; // "DNS", "TLS SNI", or "DNS, TLS SNI"
  communityIds: string[]; // Community IDs for cross-tool correlation
}

interface DomainsResponse {
  domains: DomainSummary[];
  totalCount: number;
}

type DomainSortField = 'domain' | 'queries' | 'clients' | 'type';
type SortOrder = 'asc' | 'desc';

export interface DomainsPageProps {
  /** Custom row actions to render in the expanded row details */
  rowActions?: (row: DomainSummary) => React.ReactNode;
}

export default function DomainsPage({ rowActions }: DomainsPageProps = {}) {
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'root' | 'subdomain'>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<DomainSortField>('queries');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch domains data
  const { data: domainsData, error, mutate } = useSWR<DomainsResponse>(
    'domains',
    () => fetch(`${getBackendUrl()}/api/domains`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const domains = domainsData?.domains || [];
  const totalCount = domainsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: DomainSortField) => {
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
  const filteredDomains = useMemo(() => {
    let filtered = domains;

    // Apply Community ID filter first (if active)
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(d => 
        d.communityIds && d.communityIds.some(cid => selectedCommunityIDs.has(cid))
      );
    }

    // Apply type filter
    if (filterType === 'root') {
      filtered = filtered.filter(d => !d.isSubdomain);
    } else if (filterType === 'subdomain') {
      filtered = filtered.filter(d => d.isSubdomain);
    }

    // Apply search filter with negation support (e.g., "!google" excludes Google domains)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(d =>
        matchesSearchTerms([
          d.domain,
          d.parentDomain || '',
          d.source || '',
          ...(d.recordTypes || []),
          ...(d.resolvedIPs || []),
        ], searchTerms)
      );
    }

    // Apply sorting with stable secondary sort by domain name
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'domain':
          comparison = a.domain.localeCompare(b.domain);
          break;
        case 'queries':
          comparison = a.queryCount - b.queryCount;
          break;
        case 'clients':
          comparison = a.uniqueClients - b.uniqueClients;
          break;
        case 'type':
          // Sort root domains first
          if (a.isSubdomain === b.isSubdomain) {
            comparison = a.domain.localeCompare(b.domain);
          } else {
            comparison = a.isSubdomain ? 1 : -1;
          }
          break;
      }
      // Stable secondary sort by domain name for consistent ordering
      if (comparison === 0) {
        comparison = a.domain.localeCompare(b.domain);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [domains, filterType, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs]);

  // Paginate domains
  const paginatedDomains = filteredDomains.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedDomains.map(domain => domain.domain),
    [paginatedDomains]
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

  const handleRowClick = useCallback((domain: string) => {
    setExpandedRow(prev => prev === domain ? null : domain);
  }, []);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their DNS domains and queries."
    />
  );

  // Memoize summary statistics to avoid recalculation on every render
  const stats = useMemo(() => ({
    totalQueries: domains.reduce((sum, d) => sum + d.queryCount, 0),
    uniqueTLDs: new Set(domains.map(d => {
      const parts = d.domain.split('.');
      return parts[parts.length - 1];
    })).size,
    subdomainCount: domains.filter(d => d.isSubdomain).length
  }), [domains]);

  if (error) {
    return (
      <Layout title="Domains" headerAction={fileSelector}>
        <Alert severity="error">Error loading domains: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Domains" headerAction={fileSelector}>
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

        {/* Summary Cards - Only show in table mode */}
        {viewMode === 'table' && (
        <StatBoxGrid>
          <StatBox
            icon={<LanguageIcon color="primary" />}
            label="Unique Domains"
            value={totalCount}
            learnHint="Unique Domains: Total number of unique domain names found in DNS queries."
          />
          <StatBox
            icon={<TrendingUpIcon color="success" />}
            label="Total Queries"
            value={stats.totalQueries}
            learnHint="Total Queries: Sum of all DNS queries made to all domains."
          />
          <StatBox
            icon={<PublicIcon color="warning" />}
            label="Unique TLDs"
            value={stats.uniqueTLDs}
            learnHint="Top-Level Domains: Number of different TLDs (.com, .org, .net, etc.) found."
          />
          <StatBox
            icon={<AccountTreeIcon color="info" />}
            label="Subdomains"
            value={stats.subdomainCount}
            learnHint="Subdomains: Number of subdomain entries (e.g., www.example.com, api.service.com)."
          />
        </StatBoxGrid>
        )}

        {/* Visualization Charts - Only show in chart mode */}
        {viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  data-learn="Top Domains Chart: Bar chart showing the most frequently queried domain names."
                  key={`top-by-queries-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/top-by-queries`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Domains by Query Count"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  data-learn="TLD Distribution: Pie chart showing the distribution of top-level domains (.com, .org, etc.)."
                  key={`tlds-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/tlds?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="TLD Distribution"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  data-learn="Record Types: Bar chart showing DNS query types (A, AAAA, CNAME, MX, etc.)."
                  key={`record-types-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/record-types`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="DNS Record Types"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  data-learn="Subdomain Distribution: Pie chart comparing root domain queries vs subdomain queries."
                  key={`subdomain-distribution-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/subdomain-distribution`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Subdomain Distribution"
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
            placeholder="Search domains..."
            learnHint="Domain Search: Filter domains by name, parent domain, record type, or resolved IP address. Use !term to exclude matches."
          />
          
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <Select
              data-learn="Domain Type Filter: Filter to show all domains, only root domains, or only subdomains."
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as 'all' | 'root' | 'subdomain');
                setPage(0);
              }}
            >
              <MenuItem value="all">All Domains</MenuItem>
              <MenuItem value="root">Root Domains</MenuItem>
              <MenuItem value="subdomain">Subdomains</MenuItem>
            </Select>
          </FormControl>
          
          <Button
            data-learn="Refresh Button: Reload domain data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {(searchQuery || filterType !== 'all') ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredDomains.length} of {totalCount} domains
            </Typography>
          ) : null}
        </Box>

        {/* Domains Table */}
        {!domainsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <LanguageIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Domains Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No DNS queries have been captured yet.
            </Typography>
          </Paper>
        ) : (
          <ResponsiveDataView<DomainSummary>
            data={paginatedDomains}
            totalCount={filteredDomains.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(domain) => handleRowClick(domain.domain)}
            renderCard={(domain) => (
              <Card variant="outlined">
                <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                  <Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>
                    {domain.domain}
                  </Typography>
                  <Box display="flex" gap={2} mt={0.5} flexWrap="wrap">
                    <Typography variant="caption" color="text.secondary">
                      {domain.queryCount.toLocaleString()} queries
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {domain.uniqueClients.toLocaleString()} clients
                    </Typography>
                  </Box>
                  {(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length > 0 && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5} noWrap>
                      IPs: {(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').slice(0, 3).join(', ')}
                      {(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length > 3 ? ` +${(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length - 3}` : ''}
                    </Typography>
                  )}
                  <Box display="flex" gap={1} mt={0.5} flexWrap="wrap">
                    <Typography variant="caption" color="text.secondary">
                      First: {formatTimestamp(domain.firstSeen)}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Last: {formatTimestamp(domain.lastSeen)}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            )}
            desktopTable={
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Domains Table: Detailed list of all discovered domains with query statistics and sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Domain: Click to sort domains alphabetically by name."
                        active={sortField === 'domain'}
                        direction={sortField === 'domain' ? sortOrder : 'asc'}
                        onClick={() => handleSort('domain')}
                      >
                        Domain Name
                      </TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                      <TableSortLabel
                        data-learn="Sort by Type: Click to sort by domain type (root domain vs subdomain)."
                        active={sortField === 'type'}
                        direction={sortField === 'type' ? sortOrder : 'asc'}
                        onClick={() => handleSort('type')}
                      >
                        Type
                      </TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }} data-learn="Source: Where the domain was discovered - DNS queries or TLS SNI.">
                      Source
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Queries: Click to sort domains by number of DNS queries."
                        active={sortField === 'queries'}
                        direction={sortField === 'queries' ? sortOrder : 'asc'}
                        onClick={() => handleSort('queries')}
                      >
                        Queries
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Clients: Click to sort by number of unique clients querying this domain."
                        active={sortField === 'clients'}
                        direction={sortField === 'clients' ? sortOrder : 'asc'}
                        onClick={() => handleSort('clients')}
                      >
                        Clients
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>Record Types</TableCell>
                    <TableCell>Resolved IPs</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedDomains.map((domain) => (
                    <>
                      <TableRow 
                        key={domain.domain}
                        data-row-key={domain.domain}
                        hover
                        onClick={() => handleRowClick(domain.domain)}
                        sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                        data-learn="Domain Row: Click to expand and view detailed information about this domain. Use ↑↓ arrows to navigate between rows when expanded."
                      >
                        <TableCell>
                          <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed domain information.">
                            <ExpandMoreIcon 
                              sx={{ 
                                transform: expandedRow === domain.domain ? 'rotate(180deg)' : 'rotate(0deg)',
                                transition: 'transform 0.3s'
                              }} 
                            />
                          </IconButton>
                        </TableCell>
                        <TableCell>
                          <Tooltip title={domain.domain} placement="top">
                            <Typography 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                fontWeight: 'medium',
                                maxWidth: '400px',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}
                              data-learn="Domain Name: The fully qualified domain name extracted from DNS queries."
                            >
                              {domain.domain}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                          <Chip
                            data-learn="Domain Type Tag: Indicates whether this is a root domain or a subdomain."
                            label={domain.isSubdomain ? 'Subdomain' : 'Root'}
                            size="small"
                            color={domain.isSubdomain ? 'secondary' : 'primary'}
                            sx={{ fontSize: '0.7rem' }}
                          />
                        </TableCell>
                        <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                          <Chip
                            data-learn="Source Tag: Shows where this domain was discovered - DNS queries, TLS SNI, or both."
                            label={domain.source || 'DNS'}
                            size="small"
                            color={domain.source?.includes('TLS') ? 'success' : 'default'}
                            variant="outlined"
                            sx={{ fontSize: '0.7rem' }}
                          />
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {domain.queryCount.toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {domain.uniqueClients.toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(domain.recordTypes || []).slice(0, 3).map((rt) => (
                              <Chip
                                key={rt}
                                label={rt}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn="Record Type: DNS query type (A for IPv4, AAAA for IPv6, CNAME for alias, etc.)."
                              />
                            ))}
                            {(domain.recordTypes || []).length > 3 && (
                              <Chip
                                label={`+${(domain.recordTypes || []).length - 3}`}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn="More Record Types: Click the row to see all DNS record types."
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').slice(0, 2).map((ip) => (
                              <Chip
                                key={ip}
                                label={ip}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20, fontFamily: 'monospace' }}
                                data-learn="Resolved IP: IP address that this domain name resolved to in DNS responses."
                              />
                            ))}
                            {(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length > 2 && (
                              <Chip
                                label={`+${(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length - 2}`}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn="More IPs: Click the row to see all resolved IP addresses."
                              />
                            )}
                          </Box>
                        </TableCell>
                      </TableRow>
                      
                      {/* Expandable Row Details */}
                      <TableRow>
                        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={8}>
                          <Collapse in={expandedRow === domain.domain} timeout="auto" unmountOnExit>
                            <Box sx={{ py: 2 }} data-learn="Domain Details: Extended information about DNS queries and responses for this domain.">
                              <Grid container spacing={2}>
                                {/* Time Range */}
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Query Timeline
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    First Seen: {formatTimestamp(domain.firstSeen)}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Last Seen: {formatTimestamp(domain.lastSeen)}
                                  </Typography>
                                </Grid>
                                
                                {/* Statistics */}
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Statistics
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Total Queries: {domain.queryCount.toLocaleString()}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Unique Clients: {domain.uniqueClients.toLocaleString()}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Source: {domain.source || 'DNS'}
                                  </Typography>
                                  {domain.isSubdomain && domain.parentDomain && (
                                    <Typography variant="body2" color="text.secondary">
                                      Parent Domain: {domain.parentDomain}
                                    </Typography>
                                  )}
                                </Grid>
                                
                                {/* All Record Types */}
                                {(domain.recordTypes || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      All Record Types ({(domain.recordTypes || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(domain.recordTypes || []).map((rt) => (
                                        <Chip
                                          key={rt}
                                          label={rt}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* Response Codes */}
                                {(domain.responseCodes || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      DNS Response Codes
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(domain.responseCodes || []).map((rc) => {
                                        const responseCodeName = rc === 0 ? 'Success' : 
                                                               rc === 1 ? 'Format Error' :
                                                               rc === 2 ? 'Server Failure' :
                                                               rc === 3 ? 'Name Error' :
                                                               rc === 4 ? 'Not Implemented' :
                                                               rc === 5 ? 'Refused' :
                                                               `Code ${rc}`;
                                        return (
                                          <Chip
                                            key={rc}
                                            label={`${responseCodeName} (${rc})`}
                                            size="small"
                                            color={rc === 0 ? 'success' : 'error'}
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        );
                                      })}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* All Resolved IPs */}
                                {(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      All Resolved IP Addresses ({(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').map((ip) => (
                                        <Chip
                                          key={ip}
                                          label={ip}
                                          size="small"
                                          color="info"
                                          sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* Community IDs for Cross-Tool Correlation */}
                                {(domain.communityIds || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Community IDs: Corelight Community ID v1 for cross-tool correlation with Zeek, Suricata, and other network security tools. Click to filter all pages by this ID.">
                                      Community IDs ({(domain.communityIds || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(domain.communityIds || []).slice(0, 10).map((cid) => (
                                        <CommunityIDChip key={cid} communityId={cid} mode="chip" />
                                      ))}
                                      {(domain.communityIds || []).length > 10 && (
                                        <Chip
                                          label={`+${(domain.communityIds || []).length - 10} more`}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      )}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* Custom row actions from parent */}
                                {rowActions && (
                                  <Grid item xs={12}>
                                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                      {rowActions(domain)}
                                    </Box>
                                  </Grid>
                                )}
                              </Grid>
                            </Box>
                          </Collapse>
                        </TableCell>
                      </TableRow>
                    </>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            }
          />
        )}
        </>
        )}
      </Box>
    </Layout>
  );
}

