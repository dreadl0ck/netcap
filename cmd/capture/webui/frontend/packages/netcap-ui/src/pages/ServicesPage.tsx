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

import React, { useState, useMemo, useEffect, useCallback } from 'react';
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
  Build as BuildIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingUpIcon,
  DeviceHub as DeviceHubIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Cable as CableIcon,
  Search as SearchIcon,
  Add as AddIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';

interface ServiceSummary {
  timestamp: number;
  ip: string;
  port: number;
  name: string;
  banner: string;
  protocol: string;
  numFlows: number;
  product: string;
  vendor: string;
  version: string;
  notes: string;
  bytesServer: number;
  bytesClient: number;
  hostname: string;
  os: string;
  applications: string[];
  portName: string;
  detectedProtocolName: string;
  matchedProbeID: string;
}

interface ServicesResponse {
  services: ServiceSummary[];
  totalCount: number;
}

type ServiceSortField = 'ip' | 'port' | 'protocol' | 'flows' | 'bytes';
type SortOrder = 'asc' | 'desc';

export default function ServicesPage() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<ServiceSortField>('bytes');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

  // Initialize search query from URL parameter
  useEffect(() => {
    if (router.isReady && router.query.search && typeof router.query.search === 'string') {
      setSearchQuery(router.query.search);
      setPage(0);
    }
  }, [router.isReady, router.query.search]);

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch services data
  const { data: servicesData, error, mutate } = useSWR<ServicesResponse>(
    'services',
    () => fetch(`${getBackendUrl()}/api/services`).then(res => res.json()),
    {
      refreshInterval: 10000,
    }
  );

  const services = servicesData?.services || [];
  const totalCount = servicesData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: ServiceSortField) => {
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
  const filteredServices = useMemo(() => {
    let filtered = services;

    // Apply search filter with negation support (e.g., "!SSH" excludes SSH services)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(s =>
        matchesSearchTerms([
          s.ip,
          s.port.toString(),
          s.name || '',
          s.protocol || '',
          s.product || '',
          s.vendor || '',
          s.hostname || '',
          s.portName || '',
          ...(s.applications || []),
        ], searchTerms)
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'ip':
          comparison = a.ip.localeCompare(b.ip);
          break;
        case 'port':
          comparison = a.port - b.port;
          break;
        case 'protocol':
          const protoA = a.protocol || '';
          const protoB = b.protocol || '';
          comparison = protoA.localeCompare(protoB);
          break;
        case 'flows':
          comparison = a.numFlows - b.numFlows;
          break;
        case 'bytes':
          const totalBytesA = a.bytesServer + a.bytesClient;
          const totalBytesB = b.bytesServer + b.bytesClient;
          comparison = totalBytesA - totalBytesB;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [services, searchQuery, sortField, sortOrder]);

  // Paginate services
  const paginatedServices = filteredServices.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedServices.map((svc, idx) => `${svc.ip}-${svc.port}-${idx}`),
    [paginatedServices]
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
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their discovered network services."
    />
  );

  // Calculate summary statistics
  const totalBytes = services.reduce((sum, s) => sum + s.bytesServer + s.bytesClient, 0);
  const totalFlows = services.reduce((sum, s) => sum + s.numFlows, 0);
  const uniqueProtocols = new Set(services.map(s => s.protocol)).size;
  const uniquePorts = new Set(services.map(s => s.port)).size;

  if (error) {
    return (
      <Layout title="Services" headerAction={fileSelector}>
        <Alert severity="error">Error loading services: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Services" headerAction={fileSelector}>
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
            icon={<BuildIcon color="primary" />}
            label="Total Services"
            value={totalCount}
            learnHint="Total Services: Number of network services discovered in this PCAP file."
          />
          <StatBox
            icon={<TrendingUpIcon color="success" />}
            label="Total Traffic"
            value={formatBytes(totalBytes)}
            learnHint="Total Traffic: Sum of all bytes transferred to and from all services."
          />
          <StatBox
            icon={<DeviceHubIcon color="warning" />}
            label="Total Flows"
            value={totalFlows}
            learnHint="Total Flows: Total number of network flows across all services."
          />
          <StatBox
            icon={<SpeedIcon color="info" />}
            label="Unique Ports"
            value={uniquePorts}
            learnHint="Unique Ports: Number of different service ports discovered in the capture."
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
                  data-learn="Top Services Chart: Bar chart showing the services with the most traffic."
                  key={`top-by-traffic-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/services/top-by-traffic`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Services by Traffic"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Protocol Distribution: Pie chart showing the distribution of protocols across services."
                  key={`protocols-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/services/protocols?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Protocol Distribution"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top Ports Chart: Bar chart showing the most commonly used service ports."
                  key={`top-ports-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/services/top-ports`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Service Ports"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top Products Chart: Bar chart showing the most common software products and vendors detected on services."
                  key={`top-products-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/services/top-products`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Service Products"
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
            placeholder="Search services..."
            learnHint="Service Search: Filter services by IP address, port, protocol, product, vendor, hostname, or applications. Use !term to exclude matches (e.g., !SSH excludes SSH services)."
          />
          
          <Button
            data-learn="Refresh Button: Reload service data from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredServices.length} of {totalCount} services
            </Typography>
          ) : null}
        </Box>

        {/* Services Table */}
        {!servicesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <BuildIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Services Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No service records have been captured yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Services Table: Detailed list of all discovered network services with sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by IP: Click to sort services by IP address."
                        active={sortField === 'ip'}
                        direction={sortField === 'ip' ? sortOrder : 'asc'}
                        onClick={() => handleSort('ip')}
                      >
                        IP Address
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Port: Click to sort services by port number."
                        active={sortField === 'port'}
                        direction={sortField === 'port' ? sortOrder : 'asc'}
                        onClick={() => handleSort('port')}
                      >
                        Port
                      </TableSortLabel>
                    </TableCell>
                    <TableCell data-learn="Service Name: Official IANA service name for this port if available.">
                      Service
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Protocol: Click to sort services by protocol type."
                        active={sortField === 'protocol'}
                        direction={sortField === 'protocol' ? sortOrder : 'asc'}
                        onClick={() => handleSort('protocol')}
                      >
                        Protocol
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Flows: Click to sort services by number of network flows."
                        active={sortField === 'flows'}
                        direction={sortField === 'flows' ? sortOrder : 'asc'}
                        onClick={() => handleSort('flows')}
                      >
                        Flows
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Bytes: Click to sort services by total data transferred."
                        active={sortField === 'bytes'}
                        direction={sortField === 'bytes' ? sortOrder : 'asc'}
                        onClick={() => handleSort('bytes')}
                      >
                        Bytes
                      </TableSortLabel>
                    </TableCell>
                    <TableCell data-learn="Product: Detected software product/vendor running this service.">
                      Product
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedServices.map((svc, idx) => {
                    const rowKey = `${svc.ip}-${svc.port}-${idx}`;
                    const totalBytes = svc.bytesServer + svc.bytesClient;
                    return (
                      <React.Fragment key={rowKey}>
                        <TableRow 
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Service Row: Click to expand and view detailed information about this service. Use ↑↓ arrows to navigate between rows when expanded."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed service information.">
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
                                color: '#2196f3',
                                fontWeight: 'bold',
                              }}
                              data-learn="Service IP: IP address where this service is running."
                            >
                              {svc.ip}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2"
                              sx={{ 
                                fontFamily: 'monospace',
                                color: '#FFB74D',
                                fontWeight: 'medium',
                              }}
                            >
                              {svc.port}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {svc.portName ? (
                              <Chip
                                data-learn="Port Name: Official IANA service name for this port number."
                                label={svc.portName}
                                size="small"
                                color="secondary"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem' }}
                              />
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
                                {svc.name || '-'}
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="Protocol: Network protocol used by this service."
                              label={svc.protocol || 'Unknown'}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {svc.numFlows.toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {formatBytes(totalBytes)}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {svc.product ? (
                              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                                <Typography variant="body2" sx={{ fontWeight: 'medium', fontSize: '0.8rem' }}>
                                  {svc.product}
                                </Typography>
                                {svc.vendor && (
                                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                    {svc.vendor}
                                  </Typography>
                                )}
                              </Box>
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
                                -
                              </Typography>
                            )}
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={8}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="Service Details: Extended information about this network service including banner, version, hostname, and traffic statistics.">
                                <Grid container spacing={2}>
                                  {/* Service Information */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Service Information
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Timestamp: {formatTimestamp(svc.timestamp)}
                                    </Typography>
                                    {svc.name && (
                                      <Typography variant="body2" color="text.secondary">
                                        Name: {svc.name}
                                      </Typography>
                                    )}
                                    {svc.protocol && (
                                      <Typography variant="body2" color="text.secondary">
                                        Protocol: {svc.protocol}
                                      </Typography>
                                    )}
                                    {svc.detectedProtocolName && (
                                      <Typography variant="body2" color="text.secondary">
                                        Detected Protocol: {svc.detectedProtocolName}
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Product & Version */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Product & Version
                                    </Typography>
                                    {svc.product && (
                                      <Typography variant="body2" color="text.secondary">
                                        Product: {svc.product}
                                      </Typography>
                                    )}
                                    {svc.vendor && (
                                      <Typography variant="body2" color="text.secondary">
                                        Vendor: {svc.vendor}
                                      </Typography>
                                    )}
                                    {svc.version && (
                                      <Typography variant="body2" color="text.secondary">
                                        Version: {svc.version}
                                      </Typography>
                                    )}
                                    {svc.os && (
                                      <Typography variant="body2" color="text.secondary">
                                        OS: {svc.os}
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Traffic Statistics */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Traffic Statistics
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Total Bytes: {formatBytes(totalBytes)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Bytes Server→Client: {formatBytes(svc.bytesServer)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Bytes Client→Server: {formatBytes(svc.bytesClient)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Number of Flows: {svc.numFlows.toLocaleString()}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Host Information */}
                                  {(svc.hostname || svc.banner) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Host Information
                                      </Typography>
                                      {svc.hostname && (
                                        <Typography variant="body2" color="text.secondary">
                                          Hostname: {svc.hostname}
                                        </Typography>
                                      )}
                                      {svc.banner && (
                                        <Typography 
                                          variant="body2" 
                                          color="text.secondary"
                                          sx={{ 
                                            fontFamily: 'monospace',
                                            fontSize: '0.75rem',
                                            whiteSpace: 'pre-wrap',
                                            wordBreak: 'break-all'
                                          }}
                                        >
                                          Banner:{'\n'}{svc.banner}
                                        </Typography>
                                      )}
                                    </Grid>
                                  )}
                                  
                                  {/* Applications */}
                                  {(svc.applications || []).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Detected Applications ({(svc.applications || []).length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {(svc.applications || []).map((app) => (
                                          <Chip
                                            key={app}
                                            label={app}
                                            size="small"
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }}
                                            data-learn="Application: Application detected by Deep Packet Inspection (DPI)."
                                          />
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Notes */}
                                  {svc.notes && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Notes
                                      </Typography>
                                      <Typography variant="body2" color="text.secondary">
                                        {svc.notes}
                                      </Typography>
                                    </Grid>
                                  )}
                                  
                                  {/* Action Buttons */}
                                  <Grid item xs={12}>
                                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                      <Button
                                        data-learn="Show Connections: Navigate to the Connections page filtered for this service's IP address and port."
                                        variant="outlined"
                                        color="primary"
                                        startIcon={<CableIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          router.push(`/connections?search=${encodeURIComponent(`${svc.ip}:${svc.port}`)}`);
                                        }}
                                        size="small"
                                      >
                                        Show Connections
                                      </Button>
                                      {svc.product && svc.matchedProbeID && (
                                        <Button
                                          data-learn="View Probe: Navigate to the Probes page to view details about the probe that matched this service."
                                          variant="outlined"
                                          color="primary"
                                          startIcon={<SearchIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/probes?search=${encodeURIComponent(svc.matchedProbeID)}`);
                                          }}
                                          size="small"
                                        >
                                          View Probe
                                        </Button>
                                      )}
                                      {svc.banner && (
                                        <Button
                                          data-learn="Create Probe: Create a new service probe using this service's banner as test input. Opens the Probes page with the banner pre-filled."
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<AddIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/probes?create=true&banner=${encodeURIComponent(svc.banner)}`);
                                          }}
                                          size="small"
                                        >
                                          Create Probe
                                        </Button>
                                      )}
                                    </Box>
                                  </Grid>
                                </Grid>
                              </Box>
                            </Collapse>
                          </TableCell>
                        </TableRow>
                      </React.Fragment>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              data-learn="Table Pagination: Navigate through pages of services and change how many rows to display per page."
              component="div"
              count={filteredServices.length}
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

