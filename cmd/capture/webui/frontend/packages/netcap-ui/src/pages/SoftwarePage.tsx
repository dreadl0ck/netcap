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
  Memory as MemoryIcon,
  Computer as ComputerIcon,
  Apps as AppsIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Cable as CableIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

import { ChartFrame } from '../components/ChartFrame';
interface SoftwareSummary {
  product: string;
  version: string;
  os: string;
  count: number;
  devices: string[];
  services: string[];
  dpiResults: string[];
  firstSeen: number;
  lastSeen: number;
  sourceNames: string[];
  flows: string[];
  // Detection context
  detectionMethod: string;
  confidenceLevel: string;
  // Behavioral fingerprint
  behaviorProfile: string;
  isHeadless: boolean;
  isEmulated: boolean;
  isAutomated: boolean;
  // Risk indicators
  hasKnownVulnerabilities: boolean;
  isEndOfLife: boolean;
  supportStatus: string;
  // Community ID for cross-tool correlation
  communityIds: string[];
}

interface SoftwareResponse {
  software: SoftwareSummary[];
  totalCount: number;
}

type SoftwareSortField = 'product' | 'version' | 'count' | 'devices';
type SortOrder = 'asc' | 'desc';

export default function SoftwarePage() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<SoftwareSortField>('count');
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

  // Fetch software data
  const { data: softwareData, error, mutate } = useSWR<SoftwareResponse>(
    'software',
    () => fetch(`${getBackendUrl()}/api/software`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const software = softwareData?.software || [];
  const totalCount = softwareData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: SoftwareSortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0);
  };

  // Apply filters and sorting
  const filteredSoftware = useMemo(() => {
    let filtered = software;

    // Apply Community ID filter first (if active)
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(sw => 
        sw.communityIds && sw.communityIds.some(cid => selectedCommunityIDs.has(cid))
      );
    }

    // Apply search filter with negation support (e.g., "!Windows" excludes Windows software)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(sw =>
        matchesSearchTerms([
          sw.product,
          sw.version || '',
          sw.os || '',
          ...(sw.devices || []),
          ...(sw.services || []),
        ], searchTerms)
      );
    }

    // Apply sorting with stable secondary sort by product and version
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'product':
          comparison = a.product.localeCompare(b.product);
          break;
        case 'version':
          comparison = (a.version || '').localeCompare(b.version || '');
          break;
        case 'count':
          comparison = a.count - b.count;
          break;
        case 'devices':
          comparison = a.devices.length - b.devices.length;
          break;
      }
      // Stable secondary sort by product then version for consistent ordering
      if (comparison === 0) {
        comparison = a.product.localeCompare(b.product);
        if (comparison === 0) {
          comparison = (a.version || '').localeCompare(b.version || '');
        }
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [software, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs]);

  const paginatedSoftware = filteredSoftware.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedSoftware.map((sw, idx) => `${sw.product}-${sw.version}-${idx}`),
    [paginatedSoftware]
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
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their detected software and versions."
    />
  );

  // Calculate summary statistics
  const uniqueProducts = new Set(software.map(sw => sw.product)).size;
  const uniqueVersions = software.filter(sw => sw.version).length;
  const totalDetections = software.reduce((sum, sw) => sum + sw.count, 0);

  if (error) {
    return (
      <Layout title="Software" headerAction={fileSelector}>
        <Alert severity="error">Error loading software: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Software" headerAction={fileSelector}>
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
            icon={<AppsIcon color="primary" />}
            label="Unique Products"
            value={uniqueProducts}
            learnHint="Unique Products: Number of different software products detected in the network traffic."
          />
          <StatBox
            icon={<MemoryIcon color="warning" />}
            label="Versions Tracked"
            value={uniqueVersions}
            learnHint="Versions Tracked: Number of specific software versions detected."
          />
          <StatBox
            icon={<ComputerIcon color="info" />}
            label="Total Detections"
            value={totalDetections}
            learnHint="Total Detections: Total number of software detection events across all captures."
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
                  data-learn="Top Products: Bar chart showing the most frequently detected software products and versions."
                  key={`top-products-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/software/top-products`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Software Products"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  data-learn="Vendor Distribution: Pie chart showing the distribution of software by vendor/manufacturer."
                  key={`vendors-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/software/vendors?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Software Vendors"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  data-learn="Operating Systems: Bar chart showing detected operating systems from software analysis."
                  key={`operating-systems-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/software/operating-systems`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Operating Systems"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  data-learn="Version Hierarchy: Sunburst chart showing the relationship between products and their versions."
                  key={`versions-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/software/versions`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Software Versions"
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
            placeholder="Search software..."
            learnHint="Software Search: Filter software by product name, version, OS, device, or service. Use !term to exclude matches."
          />
          
          <Button
            data-learn="Refresh Button: Reload software data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredSoftware.length} of {totalCount} software entries
            </Typography>
          ) : null}
        </Box>

        {/* Software Table */}
        {!softwareData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <AppsIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Software Detected
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No software information has been captured yet.
            </Typography>
          </Paper>
        ) : (
          <ResponsiveDataView<SoftwareSummary>
            data={paginatedSoftware}
            totalCount={filteredSoftware.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(sw) => handleRowClick(`${sw.product}-${sw.version}-${paginatedSoftware.indexOf(sw)}`)}
            renderCard={(sw) => (
              <Card variant="outlined">
                <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                  <Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>
                    {sw.product}
                  </Typography>
                  <Box display="flex" gap={2} mt={0.5} flexWrap="wrap">
                    {sw.version && (
                      <Typography variant="caption" color="text.secondary">
                        v{sw.version}
                      </Typography>
                    )}
                    <Typography variant="caption" color="text.secondary">
                      {sw.count.toLocaleString()} detections
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {sw.devices.length} devices
                    </Typography>
                  </Box>
                  {sw.os && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                      OS: {sw.os}
                    </Typography>
                  )}
                </CardContent>
              </Card>
            )}
            desktopTable={
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Software Table: Detailed list of all detected software with versions and associated devices.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Product: Click to sort software by product name alphabetically."
                        active={sortField === 'product'}
                        direction={sortField === 'product' ? sortOrder : 'asc'}
                        onClick={() => handleSort('product')}
                      >
                        Product
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Version: Click to sort software by version number."
                        active={sortField === 'version'}
                        direction={sortField === 'version' ? sortOrder : 'asc'}
                        onClick={() => handleSort('version')}
                      >
                        Version
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Detections: Click to sort by number of times this software was detected."
                        active={sortField === 'count'}
                        direction={sortField === 'count' ? sortOrder : 'asc'}
                        onClick={() => handleSort('count')}
                      >
                        Detections
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Devices: Click to sort by number of devices using this software."
                        active={sortField === 'devices'}
                        direction={sortField === 'devices' ? sortOrder : 'asc'}
                        onClick={() => handleSort('devices')}
                      >
                        Devices
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>OS</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedSoftware.map((sw, idx) => {
                    const rowKey = `${sw.product}-${sw.version}-${idx}`;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Software Row: Click to expand and view detailed information about this software. Use ↑↓ arrows to navigate between rows when expanded."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed software information.">
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
                                fontWeight: 'medium'
                              }}
                              data-learn="Product Name: The name of the software product detected in the network."
                            >
                              {sw.product}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2"
                              sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                              data-learn="Version: Specific version number or identifier of the software."
                            >
                              {sw.version}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {sw.count.toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {sw.devices.length.toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {sw.os ? (
                              <Chip
                              data-learn="Operating System: The OS this software runs on or was detected from."
                              label={sw.os}
                              size="small"
                              color="info"
                              sx={{ fontSize: '0.7rem' }}
                            />
                            ) : ''}
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="Software Details: Extended information about this software including detection timeline, devices, services, and DPI results.">
                                <Grid container spacing={2}>
                                  {/* Time Range */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Detection Timeline
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      First Detected: {formatTimestamp(sw.firstSeen)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Last Detected: {formatTimestamp(sw.lastSeen)}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Statistics */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Statistics
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Total Detections: {sw.count.toLocaleString()}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Devices: {sw.devices.length.toLocaleString()}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Services: {sw.services.length.toLocaleString()}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Source Names */}
                                  {(sw.sourceNames || []).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Detection Sources ({(sw.sourceNames || []).length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {(sw.sourceNames || []).map((source) => (
                                          <Chip
                                            key={source}
                                            label={source}
                                            size="small"
                                            variant="outlined"
                                            color="secondary"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* DPI Results */}
                                  {(sw.dpiResults || []).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        DPI Detection Results ({(sw.dpiResults || []).length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {(sw.dpiResults || []).map((dpi) => (
                                          <Chip
                                            key={dpi}
                                            label={dpi}
                                            size="small"
                                            color="success"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}

                                  {/* Detection Context */}
                                  {(sw.detectionMethod || sw.confidenceLevel) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Detection Context: How this software was detected and confidence level of the identification.">
                                        Detection Context
                                      </Typography>
                                      {sw.detectionMethod && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                          <Typography variant="body2" color="text.secondary">
                                            Method:
                                          </Typography>
                                          <Chip 
                                            label={sw.detectionMethod} 
                                            size="small" 
                                            color="info"
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }}
                                          />
                                        </Box>
                                      )}
                                      {sw.confidenceLevel && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                          <Typography variant="body2" color="text.secondary">
                                            Confidence:
                                          </Typography>
                                          <Chip 
                                            label={sw.confidenceLevel} 
                                            size="small" 
                                            color={sw.confidenceLevel === 'high' ? 'success' : sw.confidenceLevel === 'medium' ? 'warning' : 'default'}
                                            sx={{ fontSize: '0.7rem' }}
                                          />
                                        </Box>
                                      )}
                                    </Grid>
                                  )}

                                  {/* Behavior Analysis */}
                                  {(sw.behaviorProfile || sw.isHeadless || sw.isEmulated || sw.isAutomated) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Behavior Analysis: Behavioral classification of the software based on observed patterns.">
                                        Behavior Analysis
                                      </Typography>
                                      {sw.behaviorProfile && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                          <Typography variant="body2" color="text.secondary">
                                            Profile:
                                          </Typography>
                                          <Chip 
                                            label={sw.behaviorProfile} 
                                            size="small" 
                                            color="secondary"
                                            sx={{ fontSize: '0.7rem' }}
                                          />
                                        </Box>
                                      )}
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
                                        {sw.isHeadless && (
                                          <Chip 
                                            label="Headless" 
                                            size="small" 
                                            color="warning"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn="Detected as running in headless mode (no UI)."
                                          />
                                        )}
                                        {sw.isEmulated && (
                                          <Chip 
                                            label="Emulated" 
                                            size="small" 
                                            color="warning"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn="Detected as running in an emulated environment."
                                          />
                                        )}
                                        {sw.isAutomated && (
                                          <Chip 
                                            label="Automated" 
                                            size="small" 
                                            color="warning"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn="Detected as automation tool (Selenium, Puppeteer, etc.)."
                                          />
                                        )}
                                      </Box>
                                    </Grid>
                                  )}

                                  {/* Security Status */}
                                  {(sw.hasKnownVulnerabilities || sw.isEndOfLife || sw.supportStatus) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Security Status: Risk indicators for this software version.">
                                        Security Status
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {sw.hasKnownVulnerabilities && (
                                          <Chip 
                                            label="⚠️ Known Vulnerabilities" 
                                            size="small" 
                                            color="error"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn="This software version has known security vulnerabilities."
                                          />
                                        )}
                                        {sw.isEndOfLife && (
                                          <Chip 
                                            label="⚠️ End of Life" 
                                            size="small" 
                                            color="error"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn="This software version is no longer receiving security updates."
                                          />
                                        )}
                                        {sw.supportStatus && (
                                          <Chip 
                                            label={`Support: ${sw.supportStatus}`} 
                                            size="small" 
                                            color={sw.supportStatus === 'active' ? 'success' : sw.supportStatus === 'maintenance' ? 'warning' : 'error'}
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }}
                                          />
                                        )}
                                        {!sw.hasKnownVulnerabilities && !sw.isEndOfLife && !sw.supportStatus && (
                                          <Chip 
                                            label="✓ No known issues" 
                                            size="small" 
                                            color="success"
                                            sx={{ fontSize: '0.7rem' }}
                                          />
                                        )}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Associated Devices */}
                                  {(sw.devices || []).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Associated Devices ({(sw.devices || []).length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {(sw.devices || []).map((device) => (
                                          <Chip
                                            key={device}
                                            label={device}
                                            size="small"
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }}
                                          />
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Associated Services */}
                                  {(sw.services || []).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Associated Services ({(sw.services || []).length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {(sw.services || []).map((service) => (
                                          <Chip
                                            key={service}
                                            label={service}
                                            size="small"
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Community IDs for Cross-Tool Correlation */}
                                  {(sw.communityIds || []).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Community IDs: Corelight Community ID v1 identifiers for cross-tool correlation with Zeek, Suricata, and other network security tools. Click to filter all pages by these IDs.">
                                        Community IDs ({(sw.communityIds || []).length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {(sw.communityIds || []).slice(0, 10).map((cid) => (
                                          <CommunityIDChip key={cid} communityId={cid} mode="chip" />
                                        ))}
                                        {(sw.communityIds || []).length > 10 && (
                                          <Chip
                                            label={`+${(sw.communityIds || []).length - 10} more`}
                                            size="small"
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        )}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Action Buttons */}
                                  {((sw.devices || []).length > 0 || (sw.flows || []).length > 0) && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Navigation
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                        {/* Show Connections button if flows are available */}
                                        {(sw.flows || []).length > 0 && (
                                          <Button
                                            data-learn="Show Connections: Navigate to Connections page with the first flow identifier to see network connections associated with this software."
                                            variant="outlined"
                                            color="primary"
                                            startIcon={<CableIcon />}
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              router.push(`/connections?search=${encodeURIComponent(sw.flows[0])}`);
                                            }}
                                            size="small"
                                          >
                                            Show Connections
                                          </Button>
                                        )}
                                        {/* Device-specific buttons */}
                                        {(sw.devices || []).map((device) => (
                                          <Button
                                            key={device}
                                            data-learn="View Connections: Navigate to Connections page filtered for this host to see all network connections from/to this device."
                                            variant="outlined"
                                            color="secondary"
                                            startIcon={<CableIcon />}
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              router.push(`/connections?search=${encodeURIComponent(device)}`);
                                            }}
                                            size="small"
                                          >
                                            Connections for {device}
                                          </Button>
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
            }
          />
        )}
        </>
        )}
      </Box>
    </Layout>
  );
}

