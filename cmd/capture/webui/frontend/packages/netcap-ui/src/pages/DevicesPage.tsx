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

import { useState, useMemo, useEffect, useCallback } from 'react';
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
  Router as RouterIcon,
  Memory as MemoryIcon,
  Devices as DevicesIcon,
  Business as BusinessIcon,
  TrendingUp as TrendingUpIcon,
  Apps as AppsIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';

import { ChartFrame } from '../components/ChartFrame';
interface DeviceProfileSummary {
  macAddr: string;
  deviceManufacturer: string;
  numDeviceIPs: number;
  numContacts: number;
  numPackets: number;
  bytes: number;
  timestamp: number;  // Unix timestamp in nanoseconds from backend
  applications: string[];
  devices: string[];
  deviceIPs: string[];
  contacts: string[];
  hostnames: string[];
  deviceTypes: string[];
  os: string;
  roles: string[];
}

interface DevicesResponse {
  devices: DeviceProfileSummary[];
  totalCount: number;
}

type DeviceSortField = 'macAddr' | 'manufacturer' | 'packets' | 'bytes' | 'ips' | 'contacts';
type SortOrder = 'asc' | 'desc';

export default function DevicesPage() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<DeviceSortField>('macAddr');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
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

  // Fetch devices data
  const { data: devicesData, error, mutate } = useSWR<DevicesResponse>(
    'devices',
    () => fetch(`${getBackendUrl()}/api/devices`).then(res => res.json()),
    {
      refreshInterval: 10000,
    }
  );

  const devices = devicesData?.devices || [];
  const totalCount = devicesData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: DeviceSortField) => {
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
  const filteredDevices = useMemo(() => {
    let filtered = devices;

    // Apply search filter with negation support (e.g., "!Apple" excludes Apple devices)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(d =>
        matchesSearchTerms([
          d.macAddr,
          d.deviceManufacturer || '',
          ...(d.devices || []),
          ...(d.applications || []),
        ], searchTerms)
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'macAddr':
          comparison = a.macAddr.localeCompare(b.macAddr);
          break;
        case 'manufacturer':
          comparison = (a.deviceManufacturer || '').localeCompare(b.deviceManufacturer || '');
          break;
        case 'packets':
          comparison = a.numPackets - b.numPackets;
          break;
        case 'bytes':
          comparison = a.bytes - b.bytes;
          break;
        case 'ips':
          comparison = a.numDeviceIPs - b.numDeviceIPs;
          break;
        case 'contacts':
          comparison = a.numContacts - b.numContacts;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [devices, searchQuery, sortField, sortOrder]);

  // Paginate devices
  const paginatedDevices = filteredDevices.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedDevices.map(device => device.macAddr),
    [paginatedDevices]
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

  const handleRowClick = useCallback((macAddr: string) => {
    setExpandedRow(prev => prev === macAddr ? null : macAddr);
  }, []);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their identified network devices and hardware."
    />
  );

  if (error) {
    return (
      <Layout title="Devices" headerAction={fileSelector}>
        <Alert severity="error">Error loading devices: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Devices" headerAction={fileSelector}>
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
            icon={<RouterIcon color="primary" />}
            label="Total Devices"
            value={totalCount}
          />
          <StatBox
            icon={<BusinessIcon color="success" />}
            label="Unique Vendors"
            value={new Set(devices.map(d => d.deviceManufacturer).filter(m => m)).size}
          />
          <StatBox
            icon={<MemoryIcon color="warning" />}
            label="Device Types"
            value={new Set(devices.flatMap(d => d.devices || [])).size}
          />
          <StatBox
            icon={<TrendingUpIcon color="info" />}
            label="Total Traffic"
            value={formatBytes(devices.reduce((sum, d) => sum + d.bytes, 0))}
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
                  key={`mac-vendors-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/mac-vendors`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top MAC Vendors"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  key={`traffic-dist-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/traffic-distribution?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Traffic Distribution"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  key={`hardware-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/hardware`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Device Types"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  key={`operating-systems-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/operating-systems?showLegend=false`}
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
          
          <Grid item xs={12}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <ChartFrame
                  key={`applications-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/applications`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Applications"
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
            placeholder="Search devices..."
            learnHint="Search Devices: Filter the devices table by MAC address, manufacturer, device type, or application name. Use !term to exclude matches (e.g., !Apple excludes Apple devices)."
          />
          
          <Button 
            data-learn="Refresh Devices: Reload device data and visualization charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredDevices.length} of {totalCount} devices
            </Typography>
          ) : null}
        </Box>

        {/* Devices Table */}
        {!devicesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <RouterIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Devices Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No device profiles have been captured yet.
            </Typography>
          </Paper>
        ) : (
          <ResponsiveDataView<DeviceProfileSummary>
            data={paginatedDevices}
            totalCount={filteredDevices.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(device) => handleRowClick(device.macAddr)}
            renderCard={(device) => (
              <Card variant="outlined">
                <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                  <Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>
                    {device.macAddr}
                  </Typography>
                  {device.deviceManufacturer && (
                    <Typography variant="caption" color="text.secondary" display="block">
                      {device.deviceManufacturer}
                    </Typography>
                  )}
                  <Box display="flex" gap={2} mt={0.5} flexWrap="wrap">
                    <Typography variant="caption" color="text.secondary">
                      {device.numPackets.toLocaleString()} pkts
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {formatBytes(device.bytes)}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {device.numDeviceIPs} IPs
                    </Typography>
                  </Box>
                  {device.os && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                      OS: {device.os}
                    </Typography>
                  )}
                  {(device.devices || []).length > 0 && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5} noWrap>
                      Types: {(device.devices || []).slice(0, 2).join(', ')}{(device.devices || []).length > 2 ? ` +${(device.devices || []).length - 2}` : ''}
                    </Typography>
                  )}
                </CardContent>
              </Card>
            )}
            desktopTable={
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        active={sortField === 'macAddr'}
                        direction={sortField === 'macAddr' ? sortOrder : 'asc'}
                        onClick={() => handleSort('macAddr')}
                      >
                        MAC Address
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        active={sortField === 'manufacturer'}
                        direction={sortField === 'manufacturer' ? sortOrder : 'asc'}
                        onClick={() => handleSort('manufacturer')}
                      >
                        Manufacturer
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        active={sortField === 'packets'}
                        direction={sortField === 'packets' ? sortOrder : 'asc'}
                        onClick={() => handleSort('packets')}
                      >
                        Packets
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        active={sortField === 'bytes'}
                        direction={sortField === 'bytes' ? sortOrder : 'asc'}
                        onClick={() => handleSort('bytes')}
                      >
                        Bytes
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        active={sortField === 'ips'}
                        direction={sortField === 'ips' ? sortOrder : 'asc'}
                        onClick={() => handleSort('ips')}
                      >
                        IPs
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        active={sortField === 'contacts'}
                        direction={sortField === 'contacts' ? sortOrder : 'asc'}
                        onClick={() => handleSort('contacts')}
                      >
                        Contacts
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>Device Types</TableCell>
                    <TableCell>Applications</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedDevices.map((device) => (
                    <>
                      <TableRow 
                        key={device.macAddr}
                        data-row-key={device.macAddr}
                        hover
                        onClick={() => handleRowClick(device.macAddr)}
                        sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                        data-learn="Device Row: Click to expand and view detailed information about this device. Use ↑↓ arrows to navigate between rows when expanded."
                      >
                        <TableCell>
                          <IconButton size="small">
                            <ExpandMoreIcon 
                              sx={{ 
                                transform: expandedRow === device.macAddr ? 'rotate(180deg)' : 'rotate(0deg)',
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
                          >
                            {device.macAddr}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {device.deviceManufacturer ? (
                            <Chip
                              label={device.deviceManufacturer}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }}
                            />
                          ) : (
                            <Typography variant="body2" color="text.secondary">
                              Unknown
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {device.numPackets.toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {formatBytes(device.bytes)}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {device.numDeviceIPs}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {device.numContacts}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(device.devices || []).slice(0, 2).map((dev) => (
                              <Chip
                                key={dev}
                                label={dev}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                              />
                            ))}
                            {(device.devices || []).length > 2 && (
                              <Chip
                                label={`+${(device.devices || []).length - 2}`}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(device.applications || []).slice(0, 2).map((app) => (
                              <Chip
                                key={app}
                                label={app}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                              />
                            ))}
                            {(device.applications || []).length > 2 && (
                              <Chip
                                label={`+${(device.applications || []).length - 2}`}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                              />
                            )}
                          </Box>
                        </TableCell>
                      </TableRow>
                      
                      {/* Expandable Row Details */}
                      <TableRow>
                        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={9}>
                          <Collapse in={expandedRow === device.macAddr} timeout="auto" unmountOnExit>
                            <Box sx={{ py: 2 }}>
                              <Grid container spacing={2}>
                                {/* Time Info */}
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    First Seen
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    {formatTimestamp(device.timestamp)}
                                  </Typography>
                                </Grid>
                                
                                {/* Statistics */}
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Statistics
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Packets: {device.numPackets.toLocaleString()}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Bytes: {formatBytes(device.bytes)}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Device IPs: {device.numDeviceIPs}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Contacts: {device.numContacts}
                                  </Typography>
                                </Grid>
                                
                                {/* Network Discovery: Hostnames */}
                                {(device.hostnames || []).length > 0 && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Discovered Hostnames
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(device.hostnames || []).map((h) => (
                                        <Chip
                                          key={h}
                                          label={h}
                                          size="small"
                                          color="primary"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}

                                {/* Network Discovery: OS */}
                                {device.os && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Operating System / Firmware
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                                      {device.os}
                                    </Typography>
                                  </Grid>
                                )}

                                {/* Network Discovery: Device Types */}
                                {(device.deviceTypes || []).length > 0 && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Discovered Device Types
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(device.deviceTypes || []).map((dt) => (
                                        <Chip
                                          key={dt}
                                          label={dt}
                                          size="small"
                                          color="warning"
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}

                                {/* Network Discovery: Roles */}
                                {(device.roles || []).length > 0 && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Network Roles
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(device.roles || []).map((r) => (
                                        <Chip
                                          key={r}
                                          label={r}
                                          size="small"
                                          color="secondary"
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}

                                {/* All Device IPs */}
                                {(device.deviceIPs || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Device IP Addresses ({(device.deviceIPs || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(device.deviceIPs || []).map((ip) => (
                                        <Chip
                                          key={ip}
                                          label={ip}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* All Device Types */}
                                {(device.devices || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      All Device Types ({(device.devices || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(device.devices || []).map((dev) => (
                                        <Chip
                                          key={dev}
                                          label={dev}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* All Applications */}
                                {(device.applications || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      All Applications ({(device.applications || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(device.applications || []).map((app) => (
                                        <Chip
                                          key={app}
                                          label={app}
                                          size="small"
                                          color="info"
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* Contacted IPs (top 20) */}
                                {(device.contacts || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Contacted IPs ({(device.contacts || []).length} total, showing top 20)
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(device.contacts || []).slice(0, 20).map((contact) => (
                                        <Chip
                                          key={contact}
                                          label={contact}
                                          size="small"
                                          variant="outlined"
                                          color="secondary"
                                          sx={{ fontSize: '0.7rem', fontFamily: 'monospace' }}
                                        />
                                      ))}
                                      {(device.contacts || []).length > 20 && (
                                        <Chip
                                          label={`+${(device.contacts || []).length - 20} more`}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.7rem' }}
                                        />
                                      )}
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

