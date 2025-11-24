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
  TablePagination,
  TableRow,
  TableSortLabel,
  TextField,
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
import Layout from '@/components/Layout';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatBytes, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';

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
}

interface DevicesResponse {
  devices: DeviceProfileSummary[];
  totalCount: number;
}

type DeviceSortField = 'macAddr' | 'manufacturer' | 'packets' | 'bytes' | 'ips' | 'contacts';
type SortOrder = 'asc' | 'desc';

export default function DevicesPage() {
  const router = useRouter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<DeviceSortField>('macAddr');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const [viewMode, setViewMode] = useState<'table' | 'chart'>('table');

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

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(d =>
        d.macAddr.toLowerCase().includes(query) ||
        (d.deviceManufacturer || '').toLowerCase().includes(query) ||
        (d.devices || []).some(dev => dev.toLowerCase().includes(query)) ||
        (d.applications || []).some(a => a.toLowerCase().includes(query))
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
  }, [mutateStatus, mutate]);

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

        {/* Summary Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <RouterIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Devices
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
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <BusinessIcon color="success" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Vendors
                    </Typography>
                    <Typography variant="h5">
                      {new Set(devices.map(d => d.deviceManufacturer).filter(m => m)).size.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <MemoryIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Device Types
                    </Typography>
                    <Typography variant="h5">
                      {new Set(devices.flatMap(d => d.devices || [])).size.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TrendingUpIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Traffic
                    </Typography>
                    <Typography variant="h5">
                      {formatBytes(devices.reduce((sum, d) => sum + d.bytes, 0))}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Visualization Charts - Only show in chart mode */}
        {viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
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
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
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
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
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
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
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
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
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
          <TextField
            data-learn="Search Devices: Filter the devices table by MAC address, manufacturer, device type, or application name."
            size="small"
            placeholder="Search devices..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
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
          <>
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
                        hover
                        onClick={() => handleRowClick(device.macAddr)}
                        sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
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

            <TablePagination
              component="div"
              count={filteredDevices.length}
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

