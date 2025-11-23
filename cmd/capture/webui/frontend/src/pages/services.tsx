import { useState, useMemo } from 'react';
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
  SelectChangeEvent,
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
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  SwapHoriz as SwapHorizIcon,
  Build as BuildIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingUpIcon,
  DeviceHub as DeviceHubIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import { api, formatBytes, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';

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
}

interface ServicesResponse {
  services: ServiceSummary[];
  totalCount: number;
}

type ServiceSortField = 'ip' | 'port' | 'protocol' | 'flows' | 'bytes';
type SortOrder = 'asc' | 'desc';

export default function ServicesPage() {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<ServiceSortField>('bytes');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

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

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(s =>
        s.ip.toLowerCase().includes(query) ||
        s.port.toString().includes(query) ||
        (s.name || '').toLowerCase().includes(query) ||
        (s.protocol || '').toLowerCase().includes(query) ||
        (s.product || '').toLowerCase().includes(query) ||
        (s.vendor || '').toLowerCase().includes(query) ||
        (s.hostname || '').toLowerCase().includes(query) ||
        (s.portName || '').toLowerCase().includes(query) ||
        (s.applications || []).some(a => a.toLowerCase().includes(query))
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

  const handleChangePage = (_event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleRefresh = () => {
    mutate();
    // Also refresh charts
    setChartRefreshKey(prev => prev + 1);
  };

  const handleFileChange = async (event: SelectChangeEvent<string>) => {
    const newFile = event.target.value;
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(newFile);
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
  };

  const handleRowClick = (key: string) => {
    setExpandedRow(expandedRow === key ? null : key);
  };

  // Get only completed files for the selector, sorted alphabetically for consistency
  const completedFiles = (inputFiles?.filter((f: any) => f.isCompleted) || [])
    .sort((a: any, b: any) => a.path.localeCompare(b.path));
  
  // Current selected value - use backend's activeInputFile or fallback to first file
  const selectedValue = status?.activeInputFile || completedFiles[0]?.path || '';
  // Match by comparing both full path and basename
  const selectedFile = completedFiles.find((f: any) => 
    f.path === selectedValue || f.name === selectedValue || f.path.endsWith('/' + selectedValue)
  );

  // File selector for header
  const fileSelector = completedFiles.length > 1 && selectedFile ? (
    <FormControl size="small" disabled={switchingFile} sx={{ minWidth: 300, maxWidth: 400 }}>
      <Select
        data-learn="Capture Selector: Switch between different analyzed PCAP files to view their discovered network services."
        value={selectedValue}
        onChange={handleFileChange}
        startAdornment={
          switchingFile ? (
            <CircularProgress size={20} sx={{ mr: 1, color: 'inherit' }} />
          ) : (
            <SwapHorizIcon sx={{ mr: 1, color: 'inherit' }} />
          )
        }
        renderValue={() => (
          <Box display="flex" alignItems="center" gap={1} minWidth={0} flex={1}>
            <Typography sx={{ 
              fontFamily: 'monospace', 
              fontSize: '0.85rem', 
              color: 'inherit',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              flex: 1,
              minWidth: 0,
            }}>
              {selectedFile.name}
            </Typography>
          </Box>
        )}
        sx={{
          color: 'inherit',
          '.MuiOutlinedInput-notchedOutline': {
            borderColor: 'rgba(255, 255, 255, 0.23)',
          },
          '&:hover .MuiOutlinedInput-notchedOutline': {
            borderColor: 'rgba(255, 255, 255, 0.4)',
          },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
            borderColor: 'primary.light',
          },
          '.MuiSelect-icon': {
            color: 'inherit',
          },
          '& .MuiSelect-select': {
            display: 'flex',
            alignItems: 'center',
          },
        }}
      >
        {completedFiles.map((file: any) => (
          <MenuItem key={file.path} value={file.path}>
            <Box display="flex" alignItems="center" gap={1} width="100%">
              {selectedValue === file.path && (
                <Chip
                  data-learn="Active File Indicator: Shows which PCAP file is currently being analyzed."
                  label="Active"
                  size="small"
                  color="success"
                  sx={{ height: 20, fontSize: '0.7rem' }}
                />
              )}
              <Typography
                sx={{
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  flex: 1,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {file.name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {formatBytes(file.size)}
              </Typography>
            </Box>
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  ) : null;

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
        {/* Summary Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Total Services: Number of network services discovered in this PCAP file.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <BuildIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Services
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
            <Card data-learn="Total Traffic: Sum of all bytes transferred to and from all services.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TrendingUpIcon color="success" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Traffic
                    </Typography>
                    <Typography variant="h5">
                      {formatBytes(totalBytes)}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Total Flows: Total number of network flows across all services.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <DeviceHubIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Flows
                    </Typography>
                    <Typography variant="h5">
                      {totalFlows.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Unique Ports: Number of different service ports discovered in the capture.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SpeedIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Ports
                    </Typography>
                    <Typography variant="h5">
                      {uniquePorts.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Visualization Charts */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
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
            <Card sx={{ height: 500 }}>
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
            <Card sx={{ height: 500 }}>
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
            <Card sx={{ height: 500 }}>
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

        {/* Filters and Actions */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField
            data-learn="Service Search: Filter services by IP address, port, protocol, product, vendor, hostname, or applications."
            size="small"
            placeholder="Search services..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
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
                      <>
                        <TableRow 
                          key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Service Row: Click to expand and view detailed information about this service."
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
                                          Banner: {svc.banner}
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
                                        {(svc.applications || []).map((app, appIdx) => (
                                          <Chip
                                            key={appIdx}
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
      </Box>
    </Layout>
  );
}

