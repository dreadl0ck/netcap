import { useState, useMemo, useCallback } from 'react';
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
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Memory as MemoryIcon,
  Business as BusinessIcon,
  Computer as ComputerIcon,
  Apps as AppsIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';

interface SoftwareSummary {
  product: string;
  vendor: string;
  version: string;
  os: string;
  count: number;
  devices: string[];
  services: string[];
  dpiResults: string[];
  firstSeen: number;
  lastSeen: number;
  sourceNames: string[];
}

interface SoftwareResponse {
  software: SoftwareSummary[];
  totalCount: number;
}

type SoftwareSortField = 'product' | 'vendor' | 'version' | 'count' | 'devices';
type SortOrder = 'asc' | 'desc';

export default function SoftwarePage() {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<SoftwareSortField>('count');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

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

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(sw =>
        sw.product.toLowerCase().includes(query) ||
        (sw.vendor || '').toLowerCase().includes(query) ||
        (sw.version || '').toLowerCase().includes(query) ||
        (sw.os || '').toLowerCase().includes(query) ||
        (sw.devices || []).some(d => d.toLowerCase().includes(query)) ||
        (sw.services || []).some(s => s.toLowerCase().includes(query))
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'product':
          comparison = a.product.localeCompare(b.product);
          break;
        case 'vendor':
          comparison = (a.vendor || '').localeCompare(b.vendor || '');
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
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [software, searchQuery, sortField, sortOrder]);

  const paginatedSoftware = filteredSoftware.slice(
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
  }, [mutateStatus, mutate]);

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
  const uniqueVendors = new Set(software.filter(sw => sw.vendor).map(sw => sw.vendor)).size;
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
        {/* Summary Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Unique Products: Number of different software products detected in the network traffic.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <AppsIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Products
                    </Typography>
                    <Typography variant="h5">
                      {uniqueProducts.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Unique Vendors: Number of different software vendors identified.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <BusinessIcon color="success" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Vendors
                    </Typography>
                    <Typography variant="h5">
                      {uniqueVendors.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Versions Tracked: Number of specific software versions detected.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <MemoryIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Versions Tracked
                    </Typography>
                    <Typography variant="h5">
                      {uniqueVersions.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Total Detections: Total number of software detection events across all captures.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ComputerIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Detections
                    </Typography>
                    <Typography variant="h5">
                      {totalDetections.toLocaleString()}
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
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
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
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
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
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
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

        {/* Filters and Actions */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField
            data-learn="Software Search: Filter software by product name, vendor, version, OS, device, or service."
            size="small"
            placeholder="Search software..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
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
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Software Table: Detailed list of all detected software with versions, vendors, and associated devices.">
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
                        data-learn="Sort by Vendor: Click to sort software by vendor/manufacturer name."
                        active={sortField === 'vendor'}
                        direction={sortField === 'vendor' ? sortOrder : 'asc'}
                        onClick={() => handleSort('vendor')}
                      >
                        Vendor
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
                    const rowKey = `${sw.product}-${sw.vendor}-${sw.version}-${idx}`;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Software Row: Click to expand and view detailed information about this software."
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
                            {sw.vendor ? (
                              <Chip
                                data-learn="Vendor Tag: Software manufacturer or vendor name."
                                label={sw.vendor}
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
                          <TableCell>
                            <Typography 
                              variant="body2"
                              sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                              data-learn="Version: Specific version number or identifier of the software."
                            >
                              {sw.version || 'N/A'}
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
                            ) : (
                              <Typography variant="body2" color="text.secondary">
                                Unknown
                              </Typography>
                            )}
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}>
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
              data-learn="Table Pagination: Navigate through pages of software and change how many rows to display per page."
              component="div"
              count={filteredSoftware.length}
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

