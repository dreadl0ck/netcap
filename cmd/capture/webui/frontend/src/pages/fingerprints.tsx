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
  TextField,
  Tooltip,
  Typography,
  Alert,
  Collapse,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Fingerprint as FingerprintIcon,
  Security as SecurityIcon,
  VpnLock as VpnLockIcon,
  Router as RouterIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';

interface FingerprintSummary {
  fingerprint: string;
  type: string;
  count: number;
  hosts: string[];
  description: string;
  firstSeen: number;
  lastSeen: number;
}

interface FingerprintsResponse {
  fingerprints: FingerprintSummary[];
  totalCount: number;
}

type FingerprintSortField = 'fingerprint' | 'type' | 'count' | 'hosts';
type SortOrder = 'asc' | 'desc';

export default function FingerprintsPage() {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'JA3' | 'HASSH' | 'DHCP'>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<FingerprintSortField>('count');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

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

    // Apply type filter
    if (filterType !== 'all') {
      filtered = filtered.filter(fp => fp.type === filterType);
    }

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(fp =>
        fp.fingerprint.toLowerCase().includes(query) ||
        fp.type.toLowerCase().includes(query) ||
        (fp.description || '').toLowerCase().includes(query) ||
        (fp.hosts || []).some(h => h.toLowerCase().includes(query))
      );
    }

    // Apply sorting
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
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [fingerprints, filterType, searchQuery, sortField, sortOrder]);

  const paginatedFingerprints = filteredFingerprints.slice(
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
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view device and application fingerprints."
    />
  );

  // Calculate summary statistics
  const ja3Count = fingerprints.filter(fp => fp.type === 'JA3').length;
  const hasshCount = fingerprints.filter(fp => fp.type === 'HASSH').length;
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
        {/* Summary Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Total Fingerprints: Number of unique fingerprint hashes discovered across all types.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <FingerprintIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Fingerprints
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
            <Card data-learn="JA3 Fingerprints: TLS/SSL client fingerprints from encrypted connections.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <VpnLockIcon color="success" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      JA3 (TLS)
                    </Typography>
                    <Typography variant="h5">
                      {ja3Count.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="HASSH Fingerprints: SSH client and server fingerprints for secure shell connections.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SecurityIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      HASSH (SSH)
                    </Typography>
                    <Typography variant="h5">
                      {hasshCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="DHCP Fingerprints: Device fingerprints from DHCP requests for device identification.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <RouterIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      DHCP
                    </Typography>
                    <Typography variant="h5">
                      {dhcpCount.toLocaleString()}
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
                  data-learn="Type Distribution: Pie chart showing distribution of JA3, HASSH, and DHCP fingerprints."
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
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top JA3: Bar chart showing the most common TLS client fingerprints."
                  key={`top-ja3-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/top-ja3`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top JA3 Fingerprints"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top HASSH: Bar chart showing the most common SSH client/server fingerprints."
                  key={`top-hassh-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/top-hassh`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top HASSH Fingerprints"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
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

        {/* Filters and Actions */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField
            data-learn="Fingerprint Search: Filter by fingerprint hash, type, description, or associated host."
            size="small"
            placeholder="Search fingerprints..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
          />
          
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <Select
              data-learn="Type Filter: Filter to show all fingerprints or only specific types (JA3, HASSH, DHCP)."
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as 'all' | 'JA3' | 'HASSH' | 'DHCP');
                setPage(0);
              }}
            >
              <MenuItem value="all">All Types</MenuItem>
              <MenuItem value="JA3">JA3 (TLS)</MenuItem>
              <MenuItem value="HASSH">HASSH (SSH)</MenuItem>
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
          
          {(searchQuery || filterType !== 'all') ? (
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
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Fingerprint Row: Click to expand and view detailed information about this fingerprint."
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
                              data-learn="Fingerprint Type: Protocol or method used for this fingerprint (JA3 for TLS, HASSH for SSH, DHCP for device identification)."
                              label={fp.type}
                              size="small"
                              color={fp.type === 'JA3' ? 'success' : fp.type === 'HASSH' ? 'warning' : 'info'}
                              sx={{ fontSize: '0.7rem' }}
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
                              {fp.description || 'No description available'}
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
      </Box>
    </Layout>
  );
}

