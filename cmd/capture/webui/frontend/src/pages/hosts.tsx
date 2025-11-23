import { useState, useMemo, useEffect, useCallback } from 'react';
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
  Public as GeoIcon,
  Devices as DevicesIcon,
  Security as SecurityIcon,
  Language as LanguageIcon,
  LocalOffer as TagIcon,
  TrendingUp as TrendingUpIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatBytes, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';

interface ProtocolInfo {
  name: string;
  packets: number;
  category: string;
}

interface PortInfo {
  port: number;
  protocol: string;
  packets: number;
  bytes: number;
}

interface IPProfileSummary {
  addr: string;
  numPackets: number;
  bytes: number;
  geolocation: string;
  dnsNames: string[];
  timestampFirst: number;
  timestampLast: number;
  applications: string[];
  ja3Hashes: Record<string, string>;
  protocolsCount: number;
  snisCount: number;
  srcPortsCount: number;
  dstPortsCount: number;
  contactedPortsCount: number;
  ja3FingerprintMatches: string[];
  ja3sFingerprintMatches: string[];
  topProtocols: ProtocolInfo[];
  topSrcPorts: PortInfo[];
  topDstPorts: PortInfo[];
  topContactedPorts: PortInfo[];
  isInternal: boolean;
}

interface HostsResponse {
  hosts: IPProfileSummary[];
  totalCount: number;
}

type HostSortField = 'addr' | 'type' | 'packets' | 'bytes';
type SortOrder = 'asc' | 'desc';

export default function HostsPage() {
  const router = useRouter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'internal' | 'external'>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<HostSortField>('addr');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');

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

  // Fetch hosts data
  const { data: hostsData, error, mutate } = useSWR<HostsResponse>(
    'hosts',
    () => fetch(`${getBackendUrl()}/api/hosts`).then(res => res.json()),
    {
      refreshInterval: 10000,
    }
  );

  const hosts = hostsData?.hosts || [];
  const totalCount = hostsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: HostSortField) => {
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
  const filteredHosts = useMemo(() => {
    let filtered = hosts;

    // Apply type filter
    if (filterType === 'internal') {
      filtered = filtered.filter(h => h.isInternal);
    } else if (filterType === 'external') {
      filtered = filtered.filter(h => !h.isInternal);
    }

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(h =>
        h.addr.toLowerCase().includes(query) ||
        (h.dnsNames || []).some(n => n.toLowerCase().includes(query)) ||
        (h.geolocation || '').toLowerCase().includes(query) ||
        (h.applications || []).some(a => a.toLowerCase().includes(query))
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'addr':
          comparison = a.addr.localeCompare(b.addr);
          break;
        case 'type':
          // Sort internal first (true > false), then by address
          if (a.isInternal === b.isInternal) {
            comparison = a.addr.localeCompare(b.addr);
          } else {
            comparison = a.isInternal ? -1 : 1;
          }
          break;
        case 'packets':
          comparison = a.numPackets - b.numPackets;
          break;
        case 'bytes':
          comparison = a.bytes - b.bytes;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [hosts, filterType, searchQuery, sortField, sortOrder]);

  // Paginate hosts
  const paginatedHosts = filteredHosts.slice(
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

  const handleRowClick = useCallback((addr: string) => {
    setExpandedRow(prev => prev === addr ? null : addr);
  }, []);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their discovered network hosts and connections."
    />
  );

  if (error) {
    return (
      <Layout title="Hosts" headerAction={fileSelector}>
        <Alert severity="error">Error loading hosts: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Hosts" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        {/* Summary Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <DevicesIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Hosts
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
                  <SecurityIcon color="success" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Internal Hosts
                    </Typography>
                    <Typography variant="h5">
                      {hosts.filter(h => h.isInternal).length.toLocaleString()}
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
                  <LanguageIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      External Hosts
                    </Typography>
                    <Typography variant="h5">
                      {hosts.filter(h => !h.isInternal).length.toLocaleString()}
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
                      {formatBytes(hosts.reduce((sum, h) => sum + h.bytes, 0))}
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
                  key={`top-talkers-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/hosts/top-talkers`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Hosts by Traffic"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  key={`traffic-dist-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/hosts/traffic-distribution?showLegend=false`}
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
                  key={`applications-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/hosts/applications`}
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
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  key={`protocols-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/hosts/protocols?showLegend=false`}
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
        </Grid>

        {/* Filters and Actions */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField
            data-learn="Search Hosts: Filter the hosts table by IP address, DNS name, geolocation, or application name."
            size="small"
            placeholder="Search hosts..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
          />
          
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <Select
              data-learn="Host Type Filter: Show all hosts, only internal network hosts, or only external hosts."
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as 'all' | 'internal' | 'external');
                setPage(0);
              }}
            >
              <MenuItem value="all">All Hosts</MenuItem>
              <MenuItem value="internal">Internal Only</MenuItem>
              <MenuItem value="external">External Only</MenuItem>
            </Select>
          </FormControl>
          
          <Button 
            data-learn="Refresh Hosts: Reload host data and visualization charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery || filterType !== 'all' ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredHosts.length} of {totalCount} hosts
            </Typography>
          ) : null}
        </Box>

        {/* Hosts Table */}
        {!hostsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <DevicesIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Hosts Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No IP profiles have been captured yet.
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
                        active={sortField === 'addr'}
                        direction={sortField === 'addr' ? sortOrder : 'asc'}
                        onClick={() => handleSort('addr')}
                      >
                        IP Address
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        active={sortField === 'type'}
                        direction={sortField === 'type' ? sortOrder : 'asc'}
                        onClick={() => handleSort('type')}
                      >
                        Type
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
                    <TableCell>Geolocation</TableCell>
                    <TableCell>DNS Names</TableCell>
                    <TableCell>Applications</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedHosts.map((host) => (
                    <>
                      <TableRow 
                        key={host.addr}
                        hover
                        onClick={() => handleRowClick(host.addr)}
                        sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                      >
                        <TableCell>
                          <IconButton size="small">
                            <ExpandMoreIcon 
                              sx={{ 
                                transform: expandedRow === host.addr ? 'rotate(180deg)' : 'rotate(0deg)',
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
                            {host.addr}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={host.isInternal ? 'Internal' : 'External'}
                            size="small"
                            color={host.isInternal ? 'success' : 'warning'}
                            sx={{ fontSize: '0.7rem' }}
                          />
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {host.numPackets.toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {formatBytes(host.bytes)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {host.geolocation && (
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                              <GeoIcon fontSize="small" color="action" />
                              <Typography variant="body2">
                                {host.geolocation}
                              </Typography>
                            </Box>
                          )}
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(host.dnsNames || []).slice(0, 2).map((name) => (
                              <Chip
                                key={name}
                                label={name}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                              />
                            ))}
                            {(host.dnsNames || []).length > 2 && (
                              <Chip
                                label={`+${(host.dnsNames || []).length - 2}`}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(host.applications || []).slice(0, 2).map((app) => (
                              <Chip
                                key={app}
                                label={app}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                              />
                            ))}
                            {(host.applications || []).length > 2 && (
                              <Chip
                                label={`+${(host.applications || []).length - 2}`}
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
                        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={8}>
                          <Collapse in={expandedRow === host.addr} timeout="auto" unmountOnExit>
                            <Box sx={{ py: 2 }}>
                              <Grid container spacing={2}>
                                {/* Time Range */}
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Time Range
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    First: {formatTimestamp(host.timestampFirst)}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Last: {formatTimestamp(host.timestampLast)}
                                  </Typography>
                                </Grid>
                                
                                {/* Statistics */}
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Statistics
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Protocols: {host.protocolsCount}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Source Ports: {host.srcPortsCount}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Destination Ports: {host.dstPortsCount}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Contacted Ports: {host.contactedPortsCount}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    SNIs: {host.snisCount}
                                  </Typography>
                                </Grid>
                                
                                {/* Top Protocols */}
                                {(host.topProtocols || []).length > 0 && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Top Protocols
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(host.topProtocols || []).map((proto) => (
                                        <Tooltip
                                          key={proto.name}
                                          title={`${proto.packets.toLocaleString()} packets (${proto.category})`}
                                        >
                                          <Chip
                                            label={proto.name}
                                            size="small"
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        </Tooltip>
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* Top Contacted Ports */}
                                {(host.topContactedPorts || []).length > 0 && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Top Contacted Ports
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(host.topContactedPorts || []).map((port) => (
                                        <Tooltip
                                          key={`${port.port}-${port.packets}`}
                                          title={`${port.packets.toLocaleString()} packets, ${formatBytes(port.bytes)}`}
                                        >
                                          <Chip
                                            label={`${port.port}/${port.protocol}`}
                                            size="small"
                                            variant="outlined"
                                            color="primary"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        </Tooltip>
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* All DNS Names */}
                                {(host.dnsNames || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      All DNS Names ({(host.dnsNames || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(host.dnsNames || []).map((name) => (
                                        <Chip
                                          key={name}
                                          label={name}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* All Applications */}
                                {(host.applications || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      All Applications ({(host.applications || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(host.applications || []).map((app) => (
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
                                
                                {/* JA3 Fingerprints */}
                                {((host.ja3FingerprintMatches || []).length > 0 || (host.ja3sFingerprintMatches || []).length > 0) && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      TLS Fingerprints
                                    </Typography>
                                    {(host.ja3FingerprintMatches || []).length > 0 && (
                                      <Box sx={{ mb: 1 }}>
                                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                          JA3 (Client):
                                        </Typography>
                                        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                          {(host.ja3FingerprintMatches || []).map((match) => (
                                            <Chip
                                              key={match}
                                              label={match}
                                              size="small"
                                              variant="outlined"
                                              color="secondary"
                                              sx={{ fontSize: '0.7rem' }}
                                            />
                                          ))}
                                        </Box>
                                      </Box>
                                    )}
                                    {(host.ja3sFingerprintMatches || []).length > 0 && (
                                      <Box>
                                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                          JA3S (Server):
                                        </Typography>
                                        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                          {(host.ja3sFingerprintMatches || []).map((match) => (
                                            <Chip
                                              key={match}
                                              label={match}
                                              size="small"
                                              variant="outlined"
                                              color="secondary"
                                              sx={{ fontSize: '0.7rem' }}
                                            />
                                          ))}
                                        </Box>
                                      </Box>
                                    )}
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
              count={filteredHosts.length}
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

