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
  Typography,
  Alert,
  Collapse,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Cable as CableIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingUpIcon,
  Timer as TimerIcon,
  Article as ArticleIcon,
  Download as DownloadIcon,
  Computer as ComputerIcon,
  Router as RouterIcon,
  Build as BuildIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import ConversationModal from '@/components/ConversationModal';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatBytes, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';

interface ConnectionSummary {
  timestampFirst: number;
  timestampLast: number;
  linkProto: string;
  networkProto: string;
  transportProto: string;
  applicationProto: string;
  srcMAC: string;
  dstMAC: string;
  srcIP: string;
  srcPort: string;
  dstIP: string;
  dstPort: string;
  totalSize: number;
  appPayloadSize: number;
  numPackets: number;
  duration: number;
  bytesClientToServer: number;
  bytesServerToClient: number;
  numFINFlags: number;
  numRSTFlags: number;
  numACKFlags: number;
  numSYNFlags: number;
  numURGFlags: number;
  numECEFlags: number;
  numPSHFlags: number;
  numCWRFlags: number;
  numNSFlags: number;
  meanWindowSize: number;
  applications: string[];
  serverPortName: string;
  detectedProtocolName: string;
}

interface ConnectionsResponse {
  connections: ConnectionSummary[];
  totalCount: number;
}

type ConnectionSortField = 'endpoints' | 'protocol' | 'packets' | 'bytes' | 'duration';
type SortOrder = 'asc' | 'desc';

export default function ConnectionsPage() {
  const router = useRouter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<ConnectionSortField>('bytes');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [conversationModalOpen, setConversationModalOpen] = useState(false);
  const [selectedConnection, setSelectedConnection] = useState<ConnectionSummary | null>(null);

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch connections data
  const { data: connectionsData, error, mutate } = useSWR<ConnectionsResponse>(
    'connections',
    () => fetch(`${getBackendUrl()}/api/connections`).then(res => res.json()),
    {
      refreshInterval: 10000,
    }
  );

  const connections = connectionsData?.connections || [];
  const totalCount = connectionsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: ConnectionSortField) => {
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
  const filteredConnections = useMemo(() => {
    let filtered = connections;

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(c =>
        c.srcIP.toLowerCase().includes(query) ||
        c.dstIP.toLowerCase().includes(query) ||
        c.srcPort.toLowerCase().includes(query) ||
        c.dstPort.toLowerCase().includes(query) ||
        (c.applicationProto || '').toLowerCase().includes(query) ||
        (c.transportProto || '').toLowerCase().includes(query) ||
        (c.applications || []).some(a => a.toLowerCase().includes(query))
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'endpoints': {
          const endpointA = `${a.srcIP}:${a.srcPort}-${a.dstIP}:${a.dstPort}`;
          const endpointB = `${b.srcIP}:${b.srcPort}-${b.dstIP}:${b.dstPort}`;
          comparison = endpointA.localeCompare(endpointB);
          break;
        }
        case 'protocol': {
          const protoA = a.applicationProto || a.transportProto || '';
          const protoB = b.applicationProto || b.transportProto || '';
          comparison = protoA.localeCompare(protoB);
          break;
        }
        case 'packets':
          comparison = a.numPackets - b.numPackets;
          break;
        case 'bytes':
          comparison = a.totalSize - b.totalSize;
          break;
        case 'duration':
          comparison = a.duration - b.duration;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [connections, searchQuery, sortField, sortOrder]);

  // Paginate connections
  const paginatedConnections = filteredConnections.slice(
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

  const handleRowClick = useCallback((key: string) => {
    setExpandedRow(prev => prev === key ? null : key);
  }, []);

  const handleViewConversation = useCallback((conn: ConnectionSummary) => {
    setSelectedConnection(conn);
    setConversationModalOpen(true);
  }, []);

  const handleCloseConversationModal = useCallback(() => {
    setConversationModalOpen(false);
    setSelectedConnection(null);
  }, []);

  const handleDownloadPCAP = useCallback(async (conn: ConnectionSummary) => {
    try {
      // Generate download URL
      const params = new URLSearchParams({
        srcIP: conn.srcIP,
        srcPort: conn.srcPort,
        dstIP: conn.dstIP,
        dstPort: conn.dstPort,
      });
      const downloadUrl = `${getBackendUrl()}/api/connections/download-pcap?${params}`;
      
      // Fetch the file as a blob
      const response = await fetch(downloadUrl);
      
      if (!response.ok) {
        const errorText = await response.text();
        alert(`Failed to download PCAP: ${errorText}`);
        return;
      }
      
      // Get the blob and create a download link
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      
      // Create a temporary anchor element and trigger download
      const a = document.createElement('a');
      a.href = url;
      a.download = `connection_${conn.srcIP}-${conn.srcPort}_${conn.dstIP}-${conn.dstPort}.pcap`;
      document.body.appendChild(a);
      a.click();
      
      // Cleanup
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
      alert(`Failed to download PCAP: ${error}`);
    }
  }, []);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their network connections and flows."
    />
  );

  // Memoize summary statistics to avoid recalculation on every render
  const stats = useMemo(() => ({
    totalBytes: connections.reduce((sum, c) => sum + c.totalSize, 0),
    avgDuration: connections.length > 0 
      ? connections.reduce((sum, c) => sum + c.duration, 0) / connections.length 
      : 0,
    uniqueProtocols: new Set(connections.map(c => c.applicationProto || c.transportProto)).size
  }), [connections]);

  if (error) {
    return (
      <Layout title="Connections" headerAction={fileSelector}>
        <Alert severity="error">Error loading connections: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Connections" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        {/* Summary Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Total Connections: Number of network connections captured in this PCAP file.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <CableIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Connections
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
            <Card data-learn="Total Traffic: Sum of all bytes transferred across all connections.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TrendingUpIcon color="success" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Traffic
                    </Typography>
                    <Typography variant="h5">
                      {formatBytes(stats.totalBytes)}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Avg Duration: Average duration of all network connections.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TimerIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Avg Duration
                    </Typography>
                    <Typography variant="h5">
                      {(stats.avgDuration / 1e9).toFixed(2)}s
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Unique Protocols: Number of different protocols detected in the connections.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SpeedIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Protocols
                    </Typography>
                    <Typography variant="h5">
                      {stats.uniqueProtocols.toLocaleString()}
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
                  data-learn="Top Connections Chart: Bar chart showing the connections with the most traffic."
                  key={`top-by-traffic-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/top-by-traffic`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Connections by Traffic"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Protocol Distribution: Pie chart showing the distribution of protocols across connections."
                  key={`protocols-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/protocols?showLegend=false`}
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
                  data-learn="Applications Chart: Bar chart showing the top detected applications in the connections."
                  key={`applications-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/applications`}
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
                  data-learn="Duration vs Size: Scatter plot showing the relationship between connection duration and data size."
                  key={`duration-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/duration`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Connection Duration vs Size"
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Filters and Actions */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField
            data-learn="Connection Search: Filter connections by IP addresses, ports, protocols, or applications."
            size="small"
            placeholder="Search connections..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
          />
          
          <Button
            data-learn="Refresh Button: Reload connection data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredConnections.length} of {totalCount} connections
            </Typography>
          ) : null}
        </Box>

        {/* Connections Table */}
        {!connectionsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <CableIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Connections Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No connection records have been captured yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Connections Table: Detailed list of all captured network connections with sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Endpoints: Click to sort connections by source and destination IP:port pairs."
                        active={sortField === 'endpoints'}
                        direction={sortField === 'endpoints' ? sortOrder : 'asc'}
                        onClick={() => handleSort('endpoints')}
                      >
                        Connection
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Protocol: Click to sort connections by application or transport protocol."
                        active={sortField === 'protocol'}
                        direction={sortField === 'protocol' ? sortOrder : 'asc'}
                        onClick={() => handleSort('protocol')}
                      >
                        Protocol
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Packets: Click to sort connections by packet count."
                        active={sortField === 'packets'}
                        direction={sortField === 'packets' ? sortOrder : 'asc'}
                        onClick={() => handleSort('packets')}
                      >
                        Packets
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Bytes: Click to sort connections by total data transferred."
                        active={sortField === 'bytes'}
                        direction={sortField === 'bytes' ? sortOrder : 'asc'}
                        onClick={() => handleSort('bytes')}
                      >
                        Bytes
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Duration: Click to sort connections by how long they lasted."
                        active={sortField === 'duration'}
                        direction={sortField === 'duration' ? sortOrder : 'asc'}
                        onClick={() => handleSort('duration')}
                      >
                        Duration
                      </TableSortLabel>
                    </TableCell>
                    <TableCell data-learn="Server Port: Service name associated with the destination port from IANA database.">
                      Server Port
                    </TableCell>
                    <TableCell>Applications</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedConnections.map((conn, idx) => {
                    const rowKey = `${conn.srcIP}-${conn.srcPort}-${conn.dstIP}-${conn.dstPort}-${idx}`;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Connection Row: Click to expand and view detailed information about this connection."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed connection information.">
                              <ExpandMoreIcon 
                                sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} 
                              />
                            </IconButton>
                          </TableCell>
                          <TableCell>
                            <Box 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                display: 'flex',
                                alignItems: 'center',
                              }}
                              data-learn="Connection Endpoints: Source IP:port → Destination IP:port showing the direction of the connection. For link-layer only connections, shows MAC addresses."
                            >
                              {conn.srcIP ? (
                                <>
                                  <Box component="span" sx={{ color: '#f44336', fontWeight: 'bold' }}>
                                    {conn.srcIP}
                                  </Box>
                                  {conn.srcPort && (
                                    <>
                                      <Box component="span" sx={{ color: 'text.secondary' }}>:</Box>
                                      <Box component="span" sx={{ color: '#FFB74D', fontWeight: 'medium' }}>
                                        {conn.srcPort}
                                      </Box>
                                    </>
                                  )}
                                  <Box component="span" sx={{ color: 'text.secondary', mx: 0.5 }}>→</Box>
                                  <Box component="span" sx={{ color: '#2196f3', fontWeight: 'bold' }}>
                                    {conn.dstIP}
                                  </Box>
                                  {conn.dstPort && (
                                    <>
                                      <Box component="span" sx={{ color: 'text.secondary' }}>:</Box>
                                      <Box component="span" sx={{ color: '#FFB74D', fontWeight: 'medium' }}>
                                        {conn.dstPort}
                                      </Box>
                                    </>
                                  )}
                                </>
                              ) : (
                                <>
                                  <Box component="span" sx={{ color: '#f44336', fontWeight: 'bold' }}>
                                    {conn.srcMAC || 'N/A'}
                                  </Box>
                                  <Box component="span" sx={{ color: 'text.secondary', mx: 0.5 }}>→</Box>
                                  <Box component="span" sx={{ color: '#2196f3', fontWeight: 'bold' }}>
                                    {conn.dstMAC || 'N/A'}
                                  </Box>
                                </>
                              )}
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="Protocol Tag: Shows the application layer protocol, or transport protocol if no application protocol detected."
                              label={conn.applicationProto || conn.transportProto || 'Unknown'}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {conn.numPackets.toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {formatBytes(conn.totalSize)}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {(conn.duration / 1e9).toFixed(3)}s
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {conn.serverPortName ? (
                              <Chip
                                data-learn="Server Port Name: Official service name for this destination port from IANA port registry."
                                label={conn.serverPortName}
                                size="small"
                                color="secondary"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem' }}
                              />
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
                                {conn.dstPort || '-'}
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                              {(conn.applications || []).slice(0, 2).map((app) => (
                                <Chip
                                  key={`${rowKey}-app-${app}`}
                                  label={app}
                                  size="small"
                                  color="info"
                                  sx={{ fontSize: '0.7rem', height: 20 }}
                                  data-learn="Application Tag: Application detected by Deep Packet Inspection (DPI)."
                                />
                              ))}
                              {(conn.applications || []).length > 2 && (
                                <Chip
                                  label={`+${(conn.applications || []).length - 2}`}
                                  size="small"
                                  color="info"
                                  sx={{ fontSize: '0.7rem', height: 20 }}
                                  data-learn="More Applications: Click the row to see all detected applications."
                                />
                              )}
                            </Box>
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={8}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="Connection Details: Extended information about this network connection including timestamps, MAC addresses, protocols, flags, and statistics.">
                                <Grid container spacing={2}>
                                  {/* Time Range */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Time Range
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      First: {formatTimestamp(conn.timestampFirst)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Last: {formatTimestamp(conn.timestampLast)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Duration: {(conn.duration / 1e9).toFixed(3)} seconds
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Link Layer */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Link Layer
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Protocol: {conn.linkProto}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Src MAC: {conn.srcMAC}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Dst MAC: {conn.dstMAC}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Network & Transport Layer */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Network & Transport
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Network Protocol: {conn.networkProto}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Transport Protocol: {conn.transportProto}
                                    </Typography>
                                    {conn.applicationProto && (
                                      <Typography variant="body2" color="text.secondary">
                                        Application Protocol: {conn.applicationProto}
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Protocol Detection */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Protocol Detection
                                    </Typography>
                                    {conn.serverPortName && (
                                      <Typography variant="body2" color="text.secondary">
                                        Server Port Name: {conn.serverPortName}
                                      </Typography>
                                    )}
                                    {conn.detectedProtocolName && (
                                      <Typography variant="body2" color="text.secondary">
                                        Detected Protocol: {conn.detectedProtocolName}
                                      </Typography>
                                    )}
                                    {!conn.serverPortName && !conn.detectedProtocolName && (
                                      <Typography variant="body2" color="text.secondary">
                                        No protocol detection information available
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Traffic Statistics */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Traffic Statistics
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Total Size: {formatBytes(conn.totalSize)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      App Payload: {formatBytes(conn.appPayloadSize)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Packets: {conn.numPackets.toLocaleString()}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Client→Server: {formatBytes(conn.bytesClientToServer)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Server→Client: {formatBytes(conn.bytesServerToClient)}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* TCP Flags */}
                                  {conn.transportProto === 'TCP' && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        TCP Flags
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {conn.numSYNFlags > 0 && (
                                          <Chip label={`SYN: ${conn.numSYNFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numACKFlags > 0 && (
                                          <Chip label={`ACK: ${conn.numACKFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numFINFlags > 0 && (
                                          <Chip label={`FIN: ${conn.numFINFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numRSTFlags > 0 && (
                                          <Chip label={`RST: ${conn.numRSTFlags}`} size="small" variant="outlined" color="error" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numPSHFlags > 0 && (
                                          <Chip label={`PSH: ${conn.numPSHFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numURGFlags > 0 && (
                                          <Chip label={`URG: ${conn.numURGFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numECEFlags > 0 && (
                                          <Chip label={`ECE: ${conn.numECEFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numCWRFlags > 0 && (
                                          <Chip label={`CWR: ${conn.numCWRFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numNSFlags > 0 && (
                                          <Chip label={`NS: ${conn.numNSFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        <Chip label={`Mean Window: ${conn.meanWindowSize}`} size="small" variant="outlined" color="info" sx={{ fontSize: '0.75rem' }} />
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* All Applications */}
                                  {(conn.applications || []).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        All Detected Applications ({(conn.applications || []).length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {(conn.applications || []).map((app) => (
                                          <Chip
                                            key={`${rowKey}-app-detail-${app}`}
                                            label={app}
                                            size="small"
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Action Buttons */}
                                  <Grid item xs={12}>
                                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                      {(conn.transportProto === 'TCP' || conn.transportProto === 'UDP') && (
                                        <>
                                          <Button
                                            data-learn="View Raw Conversation: Display the raw conversation data in Wireshark-style hex dump format, with client data in red and server data in blue."
                                            variant="outlined"
                                            startIcon={<ArticleIcon />}
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              handleViewConversation(conn);
                                            }}
                                            size="small"
                                          >
                                            View Raw Conversation
                                          </Button>
                                          <Button
                                            data-learn="Download as PCAP: Download a filtered PCAP file containing only the packets from this connection."
                                            variant="outlined"
                                            startIcon={<DownloadIcon />}
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              handleDownloadPCAP(conn);
                                            }}
                                            size="small"
                                          >
                                            Download as PCAP
                                          </Button>
                                        </>
                                      )}
                                      
                                      {/* Navigation Buttons */}
                                      {conn.srcIP && (
                                        <Button
                                          data-learn="View Client in Hosts: Navigate to the Hosts page filtered for the client IP address."
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<ComputerIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/hosts?search=${encodeURIComponent(conn.srcIP)}`);
                                          }}
                                          size="small"
                                        >
                                          Client IP in Hosts
                                        </Button>
                                      )}
                                      
                                      {conn.dstIP && (
                                        <Button
                                          data-learn="View Server in Hosts: Navigate to the Hosts page filtered for the server IP address."
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<ComputerIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/hosts?search=${encodeURIComponent(conn.dstIP)}`);
                                          }}
                                          size="small"
                                        >
                                          Server IP in Hosts
                                        </Button>
                                      )}
                                      
                                      {(conn.srcMAC || conn.dstMAC) && (
                                        <>
                                          {conn.srcMAC && (
                                            <Button
                                              data-learn="View Client MAC in Devices: Navigate to the Devices page filtered for the client MAC address."
                                              variant="outlined"
                                              color="secondary"
                                              startIcon={<RouterIcon />}
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                router.push(`/devices?search=${encodeURIComponent(conn.srcMAC)}`);
                                              }}
                                              size="small"
                                            >
                                              Client MAC in Devices
                                            </Button>
                                          )}
                                          
                                          {conn.dstMAC && (
                                            <Button
                                              data-learn="View Server MAC in Devices: Navigate to the Devices page filtered for the server MAC address."
                                              variant="outlined"
                                              color="secondary"
                                              startIcon={<RouterIcon />}
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                router.push(`/devices?search=${encodeURIComponent(conn.dstMAC)}`);
                                              }}
                                              size="small"
                                            >
                                              Server MAC in Devices
                                            </Button>
                                          )}
                                        </>
                                      )}
                                      
                                      {conn.dstIP && (
                                        <Button
                                          data-learn="View Service: Navigate to the Services page filtered for the server IP address."
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<BuildIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/services?search=${encodeURIComponent(conn.dstIP)}`);
                                          }}
                                          size="small"
                                        >
                                          Service
                                        </Button>
                                      )}
                                    </Box>
                                  </Grid>
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
              data-learn="Table Pagination: Navigate through pages of connections and change how many rows to display per page."
              component="div"
              count={filteredConnections.length}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
            />
          </>
        )}
      </Box>

      {/* Conversation Modal */}
      {selectedConnection && (
        <ConversationModal
          open={conversationModalOpen}
          onClose={handleCloseConversationModal}
          srcIP={selectedConnection.srcIP}
          srcPort={selectedConnection.srcPort}
          dstIP={selectedConnection.dstIP}
          dstPort={selectedConnection.dstPort}
          protocol={selectedConnection.transportProto}
        />
      )}
    </Layout>
  );
}

