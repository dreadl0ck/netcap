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
  TablePagination,
  TableRow,
  TableSortLabel,
  TextField,
  Typography,
  Alert,
  Collapse,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Http as HttpIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingUpIcon,
  Public as PublicIcon,
  Download as DownloadIcon,
  Cable as CableIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import ConversationModal from '@/components/ConversationModal';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatBytes, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';

interface HTTPSummary {
  timestamp: number;
  proto: string;
  method: string;
  host: string;
  url: string;
  userAgent: string;
  referer: string;
  reqContentLength: number;
  resContentLength: number;
  contentType: string;
  statusCode: number;
  srcIP: string;
  dstIP: string;
  srcPort: number;
  dstPort: number;
  flow: string;
  reqContentEncoding: string;
  resContentEncoding: string;
  serverName: string;
  resContentType: string;
  contentTypeDetected: string;
  resContentTypeDetected: string;
  doneAfter: number;
  dnsDoneAfter: number;
  firstByteAfter: number;
  tlsDoneAfter: number;
  requestHeader: { [key: string]: string };
  responseHeader: { [key: string]: string };
  parameters: { [key: string]: string };
}

interface HTTPResponse {
  http: HTTPSummary[];
  totalCount: number;
}

type HTTPSortField = 'timestamp' | 'method' | 'host' | 'statusCode' | 'size';
type SortOrder = 'asc' | 'desc';

export default function HTTPPage() {
  const router = useRouter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<HTTPSortField>('timestamp');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useState<'table' | 'chart'>('table');
  const [conversationModalOpen, setConversationModalOpen] = useState(false);
  const [selectedHTTP, setSelectedHTTP] = useState<HTTPSummary | null>(null);

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Initialize search query from URL parameter
  useEffect(() => {
    if (router.isReady && router.query.search) {
      setSearchQuery(router.query.search as string);
    }
  }, [router.isReady, router.query.search]);

  // Fetch HTTP data
  const { data: httpData, error, mutate } = useSWR<HTTPResponse>(
    'http',
    () => fetch(`${getBackendUrl()}/api/http`).then(res => res.json()),
    {
      refreshInterval: 10000,
    }
  );

  const httpRecords = httpData?.http || [];
  const totalCount = httpData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: HTTPSortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0);
  };

  // Apply filters and sorting
  const filteredHTTP = useMemo(() => {
    let filtered = httpRecords;

    // Apply search filter
    if (searchQuery) {
      const searchTerms = searchQuery
        .split(/[,\s]+/)
        .map(term => term.trim())
        .filter(term => term.length > 0);
      
      filtered = filtered.filter(h => {
        return searchTerms.some(query => {
          const queryLower = query.toLowerCase();
          return (
            h.srcIP.toLowerCase().includes(queryLower) ||
            h.dstIP.toLowerCase().includes(queryLower) ||
            (h.host || '').toLowerCase().includes(queryLower) ||
            (h.url || '').toLowerCase().includes(queryLower) ||
            (h.method || '').toLowerCase().includes(queryLower) ||
            (h.userAgent || '').toLowerCase().includes(queryLower) ||
            (h.statusCode.toString()).includes(query)
          );
        });
      });
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'timestamp':
          comparison = a.timestamp - b.timestamp;
          break;
        case 'method':
          comparison = (a.method || '').localeCompare(b.method || '');
          break;
        case 'host':
          comparison = (a.host || '').localeCompare(b.host || '');
          break;
        case 'statusCode':
          comparison = a.statusCode - b.statusCode;
          break;
        case 'size':
          comparison = (a.reqContentLength + a.resContentLength) - (b.reqContentLength + b.resContentLength);
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [httpRecords, searchQuery, sortField, sortOrder]);

  // Paginate HTTP records
  const paginatedHTTP = filteredHTTP.slice(
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

  const handleViewConversation = useCallback((http: HTTPSummary) => {
    setSelectedHTTP(http);
    setConversationModalOpen(true);
  }, []);

  const handleCloseConversationModal = useCallback(() => {
    setConversationModalOpen(false);
    setSelectedHTTP(null);
  }, []);

  const handleDownloadPCAP = useCallback(async (http: HTTPSummary) => {
    try {
      const params = new URLSearchParams({
        srcIP: http.srcIP,
        dstIP: http.dstIP,
      });
      const downloadUrl = `${getBackendUrl()}/api/http/download-pcap?${params}`;
      
      const response = await fetch(downloadUrl);
      
      if (!response.ok) {
        const errorText = await response.text();
        alert(`Failed to download PCAP: ${errorText}`);
        return;
      }
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      
      const a = document.createElement('a');
      a.href = url;
      a.download = `http_${http.srcIP}_${http.dstIP}_${http.method}_${http.statusCode}.pcap`;
      document.body.appendChild(a);
      a.click();
      
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
      alert(`Failed to download PCAP: ${error}`);
    }
  }, []);

  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their HTTP traffic records."
    />
  );

  // Calculate statistics
  const stats = useMemo(() => ({
    totalRequests: httpRecords.length,
    totalBytes: httpRecords.reduce((sum, h) => sum + h.reqContentLength + h.resContentLength, 0),
    uniqueHosts: new Set(httpRecords.map(h => h.host)).size,
    statusErrors: httpRecords.filter(h => h.statusCode >= 400).length,
  }), [httpRecords]);

  // Get status code color
  const getStatusCodeColor = (code: number) => {
    if (code >= 200 && code < 300) return 'success';
    if (code >= 300 && code < 400) return 'info';
    if (code >= 400 && code < 500) return 'warning';
    if (code >= 500) return 'error';
    return 'default';
  };

  if (error) {
    return (
      <Layout title="HTTP" headerAction={fileSelector}>
        <Alert severity="error">Error loading HTTP records: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="HTTP" headerAction={fileSelector}>
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
            <Card data-learn="Total Requests: Number of HTTP requests captured in this PCAP file.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <HttpIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Requests
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
            <Card data-learn="Total Data: Sum of all request and response bytes transferred.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TrendingUpIcon color="success" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Data
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
            <Card data-learn="Unique Hosts: Number of different hosts accessed in HTTP requests.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <PublicIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Hosts
                    </Typography>
                    <Typography variant="h5">
                      {stats.uniqueHosts.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Error Responses: Number of HTTP responses with status codes 400 or higher.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SpeedIcon color="error" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Error Responses
                    </Typography>
                    <Typography variant="h5">
                      {stats.statusErrors.toLocaleString()}
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
                  data-learn="Top Hosts Chart: Bar chart showing the hosts with the most HTTP requests."
                  key={`top-hosts-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/top-hosts`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top HTTP Hosts"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Status Codes: Pie chart showing the distribution of HTTP status codes."
                  key={`status-codes-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/status-codes`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="HTTP Status Codes"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Request Methods: Bar chart showing the distribution of HTTP request methods."
                  key={`methods-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/methods`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="HTTP Request Methods"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Content Types: Pie chart showing the distribution of response content types."
                  key={`content-types-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/http/content-types`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="HTTP Content Types"
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
            data-learn="HTTP Search: Filter HTTP requests by IP addresses, hosts, URLs, methods, user agents, or status codes. Multiple search terms can be separated by commas or spaces."
            size="small"
            placeholder="Search HTTP requests (comma or space separated)..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
          />
          
          <Button
            data-learn="Refresh Button: Reload HTTP data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredHTTP.length} of {totalCount} requests
            </Typography>
          ) : null}
        </Box>

        {/* HTTP Table */}
        {!httpData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <HttpIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No HTTP Records Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No HTTP traffic has been captured yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="HTTP Table: Detailed list of all captured HTTP requests and responses with sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Timestamp: Click to sort HTTP requests by when they occurred."
                        active={sortField === 'timestamp'}
                        direction={sortField === 'timestamp' ? sortOrder : 'asc'}
                        onClick={() => handleSort('timestamp')}
                      >
                        Time
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Method: Click to sort HTTP requests by HTTP method (GET, POST, etc.)."
                        active={sortField === 'method'}
                        direction={sortField === 'method' ? sortOrder : 'asc'}
                        onClick={() => handleSort('method')}
                      >
                        Method
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Host: Click to sort HTTP requests by destination host."
                        active={sortField === 'host'}
                        direction={sortField === 'host' ? sortOrder : 'asc'}
                        onClick={() => handleSort('host')}
                      >
                        Host
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>URL</TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Status: Click to sort HTTP requests by response status code."
                        active={sortField === 'statusCode'}
                        direction={sortField === 'statusCode' ? sortOrder : 'asc'}
                        onClick={() => handleSort('statusCode')}
                      >
                        Status
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Size: Click to sort HTTP requests by total data size (request + response)."
                        active={sortField === 'size'}
                        direction={sortField === 'size' ? sortOrder : 'asc'}
                        onClick={() => handleSort('size')}
                      >
                        Size
                      </TableSortLabel>
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedHTTP.map((http, idx) => {
                    const rowKey = `${http.srcIP}-${http.dstIP}-${http.timestamp}-${idx}`;
                    const totalSize = http.reqContentLength + http.resContentLength;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="HTTP Row: Click to expand and view detailed information about this HTTP request/response."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed HTTP information.">
                              <ExpandMoreIcon 
                                sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} 
                              />
                            </IconButton>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                              {formatTimestamp(http.timestamp)}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="HTTP Method: The HTTP request method used (GET, POST, PUT, DELETE, etc.)."
                              label={http.method || 'N/A'}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                maxWidth: 200,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                              data-learn="Host: The destination host from the HTTP Host header."
                            >
                              {http.host || 'N/A'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.75rem',
                                maxWidth: 250,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                              data-learn="URL: The full request URL path and query string."
                            >
                              {http.url || '/'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="HTTP Status Code: The response status code (200 OK, 404 Not Found, etc.)."
                              label={http.statusCode || 'N/A'}
                              size="small"
                              color={getStatusCodeColor(http.statusCode) as any}
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {formatBytes(totalSize)}
                            </Typography>
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="HTTP Details: Extended information about this HTTP request and response including headers, cookies, encoding, and endpoints.">
                                <Grid container spacing={2}>
                                  {/* Basic Info */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Request Details
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Time: {formatTimestamp(http.timestamp)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Method: {http.method}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Protocol: {http.proto}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Host: {http.host}
                                    </Typography>
                                    <Typography 
                                      variant="body2" 
                                      color="text.secondary"
                                      sx={{ 
                                        wordBreak: 'break-all',
                                        maxWidth: '100%',
                                      }}
                                    >
                                      URL: {http.url}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Response Details */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Response Details
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Status Code: {http.statusCode}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Content Type: {http.contentType || 'N/A'}
                                    </Typography>
                                    {http.resContentType && http.resContentType !== http.contentType && (
                                      <Typography variant="body2" color="text.secondary">
                                        Response Content Type: {http.resContentType}
                                      </Typography>
                                    )}
                                    {http.contentTypeDetected && (
                                      <Typography variant="body2" color="text.secondary">
                                        Detected Content Type: {http.contentTypeDetected}
                                      </Typography>
                                    )}
                                    {http.resContentTypeDetected && (
                                      <Typography variant="body2" color="text.secondary">
                                        Detected Response Type: {http.resContentTypeDetected}
                                      </Typography>
                                    )}
                                    <Typography variant="body2" color="text.secondary">
                                      Server: {http.serverName || 'N/A'}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Request Size: {formatBytes(http.reqContentLength)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Response Size: {formatBytes(http.resContentLength)}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Network Details */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Network Information
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Source IP: {http.srcIP}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Destination IP: {http.dstIP}
                                    </Typography>
                                    {http.reqContentEncoding && (
                                      <Typography variant="body2" color="text.secondary">
                                        Request Encoding: {http.reqContentEncoding}
                                      </Typography>
                                    )}
                                    {http.resContentEncoding && (
                                      <Typography variant="body2" color="text.secondary">
                                        Response Encoding: {http.resContentEncoding}
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Timing Information */}
                                  {(http.doneAfter > 0 || http.dnsDoneAfter > 0 || http.tlsDoneAfter > 0 || http.firstByteAfter > 0) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Timing (HTTP Proxy Mode)
                                      </Typography>
                                      {http.doneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          Total Duration: {(http.doneAfter / 1e6).toFixed(2)}ms
                                        </Typography>
                                      )}
                                      {http.dnsDoneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          DNS Lookup: {(http.dnsDoneAfter / 1e6).toFixed(2)}ms
                                        </Typography>
                                      )}
                                      {http.tlsDoneAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          TLS Handshake: {(http.tlsDoneAfter / 1e6).toFixed(2)}ms
                                        </Typography>
                                      )}
                                      {http.firstByteAfter > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          First Byte: {(http.firstByteAfter / 1e6).toFixed(2)}ms
                                        </Typography>
                                      )}
                                    </Grid>
                                  )}
                                  
                                  {/* User Agent & Referer */}
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Client Information
                                    </Typography>
                                    {http.userAgent && (
                                      <Typography 
                                        variant="body2" 
                                        color="text.secondary"
                                        sx={{ wordBreak: 'break-all', mb: 1 }}
                                      >
                                        User-Agent: {http.userAgent}
                                      </Typography>
                                    )}
                                    {http.referer && (
                                      <Typography 
                                        variant="body2" 
                                        color="text.secondary"
                                        sx={{ wordBreak: 'break-all' }}
                                      >
                                        Referer: {http.referer}
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* URL Parameters */}
                                  {http.parameters && Object.keys(http.parameters).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        URL Parameters ({Object.keys(http.parameters).length})
                                      </Typography>
                                      <Box sx={{ maxHeight: 200, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>
                                        {Object.entries(http.parameters).map(([key, value]) => (
                                          <Typography 
                                            key={key}
                                            variant="body2" 
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}
                                          >
                                            <strong>{key}:</strong> {value}
                                          </Typography>
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Request Headers */}
                                  {http.requestHeader && Object.keys(http.requestHeader).length > 0 && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Request Headers ({Object.keys(http.requestHeader).length})
                                      </Typography>
                                      <Box sx={{ maxHeight: 300, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>
                                        {Object.entries(http.requestHeader).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => (
                                          <Typography 
                                            key={key}
                                            variant="body2" 
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}
                                          >
                                            <strong>{key}:</strong> {value}
                                          </Typography>
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Response Headers */}
                                  {http.responseHeader && Object.keys(http.responseHeader).length > 0 && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Response Headers ({Object.keys(http.responseHeader).length})
                                      </Typography>
                                      <Box sx={{ maxHeight: 300, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1 }}>
                                        {Object.entries(http.responseHeader).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => (
                                          <Typography 
                                            key={key}
                                            variant="body2" 
                                            color="text.secondary"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}
                                          >
                                            <strong>{key}:</strong> {value}
                                          </Typography>
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Action Buttons */}
                                  <Grid item xs={12}>
                                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                      <Button
                                        data-learn="Show Connection: Navigate to the Connections page to view the exact TCP/UDP connection for this HTTP request using the flow identifier."
                                        variant="outlined"
                                        startIcon={<CableIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          // Use flow identifier for exact connection matching, fallback to IP:port combination
                                          const searchTerm = http.flow || `${http.srcIP}:${http.srcPort}`;
                                          router.push(`/connections?search=${encodeURIComponent(searchTerm)}`);
                                        }}
                                        size="small"
                                      >
                                        Show Connection
                                      </Button>
                                      <Button
                                        data-learn="Download as PCAP: Download a filtered PCAP file containing only the packets from this HTTP request/response."
                                        variant="outlined"
                                        startIcon={<DownloadIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleDownloadPCAP(http);
                                        }}
                                        size="small"
                                      >
                                        Download PCAP
                                      </Button>
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
              data-learn="Table Pagination: Navigate through pages of HTTP requests and change how many rows to display per page."
              component="div"
              count={filteredHTTP.length}
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

      {/* Conversation Modal */}
      {selectedHTTP && (
        <ConversationModal
          open={conversationModalOpen}
          onClose={handleCloseConversationModal}
          srcIP={selectedHTTP.srcIP}
          srcPort="80"
          dstIP={selectedHTTP.dstIP}
          dstPort="80"
          protocol="TCP"
        />
      )}
    </Layout>
  );
}

