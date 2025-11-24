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
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  VpnKey as VpnKeyIcon,
  Person as PersonIcon,
  Lock as LockIcon,
  Security as SecurityIcon,
  AccessTime as AccessTimeIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  SyncAlt as SyncAltIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';

interface CredentialSummary {
  timestamp: number;
  service: string;
  flow: string;
  user: string;
  password: string;
  notes: string;
}

interface CredentialsResponse {
  credentials: CredentialSummary[];
  totalCount: number;
}

type CredentialSortField = 'timestamp' | 'service' | 'user' | 'password';
type SortOrder = 'asc' | 'desc';

export default function CredentialsPage() {
  const router = useRouter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<CredentialSortField>('timestamp');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useState<'table' | 'chart'>('table');

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch credentials data
  const { data: credentialsData, error, mutate } = useSWR<CredentialsResponse>(
    'credentials',
    () => fetch(`${getBackendUrl()}/api/credentials`).then(res => res.json()),
    {
      refreshInterval: 10000,
    }
  );

  const credentials = credentialsData?.credentials || [];
  const totalCount = credentialsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: CredentialSortField) => {
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
  const filteredCredentials = useMemo(() => {
    let filtered = credentials;

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(c =>
        c.service.toLowerCase().includes(query) ||
        c.user.toLowerCase().includes(query) ||
        c.password.toLowerCase().includes(query) ||
        c.flow.toLowerCase().includes(query) ||
        (c.notes || '').toLowerCase().includes(query)
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'timestamp':
          comparison = a.timestamp - b.timestamp;
          break;
        case 'service':
          comparison = a.service.localeCompare(b.service);
          break;
        case 'user':
          comparison = a.user.localeCompare(b.user);
          break;
        case 'password':
          comparison = a.password.localeCompare(b.password);
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [credentials, searchQuery, sortField, sortOrder]);

  // Paginate credentials
  const paginatedCredentials = filteredCredentials.slice(
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

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view captured credentials from network traffic."
    />
  );

  // Memoize summary statistics to avoid recalculation on every render
  const stats = useMemo(() => ({
    uniqueServices: new Set(credentials.map(c => c.service)).size,
    uniqueUsers: new Set(credentials.map(c => c.user)).size,
    uniquePasswords: new Set(credentials.map(c => c.password)).size,
    avgPerService: credentials.length > 0 
      ? credentials.length / new Set(credentials.map(c => c.service)).size
      : 0,
  }), [credentials]);

  if (error) {
    return (
      <Layout title="Credentials" headerAction={fileSelector}>
        <Alert severity="error">Error loading credentials: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Credentials" headerAction={fileSelector}>
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
            <Card data-learn="Total Credentials: Number of credentials captured from network traffic in this PCAP file.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <VpnKeyIcon color="primary" data-learn="Key Icon: Indicates credential count including usernames and passwords captured from network traffic." />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Credentials
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
            <Card data-learn="Unique Services: Number of different services/protocols that had credentials captured.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SecurityIcon color="success" data-learn="Services Icon: Count of different protocols where credentials were harvested (HTTP, FTP, SMTP, etc.)." />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Services
                    </Typography>
                    <Typography variant="h5">
                      {stats.uniqueServices.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Unique Users: Number of different usernames found in captured credentials.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <PersonIcon color="warning" data-learn="Users Icon: Number of distinct usernames discovered across all captured credentials." />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Users
                    </Typography>
                    <Typography variant="h5">
                      {stats.uniqueUsers.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Unique Passwords: Number of different passwords found in captured credentials.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <LockIcon color="info" data-learn="Passwords Icon: Number of distinct passwords captured. High reuse indicates weak security practices." />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Passwords
                    </Typography>
                    <Typography variant="h5">
                      {stats.uniquePasswords.toLocaleString()}
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
                  data-learn="Credentials by Service: Bar chart showing which services/protocols had the most credentials captured."
                  key={`by-service-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/credentials/by-service`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Credentials by Service"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Credentials Timeline: Line chart showing when credentials were captured over time."
                  key={`timeline-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/credentials/timeline`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Credentials Timeline"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top Usernames: Bar chart showing the most common usernames in captured credentials."
                  key={`usernames-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/credentials/usernames`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Usernames"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Credentials by Flow: Pie chart showing the distribution of credentials across network flows."
                  key={`flows-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/credentials/flows?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Credentials by Flow"
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
            data-learn="Credential Search: Filter credentials by service, username, password, flow, or notes."
            size="small"
            placeholder="Search credentials..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
          />
          
          <Button
            data-learn="Refresh Button: Reload credential data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery ? (
            <Typography variant="body2" color="text.secondary" data-learn="Filter Count: Shows how many credentials match the current search filter out of the total.">
              Showing {filteredCredentials.length} of {totalCount} credentials
            </Typography>
          ) : null}
        </Box>

        {/* Credentials Table */}
        {!credentialsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }} data-learn="No Credentials: No credentials were found in this capture. This could mean secure protocols were used or harvesters weren't configured for the traffic.">
            <VpnKeyIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Credentials Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No credentials have been captured from network traffic yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Credentials Table: Detailed list of all captured credentials with sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Timestamp: Click to sort credentials by capture time."
                        active={sortField === 'timestamp'}
                        direction={sortField === 'timestamp' ? sortOrder : 'asc'}
                        onClick={() => handleSort('timestamp')}
                      >
                        Time
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Service: Click to sort credentials by service/protocol."
                        active={sortField === 'service'}
                        direction={sortField === 'service' ? sortOrder : 'asc'}
                        onClick={() => handleSort('service')}
                      >
                        Service
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Username: Click to sort credentials by username."
                        active={sortField === 'user'}
                        direction={sortField === 'user' ? sortOrder : 'asc'}
                        onClick={() => handleSort('user')}
                      >
                        Username
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Password: Click to sort credentials by password."
                        active={sortField === 'password'}
                        direction={sortField === 'password' ? sortOrder : 'asc'}
                        onClick={() => handleSort('password')}
                      >
                        Password
                      </TableSortLabel>
                    </TableCell>
                    <TableCell data-learn="Flow: Network flow identifier showing where the credential was captured.">
                      Flow
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedCredentials.map((cred, idx) => {
                    const rowKey = `${cred.timestamp}-${cred.service}-${cred.user}-${idx}`;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Credential Row: Click to expand and view detailed information about this captured credential."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed credential information.">
                              <ExpandMoreIcon 
                                sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} 
                              />
                            </IconButton>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }} data-learn="Capture Time: Exact timestamp when this credential was captured from network traffic.">
                              {formatTimestamp(cred.timestamp)}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              data-learn="Service Tag: Protocol or service where this credential was captured."
                              label={cred.service || 'Unknown'}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }} data-learn="Username: The captured username from the authentication attempt.">
                              {cred.user || '(empty)'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                fontFamily: 'monospace',
                                fontSize: '0.875rem',
                                color: 'error.main',
                                fontWeight: 'bold',
                              }}
                              data-learn="Password: The captured password from the authentication attempt."
                            >
                              {cred.password || '(empty)'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }} data-learn="Flow ID: Network flow identifier showing source and destination IPs and ports where credential was seen.">
                              {cred.flow ? (cred.flow.length > 40 ? cred.flow.substring(0, 37) + '...' : cred.flow) : '-'}
                            </Typography>
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="Credential Details: Extended information about this captured credential including full flow information and notes.">
                                <Grid container spacing={2}>
                                  {/* Timestamp */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Capture Time Field: Full timestamp showing when this credential was captured from the network.">
                                      Capture Time
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      {formatTimestamp(cred.timestamp)}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Service */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Service/Protocol Field: The application-layer protocol where this credential was harvested (e.g., HTTP Basic Auth, FTP, POP3).">
                                      Service/Protocol
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      {cred.service || 'Unknown'}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Username */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Username Field: The full username extracted from the authentication attempt, may include domain or email format.">
                                      Username
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                                      {cred.user || '(empty)'}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Password */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Password Field: The full password or hash captured. Plaintext passwords indicate cleartext protocols were used.">
                                      Password
                                    </Typography>
                                    <Typography 
                                      variant="body2" 
                                      sx={{ 
                                        fontFamily: 'monospace',
                                        color: 'error.main',
                                        fontWeight: 'bold',
                                        wordBreak: 'break-all',
                                      }}
                                    >
                                      {cred.password || '(empty)'}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Flow */}
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom data-learn="Network Flow Field: Complete 5-tuple flow identifier (protocol, src IP:port, dst IP:port) showing the network connection where credential was captured.">
                                      Network Flow
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all', mb: 2 }}>
                                      {cred.flow || 'N/A'}
                                    </Typography>
                                    {cred.flow && (
                                      <Button
                                        data-learn="View Connection: Navigate to the Connections page to see detailed information about this network flow."
                                        variant="outlined"
                                        size="small"
                                        startIcon={<SyncAltIcon />}
                                        onClick={() => router.push(`/connections?search=${encodeURIComponent(cred.flow)}`)}
                                        sx={{ mt: 1 }}
                                      >
                                        View Connection Details
                                      </Button>
                                    )}
                                  </Grid>
                                  
                                  {/* Notes */}
                                  {cred.notes && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Notes Field: Additional context about the credential capture including authentication method, encoding, or protocol-specific details.">
                                        Notes
                                      </Typography>
                                      <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                        {cred.notes}
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
              data-learn="Table Pagination: Navigate through pages of credentials and change how many rows to display per page."
              component="div"
              count={filteredCredentials.length}
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

