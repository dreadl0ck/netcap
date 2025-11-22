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
  Language as LanguageIcon,
  TrendingUp as TrendingUpIcon,
  Public as PublicIcon,
  AccountTree as AccountTreeIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import { api, formatTimestamp, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';

interface DomainSummary {
  domain: string;
  queryCount: number;
  uniqueClients: number;
  recordTypes: string[];
  responseCodes: number[];
  firstSeen: number;
  lastSeen: number;
  isSubdomain: boolean;
  parentDomain: string;
  resolvedIPs: string[];
}

interface DomainsResponse {
  domains: DomainSummary[];
  totalCount: number;
}

type DomainSortField = 'domain' | 'queries' | 'clients' | 'type';
type SortOrder = 'asc' | 'desc';

export default function DomainsPage() {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'root' | 'subdomain'>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<DomainSortField>('queries');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch domains data
  const { data: domainsData, error, mutate } = useSWR<DomainsResponse>(
    'domains',
    () => fetch(`${getBackendUrl()}/api/domains`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const domains = domainsData?.domains || [];
  const totalCount = domainsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: DomainSortField) => {
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
  const filteredDomains = useMemo(() => {
    let filtered = domains;

    // Apply type filter
    if (filterType === 'root') {
      filtered = filtered.filter(d => !d.isSubdomain);
    } else if (filterType === 'subdomain') {
      filtered = filtered.filter(d => d.isSubdomain);
    }

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(d =>
        d.domain.toLowerCase().includes(query) ||
        (d.parentDomain || '').toLowerCase().includes(query) ||
        (d.recordTypes || []).some(rt => rt.toLowerCase().includes(query)) ||
        (d.resolvedIPs || []).some(ip => ip.toLowerCase().includes(query))
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'domain':
          comparison = a.domain.localeCompare(b.domain);
          break;
        case 'queries':
          comparison = a.queryCount - b.queryCount;
          break;
        case 'clients':
          comparison = a.uniqueClients - b.uniqueClients;
          break;
        case 'type':
          // Sort root domains first
          if (a.isSubdomain === b.isSubdomain) {
            comparison = a.domain.localeCompare(b.domain);
          } else {
            comparison = a.isSubdomain ? 1 : -1;
          }
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [domains, filterType, searchQuery, sortField, sortOrder]);

  // Paginate domains
  const paginatedDomains = filteredDomains.slice(
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

  const handleRowClick = (domain: string) => {
    setExpandedRow(expandedRow === domain ? null : domain);
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
        data-learn="Capture Selector: Switch between different analyzed PCAP files to view their DNS domains and queries."
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
            </Box>
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  ) : null;

  // Calculate summary statistics
  const totalQueries = domains.reduce((sum, d) => sum + d.queryCount, 0);
  const uniqueTLDs = new Set(domains.map(d => {
    const parts = d.domain.split('.');
    return parts[parts.length - 1];
  })).size;
  const subdomainCount = domains.filter(d => d.isSubdomain).length;

  if (error) {
    return (
      <Layout title="Domains" headerAction={fileSelector}>
        <Alert severity="error">Error loading domains: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Domains" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        {/* Summary Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Unique Domains: Total number of unique domain names found in DNS queries.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <LanguageIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique Domains
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
            <Card data-learn="Total Queries: Sum of all DNS queries made to all domains.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TrendingUpIcon color="success" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Queries
                    </Typography>
                    <Typography variant="h5">
                      {totalQueries.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Top-Level Domains: Number of different TLDs (.com, .org, .net, etc.) found.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <PublicIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Unique TLDs
                    </Typography>
                    <Typography variant="h5">
                      {uniqueTLDs.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Subdomains: Number of subdomain entries (e.g., www.example.com, api.service.com).">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <AccountTreeIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Subdomains
                    </Typography>
                    <Typography variant="h5">
                      {subdomainCount.toLocaleString()}
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
                  data-learn="Top Domains Chart: Bar chart showing the most frequently queried domain names."
                  key={`top-by-queries-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/top-by-queries`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Domains by Query Count"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="TLD Distribution: Pie chart showing the distribution of top-level domains (.com, .org, etc.)."
                  key={`tlds-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/tlds?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="TLD Distribution"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Record Types: Bar chart showing DNS query types (A, AAAA, CNAME, MX, etc.)."
                  key={`record-types-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/record-types`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="DNS Record Types"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Subdomain Distribution: Pie chart comparing root domain queries vs subdomain queries."
                  key={`subdomain-distribution-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/subdomain-distribution`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Subdomain Distribution"
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Filters and Actions */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField
            data-learn="Domain Search: Filter domains by name, parent domain, record type, or resolved IP address."
            size="small"
            placeholder="Search domains..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
          />
          
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <Select
              data-learn="Domain Type Filter: Filter to show all domains, only root domains, or only subdomains."
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as 'all' | 'root' | 'subdomain');
                setPage(0);
              }}
            >
              <MenuItem value="all">All Domains</MenuItem>
              <MenuItem value="root">Root Domains</MenuItem>
              <MenuItem value="subdomain">Subdomains</MenuItem>
            </Select>
          </FormControl>
          
          <Button
            data-learn="Refresh Button: Reload domain data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {(searchQuery || filterType !== 'all') ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredDomains.length} of {totalCount} domains
            </Typography>
          ) : null}
        </Box>

        {/* Domains Table */}
        {!domainsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <LanguageIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Domains Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No DNS queries have been captured yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Domains Table: Detailed list of all discovered domains with query statistics and sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Domain: Click to sort domains alphabetically by name."
                        active={sortField === 'domain'}
                        direction={sortField === 'domain' ? sortOrder : 'asc'}
                        onClick={() => handleSort('domain')}
                      >
                        Domain Name
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Type: Click to sort by domain type (root domain vs subdomain)."
                        active={sortField === 'type'}
                        direction={sortField === 'type' ? sortOrder : 'asc'}
                        onClick={() => handleSort('type')}
                      >
                        Type
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Queries: Click to sort domains by number of DNS queries."
                        active={sortField === 'queries'}
                        direction={sortField === 'queries' ? sortOrder : 'asc'}
                        onClick={() => handleSort('queries')}
                      >
                        Queries
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Clients: Click to sort by number of unique clients querying this domain."
                        active={sortField === 'clients'}
                        direction={sortField === 'clients' ? sortOrder : 'asc'}
                        onClick={() => handleSort('clients')}
                      >
                        Clients
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>Record Types</TableCell>
                    <TableCell>Resolved IPs</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedDomains.map((domain) => (
                    <>
                      <TableRow 
                        key={domain.domain}
                        hover
                        onClick={() => handleRowClick(domain.domain)}
                        sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                        data-learn="Domain Row: Click to expand and view detailed information about this domain."
                      >
                        <TableCell>
                          <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed domain information.">
                            <ExpandMoreIcon 
                              sx={{ 
                                transform: expandedRow === domain.domain ? 'rotate(180deg)' : 'rotate(0deg)',
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
                              wordBreak: 'break-word'
                            }}
                            data-learn="Domain Name: The fully qualified domain name extracted from DNS queries."
                          >
                            {domain.domain}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            data-learn="Domain Type Tag: Indicates whether this is a root domain or a subdomain."
                            label={domain.isSubdomain ? 'Subdomain' : 'Root'}
                            size="small"
                            color={domain.isSubdomain ? 'secondary' : 'primary'}
                            sx={{ fontSize: '0.7rem' }}
                          />
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {domain.queryCount.toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell align="right">
                          <Typography variant="body2">
                            {domain.uniqueClients.toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(domain.recordTypes || []).slice(0, 3).map((rt, idx) => (
                              <Chip
                                key={idx}
                                label={rt}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn="Record Type: DNS query type (A for IPv4, AAAA for IPv6, CNAME for alias, etc.)."
                              />
                            ))}
                            {(domain.recordTypes || []).length > 3 && (
                              <Chip
                                label={`+${(domain.recordTypes || []).length - 3}`}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn="More Record Types: Click the row to see all DNS record types."
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(domain.resolvedIPs || []).slice(0, 2).map((ip, idx) => (
                              <Chip
                                key={idx}
                                label={ip}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20, fontFamily: 'monospace' }}
                                data-learn="Resolved IP: IP address that this domain name resolved to in DNS responses."
                              />
                            ))}
                            {(domain.resolvedIPs || []).length > 2 && (
                              <Chip
                                label={`+${(domain.resolvedIPs || []).length - 2}`}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn="More IPs: Click the row to see all resolved IP addresses."
                              />
                            )}
                          </Box>
                        </TableCell>
                      </TableRow>
                      
                      {/* Expandable Row Details */}
                      <TableRow>
                        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}>
                          <Collapse in={expandedRow === domain.domain} timeout="auto" unmountOnExit>
                            <Box sx={{ py: 2 }} data-learn="Domain Details: Extended information about DNS queries and responses for this domain.">
                              <Grid container spacing={2}>
                                {/* Time Range */}
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Query Timeline
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    First Seen: {formatTimestamp(domain.firstSeen)}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Last Seen: {formatTimestamp(domain.lastSeen)}
                                  </Typography>
                                </Grid>
                                
                                {/* Statistics */}
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Statistics
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Total Queries: {domain.queryCount.toLocaleString()}
                                  </Typography>
                                  <Typography variant="body2" color="text.secondary">
                                    Unique Clients: {domain.uniqueClients.toLocaleString()}
                                  </Typography>
                                  {domain.isSubdomain && domain.parentDomain && (
                                    <Typography variant="body2" color="text.secondary">
                                      Parent Domain: {domain.parentDomain}
                                    </Typography>
                                  )}
                                </Grid>
                                
                                {/* All Record Types */}
                                {(domain.recordTypes || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      All Record Types ({(domain.recordTypes || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(domain.recordTypes || []).map((rt, idx) => (
                                        <Chip
                                          key={idx}
                                          label={rt}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* Response Codes */}
                                {(domain.responseCodes || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      DNS Response Codes
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(domain.responseCodes || []).map((rc, idx) => {
                                        const responseCodeName = rc === 0 ? 'Success' : 
                                                               rc === 1 ? 'Format Error' :
                                                               rc === 2 ? 'Server Failure' :
                                                               rc === 3 ? 'Name Error' :
                                                               rc === 4 ? 'Not Implemented' :
                                                               rc === 5 ? 'Refused' :
                                                               `Code ${rc}`;
                                        return (
                                          <Chip
                                            key={idx}
                                            label={`${responseCodeName} (${rc})`}
                                            size="small"
                                            color={rc === 0 ? 'success' : 'error'}
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        );
                                      })}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {/* All Resolved IPs */}
                                {(domain.resolvedIPs || []).length > 0 && (
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      All Resolved IP Addresses ({(domain.resolvedIPs || []).length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {(domain.resolvedIPs || []).map((ip, idx) => (
                                        <Chip
                                          key={idx}
                                          label={ip}
                                          size="small"
                                          color="info"
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
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              data-learn="Table Pagination: Navigate through pages of domains and change how many rows to display per page."
              component="div"
              count={filteredDomains.length}
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

