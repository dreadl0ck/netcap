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
  Tabs,
  Tab,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  BugReport as BugReportIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Computer as ComputerIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatBytes, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import dynamic from 'next/dynamic';

// Dynamically import SyntaxHighlighter to avoid SSR issues
const SyntaxHighlighter = dynamic(() => import('react-syntax-highlighter').then(mod => mod.Prism), { ssr: false });
import { tomorrow } from 'react-syntax-highlighter/dist/cjs/styles/prism';

interface VulnerabilitySummary {
  id: string;
  description: string;
  severity: string;
  v2Score: string;
  accessVector: string;
  versions: string[];
  count: number;
  software: string;
  affected: number;
}

interface ExploitSummary {
  id: string;
  description: string;
  file: string;
  date: string;
  author: string;
  type: string;
  platform: string;
  port: string;
  count: number;
  software: string;
  affected: number;
}

interface HostVulnerabilitySummary {
  host: string;
  vulnerabilities: number;
  exploits: number;
  topSeverity: string;
  softwareCount: number;
}

interface VulnerabilitiesResponse {
  vulnerabilities: VulnerabilitySummary[];
  exploits: ExploitSummary[];
  affectedHosts: HostVulnerabilitySummary[];
  totalVulns: number;
  totalExploits: number;
}

type SortOrder = 'asc' | 'desc';

export default function VulnerabilitiesPage() {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchQuery, setSearchQuery] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<string>('count');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [exploitCode, setExploitCode] = useState<{[key: string]: {content: string, language: string, loading: boolean, error?: string}}>({});

  // Fetch status and input files
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch vulnerabilities data
  const { data: vulnerabilitiesData, error, mutate } = useSWR<VulnerabilitiesResponse>(
    'vulnerabilities',
    () => fetch(`${getBackendUrl()}/api/vulnerabilities`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const vulnerabilities = vulnerabilitiesData?.vulnerabilities || [];
  const exploits = vulnerabilitiesData?.exploits || [];
  const affectedHosts = vulnerabilitiesData?.affectedHosts || [];
  const totalVulns = vulnerabilitiesData?.totalVulns || 0;
  const totalExploits = vulnerabilitiesData?.totalExploits || 0;

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0);
  };

  const filteredData = useMemo(() => {
    let data: any[] = [];
    if (tabValue === 0) data = vulnerabilities;
    else if (tabValue === 1) data = exploits;
    else data = affectedHosts;

    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      data = data.filter((item: any) => 
        (item.id && item.id.toLowerCase().includes(query)) ||
        (item.description && item.description.toLowerCase().includes(query)) ||
        (item.software && item.software.toLowerCase().includes(query)) ||
        (item.host && item.host.toLowerCase().includes(query))
      );
    }

    // Sorting
    data = [...data].sort((a, b) => {
      let comparison = 0;
      // Simplified sorting logic based on common fields
      if (sortField === 'count' && 'count' in a) {
        comparison = a.count - b.count;
      } else if (sortField === 'affected' && 'affected' in a) {
        comparison = a.affected - b.affected;
      } else if (sortField === 'id' && 'id' in a) {
        comparison = a.id.localeCompare(b.id);
      } else if (sortField === 'severity' && 'severity' in a) {
        // Custom severity sort
        const sevScore = (s: string) => s === 'HIGH' ? 3 : s === 'MEDIUM' ? 2 : s === 'LOW' ? 1 : 0;
        comparison = sevScore(a.severity) - sevScore(b.severity);
      } else if (sortField === 'vulnerabilities' && 'vulnerabilities' in a) {
        comparison = a.vulnerabilities - b.vulnerabilities;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return data;
  }, [vulnerabilities, exploits, affectedHosts, tabValue, searchQuery, sortField, sortOrder]);

  const paginatedData = filteredData.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  const handleChangePage = (_event: unknown, newPage: number) => setPage(newPage);
  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };
  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    setPage(0);
    setSearchQuery('');
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

  const fetchExploitCode = async (exploitId: string, filePath: string) => {
    // If already loaded, don't fetch again
    if (exploitCode[exploitId]) {
      return;
    }

    // Set loading state
    setExploitCode(prev => ({
      ...prev,
      [exploitId]: { content: '', language: 'text', loading: true }
    }));

    try {
      const response = await fetch(`${getBackendUrl()}/api/vulnerabilities/exploit-file?file=${encodeURIComponent(filePath)}`);
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: response.statusText }));
        const errorMessage = errorData.error || `Failed to fetch exploit file: ${response.statusText}`;
        const hint = errorData.hint || '';
        throw new Error(hint ? `${errorMessage}\n${hint}` : errorMessage);
      }
      const data = await response.json();
      setExploitCode(prev => ({
        ...prev,
        [exploitId]: { content: data.content, language: data.language, loading: false }
      }));
    } catch (error) {
      console.error('Error fetching exploit code:', error);
      setExploitCode(prev => ({
        ...prev,
        [exploitId]: { 
          content: '', 
          language: 'text', 
          loading: false, 
          error: error instanceof Error ? error.message : 'Failed to load exploit code'
        }
      }));
    }
  };

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view discovered vulnerabilities."
    />
  );

  if (error) return <Layout title="Vulnerabilities" headerAction={fileSelector}><Alert severity="error">Error: {error.message}</Alert></Layout>;

  return (
    <Layout title="Vulnerabilities" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        {/* Summary Cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <BugReportIcon color="error" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">Total Vulnerabilities</Typography>
                    <Typography variant="h5">{totalVulns.toLocaleString()}</Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <WarningIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">Total Exploits</Typography>
                    <Typography variant="h5">{totalExploits.toLocaleString()}</Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ComputerIcon color="info" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">Affected Hosts</Typography>
                    <Typography variant="h5">{affectedHosts.length.toLocaleString()}</Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Charts */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 400 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  key={`severity-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/severity?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title="Vulnerability Severity"
                />
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 400 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  key={`top-software-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/top-vulnerable-software?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title="Top Vulnerable Software"
                />
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 400 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  key={`access-vectors-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/access-vectors?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title="Access Vectors"
                />
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 400 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  key={`exploit-types-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/exploit-types?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title="Exploit Types"
                />
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12}>
            <Card sx={{ height: 400 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  key={`top-affected-hosts-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/top-affected-hosts?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title="Top Affected Hosts"
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Tabs and Table */}
        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label="Vulnerabilities" />
            <Tab label="Exploits" />
            <Tab label="Affected Hosts" />
          </Tabs>
        </Box>

        <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
          <TextField
            size="small"
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            sx={{ minWidth: 300 }}
          />
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleRefresh}>Refresh</Button>
        </Box>

        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                {tabValue === 0 && (
                  <>
                    <TableCell width={40} />
                    <TableCell onClick={() => handleSort('id')} sx={{ cursor: 'pointer' }}>ID</TableCell>
                    <TableCell onClick={() => handleSort('severity')} sx={{ cursor: 'pointer' }}>Severity</TableCell>
                    <TableCell>Software</TableCell>
                    <TableCell onClick={() => handleSort('count')} sx={{ cursor: 'pointer' }} align="right">Count</TableCell>
                    <TableCell onClick={() => handleSort('affected')} sx={{ cursor: 'pointer' }} align="right">Affected Hosts</TableCell>
                  </>
                )}
                {tabValue === 1 && (
                  <>
                    <TableCell width={40} />
                    <TableCell onClick={() => handleSort('id')} sx={{ cursor: 'pointer' }}>ID</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Platform</TableCell>
                    <TableCell>Software</TableCell>
                    <TableCell onClick={() => handleSort('count')} sx={{ cursor: 'pointer' }} align="right">Count</TableCell>
                  </>
                )}
                {tabValue === 2 && (
                  <>
                    <TableCell onClick={() => handleSort('host')} sx={{ cursor: 'pointer' }}>Host</TableCell>
                    <TableCell onClick={() => handleSort('vulnerabilities')} sx={{ cursor: 'pointer' }} align="right">Vulns</TableCell>
                    <TableCell align="right">Exploits</TableCell>
                    <TableCell>Top Severity</TableCell>
                  </>
                )}
              </TableRow>
            </TableHead>
            <TableBody>
              {paginatedData.map((row: any, idx) => {
                const key = tabValue === 0 ? row.id : tabValue === 1 ? row.id : row.host;
                return (
                  <>
                    <TableRow key={key + idx} hover onClick={() => tabValue !== 2 && handleRowClick(key)} sx={{ cursor: tabValue !== 2 ? 'pointer' : 'default' }}>
                      {tabValue === 0 && (
                        <>
                          <TableCell>
                            <IconButton size="small">
                              <ExpandMoreIcon sx={{ transform: expandedRow === key ? 'rotate(180deg)' : 'rotate(0deg)' }} />
                            </IconButton>
                          </TableCell>
                          <TableCell>{row.id}</TableCell>
                          <TableCell>
                            <Chip 
                              label={row.severity || 'UNKNOWN'} 
                              size="small" 
                              color={
                                row.severity === 'HIGH' ? 'error' : 
                                row.severity === 'MEDIUM' ? 'warning' : 
                                row.severity === 'LOW' ? 'info' :
                                'default'
                              } 
                            />
                          </TableCell>
                          <TableCell>{row.software}</TableCell>
                          <TableCell align="right">{row.count}</TableCell>
                          <TableCell align="right">{row.affected}</TableCell>
                        </>
                      )}
                      {tabValue === 1 && (
                        <>
                          <TableCell>
                            <IconButton size="small">
                              <ExpandMoreIcon sx={{ transform: expandedRow === key ? 'rotate(180deg)' : 'rotate(0deg)' }} />
                            </IconButton>
                          </TableCell>
                          <TableCell>{row.id}</TableCell>
                          <TableCell>{row.type}</TableCell>
                          <TableCell>{row.platform}</TableCell>
                          <TableCell>{row.software}</TableCell>
                          <TableCell align="right">{row.count}</TableCell>
                        </>
                      )}
                      {tabValue === 2 && (
                        <>
                          <TableCell>{row.host}</TableCell>
                          <TableCell align="right">{row.vulnerabilities}</TableCell>
                          <TableCell align="right">{row.exploits}</TableCell>
                          <TableCell>
                            {row.topSeverity ? (
                              <Chip 
                                label={row.topSeverity} 
                                size="small" 
                                color={
                                  row.topSeverity === 'HIGH' ? 'error' : 
                                  row.topSeverity === 'MEDIUM' ? 'warning' : 
                                  row.topSeverity === 'LOW' ? 'info' :
                                  'default'
                                } 
                              />
                            ) : (
                              <Chip 
                                label="UNKNOWN" 
                                size="small" 
                                color="default" 
                              />
                            )}
                          </TableCell>
                        </>
                      )}
                    </TableRow>
                    {(tabValue === 0 || tabValue === 1) && (
                      <TableRow>
                        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
                          <Collapse in={expandedRow === key} timeout="auto" unmountOnExit>
                            <Box sx={{ py: 2, px: 2 }}>
                              {tabValue === 0 && (
                                <>
                                  <Typography variant="h6" gutterBottom>
                                    {row.id}
                                  </Typography>
                                  <Box sx={{ mb: 2 }}>
                                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                      Description
                                    </Typography>
                                    <Typography variant="body2" paragraph>
                                      {row.description || 'No description available'}
                                    </Typography>
                                  </Box>
                                  <Grid container spacing={2}>
                                    <Grid item xs={12} md={6}>
                                      <Card variant="outlined" sx={{ p: 2 }}>
                                        <Typography variant="subtitle2" gutterBottom>
                                          Severity & Scoring
                                        </Typography>
                                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                            <Typography variant="body2" color="text.secondary">
                                              Severity:
                                            </Typography>
                                            <Chip 
                                              label={row.severity || 'UNKNOWN'} 
                                              size="small" 
                                              color={
                                                row.severity === 'HIGH' ? 'error' : 
                                                row.severity === 'MEDIUM' ? 'warning' : 
                                                row.severity === 'LOW' ? 'info' :
                                                'default'
                                              } 
                                            />
                                          </Box>
                                          {row.v2Score && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <Typography variant="body2" color="text.secondary">
                                                CVSS v2 Score:
                                              </Typography>
                                              <Typography variant="body2" fontWeight="medium">
                                                {row.v2Score}
                                              </Typography>
                                            </Box>
                                          )}
                                          {row.accessVector && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <Typography variant="body2" color="text.secondary">
                                                Access Vector:
                                              </Typography>
                                              <Typography variant="body2" fontWeight="medium">
                                                {row.accessVector}
                                              </Typography>
                                            </Box>
                                          )}
                                        </Box>
                                      </Card>
                                    </Grid>
                                    <Grid item xs={12} md={6}>
                                      <Card variant="outlined" sx={{ p: 2 }}>
                                        <Typography variant="subtitle2" gutterBottom>
                                          Impact
                                        </Typography>
                                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <Typography variant="body2" color="text.secondary">
                                              Software:
                                            </Typography>
                                            <Typography variant="body2" fontWeight="medium">
                                              {row.software || 'N/A'}
                                            </Typography>
                                          </Box>
                                          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <Typography variant="body2" color="text.secondary">
                                              Occurrences:
                                            </Typography>
                                            <Typography variant="body2" fontWeight="medium">
                                              {row.count}
                                            </Typography>
                                          </Box>
                                          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <Typography variant="body2" color="text.secondary">
                                              Affected Hosts:
                                            </Typography>
                                            <Typography variant="body2" fontWeight="medium">
                                              {row.affected}
                                            </Typography>
                                          </Box>
                                        </Box>
                                      </Card>
                                    </Grid>
                                    {row.versions && row.versions.length > 0 && (
                                      <Grid item xs={12}>
                                        <Card variant="outlined" sx={{ p: 2 }}>
                                          <Typography variant="subtitle2" gutterBottom>
                                            Affected Versions
                                          </Typography>
                                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                            {row.versions.map((version: string) => (
                                              <Chip 
                                                key={version} 
                                                label={version} 
                                                size="small" 
                                                variant="outlined"
                                              />
                                            ))}
                                          </Box>
                                        </Card>
                                      </Grid>
                                    )}
                                  </Grid>
                                </>
                              )}
                              {tabValue === 1 && (
                                <>
                                  <Typography variant="h6" gutterBottom>
                                    {row.id}
                                  </Typography>
                                  <Box sx={{ mb: 2 }}>
                                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                      Description
                                    </Typography>
                                    <Typography variant="body2" paragraph>
                                      {row.description || 'No description available'}
                                    </Typography>
                                  </Box>
                                  <Grid container spacing={2}>
                                    <Grid item xs={12} md={6}>
                                      <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                                        <Typography variant="subtitle2" gutterBottom>
                                          Exploit Details
                                        </Typography>
                                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                          {row.type && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <Typography variant="body2" color="text.secondary">
                                                Type:
                                              </Typography>
                                              <Typography variant="body2" fontWeight="medium">
                                                {row.type}
                                              </Typography>
                                            </Box>
                                          )}
                                          {row.platform && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <Typography variant="body2" color="text.secondary">
                                                Platform:
                                              </Typography>
                                              <Typography variant="body2" fontWeight="medium">
                                                {row.platform}
                                              </Typography>
                                            </Box>
                                          )}
                                          {row.port && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <Typography variant="body2" color="text.secondary">
                                                Port:
                                              </Typography>
                                              <Typography variant="body2" fontWeight="medium">
                                                {row.port}
                                              </Typography>
                                            </Box>
                                          )}
                                          {row.file && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <Typography variant="body2" color="text.secondary">
                                                File:
                                              </Typography>
                                              <Typography variant="body2" fontWeight="medium" sx={{ 
                                                maxWidth: 200, 
                                                overflow: 'hidden', 
                                                textOverflow: 'ellipsis',
                                                whiteSpace: 'nowrap'
                                              }}>
                                                {row.file}
                                              </Typography>
                                            </Box>
                                          )}
                                        </Box>
                                      </Card>
                                    </Grid>
                                    <Grid item xs={12} md={6}>
                                      <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                                        <Typography variant="subtitle2" gutterBottom>
                                          Impact & Metadata
                                        </Typography>
                                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <Typography variant="body2" color="text.secondary">
                                              Software:
                                            </Typography>
                                            <Typography variant="body2" fontWeight="medium">
                                              {row.software || 'N/A'}
                                            </Typography>
                                          </Box>
                                          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <Typography variant="body2" color="text.secondary">
                                              Occurrences:
                                            </Typography>
                                            <Typography variant="body2" fontWeight="medium">
                                              {row.count}
                                            </Typography>
                                          </Box>
                                          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <Typography variant="body2" color="text.secondary">
                                              Affected Hosts:
                                            </Typography>
                                            <Typography variant="body2" fontWeight="medium">
                                              {row.affected}
                                            </Typography>
                                          </Box>
                                          {row.author && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <Typography variant="body2" color="text.secondary">
                                                Author:
                                              </Typography>
                                              <Typography variant="body2" fontWeight="medium">
                                                {row.author}
                                              </Typography>
                                            </Box>
                                          )}
                                          {row.date && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                                              <Typography variant="body2" color="text.secondary">
                                                Date:
                                              </Typography>
                                              <Typography variant="body2" fontWeight="medium">
                                                {row.date}
                                              </Typography>
                                            </Box>
                                          )}
                                        </Box>
                                      </Card>
                                    </Grid>
                                    {row.file && (
                                      <Grid item xs={12}>
                                        <Card variant="outlined" sx={{ p: 2, mt: 2 }}>
                                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                                          <Typography variant="subtitle2">
                                            Exploit POC Code
                                          </Typography>
                                          {!exploitCode[row.id] && (
                                            <Button
                                              size="small"
                                              startIcon={<CodeIcon />}
                                              onClick={() => fetchExploitCode(row.id, row.file)}
                                              variant="outlined"
                                            >
                                              Load Code
                                            </Button>
                                          )}
                                        </Box>
                                        {exploitCode[row.id]?.loading && (
                                          <Box sx={{ display: 'flex', justifyContent: 'center', p: 2 }}>
                                            <CircularProgress size={24} />
                                          </Box>
                                        )}
                                        {exploitCode[row.id]?.error && (
                                          <Alert severity="warning">
                                            <Typography variant="body2" component="div" sx={{ whiteSpace: 'pre-line' }}>
                                              {exploitCode[row.id].error}
                                            </Typography>
                                          </Alert>
                                        )}
                                        {exploitCode[row.id]?.content && (
                                          <Box sx={{ 
                                            maxHeight: 600, 
                                            overflow: 'auto',
                                            '& pre': {
                                              margin: 0,
                                              fontSize: '0.85rem',
                                            }
                                          }}>
                                            <SyntaxHighlighter
                                              language={exploitCode[row.id].language}
                                              style={tomorrow}
                                              showLineNumbers
                                              wrapLines
                                            >
                                              {exploitCode[row.id].content}
                                            </SyntaxHighlighter>
                                          </Box>
                                        )}
                                        </Card>
                                      </Grid>
                                    )}
                                  </Grid>
                                </>
                              )}
                            </Box>
                          </Collapse>
                        </TableCell>
                      </TableRow>
                    )}
                  </>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          component="div"
          count={filteredData.length}
          page={page}
          onPageChange={handleChangePage}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Box>
    </Layout>
  );
}

