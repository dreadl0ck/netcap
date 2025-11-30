/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Fingerprint as FingerprintIcon,
  Download as DownloadIcon,
  Cable as CableIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { formatTimestamp, getBackendUrl } from '../lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation } from '../hooks';

interface CertificateSummary {
  timestamp: number;
  srcIP: string;
  srcPort: number;
  dstIP: string;
  dstPort: number;
  srcMAC: string;
  dstMAC: string;
  chainIndex: number;
  subjectCommonName: string;
  subjectAltNames: string[];
  subjectOrganization: string;
  subjectCountry: string;
  subjectLocality: string;
  subjectProvince: string;
  issuerCommonName: string;
  issuerOrganization: string;
  issuerCountry: string;
  notBefore: number;
  notAfter: number;
  isExpired: boolean;
  isSelfSigned: boolean;
  daysUntilExpiration: number;
  isNotYetValid: boolean;
  hasWeakSignature: boolean;
  hasShortKeySize: boolean;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySize: number;
  serialNumber: string;
  version: number;
  sha256Fingerprint: string;
  sha1Fingerprint: string;
  keyUsage: string[];
  extKeyUsage: string[];
  isCA: boolean;
  maxPathLen: number;
  firstSeen: number;
  lastSeen: number;
  seenCount: number;
  // JA4X certificate fingerprinting
  ja4x: string;
  ja4xRaw: string;
  ja4xDescription: string;
}

interface CertificatesResponse {
  certificates: CertificateSummary[];
  totalCount: number;
}

type CertificateSortField = 'subject' | 'issuer' | 'expiration' | 'seenCount' | 'keySize';
type SortOrder = 'asc' | 'desc';

export default function CertificatesPage() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<CertificateSortField>('seenCount');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useState<'table' | 'chart'>('table');

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Initialize search query from URL parameter
  useEffect(() => {
    if (router.isReady && router.query.search) {
      setSearchQuery(router.query.search as string);
    }
  }, [router.isReady, router.query.search]);

  // Fetch certificates data
  const { data: certificatesData, error, mutate } = useSWR<CertificatesResponse>(
    'certificates',
    () => fetch(`${getBackendUrl()}/api/certificates`).then(res => res.json()),
    {
      refreshInterval: 10000,
    }
  );

  const certificates = certificatesData?.certificates || [];
  const totalCount = certificatesData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: CertificateSortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0);
  };

  // Apply filters and sorting
  const filteredCertificates = useMemo(() => {
    let filtered = certificates;

    // Apply search filter
    if (searchQuery) {
      const searchTerms = searchQuery
        .split(/[,\s]+/)
        .map(term => term.trim())
        .filter(term => term.length > 0);
      
      filtered = filtered.filter(cert => {
        return searchTerms.some(query => {
          const queryLower = query.toLowerCase();
          return (
            cert.subjectCommonName.toLowerCase().includes(queryLower) ||
            cert.issuerCommonName.toLowerCase().includes(queryLower) ||
            cert.subjectOrganization.toLowerCase().includes(queryLower) ||
            cert.issuerOrganization.toLowerCase().includes(queryLower) ||
            cert.srcIP.toLowerCase().includes(queryLower) ||
            cert.dstIP.toLowerCase().includes(queryLower) ||
            cert.sha256Fingerprint.toLowerCase().includes(queryLower) ||
            cert.serialNumber.toLowerCase().includes(queryLower) ||
            (cert.subjectAltNames || []).some(a => a.toLowerCase().includes(queryLower))
          );
        });
      });
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'subject':
          comparison = a.subjectCommonName.localeCompare(b.subjectCommonName);
          break;
        case 'issuer':
          comparison = a.issuerCommonName.localeCompare(b.issuerCommonName);
          break;
        case 'expiration':
          comparison = a.daysUntilExpiration - b.daysUntilExpiration;
          break;
        case 'seenCount':
          comparison = a.seenCount - b.seenCount;
          break;
        case 'keySize':
          comparison = a.publicKeySize - b.publicKeySize;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [certificates, searchQuery, sortField, sortOrder]);

  // Paginate certificates
  const paginatedCertificates = filteredCertificates.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedCertificates.map((cert, idx) => `${cert.sha256Fingerprint}-${idx}`),
    [paginatedCertificates]
  );

  // Enable keyboard navigation for detail views (UP/DOWN arrows)
  useTableKeyboardNavigation(expandedRow, rowKeys, setExpandedRow);

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
  }, [api, mutateStatus, mutate]);

  const handleRowClick = useCallback((key: string) => {
    setExpandedRow(prev => prev === key ? null : key);
  }, []);

  const handleShowConnection = useCallback((cert: CertificateSummary) => {
    // Navigate to connections page with search filter for this connection
    // Note: Certificate srcIP/srcPort is the server (sender of cert), dstIP/dstPort is the client
    // Connections are stored in client->server format, so we flip the order
    const searchTerm = `${cert.dstIP}:${cert.dstPort}->${cert.srcIP}:${cert.srcPort}`;
    router.push(`/connections?search=${encodeURIComponent(searchTerm)}`);
  }, [router]);

  const handleDownloadPCAP = useCallback(async (cert: CertificateSummary) => {
    try {
      const params = new URLSearchParams({
        srcIP: cert.srcIP,
        srcPort: cert.srcPort.toString(),
        dstIP: cert.dstIP,
        dstPort: cert.dstPort.toString(),
      });
      const downloadUrl = `${getBackendUrl()}/api/certificates/download-pcap?${params}`;
      
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
      a.download = `certificate_${cert.srcIP}-${cert.srcPort}_${cert.dstIP}-${cert.dstPort}.pcap`;
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
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their TLS certificates."
    />
  );

  // Calculate statistics
  const stats = useMemo(() => ({
    expiredCount: certificates.filter(c => c.isExpired).length,
    selfSignedCount: certificates.filter(c => c.isSelfSigned).length,
    weakCount: certificates.filter(c => c.hasWeakSignature || c.hasShortKeySize).length,
    uniqueIssuers: new Set(certificates.map(c => c.issuerCommonName)).size,
  }), [certificates]);

  // Helper function to get status icon
  const getStatusIcon = (cert: CertificateSummary) => {
    if (cert.isExpired) {
      return <ErrorIcon color="error" />;
    }
    if (cert.hasWeakSignature || cert.hasShortKeySize) {
      return <WarningIcon color="warning" />;
    }
    if (cert.isSelfSigned) {
      return <WarningIcon color="warning" />;
    }
    if (cert.daysUntilExpiration < 30) {
      return <WarningIcon color="warning" />;
    }
    return <CheckCircleIcon color="success" />;
  };

  if (error) {
    return (
      <Layout title="Certificates" headerAction={fileSelector}>
        <Alert severity="error">Error loading certificates: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Certificates" headerAction={fileSelector}>
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
            <Card data-learn="Total Certificates: Number of TLS certificates captured in this PCAP file.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SecurityIcon color="primary" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Certificates
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
            <Card data-learn="Expired Certificates: Number of certificates that have expired.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ErrorIcon color="error" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Expired
                    </Typography>
                    <Typography variant="h5">
                      {stats.expiredCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Self-Signed Certificates: Number of self-signed certificates detected.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <WarningIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Self-Signed
                    </Typography>
                    <Typography variant="h5">
                      {stats.selfSignedCount.toLocaleString()}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <Card data-learn="Weak Certificates: Number of certificates with weak signatures or short key sizes.">
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <WarningIcon color="warning" />
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Weak Security
                    </Typography>
                    <Typography variant="h5">
                      {stats.weakCount.toLocaleString()}
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
                  data-learn="Top Issuers Chart: Bar chart showing the most common certificate issuers."
                  key={`top-issuers-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/certificates/top-issuers`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Certificate Issuers"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Certificate Status: Pie chart showing the distribution of certificate statuses (valid, expired, self-signed, weak)."
                  key={`status-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/certificates/status-distribution?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Certificate Status Distribution"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Key Algorithms: Bar chart showing the distribution of public key algorithms used."
                  key={`algorithms-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/certificates/key-algorithms`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Public Key Algorithms"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Expiration Timeline: Timeline showing when certificates will expire."
                  key={`expiration-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/certificates/expiration-timeline`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Certificate Expiration Timeline"
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
            data-learn="Certificate Search: Filter certificates by subject, issuer, organization, IP addresses, fingerprint, or serial number. Multiple search terms can be separated by commas or spaces."
            size="small"
            placeholder="Search certificates (comma or space separated)..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ minWidth: 300 }}
          />
          
          <Button
            data-learn="Refresh Button: Reload certificate data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredCertificates.length} of {totalCount} certificates
            </Typography>
          ) : null}
        </Box>

        {/* Certificates Table */}
        {!certificatesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <SecurityIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Certificates Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No TLS certificate records have been captured yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Certificates Table: Detailed list of all captured TLS certificates with sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell width={40}>Status</TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Subject: Click to sort certificates by subject common name."
                        active={sortField === 'subject'}
                        direction={sortField === 'subject' ? sortOrder : 'asc'}
                        onClick={() => handleSort('subject')}
                      >
                        Subject
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Issuer: Click to sort certificates by issuer."
                        active={sortField === 'issuer'}
                        direction={sortField === 'issuer' ? sortOrder : 'asc'}
                        onClick={() => handleSort('issuer')}
                      >
                        Issuer
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Expiration: Click to sort certificates by days until expiration."
                        active={sortField === 'expiration'}
                        direction={sortField === 'expiration' ? sortOrder : 'asc'}
                        onClick={() => handleSort('expiration')}
                      >
                        Expires In
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Key Size: Click to sort certificates by public key size."
                        active={sortField === 'keySize'}
                        direction={sortField === 'keySize' ? sortOrder : 'asc'}
                        onClick={() => handleSort('keySize')}
                      >
                        Key Size
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Seen Count: Click to sort certificates by how many times they were observed."
                        active={sortField === 'seenCount'}
                        direction={sortField === 'seenCount' ? sortOrder : 'asc'}
                        onClick={() => handleSort('seenCount')}
                      >
                        Seen
                      </TableSortLabel>
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedCertificates.map((cert, idx) => {
                    const rowKey = `${cert.sha256Fingerprint}-${idx}`;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Certificate Row: Click to expand and view detailed information about this certificate. Use ↑↓ arrows to navigate between rows when expanded."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed certificate information.">
                              <ExpandMoreIcon 
                                sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} 
                              />
                            </IconButton>
                          </TableCell>
                          <TableCell>
                            {getStatusIcon(cert)}
                          </TableCell>
                          <TableCell>
                            <Box sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                              {cert.subjectCommonName || '-'}
                            </Box>
                            {cert.subjectOrganization && (
                              <Typography variant="caption" color="text.secondary" display="block">
                                {cert.subjectOrganization}
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              {cert.issuerCommonName || '-'}
                            </Typography>
                            {cert.isSelfSigned && (
                              <Chip label="Self-Signed" size="small" color="warning" sx={{ fontSize: '0.65rem', height: 18, mt: 0.5 }} />
                            )}
                          </TableCell>
                          <TableCell align="right">
                            <Typography 
                              variant="body2"
                              color={
                                cert.isExpired ? 'error' : 
                                cert.daysUntilExpiration < 30 ? 'warning.main' : 
                                'text.primary'
                              }
                            >
                              {cert.isExpired ? 'Expired' : `${cert.daysUntilExpiration} days`}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography 
                              variant="body2"
                              color={cert.hasShortKeySize ? 'error' : 'text.primary'}
                            >
                              {cert.publicKeySize} bits
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {cert.seenCount.toLocaleString()}
                            </Typography>
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="Certificate Details: Extended information about this TLS certificate including validity, algorithms, fingerprints, and connection details.">
                                <Grid container spacing={2}>
                                  {/* Certificate Status Summary */}
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Certificate Status
                                    </Typography>
                                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', alignItems: 'center' }}>
                                      <Typography variant="body2" color="text.secondary" sx={{ mr: 1 }}>
                                        Observed: {cert.seenCount} time{cert.seenCount !== 1 ? 's' : ''}
                                      </Typography>
                                      {cert.isExpired && (
                                        <Chip label="EXPIRED" size="small" color="error" sx={{ fontSize: '0.75rem' }} />
                                      )}
                                      {cert.isNotYetValid && (
                                        <Chip label="Not Yet Valid" size="small" color="error" sx={{ fontSize: '0.75rem' }} />
                                      )}
                                      {cert.isSelfSigned && (
                                        <Chip label="Self-Signed" size="small" color="warning" sx={{ fontSize: '0.75rem' }} />
                                      )}
                                      {!cert.isExpired && !cert.isNotYetValid && cert.daysUntilExpiration < 30 && (
                                        <Chip label={`Expires in ${cert.daysUntilExpiration} days`} size="small" color="warning" sx={{ fontSize: '0.75rem' }} />
                                      )}
                                      {!cert.isExpired && !cert.isNotYetValid && cert.daysUntilExpiration >= 30 && (
                                        <Chip label={`Valid for ${cert.daysUntilExpiration} days`} size="small" color="success" sx={{ fontSize: '0.75rem' }} />
                                      )}
                                    </Box>
                                  </Grid>

                                  {/* Connection Information */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Connection
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                                      IP: {cert.srcIP}:{cert.srcPort} → {cert.dstIP}:{cert.dstPort}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                      MAC: {cert.srcMAC || 'N/A'} → {cert.dstMAC || 'N/A'}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Captured: {formatTimestamp(cert.timestamp)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      First Seen: {formatTimestamp(cert.firstSeen)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Last Seen: {formatTimestamp(cert.lastSeen)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Chain Position: {cert.chainIndex}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Validity Period */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Validity Period
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Not Before: {formatTimestamp(cert.notBefore)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Not After: {formatTimestamp(cert.notAfter)}
                                    </Typography>
                                    <Typography variant="body2" color={cert.isExpired ? 'error.main' : cert.daysUntilExpiration < 30 ? 'warning.main' : 'success.main'}>
                                      {cert.isExpired 
                                        ? `Expired ${Math.abs(cert.daysUntilExpiration)} days ago`
                                        : `Valid for ${cert.daysUntilExpiration} more days`
                                      }
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                                      Certificate Version: X.509 v{cert.version}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Subject Details */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Subject (Certificate Owner)
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 'medium' }}>
                                      Common Name: {cert.subjectCommonName || 'N/A'}
                                    </Typography>
                                    {cert.subjectOrganization && (
                                      <Typography variant="body2" color="text.secondary">
                                        Organization: {cert.subjectOrganization}
                                      </Typography>
                                    )}
                                    {cert.subjectCountry && (
                                      <Typography variant="body2" color="text.secondary">
                                        Country: {cert.subjectCountry}
                                      </Typography>
                                    )}
                                    {cert.subjectProvince && (
                                      <Typography variant="body2" color="text.secondary">
                                        State/Province: {cert.subjectProvince}
                                      </Typography>
                                    )}
                                    {cert.subjectLocality && (
                                      <Typography variant="body2" color="text.secondary">
                                        Locality: {cert.subjectLocality}
                                      </Typography>
                                    )}
                                    {!cert.subjectOrganization && !cert.subjectCountry && !cert.subjectProvince && !cert.subjectLocality && (
                                      <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                                        No additional subject information
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Issuer Details */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Issuer (Certificate Authority)
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 'medium' }}>
                                      Common Name: {cert.issuerCommonName || 'N/A'}
                                    </Typography>
                                    {cert.issuerOrganization && (
                                      <Typography variant="body2" color="text.secondary">
                                        Organization: {cert.issuerOrganization}
                                      </Typography>
                                    )}
                                    {cert.issuerCountry && (
                                      <Typography variant="body2" color="text.secondary">
                                        Country: {cert.issuerCountry}
                                      </Typography>
                                    )}
                                    {cert.isSelfSigned && (
                                      <Box sx={{ mt: 0.5 }}>
                                        <Chip 
                                          label="Self-Signed Certificate" 
                                          size="small" 
                                          color="warning" 
                                          sx={{ fontSize: '0.7rem' }}
                                          icon={<WarningIcon sx={{ fontSize: '0.9rem' }} />}
                                        />
                                      </Box>
                                    )}
                                    {!cert.issuerOrganization && !cert.issuerCountry && !cert.isSelfSigned && (
                                      <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                                        No additional issuer information
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Cryptography & Security */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Cryptography & Security
                                    </Typography>
                                    <Typography 
                                      variant="body2" 
                                      color={cert.hasWeakSignature ? 'error' : 'text.secondary'}
                                      sx={{ fontWeight: cert.hasWeakSignature ? 'medium' : 'normal' }}
                                    >
                                      Signature Algorithm: {cert.signatureAlgorithm || 'Unknown'}
                                      {cert.hasWeakSignature && ' ⚠️'}
                                    </Typography>
                                    <Typography 
                                      variant="body2" 
                                      color="text.secondary"
                                    >
                                      Public Key Algorithm: {cert.publicKeyAlgorithm || 'Unknown'}
                                    </Typography>
                                    <Typography 
                                      variant="body2" 
                                      color={cert.hasShortKeySize ? 'error' : 'text.secondary'}
                                      sx={{ fontWeight: cert.hasShortKeySize ? 'medium' : 'normal' }}
                                    >
                                      Public Key Size: {cert.publicKeySize} bits
                                      {cert.hasShortKeySize && ' ⚠️ (Too Short)'}
                                    </Typography>
                                    <Box sx={{ mt: 1, display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                      {cert.hasWeakSignature && (
                                        <Chip 
                                          label="⚠️ Weak Signature Algorithm" 
                                          size="small" 
                                          color="error" 
                                          sx={{ fontSize: '0.7rem' }}
                                        />
                                      )}
                                      {cert.hasShortKeySize && (
                                        <Chip 
                                          label="⚠️ Insufficient Key Size" 
                                          size="small" 
                                          color="error" 
                                          sx={{ fontSize: '0.7rem' }}
                                        />
                                      )}
                                      {!cert.hasWeakSignature && !cert.hasShortKeySize && (
                                        <Chip 
                                          label="✓ Strong Cryptography" 
                                          size="small" 
                                          color="success" 
                                          sx={{ fontSize: '0.7rem' }}
                                        />
                                      )}
                                    </Box>
                                  </Grid>
                                  
                                  {/* Fingerprints & Serial */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Certificate Identifiers
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                      SHA-256 Fingerprint:
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all', mb: 1 }}>
                                      {cert.sha256Fingerprint || 'N/A'}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                      SHA-1 Fingerprint:
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all', mb: 1 }}>
                                      {cert.sha1Fingerprint || 'N/A'}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                      Serial Number:
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all' }}>
                                      {cert.serialNumber || 'N/A'}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Subject Alternative Names */}
                                  <Grid item xs={12}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Subject Alternative Names (SAN)
                                    </Typography>
                                    {(cert.subjectAltNames || []).length > 0 ? (
                                      <>
                                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                          Additional domain names and identities this certificate is valid for ({(cert.subjectAltNames || []).length} total):
                                        </Typography>
                                        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                          {(cert.subjectAltNames || []).map((san, i) => (
                                            <Chip
                                              key={`${rowKey}-san-${i}`}
                                              label={san}
                                              size="small"
                                              variant="outlined"
                                              color="default"
                                              sx={{ 
                                                fontSize: '0.7rem',
                                                fontFamily: 'monospace'
                                              }}
                                            />
                                          ))}
                                        </Box>
                                      </>
                                    ) : (
                                      <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                                        No Subject Alternative Names present (certificate only valid for CN: {cert.subjectCommonName || 'N/A'})
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Certificate Authority Info */}
                                  {cert.isCA && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Certificate Authority
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', alignItems: 'center' }}>
                                        <Chip 
                                          label="✓ This is a Certificate Authority" 
                                          size="small" 
                                          color="info" 
                                          sx={{ fontSize: '0.75rem', fontWeight: 'medium' }}
                                        />
                                        <Chip 
                                          label={cert.maxPathLen === -1 ? 'Unlimited Path Length' : `Max Path Length: ${cert.maxPathLen}`}
                                          size="small" 
                                          variant="outlined"
                                          color="info"
                                          sx={{ fontSize: '0.7rem' }}
                                        />
                                      </Box>
                                      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                                        This certificate can sign other certificates {cert.maxPathLen === -1 ? 'with no depth restrictions' : `up to ${cert.maxPathLen} level(s) deep`}
                                      </Typography>
                                    </Grid>
                                  )}

                                  {/* Key Usage */}
                                  {((cert.keyUsage || []).length > 0 || (cert.extKeyUsage || []).length > 0) && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        Key Usage & Extensions
                                      </Typography>
                                      {(cert.keyUsage || []).length > 0 && (
                                        <>
                                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                            Key Usage (what the key can be used for):
                                          </Typography>
                                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
                                            {(cert.keyUsage || []).map((usage, i) => (
                                              <Chip
                                                key={`${rowKey}-ku-${i}`}
                                                label={usage}
                                                size="small"
                                                color="primary"
                                                variant="outlined"
                                                sx={{ fontSize: '0.7rem' }}
                                              />
                                            ))}
                                          </Box>
                                        </>
                                      )}
                                      {(cert.extKeyUsage || []).length > 0 && (
                                        <>
                                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                            Extended Key Usage (specific purposes):
                                          </Typography>
                                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                            {(cert.extKeyUsage || []).map((usage, i) => (
                                              <Chip
                                                key={`${rowKey}-eku-${i}`}
                                                label={usage}
                                                size="small"
                                                color="secondary"
                                                variant="outlined"
                                                sx={{ fontSize: '0.7rem' }}
                                              />
                                            ))}
                                          </Box>
                                        </>
                                      )}
                                    </Grid>
                                  )}

                                  {/* JA4X Certificate Fingerprinting */}
                                  {cert.ja4x && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="JA4X: Certificate fingerprint based on issuer/subject RDN ordering, extensions, and signature algorithm.">
                                        JA4X Certificate Fingerprint
                                      </Typography>
                                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                        <Chip 
                                          label={cert.ja4x} 
                                          size="small" 
                                          color="secondary"
                                          sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                                        />
                                      </Box>
                                      {cert.ja4xDescription && (
                                        <Typography variant="body2" color="text.secondary">
                                          {cert.ja4xDescription}
                                        </Typography>
                                      )}
                                      {cert.ja4xRaw && (
                                        <Box sx={{ mt: 1 }}>
                                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                            Raw (unhashed):
                                          </Typography>
                                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.65rem', wordBreak: 'break-all' }}>
                                            {cert.ja4xRaw}
                                          </Typography>
                                        </Box>
                                      )}
                                    </Grid>
                                  )}
                                  
                                  {/* Action Buttons */}
                                  <Grid item xs={12}>
                                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                      <Button
                                        data-learn="Show Connection: Navigate to the Connections page to view the connection that used this certificate."
                                        variant="outlined"
                                        startIcon={<CableIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleShowConnection(cert);
                                        }}
                                        size="small"
                                      >
                                        Show Connection
                                      </Button>
                                      <Button
                                        data-learn="Download PCAP: Download a filtered PCAP file containing only the packets from this connection."
                                        variant="outlined"
                                        startIcon={<DownloadIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleDownloadPCAP(cert);
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
              data-learn="Table Pagination: Navigate through pages of certificates and change how many rows to display per page."
              component="div"
              count={filteredCertificates.length}
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

