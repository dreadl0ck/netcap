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

import React, { useState, useMemo, useCallback, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Typography,
  Alert,
  Collapse,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
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
import { CertificateAssessmentNotice, certificateValidityLabel } from '../components/RecordSemantics';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import SearchInput from '../components/SearchInput';
import CommunityIDChip from '../components/CommunityIDChip';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatTimestamp, getBackendUrl } from '../lib/api';

import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { scopeCaptureURL } from '../lib/captureSelection';
import { message as finalCopyMessage } from "../lib/i18n";




export interface CertificateSummary {
  assessmentBasis?: string; assessmentTimeNs?: string; validityState?: string;
  selfSignatureState?: string; certificateSender?: string;
  notBeforeRFC3339?: string; notAfterRFC3339?: string;
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
  // Community ID for cross-tool correlation
  communityId: string;
  communityIds: string[];
}

interface CertificatesResponse {
  certificates: CertificateSummary[];
  totalCount: number;
}

type CertificateSortField = 'subject' | 'issuer' | 'expiration' | 'seenCount' | 'keySize';
type SortOrder = 'asc' | 'desc';
type CertificateFilterType = 'all' | 'expired' | 'selfSigned' | 'weakSecurity';

export interface CertificatesPageProps {
  /** Custom row actions to render in the expanded row details */
  rowActions?: (row: CertificateSummary) => React.ReactNode;
}

export default function CertificatesPage({ rowActions }: CertificatesPageProps = {}) {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<CertificateFilterType>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<CertificateSortField>('seenCount');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

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
    () => api.getCaptureInventory('certificates'),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
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

    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(cert =>
        (cert.communityIds || []).some(id => selectedCommunityIDs.has(id))
      );
    }

    // Apply certificate status filter
    if (filterType !== 'all') {
      filtered = filtered.filter(cert => {
        switch (filterType) {
          case 'expired':
            return cert.assessmentBasis === 'capture-time' && cert.validityState === 'expired';
          case 'selfSigned':
            return cert.selfSignatureState === 'verified';
          case 'weakSecurity':
            return cert.hasWeakSignature || cert.hasShortKeySize;
          default:
            return true;
        }
      });
    }

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

    // Apply sorting with stable secondary sort by sha256Fingerprint
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
      // Stable secondary sort by sha256Fingerprint for consistent ordering
      if (comparison === 0) {
        comparison = a.sha256Fingerprint.localeCompare(b.sha256Fingerprint);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [certificates, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs, filterType]);

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
      alert(i18nText("ui:m_7ab800e4d59917b1d34c"));
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate, __uiLocale]);

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
      
      const response = await fetch(scopeCaptureURL(downloadUrl));
      
      if (!response.ok) {
        const errorText = await response.text();
        alert(i18nText("ui:m_c63b36b2fde6b1f5d69c", { arg0: errorText }));
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
      alert(i18nText("ui:m_c63b36b2fde6b1f5d69c", { arg0: error }));
    }
  }, [__uiLocale]);

  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_5e7ecc72534d4936e134")} />
  );

  // Calculate statistics
  const stats = useMemo(() => ({
    expiredCount: certificates.filter(c => c.assessmentBasis === 'capture-time' && c.validityState === 'expired').length,
    selfSignedCount: certificates.filter(c => c.selfSignatureState === 'verified').length,
    weakCount: certificates.filter(c => c.hasWeakSignature || c.hasShortKeySize).length,
    uniqueIssuers: new Set(certificates.map(c => c.issuerCommonName)).size,
  }), [certificates]);

  // Helper function to get status icon
  const getStatusIcon = (cert: CertificateSummary) => {
    if (cert.assessmentBasis !== 'capture-time' || cert.validityState === 'unavailable' || !cert.validityState) return <WarningIcon color="warning" />;
    if (cert.validityState === 'expired') {
      return <ErrorIcon color="error" />;
    }
    if (cert.hasWeakSignature || cert.hasShortKeySize) {
      return <WarningIcon color="warning" />;
    }
    if (cert.selfSignatureState === 'verified') {
      return <WarningIcon color="warning" />;
    }
    if (cert.daysUntilExpiration < 30) {
      return <WarningIcon color="warning" />;
    }
    return <CheckCircleIcon color="success" />;
  };

  if (error) {
    return (
      <Layout title={i18nText("ui:m_d600f8703e15ddbf7363")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_9ee913c1e3b2079aed4b", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_d600f8703e15ddbf7363")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
            exclusive
            onChange={(_e, newValue) => {
              if (newValue !== null) {
                setViewMode(newValue);
              }
            }}
            size="small"
            data-learn={i18nText("ui:m_4f46daf2537ea500313b")}><ToggleButton value="table"><TableChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              {i18nRichText("ui:m_b65e2110701259d5e7dc", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
            </ToggleButton><ToggleButton value="chart"><BarChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              {i18nRichText("ui:m_da105eec6af81877e667", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
            </ToggleButton></ToggleButtonGroup></Box>{/* Summary Cards - Only show in table mode */}{viewMode === 'table' && (
        <StatBoxGrid><StatBox icon={<SecurityIcon color="primary" />}
            label={i18nText("ui:m_ba979be5018d353c7042")}
            value={totalCount}
            onClick={() => { setFilterType('all'); setPage(0); }}
            isActive={filterType === 'all'}
            activeColor="primary"
            learnHint={translate("ui:m_34f618eff79a430d0e7f")} /><StatBox icon={<ErrorIcon color="error" />}
            label={i18nText("ui:m_d17c1c03e8e4aa170197")}
            value={stats.expiredCount}
            onClick={() => { setFilterType('expired'); setPage(0); }}
            isActive={filterType === 'expired'}
            activeColor="error"
            learnHint={translate("ui:m_a95f351df6622e59371d")} /><StatBox icon={<WarningIcon color="warning" />}
            label={i18nText("ui:m_08c9cbb8269401eac8a3")}
            value={stats.selfSignedCount}
            onClick={() => { setFilterType('selfSigned'); setPage(0); }}
            isActive={filterType === 'selfSigned'}
            activeColor="warning"
            learnHint={translate("ui:m_220c5c30c057d806d841")} /><StatBox icon={<WarningIcon color="warning" />}
            label={i18nText("ui:m_5faa63383d9260d63698")}
            value={stats.weakCount}
            onClick={() => { setFilterType('weakSecurity'); setPage(0); }}
            isActive={filterType === 'weakSecurity'}
            activeColor="warning"
            learnHint={translate("ui:m_a14a0090718b21c8af30")} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_8de7c334e144bc1075d9")}
                  key={`top-issuers-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/certificates/top-issuers`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_4fe93828507e88828fea")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_efbdd80b35c46968ce6c")}
                  key={`status-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/certificates/status-distribution?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_6140b0292b9cfea11af4")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_43d9f6ec4649c6a65423")}
                  key={`algorithms-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/certificates/key-algorithms`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_7b0d881228116ff40d13")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_9380df1c1f1a546db705")}
                  key={`expiration-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/certificates/expiration-timeline`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_d2c7b04d90dad92b8acf")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_fe58c45b25124e034e9f")}
            learnHint={translate("ui:m_0c4e45dd1fd7e3244704")} /><Button data-learn={i18nText("ui:m_cff86de2b9512e54b83b")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{(searchQuery || filterType !== 'all') ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_4c1b99a1b00c2b34b41b", { arg0: filteredCertificates.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Certificates Table */}{!certificatesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><SecurityIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_ead64113672af8975ff5")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_e8af4f3742960582fa21")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedCertificates}
            totalCount={filteredCertificates.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            renderCard={(cert) => (
              <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Box display="flex" alignItems="center" gap={1} mb={0.5}>{getStatusIcon(cert)}<Typography variant="body2" fontWeight="medium" noWrap sx={{ fontFamily: 'monospace', flex: 1 }}>{cert.subjectCommonName || '-'}</Typography></Box><Typography variant="caption" color="text.secondary" display="block">
                    {i18nRichText("ui:m_8fc0de9e5d574a97264a", { arg0: cert.issuerCommonName || '-', arg1: cert.selfSignatureState === 'verified' && i18nText("ui:m_54cfe89196ecc8f6395b") })}
                  </Typography><Box display="flex" justifyContent="space-between" alignItems="center" mt={0.5}><Typography variant="caption"
                      color={cert.isExpired ? 'error' :
                        cert.daysUntilExpiration < 30 ? 'warning.main' :
                        'text.secondary'}>{certificateValidityLabel(cert)}</Typography><Box display="flex" gap={0.5} alignItems="center"><Chip label={i18nText("ui:m_f53154b71d828b0099a0", { arg0: cert.publicKeySize })}
                        size="small"
                        color={cert.hasShortKeySize ? 'error' : 'default'}
                        sx={{ fontSize: '0.65rem', height: 18 }} /><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_9cfda7900642216a5659", { arg0: cert.seenCount.toLocaleString(getUILocale()) })}
                      </Typography></Box></Box><Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                    {i18nRichText("ui:m_6db829352b0c8a42e5b2", { arg0: formatTimestamp(cert.notBefore, 'nanoseconds'), arg1: formatTimestamp(cert.notAfter, 'nanoseconds') })}
                  </Typography></CardContent></Card>
            )}
            desktopTable={<TableContainer component={Paper}><Table size="small" data-learn={i18nText("ui:m_7b36a950062e7b3f041c")}><TableHead><TableRow><TableCell width={40}></TableCell><TableCell width={40}>{i18nText("ui:m_cf025c2b66b1d8e97700")}</TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_d6ebd6950be4934b6249")}
                        active={sortField === 'subject'}
                        direction={sortField === 'subject' ? sortOrder : 'asc'}
                        onClick={() => handleSort('subject')}>
                        {i18nText("ui:m_1561e8461e059158615d")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_6ce8e447d7f2ce6c2ffa")}
                        active={sortField === 'issuer'}
                        direction={sortField === 'issuer' ? sortOrder : 'asc'}
                        onClick={() => handleSort('issuer')}>
                        {i18nText("ui:m_e7e7c4777f1b0ad2f847")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_0adc1a479d4ae5ae5e58")}
                        active={sortField === 'expiration'}
                        direction={sortField === 'expiration' ? sortOrder : 'asc'}
                        onClick={() => handleSort('expiration')}>
                        {i18nText("ui:m_c3e27e95c567f5b07fd6")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_d87517ff315a069f2a0a")}
                        active={sortField === 'keySize'}
                        direction={sortField === 'keySize' ? sortOrder : 'asc'}
                        onClick={() => handleSort('keySize')}>
                        {i18nText("ui:m_706c6828e2d71df3fca8")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_c37c255f48a02609f581")}
                        active={sortField === 'seenCount'}
                        direction={sortField === 'seenCount' ? sortOrder : 'asc'}
                        onClick={() => handleSort('seenCount')}>
                        {i18nText("ui:m_7172f6e66222f3ec6754")}
                      </TableSortLabel></TableCell></TableRow></TableHead><TableBody>{paginatedCertificates.map((cert, idx) => {
                    const rowKey = `${cert.sha256Fingerprint}-${idx}`;
                    return (
                      <><TableRow key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn={i18nText("ui:m_aa3be3383741f7e699db")}><TableCell><IconButton size="small" data-learn={i18nText("ui:m_2160d4664ac65f3b215e")}><ExpandMoreIcon sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} /></IconButton></TableCell><TableCell>{getStatusIcon(cert)}</TableCell><TableCell><Box sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>{cert.subjectCommonName || '-'}</Box>{cert.subjectOrganization && (
                              <Typography variant="caption" color="text.secondary" display="block">{cert.subjectOrganization}</Typography>
                            )}</TableCell><TableCell><Typography variant="body2">{cert.issuerCommonName || '-'}</Typography>{cert.selfSignatureState === 'verified' && (
                              <Chip label={i18nText("ui:m_08c9cbb8269401eac8a3")} size="small" color="warning" sx={{ fontSize: '0.65rem', height: 18, mt: 0.5 }} />
                            )}</TableCell><TableCell align="right"><Typography variant="body2"
                              color={cert.isExpired ? 'error' : 
                                cert.daysUntilExpiration < 30 ? 'warning.main' : 
                                'text.primary'}>{certificateValidityLabel(cert)}</Typography></TableCell><TableCell align="right"><Typography variant="body2"
                              color={cert.hasShortKeySize ? 'error' : 'text.primary'}>
                              {i18nRichText("ui:m_e6a86451dc6bdfeabe39", { arg0: cert.publicKeySize })}
                            </Typography></TableCell><TableCell align="right"><Typography variant="body2">{cert.seenCount.toLocaleString(getUILocale())}</Typography></TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={7}><Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit><Box sx={{ py: 2 }} data-learn={i18nText("ui:m_2aa752e6650c756f71fd")}><CertificateAssessmentNotice cert={cert} /><Grid container spacing={2}>{/* Certificate Status Summary */}<Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_e2c1dcaa4192628576e1")}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', alignItems: 'center' }}><Typography variant="body2" color="text.secondary" sx={{ mr: 1 }}>
                                        {i18nRichText("ui:m_551551028a9e33195b74", { arg0: cert.seenCount })}
                                      </Typography>{cert.assessmentBasis === 'capture-time' && cert.validityState === 'expired' && (
                                        <Chip label={i18nText("ui:m_749b044d0c450a227ebc")} size="small" color="error" sx={{ fontSize: '0.75rem' }} />
                                      )}{cert.assessmentBasis === 'capture-time' && cert.validityState === 'not-yet-valid' && (
                                        <Chip label={i18nText("ui:m_248bb7e390aff5e4cad0")} size="small" color="error" sx={{ fontSize: '0.75rem' }} />
                                      )}{cert.selfSignatureState === 'verified' && (
                                        <Chip label={i18nText("ui:m_08c9cbb8269401eac8a3")} size="small" color="warning" sx={{ fontSize: '0.75rem' }} />
                                      )}{cert.assessmentBasis === 'capture-time' && cert.validityState === 'valid' && cert.daysUntilExpiration < 30 && (
                                        <Chip label={i18nText("ui:m_cfbbd8b38a18afd68495", { arg0: cert.daysUntilExpiration })} size="small" color="warning" sx={{ fontSize: '0.75rem' }} />
                                      )}{cert.assessmentBasis === 'capture-time' && cert.validityState === 'valid' && cert.daysUntilExpiration >= 30 && (
                                        <Chip label={i18nText("ui:m_65928c1182ba09fcfdf6", { arg0: cert.daysUntilExpiration })} size="small" color="success" sx={{ fontSize: '0.75rem' }} />
                                      )}</Box></Grid>{/* Connection Information */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_6e3eaaf519e2d29c1f65")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                                      {i18nRichText("ui:m_1a90a00c310ba72dcdae", { arg0: cert.srcIP, arg1: String(cert.srcPort), arg2: cert.dstIP, arg3: String(cert.dstPort) })}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                      {i18nRichText("ui:m_cb41860a6bf9e194fdb2", { arg0: cert.srcMAC || i18nText("ui:m_8dc598ebf1e055830140"), arg1: cert.dstMAC || i18nText("ui:m_8dc598ebf1e055830140") })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_b51187a1af8edb545759", { arg0: formatTimestamp(cert.timestamp, 'nanoseconds') })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_c2f3901b4530d9bcca6c", { arg0: formatTimestamp(cert.firstSeen, 'nanoseconds') })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_6ac7e146e6fe1424812b", { arg0: formatTimestamp(cert.lastSeen, 'nanoseconds') })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_e0da41b8b82119f97fd9", { arg0: cert.chainIndex })}
                                    </Typography></Grid>{/* Validity Period */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_81ef6bd2740e47b8dbe5")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_9d0164a9cfd3af7587cd", { arg0: cert.notBeforeRFC3339 || (cert.notBefore ? formatTimestamp(cert.notBefore, 'nanoseconds') : i18nText('ui:m_b6f62be183440dfdc4c4')) })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_fe8efc42daa89725ef3d", { arg0: cert.notAfterRFC3339 || (cert.notAfter ? formatTimestamp(cert.notAfter, 'nanoseconds') : i18nText('ui:m_b6f62be183440dfdc4c4')) })}
                                    </Typography><Typography variant="body2" color={cert.assessmentBasis !== 'capture-time' || cert.validityState === 'unavailable' ? 'text.secondary' : cert.isExpired ? 'error.main' : cert.daysUntilExpiration < 30 ? 'warning.main' : 'success.main'}>{certificateValidityLabel(cert)}</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                                      {i18nRichText("ui:m_41beba29048404202377", { arg0: String(cert.version) })}
                                    </Typography></Grid>{/* Subject Details */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_d59bbdd1968c166f1373")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontWeight: 'medium' }}>
                                      {i18nRichText("ui:m_8aca4632ecfb5562cc7f", { arg0: cert.subjectCommonName || i18nText("ui:m_8dc598ebf1e055830140") })}
                                    </Typography>{cert.subjectOrganization && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_454aa4c4a40559ca4e42", { arg0: cert.subjectOrganization })}
                                      </Typography>
                                    )}{cert.subjectCountry && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_8a39b41595d646f6fa22", { arg0: cert.subjectCountry })}
                                      </Typography>
                                    )}{cert.subjectProvince && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_58662e021b30b8650789", { arg0: cert.subjectProvince })}
                                      </Typography>
                                    )}{cert.subjectLocality && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_e17df9fecfe5f80fa57c", { arg0: cert.subjectLocality })}
                                      </Typography>
                                    )}{!cert.subjectOrganization && !cert.subjectCountry && !cert.subjectProvince && !cert.subjectLocality && (
                                      <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                                        {i18nText("ui:m_048d992f32f0e4bc90e5")}
                                      </Typography>
                                    )}</Grid>{/* Issuer Details */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_a9553de40d044a4e12db")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontWeight: 'medium' }}>
                                      {i18nRichText("ui:m_8aca4632ecfb5562cc7f", { arg0: cert.issuerCommonName || i18nText("ui:m_8dc598ebf1e055830140") })}
                                    </Typography>{cert.issuerOrganization && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_454aa4c4a40559ca4e42", { arg0: cert.issuerOrganization })}
                                      </Typography>
                                    )}{cert.issuerCountry && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_8a39b41595d646f6fa22", { arg0: cert.issuerCountry })}
                                      </Typography>
                                    )}{cert.selfSignatureState === 'verified' && (
                                      <Box sx={{ mt: 0.5 }}><Chip label={i18nText("ui:m_063e8d16231cd10cfc6a")} 
                                          size="small" 
                                          color="warning" 
                                          sx={{ fontSize: '0.7rem' }}
                                          icon={<WarningIcon sx={{ fontSize: '0.9rem' }} />} /></Box>
                                    )}{!cert.issuerOrganization && !cert.issuerCountry && cert.selfSignatureState !== 'verified' && (
                                      <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                                        {i18nText("ui:m_38772ce1f1ac7efb8482")}
                                      </Typography>
                                    )}</Grid>{/* Cryptography & Security */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_617cadfc1555c144958d")}
                                    </Typography><Typography variant="body2" 
                                      color={cert.hasWeakSignature ? 'error' : 'text.secondary'}
                                      sx={{ fontWeight: cert.hasWeakSignature ? 'medium' : 'normal' }}>
                                      {i18nRichText("ui:m_f419a16077669d26d935", { arg0: cert.signatureAlgorithm || i18nText("ui:m_2f1ac5f44673922d2bf2"), arg1: cert.hasWeakSignature && ' ⚠️' })}
                                    </Typography><Typography variant="body2" 
                                      color="text.secondary">
                                      {i18nRichText("ui:m_e93dcf9f788b928ae803", { arg0: cert.publicKeyAlgorithm || i18nText("ui:m_2f1ac5f44673922d2bf2") })}
                                    </Typography><Typography variant="body2" 
                                      color={cert.hasShortKeySize ? 'error' : 'text.secondary'}
                                      sx={{ fontWeight: cert.hasShortKeySize ? 'medium' : 'normal' }}>
                                      {i18nRichText("ui:m_6e505de182f86e659706", { arg0: cert.publicKeySize, arg1: cert.hasShortKeySize && i18nText("ui:m_2ee87560a549d8c37c2c") })}
                                    </Typography><Box sx={{ mt: 1, display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{cert.hasWeakSignature && (
                                        <Chip label={i18nText("ui:m_ac71dde884c1b3551d0d")} 
                                          size="small" 
                                          color="error" 
                                          sx={{ fontSize: '0.7rem' }} />
                                      )}{cert.hasShortKeySize && (
                                        <Chip label={i18nText("ui:m_e67ae9741f7d9174c608")} 
                                          size="small" 
                                          color="error" 
                                          sx={{ fontSize: '0.7rem' }} />
                                      )}{!cert.hasWeakSignature && !cert.hasShortKeySize && (
                                        <Chip label={i18nText("ui:m_7de56ecaea2cce659d00")} 
                                          size="small" 
                                          color="success" 
                                          sx={{ fontSize: '0.7rem' }} />
                                      )}</Box></Grid>{/* Fingerprints & Serial */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_45fd98e2c1d40861d1f5")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                      {i18nText("ui:m_072bd517bca94c681689")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all', mb: 1 }}>{cert.sha256Fingerprint || i18nText("ui:m_8dc598ebf1e055830140")}</Typography><Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                      {i18nText("ui:m_c28dd6e9594133c7b116")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all', mb: 1 }}>{cert.sha1Fingerprint || i18nText("ui:m_8dc598ebf1e055830140")}</Typography><Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                                      {i18nText("ui:m_bb478a415237c8bea711")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all' }}>{cert.serialNumber || i18nText("ui:m_8dc598ebf1e055830140")}</Typography>{(cert.communityIds || []).length > 0 && (
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{cert.communityIds.map(id => <CommunityIDChip key={id} communityId={id} mode="chip" />)}</Box>
                                    )}</Grid>{/* Subject Alternative Names */}<Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_f72f2eb7ef31104ecf40")}
                                    </Typography>{(cert.subjectAltNames || []).length > 0 ? (
                                      <><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                          {i18nRichText("ui:m_2878f6badc52ddb64e89", { arg0: (cert.subjectAltNames || []).length })}
                                        </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(cert.subjectAltNames || []).map((san, i) => (
                                            <Chip key={`${rowKey}-san-${i}`}
                                              label={san}
                                              size="small"
                                              variant="outlined"
                                              color="default"
                                              sx={{ 
                                                fontSize: '0.7rem',
                                                fontFamily: 'monospace'
                                              }} />
                                          ))}</Box></>
                                    ) : (
                                      <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                                        {i18nRichText("ui:m_b2386a2ccc976a4da5a0", { arg0: cert.subjectCommonName || i18nText("ui:m_8dc598ebf1e055830140") })}
                                      </Typography>
                                    )}</Grid>{/* Certificate Authority Info */}{cert.isCA && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nText("ui:m_c454ee75b4bfcffecc93")}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', alignItems: 'center' }}><Chip label={i18nText("ui:m_88dc4dc485045d75196c")} 
                                          size="small" 
                                          color="info" 
                                          sx={{ fontSize: '0.75rem', fontWeight: 'medium' }} /><Chip label={cert.maxPathLen === -1 ? i18nText("ui:m_139e67e8bd335ec1f34d") : i18nText("ui:m_ec6e4f5eb18d11e321a6", { arg0: cert.maxPathLen })}
                                          size="small" 
                                          variant="outlined"
                                          color="info"
                                          sx={{ fontSize: '0.7rem' }} /></Box><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                                        {i18nRichText("ui:m_bdf83045e9d0119e3551", { arg0: cert.maxPathLen === -1 ? i18nText("ui:m_7dd701202402e27b5af1") : i18nText("ui:m_694384e016ed5590df0e", { arg0: cert.maxPathLen }) })}
                                      </Typography></Grid>
                                  )}{/* Key Usage */}{((cert.keyUsage || []).length > 0 || (cert.extKeyUsage || []).length > 0) && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nText("ui:m_3b0a4acf644ce490eff7")}
                                      </Typography>{(cert.keyUsage || []).length > 0 && (
                                        <><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                            {i18nText("ui:m_a6eda42183ba83e41693")}
                                          </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>{(cert.keyUsage || []).map((usage, i) => (
                                              <Chip key={`${rowKey}-ku-${i}`}
                                                label={usage}
                                                size="small"
                                                color="primary"
                                                variant="outlined"
                                                sx={{ fontSize: '0.7rem' }} />
                                            ))}</Box></>
                                      )}{(cert.extKeyUsage || []).length > 0 && (
                                        <><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                            {i18nText("ui:m_8d972eb7a1e211f747c1")}
                                          </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(cert.extKeyUsage || []).map((usage, i) => (
                                              <Chip key={`${rowKey}-eku-${i}`}
                                                label={usage}
                                                size="small"
                                                color="secondary"
                                                variant="outlined"
                                                sx={{ fontSize: '0.7rem' }} />
                                            ))}</Box></>
                                      )}</Grid>
                                  )}{/* JA4X Certificate Fingerprinting */}{cert.ja4x && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_31ef80c4ec3bcda10b75")}>
                                        {i18nText("ui:m_11e3fb86a188a27254f0")}
                                      </Typography><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}><Chip label={cert.ja4x} 
                                          size="small" 
                                          color="secondary"
                                          sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }} /></Box>{cert.ja4xDescription && (
                                        <Typography variant="body2" color="text.secondary">{cert.ja4xDescription}</Typography>
                                      )}{cert.ja4xRaw && (
                                        <Box sx={{ mt: 1 }}><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                            {i18nText("ui:m_512ee594b932fdb9ea46")}
                                          </Typography><Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.65rem', wordBreak: 'break-all' }}>{cert.ja4xRaw}</Typography></Box>
                                      )}</Grid>
                                  )}{/* Action Buttons */}<Grid item xs={12}><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}><Button data-learn={i18nText("ui:m_a8c4c5e3e20dff31d8d2")}
                                        variant="outlined"
                                        startIcon={<CableIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleShowConnection(cert);
                                        }}
                                        size="small">
                                        {i18nText("ui:m_6e4460fb915c45550838")}
                                      </Button><Button data-learn={i18nText("ui:m_307516b08401bcb7ac91")}
                                        variant="outlined"
                                        startIcon={<DownloadIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleDownloadPCAP(cert);
                                        }}
                                        size="small">
                                        {i18nText("ui:m_866ab5d39a9b8045fa5c")}
                                      </Button>{/* Custom row actions from parent */}{rowActions && rowActions(cert)}</Box></Grid></Grid></Box></Collapse></TableCell></TableRow></>
                    );
                  })}</TableBody></Table></TableContainer>} />
        )}</>
        )}</Box></Layout>
  );
}
