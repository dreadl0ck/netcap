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

import React, { useState, useMemo, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  FormControl,
  IconButton,
  MenuItem,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Tooltip,
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
  Language as LanguageIcon,
  TrendingUp as TrendingUpIcon,
  Public as PublicIcon,
  AccountTree as AccountTreeIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';
import { formatDurationNs, medianRTT, rttSortKey, transactionFlags, type DNSTransactionSummary } from '../lib/dnsTransactions';
import { useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';

import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";




export interface DomainSummary {
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
  source: string; // "DNS", "TLS SNI", or "DNS, TLS SNI"
  communityIds: string[]; // Community IDs for cross-tool correlation
  dnsTransactions?: DNSTransactionSummary; // absent for SNI-only domains and older captures
}

interface DomainsResponse {
  domains: DomainSummary[];
  totalCount: number;
}

type DomainSortField = 'domain' | 'queries' | 'clients' | 'type' | 'rtt';
type SortOrder = 'asc' | 'desc';

export interface DomainsPageProps {
  /** Custom row actions to render in the expanded row details */
  rowActions?: (row: DomainSummary) => React.ReactNode;
}

export default function DomainsPage({ rowActions }: DomainsPageProps = {}) {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'root' | 'subdomain'>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<DomainSortField>('queries');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch domains data
  const { data: domainsData, error, mutate } = useSWR<DomainsResponse>(
    'domains',
    () => api.getCaptureInventory('domains'),
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

    // Apply Community ID filter first (if active)
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(d => 
        d.communityIds && d.communityIds.some(cid => selectedCommunityIDs.has(cid))
      );
    }

    // Apply type filter
    if (filterType === 'root') {
      filtered = filtered.filter(d => !d.isSubdomain);
    } else if (filterType === 'subdomain') {
      filtered = filtered.filter(d => d.isSubdomain);
    }

    // Apply search filter with negation support (e.g., "!google" excludes Google domains)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(d =>
        matchesSearchTerms([
          d.domain,
          d.parentDomain || '',
          d.source || '',
          ...(d.recordTypes || []),
          ...(d.resolvedIPs || []),
        ], searchTerms)
      );
    }

    // Apply sorting with stable secondary sort by domain name
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
        case 'rtt': {
          const ka = rttSortKey(a.dnsTransactions);
          const kb = rttSortKey(b.dnsTransactions);
          comparison = ka === kb ? 0 : ka < kb ? -1 : 1;
          break;
        }
        case 'type':
          // Sort root domains first
          if (a.isSubdomain === b.isSubdomain) {
            comparison = a.domain.localeCompare(b.domain);
          } else {
            comparison = a.isSubdomain ? 1 : -1;
          }
          break;
      }
      // Stable secondary sort by domain name for consistent ordering
      if (comparison === 0) {
        comparison = a.domain.localeCompare(b.domain);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [domains, filterType, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs]);

  // Paginate domains
  const paginatedDomains = filteredDomains.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedDomains.map(domain => domain.domain),
    [paginatedDomains]
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
      alert(i18nText("ui:m_7ab800e4d59917b1d34c"));
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate, __uiLocale]);

  const handleRowClick = useCallback((domain: string) => {
    setExpandedRow(prev => prev === domain ? null : domain);
  }, []);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_c4bf545e35cc709e80a1")} />
  );

  // Memoize summary statistics to avoid recalculation on every render
  const stats = useMemo(() => ({
    totalQueries: domains.reduce((sum, d) => sum + d.queryCount, 0),
    uniqueTLDs: new Set(domains.map(d => {
      const parts = d.domain.split('.');
      return parts[parts.length - 1];
    })).size,
    subdomainCount: domains.filter(d => d.isSubdomain).length
  }), [domains]);

  if (error) {
    return (
      <Layout title={i18nText("ui:m_ef349205fde9161a7005")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_53e45576a74ba00502f7", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_ef349205fde9161a7005")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
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
        <StatBoxGrid><StatBox icon={<LanguageIcon color="primary" />}
            label={i18nText("ui:m_d41f93d7fcb0f862cda6")}
            value={totalCount}
            learnHint={translate("ui:m_11d2e7c8aad6ce777da7")} /><StatBox icon={<TrendingUpIcon color="success" />}
            label={i18nText("ui:m_eaadcad72b5472d29899")}
            value={stats.totalQueries}
            learnHint={translate("ui:m_b8c3d6ff5f5749b5d294")} /><StatBox icon={<PublicIcon color="warning" />}
            label={i18nText("ui:m_3c3af64fb349b2bf6654")}
            value={stats.uniqueTLDs}
            learnHint={translate("ui:m_c5f3dd97f8b9b957d579")} /><StatBox icon={<AccountTreeIcon color="info" />}
            label={i18nText("ui:m_b5fece3843f7bb605507")}
            value={stats.subdomainCount}
            learnHint={translate("ui:m_eba56a3eda953e64fa98")} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_471adde7e9990b42e59f")}
                  key={`top-by-queries-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/top-by-queries`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_b0fe261e29494e6da766")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_08bd00a8cca335c63ddc")}
                  key={`tlds-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/tlds?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_ce2d77549f53b37ee0fd")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_a690f5e2089de64e1e99")}
                  key={`record-types-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/record-types`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_aac38c0190d1b3fef630")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_0b48dcb6ac4434c2f813")}
                  key={`subdomain-distribution-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/domains/subdomain-distribution`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_872220d90978230aa649")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_e0ec4c40b29778179013")}
            learnHint={translate("ui:m_86de4885b4cc7b53ee32")} /><FormControl size="small" sx={{ minWidth: 150 }}><Select data-learn={i18nText("ui:m_fc011a0eb5b2b83cf5d5")}
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as 'all' | 'root' | 'subdomain');
                setPage(0);
              }}><MenuItem value="all">{i18nText("ui:m_3c6de4499e09e6f3fd1c")}</MenuItem><MenuItem value="root">{i18nText("ui:m_0e0283678f96b6c8771a")}</MenuItem><MenuItem value="subdomain">{i18nText("ui:m_b5fece3843f7bb605507")}</MenuItem></Select></FormControl><Button data-learn={i18nText("ui:m_516efadfeac31b936cce")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{(searchQuery || filterType !== 'all') ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_fff6b69e1da47ff9dae4", { arg0: filteredDomains.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Domains Table */}{!domainsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><LanguageIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_369ec34de22afc2092e5")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_b352453914458fe13583")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedDomains}
            totalCount={filteredDomains.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(domain) => handleRowClick(domain.domain)}
            renderCard={(domain) => (
              <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>{domain.domain}</Typography><Box display="flex" gap={2} mt={0.5} flexWrap="wrap"><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_66d27af5bd35445995e2", { arg0: domain.queryCount })}
                    </Typography><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_54c1aaf2b2d69aa497b5", { arg0: domain.uniqueClients })}
                    </Typography></Box>{(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length > 0 && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5} noWrap>
                      {i18nRichText("ui:m_3430d6af098deb1d86eb", { arg0: (domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').slice(0, 3).join(', '), arg1: (domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length > 3 ? ` +${(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length - 3}` : '' })}
                    </Typography>
                  )}<Box display="flex" gap={1} mt={0.5} flexWrap="wrap"><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_15d5e1f7d677437722bf", { arg0: formatTimestamp(domain.firstSeen, 'nanoseconds') })}
                    </Typography><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_0f8d6be8cc3baa6c1c17", { arg0: formatTimestamp(domain.lastSeen, 'nanoseconds') })}
                    </Typography></Box></CardContent></Card>
            )}
            desktopTable={<TableContainer component={Paper}><Table size="small" data-learn={i18nText("ui:m_234e8dfe17341bed8a02")}><TableHead><TableRow><TableCell width={40}></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_6922a099cfda078e1819")}
                        active={sortField === 'domain'}
                        direction={sortField === 'domain' ? sortOrder : 'asc'}
                        onClick={() => handleSort('domain')}>
                        {i18nText("ui:m_3460200432e5e2765020")}
                      </TableSortLabel></TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}><TableSortLabel data-learn={i18nText("ui:m_1d6bd0272781df56ccc8")}
                        active={sortField === 'type'}
                        direction={sortField === 'type' ? sortOrder : 'asc'}
                        onClick={() => handleSort('type')}>
                        {i18nText("ui:m_3da346bd3b7d84ce65d6")}
                      </TableSortLabel></TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }} data-learn={i18nText("ui:m_36c950f4eec67ee99657")}>
                      {i18nText("ui:m_4113167561ccea5b6c6b")}
                    </TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_b1f88842a007ea325f78")}
                        active={sortField === 'queries'}
                        direction={sortField === 'queries' ? sortOrder : 'asc'}
                        onClick={() => handleSort('queries')}>
                        {i18nText("ui:m_371bc19b3c9c4c5e6abf")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_02c7f1d30bde1cf372fb")}
                        active={sortField === 'clients'}
                        direction={sortField === 'clients' ? sortOrder : 'asc'}
                        onClick={() => handleSort('clients')}>
                        {i18nText("ui:m_afc13d85c5fb49315cfe")}
                      </TableSortLabel></TableCell><TableCell align="right" sx={{ display: { xs: 'none', lg: 'table-cell' } }}><TableSortLabel data-learn={i18nText("ui:m_82a98958ee5c6f0525e6")}
                        active={sortField === 'rtt'}
                        direction={sortField === 'rtt' ? sortOrder : 'asc'}
                        onClick={() => handleSort('rtt')}>
                        {i18nText("ui:m_d61888c3356f8c73b988")}
                      </TableSortLabel></TableCell><TableCell>{i18nText("ui:m_2532227a0436e915130b")}</TableCell><TableCell>{i18nText("ui:m_bc5a0f02fec085cf31e8")}</TableCell></TableRow></TableHead><TableBody>{paginatedDomains.map((domain) => (
                    <><TableRow key={domain.domain}
                        data-row-key={domain.domain}
                        hover
                        onClick={() => handleRowClick(domain.domain)}
                        sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                        data-learn={i18nText("ui:m_f080710e1231eed2514b")}><TableCell><IconButton size="small" data-learn={i18nText("ui:m_ea240840dd6540c63c6c")}><ExpandMoreIcon sx={{ 
                                transform: expandedRow === domain.domain ? 'rotate(180deg)' : 'rotate(0deg)',
                                transition: 'transform 0.3s'
                              }} /></IconButton></TableCell><TableCell><Tooltip title={domain.domain} placement="top"><Typography sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                fontWeight: 'medium',
                                maxWidth: '400px',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}
                              data-learn={i18nText("ui:m_faa80fa354473e76f98b")}>{domain.domain}</Typography></Tooltip></TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}><Chip data-learn={i18nText("ui:m_be98e6c21c3d3750c994")}
                            label={domain.isSubdomain ? i18nText("ui:m_485136190e9e87ba5407") : i18nText("ui:m_b1f206875930039e21ef")}
                            size="small"
                            color={domain.isSubdomain ? 'secondary' : 'primary'}
                            sx={{ fontSize: '0.7rem' }} /></TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}><Chip data-learn={i18nText("ui:m_d59fd8a4ac3e2dc96a1f")}
                            label={domain.source || 'DNS'}
                            size="small"
                            color={domain.source?.includes('TLS') ? 'success' : 'default'}
                            variant="outlined"
                            sx={{ fontSize: '0.7rem' }} /></TableCell><TableCell align="right"><Typography variant="body2">{domain.queryCount.toLocaleString(getUILocale())}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{domain.uniqueClients.toLocaleString(getUILocale())}</Typography></TableCell><TableCell align="right" sx={{ display: { xs: 'none', lg: 'table-cell' } }}><Tooltip title={transactionFlags(domain.dnsTransactions).join(', ') || i18nText("ui:m_8ba4a3538e3fa9465f90")} placement="top"><Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{medianRTT(domain.dnsTransactions)}{transactionFlags(domain.dnsTransactions).length > 0 && ' ⚠'}</Typography></Tooltip></TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(domain.recordTypes || []).slice(0, 3).map((rt) => (
                              <Chip key={rt}
                                label={rt}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn={i18nText("ui:m_30b5fd2fe257ca3f52bb")} />
                            ))}{(domain.recordTypes || []).length > 3 && (
                              <Chip label={`+${(domain.recordTypes || []).length - 3}`}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn={i18nText("ui:m_442501a2a8e7c91b8a30")} />
                            )}</Box></TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').slice(0, 2).map((ip) => (
                              <Chip key={ip}
                                label={ip}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20, fontFamily: 'monospace' }}
                                data-learn={i18nText("ui:m_66db74589915a7977cd3")} />
                            ))}{(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length > 2 && (
                              <Chip label={`+${(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length - 2}`}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }}
                                data-learn={i18nText("ui:m_daa2c98ac6353572c9fb")} />
                            )}</Box></TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={9}><Collapse in={expandedRow === domain.domain} timeout="auto" unmountOnExit><Box sx={{ py: 2 }} data-learn={i18nText("ui:m_c87aa0e37b3c15e0cde4")}><Grid container spacing={2}>{/* Time Range */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                    {i18nText("ui:m_7ef537318f8d80df5a89")}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_c2f3901b4530d9bcca6c", { arg0: formatTimestamp(domain.firstSeen, 'nanoseconds') })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_6ac7e146e6fe1424812b", { arg0: formatTimestamp(domain.lastSeen, 'nanoseconds') })}
                                  </Typography></Grid>{/* Statistics */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                    {i18nText("ui:m_893be24c31571dda650e")}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_060dd826826b35d54f18", { arg0: domain.queryCount.toLocaleString(getUILocale()) })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_7613667e4df304cacfa9", { arg0: domain.uniqueClients.toLocaleString(getUILocale()) })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_eba7f6ae13168c0bacc5", { arg0: domain.source || 'DNS' })}
                                  </Typography>{domain.isSubdomain && domain.parentDomain && (
                                    <Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_1a26412ace84a19f6b1a", { arg0: domain.parentDomain })}
                                    </Typography>
                                  )}</Grid>{domain.dnsTransactions && (
                                  <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_96ba4c36ef31489e09d6")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_61398bc0fcb54e1423d7", { arg0: domain.dnsTransactions.queries.toLocaleString(getUILocale()), arg1: domain.dnsTransactions.retransmissions.toLocaleString(getUILocale()) })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_9cdefdb2f4161ce4b499", { arg0: domain.dnsTransactions.answered.toLocaleString(getUILocale()), arg1: domain.dnsTransactions.late.toLocaleString(getUILocale()), arg2: domain.dnsTransactions.unanswered.toLocaleString(getUILocale()) })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_38623e05edb35b9d6288", { arg0: domain.dnsTransactions.unsolicited.toLocaleString(getUILocale()) })}
                                    </Typography>{(domain.dnsTransactions.reordered ?? 0) > 0 && <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_acaff9e152d96ac35d45", { arg0: domain.dnsTransactions.reordered })}</Typography>}{domain.dnsTransactions.rttTruncated && <Typography variant="body2" color="text.secondary">{i18nText("ui:m_53442baba34bd44d5f01")}</Typography>}{domain.dnsTransactions.rttSamples > 0 && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_0a2e71ae25ddbfddede3", { arg0: formatDurationNs(domain.dnsTransactions.rttMedianNs), arg1: formatDurationNs(domain.dnsTransactions.rttP95Ns), arg2: domain.dnsTransactions.rttSamples.toLocaleString(getUILocale()) })}
                                      </Typography>
                                    )}<Typography variant="caption" color="text.secondary">
                                      {i18nText("ui:m_6dd05ff3286ab74c8ecf")}
                                    </Typography></Grid>
                                )}{/* All Record Types */}{(domain.recordTypes || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nRichText("ui:m_eaaf390b1ce744c6f942", { arg0: (domain.recordTypes || []).length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(domain.recordTypes || []).map((rt) => (
                                        <Chip key={rt}
                                          label={rt}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }} />
                                      ))}</Box></Grid>
                                )}{/* Response Codes */}{(domain.responseCodes || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_2be6f44f32fba13e7015")}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(domain.responseCodes || []).map((rc) => {
                                        const responseCodeName = rc === 0 ? i18nText("ui:m_74720a7ce02c9b30dc05") : 
                                                               rc === 1 ? translate("ui:m_f3f0206dfe513afad329") :
                                                               rc === 2 ? translate("ui:m_aaccf60f1d83d6983065") :
                                                               rc === 3 ? translate("ui:m_3762c103f76540f01b96") :
                                                               rc === 4 ? translate("ui:m_52eb7e9077c79601ccf3") :
                                                               rc === 5 ? i18nText("ui:m_ec2e545d1c38366dc86a") :
                                                               i18nText("ui:m_00e8238df62b96a74933", { arg0: String(rc) });
                                        return (
                                          <Chip key={rc}
                                            label={`${responseCodeName} (${rc})`}
                                            size="small"
                                            color={rc === 0 ? 'success' : 'error'}
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem' }} />
                                        );
                                      })}</Box></Grid>
                                )}{/* All Resolved IPs */}{(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nRichText("ui:m_c9299332591e39db443f", { arg0: (domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(domain.resolvedIPs || []).filter(ip => ip && ip !== '<nil>').map((ip) => (
                                        <Chip key={ip}
                                          label={ip}
                                          size="small"
                                          color="info"
                                          sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }} />
                                      ))}</Box></Grid>
                                )}{/* Community IDs for Cross-Tool Correlation */}{(domain.communityIds || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_1c1a16162b43aab1338b")}>
                                      {i18nRichText("ui:m_90788a0b65a00abd64e0", { arg0: (domain.communityIds || []).length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(domain.communityIds || []).slice(0, 10).map((cid) => (
                                        <CommunityIDChip key={cid} communityId={cid} mode="chip" />
                                      ))}{(domain.communityIds || []).length > 10 && (
                                        <Chip label={i18nText("ui:m_5000f686d6d8f94a73f9", { arg0: (domain.communityIds || []).length - 10 })}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }} />
                                      )}</Box></Grid>
                                )}{/* Custom row actions from parent */}{rowActions && (
                                  <Grid item xs={12}><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>{rowActions(domain)}</Box></Grid>
                                )}</Grid></Box></Collapse></TableCell></TableRow></>
                  ))}</TableBody></Table></TableContainer>} />
        )}</>
        )}</Box></Layout>
  );
}
