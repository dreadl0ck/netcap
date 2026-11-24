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
import type { FingerprintSummary, FingerprintsResponse } from '../lib/api';
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
  Fingerprint as FingerprintIcon,
  Security as SecurityIcon,
  VpnLock as VpnLockIcon,
  Router as RouterIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Http as HttpIcon,
  VerifiedUser as VerifiedUserIcon,
  Memory as MemoryIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import SearchInput from '../components/SearchInput';
import ResponsiveDataView from '../components/ResponsiveDataView';
import { CommunityIDChip } from '../components/CommunityIDChip';
import { formatTimestamp, getBackendUrl } from '../lib/api';
import { useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';


import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { getLocale } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";





type FingerprintSortField = 'fingerprint' | 'type' | 'count' | 'hosts';
type SortOrder = 'asc' | 'desc';
type FingerprintTypeFilter = 'all' | 'JA4' | 'JA4S' | 'JA4H' | 'JA4X' | 'JA4T' | 'JA4TS' | 'JA4SSH' | 'DHCP';

export default function FingerprintsPage() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<FingerprintTypeFilter>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<FingerprintSortField>('count');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

  // Debounce search input so we don't re-fetch on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearchQuery(searchQuery), 300);
    return () => clearTimeout(t);
  }, [searchQuery]);

  // Reset page to 0 when the Community ID filter changes via global context
  // (e.g., clicking a CommunityIDChip on another page), so the user never
  // lands on an out-of-range page that shows an empty table.
  useEffect(() => {
    setPage(0);
  }, [selectedCommunityIDs, isCommunityIDFilterActive]);

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Stable, sorted list of community IDs for SWR keying.
  const communityIdsArr = useMemo(
    () => (isCommunityIDFilterActive ? Array.from(selectedCommunityIDs).sort() : undefined),
    [isCommunityIDFilterActive, selectedCommunityIDs]
  );

  // Fetch fingerprints from the backend with filters, sort and pagination
  // applied server-side. Per-row community IDs and hosts are capped by the
  // backend so the browser never has to render unbounded arrays.
  const { data: fingerprintsData, error, mutate } = useSWR<FingerprintsResponse>(
    ['fingerprints', debouncedSearchQuery, filterType, sortField, sortOrder, page, rowsPerPage, communityIdsArr],
    () => api.getFingerprints({
      limit: rowsPerPage,
      offset: page * rowsPerPage,
      type: filterType !== 'all' ? filterType : undefined,
      search: debouncedSearchQuery || undefined,
      sortField,
      sortOrder,
      communityIds: communityIdsArr,
    }),
    {
      refreshInterval: 0,
      keepPreviousData: true,
    }
  );

  const paginatedFingerprints = fingerprintsData?.fingerprints ?? [];
  const filteredTotalCount = fingerprintsData?.totalCount ?? 0;
  const stats = fingerprintsData?.stats;
  const totalCount = stats?.totalFingerprints ?? 0;

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

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedFingerprints.map((fp, idx) => `${fp.type}-${fp.fingerprint}-${idx}`),
    [paginatedFingerprints]
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

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_70b1cc76d35246d3d575")} />
  );

  // Summary statistics provided by the backend over the FULL dataset
  // (independent of the current page or active filters).
  const counts = stats?.countsByType ?? {};
  const ja4Count = counts['JA4'] ?? 0;
  const ja4sCount = counts['JA4S'] ?? 0;
  const ja4hCount = counts['JA4H'] ?? 0;
  const ja4xCount = counts['JA4X'] ?? 0;
  const ja4tCount = counts['JA4T'] ?? 0;
  const ja4tsCount = counts['JA4TS'] ?? 0;
  const ja4sshCount = counts['JA4SSH'] ?? 0;
  const dhcpCount = counts['DHCP'] ?? 0;
  // Kept for potential future use; the in-page summary cards don't currently
  // display total occurrences but the backend exposes it.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const totalOccurrences = stats?.totalOccurrences ?? 0;

  if (error) {
    return (
      <Layout title={i18nText("ui:m_919292d9354daf5b36fd")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_6bf71d4762064edd0a34", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_919292d9354daf5b36fd")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{fingerprintsData?.partial && <Alert severity="info" sx={{ mb: 2 }}>This inventory reached its scan limit. Counts and search cover only the indexed records.</Alert>}{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
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
            </ToggleButton></ToggleButtonGroup></Box>{/* Summary Cards - Row 1: Core TLS fingerprints - Only show in table mode */}{viewMode === 'table' && (
        <Grid container spacing={2} sx={{ mb: 2 }}><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_d384d52f117191a79abb")}
              onClick={() => { setFilterType('all'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'all' ? 2 : 0,
                borderColor: 'primary.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><FingerprintIcon color="primary" /><Box><Typography variant="caption" color="text.secondary">
                      {i18nText("ui:m_69fcd9877bc9847f4367")}
                    </Typography><Typography variant="h6">{totalCount.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_986b6d72a781a8c950aa")}
              onClick={() => { setFilterType('JA4'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4' ? 2 : 0,
                borderColor: 'success.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><VpnLockIcon color="success" /><Box><Typography variant="caption" color="text.secondary">
                      {i18nText("ui:m_1ecdd91fab83aec71251")}
                    </Typography><Typography variant="h6">{ja4Count.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_32ee75f90a9823c42743")}
              onClick={() => { setFilterType('JA4S'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4S' ? 2 : 0,
                borderColor: 'info.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><VpnLockIcon color="info" /><Box><Typography variant="caption" color="text.secondary">
                      {i18nText("ui:m_882a5993aa766ba31098")}
                    </Typography><Typography variant="h6">{ja4sCount.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_acdb00755da7d745843c")}
              onClick={() => { setFilterType('JA4H'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4H' ? 2 : 0,
                borderColor: 'secondary.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><HttpIcon color="secondary" /><Box><Typography variant="caption" color="text.secondary">
                      {i18nText("ui:m_8e4ec15e25640c1bba90")}
                    </Typography><Typography variant="h6">{ja4hCount.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_d262614abda164d9c082")}
              onClick={() => { setFilterType('JA4X'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4X' ? 2 : 0,
                borderColor: 'secondary.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><VerifiedUserIcon sx={{ color: 'secondary.main' }} /><Box><Typography variant="caption" color="text.secondary">
                      {i18nText("ui:m_a3e21dc5642ba9be62ea")}
                    </Typography><Typography variant="h6">{ja4xCount.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid></Grid>
        )}{/* Summary Cards - Row 2: TCP, SSH, and DHCP fingerprints - Only show in table mode */}{viewMode === 'table' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_ca20cc966d571ffd8bc8")}
              onClick={() => { setFilterType('JA4T'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4T' ? 2 : 0,
                borderColor: 'warning.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><MemoryIcon sx={{ color: 'warning.main' }} /><Box><Typography variant="caption" color="text.secondary">
                      {i18nText("ui:m_de8b6468912754437181")}
                    </Typography><Typography variant="h6">{ja4tCount.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_a77dbf9937b943ca9120")}
              onClick={() => { setFilterType('JA4TS'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4TS' ? 2 : 0,
                borderColor: 'info.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><MemoryIcon sx={{ color: 'info.main' }} /><Box><Typography variant="caption" color="text.secondary">
                      {i18nText("ui:m_9f6a56b8e786c8e3f511")}
                    </Typography><Typography variant="h6">{ja4tsCount.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_9573b1e12bf503aacb9e")}
              onClick={() => { setFilterType('JA4SSH'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'JA4SSH' ? 2 : 0,
                borderColor: 'warning.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><SecurityIcon color="warning" /><Box><Typography variant="caption" color="text.secondary">
                      {i18nText("ui:m_8d90fe9abe7685569b49")}
                    </Typography><Typography variant="h6">{ja4sshCount.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={2.4}><Card data-learn={i18nText("ui:m_c0a14aa2c310b7b7a435")}
              onClick={() => { setFilterType('DHCP'); setPage(0); }}
              sx={{ 
                cursor: 'pointer', 
                transition: 'all 0.2s',
                border: filterType === 'DHCP' ? 2 : 0,
                borderColor: 'info.main',
                '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 }
              }}><CardContent sx={{ py: 1.5 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><RouterIcon color="info" /><Box><Typography variant="caption" color="text.secondary">DHCP
                    </Typography><Typography variant="h6">{dhcpCount.toLocaleString(getUILocale())}</Typography></Box></Box></CardContent></Card></Grid></Grid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_31142c201f82028f078c")}
                  key={`type-distribution-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/type-distribution?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_4eea05d33ee0dba079ac")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_3bf81207065c3d1d0f50")}
                  key={`top-ja4-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/top-ja4`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_8978091ad22768c05ab6")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_9a2b6507d8ae9b1e1598")}
                  key={`top-ja4ssh-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/top-ja4ssh`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_70e822ed966f0a288768")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_1d73e8350464e4745ed2")}
                  key={`hosts-per-fingerprint-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/fingerprints/hosts-per-fingerprint`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_5e873c230e0ea0ec7a07")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_f84d00422404162c4f54")}
            learnHint={translate("ui:m_1d6b3495ec3022d0d0ba")} /><FormControl size="small" sx={{ minWidth: 180 }}><Select data-learn={i18nText("ui:m_f1effe0c5f780538aa59")}
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as 'all' | 'JA4' | 'JA4S' | 'JA4H' | 'JA4X' | 'JA4T' | 'JA4TS' | 'JA4SSH' | 'DHCP');
                setPage(0);
              }}><MenuItem value="all">{i18nText("ui:m_54b1a113c48b3b056e29")}</MenuItem><MenuItem value="JA4">{i18nText("ui:m_1ecdd91fab83aec71251")}</MenuItem><MenuItem value="JA4S">{i18nText("ui:m_882a5993aa766ba31098")}</MenuItem><MenuItem value="JA4H">{i18nText("ui:m_8e4ec15e25640c1bba90")}</MenuItem><MenuItem value="JA4X">{i18nText("ui:m_a3e21dc5642ba9be62ea")}</MenuItem><MenuItem value="JA4T">{i18nText("ui:m_de8b6468912754437181")}</MenuItem><MenuItem value="JA4TS">{i18nText("ui:m_9f6a56b8e786c8e3f511")}</MenuItem><MenuItem value="JA4SSH">{i18nText("ui:m_8d90fe9abe7685569b49")}</MenuItem><MenuItem value="DHCP">DHCP</MenuItem></Select></FormControl><Button data-learn={i18nText("ui:m_12004b6de9ca0ff4c8bc")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{(searchQuery || filterType !== 'all' || isCommunityIDFilterActive) ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_015542657b8ded25bcca", { arg0: filteredTotalCount.toLocaleString(getUILocale()), arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Fingerprints Table */}{!fingerprintsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><FingerprintIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_a1884fcca864de539a59")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_865212996445a286bd4c")}
            </Typography></Paper>
        ) : (
          <><ResponsiveDataView data={paginatedFingerprints}
              totalCount={filteredTotalCount}
              page={page}
              rowsPerPage={rowsPerPage}
              onPageChange={handleChangePage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
              onCardClick={(fp: FingerprintSummary) => {
                const idx = paginatedFingerprints.indexOf(fp);
                const rowKey = `${fp.type}-${fp.fingerprint}-${idx}`;
                handleRowClick(rowKey);
              }}
              renderCard={(fp: FingerprintSummary, idx: number) => (
                <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}><Typography variant="subtitle2"
                        sx={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all', flex: 1, mr: 1 }}>{fp.fingerprint}</Typography><Chip label={fp.type}
                        size="small"
                        color={fp.type === 'JA4' ? 'success' :
                          fp.type === 'JA4S' ? 'primary' :
                          fp.type === 'JA4H' ? 'secondary' :
                          fp.type === 'JA4X' ? 'default' :
                          fp.type === 'JA4T' ? 'error' :
                          fp.type === 'JA4TS' ? 'error' :
                          fp.type === 'JA4SSH' ? 'warning' :
                          'info'}
                        sx={{
                          fontSize: '0.7rem',
                          ...(fp.type === 'JA4X' && { backgroundColor: 'secondary.main', color: 'secondary.contrastText' }),
                          ...(fp.type === 'JA4TS' && { backgroundColor: 'info.main', color: 'info.contrastText' }),
                        }} /></Box><Box sx={{ display: 'flex', gap: 2, mb: 0.5 }}><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_99799db2053938fe5872", { arg0: fp.count.toLocaleString(getUILocale()) })}
                      </Typography><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_38c6c7a7c2053a725ffa", { arg0: fp.hostsTotal.toLocaleString(getUILocale()) })}
                      </Typography></Box>{fp.description && (
                      <Typography variant="caption" color="text.secondary" noWrap>{fp.description}</Typography>
                    )}</CardContent></Card>
              )}
              desktopTable={<TableContainer component={Paper}><Table size="small" data-learn={i18nText("ui:m_ac7695a2903993e17bb6")}><TableHead><TableRow><TableCell width={40}></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_343e85952e777db09a04")}
                        active={sortField === 'fingerprint'}
                        direction={sortField === 'fingerprint' ? sortOrder : 'asc'}
                        onClick={() => handleSort('fingerprint')}>
                        {i18nText("ui:m_364ab56f4db4d9a1c3a1")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_0bb20d504bc7e4d64049")}
                        active={sortField === 'type'}
                        direction={sortField === 'type' ? sortOrder : 'asc'}
                        onClick={() => handleSort('type')}>
                        {i18nText("ui:m_3da346bd3b7d84ce65d6")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_eea7d2d4bdebd9d4597f")}
                        active={sortField === 'count'}
                        direction={sortField === 'count' ? sortOrder : 'asc'}
                        onClick={() => handleSort('count')}>
                        {i18nText("ui:m_9cc2c6f927f2cbb0421c")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_0b51c6f242cf2a4beed4")}
                        active={sortField === 'hosts'}
                        direction={sortField === 'hosts' ? sortOrder : 'asc'}
                        onClick={() => handleSort('hosts')}>
                        {i18nText("ui:m_74ae2e341e215c830a8f")}
                      </TableSortLabel></TableCell><TableCell>{i18nText("ui:m_a02602e322c10d1a5449")}</TableCell></TableRow></TableHead><TableBody>{paginatedFingerprints.map((fp, idx) => {
                    const rowKey = `${fp.type}-${fp.fingerprint}-${idx}`;
                    return (
                      <><TableRow key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn={i18nText("ui:m_fb95b3cc4cc56daec274")}><TableCell><IconButton size="small" data-learn={i18nText("ui:m_9012a23ed61c91acbc9a")}><ExpandMoreIcon sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} /></IconButton></TableCell><TableCell><Typography sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                fontWeight: 'medium',
                                wordBreak: 'break-all'
                              }}
                              data-learn={i18nText("ui:m_9feee40d006c6e17f387")}>{fp.fingerprint}</Typography></TableCell><TableCell><Chip data-learn={i18nText("ui:m_fa5036e23d74d871394c")}
                              label={fp.type}
                              size="small"
                              color={fp.type === 'JA4' ? 'success' : 
                                fp.type === 'JA4S' ? 'primary' : 
                                fp.type === 'JA4H' ? 'secondary' :
                                fp.type === 'JA4X' ? 'default' :
                                fp.type === 'JA4T' ? 'error' :
                                fp.type === 'JA4TS' ? 'error' :
                                fp.type === 'JA4SSH' ? 'warning' : 
                                'info'}
                              sx={{ 
                                fontSize: '0.7rem',
                                ...(fp.type === 'JA4X' && { backgroundColor: 'secondary.main', color: 'secondary.contrastText' }),
                                ...(fp.type === 'JA4TS' && { backgroundColor: 'info.main', color: 'info.contrastText' }),
                              }} /></TableCell><TableCell align="right"><Typography variant="body2">{fp.count.toLocaleString(getUILocale())}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{fp.hostsTotal.toLocaleString(getUILocale())}</Typography></TableCell><TableCell><Typography variant="body2" color="text.secondary" sx={{ 
                              maxWidth: 300,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}>{fp.description}</Typography></TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}><Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit><Box sx={{ py: 2 }} data-learn={i18nText("ui:m_a0c45e00870ead528b1f")}><Grid container spacing={2}>{/* Time Range */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_ebd9f51d60130ed4f5b7")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_c2f3901b4530d9bcca6c", { arg0: formatTimestamp(fp.firstSeen, 'nanoseconds') })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_6ac7e146e6fe1424812b", { arg0: formatTimestamp(fp.lastSeen, 'nanoseconds') })}
                                    </Typography></Grid>{/* Statistics */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_893be24c31571dda650e")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_e56d31bfe0f111e5036a", { arg0: fp.count.toLocaleString(getUILocale()) })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_3cca09b6cad85e23574d", { arg0: fp.hostsTotal.toLocaleString(getUILocale()) })}
                                    </Typography></Grid>{/* Full Description */}{fp.description && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nText("ui:m_9268c3aee93ad0bebb91")}
                                      </Typography><Typography variant="body2" color="text.secondary">{fp.description}</Typography></Grid>
                                  )}{/* Associated Hosts */}{fp.hosts.length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_0c643030722fff871686", { arg0: fp.hostsTruncated ? i18nText("ui:m_c713d4788099b5455698", { arg0: fp.hosts.length, arg1: fp.hostsTotal.toLocaleString(getUILocale()) }) : ` (${fp.hostsTotal.toLocaleString(getLocale())})` })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{fp.hosts.map((host) => (
                                          <Chip key={host}
                                            label={host}
                                            size="small"
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }} />
                                        ))}</Box></Grid>
                                  )}{/* Community IDs */}{fp.communityIds && fp.communityIds.length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_8a87f6b6ac34314d7faf", { arg0: fp.communityIdsTruncated ? i18nText("ui:m_c713d4788099b5455698", { arg0: fp.communityIds.length, arg1: fp.communityIdsTotal.toLocaleString(getUILocale()) }) : ` (${fp.communityIdsTotal.toLocaleString(getLocale())})` })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{fp.communityIds.map((cid) => {
                                          const isMatch = isCommunityIDFilterActive && selectedCommunityIDs.has(cid);
                                          return (
                                            <Tooltip key={cid}
                                              title={isMatch ? i18nText("ui:m_917dcf0ceb20fab8fa16") : ''}
                                              arrow
                                              disableHoverListener={!isMatch}><Box sx={isMatch ? {
                                                  outline: theme => `2px solid ${theme.palette.primary.main}`,
                                                  outlineOffset: 1,
                                                  borderRadius: 1,
                                                } : undefined}><CommunityIDChip communityId={cid}
                                                  mode="chip"
                                                  truncate={false} /></Box></Tooltip>
                                          );
                                        })}</Box>{fp.communityIdsTruncated && (
                                        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                                          {i18nText("ui:m_0575f9943a6ad5b24925")}
                                        </Typography>
                                      )}</Grid>
                                  )}</Grid></Box></Collapse></TableCell></TableRow></>
                    );
                  })}</TableBody></Table></TableContainer>} /></>
        )}</>
        )}</Box></Layout>
  );
}
