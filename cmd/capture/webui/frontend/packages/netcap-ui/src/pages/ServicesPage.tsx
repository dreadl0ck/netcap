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

import React, { useState, useMemo, useEffect, useCallback } from 'react';
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
  Build as BuildIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingUpIcon,
  DeviceHub as DeviceHubIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Cable as CableIcon,
  Search as SearchIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';
import ServiceOverview from '../components/ServiceOverview';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';

import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';

import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";
import { rawCode } from "../lib/i18n";





export interface ServiceSummary {
  timestamp: number;
  ip: string;
  port: number;
  name: string;
  banner: string;
  protocol: string;
  numFlows: number;
  product: string;
  vendor: string;
  version: string;
  notes: string;
  bytesServer: number;
  bytesClient: number;
  hostname: string;
  os: string;
  applications: string[];
  portName: string;
  detectedProtocolName: string;
  matchedProbeID: string;
}

interface ServicesResponse {
  services: ServiceSummary[];
  totalCount: number;
}

type ServiceSortField = 'ip' | 'port' | 'protocol' | 'flows' | 'bytes';
type SortOrder = 'asc' | 'desc';

export interface ServicesPageProps {
  /** Custom row actions to render in the expanded row details */
  rowActions?: (row: ServiceSummary) => React.ReactNode;
}

export default function ServicesPage({ rowActions }: ServicesPageProps = {}) {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<ServiceSortField>('bytes');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

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

  // Fetch services data
  const { data: servicesData, error, mutate } = useSWR<ServicesResponse>(
    'services',
    () => api.getCaptureInventory<ServicesResponse>('services'),
    {
      refreshInterval: 10000,
    }
  );

  const services = servicesData?.services || [];
  const totalCount = servicesData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: ServiceSortField) => {
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
  const filteredServices = useMemo(() => {
    let filtered = services;

    // Apply search filter with negation support (e.g., "!SSH" excludes SSH services)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(s =>
        matchesSearchTerms([
          s.ip,
          s.port.toString(),
          s.name || '',
          s.protocol || '',
          s.product || '',
          s.vendor || '',
          s.hostname || '',
          s.portName || '',
          ...(s.applications || []),
        ], searchTerms)
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'ip':
          comparison = a.ip.localeCompare(b.ip);
          break;
        case 'port':
          comparison = a.port - b.port;
          break;
        case 'protocol':
          const protoA = a.protocol || '';
          const protoB = b.protocol || '';
          comparison = protoA.localeCompare(protoB);
          break;
        case 'flows':
          comparison = a.numFlows - b.numFlows;
          break;
        case 'bytes':
          const totalBytesA = a.bytesServer + a.bytesClient;
          const totalBytesB = b.bytesServer + b.bytesClient;
          comparison = totalBytesA - totalBytesB;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [services, searchQuery, sortField, sortOrder]);

  // Paginate services
  const paginatedServices = filteredServices.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedServices.map((svc, idx) => `${svc.ip}-${svc.port}-${idx}`),
    [paginatedServices]
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

  const handleRowClick = useCallback((key: string) => {
    setExpandedRow(prev => prev === key ? null : key);
  }, []);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_b08a862a28d919ad97f4")} />
  );

  // Calculate summary statistics
  const totalBytes = services.reduce((sum, s) => sum + s.bytesServer + s.bytesClient, 0);
  const totalFlows = services.reduce((sum, s) => sum + s.numFlows, 0);
  const uniqueProtocols = new Set(services.map(s => s.protocol)).size;
  const uniquePorts = new Set(services.map(s => s.port)).size;

  if (error) {
    return (
      <Layout title={i18nText("ui:m_c38f6f95f9a323ed3103")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_1bf29380ede5f9fd05a2", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_c38f6f95f9a323ed3103")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
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
        <StatBoxGrid><StatBox icon={<BuildIcon color="primary" />}
            label={i18nText("ui:m_bf273a9105197f00ac32")}
            value={totalCount}
            learnHint={translate("ui:m_ed991270f4dc86e406d4")} /><StatBox icon={<TrendingUpIcon color="success" />}
            label={i18nText("ui:m_5d5e198526c29a315aa1")}
            value={formatBytes(totalBytes)}
            learnHint={translate("ui:m_883fcd94d22d6c647848")} /><StatBox icon={<DeviceHubIcon color="warning" />}
            label={i18nText("ui:m_e232fea4190d7070f9ef")}
            value={totalFlows}
            learnHint={translate("ui:m_bc04fb01b8d055462530")} /><StatBox icon={<SpeedIcon color="info" />}
            label={i18nText("ui:m_413543f2e3fcea7b2fb2")}
            value={uniquePorts}
            learnHint={translate("ui:m_bac57770ff8e4bd6ca8c")} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_3735ab4f1185c2a535cd")}
                  key={`top-by-traffic-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/services/top-by-traffic`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_6bdba37659546954a71c")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_6381a397981209972827")}
                  key={`protocols-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/services/protocols?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_482e3d02454bb91d5c35")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_ba728ca0216ffadf06ea")}
                  key={`top-ports-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/services/top-ports`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_e5c5edb6faf48033bc37")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_10867755879c49cf523b")}
                  key={`top-products-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/services/top-products`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_6764e53c7c24125e7c0b")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_26a6d3bc2cd359557bc6")}
            learnHint={translate("ui:m_2e9d7e7df356ec3ea697")} /><Button data-learn={i18nText("ui:m_110c124d8584cb2f2c23")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_21fbe43a2ea96152d31f", { arg0: filteredServices.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Services Table */}{!servicesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><BuildIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_e630608324a59534205a")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_c956b9cc41f9855a34ce")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedServices}
            totalCount={filteredServices.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            renderCard={(svc) => {
              const svcTotalBytes = svc.bytesServer + svc.bytesClient;
              const cardKey = rawCode("card-{arg0}-{arg1}-{arg2}", { arg0: svc.ip, arg1: String(svc.port), arg2: svc.protocol });
              const open = expandedRow === cardKey;
              return (
                <Card variant="outlined"><CardContent role="button"
                    tabIndex={0}
                    aria-expanded={open}
                    aria-label={i18nText("ui:m_32d4b3b73455e681ef1d", { arg0: svc.ip, arg1: String(svc.port) })}
                    onClick={() => handleRowClick(cardKey)}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleRowClick(cardKey); } }}
                    sx={{ py: 1.5, px: 2, cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' }, '&:last-child': { pb: 1.5 } }}><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}><Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'primary.main', fontWeight: 'bold' }}>{svc.ip}</Typography><Chip label={svc.protocol || i18nText("ui:m_2f1ac5f44673922d2bf2")}
                        size="small"
                        color="primary"
                        sx={{ fontSize: '0.7rem' }} /></Box><Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 0.5 }}><Typography variant="body2" sx={{ fontFamily: 'monospace', color: 'warning.main', fontWeight: 'medium' }}>:{svc.port}</Typography>{svc.portName && (
                        <Chip label={svc.portName} size="small" color="secondary" variant="outlined" sx={{ fontSize: '0.65rem' }} />
                      )}</Box>{svc.banner && (
                      <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', mb: 0.5 }}>{svc.banner.length > 60 ? svc.banner.substring(0, 60) + '...' : svc.banner}</Typography>
                    )}<Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_7cd05b7e9c3dc90dd50c", { arg0: svc.numFlows })}
                      </Typography><Typography variant="caption" color="text.secondary">{formatBytes(svcTotalBytes)}</Typography></Box></CardContent><Collapse in={open} timeout="auto" unmountOnExit><Box sx={{ p: 1.5, pt: 0 }}><ServiceOverview service={svc} /></Box></Collapse></Card>
              );
            }}
            desktopTable={<TableContainer component={Paper}><Table size="small" data-learn={i18nText("ui:m_2de944559f93ad9090c0")}><TableHead><TableRow><TableCell width={40}></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_9647aeffd19c0ab84832")}
                        active={sortField === 'ip'}
                        direction={sortField === 'ip' ? sortOrder : 'asc'}
                        onClick={() => handleSort('ip')}>
                        {i18nText("ui:m_7bcf5a662fd0c3e8f3c2")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_60c28ca4ab0db7aa59ad")}
                        active={sortField === 'port'}
                        direction={sortField === 'port' ? sortOrder : 'asc'}
                        onClick={() => handleSort('port')}>
                        {i18nText("ui:m_e3ee61fa78ee06ea77cc")}
                      </TableSortLabel></TableCell><TableCell data-learn={i18nText("ui:m_c725be5166540e460549")}>
                      {i18nText("ui:m_e1d47e59dd85d4abaa0f")}
                    </TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_f3efedf8d252d626855b")}
                        active={sortField === 'protocol'}
                        direction={sortField === 'protocol' ? sortOrder : 'asc'}
                        onClick={() => handleSort('protocol')}>
                        {i18nText("ui:m_2d5b0d13af7edb332cfd")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_70c7455347699f29f52a")}
                        active={sortField === 'flows'}
                        direction={sortField === 'flows' ? sortOrder : 'asc'}
                        onClick={() => handleSort('flows')}>
                        {i18nText("ui:m_533e6ea96e567e590ef9")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_2c9c132e466ef2939ddd")}
                        active={sortField === 'bytes'}
                        direction={sortField === 'bytes' ? sortOrder : 'asc'}
                        onClick={() => handleSort('bytes')}>
                        {i18nText("ui:m_dc58fb07f5e14e63a67b")}
                      </TableSortLabel></TableCell><TableCell data-learn={i18nText("ui:m_adcaa1f6c131ea15270b")}>
                      {i18nText("ui:m_402c5274713115bcbd2e")}
                    </TableCell></TableRow></TableHead><TableBody>{paginatedServices.map((svc, idx) => {
                    const rowKey = `${svc.ip}-${svc.port}-${idx}`;
                    const totalBytes = svc.bytesServer + svc.bytesClient;
                    return (
                      <React.Fragment key={rowKey}><TableRow data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn={i18nText("ui:m_c9fc6f87ef8b860d0d25")}><TableCell><IconButton size="small" data-learn={i18nText("ui:m_0772730cc424206fe6f8")}><ExpandMoreIcon sx={{
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} /></IconButton></TableCell><TableCell><Typography sx={{
                                fontFamily: 'monospace',
                                fontSize: '0.875rem',
                                color: 'primary.main',
                                fontWeight: 'bold',
                              }}
                              data-learn={i18nText("ui:m_9b14597c447f1cb34108")}>{svc.ip}</Typography></TableCell><TableCell><Typography variant="body2"
                              sx={{
                                fontFamily: 'monospace',
                                color: 'warning.main',
                                fontWeight: 'medium',
                              }}>{svc.port}</Typography></TableCell><TableCell>{svc.portName ? (
                              <Chip data-learn={i18nText("ui:m_b163408f04d6e4d13bdf")}
                                label={svc.portName}
                                size="small"
                                color="secondary"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem' }} />
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>{svc.name || '-'}</Typography>
                            )}</TableCell><TableCell><Chip data-learn={i18nText("ui:m_1cb47da436a70dc7ec78")}
                              label={svc.protocol || i18nText("ui:m_2f1ac5f44673922d2bf2")}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }} /></TableCell><TableCell align="right"><Typography variant="body2">{svc.numFlows.toLocaleString(getUILocale())}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{formatBytes(totalBytes)}</Typography></TableCell><TableCell>{svc.product ? (
                              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}><Typography variant="body2" sx={{ fontWeight: 'medium', fontSize: '0.8rem' }}>{svc.product}</Typography>{svc.vendor && (
                                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>{svc.vendor}</Typography>
                                )}</Box>
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>-
                              </Typography>
                            )}</TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={8}><Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit><Box sx={{ py: 2 }} data-learn={i18nText("ui:m_7ee016863b7edf7b17f6")}><Grid container spacing={2}><Grid item xs={12}><ServiceOverview service={svc} /></Grid>{/* Applications */}{(svc.applications || []).length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_12327e198adaa6d81100", { arg0: (svc.applications || []).length })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(svc.applications || []).map((app) => (
                                          <Chip key={app}
                                            label={app}
                                            size="small"
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }}
                                            data-learn={i18nText("ui:m_b48767233421abbc5192")} />
                                        ))}</Box></Grid>
                                  )}{/* Notes */}{svc.notes && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nText("ui:m_906235396e574e3ca4d8")}
                                      </Typography><Typography variant="body2" color="text.secondary">{svc.notes}</Typography></Grid>
                                  )}{/* Action Buttons */}<Grid item xs={12}><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}><Button data-learn={i18nText("ui:m_aa618148e35c6a57fe67")}
                                        variant="outlined"
                                        color="primary"
                                        startIcon={<CableIcon />}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          router.push(`/connections?search=${encodeURIComponent(`${svc.ip}:${svc.port}`)}`);
                                        }}
                                        size="small">
                                        {i18nText("ui:m_1d63dcd4ff17dbd7a873")}
                                      </Button>{svc.matchedProbeID && (
                                        <Button data-learn={i18nText("ui:m_76ed71b662e04df4e699")}
                                          variant="outlined"
                                          color="primary"
                                          startIcon={<SearchIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/service-signatures?search=${encodeURIComponent(svc.matchedProbeID)}`);
                                          }}
                                          size="small">
                                          {i18nText("ui:m_0d71747f450ee6aade72")}
                                        </Button>
                                      )}{/* Custom row actions from parent */}{rowActions && rowActions(svc)}</Box></Grid></Grid></Box></Collapse></TableCell></TableRow></React.Fragment>
                    );
                  })}</TableBody></Table></TableContainer>} />
        )}</>
        )}</Box></Layout>
  );
}
