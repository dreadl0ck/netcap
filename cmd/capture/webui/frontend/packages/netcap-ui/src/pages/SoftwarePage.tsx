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
  Memory as MemoryIcon,
  Computer as ComputerIcon,
  Apps as AppsIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Cable as CableIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';

import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

import { ChartFrame } from '../components/ChartFrame';
import SoftwareEvidence, { type SoftwareObservation } from '../components/SoftwareEvidence';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";





interface SoftwareSummary {
  observations?: SoftwareObservation[];
  observationsCapped?: boolean;
  product: string;
  version: string;
  os: string;
  count: number;
  devices: string[];
  services: string[];
  dpiResults: string[];
  firstSeen: number;
  lastSeen: number;
  sourceNames: string[];
  flows: string[];
  // Detection context
  detectionMethod: string;
  confidenceLevel: string;
  // Behavioral fingerprint
  behaviorProfile: string;
  isHeadless: boolean;
  isEmulated: boolean;
  isAutomated: boolean;
  // Risk indicators
  hasKnownVulnerabilities: boolean;
  isEndOfLife: boolean;
  supportStatus: string;
  // Community ID for cross-tool correlation
  communityIds: string[];
}

interface SoftwareResponse {
  software: SoftwareSummary[];
  totalCount: number;
}

type SoftwareSortField = 'product' | 'version' | 'count' | 'devices';
type SortOrder = 'asc' | 'desc';

export default function SoftwarePage() {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<SoftwareSortField>('count');
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

  // Fetch software data
  const { data: softwareData, error, mutate } = useSWR<SoftwareResponse>(
    'software',
    () => fetch(`${getBackendUrl()}/api/software`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const software = softwareData?.software || [];
  const totalCount = softwareData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: SoftwareSortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0);
  };

  // Apply filters and sorting
  const filteredSoftware = useMemo(() => {
    let filtered = software;

    // Apply Community ID filter first (if active)
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(sw => 
        sw.communityIds && sw.communityIds.some(cid => selectedCommunityIDs.has(cid))
      );
    }

    // Apply search filter with negation support (e.g., "!Windows" excludes Windows software)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(sw =>
        matchesSearchTerms([
          sw.product,
          sw.version || '',
          sw.os || '',
          ...(sw.devices || []),
          ...(sw.services || []),
        ], searchTerms)
      );
    }

    // Apply sorting with stable secondary sort by product and version
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'product':
          comparison = a.product.localeCompare(b.product);
          break;
        case 'version':
          comparison = (a.version || '').localeCompare(b.version || '');
          break;
        case 'count':
          comparison = a.count - b.count;
          break;
        case 'devices':
          comparison = a.devices.length - b.devices.length;
          break;
      }
      // Stable secondary sort by product then version for consistent ordering
      if (comparison === 0) {
        comparison = a.product.localeCompare(b.product);
        if (comparison === 0) {
          comparison = (a.version || '').localeCompare(b.version || '');
        }
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [software, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs]);

  const paginatedSoftware = filteredSoftware.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedSoftware.map((sw, idx) => `${sw.product}-${sw.version}-${idx}`),
    [paginatedSoftware]
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
      learnHint={finalCopyMessage("ui:m_bf6281783374a094fcbb")} />
  );

  // Calculate summary statistics
  const uniqueProducts = new Set(software.map(sw => sw.product)).size;
  const uniqueVersions = software.filter(sw => sw.version).length;
  const totalDetections = software.reduce((sum, sw) => sum + sw.count, 0);

  if (error) {
    return (
      <Layout title={i18nText("ui:m_99c431556bb898cfc4c6")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_5637367acb5d333d6ba3", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_99c431556bb898cfc4c6")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
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
        <StatBoxGrid><StatBox icon={<AppsIcon color="primary" />}
            label={i18nText("ui:m_957e5299b7bbab9f187e")}
            value={uniqueProducts}
            learnHint={translate("ui:m_78e51bc97ee110bbef99")} /><StatBox icon={<MemoryIcon color="warning" />}
            label={i18nText("ui:m_68c879336eb386dd3116")}
            value={uniqueVersions}
            learnHint={translate("ui:m_b381b28bd466af4cc813")} /><StatBox icon={<ComputerIcon color="info" />}
            label={i18nText("ui:m_fcb39f2d7b253d8f3e73")}
            value={totalDetections}
            learnHint={translate("ui:m_023e02f2a07b77b3c8a5")} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_1b71c1aac03fc855a20f")}
                  key={`top-products-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/software/top-products`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_fca27a2ace1a06d72cc1")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_960c9d263a38ef2a5c59")}
                  key={`vendors-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/software/vendors?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_3fca767c891d469a4337")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_65bfd8011b4e38e8a512")}
                  key={`operating-systems-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/software/operating-systems`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_52b71f6b027713d3cd43")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_7bd8302710ea015dedc5")}
                  key={`versions-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/software/versions`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_77613af5f47b794ec749")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_19ca16efd825b68b33ad")}
            learnHint={translate("ui:m_23ec532b17c93646d00c")} /><Button data-learn={i18nText("ui:m_cd9c752b81e4341c1277")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_fba3e429409505c58665", { arg0: filteredSoftware.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Software Table */}{!softwareData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><AppsIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_ff4a9d3ab7fea72d5a32")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_08f18ebe75b59956f4e5")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedSoftware}
            totalCount={filteredSoftware.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(sw) => handleRowClick(`${sw.product}-${sw.version}-${paginatedSoftware.indexOf(sw)}`)}
            renderCard={(sw) => (
              <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>{sw.product}</Typography><Box display="flex" gap={2} mt={0.5} flexWrap="wrap">{sw.version && (
                      <Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_ff085e14eacb1481b688", { arg0: String(sw.version) })}
                      </Typography>
                    )}<Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_a165d617fcdfc33794f7", { arg0: sw.count.toLocaleString(getUILocale()) })}
                    </Typography><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_dfe52c2e6132ea03a45d", { arg0: sw.devices.length })}
                    </Typography></Box>{sw.os && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                      {i18nRichText("ui:m_8136a09648ef4af1f7b6", { arg0: sw.os })}
                    </Typography>
                  )}</CardContent></Card>
            )}
            desktopTable={<TableContainer component={Paper}><Table size="small" data-learn={i18nText("ui:m_f6ccfd3d7032786a7220")}><TableHead><TableRow><TableCell width={40}></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_426d8ead1d39d70ead49")}
                        active={sortField === 'product'}
                        direction={sortField === 'product' ? sortOrder : 'asc'}
                        onClick={() => handleSort('product')}>
                        {i18nText("ui:m_402c5274713115bcbd2e")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_caf7b7f2b1141fcbaa78")}
                        active={sortField === 'version'}
                        direction={sortField === 'version' ? sortOrder : 'asc'}
                        onClick={() => handleSort('version')}>
                        {i18nText("ui:m_37b931c3ef2914c51753")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_3eea4556a3c457ebeded")}
                        active={sortField === 'count'}
                        direction={sortField === 'count' ? sortOrder : 'asc'}
                        onClick={() => handleSort('count')}>
                        {i18nText("ui:m_9940ca574ee0fed6156c")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_f14e454a6d2ff7f5981d")}
                        active={sortField === 'devices'}
                        direction={sortField === 'devices' ? sortOrder : 'asc'}
                        onClick={() => handleSort('devices')}>
                        {i18nText("ui:m_96f53788dbcf443fbaab")}
                      </TableSortLabel></TableCell><TableCell>OS</TableCell></TableRow></TableHead><TableBody>{paginatedSoftware.map((sw, idx) => {
                    const rowKey = `${sw.product}-${sw.version}-${idx}`;
                    return (
                      <><TableRow key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn={i18nText("ui:m_145ff35d0329c0478b4d")}><TableCell><IconButton size="small" data-learn={i18nText("ui:m_2b9852ea1adcda432185")}><ExpandMoreIcon sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} /></IconButton></TableCell><TableCell><Typography sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                fontWeight: 'medium'
                              }}
                              data-learn={i18nText("ui:m_ad02ab2b9a5ab345df71")}>{sw.product}</Typography></TableCell><TableCell><Typography variant="body2"
                              sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                              data-learn={i18nText("ui:m_a1a5c25a926be06eb27d")}>{sw.version}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{sw.count.toLocaleString(getUILocale())}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{sw.devices.length.toLocaleString(getUILocale())}</Typography></TableCell><TableCell>{sw.os ? (
                              <Chip data-learn={i18nText("ui:m_edcff408390fd2164bf1")}
                              label={sw.os}
                              size="small"
                              color="info"
                              sx={{ fontSize: '0.7rem' }} />
                            ) : ''}</TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}><Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit><Box sx={{ py: 2 }} data-learn={i18nText("ui:m_bda1dae693d3ff9df043")}><Grid container spacing={2}>{/* Time Range */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_1c53a7a9be0235f877ce")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_be30d6c838f3600ce446", { arg0: formatTimestamp(sw.firstSeen, 'nanoseconds') })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_04372e0b14a571e22a09", { arg0: formatTimestamp(sw.lastSeen, 'nanoseconds') })}
                                    </Typography></Grid>{/* Statistics */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_893be24c31571dda650e")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_d526ac831f5857c31ed9", { arg0: sw.count.toLocaleString(getUILocale()) })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_c01d962cfc174aa3c779", { arg0: sw.devices.length.toLocaleString(getUILocale()) })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_5afdb17393e2077bd0ae", { arg0: sw.services.length.toLocaleString(getUILocale()) })}
                                    </Typography></Grid>{/* Source Names */}{(sw.sourceNames || []).length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_628c3d91bfc77e12569b", { arg0: (sw.sourceNames || []).length })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(sw.sourceNames || []).map((source) => (
                                          <Chip key={source}
                                            label={source}
                                            size="small"
                                            variant="outlined"
                                            color="secondary"
                                            sx={{ fontSize: '0.75rem' }} />
                                        ))}</Box></Grid>
                                  )}{/* DPI Results */}{(sw.dpiResults || []).length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_e5229abea19522e98c33", { arg0: (sw.dpiResults || []).length })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(sw.dpiResults || []).map((dpi) => (
                                          <Chip key={dpi}
                                            label={dpi}
                                            size="small"
                                            color="success"
                                            sx={{ fontSize: '0.75rem' }} />
                                        ))}</Box></Grid>
                                  )}{/* Detection Context */}{(sw.detectionMethod || sw.confidenceLevel) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_80f1ae784cb4bb10a22b")}>
                                        {i18nText("ui:m_2d20fbb44e8b1ff4a430")}
                                      </Typography>{sw.detectionMethod && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}><Typography variant="body2" color="text.secondary">
                                            {i18nText("ui:m_f65b6a682efcf6a00011")}
                                          </Typography><Chip label={sw.detectionMethod} 
                                            size="small" 
                                            color="info"
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }} /></Box>
                                      )}{sw.confidenceLevel && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Typography variant="body2" color="text.secondary">
                                            {i18nText("ui:m_9e39c37820b4f2602185")}
                                          </Typography><Chip label={sw.confidenceLevel} 
                                            size="small" 
                                            color={sw.confidenceLevel === 'high' ? 'success' : sw.confidenceLevel === 'medium' ? 'warning' : 'default'}
                                            sx={{ fontSize: '0.7rem' }} /></Box>
                                      )}</Grid>
                                  )}{/* Behavior Analysis */}{(sw.behaviorProfile || sw.isHeadless || sw.isEmulated || sw.isAutomated) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_e0bacc620b364128fd48")}>
                                        {i18nText("ui:m_ec92e9aede7efee2e053")}
                                      </Typography>{sw.behaviorProfile && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}><Typography variant="body2" color="text.secondary">
                                            {i18nText("ui:m_02e3c1636994178f9cc0")}
                                          </Typography><Chip label={sw.behaviorProfile} 
                                            size="small" 
                                            color="secondary"
                                            sx={{ fontSize: '0.7rem' }} /></Box>
                                      )}<Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>{sw.isHeadless && (
                                          <Chip label={i18nText("ui:m_c020b32f24904d1f937f")} 
                                            size="small" 
                                            color="warning"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn={i18nText("ui:m_e3bd0d3de4bbb570725d")} />
                                        )}{sw.isEmulated && (
                                          <Chip label={i18nText("ui:m_5370086dd76e38633bc7")} 
                                            size="small" 
                                            color="warning"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn={i18nText("ui:m_54a65ce113d323bd499c")} />
                                        )}{sw.isAutomated && (
                                          <Chip label={i18nText("ui:m_e68afe3e614018fb989b")} 
                                            size="small" 
                                            color="warning"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn={i18nText("ui:m_f050bf7517a514b82d1d")} />
                                        )}</Box></Grid>
                                  )}{/* Security Status */}{(sw.hasKnownVulnerabilities || sw.isEndOfLife || sw.supportStatus) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_7d44914a27928f09e9b9")}>
                                        {i18nText("ui:m_bf87a685277e0e9f1099")}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{sw.hasKnownVulnerabilities && (
                                          <Chip label={i18nText("ui:m_741ba0a6f99c2f2c24f7")} 
                                            size="small" 
                                            color="error"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn={i18nText("ui:m_784242bb2926d075c456")} />
                                        )}{sw.isEndOfLife && (
                                          <Chip label={i18nText("ui:m_3dbaa235603dbf28302a")} 
                                            size="small" 
                                            color="error"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn={i18nText("ui:m_789271e085ffe9d0b267")} />
                                        )}{sw.supportStatus && (
                                          <Chip label={i18nText("ui:m_b44433824ccff93bb4e1", { arg0: sw.supportStatus })} 
                                            size="small" 
                                            color={sw.supportStatus === 'active' ? 'success' : sw.supportStatus === 'maintenance' ? 'warning' : 'error'}
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }} />
                                        )}{!sw.hasKnownVulnerabilities && !sw.isEndOfLife && !sw.supportStatus && (
                                          <Chip label={i18nText("ui:m_0077412bf3fe5b956c0b")} 
                                            size="small" 
                                            color="success"
                                            sx={{ fontSize: '0.7rem' }} />
                                        )}</Box></Grid>
                                  )}<SoftwareEvidence observations={sw.observations} capped={sw.observationsCapped} />{/* Associated Devices */}{(sw.devices || []).length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_532be95c27b2d1d1f8b8", { arg0: (sw.devices || []).length })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(sw.devices || []).map((device) => (
                                          <Chip key={device}
                                            label={device}
                                            size="small"
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }} />
                                        ))}</Box></Grid>
                                  )}{/* Associated Services */}{(sw.services || []).length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_08200ae03ebad3895c80", { arg0: (sw.services || []).length })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(sw.services || []).map((service) => (
                                          <Chip key={service}
                                            label={service}
                                            size="small"
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }} />
                                        ))}</Box></Grid>
                                  )}{/* Community IDs for Cross-Tool Correlation */}{(sw.communityIds || []).length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_ac000b817d4770fd4558")}>
                                        {i18nRichText("ui:m_90788a0b65a00abd64e0", { arg0: (sw.communityIds || []).length })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(sw.communityIds || []).slice(0, 10).map((cid) => (
                                          <CommunityIDChip key={cid} communityId={cid} mode="chip" />
                                        ))}{(sw.communityIds || []).length > 10 && (
                                          <Chip label={i18nText("ui:m_5000f686d6d8f94a73f9", { arg0: (sw.communityIds || []).length - 10 })}
                                            size="small"
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem' }} />
                                        )}</Box></Grid>
                                  )}{/* Action Buttons */}{((sw.devices || []).length > 0 || (sw.flows || []).length > 0) && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nText("ui:m_dc041f79b3881eba84cd")}
                                      </Typography><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>{/* Show Connections button if flows are available */}{(sw.flows || []).length > 0 && (
                                          <Button data-learn={i18nText("ui:m_9fd521249ccf6ffe1652")}
                                            variant="outlined"
                                            color="primary"
                                            startIcon={<CableIcon />}
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              router.push(`/connections?search=${encodeURIComponent(sw.flows[0])}`);
                                            }}
                                            size="small">
                                            {i18nText("ui:m_1d63dcd4ff17dbd7a873")}
                                          </Button>
                                        )}{/* Device-specific buttons */}{(sw.devices || []).map((device) => (
                                          <Button key={device}
                                            data-learn={i18nText("ui:m_889e1b77513c656c48e8")}
                                            variant="outlined"
                                            color="secondary"
                                            startIcon={<CableIcon />}
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              router.push(`/connections?search=${encodeURIComponent(device)}`);
                                            }}
                                            size="small">
                                            {i18nRichText("ui:m_6ba8370895e0b6425308", { arg0: device })}
                                          </Button>
                                        ))}</Box></Grid>
                                  )}</Grid></Box></Collapse></TableCell></TableRow></>
                    );
                  })}</TableBody></Table></TableContainer>} />
        )}</>
        )}</Box></Layout>
  );
}
