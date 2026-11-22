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

import { useState, useMemo, useEffect, useCallback } from 'react';
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
  Public as GeoIcon,
  Devices as DevicesIcon,
  Security as SecurityIcon,
  Language as LanguageIcon,
  LocalOffer as TagIcon,
  TrendingUp as TrendingUpIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Download as DownloadIcon,
  Cable as CableIcon,
  FilterAlt as FilterAltIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import BehaviorAssetContext from '../components/BehaviorAssetContext';
import HostIdentity, { type HostIdentityData } from '../components/HostIdentity';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import SearchInput from '../components/SearchInput';
import MobileFilterSheet from '../components/MobileFilterSheet';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';

import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode, useIsMobile } from '../hooks';

import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { message, displayError, renderError, translate } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";




interface ProtocolInfo {
  name: string;
  packets: number;
  category: string;
}

interface PortInfo {
  port: number;
  protocol: string;
  packets: number;
  bytes: number;
}

export interface HostSummary {
  addr: string;
  numPackets: number;
  bytes: number;
  geolocation: string;
  dnsNames: string[];
  timestampFirst: number;
  timestampLast: number;
  applications: string[];
  ja3Hashes: Record<string, string>;
  protocolsCount: number;
  snisCount: number;
  srcPortsCount: number;
  dstPortsCount: number;
  contactedPortsCount: number;
  ja3FingerprintMatches: string[];
  ja3sFingerprintMatches: string[];
  topProtocols: ProtocolInfo[];
  topSrcPorts: PortInfo[];
  topDstPorts: PortInfo[];
  topContactedPorts: PortInfo[];
  isInternal: boolean;
}

interface HostsResponse {
	hosts: HostSummary[];
	totalCount: number;
	identity?: HostIdentityData;
}

type HostSortField = 'addr' | 'type' | 'packets' | 'bytes';
type SortOrder = 'asc' | 'desc';

export interface HostsPageProps {
  /** Custom row actions to render in the expanded row details */
  rowActions?: (row: HostSummary) => React.ReactNode;
}

export default function HostsPage({ rowActions }: HostsPageProps = {}) {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'internal' | 'external'>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<HostSortField>('addr');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const [viewMode, setViewMode] = useViewMode();
  const [filterSheetOpen, setFilterSheetOpen] = useState(false);
  const isMobile = useIsMobile();

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

  // Fetch hosts data
  const { data: hostsData, error, mutate } = useSWR<HostsResponse>(
    'hosts',
    () => fetch(`${getBackendUrl()}/api/hosts`).then(res => {
      if (!res.ok) throw displayError(message("ui:m_762097b766ebd882235c"));
      return res.json();
    }),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const hosts = hostsData?.hosts || [];
  const totalCount = hostsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: HostSortField) => {
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
  const filteredHosts = useMemo(() => {
    let filtered = hosts;

    // Apply type filter
    if (filterType === 'internal') {
      filtered = filtered.filter(h => h.isInternal);
    } else if (filterType === 'external') {
      filtered = filtered.filter(h => !h.isInternal);
    }

    // Apply search filter with negation support (e.g., "!192.168" excludes internal IPs)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(h =>
        matchesSearchTerms([
          h.addr,
          ...(h.dnsNames || []),
          h.geolocation || '',
          ...(h.applications || []),
        ], searchTerms)
      );
    }

    // Apply sorting with stable secondary sort by address
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'addr':
          comparison = a.addr.localeCompare(b.addr);
          break;
        case 'type':
          // Sort internal first (true > false), then by address
          if (a.isInternal === b.isInternal) {
            comparison = a.addr.localeCompare(b.addr);
          } else {
            comparison = a.isInternal ? -1 : 1;
          }
          break;
        case 'packets':
          comparison = a.numPackets - b.numPackets;
          break;
        case 'bytes':
          comparison = a.bytes - b.bytes;
          break;
      }
      // Stable secondary sort by address for consistent ordering
      if (comparison === 0) {
        comparison = a.addr.localeCompare(b.addr);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [hosts, filterType, searchQuery, sortField, sortOrder]);

  // Paginate hosts
  const paginatedHosts = filteredHosts.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedHosts.map(host => host.addr),
    [paginatedHosts]
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

  const handleRowClick = useCallback((addr: string) => {
    setExpandedRow(prev => prev === addr ? null : addr);
  }, []);

  const handleDownloadPCAP = useCallback(async (host: HostSummary) => {
    try {
      // Generate download URL with host IP filter
      const params = new URLSearchParams({
        host: host.addr,
      });
      const downloadUrl = `${getBackendUrl()}/api/hosts/download-pcap?${params}`;
      
      // Fetch the file as a blob
      const response = await fetch(downloadUrl);
      
      if (!response.ok) {
        const errorText = await response.text();
        alert(i18nText("ui:m_c63b36b2fde6b1f5d69c", { arg0: errorText }));
        return;
      }
      
      // Get the blob and create a download link
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      
      // Create a temporary anchor element and trigger download
      const a = document.createElement('a');
      a.href = url;
      a.download = `host_${host.addr.replace(/[:.]/g, '_')}.pcap`;
      document.body.appendChild(a);
      a.click();
      
      // Cleanup
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
      alert(i18nText("ui:m_c63b36b2fde6b1f5d69c", { arg0: error }));
    }
  }, [__uiLocale]);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_21be31af050e9ab11ee9")} />
  );

  if (error) {
    return (
      <Layout title={i18nText("ui:m_74ae2e341e215c830a8f")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_e3444e449887083c6135", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_74ae2e341e215c830a8f")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
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
        <StatBoxGrid><StatBox icon={<DevicesIcon color="primary" />}
            label={i18nText("ui:m_7b8e6ed82dbeffc8857c")}
            value={totalCount} /><StatBox icon={<SecurityIcon color="success" />}
            label={i18nText("ui:m_43a3c5eafc34b423a61e")}
            value={hosts.filter(h => h.isInternal).length}
            onClick={() => {
              setFilterType(filterType === 'internal' ? 'all' : 'internal');
              setPage(0);
            }}
            isActive={filterType === 'internal'}
            activeColor="success"
            activeText={translate("ui:m_f548bf230e66fd5ff76d")}
            learnHint={translate("ui:m_635567d2033ff19874e4")} /><StatBox icon={<LanguageIcon color="warning" />}
            label={i18nText("ui:m_127e72570f838af976a7")}
            value={hosts.filter(h => !h.isInternal).length}
            onClick={() => {
              setFilterType(filterType === 'external' ? 'all' : 'external');
              setPage(0);
            }}
            isActive={filterType === 'external'}
            activeColor="warning"
            activeText={translate("ui:m_f548bf230e66fd5ff76d")}
            learnHint={translate("ui:m_b9da3193234b134c912d")} /><StatBox icon={<TrendingUpIcon color="info" />}
            label={i18nText("ui:m_5d5e198526c29a315aa1")}
            value={formatBytes(hosts.reduce((sum, h) => sum + h.bytes, 0))} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`top-talkers-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/hosts/top-talkers`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_1f8fe89d141bd9c767a0")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`traffic-dist-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/hosts/traffic-distribution?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_775f4934528e066879c8")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`applications-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/hosts/applications`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_ae0a28dbe2f164151ca0")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`protocols-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/hosts/protocols?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_482e3d02454bb91d5c35")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <>{isMobile ? (
          <><Box sx={{ mb: 2, display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}><Chip icon={<FilterAltIcon />}
                label={i18nText("ui:m_5bac756d6be369f36626", { arg0: (searchQuery || filterType !== 'all') ? ` (${(searchQuery ? 1 : 0) + (filterType !== 'all' ? 1 : 0)})` : '' })}
                onClick={() => setFilterSheetOpen(true)}
                variant="outlined" /><IconButton onClick={handleRefresh} size="small"><RefreshIcon /></IconButton>{searchQuery || filterType !== 'all' ? (
                <Typography variant="body2" color="text.secondary">
                  {i18nRichText("ui:m_95c3b7a0055bd8af66bf", { arg0: filteredHosts.length, arg1: totalCount })}
                </Typography>
              ) : null}</Box><MobileFilterSheet open={filterSheetOpen}
              onOpen={() => setFilterSheetOpen(true)}
              onClose={() => setFilterSheetOpen(false)}><SearchInput value={searchQuery}
                onChange={(value) => {
                  setSearchQuery(value);
                  setPage(0);
                }}
                placeholder={i18nText("ui:m_544180d1cfcaab7f1db1")}
                learnHint={translate("ui:m_701aac13656e76525243")} /><FormControl size="small" fullWidth><Select data-learn={i18nText("ui:m_2d795686fe60f607dfb3")}
                  value={filterType}
                  onChange={(e) => {
                    setFilterType(e.target.value as 'all' | 'internal' | 'external');
                    setPage(0);
                  }}><MenuItem value="all">{i18nText("ui:m_81c588908b4b314d3b8b")}</MenuItem><MenuItem value="internal">{i18nText("ui:m_9f9a664b128f44d3b09d")}</MenuItem><MenuItem value="external">{i18nText("ui:m_c7657cb5faaa4a68e3ba")}</MenuItem></Select></FormControl></MobileFilterSheet></>
        ) : (
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_544180d1cfcaab7f1db1")}
            learnHint={translate("ui:m_701aac13656e76525243")} /><FormControl size="small" sx={{ minWidth: 150 }}><Select data-learn={i18nText("ui:m_2d795686fe60f607dfb3")}
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as 'all' | 'internal' | 'external');
                setPage(0);
              }}><MenuItem value="all">{i18nText("ui:m_81c588908b4b314d3b8b")}</MenuItem><MenuItem value="internal">{i18nText("ui:m_9f9a664b128f44d3b09d")}</MenuItem><MenuItem value="external">{i18nText("ui:m_c7657cb5faaa4a68e3ba")}</MenuItem></Select></FormControl><Button data-learn={i18nText("ui:m_7d366c424bb6c20e8ca3")}
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{searchQuery || filterType !== 'all' ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_95c3b7a0055bd8af66bf", { arg0: filteredHosts.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>
        )}{/* Hosts Table */}{!hostsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><DevicesIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_4e000f77467708498990")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_782a88523e27be8505fb")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedHosts}
            totalCount={filteredHosts.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(host) => handleRowClick(host.addr)}
            renderCard={(host) => (
              <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>{host.addr}</Typography><Box display="flex" gap={2} mt={0.5} flexWrap="wrap"><Typography variant="caption" color="text.secondary">{host.isInternal ? i18nText("ui:m_7da5b7a2192404a9e9c2") : i18nText("ui:m_c711a1ab4dd36a7ab798")}</Typography><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_9a343c2d3b0d6ef0ef21", { arg0: host.numPackets?.toLocaleString(getUILocale()) })}
                    </Typography><Typography variant="caption" color="text.secondary">{formatBytes(host.bytes)}</Typography></Box>{host.geolocation && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>{host.geolocation}</Typography>
                  )}{host.dnsNames && host.dnsNames.length > 0 && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5} noWrap>{host.dnsNames.slice(0, 2).join(', ')}{host.dnsNames.length > 2 ? ` +${host.dnsNames.length - 2}` : ''}</Typography>
                  )}</CardContent></Card>
            )}
            desktopTable={<TableContainer component={Paper}><Table size="small"><TableHead><TableRow><TableCell width={40}></TableCell><TableCell><TableSortLabel active={sortField === 'addr'}
                        direction={sortField === 'addr' ? sortOrder : 'asc'}
                        onClick={() => handleSort('addr')}>
                        {i18nText("ui:m_7bcf5a662fd0c3e8f3c2")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel active={sortField === 'type'}
                        direction={sortField === 'type' ? sortOrder : 'asc'}
                        onClick={() => handleSort('type')}>
                        {i18nText("ui:m_3da346bd3b7d84ce65d6")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel active={sortField === 'packets'}
                        direction={sortField === 'packets' ? sortOrder : 'asc'}
                        onClick={() => handleSort('packets')}>
                        {i18nText("ui:m_ebe2f7ca86cd1049725b")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel active={sortField === 'bytes'}
                        direction={sortField === 'bytes' ? sortOrder : 'asc'}
                        onClick={() => handleSort('bytes')}>
                        {i18nText("ui:m_dc58fb07f5e14e63a67b")}
                      </TableSortLabel></TableCell><TableCell>{i18nText("ui:m_1d8ac19cda6dcf0bb752")}</TableCell><TableCell>{i18nText("ui:m_91957f0118074e259daf")}</TableCell><TableCell>{i18nText("ui:m_22e33af3cdbf3a8a93d6")}</TableCell></TableRow></TableHead><TableBody>{paginatedHosts.map((host) => (
                    <><TableRow key={host.addr}
                        data-row-key={host.addr}
                        hover
                        onClick={() => handleRowClick(host.addr)}
                        sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                        data-learn={i18nText("ui:m_d0fcb9142842eb46c497")}><TableCell><IconButton size="small"><ExpandMoreIcon sx={{
                                transform: expandedRow === host.addr ? 'rotate(180deg)' : 'rotate(0deg)',
                                transition: 'transform 0.3s'
                              }} /></IconButton></TableCell><TableCell><Typography sx={{
                              fontFamily: 'monospace',
                              fontSize: '0.875rem',
                              fontWeight: 'medium'
                            }}>{host.addr}</Typography></TableCell><TableCell><Chip label={host.isInternal ? i18nText("ui:m_7da5b7a2192404a9e9c2") : i18nText("ui:m_c711a1ab4dd36a7ab798")}
                            size="small"
                            color={host.isInternal ? 'success' : 'warning'}
                            sx={{ fontSize: '0.7rem' }} /></TableCell><TableCell align="right"><Typography variant="body2">{host.numPackets.toLocaleString(getUILocale())}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{formatBytes(host.bytes)}</Typography></TableCell><TableCell>{host.geolocation && (
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}><GeoIcon fontSize="small" color="action" /><Typography variant="body2">{host.geolocation}</Typography></Box>
                          )}</TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(host.dnsNames || []).slice(0, 2).map((name) => (
                              <Chip key={name}
                                label={name}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }} />
                            ))}{(host.dnsNames || []).length > 2 && (
                              <Chip label={`+${(host.dnsNames || []).length - 2}`}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }} />
                            )}</Box></TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(host.applications || []).slice(0, 2).map((app) => (
                              <Chip key={app}
                                label={app}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }} />
                            ))}{(host.applications || []).length > 2 && (
                              <Chip label={`+${(host.applications || []).length - 2}`}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }} />
                            )}</Box></TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={8}><Collapse in={expandedRow === host.addr} timeout="auto" unmountOnExit><BehaviorAssetContext asset={host.addr} /><Box sx={{ py: 2 }}>{/* Action Buttons */}<Box sx={{ mb: 2, display: 'flex', justifyContent: 'flex-end', gap: 1, flexWrap: 'wrap' }}><Button variant="outlined" size="small" onClick={(event) => { event.stopPropagation(); router.push(`/behavior?asset=${encodeURIComponent(host.addr)}`); }}>{i18nText("ui:m_4b749c052140e836b8d2")}</Button><Button data-learn={i18nText("ui:m_fc2ff0ed2d430c91380c")}
                                  variant="outlined"
                                  size="small"
                                  startIcon={<CableIcon />}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    router.push(`/connections?search=${encodeURIComponent(host.addr)}`);
                                  }}>
                                  {i18nText("ui:m_1d63dcd4ff17dbd7a873")}
                                </Button><Button data-learn={i18nText("ui:m_64b1fb954822e1cbdb7b")}
                                  variant="outlined"
                                  size="small"
                                  startIcon={<DownloadIcon />}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleDownloadPCAP(host);
                                  }}>
                                  {i18nText("ui:m_c2c52203522b7dc5d8e4")}
                                </Button>{/* Custom row actions from parent */}{rowActions && rowActions(host)}</Box><HostIdentity identity={hostsData?.identity} ip={host.addr} /><Grid container spacing={2}>{/* Time Range */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                    {i18nText("ui:m_4d5b7908dabae92d8fae")}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_15d5e1f7d677437722bf", { arg0: formatTimestamp(host.timestampFirst, 'nanoseconds') })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_0f8d6be8cc3baa6c1c17", { arg0: formatTimestamp(host.timestampLast, 'nanoseconds') })}
                                  </Typography></Grid>{/* Statistics */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                    {i18nText("ui:m_893be24c31571dda650e")}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_02dfdc04186663dd97ec", { arg0: host.protocolsCount })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_22cb68fcbcb3138e692a", { arg0: host.srcPortsCount })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_70fd97dde33ead23b7d7", { arg0: host.dstPortsCount })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_be573b7ba1a7ee00e602", { arg0: host.contactedPortsCount })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_b91947fc569cbe1cb7e5", { arg0: host.snisCount })}
                                  </Typography></Grid>{/* Top Protocols */}{(host.topProtocols || []).length > 0 && (
                                  <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_639756a3e2b9ef0e6613")}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(host.topProtocols || []).map((proto) => (
                                        <Tooltip key={proto.name}
                                          title={i18nText("ui:m_cd25af6528329eae6eb8", { arg0: proto.packets, arg1: proto.category })}><Chip label={proto.name}
                                            size="small"
                                            variant="outlined"
                                            sx={{ fontSize: '0.75rem' }} /></Tooltip>
                                      ))}</Box></Grid>
                                )}{/* Top Contacted Ports */}{(host.topContactedPorts || []).length > 0 && (
                                  <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_90b6702d8d32f866ac9e")}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(host.topContactedPorts || []).map((port) => (
                                        <Tooltip key={`${port.port}-${port.packets}`}
                                          title={i18nText("ui:m_9f84c73616966f0f5554", { arg0: port.packets, arg1: formatBytes(port.bytes) })}><Chip label={`${port.port}/${port.protocol}`}
                                            size="small"
                                            variant="outlined"
                                            color="primary"
                                            sx={{ fontSize: '0.75rem' }} /></Tooltip>
                                      ))}</Box></Grid>
                                )}{/* All DNS Names */}{(host.dnsNames || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nRichText("ui:m_2527df7a85b633a1ff20", { arg0: (host.dnsNames || []).length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(host.dnsNames || []).map((name) => (
                                        <Chip key={name}
                                          label={name}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }} />
                                      ))}</Box></Grid>
                                )}{/* All Applications */}{(host.applications || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nRichText("ui:m_1e513bd0c1ce7dbe8342", { arg0: (host.applications || []).length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(host.applications || []).map((app) => (
                                        <Chip key={app}
                                          label={app}
                                          size="small"
                                          color="info"
                                          sx={{ fontSize: '0.75rem' }} />
                                      ))}</Box></Grid>
                                )}{/* JA3 Fingerprints */}{((host.ja3FingerprintMatches || []).length > 0 || (host.ja3sFingerprintMatches || []).length > 0) && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_f24ee8e5d3f110cc4258")}
                                    </Typography>{(host.ja3FingerprintMatches || []).length > 0 && (
                                      <Box sx={{ mb: 1 }}><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                          {i18nText("ui:m_2b05480af0603a5fd210")}
                                        </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(host.ja3FingerprintMatches || []).map((match) => (
                                            <Chip key={match}
                                              label={match}
                                              size="small"
                                              variant="outlined"
                                              color="secondary"
                                              sx={{ fontSize: '0.7rem' }} />
                                          ))}</Box></Box>
                                    )}{(host.ja3sFingerprintMatches || []).length > 0 && (
                                      <Box><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                          {i18nText("ui:m_ba6dd8db7b2c083da956")}
                                        </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(host.ja3sFingerprintMatches || []).map((match) => (
                                            <Chip key={match}
                                              label={match}
                                              size="small"
                                              variant="outlined"
                                              color="secondary"
                                              sx={{ fontSize: '0.7rem' }} />
                                          ))}</Box></Box>
                                    )}</Grid>
                                )}</Grid></Box></Collapse></TableCell></TableRow></>
                  ))}</TableBody></Table></TableContainer>} />
        )}</>
        )}</Box></Layout>
  );
}
