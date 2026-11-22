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
  Router as RouterIcon,
  Memory as MemoryIcon,
  Devices as DevicesIcon,
  Business as BusinessIcon,
  TrendingUp as TrendingUpIcon,
  Apps as AppsIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import BehaviorAssetContext from '../components/BehaviorAssetContext';
import ResponsiveDataView from '../components/ResponsiveDataView';
import FileSelectorHeader from '../components/FileSelectorHeader';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';

import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';

import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";




interface DeviceProfileSummary {
  macAddr: string;
  deviceManufacturer: string;
  numDeviceIPs: number;
  numContacts: number;
  numPackets: number;
  bytes: number;
  timestamp: number;  // Unix timestamp in nanoseconds from backend
  applications: string[];
  devices: string[];
  deviceIPs: string[];
  contacts: string[];
  hostnames: string[];
  deviceTypes: string[];
  os: string;
  roles: string[];
}

interface DevicesResponse {
  devices: DeviceProfileSummary[];
  totalCount: number;
}

type DeviceSortField = 'macAddr' | 'manufacturer' | 'packets' | 'bytes' | 'ips' | 'contacts';
type SortOrder = 'asc' | 'desc';

export default function DevicesPage() {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<DeviceSortField>('macAddr');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
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

  // Fetch devices data
  const { data: devicesData, error, mutate } = useSWR<DevicesResponse>(
    'devices',
    () => fetch(`${getBackendUrl()}/api/devices`).then(res => res.json()),
    {
      refreshInterval: 10000,
    }
  );

  const devices = devicesData?.devices || [];
  const totalCount = devicesData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: DeviceSortField) => {
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
  const filteredDevices = useMemo(() => {
    let filtered = devices;

    // Apply search filter with negation support (e.g., "!Apple" excludes Apple devices)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(d =>
        matchesSearchTerms([
          d.macAddr,
          d.deviceManufacturer || '',
          ...(d.devices || []),
          ...(d.applications || []),
        ], searchTerms)
      );
    }

    // Apply sorting
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'macAddr':
          comparison = a.macAddr.localeCompare(b.macAddr);
          break;
        case 'manufacturer':
          comparison = (a.deviceManufacturer || '').localeCompare(b.deviceManufacturer || '');
          break;
        case 'packets':
          comparison = a.numPackets - b.numPackets;
          break;
        case 'bytes':
          comparison = a.bytes - b.bytes;
          break;
        case 'ips':
          comparison = a.numDeviceIPs - b.numDeviceIPs;
          break;
        case 'contacts':
          comparison = a.numContacts - b.numContacts;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [devices, searchQuery, sortField, sortOrder]);

  // Paginate devices
  const paginatedDevices = filteredDevices.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedDevices.map(device => device.macAddr),
    [paginatedDevices]
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

  const handleRowClick = useCallback((macAddr: string) => {
    setExpandedRow(prev => prev === macAddr ? null : macAddr);
  }, []);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_f1863b3c3bacda3ec758")} />
  );

  if (error) {
    return (
      <Layout title={i18nText("ui:m_96f53788dbcf443fbaab")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_fe54b159bf70335806ad", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_96f53788dbcf443fbaab")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
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
        <StatBoxGrid><StatBox icon={<RouterIcon color="primary" />}
            label={i18nText("ui:m_0a8abb79ee6193edf6b5")}
            value={totalCount} /><StatBox icon={<BusinessIcon color="success" />}
            label={i18nText("ui:m_b77b562e0f6a4048e15a")}
            value={new Set(devices.map(d => d.deviceManufacturer).filter(m => m)).size} /><StatBox icon={<MemoryIcon color="warning" />}
            label={i18nText("ui:m_69c9a62452b99a53fb02")}
            value={new Set(devices.flatMap(d => d.devices || [])).size} /><StatBox icon={<TrendingUpIcon color="info" />}
            label={i18nText("ui:m_5d5e198526c29a315aa1")}
            value={formatBytes(devices.reduce((sum, d) => sum + d.bytes, 0))} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`mac-vendors-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/mac-vendors`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_f2645fd4d28e89f8b2ba")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`traffic-dist-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/traffic-distribution?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_775f4934528e066879c8")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`hardware-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/hardware`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_117d805bce13aeec3616")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`operating-systems-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/operating-systems?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_52b71f6b027713d3cd43")} /></CardContent></Card></Grid><Grid item xs={12}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`applications-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/devices/applications`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_ae0a28dbe2f164151ca0")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_b9173ff2687da4055991")}
            learnHint={translate("ui:m_8851ac395a83baf2fc57")} /><Button data-learn={i18nText("ui:m_50d5b84bd067aff6f67d")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_699cda34964d8f0624de", { arg0: filteredDevices.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Devices Table */}{!devicesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><RouterIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_5987762487740bdfb7db")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_32685d03055b807acd4f")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedDevices}
            totalCount={filteredDevices.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(device) => handleRowClick(device.macAddr)}
            renderCard={(device) => (
              <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>{device.macAddr}</Typography>{device.deviceManufacturer && (
                    <Typography variant="caption" color="text.secondary" display="block">{device.deviceManufacturer}</Typography>
                  )}<Box display="flex" gap={2} mt={0.5} flexWrap="wrap"><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_9a343c2d3b0d6ef0ef21", { arg0: device.numPackets.toLocaleString(getUILocale()) })}
                    </Typography><Typography variant="caption" color="text.secondary">{formatBytes(device.bytes)}</Typography><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_739c958f09bc01cf5662", { arg0: device.numDeviceIPs })}
                    </Typography></Box>{device.os && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                      {i18nRichText("ui:m_8136a09648ef4af1f7b6", { arg0: device.os })}
                    </Typography>
                  )}{(device.devices || []).length > 0 && (
                    <Typography variant="caption" color="text.secondary" display="block" mt={0.5} noWrap>
                      {i18nRichText("ui:m_be6c76a26ea2a83a1d1a", { arg0: (device.devices || []).slice(0, 2).join(', '), arg1: (device.devices || []).length > 2 ? ` +${(device.devices || []).length - 2}` : '' })}
                    </Typography>
                  )}</CardContent></Card>
            )}
            desktopTable={<TableContainer component={Paper}><Table size="small"><TableHead><TableRow><TableCell width={40}></TableCell><TableCell><TableSortLabel active={sortField === 'macAddr'}
                        direction={sortField === 'macAddr' ? sortOrder : 'asc'}
                        onClick={() => handleSort('macAddr')}>
                        {i18nText("ui:m_ecc722f7539979fed8c0")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel active={sortField === 'manufacturer'}
                        direction={sortField === 'manufacturer' ? sortOrder : 'asc'}
                        onClick={() => handleSort('manufacturer')}>
                        {i18nText("ui:m_77701993fd2ad409fed9")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel active={sortField === 'packets'}
                        direction={sortField === 'packets' ? sortOrder : 'asc'}
                        onClick={() => handleSort('packets')}>
                        {i18nText("ui:m_ebe2f7ca86cd1049725b")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel active={sortField === 'bytes'}
                        direction={sortField === 'bytes' ? sortOrder : 'asc'}
                        onClick={() => handleSort('bytes')}>
                        {i18nText("ui:m_dc58fb07f5e14e63a67b")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel active={sortField === 'ips'}
                        direction={sortField === 'ips' ? sortOrder : 'asc'}
                        onClick={() => handleSort('ips')}>
                        {i18nText("ui:m_e4230c024091bbffc7ac")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel active={sortField === 'contacts'}
                        direction={sortField === 'contacts' ? sortOrder : 'asc'}
                        onClick={() => handleSort('contacts')}>
                        {i18nText("ui:m_37b96a6801cf532b1a0a")}
                      </TableSortLabel></TableCell><TableCell>{i18nText("ui:m_69c9a62452b99a53fb02")}</TableCell><TableCell>{i18nText("ui:m_22e33af3cdbf3a8a93d6")}</TableCell></TableRow></TableHead><TableBody>{paginatedDevices.map((device) => (
                    <><TableRow key={device.macAddr}
                        data-row-key={device.macAddr}
                        hover
                        onClick={() => handleRowClick(device.macAddr)}
                        sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                        data-learn={i18nText("ui:m_d18c94c80840477f0ca0")}><TableCell><IconButton size="small"><ExpandMoreIcon sx={{ 
                                transform: expandedRow === device.macAddr ? 'rotate(180deg)' : 'rotate(0deg)',
                                transition: 'transform 0.3s'
                              }} /></IconButton></TableCell><TableCell><Typography sx={{ 
                              fontFamily: 'monospace', 
                              fontSize: '0.875rem',
                              fontWeight: 'medium'
                            }}>{device.macAddr}</Typography></TableCell><TableCell>{device.deviceManufacturer ? (
                            <Chip label={device.deviceManufacturer}
                              size="small"
                              color="primary"
                              sx={{ fontSize: '0.7rem' }} />
                          ) : (
                            <Typography variant="body2" color="text.secondary">
                              {i18nText("ui:m_2f1ac5f44673922d2bf2")}
                            </Typography>
                          )}</TableCell><TableCell align="right"><Typography variant="body2">{device.numPackets.toLocaleString(getUILocale())}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{formatBytes(device.bytes)}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{device.numDeviceIPs}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{device.numContacts}</Typography></TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.devices || []).slice(0, 2).map((dev) => (
                              <Chip key={dev}
                                label={dev}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }} />
                            ))}{(device.devices || []).length > 2 && (
                              <Chip label={`+${(device.devices || []).length - 2}`}
                                size="small"
                                variant="outlined"
                                sx={{ fontSize: '0.7rem', height: 20 }} />
                            )}</Box></TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.applications || []).slice(0, 2).map((app) => (
                              <Chip key={app}
                                label={app}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }} />
                            ))}{(device.applications || []).length > 2 && (
                              <Chip label={`+${(device.applications || []).length - 2}`}
                                size="small"
                                color="info"
                                sx={{ fontSize: '0.7rem', height: 20 }} />
                            )}</Box></TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={9}><Collapse in={expandedRow === device.macAddr} timeout="auto" unmountOnExit><BehaviorAssetContext asset={device.macAddr} /><Button variant="outlined" size="small" onClick={(event) => { event.stopPropagation(); router.push(`/behavior?asset=${encodeURIComponent(device.macAddr)}`); }}>{i18nText("ui:m_4b749c052140e836b8d2")}</Button><Box sx={{ py: 2 }}><Grid container spacing={2}>{/* Time Info */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                    {i18nText("ui:m_e7368473dd089d37c0a2")}
                                  </Typography><Typography variant="body2" color="text.secondary">{formatTimestamp(device.timestamp, 'nanoseconds')}</Typography></Grid>{/* Statistics */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                    {i18nText("ui:m_893be24c31571dda650e")}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_94ab2e0e70b26bb01a5b", { arg0: device.numPackets.toLocaleString(getUILocale()) })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_1386c34f5f9ed210a2f5", { arg0: formatBytes(device.bytes) })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_e3958a7aece74413b671", { arg0: device.numDeviceIPs })}
                                  </Typography><Typography variant="body2" color="text.secondary">
                                    {i18nRichText("ui:m_bc89f08dd19c1280e87a", { arg0: device.numContacts })}
                                  </Typography></Grid>{/* Network Discovery: Hostnames */}{(device.hostnames || []).length > 0 && (
                                  <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_4951faf85a01bba7ee2c")}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.hostnames || []).map((h) => (
                                        <Chip key={h}
                                          label={h}
                                          size="small"
                                          color="primary"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }} />
                                      ))}</Box></Grid>
                                )}{/* Network Discovery: OS */}{device.os && (
                                  <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_c3bb5b758d2559cabbb7")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>{device.os}</Typography></Grid>
                                )}{/* Network Discovery: Device Types */}{(device.deviceTypes || []).length > 0 && (
                                  <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_39fd739eaae2d0c0ddd6")}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.deviceTypes || []).map((dt) => (
                                        <Chip key={dt}
                                          label={dt}
                                          size="small"
                                          color="warning"
                                          sx={{ fontSize: '0.75rem' }} />
                                      ))}</Box></Grid>
                                )}{/* Network Discovery: Roles */}{(device.roles || []).length > 0 && (
                                  <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_7b43c8abc127253b7ad8")}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.roles || []).map((r) => (
                                        <Chip key={r}
                                          label={r}
                                          size="small"
                                          color="secondary"
                                          sx={{ fontSize: '0.75rem' }} />
                                      ))}</Box></Grid>
                                )}{/* All Device IPs */}{(device.deviceIPs || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nRichText("ui:m_5a89d0200c968fbac147", { arg0: (device.deviceIPs || []).length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.deviceIPs || []).map((ip) => (
                                        <Chip key={ip}
                                          label={ip}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }} />
                                      ))}</Box></Grid>
                                )}{/* All Device Types */}{(device.devices || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nRichText("ui:m_895a92afe836d497a26e", { arg0: (device.devices || []).length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.devices || []).map((dev) => (
                                        <Chip key={dev}
                                          label={dev}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.75rem' }} />
                                      ))}</Box></Grid>
                                )}{/* All Applications */}{(device.applications || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nRichText("ui:m_1e513bd0c1ce7dbe8342", { arg0: (device.applications || []).length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.applications || []).map((app) => (
                                        <Chip key={app}
                                          label={app}
                                          size="small"
                                          color="info"
                                          sx={{ fontSize: '0.75rem' }} />
                                      ))}</Box></Grid>
                                )}{/* Contacted IPs (top 20) */}{(device.contacts || []).length > 0 && (
                                  <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                      {i18nRichText("ui:m_fb6907c8bb15fba8fbe8", { arg0: (device.contacts || []).length })}
                                    </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(device.contacts || []).slice(0, 20).map((contact) => (
                                        <Chip key={contact}
                                          label={contact}
                                          size="small"
                                          variant="outlined"
                                          color="secondary"
                                          sx={{ fontSize: '0.7rem', fontFamily: 'monospace' }} />
                                      ))}{(device.contacts || []).length > 20 && (
                                        <Chip label={i18nText("ui:m_5000f686d6d8f94a73f9", { arg0: (device.contacts || []).length - 20 })}
                                          size="small"
                                          variant="outlined"
                                          sx={{ fontSize: '0.7rem' }} />
                                      )}</Box></Grid>
                                )}</Grid></Box></Collapse></TableCell></TableRow></>
                  ))}</TableBody></Table></TableContainer>} />
        )}</>
        )}</Box></Layout>
  );
}
