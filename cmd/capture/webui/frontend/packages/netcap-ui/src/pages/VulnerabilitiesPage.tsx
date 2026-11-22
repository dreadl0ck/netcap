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

import { useState, useMemo, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
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
  Tabs,
  Tab,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  BugReport as BugReportIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Computer as ComputerIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Apps as AppsIcon,
  OpenInNew as OpenInNewIcon,
  Cable as CableIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import SearchInput from '../components/SearchInput';
import ResponsiveDataView from '../components/ResponsiveDataView';
import VulnerabilityReferences, { type VulnerabilityReference } from '../components/VulnerabilityReferences';
import VulnerabilityKEV, { type KEVStatus } from '../components/VulnerabilityKEV';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { getBackendUrl } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';

import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";




interface SoftwareInfo {
  product: string;
  vendor: string;
  version: string;
  flows: string[];
  communityIds: string[]; // Community IDs for cross-tool correlation
}

interface VulnerabilitySummary {
  id: string;
  description: string;
  severity: string;
  v2Score: string;
  accessVector: string;
  versions: string[];
  count: number;
  software: SoftwareInfo | null;
  affected: number;
  references?: VulnerabilityReference[];
  kev?: KEVStatus;
  communityIds: string[]; // Community IDs for cross-tool correlation
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
  software: SoftwareInfo | null;
  affected: number;
  communityIds: string[]; // Community IDs for cross-tool correlation
}

interface HostVulnerabilitySummary {
  host: string;
  vulnerabilities: number;
  exploits: number;
  topSeverity: string;
  softwareCount: number;
}

interface VulnerabilitiesResponse {
  kevStatus?: 'available' | 'unavailable' | 'invalid-or-stale';
  vulnerabilities: VulnerabilitySummary[];
  exploits: ExploitSummary[];
  affectedHosts: HostVulnerabilitySummary[];
  totalVulns: number;
  totalExploits: number;
}

type SortOrder = 'asc' | 'desc';

export default function VulnerabilitiesPage() {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<string>('count');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();

  // Fetch status and input files
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  const communityIds = useMemo(
    () => isCommunityIDFilterActive ? Array.from(selectedCommunityIDs).sort() : [],
    [isCommunityIDFilterActive, selectedCommunityIDs]
  );

  // Fetch only the matching findings when the cross-page filter is active.
  const { data: vulnerabilitiesData, error, mutate } = useSWR<VulnerabilitiesResponse>(
    ['vulnerabilities', communityIds],
    () => {
      const params = new URLSearchParams();
      communityIds.forEach(id => params.append('communityId', id));
      return fetch(`${getBackendUrl()}/api/vulnerabilities?${params}`).then(res => res.json());
    },
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
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let data: any[] = [];
    if (tabValue === 0) data = vulnerabilities;
    else if (tabValue === 1) data = exploits;
    else data = affectedHosts;

    // Apply Community ID filter first (if active) - only for vulnerabilities and exploits tabs
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0 && (tabValue === 0 || tabValue === 1)) {
      data = data.filter((item: VulnerabilitySummary | ExploitSummary) => 
        item.communityIds && item.communityIds.some(cid => selectedCommunityIDs.has(cid))
      );
    } else if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0 && tabValue === 2) {
      // For affected hosts tab, return empty as hosts don't have community IDs
      return [];
    }

    // Apply search filter with negation support (e.g., "!HIGH" excludes high severity)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      data = data.filter((item: any) => 
        matchesSearchTerms([
          item.id || '',
          item.description || '',
          item.software?.product || '',
          item.host || '',
          item.severity || '',
        ], searchTerms)
      );
    }

    // Sorting with stable secondary sort by id or host
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
      // Stable secondary sort by id or host for consistent ordering
      if (comparison === 0) {
        const idA = a.id || a.host || '';
        const idB = b.id || b.host || '';
        comparison = idA.localeCompare(idB);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return data;
  }, [vulnerabilities, exploits, affectedHosts, tabValue, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs]);

  const paginatedData = filteredData.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation (only for tabs 0 and 1 which have expandable rows)
  const rowKeys = useMemo(() => {
    if (tabValue === 2) return []; // Tab 2 doesn't have expandable rows
    return paginatedData.map((row: any) => 
      tabValue === 0 ? row.id : tabValue === 1 ? row.id : row.host
    );
  }, [paginatedData, tabValue]);

  // Enable keyboard navigation for detail views (UP/DOWN arrows)
  useTableKeyboardNavigation(expandedRow, rowKeys, setExpandedRow);

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
      alert(i18nText("ui:m_7ab800e4d59917b1d34c"));
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate, __uiLocale]);

  const handleRowClick = useCallback((key: string) => {
    setExpandedRow(prev => prev === key ? null : key);
  }, []);

  const handleHostClick = useCallback((host: string) => {
    router.push(`/hosts?search=${encodeURIComponent(host)}`);
  }, [router]);

  const handleSoftwareClick = useCallback((software: string) => {
    router.push(`/software?search=${encodeURIComponent(software)}`);
  }, [router]);

  // Helper function to get display name for software
  const getSoftwareDisplayName = useCallback((software: SoftwareInfo | null | undefined): string => {
    if (!software) return 'N/A';
    
    // Prefer Product, fall back to Vendor
    const name = software.product || software.vendor || 'N/A';
    
    // Add version if available
    if (software.version && name !== 'N/A') {
      return `${name} ${software.version}`;
    }
    
    return name;
  }, []);

  // Helper function to get search term for software (for navigation)
  const getSoftwareSearchTerm = useCallback((software: SoftwareInfo | null | undefined): string => {
    if (!software) return '';
    return software.product || software.vendor || '';
  }, []);

  const handleViewAffectedHosts = useCallback(() => {
    setTabValue(2); // Switch to Affected Hosts tab
    setExpandedRow(null); // Close expanded row
  }, []);

  const handleViewConnections = useCallback((software: string) => {
    router.push(`/connections?search=${encodeURIComponent(software)}`);
  }, [router]);

  const handleViewConnectionsByFlow = useCallback((flows: string[]) => {
    if (flows && flows.length > 0) {
      // Use the first flow to search on the connections page
      router.push(`/connections?search=${encodeURIComponent(flows[0])}`);
    }
  }, [router]);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_8268e2ba31e84d366d8e")} />
  );

  if (error) return <Layout title={i18nText("ui:m_dcd77622dbed6480723d")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_d47fa33706b87799ca0e", { arg0: renderError(error) })}</Alert></Layout>;

  return (
    <Layout title={i18nText("ui:m_dcd77622dbed6480723d")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}><Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          {i18nRichText("ui:m_0372390272e422433fa5", { arg0: vulnerabilitiesData?.kevStatus === 'available' ? i18nText("ui:m_560b680c17314344f9dc") : vulnerabilitiesData?.kevStatus === 'invalid-or-stale' ? i18nText("ui:m_9afebdd68212d9c70955") : i18nText("ui:m_ddddc9fec2c62ce5d4b3") })}
        </Typography>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
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
        <StatBoxGrid><StatBox icon={<BugReportIcon color="error" />}
            label={i18nText("ui:m_d5dbcb2f3981ec05e973")}
            value={totalVulns} /><StatBox icon={<WarningIcon color="warning" />}
            label={i18nText("ui:m_264943442784fcb84119")}
            value={totalExploits} /><StatBox icon={<ComputerIcon color="info" />}
            label={i18nText("ui:m_644712028d971ef007b5")}
            value={affectedHosts.length} /></StatBoxGrid>
        )}{/* Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 280, md: 'calc(50vh - 80px)' }, minHeight: 230, maxHeight: 400 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`severity-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/severity?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title={i18nText("ui:m_714ea990c2d9ee98566c")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 280, md: 'calc(50vh - 80px)' }, minHeight: 230, maxHeight: 400 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`top-software-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/top-vulnerable-software?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title={i18nText("ui:m_ee8c75a59c380ebcbdd2")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 280, md: 'calc(50vh - 80px)' }, minHeight: 230, maxHeight: 400 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`access-vectors-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/access-vectors?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title={i18nText("ui:m_dfa5477f4f7bf1da2202")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 280, md: 'calc(50vh - 80px)' }, minHeight: 230, maxHeight: 400 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`exploit-types-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/exploit-types?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title={i18nText("ui:m_6d608c1dc1f52f948211")} /></CardContent></Card></Grid><Grid item xs={12}><Card sx={{ height: { xs: 280, md: 'calc(50vh - 80px)' }, minHeight: 230, maxHeight: 400 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame key={`top-affected-hosts-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/vulnerabilities/top-affected-hosts?showLegend=false`}
                  style={{ width: '100%', height: '100%', border: 'none' }}
                  title={i18nText("ui:m_ab88b597d28eef11aa9b")} /></CardContent></Card></Grid></Grid>
        )}{/* Tabs and Table - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}><Tabs value={tabValue} onChange={handleTabChange}><Tab label={i18nText("ui:m_dcd77622dbed6480723d")} /><Tab label={i18nText("ui:m_47fd8c82c21e38ddc327")} /><Tab label={i18nText("ui:m_644712028d971ef007b5")} /></Tabs></Box><Box sx={{ mb: 2, display: 'flex', gap: 2 }}><SearchInput value={searchQuery}
            onChange={setSearchQuery}
            placeholder={i18nText("ui:m_d5a75ba69fa3b6de0393")}
            learnHint={translate("ui:m_2559b0fb3349927ae9c6")} /><Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleRefresh}>{i18nText("ui:m_230fc1b63eb3ef4e6a34")}</Button></Box><ResponsiveDataView data={paginatedData}
          totalCount={filteredData.length}
          page={page}
          rowsPerPage={rowsPerPage}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
          renderCard={(row: any) => (
            <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>{tabValue === 0 && (
                  <Box><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}><Typography variant="subtitle2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{row.id}</Typography><Chip label={row.severity || i18nText("ui:m_d5b7b36db002bbabbc09")}
                        size="small"
                        color={row.severity === 'HIGH' ? 'error' :
                          row.severity === 'MEDIUM' ? 'warning' :
                          row.severity === 'LOW' ? 'info' :
                          'default'} /></Box><Typography variant="body2" color="text.secondary" noWrap>{getSoftwareDisplayName(row.software)}</Typography><Box sx={{ display: 'flex', gap: 2, mt: 1 }}><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_99799db2053938fe5872", { arg0: row.count })}
                      </Typography><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_88c57229904faeab812a", { arg0: row.affected })}
                      </Typography></Box><VulnerabilityReferences references={row.references} /><VulnerabilityKEV cve={row.id} status={row.kev} /></Box>
                )}{tabValue === 1 && (
                  <Box><Typography variant="subtitle2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem', mb: 0.5 }}>{row.id}</Typography><Box sx={{ display: 'flex', gap: 1, mb: 0.5, flexWrap: 'wrap' }}><Chip label={row.type} size="small" variant="outlined" /><Chip label={row.platform} size="small" variant="outlined" /></Box><Typography variant="body2" color="text.secondary" noWrap>{getSoftwareDisplayName(row.software)}</Typography><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_99799db2053938fe5872", { arg0: row.count })}
                    </Typography></Box>
                )}{tabValue === 2 && (
                  <Box><Typography variant="subtitle2" sx={{ fontFamily: 'monospace', mb: 0.5 }}>{row.host}</Typography><Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_5b1516e9963abde2b971", { arg0: row.vulnerabilities })}
                      </Typography><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_655b47764a61847aef8e", { arg0: row.exploits })}
                      </Typography></Box>{row.topSeverity && (
                      <Chip label={row.topSeverity}
                        size="small"
                        sx={{ mt: 0.5 }}
                        color={row.topSeverity === 'HIGH' ? 'error' :
                          row.topSeverity === 'MEDIUM' ? 'warning' :
                          row.topSeverity === 'LOW' ? 'info' :
                          'default'} />
                    )}</Box>
                )}</CardContent></Card>
          )}
          onCardClick={(row: any) => {
            const key = tabValue === 0 ? row.id : tabValue === 1 ? row.id : row.host;
            if (tabValue === 2) {
              handleHostClick(row.host);
            } else {
              handleRowClick(key);
            }
          }}
          desktopTable={<TableContainer component={Paper}><Table size="small"><TableHead><TableRow>{tabValue === 0 && (
                  <><TableCell width={40} /><TableCell onClick={() => handleSort('id')} sx={{ cursor: 'pointer' }}>{i18nText("ui:m_6a146c4aa07a5bf6c87a")}</TableCell><TableCell onClick={() => handleSort('severity')} sx={{ cursor: 'pointer' }}>{i18nText("ui:m_d1de98cbf475009ee57d")}</TableCell><TableCell>{i18nText("ui:m_99c431556bb898cfc4c6")}</TableCell><TableCell onClick={() => handleSort('count')} sx={{ cursor: 'pointer' }} align="right">{i18nText("ui:m_9cc2c6f927f2cbb0421c")}</TableCell><TableCell onClick={() => handleSort('affected')} sx={{ cursor: 'pointer' }} align="right">{i18nText("ui:m_644712028d971ef007b5")}</TableCell></>
                )}{tabValue === 1 && (
                  <><TableCell width={40} /><TableCell onClick={() => handleSort('id')} sx={{ cursor: 'pointer' }}>{i18nText("ui:m_6a146c4aa07a5bf6c87a")}</TableCell><TableCell>{i18nText("ui:m_3da346bd3b7d84ce65d6")}</TableCell><TableCell>{i18nText("ui:m_c40842521044a48c10eb")}</TableCell><TableCell>{i18nText("ui:m_99c431556bb898cfc4c6")}</TableCell><TableCell onClick={() => handleSort('count')} sx={{ cursor: 'pointer' }} align="right">{i18nText("ui:m_9cc2c6f927f2cbb0421c")}</TableCell></>
                )}{tabValue === 2 && (
                  <><TableCell onClick={() => handleSort('host')} sx={{ cursor: 'pointer' }}>{i18nText("ui:m_d36e3ee418e39309c3c7")}</TableCell><TableCell onClick={() => handleSort('vulnerabilities')} sx={{ cursor: 'pointer' }} align="right">{i18nText("ui:m_1bcb7c103c1346dba247")}</TableCell><TableCell align="right">{i18nText("ui:m_47fd8c82c21e38ddc327")}</TableCell><TableCell>{i18nText("ui:m_1fcfaabddc5e0aa6d209")}</TableCell></>
                )}</TableRow></TableHead><TableBody>{paginatedData.map((row: any, idx) => {
                const key = tabValue === 0 ? row.id : tabValue === 1 ? row.id : row.host;
                return (
                  <><TableRow key={key + idx} data-row-key={key} hover onClick={() => tabValue !== 2 && handleRowClick(key)} sx={{ cursor: tabValue !== 2 ? 'pointer' : 'default' }}>{tabValue === 0 && (
                        <><TableCell><IconButton size="small"><ExpandMoreIcon sx={{ transform: expandedRow === key ? 'rotate(180deg)' : 'rotate(0deg)' }} /></IconButton></TableCell><TableCell>{row.id}<VulnerabilityKEV cve={row.id} status={row.kev} compact /></TableCell><TableCell><Chip label={row.severity || i18nText("ui:m_d5b7b36db002bbabbc09")} 
                              size="small" 
                              color={row.severity === 'HIGH' ? 'error' : 
                                row.severity === 'MEDIUM' ? 'warning' : 
                                row.severity === 'LOW' ? 'info' :
                                'default'} /></TableCell><TableCell>{getSoftwareDisplayName(row.software)}</TableCell><TableCell align="right">{row.count}</TableCell><TableCell align="right">{row.affected}</TableCell></>
                      )}{tabValue === 1 && (
                        <><TableCell><IconButton size="small"><ExpandMoreIcon sx={{ transform: expandedRow === key ? 'rotate(180deg)' : 'rotate(0deg)' }} /></IconButton></TableCell><TableCell>{row.id}</TableCell><TableCell>{row.type}</TableCell><TableCell>{row.platform}</TableCell><TableCell>{getSoftwareDisplayName(row.software)}</TableCell><TableCell align="right">{row.count}</TableCell></>
                      )}{tabValue === 2 && (
                        <><TableCell onClick={() => handleHostClick(row.host)}
                            sx={{ 
                              cursor: 'pointer',
                              '&:hover': {
                                textDecoration: 'underline',
                                color: 'primary.main'
                              }
                            }}>{row.host}</TableCell><TableCell align="right">{row.vulnerabilities}</TableCell><TableCell align="right">{row.exploits}</TableCell><TableCell>{row.topSeverity ? (
                              <Chip label={row.topSeverity} 
                                size="small" 
                                color={row.topSeverity === 'HIGH' ? 'error' : 
                                  row.topSeverity === 'MEDIUM' ? 'warning' : 
                                  row.topSeverity === 'LOW' ? 'info' :
                                  'default'} />
                            ) : (
                              <Chip label={i18nText("ui:m_d5b7b36db002bbabbc09")} 
                                size="small" 
                                color="default" />
                            )}</TableCell></>
                      )}</TableRow>{(tabValue === 0 || tabValue === 1) && (
                      <TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}><Collapse in={expandedRow === key} timeout="auto" unmountOnExit><Box sx={{ py: 2, px: 2 }}>{tabValue === 0 && (
                                <><Typography variant="h6" gutterBottom>{row.id}</Typography><Box sx={{ mb: 2 }}><Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                      {i18nText("ui:m_a02602e322c10d1a5449")}
                                    </Typography><Typography variant="body2" paragraph>{row.description}</Typography></Box><VulnerabilityReferences references={row.references} /><VulnerabilityKEV cve={row.id} status={row.kev} /><Grid container spacing={2}><Grid item xs={12} md={6}><Card variant="outlined" sx={{ p: 2 }}><Typography variant="subtitle2" gutterBottom>
                                          {i18nText("ui:m_e72cf609fd14e653ba5e")}
                                        </Typography><Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><Typography variant="body2" color="text.secondary">
                                              {i18nText("ui:m_52e28346dd26ed43e495")}
                                            </Typography><Chip label={row.severity || i18nText("ui:m_d5b7b36db002bbabbc09")} 
                                              size="small" 
                                              color={row.severity === 'HIGH' ? 'error' : 
                                                row.severity === 'MEDIUM' ? 'warning' : 
                                                row.severity === 'LOW' ? 'info' :
                                                'default'} /></Box>{row.v2Score && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                                {i18nText("ui:m_c4d19fe950f2ecb6579b")}
                                              </Typography><Typography variant="body2" fontWeight="medium">{row.v2Score}</Typography></Box>
                                          )}{row.accessVector && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                                {i18nText("ui:m_100234ff32c593c27a10")}
                                              </Typography><Typography variant="body2" fontWeight="medium">{row.accessVector}</Typography></Box>
                                          )}</Box></Card></Grid><Grid item xs={12} md={6}><Card variant="outlined" sx={{ p: 2 }}><Typography variant="subtitle2" gutterBottom>
                                          {i18nText("ui:m_a50e7abf181b36abc669")}
                                        </Typography><Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}><Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                              {i18nText("ui:m_9f1424b24bec0af1ce9a")}
                                            </Typography><Typography variant="body2" fontWeight="medium">{getSoftwareDisplayName(row.software)}</Typography></Box><Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                              {i18nText("ui:m_c0f6bfdf17491b9c661f")}
                                            </Typography><Typography variant="body2" fontWeight="medium">{row.count}</Typography></Box><Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                              {i18nText("ui:m_178707747a95c75520f2")}
                                            </Typography><Typography variant="body2" fontWeight="medium">{row.affected}</Typography></Box></Box></Card></Grid><Grid item xs={12}><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>{row.software && (
                                          <><Button variant="outlined"
                                              color="primary"
                                              size="small"
                                              startIcon={<AppsIcon />}
                                              endIcon={<OpenInNewIcon sx={{ fontSize: 16 }} />}
                                              onClick={() => handleSoftwareClick(getSoftwareSearchTerm(row.software))}
                                              data-learn={i18nText("ui:m_c692915bd6b13aa159d1")}>
                                              {i18nText("ui:m_cca6dfab136315dc85b4")}
                                            </Button><Button variant="outlined"
                                              color="info"
                                              size="small"
                                              startIcon={<CableIcon />}
                                              endIcon={<OpenInNewIcon sx={{ fontSize: 16 }} />}
                                              onClick={() => row.software?.flows && row.software.flows.length > 0 ? handleViewConnectionsByFlow(row.software.flows) : handleViewConnections(getSoftwareSearchTerm(row.software))}
                                              data-learn={i18nText("ui:m_dc1f34d00b17ac675c64")}>
                                              {i18nText("ui:m_ea20f031bdb1838bed13")}
                                            </Button></>
                                        )}{row.affected > 0 && (
                                          <Button variant="outlined"
                                            color="secondary"
                                            size="small"
                                            startIcon={<ComputerIcon />}
                                            onClick={handleViewAffectedHosts}
                                            data-learn={i18nText("ui:m_f918d8af6077a61a8795")}>
                                            {i18nRichText("ui:m_b295d86666a050f912f1", { arg0: row.affected })}
                                          </Button>
                                        )}</Box></Grid>{row.versions && row.versions.length > 0 && (
                                      <Grid item xs={12}><Card variant="outlined" sx={{ p: 2 }}><Typography variant="subtitle2" gutterBottom>
                                            {i18nText("ui:m_448a7fbc89af999365d9")}
                                          </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{row.versions.map((version: string) => (
                                              <Chip key={version} 
                                                label={version} 
                                                size="small" 
                                                variant="outlined" />
                                            ))}</Box></Card></Grid>
                                    )}{row.communityIds && row.communityIds.length > 0 && (
                                      <Grid item xs={12}><Card variant="outlined" sx={{ p: 2 }}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_ac000b817d4770fd4558")}>
                                            {i18nRichText("ui:m_90788a0b65a00abd64e0", { arg0: row.communityIds.length })}
                                          </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{row.communityIds.slice(0, 10).map((cid: string) => (
                                              <CommunityIDChip key={cid} communityId={cid} mode="chip" />
                                            ))}{row.communityIds.length > 10 && (
                                              <Chip label={i18nText("ui:m_5000f686d6d8f94a73f9", { arg0: row.communityIds.length - 10 })}
                                                size="small"
                                                variant="outlined" />
                                            )}</Box></Card></Grid>
                                    )}</Grid></>
                              )}{tabValue === 1 && (
                                <><Typography variant="h6" gutterBottom>{row.id}</Typography><Box sx={{ mb: 2 }}><Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                      {i18nText("ui:m_a02602e322c10d1a5449")}
                                    </Typography><Typography variant="body2" paragraph>{row.description}</Typography></Box><Grid container spacing={2}><Grid item xs={12} md={6}><Card variant="outlined" sx={{ p: 2, height: '100%' }}><Typography variant="subtitle2" gutterBottom>
                                          {i18nText("ui:m_f2ddc364a574c722d5bb")}
                                        </Typography><Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>{row.type && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                                {i18nText("ui:m_b493e7f4865edb6a6c13")}
                                              </Typography><Typography variant="body2" fontWeight="medium">{row.type}</Typography></Box>
                                          )}{row.platform && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                                {i18nText("ui:m_625d277aa77c7f542df3")}
                                              </Typography><Typography variant="body2" fontWeight="medium">{row.platform}</Typography></Box>
                                          )}{row.port && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                                {i18nText("ui:m_8f867960129b7133cf0b")}
                                              </Typography><Typography variant="body2" fontWeight="medium">{row.port}</Typography></Box>
                                          )}{row.file && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                                {i18nText("ui:m_13c4e4f2e300b341f8b1")}
                                              </Typography><Typography variant="body2" fontWeight="medium" sx={{ 
                                                maxWidth: 200, 
                                                overflow: 'hidden', 
                                                textOverflow: 'ellipsis',
                                                whiteSpace: 'nowrap'
                                              }}>{row.file}</Typography></Box>
                                          )}</Box></Card></Grid><Grid item xs={12} md={6}><Card variant="outlined" sx={{ p: 2, height: '100%' }}><Typography variant="subtitle2" gutterBottom>
                                          {i18nText("ui:m_09e8d84b29f38a879b80")}
                                        </Typography><Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}><Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                              {i18nText("ui:m_9f1424b24bec0af1ce9a")}
                                            </Typography><Typography variant="body2" fontWeight="medium">{getSoftwareDisplayName(row.software)}</Typography></Box><Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                              {i18nText("ui:m_c0f6bfdf17491b9c661f")}
                                            </Typography><Typography variant="body2" fontWeight="medium">{row.count}</Typography></Box><Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                              {i18nText("ui:m_178707747a95c75520f2")}
                                            </Typography><Typography variant="body2" fontWeight="medium">{row.affected}</Typography></Box>{row.author && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                                {i18nText("ui:m_90b7650f80029ad3e753")}
                                              </Typography><Typography variant="body2" fontWeight="medium">{row.author}</Typography></Box>
                                          )}{row.date && (
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="body2" color="text.secondary">
                                                {i18nText("ui:m_982f93c7e600897ff996")}
                                              </Typography><Typography variant="body2" fontWeight="medium">{row.date}</Typography></Box>
                                          )}</Box></Card></Grid><Grid item xs={12}><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>{row.software && (
                                          <><Button variant="outlined"
                                              color="primary"
                                              size="small"
                                              startIcon={<AppsIcon />}
                                              endIcon={<OpenInNewIcon sx={{ fontSize: 16 }} />}
                                              onClick={() => handleSoftwareClick(getSoftwareSearchTerm(row.software))}
                                              data-learn={i18nText("ui:m_c692915bd6b13aa159d1")}>
                                              {i18nText("ui:m_cca6dfab136315dc85b4")}
                                            </Button><Button variant="outlined"
                                              color="info"
                                              size="small"
                                              startIcon={<CableIcon />}
                                              endIcon={<OpenInNewIcon sx={{ fontSize: 16 }} />}
                                              onClick={() => row.software?.flows && row.software.flows.length > 0 ? handleViewConnectionsByFlow(row.software.flows) : handleViewConnections(getSoftwareSearchTerm(row.software))}
                                              data-learn={i18nText("ui:m_3646fdfc92c85bf96452")}>
                                              {i18nText("ui:m_ea20f031bdb1838bed13")}
                                            </Button></>
                                        )}{row.affected > 0 && (
                                          <Button variant="outlined"
                                            color="secondary"
                                            size="small"
                                            startIcon={<ComputerIcon />}
                                            onClick={handleViewAffectedHosts}
                                            data-learn={i18nText("ui:m_ca3933632848d5e2618c")}>
                                            {i18nRichText("ui:m_b295d86666a050f912f1", { arg0: row.affected })}
                                          </Button>
                                        )}</Box></Grid>{row.communityIds && row.communityIds.length > 0 && (
                                      <Grid item xs={12}><Card variant="outlined" sx={{ p: 2 }}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_ac000b817d4770fd4558")}>
                                            {i18nRichText("ui:m_90788a0b65a00abd64e0", { arg0: row.communityIds.length })}
                                          </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{row.communityIds.slice(0, 10).map((cid: string) => (
                                              <CommunityIDChip key={cid} communityId={cid} mode="chip" />
                                            ))}{row.communityIds.length > 10 && (
                                              <Chip label={i18nText("ui:m_5000f686d6d8f94a73f9", { arg0: row.communityIds.length - 10 })}
                                                size="small"
                                                variant="outlined" />
                                            )}</Box></Card></Grid>
                                    )}{row.file && (
                                      <Grid item xs={12}><Alert severity="info">{i18nText("ui:m_00ef9a144a7898f712a0")}</Alert></Grid>
                                    )}</Grid></>
                              )}</Box></Collapse></TableCell></TableRow>
                    )}</>
                );
              })}</TableBody></Table></TableContainer>} /></>
        )}</Box></Layout>
  );
}
