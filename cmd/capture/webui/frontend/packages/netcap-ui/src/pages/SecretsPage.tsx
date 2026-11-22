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
  VpnKey as VpnKeyIcon,
  Person as PersonIcon,
  Lock as LockIcon,
  Security as SecurityIcon,
  AccessTime as AccessTimeIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  SyncAlt as SyncAltIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Tag as TagIcon,
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
import { translate as i18nText, renderText as i18nRenderText, richText as i18nRichText, message as i18nMessage, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { errorText } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";





export interface SecretSummary {
  timestamp: number;
  service: string;
  flow: string;
  user: string;
  password: string;
  kind?: string;
  value?: string;
  parameter?: string;
  notes: string;
  // Hash-based credentials
  hash: string;
  hashType: string;
  domain: string;
  realm: string;
  challenge: string;
  serviceName: string;
  etype: number;
  hashcatFormat: string;
  // HTTP Digest specific
  method: string;
  nonce: string;
  uri: string;
  qop: string;
  nc: string;
  cnonce: string;
  // NTLM specific
  workstation: string;
  lmHash: string;
  ntHash: string;
  // Authentication result tracking
  authSuccess: boolean;
  authSuccessSet: boolean;
  authAttempts: number;
  // RADIUS specific
  macAddress: string;
  framedAddress: string;
  connectInfo: string;
  replyMessage: string;
  // SOCKS specific
  socksVersion: number;
  socksStatus: string;
  // SIP specific
  sipMethod: string;
  sipCallId: string;
  sipFrom: string;
  sipTo: string;
  // Community ID for cross-tool correlation
  communityId: string;
}

interface SecretsResponse {
  secrets: SecretSummary[];
  totalCount: number;
}

type CredentialSortField = 'timestamp' | 'service' | 'user' | 'password';
type SortOrder = 'asc' | 'desc';
type CredentialFilterType = 'all' | 'failed' | 'successful' | 'hashed';

// Service category mapping for color-coding and UI labels
const serviceCategories: Record<string, { category: 'auth' | 'discovery' | 'remote' | 'database' | 'network', color: 'primary' | 'secondary' | 'warning' | 'info' | 'success', userLabel: string, passLabel: string }> = {
  // Authentication protocols (traditional credentials)
  'FTP': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'HTTP': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'HTTP Basic': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'HTTP Digest': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Hash' },
  'HTTP NTLM': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'NTLM Hash' },
  'SMTP': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'POP3': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'IMAP': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'Telnet': { category: 'auth', color: 'primary', userLabel: 'Username', passLabel: 'Password' },
  'NTLMSSP': { category: 'auth', color: 'warning', userLabel: 'Domain\\User', passLabel: 'NTLM Hash' },
  'Kerberos AS-REQ': { category: 'auth', color: 'warning', userLabel: 'Principal', passLabel: 'Ticket Hash' },
  'Kerberos AS-REP': { category: 'auth', color: 'warning', userLabel: 'Principal', passLabel: 'Encrypted Data' },
  'Kerberos TGS-REP': { category: 'auth', color: 'warning', userLabel: 'Service Principal', passLabel: 'Ticket Hash' },
  'LDAP': { category: 'auth', color: 'primary', userLabel: 'DN/User', passLabel: 'Password' },
  // Database protocols
  'PostgreSQL': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'Password' },
  'PostgreSQL Hash': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'MD5 Hash' },
  'MySQL': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'Password/Hash' },
  'MongoDB': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'SCRAM Data' },
  'MongoDB Challenge Response': { category: 'database', color: 'info', userLabel: 'Username', passLabel: 'Challenge/Response' },
  'Redis': { category: 'database', color: 'info', userLabel: 'Database', passLabel: 'Password' },
  // Remote access
  'VNC': { category: 'remote', color: 'warning', userLabel: 'Connection', passLabel: 'Challenge/Response' },
  'TeamViewer': { category: 'remote', color: 'warning', userLabel: 'Command', passLabel: '' },
  'TeamViewer Auth': { category: 'remote', color: 'warning', userLabel: 'Auth Event', passLabel: '' },
  // Network discovery (metadata, not credentials)
  'mDNS': { category: 'discovery', color: 'success', userLabel: 'Hostnames', passLabel: '' },
  'NBNS': { category: 'discovery', color: 'success', userLabel: 'NetBIOS Name', passLabel: '' },
  'UPnP': { category: 'discovery', color: 'success', userLabel: 'Device Info', passLabel: '' },
  'WSD': { category: 'discovery', color: 'success', userLabel: 'Device Address', passLabel: '' },
  // Network management
  'SNMP': { category: 'network', color: 'secondary', userLabel: 'Community String', passLabel: '' },
};

// Helper function to get service info with defaults
const getServiceInfo = (service: string) => {
  const info = serviceCategories[service] || { 
    category: 'auth' as const, 
    color: 'primary' as const, 
    userLabel: 'Username', 
    passLabel: 'Password' 
  };
  return { ...info, userLabel: i18nText(info.userLabel), passLabel: info.passLabel ? i18nText(info.passLabel) : '' };
};

// Helper function to truncate string with ellipsis
const truncateString = (str: string, maxLength: number) => {
  if (!str || str.length <= maxLength) return str;
  return str.substring(0, maxLength) + '…';
};

// parseIPPort splits "IP:port" for both IPv4 and IPv6 addresses.
// IPv6 example: "2001:470:1f0b:16b0:20c:29ff:feb7:1d68:51580" — last colon separates port
// IPv4 example: "192.168.1.1:80"
const parseIPPort = (s: string): [string, string] | null => {
  const lastColon = s.lastIndexOf(':');
  if (lastColon === -1) return null;
  const ip = s.substring(0, lastColon);
  const port = s.substring(lastColon + 1);
  if (!/^\d+$/.test(port)) return null;
  return [ip, port];
};

// Helper function to parse and render colorized flow identifier
// Handles both IPv4 and IPv6 flows:
//   IPv4: "192.168.1.1:80->10.0.0.1:443"
//   IPv6: "2001:470:1f0b::1d68:51580->2001:470:1f0b::fea8:26f7:1812"
//   With protocol: "TCP:192.168.1.1:80->10.0.0.1:443"
const renderColorizedFlow = (flow: string) => {
  if (!flow) return null;

  // Split on "->" to get src and dst sides
  const arrowIdx = flow.indexOf('->');
  if (arrowIdx === -1) {
    return (
      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{flow}</Typography>
    );
  }

  let srcSide = flow.substring(0, arrowIdx);
  const dstSide = flow.substring(arrowIdx + 2);

  // Check for optional protocol prefix (e.g., "TCP:")
  let proto: string | undefined;
  const protoMatch = srcSide.match(/^([A-Z]+):(.+)$/);
  if (protoMatch) {
    proto = protoMatch[1];
    srcSide = protoMatch[2];
  }

  const src = parseIPPort(srcSide);
  const dst = parseIPPort(dstSide);

  if (!src || !dst) {
    return (
      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{flow}</Typography>
    );
  }

  const [srcIP, srcPort] = src;
  const [dstIP, dstPort] = dst;

  return (
    <Box sx={{
        fontFamily: 'monospace',
        fontSize: '0.8rem',
        display: 'flex',
        alignItems: 'center',
      }}>{proto && (
        <Box component="span" sx={{ color: 'text.secondary' }}>{proto}:</Box>
      )}<Box component="span" sx={{ color: 'error.main', fontWeight: 'bold' }}>{srcIP}</Box><Box component="span" sx={{ color: 'text.secondary' }}>:</Box><Box component="span" sx={{ color: 'warning.main', fontWeight: 'medium' }}>{srcPort}</Box><Box component="span" sx={{ color: 'text.secondary', mx: 0.5 }}>→</Box><Box component="span" sx={{ color: 'primary.main', fontWeight: 'bold' }}>{dstIP}</Box><Box component="span" sx={{ color: 'text.secondary' }}>:</Box><Box component="span" sx={{ color: 'warning.main', fontWeight: 'medium' }}>{dstPort}</Box></Box>
  );
};

export interface SecretsPageProps {
  /** Custom row actions to render in the expanded row details */
  rowActions?: (row: SecretSummary) => React.ReactNode;
}

export default function SecretsPage({ rowActions }: SecretsPageProps = {}) {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const { selectedCommunityIDs, isFilterActive: isCommunityIDFilterActive } = useCommunityIDFilter();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<CredentialFilterType>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [sortField, setSortField] = useState<CredentialSortField>('timestamp');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [baseViewMode, setBaseViewMode] = useViewMode();
  const [showAuth, setShowAuth] = useState(false);
  // Extend view mode to support 'auth' tab locally
  const viewMode = showAuth ? 'auth' : baseViewMode;
  const setViewMode = (mode: string) => {
    if (mode === 'auth') {
      setShowAuth(true);
    } else {
      setShowAuth(false);
      setBaseViewMode(mode as 'table' | 'chart');
    }
  };

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Initialize search query from URL parameter
  useEffect(() => {
    if (router.isReady && router.query.search) {
      setSearchQuery(router.query.search as string);
    }
  }, [router.isReady, router.query.search]);

  // Fetch credentials data
  const { data: credentialsData, error, mutate } = useSWR<SecretsResponse>(
    'secrets',
    () => fetch(`${getBackendUrl()}/api/secrets`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const credentials = credentialsData?.secrets || [];
  const totalCount = credentialsData?.totalCount || 0;

  // Handle sort column click
  const handleSort = (field: CredentialSortField) => {
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
  const filteredCredentials = useMemo(() => {
    let filtered = credentials;

    // Apply Community ID filter first (if active)
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(c => 
        c.communityId && selectedCommunityIDs.has(c.communityId)
      );
    }

    // Apply credential type filter
    if (filterType !== 'all') {
      filtered = filtered.filter(cred => {
        switch (filterType) {
          case 'failed':
            return cred.authSuccessSet && !cred.authSuccess;
          case 'successful':
            return cred.authSuccessSet && cred.authSuccess;
          case 'hashed':
            return Boolean(cred.hash || cred.hashType || cred.hashcatFormat);
          default:
            return true;
        }
      });
    }

    // Apply search filter with negation support (e.g., "!FTP" excludes FTP)
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      filtered = filtered.filter(c =>
        matchesSearchTerms([
          c.service,
          c.user,
          c.password,
          c.value ?? '', c.kind ?? '', c.parameter ?? '',
          c.flow,
          c.notes || '',
        ], searchTerms)
      );
    }

    // Apply sorting with stable secondary sort by flow identifier
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'timestamp':
          comparison = a.timestamp - b.timestamp;
          break;
        case 'service':
          comparison = a.service.localeCompare(b.service);
          break;
        case 'user':
          comparison = a.user.localeCompare(b.user);
          break;
        case 'password':
          comparison = (a.password || a.value || '').localeCompare(b.password || b.value || '');
          break;
      }
      // Stable secondary sort by flow identifier for consistent ordering
      if (comparison === 0) {
        comparison = (a.flow || '').localeCompare(b.flow || '');
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [credentials, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs, filterType]);

  // Paginate credentials
  const paginatedCredentials = filteredCredentials.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedCredentials.map((cred, idx) => `${cred.timestamp}-${cred.service}-${cred.user}-${idx}`),
    [paginatedCredentials]
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
      learnHint={finalCopyMessage("ui:m_597e81cf106eb3efe528")} />
  );

  // Memoize summary statistics to avoid recalculation on every render
  const stats = useMemo(() => ({
    uniqueServices: new Set(credentials.map(c => c.service)).size,
    uniqueUsers: new Set(credentials.map(c => c.user)).size,
    uniquePasswords: new Set(credentials.map(c => c.password).filter(Boolean)).size,
    avgPerService: credentials.length > 0 
      ? credentials.length / new Set(credentials.map(c => c.service)).size
      : 0,
    failedCount: credentials.filter(c => c.authSuccessSet && !c.authSuccess).length,
    successfulCount: credentials.filter(c => c.authSuccessSet && c.authSuccess).length,
    hashedCount: credentials.filter(c => Boolean(c.hash || c.hashType || c.hashcatFormat)).length,
  }), [credentials]);

  if (error) {
    return (
      <Layout title={i18nText("ui:m_e07371b6b8d7ea089087")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_ae1eefbf9346a1d00616", { arg0: i18nRenderText(renderError(error)) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_e07371b6b8d7ea089087")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle */}<Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}><ToggleButtonGroup value={viewMode}
            exclusive
            onChange={(_e, newValue: string | null) => {
              if (newValue !== null) {
                setViewMode(newValue);
              }
            }}
            size="small"
            data-learn={i18nText("ui:m_89886482976cfe48af47")}><ToggleButton value="table"><TableChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              {i18nRichText("ui:m_b65e2110701259d5e7dc", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
            </ToggleButton><ToggleButton value="chart"><BarChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              {i18nRichText("ui:m_da105eec6af81877e667", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
            </ToggleButton><ToggleButton value="auth"><SyncAltIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              {i18nRichText("ui:m_349e840204ecfe088a51", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
            </ToggleButton></ToggleButtonGroup></Box>{/* Summary Cards - Row 1: Filters - Only show in table mode */}{viewMode === 'table' && (
        <StatBoxGrid><StatBox icon={<VpnKeyIcon color="primary" />}
            label={i18nText("ui:m_d10e657e170429a9a6a4")}
            value={totalCount}
            onClick={() => { setFilterType('all'); setPage(0); }}
            isActive={filterType === 'all'}
            activeColor="primary"
            learnHint={translate("ui:m_af10a983a77375c21ba0")} /><StatBox icon={<ErrorIcon color="error" />}
            label={i18nText("ui:m_e5ae94910dcfe8f8696c")}
            value={stats.failedCount}
            onClick={() => { setFilterType('failed'); setPage(0); }}
            isActive={filterType === 'failed'}
            activeColor="error"
            learnHint={translate("ui:m_55398ea8ead7a7354ca8")} /><StatBox icon={<CheckCircleIcon color="success" />}
            label={i18nText("ui:m_85050d6e930921186c12")}
            value={stats.successfulCount}
            onClick={() => { setFilterType('successful'); setPage(0); }}
            isActive={filterType === 'successful'}
            activeColor="success"
            learnHint={translate("ui:m_575bb947238c2b1ef99c")} /><StatBox icon={<TagIcon color="warning" />}
            label={i18nText("ui:m_a3fcf9b29352e0ce77dd")}
            value={stats.hashedCount}
            onClick={() => { setFilterType('hashed'); setPage(0); }}
            isActive={filterType === 'hashed'}
            activeColor="warning"
            learnHint={translate("ui:m_942a1f80db9198581e5c")} /></StatBoxGrid>
        )}{/* Summary Cards - Row 2: Statistics - Only show in table mode */}{viewMode === 'table' && (
        <StatBoxGrid><StatBox icon={<SecurityIcon color="success" />}
            label={i18nText("ui:m_40cc75471da545d83df8")}
            value={stats.uniqueServices}
            learnHint={translate("ui:m_c729979894051206df70")} /><StatBox icon={<PersonIcon color="warning" />}
            label={i18nText("ui:m_d86cbb9f9c140eb56b24")}
            value={stats.uniqueUsers}
            learnHint={translate("ui:m_9276bd31f8df61cc41ed")} /><StatBox icon={<LockIcon color="info" />}
            label={i18nText("ui:m_9eb0cf3b8ebb344f0db7")}
            value={stats.uniquePasswords}
            learnHint={translate("ui:m_74f7049b7ed8d0fb8fde")} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_81ef54fdba4a85009b2b")}
                  key={`by-service-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/secrets/by-service`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_03c73e04165bbe093af2")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_caf08ae461e5de298ebe")}
                  key={`timeline-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/secrets/timeline`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_b393ac6dbc3103aa6ea5")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_66a2e1c70cb6992473d8")}
                  key={`usernames-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/secrets/usernames`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_f2f37656215e54f573f4")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_e6ea340e453ac398e328")}
                  key={`flows-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/secrets/flows?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_02acf1cbb307aef0d96d")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_a61d07cd2ca1d28f77c7")}
            learnHint={translate("ui:m_2ca9a56128b5c0ab76b0")} /><Button data-learn={i18nText("ui:m_eed2d0c969ee5ca700c9")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{(searchQuery || filterType !== 'all') ? (
            <Typography variant="body2" color="text.secondary" data-learn={i18nText("ui:m_749195289cc91c23beaf")}>
              {i18nRichText("ui:m_28f72b2932d2788365ba", { arg0: filteredCredentials.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Credentials Table */}{!credentialsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }} data-learn={i18nText("ui:m_2b168d47785850a6eca5")}><VpnKeyIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_e379ab149e8e0d38178a")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_c4779a3daca179f82694")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedCredentials}
            totalCount={filteredCredentials.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            renderCard={(cred) => (
              <Card variant="outlined"><CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}><Chip label={cred.service || i18nText("ui:m_2f1ac5f44673922d2bf2")}
                      size="small"
                      color={getServiceInfo(cred.service).color}
                      sx={{ fontSize: '0.7rem' }} /><Typography variant="caption" color="text.secondary">{formatTimestamp(cred.timestamp, 'nanoseconds')}</Typography></Box>{cred.flow && (
                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', mb: 0.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.flow}</Typography>
                  )}<Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{getServiceInfo(cred.service).userLabel}: {truncateString(cred.user, 30)}</Typography>{getServiceInfo(cred.service).passLabel && cred.password && (
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'error.main' }}>{getServiceInfo(cred.service).passLabel}: {truncateString(cred.password, 30)}</Typography>
                  )}{cred.value && (
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>{cred.kind ?? i18nText("ui:m_eecbe8b9f8021c232dd0")}({cred.parameter}): {cred.value}</Typography>
                  )}</CardContent></Card>
            )}
            desktopTable={<TableContainer component={Paper}><Table size="small" data-learn={i18nText("ui:m_a1ef693aa0958064fe56")}><TableHead><TableRow><TableCell width={40}></TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}><TableSortLabel data-learn={i18nText("ui:m_1617938c89a86027d744")}
                        active={sortField === 'timestamp'}
                        direction={sortField === 'timestamp' ? sortOrder : 'asc'}
                        onClick={() => handleSort('timestamp')}>
                        {i18nText("ui:m_b62418ba3d29bf760ea0")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_1614ee8ca950b01f97ea")}
                        active={sortField === 'service'}
                        direction={sortField === 'service' ? sortOrder : 'asc'}
                        onClick={() => handleSort('service')}>
                        {i18nText("ui:m_e1d47e59dd85d4abaa0f")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_baf7f8cc8527f334cbb3")}
                        active={sortField === 'user'}
                        direction={sortField === 'user' ? sortOrder : 'asc'}
                        onClick={() => handleSort('user')}>
                        {i18nText("ui:m_4bae04cf82819470ec10")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_d96a3e828fd9a6becbfb")}
                        active={sortField === 'password'}
                        direction={sortField === 'password' ? sortOrder : 'asc'}
                        onClick={() => handleSort('password')}>
                        {i18nText("ui:m_a74fa671e45574b2cd22")}
                      </TableSortLabel></TableCell><TableCell data-learn={i18nText("ui:m_2a9262a483933e6ec9b8")}>
                      {i18nText("ui:m_445f5c7623fff323a4b0")}
                    </TableCell></TableRow></TableHead><TableBody>{paginatedCredentials.map((cred, idx) => {
                    const rowKey = `${cred.timestamp}-${cred.service}-${cred.user}-${idx}`;
                    return (
                      <><TableRow key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn={i18nText("ui:m_ff33aaefe886296124ae")}><TableCell><IconButton size="small" data-learn={i18nText("ui:m_e00c7c7d37c5e04842aa")}><ExpandMoreIcon sx={{
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} /></IconButton></TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }} data-learn={i18nText("ui:m_3ddf5cc392aeb839e026")}>{formatTimestamp(cred.timestamp, 'nanoseconds')}</Typography></TableCell><TableCell><Chip data-learn={i18nText("ui:m_b1b3451c60cac852e7de")}
                              label={cred.service || i18nText("ui:m_2f1ac5f44673922d2bf2")}
                              size="small"
                              color={getServiceInfo(cred.service).color}
                              sx={{ fontSize: '0.7rem' }} /></TableCell><TableCell><Typography variant="body2"
                              sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}
                              data-learn={i18nText("ui:m_debfc7068dac655469dd")}
                              title={cred.user.length > 25 ? cred.user : undefined}>{truncateString(cred.user, 25)}</Typography></TableCell><TableCell><Typography variant="body2"
                              sx={{
                                fontFamily: 'monospace',
                                fontSize: '0.875rem',
                              }}
                              data-learn={i18nText("ui:m_75c8c868fffd728d18f5")}
                              title={cred.value || (cred.password.length > 25 ? cred.password : undefined)}>{cred.value ? `${cred.kind ?? 'token'} (${cred.parameter ?? ''}): ${truncateString(cred.value, 25)}` : truncateString(cred.password, 25)}</Typography></TableCell><TableCell>{cred.flow ? renderColorizedFlow(cred.flow) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.8rem' }}>-
                              </Typography>
                            )}</TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}><Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit><Box sx={{ py: 2 }} data-learn={i18nText("ui:m_1c488bb6fd0b3e83a8ac")}><Grid container spacing={2}>{/* Timestamp */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_3a1ee9e50b08fc369dd6")}>
                                      {i18nText("ui:m_b21c719bd4af49bbafd2")}
                                    </Typography><Typography variant="body2" color="text.secondary">{formatTimestamp(cred.timestamp, 'nanoseconds')}</Typography></Grid>{/* Service */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_3af4c04a2e940a058d54")}>
                                      {i18nText("ui:m_e001a12fcde245530a15")}
                                    </Typography><Typography variant="body2" color="text.secondary">{cred.service || i18nText("ui:m_2f1ac5f44673922d2bf2")}</Typography></Grid>{/* Username/Primary Data */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_44e19fc32c852df7f305", { arg0: getServiceInfo(cred.service).userLabel })}>{getServiceInfo(cred.service).userLabel}</Typography><Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{cred.user}</Typography></Grid>{/* Password/Secondary Data - only show if service has password field */}{getServiceInfo(cred.service).passLabel && (
                                  <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_036a95f44ca22834aec6", { arg0: getServiceInfo(cred.service).passLabel })}>{getServiceInfo(cred.service).passLabel}</Typography><Typography variant="body2"
                                      sx={{
                                        fontFamily: 'monospace',
                                        color: getServiceInfo(cred.service).category === 'discovery' ? 'text.secondary' : 'error.main',
                                        fontWeight: getServiceInfo(cred.service).category === 'discovery' ? 'normal' : 'bold',
                                        wordBreak: 'break-all',
                                      }}>{cred.password}</Typography></Grid>
                                  )}{/* Flow */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_367dadc27b609d546678")}>
                                      {i18nText("ui:m_e6732e1d9743a2d694d2")}
                                    </Typography><Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all', mb: 2 }}>{cred.flow || i18nText("ui:m_8dc598ebf1e055830140")}</Typography>{cred.flow && (
                                      <Button data-learn={i18nText("ui:m_b5b7a0c7dae96cb0b5e0")}
                                        variant="outlined"
                                        size="small"
                                        startIcon={<SyncAltIcon />}
                                        onClick={() => router.push(`/connections?search=${encodeURIComponent(cred.flow)}`)}
                                        sx={{ mt: 1 }}>
                                        {i18nText("ui:m_6c5d61871b4aa112fc63")}
                                      </Button>
                                    )}</Grid>{/* Community ID for Cross-Tool Correlation */}{cred.communityId && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_6520556565357b546291")}>
                                        {i18nText("ui:m_05fb20693d84c7cd3199")}
                                      </Typography><CommunityIDChip communityId={cred.communityId} mode="text" /></Grid>
                                  )}{/* Notes */}{cred.notes && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_1ed60c0b1a70719998b0")}>
                                        {i18nText("ui:m_906235396e574e3ca4d8")}
                                      </Typography><Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{cred.notes}</Typography></Grid>
                                  )}{/* Authentication Result */}{cred.authSuccessSet && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_4a1019b0f0d211fa4b11")}>
                                        {i18nText("ui:m_d3b8b569a892d62ba379")}
                                      </Typography><Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}><Chip label={cred.authSuccess ? i18nText("ui:m_2779356e27ca2f9e69a1") : i18nText("ui:m_9ec2da2237bac370177f")}
                                          size="small"
                                          color={cred.authSuccess ? 'success' : 'error'}
                                          sx={{ fontWeight: 'bold' }} />{cred.authAttempts > 0 && (
                                          <Typography variant="body2" color="text.secondary">
                                            {i18nRichText("ui:m_a2cada26e72c70a006a9", { arg0: cred.authAttempts, arg1: cred.authAttempts > 1 ? 's' : '' })}
                                          </Typography>
                                        )}</Box></Grid>
                                  )}{/* Hash Information */}{(cred.hash || cred.hashType || cred.hashcatFormat) && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_91fbfbcd69b407f25364")}>
                                        {i18nText("ui:m_661dad40bb98964a21c7")}
                                      </Typography>{cred.hashType && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}><Typography variant="body2" color="text.secondary">{i18nText("ui:m_b493e7f4865edb6a6c13")}</Typography><Chip label={cred.hashType} size="small" color="warning" variant="outlined" sx={{ fontSize: '0.7rem' }} /></Box>
                                      )}{cred.hash && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all', mb: 0.5 }}>
                                          {i18nRichText("ui:m_8a6acefe65674fac6b5c", { arg0: cred.hash })}
                                        </Typography>
                                      )}{cred.hashcatFormat && (
                                        <Box sx={{ mt: 1 }}><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                                            {i18nText("ui:m_3b245c11d499f1de1acf")}
                                          </Typography><Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all', bgcolor: 'background.paper', p: 1, borderRadius: 1, border: '1px solid', borderColor: 'divider' }}>{cred.hashcatFormat}</Typography></Box>
                                      )}</Grid>
                                  )}{/* Domain/NTLM Information */}{(cred.domain || cred.realm || cred.workstation || cred.ntHash || cred.lmHash) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_11a4b4e2f445a45f94e5")}>
                                        {i18nText("ui:m_24ef5af30d376e8b621b")}
                                      </Typography>{cred.domain && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_67b5f6fe46c371e1af31", { arg0: cred.domain })}</Typography>
                                      )}{cred.realm && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_dc68344cbe3ffb432d55", { arg0: cred.realm })}</Typography>
                                      )}{cred.workstation && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_41046d70f74c6ffa2241", { arg0: cred.workstation })}</Typography>
                                      )}{cred.serviceName && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_797d2b96360d4e6175be", { arg0: cred.serviceName })}</Typography>
                                      )}{cred.ntHash && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          {i18nRichText("ui:m_f88302939e0e61ff1ff7", { arg0: cred.ntHash })}
                                        </Typography>
                                      )}{cred.lmHash && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          {i18nRichText("ui:m_c12914f6d9446947ee66", { arg0: cred.lmHash })}
                                        </Typography>
                                      )}</Grid>
                                  )}{/* HTTP Digest Info */}{(cred.nonce || cred.uri || cred.qop) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_1e8b6d56ab22cd70e553")}>
                                        {i18nText("ui:m_61904dc9d162d0270e09")}
                                      </Typography>{cred.method && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_403dc33196d2e4799a40", { arg0: cred.method })}</Typography>
                                      )}{cred.uri && (
                                        <Typography variant="body2" color="text.secondary" sx={{ wordBreak: 'break-all' }}>{i18nRichText("ui:m_bff0ab7e779ad555a233", { arg0: cred.uri })}</Typography>
                                      )}{cred.qop && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_d6b16c317df8a40893cd", { arg0: cred.qop })}</Typography>
                                      )}{cred.nonce && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          {i18nRichText("ui:m_5ea2c7020b1bc0b8b288", { arg0: cred.nonce })}
                                        </Typography>
                                      )}</Grid>
                                  )}{/* RADIUS Info */}{(cred.macAddress || cred.framedAddress || cred.connectInfo || cred.replyMessage) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_6df3327b63aac6deda19")}>
                                        {i18nText("ui:m_caceb1c6a814ec0ba215")}
                                      </Typography>{cred.macAddress && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                                          {i18nRichText("ui:m_62362885b52e69792802", { arg0: cred.macAddress })}
                                        </Typography>
                                      )}{cred.framedAddress && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                                          {i18nRichText("ui:m_18f2c0191da836a8d476", { arg0: cred.framedAddress })}
                                        </Typography>
                                      )}{cred.connectInfo && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_5ab9ac54bf3893063b08", { arg0: cred.connectInfo })}</Typography>
                                      )}{cred.replyMessage && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_98252fc2039fc6a545a9", { arg0: cred.replyMessage })}</Typography>
                                      )}</Grid>
                                  )}{/* SIP Info */}{(cred.sipMethod || cred.sipCallId || cred.sipFrom || cred.sipTo) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_d22f2023fed199d71c78")}>
                                        {i18nText("ui:m_1caabd9801be18a58e12")}
                                      </Typography>{cred.sipMethod && (
                                        <Chip label={cred.sipMethod} size="small" color="info" variant="outlined" sx={{ mb: 0.5, fontSize: '0.7rem' }} />
                                      )}{cred.sipFrom && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_382a878431a83760389e", { arg0: cred.sipFrom })}</Typography>
                                      )}{cred.sipTo && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_f66f4a86a9c290aeed59", { arg0: cred.sipTo })}</Typography>
                                      )}{cred.sipCallId && (
                                        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                          {i18nRichText("ui:m_68d7e26ce4584d820090", { arg0: cred.sipCallId })}
                                        </Typography>
                                      )}</Grid>
                                  )}{/* SOCKS Info */}{(cred.socksVersion > 0 || cred.socksStatus) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_da91b35dc6c06c65e8d0")}>
                                        {i18nText("ui:m_380566a2118d6bfd4f4d")}
                                      </Typography>{cred.socksVersion > 0 && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_243f110a3f1a816c749c", { arg0: cred.socksVersion })}</Typography>
                                      )}{cred.socksStatus && (
                                        <Typography variant="body2" color="text.secondary">{i18nRichText("ui:m_670fb8226810d80e9af7", { arg0: cred.socksStatus })}</Typography>
                                      )}</Grid>
                                  )}{/* Custom row actions from parent */}{rowActions && (
                                    <Grid item xs={12}><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>{rowActions(cred)}</Box></Grid>
                                  )}</Grid></Box></Collapse></TableCell></TableRow></>
                    );
                  })}</TableBody></Table></TableContainer>} />
        )}</>
        )}{/* Auth Activity View */}{viewMode === 'auth' && (
          <AuthActivityView />
        )}</Box></Layout>
  );
}

// AuthActivityView shows unified authentication events from Credentials, TACACS+, and Kerberos
function AuthActivityView() {
  const __uiLocale = useUILocale();
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<UIMessageText | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${getBackendUrl()}/api/auth-activity`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => {
        setEvents(Array.isArray(data?.events) ? data.events : []);
      })
      .catch((err) => {
        setError(errorText(err) || i18nMessage("ui:m_c5dace89ab5c667d3db3"));
        setEvents([]);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}><CircularProgress /></Box>
    );
  }

  if (error) {
    return <Alert severity="error" sx={{ mb: 2 }}>{i18nRenderText(error)}</Alert>;
  }

  if (events.length === 0) {
    return (
      <Alert severity="info" sx={{ mb: 2 }}>
        {i18nText("ui:m_fe61b3f8fb589ad4ac1f")}
      </Alert>
    );
  }

  const sortedEvents = [...events].sort((a, b) => (b?.timestamp ?? 0) - (a?.timestamp ?? 0));

  const protocolColors: Record<string, 'error' | 'warning' | 'info' | 'success' | 'default'> = {
    'Kerberos': 'error',
    'TACACS+': 'warning',
    'RADIUS': 'info',
    'FTP': 'default',
    'Telnet': 'default',
    'SNMP': 'default',
  };

  const getStatusColor = (status: unknown): 'success' | 'error' | 'default' => {
    if (typeof status !== 'string') return 'default';
    if (status === 'success' || status === 'PASS') return 'success';
    if (status === 'failure' || status === 'FAIL') return 'error';
    if (status.includes('error')) return 'error';
    return 'default';
  };

  return (
    <><Typography variant="h6" sx={{ mb: 2 }}>
        {i18nRichText("ui:m_bfa36be828f3b1fcb450", { arg0: events.length })}
      </Typography><Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {i18nText("ui:m_0d1db9c7a4ed141d04e4")}
      </Typography><TableContainer component={Paper}><Table size="small"><TableHead><TableRow><TableCell>{i18nText("ui:m_b62418ba3d29bf760ea0")}</TableCell><TableCell>{i18nText("ui:m_2d5b0d13af7edb332cfd")}</TableCell><TableCell>{i18nText("ui:m_b8a7a17f8bccb97b1b0e")}</TableCell><TableCell>{i18nText("ui:m_e1d47e59dd85d4abaa0f")}</TableCell><TableCell>{i18nText("ui:m_1a3caa8a333177645dfb")}</TableCell><TableCell>{i18nText("ui:m_cf025c2b66b1d8e97700")}</TableCell><TableCell>{i18nText("ui:m_4113167561ccea5b6c6b")}</TableCell><TableCell>{i18nText("ui:m_4b35e0eccce697e20a4d")}</TableCell><TableCell>{i18nText("ui:m_0e07624e3854b301c0e2")}</TableCell></TableRow></TableHead><TableBody>{sortedEvents.slice(0, 500).map((event, idx) => (
              <TableRow key={idx} hover><TableCell><Typography variant="body2" noWrap>{event?.timestamp ? formatTimestamp(event.timestamp, 'nanoseconds') : '-'}</Typography></TableCell><TableCell><Chip label={event?.protocol || i18nText("ui:m_b1b6b391498fb13c454c")}
                    size="small"
                    color={protocolColors[event?.protocol] || 'default'}
                    variant="outlined" /></TableCell><TableCell><Typography variant="body2" fontWeight="bold">{event?.user || '-'}</Typography></TableCell><TableCell>{event?.service || '-'}</TableCell><TableCell>{event?.action || '-'}</TableCell><TableCell><Chip label={String(event?.status || translate("ui:m_b1b6b391498fb13c454c"))}
                    size="small"
                    color={getStatusColor(event?.status)}
                    variant="outlined" /></TableCell><TableCell><Typography variant="body2" noWrap>{event?.srcIP || '-'}</Typography></TableCell><TableCell><Typography variant="body2" noWrap>{event?.dstIP || '-'}</Typography></TableCell><TableCell><Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>{event?.details || '-'}</Typography></TableCell></TableRow>
            ))}</TableBody></Table></TableContainer>{sortedEvents.length > 500 && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          {i18nRichText("ui:m_30e7b3a2076c4fbe5d3b", { arg0: sortedEvents.length })}
        </Typography>
      )}</>
  );
}
