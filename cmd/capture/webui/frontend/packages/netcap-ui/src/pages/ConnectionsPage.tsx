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
  Cable as CableIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingUpIcon,
  Timer as TimerIcon,
  Article as ArticleIcon,
  Download as DownloadIcon,
  Computer as ComputerIcon,
  Router as RouterIcon,
  Dns as DnsIcon,
  TableChart as TableChartIcon,
  BarChart as BarChartIcon,
  Layers as LayersIcon,
  Hub as HubIcon,
  DeviceHub as DeviceHubIcon,
  VpnKey as VpnKeyIcon,
} from '@mui/icons-material';
import ResponsiveDataView from '../components/ResponsiveDataView';
import Layout from '../components/Layout';
import BehaviorAssetContext from '../components/BehaviorAssetContext';
import DirectionalTraffic from '../components/DirectionalTraffic';
import ConversationModal from '../components/ConversationModal';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import ProducerConsumerEvidence from '../components/ProducerConsumerEvidence';
import RelatedEvidence from '../components/RelatedEvidence';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';

import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

import { ChartFrame } from '../components/ChartFrame';
import { translate as i18nText, richText as i18nRichText, formatNumber as i18nNumber, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate, formatQuantity } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";




export interface ConnectionSummary {
  dnsResolvedName?: string;
  dnsResolvedAtNs?: string;
  dnsResolutionState?: string;
  observationId?: string;
  snapshotSequence?: string;
  timestampFirst: number;
  timestampLast: number;
  timestampFirstNs?: string;
  timestampLastNs?: string;
  linkProto: string;
  networkProto: string;
  transportProto: string;
  applicationProto: string;
  srcMAC: string;
  dstMAC: string;
  srcIP: string;
  srcPort: string;
  dstIP: string;
  dstPort: string;
  totalSize: number;
  appPayloadSize: number;
  numPackets: number;
  duration: number;
  bytesClientToServer: number;
  bytesServerToClient: number;
  numFINFlags: number;
  numRSTFlags: number;
  numACKFlags: number;
  numSYNFlags: number;
  numURGFlags: number;
  numECEFlags: number;
  numPSHFlags: number;
  numCWRFlags: number;
  numNSFlags: number;
  meanWindowSize: number;
  applications: string[];
  serverPortName: string;
  detectedProtocolName: string;
  // JA4L timing fields
  tcpRttNanos: number;
  tlsHandshakeNanos: number;
  ja4lClient: string;
  ja4lServer: string;
  synTtl: number;
  // Security behavioral analysis fields
  packetsClientToServer: number;
  packetsServerToClient: number;
  byteRatio: number;
  packetRatio: number;
  avgPacketSizeClientToServer: number;
  avgPacketSizeServerToClient: number;
  isExternal: boolean;
  isBroadcast: boolean;
  isMulticast: boolean;
  // TLS SNI
  sni: string;
  // Community ID for cross-tool correlation
  communityId: string;
}

interface ConnectionsResponse {
  connections: ConnectionSummary[];
  totalCount: number;
}

interface SecretSummary {
  communityId: string;
  flow: string;
}

interface SecretsResponse {
  secrets: SecretSummary[];
  totalCount: number;
}

type ConnectionSortField = 'endpoints' | 'protocol' | 'packets' | 'bytes' | 'duration';
type SortOrder = 'asc' | 'desc';

export interface ConnectionsPageProps {
  /** Custom row actions to render in the expanded row details */
  rowActions?: (row: ConnectionSummary) => React.ReactNode;
}

export default function ConnectionsPage({ rowActions }: ConnectionsPageProps = {}) {
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
  const [sortField, setSortField] = useState<ConnectionSortField>('bytes');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [viewMode, setViewMode] = useViewMode();
  const [conversationModalOpen, setConversationModalOpen] = useState(false);
  const [selectedConnection, setSelectedConnection] = useState<ConnectionSummary | null>(null);
  const [layerFilter, setLayerFilter] = useState<'all' | 'transport' | 'network'>('all');
  const [ipVersionFilter, setIpVersionFilter] = useState<'all' | 'ipv4' | 'ipv6'>('all');

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Initialize search query from URL parameter
  useEffect(() => {
    if (router.isReady && router.query.search) {
      setSearchQuery(router.query.search as string);
    }
  }, [router.isReady, router.query.search]);

  const communityIds = useMemo(
    () => isCommunityIDFilterActive ? Array.from(selectedCommunityIDs).sort() : [],
    [isCommunityIDFilterActive, selectedCommunityIDs]
  );

  // Fetch only matching connections when the cross-page Community ID filter is active.
  const observationId = typeof router.query.observationId === 'string' ? router.query.observationId : '';
  const snapshotSequence = typeof router.query.snapshotSequence === 'string' ? router.query.snapshotSequence : '';
  const evidenceInputFile = typeof router.query.inputFile === 'string' ? router.query.inputFile : '';
  const { data: connectionsData, error, mutate } = useSWR<ConnectionsResponse>(
    ['connections', layerFilter, ipVersionFilter, communityIds, observationId, snapshotSequence, evidenceInputFile],
    () => {
      const params = new URLSearchParams({ layer: layerFilter, ipVersion: ipVersionFilter });
      communityIds.forEach(id => params.append('communityId', id));
      if (observationId || snapshotSequence) { params.set('observationId', observationId); params.set('snapshotSequence', snapshotSequence); }
      if (evidenceInputFile) params.set('inputFile', evidenceInputFile);
      return fetch(`${getBackendUrl()}/api/connections?${params}`).then(async res => { if (!res.ok) throw new Error(await res.text()); return res.json(); });
    },
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  // Fetch credentials to check which connections have secrets
  const { data: credentialsData, mutate: mutateSecrets } = useSWR<SecretsResponse>(
    'secrets',
    () => fetch(`${getBackendUrl()}/api/secrets`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  const connections = connectionsData?.connections || [];
  const totalCount = connectionsData?.totalCount || 0;

  // Build a set of community IDs that have credentials for quick lookup
  const credentialCommunityIds = useMemo(() => {
    const ids = new Set<string>();
    if (credentialsData?.secrets) {
      for (const cred of credentialsData.secrets) {
        if (cred.communityId) {
          ids.add(cred.communityId);
        }
      }
    }
    return ids;
  }, [credentialsData]);

  // Helper function to check if a connection has credentials
  const hasSecrets = useCallback((conn: ConnectionSummary): boolean => {
    return conn.communityId ? credentialCommunityIds.has(conn.communityId) : false;
  }, [credentialCommunityIds]);

  // Helper function to get the flow identifier for credentials search
  const getFlowIdentForSecret = useCallback((conn: ConnectionSummary): string => {
    // Try to find the exact credential for this connection and return its flow
    if (credentialsData?.secrets && conn.communityId) {
      const cred = credentialsData.secrets.find(c => c.communityId === conn.communityId);
      if (cred?.flow) {
        return cred.flow;
      }
    }
    // Fallback: construct a search query from the connection details
    return `${conn.srcIP}:${conn.srcPort}`;
  }, [credentialsData]);

  // Handle sort column click
  const handleSort = (field: ConnectionSortField) => {
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
  const filteredConnections = useMemo(() => {
    // Keep link-only observations in Records and in the explicit network view.
    let filtered = layerFilter === 'network' ? connections : connections.filter(c => c.srcIP || c.dstIP);

    // Apply Community ID filter first (if active)
    if (isCommunityIDFilterActive && selectedCommunityIDs.size > 0) {
      filtered = filtered.filter(c => 
        c.communityId && selectedCommunityIDs.has(c.communityId)
      );
    }

    // Apply search filter
    if (searchQuery) {
      // Handle special "external" filter for threat hunting
      if (searchQuery.toLowerCase() === 'external') {
        filtered = filtered.filter(c => c.isExternal);
      } else {
        // Split search query by comma or space to support multiple search terms
        const searchTerms = searchQuery
          .split(/[,\s]+/)  // Split by comma or whitespace
          .map(term => term.trim())
          .filter(term => term.length > 0);  // Remove empty strings
        
        filtered = filtered.filter(c => {
          // Build full connection string in multiple formats to support various search patterns
          const fullConnectionArrow = `${c.srcIP}:${c.srcPort}->${c.dstIP}:${c.dstPort}`.toLowerCase();
          const fullConnectionDash = `${c.srcIP}:${c.srcPort}-${c.dstIP}:${c.dstPort}`.toLowerCase();
          const fullConnectionUnicode = `${c.srcIP}:${c.srcPort}→${c.dstIP}:${c.dstPort}`.toLowerCase();
          
          // Check if connection matches ANY of the search terms (OR logic)
          return searchTerms.some(query => {
            const queryLower = query.toLowerCase();
            return (
              // Check full connection strings
              fullConnectionArrow.includes(queryLower) ||
              fullConnectionDash.includes(queryLower) ||
              fullConnectionUnicode.includes(queryLower) ||
              // Check individual fields
              c.srcIP.toLowerCase().includes(queryLower) ||
              c.dstIP.toLowerCase().includes(queryLower) ||
              c.srcPort.toLowerCase().includes(queryLower) ||
              c.dstPort.toLowerCase().includes(queryLower) ||
              (c.applicationProto || '').toLowerCase().includes(queryLower) ||
              (c.transportProto || '').toLowerCase().includes(queryLower) ||
              (c.applications || []).some(a => a.toLowerCase().includes(queryLower)) ||
              // Also search by SNI
              (c.sni || '').toLowerCase().includes(queryLower)
            );
          });
        });
      }
    }

    // Apply sorting with stable secondary sort by endpoints
    filtered = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'endpoints': {
          const endpointA = `${a.srcIP}:${a.srcPort}-${a.dstIP}:${a.dstPort}`;
          const endpointB = `${b.srcIP}:${b.srcPort}-${b.dstIP}:${b.dstPort}`;
          comparison = endpointA.localeCompare(endpointB);
          break;
        }
        case 'protocol': {
          const protoA = a.applicationProto || a.transportProto || '';
          const protoB = b.applicationProto || b.transportProto || '';
          comparison = protoA.localeCompare(protoB);
          break;
        }
        case 'packets':
          comparison = a.numPackets - b.numPackets;
          break;
        case 'bytes':
          comparison = a.totalSize - b.totalSize;
          break;
        case 'duration':
          comparison = a.duration - b.duration;
          break;
      }
      // Stable secondary sort by community ID or endpoints for consistent ordering
      if (comparison === 0) {
        const idA = a.communityId || `${a.srcIP}:${a.srcPort}-${a.dstIP}:${a.dstPort}`;
        const idB = b.communityId || `${b.srcIP}:${b.srcPort}-${b.dstIP}:${b.dstPort}`;
        comparison = idA.localeCompare(idB);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [connections, searchQuery, sortField, sortOrder, isCommunityIDFilterActive, selectedCommunityIDs]);

  // Paginate connections
  const paginatedConnections = filteredConnections.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Generate row keys for keyboard navigation
  const rowKeys = useMemo(() => 
    paginatedConnections.map((conn, idx) => `${conn.srcIP}-${conn.srcPort}-${conn.dstIP}-${conn.dstPort}-${idx}`),
    [paginatedConnections]
  );

  // Enable keyboard navigation for detail views (UP/DOWN arrows)
  useTableKeyboardNavigation(expandedRow, rowKeys, setExpandedRow);

  // Handler to view conversation - defined here to be available for keyboard navigation
  const handleViewConversation = useCallback((conn: ConnectionSummary) => {
    setSelectedConnection(conn);
    setConversationModalOpen(true);
  }, []);

  // Spacebar to toggle conversation for selected connection
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger when typing in input fields
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }
      
      // Check for spacebar
      if (e.code === 'Space') {
        e.preventDefault();
        
        // If conversation modal is open, close it
        if (conversationModalOpen) {
          setConversationModalOpen(false);
          setSelectedConnection(null);
          return;
        }
        
        // If we have an expanded row, open the conversation
        if (expandedRow) {
          // Find the connection index from the expanded row key
          const idx = parseInt(expandedRow.split('-').pop() || '-1', 10);
          if (idx >= 0 && idx < paginatedConnections.length) {
            const conn = paginatedConnections[idx];
            // Only open conversation if there's payload data
            if (conn.appPayloadSize > 0) {
              handleViewConversation(conn);
            }
          }
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [expandedRow, paginatedConnections, handleViewConversation, conversationModalOpen]);

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
    mutateSecrets();
    // Also refresh charts
    setChartRefreshKey(prev => prev + 1);
  }, [mutate, mutateSecrets]);

  const handleFileChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      await mutate();
      await mutateSecrets();
      
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
  }, [api, mutateStatus, mutate, mutateSecrets, __uiLocale]);

  const handleRowClick = useCallback((key: string) => {
    setExpandedRow(prev => prev === key ? null : key);
  }, []);

  const handleCloseConversationModal = useCallback(() => {
    setConversationModalOpen(false);
    setSelectedConnection(null);
  }, []);

  // Find the index of the currently selected connection in the filtered list
  const selectedConnectionIndex = useMemo(() => {
    if (!selectedConnection) return -1;
    return filteredConnections.findIndex(conn =>
      conn.srcIP === selectedConnection.srcIP &&
      conn.srcPort === selectedConnection.srcPort &&
      conn.dstIP === selectedConnection.dstIP &&
      conn.dstPort === selectedConnection.dstPort
    );
  }, [selectedConnection, filteredConnections]);

  // Find the previous connection index that has payload data
  const findPreviousConnectionWithPayload = useCallback((startIdx: number): number => {
    for (let i = startIdx - 1; i >= 0; i--) {
      if (filteredConnections[i].appPayloadSize > 0) {
        return i;
      }
    }
    return -1;
  }, [filteredConnections]);

  // Find the next connection index that has payload data
  const findNextConnectionWithPayload = useCallback((startIdx: number): number => {
    for (let i = startIdx + 1; i < filteredConnections.length; i++) {
      if (filteredConnections[i].appPayloadSize > 0) {
        return i;
      }
    }
    return -1;
  }, [filteredConnections]);

  // Check if there's a previous connection with payload
  const hasPreviousWithPayload = useMemo(() => {
    return findPreviousConnectionWithPayload(selectedConnectionIndex) !== -1;
  }, [selectedConnectionIndex, findPreviousConnectionWithPayload]);

  // Check if there's a next connection with payload
  const hasNextWithPayload = useMemo(() => {
    return findNextConnectionWithPayload(selectedConnectionIndex) !== -1;
  }, [selectedConnectionIndex, findNextConnectionWithPayload]);

  // Navigate to previous connection in the modal (skip connections without payload)
  const handleNavigatePreviousConnection = useCallback(() => {
    const prevIdx = findPreviousConnectionWithPayload(selectedConnectionIndex);
    if (prevIdx !== -1) {
      const prevConnection = filteredConnections[prevIdx];
      setSelectedConnection(prevConnection);
      
      // Calculate which page this connection is on
      const targetPage = Math.floor(prevIdx / rowsPerPage);
      if (targetPage !== page) {
        setPage(targetPage);
      }
      
      // Update expanded row with the local index within the page
      const localIdx = prevIdx - (targetPage * rowsPerPage);
      const rowKey = `${prevConnection.srcIP}-${prevConnection.srcPort}-${prevConnection.dstIP}-${prevConnection.dstPort}-${localIdx}`;
      setExpandedRow(rowKey);
      
      // Scroll the row into view after state updates
      requestAnimationFrame(() => {
        const rowElement = document.querySelector(`[data-row-key="${rowKey}"]`);
        if (rowElement) {
          rowElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      });
    }
  }, [selectedConnectionIndex, filteredConnections, page, rowsPerPage, findPreviousConnectionWithPayload]);

  // Navigate to next connection in the modal (skip connections without payload)
  const handleNavigateNextConnection = useCallback(() => {
    const nextIdx = findNextConnectionWithPayload(selectedConnectionIndex);
    if (nextIdx !== -1) {
      const nextConnection = filteredConnections[nextIdx];
      setSelectedConnection(nextConnection);
      
      // Calculate which page this connection is on
      const targetPage = Math.floor(nextIdx / rowsPerPage);
      if (targetPage !== page) {
        setPage(targetPage);
      }
      
      // Update expanded row with the local index within the page
      const localIdx = nextIdx - (targetPage * rowsPerPage);
      const rowKey = `${nextConnection.srcIP}-${nextConnection.srcPort}-${nextConnection.dstIP}-${nextConnection.dstPort}-${localIdx}`;
      setExpandedRow(rowKey);
      
      // Scroll the row into view after state updates
      requestAnimationFrame(() => {
        const rowElement = document.querySelector(`[data-row-key="${rowKey}"]`);
        if (rowElement) {
          rowElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      });
    }
  }, [selectedConnectionIndex, filteredConnections, page, rowsPerPage, findNextConnectionWithPayload]);

  const handleDownloadPCAP = useCallback(async (conn: ConnectionSummary) => {
    try {
      // Generate download URL
      const params = new URLSearchParams({
        srcIP: conn.srcIP,
        srcPort: conn.srcPort,
        dstIP: conn.dstIP,
        dstPort: conn.dstPort,
        protocol: conn.transportProto,
      });
      if (conn.timestampFirstNs && conn.timestampLastNs) {
        params.set('startNs', conn.timestampFirstNs);
        params.set('endNs', conn.timestampLastNs);
      }
      const downloadUrl = `${getBackendUrl()}/api/connections/download-pcap?${params}`;
      
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
      a.download = `connection_${conn.srcIP}-${conn.srcPort}_${conn.dstIP}-${conn.dstPort}.pcap`;
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
      learnHint={finalCopyMessage("ui:m_75fb47c5b7ff844f2ea6")} />
  );

  // Memoize summary statistics to avoid recalculation on every render
  const stats = useMemo(() => ({
    totalBytes: connections.reduce((sum, c) => sum + c.totalSize, 0),
    avgDuration: connections.length > 0 
      ? connections.reduce((sum, c) => sum + c.duration, 0) / connections.length 
      : 0,
    uniqueProtocols: new Set(connections.map(c => c.applicationProto || c.transportProto)).size
  }), [connections]);

  if (error) {
    return (
      <Layout title={i18nText("ui:m_e2895a1bb90a495f91fe")} headerAction={fileSelector}><Alert severity="error">{i18nRichText("ui:m_72e874f523952da49aa7", { arg0: renderError(error) })}</Alert></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_e2895a1bb90a495f91fe")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* View Mode Toggle and Layer Filter */}<Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 2 }}>{/* Filter Toggles */}<Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>{/* Layer Filter Toggle */}<ToggleButtonGroup value={layerFilter}
              exclusive
              onChange={(_e, newValue) => {
                if (newValue !== null) {
                  setLayerFilter(newValue);
                  setPage(0);
                }
              }}
              size="small"
              data-learn={i18nText("ui:m_32b7a6bcfd18caeb3655")}><ToggleButton value="all"><LayersIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
                {i18nRichText("ui:m_b4367c874681d7a0e11d", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
              </ToggleButton><ToggleButton value="transport"><HubIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
                {i18nRichText("ui:m_0d0c68c9c605e38f9b11", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
              </ToggleButton><ToggleButton value="network"><DeviceHubIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
                {i18nRichText("ui:m_a15de6b2b70ca2aad4bb", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>{chunks}</Box> })}
              </ToggleButton></ToggleButtonGroup>{/* IP Version Filter Toggle */}<ToggleButtonGroup value={ipVersionFilter}
              exclusive
              onChange={(_e, newValue) => {
                if (newValue !== null) {
                  setIpVersionFilter(newValue);
                  setPage(0);
                }
              }}
              size="small"
              data-learn={i18nText("ui:m_910503c87900ac69b7cf")}><ToggleButton value="all">
                {i18nRichText("ui:m_e4ca25bee4f9ac142fd8", { tag0: (chunks: import('react').ReactNode[]) => <Box component="span">{chunks}</Box> })}
              </ToggleButton><ToggleButton value="ipv4"><Box component="span">IPv4</Box></ToggleButton><ToggleButton value="ipv6"><Box component="span">IPv6</Box></ToggleButton></ToggleButtonGroup></Box>{/* View Mode Toggle */}<ToggleButtonGroup value={viewMode}
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
        <StatBoxGrid><StatBox icon={<CableIcon color="primary" />}
            label={i18nText("ui:m_df42fa1f07f31c604536")}
            value={totalCount}
            learnHint={translate("ui:m_70c95e762987b3a23230")} /><StatBox icon={<TrendingUpIcon color="success" />}
            label={i18nText("ui:m_5d5e198526c29a315aa1")}
            value={formatBytes(stats.totalBytes)}
            learnHint={translate("ui:m_e42d6deef3e608fc67f1")} /><StatBox icon={<TimerIcon color="warning" />}
            label={i18nText("ui:m_3fce9da035783ad1d5c1")}
             value={formatQuantity(stats.avgDuration / 1e9, 's')}
            learnHint={translate("ui:m_87770ddc9f759a972386")} /><StatBox icon={<SpeedIcon color="info" />}
            label={i18nText("ui:m_47cff888727c924f0ff3")}
            value={stats.uniqueProtocols}
            learnHint={translate("ui:m_312ea57fcd479fa65e5e")} /></StatBoxGrid>
        )}{/* Visualization Charts - Only show in chart mode */}{viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_8f080af74ff8d1e89117")}
                  key={`top-by-traffic-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/top-by-traffic`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_ca4b005e19b0ef531990")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_e8238b9b72c23ae32c0b")}
                  key={`protocols-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/protocols?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_482e3d02454bb91d5c35")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_69f372239fa85e50068e")}
                  key={`applications-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/applications`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_ae0a28dbe2f164151ca0")} /></CardContent></Card></Grid><Grid item xs={12} md={6}><Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}><CardContent sx={{ height: '100%', p: 1 }}><ChartFrame data-learn={i18nText("ui:m_9dae62920fda265626c6")}
                  key={`duration-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/duration`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title={i18nText("ui:m_25a3bcf56e513f0ec0e5")} /></CardContent></Card></Grid></Grid>
        )}{/* Filters and Actions - Only show in table mode */}{viewMode === 'table' && (
        <><Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder={i18nText("ui:m_c5b1bdf92d963f598468")}
            learnHint={translate("ui:m_2cf257dd4837117c9913")} /><Button data-learn={i18nText("ui:m_de255637ea3619b53e95")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small">
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button>{searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              {i18nRichText("ui:m_fb8e45560167c710639e", { arg0: filteredConnections.length, arg1: totalCount })}
            </Typography>
          ) : null}</Box>{/* Quick Filters for Threat Hunting */}<Box sx={{ mb: 2 }} data-learn={i18nText("ui:m_8d6588839c2e79ad5101")}><Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            {i18nText("ui:m_d1ed1037b4c89f1fda3a")}
          </Typography><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}><Chip label={i18nText("ui:m_94e3bad4d012da53d8f2")}
              size="small"
              color={searchQuery.includes('NONSTANDARD_HTTP') ? 'error' : 'default'}
              variant={searchQuery.includes('NONSTANDARD_HTTP') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('NONSTANDARD_HTTP') ? prev.replace('NONSTANDARD_HTTP', '').trim() : (prev ? `${prev} NONSTANDARD_HTTP` : 'NONSTANDARD_HTTP'));
                setPage(0);
              }}
              title={i18nText("ui:m_9c55462f31a780285bfd")} /><Chip label={i18nText("ui:m_d40f7db45039b12303c4")}
              size="small"
              color={searchQuery.includes('TOR') ? 'error' : 'default'}
              variant={searchQuery.includes('TOR') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('TOR') ? prev.replace('TOR', '').trim() : (prev ? `${prev} TOR` : 'TOR'));
                setPage(0);
              }}
              title={i18nText("ui:m_544058e75a67ecc59c86")} /><Chip label={i18nText("ui:m_a989dfe6d1912f90b8d6")}
              size="small"
              color={searchQuery.includes('SOCKS') ? 'warning' : 'default'}
              variant={searchQuery.includes('SOCKS') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('SOCKS') ? prev.replace('SOCKS', '').trim() : (prev ? `${prev} SOCKS` : 'SOCKS'));
                setPage(0);
              }}
              title={i18nText("ui:m_13ba9acb454c67b1922f")} /><Chip label={i18nText("ui:m_c5faa71c567c7657640c")}
              size="small"
              color={searchQuery.includes('IRC') ? 'warning' : 'default'}
              variant={searchQuery.includes('IRC') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('IRC') ? prev.replace('IRC', '').trim() : (prev ? `${prev} IRC` : 'IRC'));
                setPage(0);
              }}
              title={i18nText("ui:m_799b9244e524210047bc")} /><Chip label={i18nText("ui:m_0ff801a6d22d591017a3")}
              size="small"
              color={searchQuery.includes('TELNET') ? 'warning' : 'default'}
              variant={searchQuery.includes('TELNET') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('TELNET') ? prev.replace('TELNET', '').trim() : (prev ? `${prev} TELNET` : 'TELNET'));
                setPage(0);
              }}
              title={i18nText("ui:m_30c9d9dbf97141c6e63c")} /><Chip label={i18nText("ui:m_a19a02718f3abbad7ca4")}
              size="small"
              color={searchQuery.includes('OPENVPN') || searchQuery.includes('WIREGUARD') ? 'info' : 'default'}
              variant={searchQuery.includes('OPENVPN') || searchQuery.includes('WIREGUARD') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasVpn = searchQuery.includes('OPENVPN') || searchQuery.includes('WIREGUARD');
                if (hasVpn) {
                  setSearchQuery(prev => prev.replace('OPENVPN', '').replace('WIREGUARD', '').trim());
                } else {
                  setSearchQuery(prev => prev ? translate("ui:m_d3278b801eed3cf9413f", { arg0: prev }) : translate("ui:m_1380c48c55cc6a3da417"));
                }
                setPage(0);
              }}
              title={i18nText("ui:m_2fe97f36af22debd1078")} /><Chip label={i18nText("ui:m_41542b497771b413dedf")}
              size="small"
              color={searchQuery.includes('MINING') || searchQuery.includes('STRATUM') ? 'error' : 'default'}
              variant={searchQuery.includes('MINING') || searchQuery.includes('STRATUM') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasMining = searchQuery.includes('MINING') || searchQuery.includes('STRATUM');
                if (hasMining) {
                  setSearchQuery(prev => prev.replace('MINING', '').replace('STRATUM', '').trim());
                } else {
                  setSearchQuery(prev => prev ? translate("ui:m_192a1b34454054f4a392", { arg0: prev }) : translate("ui:m_d286edbf210489a46e01"));
                }
                setPage(0);
              }}
              title={i18nText("ui:m_507887dc78ad263a9d40")} /><Chip label={i18nText("ui:m_6b67dbb76130bdd2d7cf")}
              size="small"
              color={searchQuery.includes('BITTORRENT') ? 'info' : 'default'}
              variant={searchQuery.includes('BITTORRENT') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('BITTORRENT') ? prev.replace('BITTORRENT', '').trim() : (prev ? `${prev} BITTORRENT` : 'BITTORRENT'));
                setPage(0);
              }}
              title={i18nText("ui:m_e6e6091d24a1e0e76824")} /><Chip label={i18nText("ui:m_02f22e676b2a4c00cd38")}
              size="small"
              color={searchQuery.includes('RDP') || searchQuery.includes('VNC') || searchQuery.includes('TEAMVIEWER') ? 'warning' : 'default'}
              variant={searchQuery.includes('RDP') || searchQuery.includes('VNC') || searchQuery.includes('TEAMVIEWER') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasRemote = searchQuery.includes('RDP') || searchQuery.includes('VNC') || searchQuery.includes('TEAMVIEWER');
                if (hasRemote) {
                  setSearchQuery(prev => prev.replace('RDP', '').replace('VNC', '').replace('TEAMVIEWER', '').trim());
                } else {
                  setSearchQuery(prev => prev ? translate("ui:m_c8befb82f31eb3644f63", { arg0: prev }) : translate("ui:m_1c5ee134b9daa0bf61c1"));
                }
                setPage(0);
              }}
              title={i18nText("ui:m_31ff6e5244d1b1f8643a")} /><Chip label={i18nText("ui:m_c711a1ab4dd36a7ab798")}
              size="small"
              color={searchQuery === 'external' ? 'primary' : 'default'}
              variant={searchQuery === 'external' ? 'filled' : 'outlined'}
              onClick={() => {
                // Special filter - this will be handled differently in the filter logic
                setSearchQuery(prev => prev === 'external' ? '' : 'external');
                setPage(0);
              }}
              title={i18nText("ui:m_da28f849064a6fc9b4c2")} /><Chip label={i18nText("ui:m_53354555d5685fa2a921")}
              size="small"
              color={searchQuery.includes('MYSQL') || searchQuery.includes('POSTGRES') || searchQuery.includes('MONGODB') ? 'info' : 'default'}
              variant={searchQuery.includes('MYSQL') || searchQuery.includes('POSTGRES') || searchQuery.includes('MONGODB') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasDb = searchQuery.includes('MYSQL') || searchQuery.includes('POSTGRES') || searchQuery.includes('MONGODB');
                if (hasDb) {
                  setSearchQuery(prev => prev.replace('MYSQL', '').replace('POSTGRES', '').replace('MONGODB', '').trim());
                } else {
                  setSearchQuery(prev => prev ? translate("ui:m_3ea6c5d804bbca6b0eae", { arg0: prev }) : translate("ui:m_7e5f1362329b8ef8390f"));
                }
                setPage(0);
              }}
              title={i18nText("ui:m_da0036a88cfce955b4de")} />{searchQuery && (
              <Chip label={i18nText("ui:m_0cb3d73ec88de1474e7b")}
                size="small"
                color="secondary"
                onClick={() => {
                  setSearchQuery('');
                  setPage(0);
                }} />
            )}</Box></Box>{/* Connections Table */}{!connectionsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}><CircularProgress /></Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}><CableIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
              {i18nText("ui:m_d5a5cea5f5402486de63")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_1a1fdc66ee2d877e57af")}
            </Typography></Paper>
        ) : (
          <ResponsiveDataView data={paginatedConnections}
            totalCount={filteredConnections.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(conn) => {
              const idx = paginatedConnections.indexOf(conn);
              const rowKey = `${conn.srcIP}-${conn.srcPort}-${conn.dstIP}-${conn.dstPort}-${idx}`;
              handleRowClick(rowKey);
            }}
            renderCard={(conn) => (
              <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Box display="flex" alignItems="center" gap={0.5} flexWrap="wrap"><Typography variant="subtitle2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'error.main' }}>{conn.srcIP || conn.srcMAC || i18nText("ui:m_8dc598ebf1e055830140")}{conn.srcPort ? `:${conn.srcPort}` : ''}</Typography><Typography variant="caption" color="text.secondary">→</Typography><Typography variant="subtitle2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'primary.main' }}>{conn.dstIP || conn.dstMAC || i18nText("ui:m_8dc598ebf1e055830140")}{conn.dstPort ? `:${conn.dstPort}` : ''}</Typography></Box><Box display="flex" gap={2} mt={0.5} flexWrap="wrap" alignItems="center">{conn.transportProto && conn.transportProto !== 'Unknown' && conn.transportProto !== 'Payload' && (
                      <Chip label={conn.transportProto} size="small" color="primary" sx={{ fontSize: '0.7rem' }} />
                    )}<Typography variant="caption" color="text.secondary">{formatBytes(conn.totalSize)}</Typography><Typography variant="caption" color="text.secondary">
                      {i18nRichText("ui:m_9a343c2d3b0d6ef0ef21", { arg0: conn.numPackets.toLocaleString(getUILocale()) })}
                    </Typography>{conn.sni && (
                      <Typography variant="caption" color="success.main" sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}>{conn.sni}</Typography>
                    )}{conn.serverPortName && (
                      <Chip label={conn.serverPortName} size="small" color="secondary" variant="outlined" sx={{ fontSize: '0.65rem' }} />
                    )}</Box></CardContent></Card>
            )}
            desktopTable={<TableContainer component={Paper}><Table size="small" data-learn={i18nText("ui:m_87ed6e96071f7fbc34a8")}><TableHead><TableRow><TableCell width={40}></TableCell><TableCell><TableSortLabel data-learn={i18nText("ui:m_b33c0159540f76d2f72e")}
                        active={sortField === 'endpoints'}
                        direction={sortField === 'endpoints' ? sortOrder : 'asc'}
                        onClick={() => handleSort('endpoints')}>
                        {i18nText("ui:m_6e3eaaf519e2d29c1f65")}
                      </TableSortLabel></TableCell><TableCell sx={{ width: 80, minWidth: 60 }}><TableSortLabel data-learn={i18nText("ui:m_89904587a7b400efc37e")}
                        active={sortField === 'protocol'}
                        direction={sortField === 'protocol' ? sortOrder : 'asc'}
                        onClick={() => handleSort('protocol')}>
                        {i18nText("ui:m_2d5b0d13af7edb332cfd")}
                      </TableSortLabel></TableCell><TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}><TableSortLabel data-learn={i18nText("ui:m_ab1f49eee5f86c44d6d4")}
                        active={sortField === 'packets'}
                        direction={sortField === 'packets' ? sortOrder : 'asc'}
                        onClick={() => handleSort('packets')}>
                        {i18nText("ui:m_ebe2f7ca86cd1049725b")}
                      </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel data-learn={i18nText("ui:m_97a6a8e2139ed3ed4a4f")}
                        active={sortField === 'bytes'}
                        direction={sortField === 'bytes' ? sortOrder : 'asc'}
                        onClick={() => handleSort('bytes')}>
                        {i18nText("ui:m_dc58fb07f5e14e63a67b")}
                      </TableSortLabel></TableCell><TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}><TableSortLabel data-learn={i18nText("ui:m_d37ad3a840c841ac53ff")}
                        active={sortField === 'duration'}
                        direction={sortField === 'duration' ? sortOrder : 'asc'}
                        onClick={() => handleSort('duration')}>
                        {i18nText("ui:m_9777689642640ff1e001")}
                      </TableSortLabel></TableCell><TableCell data-learn={i18nText("ui:m_300d0e58efe870ba8f73")}>
                      {i18nText("ui:m_157a9e96d1598652fe50")}
                    </TableCell><TableCell data-learn={i18nText("ui:m_eab07128146304e944fa")}>SNI
                    </TableCell><TableCell>{i18nText("ui:m_22e33af3cdbf3a8a93d6")}</TableCell></TableRow></TableHead><TableBody>{paginatedConnections.map((conn, idx) => {
                    const rowKey = `${conn.srcIP}-${conn.srcPort}-${conn.dstIP}-${conn.dstPort}-${idx}`;
                    return (
                      <><TableRow key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn={i18nText("ui:m_9fbef78456623443ce4f")}><TableCell><IconButton size="small" data-learn={i18nText("ui:m_29140f9632c238079e2a")}><ExpandMoreIcon sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} /></IconButton></TableCell><TableCell><Box sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                display: 'flex',
                                alignItems: 'center',
                              }}
                              data-learn={i18nText("ui:m_8f28ea9757e3b09fe032")}>{conn.srcIP ? (
                                <><Box component="span" sx={{ color: 'error.main', fontWeight: 'bold' }}>{conn.srcIP}</Box>{conn.srcPort && (
                                    <><Box component="span" sx={{ color: 'text.secondary' }}>:</Box><Box component="span" sx={{ color: 'warning.main', fontWeight: 'medium' }}>{conn.srcPort}</Box></>
                                  )}<Box component="span" sx={{ color: 'text.secondary', mx: 0.5 }}>→</Box><Box component="span" sx={{ color: 'primary.main', fontWeight: 'bold' }}>{conn.dstIP}</Box>{conn.dstPort && (
                                    <><Box component="span" sx={{ color: 'text.secondary' }}>:</Box><Box component="span" sx={{ color: 'warning.main', fontWeight: 'medium' }}>{conn.dstPort}</Box></>
                                  )}</>
                              ) : (
                                <><Box component="span" sx={{ color: 'error.main', fontWeight: 'bold' }}>{conn.srcMAC || i18nText("ui:m_8dc598ebf1e055830140")}</Box><Box component="span" sx={{ color: 'text.secondary', mx: 0.5 }}>→</Box><Box component="span" sx={{ color: 'primary.main', fontWeight: 'bold' }}>{conn.dstMAC || i18nText("ui:m_8dc598ebf1e055830140")}</Box></>
                              )}</Box></TableCell><TableCell>{conn.transportProto && conn.transportProto !== 'Unknown' && conn.transportProto !== 'Payload' ? (
                              <Chip data-learn={i18nText("ui:m_4d24a5abe5a5f8513802")}
                                label={conn.transportProto}
                                size="small"
                                color="primary"
                                sx={{ fontSize: '0.7rem' }} />
                            ) : null}</TableCell><TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Typography variant="body2">{conn.numPackets.toLocaleString(getUILocale())}</Typography></TableCell><TableCell align="right"><Typography variant="body2">{formatBytes(conn.totalSize)}</Typography></TableCell><TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Typography variant="body2">{i18nNumber((conn.duration / 1e9), { minimumFractionDigits: 3, maximumFractionDigits: 3, useGrouping: false })}s
                            </Typography></TableCell><TableCell>{conn.serverPortName ? (
                              <Chip data-learn={i18nText("ui:m_d3bb2ecf8990c90e4b18")}
                                label={conn.serverPortName}
                                size="small"
                                color="secondary"
                                variant="outlined"
                                title={conn.serverPortName}
                                sx={{ 
                                  fontSize: '0.7rem',
                                  maxWidth: 100,
                                  '& .MuiChip-label': {
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                  }
                                }} />
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>{conn.dstPort || '-'}</Typography>
                            )}</TableCell><TableCell>{conn.sni ? (
                              <Typography variant="body2" 
                                sx={{ 
                                  fontFamily: 'monospace', 
                                  fontSize: '0.8rem',
                                  color: 'success.main',
                                  fontWeight: 'medium',
                                  maxWidth: 200,
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                }}
                                title={conn.sni}
                                data-learn={i18nText("ui:m_59251c1295e7002a7d64")}>{conn.sni}</Typography>
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>-
                              </Typography>
                            )}</TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(conn.applications || []).slice(0, 2).map((app) => (
                                <Chip key={`${rowKey}-app-${app}`}
                                  label={app}
                                  size="small"
                                  color="info"
                                  sx={{ fontSize: '0.7rem', height: 20 }}
                                  data-learn={i18nText("ui:m_92e8f3909a003d296dbb")} />
                              ))}{(conn.applications || []).length > 2 && (
                                <Chip label={`+${(conn.applications || []).length - 2}`}
                                  size="small"
                                  color="info"
                                  sx={{ fontSize: '0.7rem', height: 20 }}
                                  data-learn={i18nText("ui:m_3295144aac96b469a4b5")} />
                              )}</Box></TableCell></TableRow>{/* Expandable Row Details */}<TableRow><TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={9}><Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit><Box sx={{ py: 2 }} data-learn={i18nText("ui:m_053a27d7212c4a232703")}>{conn.srcIP && <BehaviorAssetContext asset={conn.srcIP} />}{conn.dstIP && <BehaviorAssetContext asset={conn.dstIP} />}<Grid container spacing={2}>{/* Time Range */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_4d5b7908dabae92d8fae")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_15d5e1f7d677437722bf", { arg0: formatTimestamp(conn.timestampFirst, 'nanoseconds') })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_0f8d6be8cc3baa6c1c17", { arg0: formatTimestamp(conn.timestampLast, 'nanoseconds') })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_e9cb34b07e56d86b4152", { arg0: i18nNumber((conn.duration / 1e9), { minimumFractionDigits: 3, maximumFractionDigits: 3, useGrouping: false }) })}
                                    </Typography></Grid>{/* Link Layer */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_cac8e5f36916ae416e13")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_a6650874cb35a85bf637", { arg0: conn.linkProto })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_9cdb79d7b3672124a63c", { arg0: conn.srcMAC })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_f453d517b088f97d2700", { arg0: conn.dstMAC })}
                                    </Typography></Grid>{/* Network & Transport Layer */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_ace55e647b8e63d4f939")}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_8d3b23ecd6da12087208", { arg0: conn.networkProto })}
                                    </Typography><Typography variant="body2" color="text.secondary">
                                      {i18nRichText("ui:m_329f7e78e6b4b9b7dde2", { arg0: conn.transportProto })}
                                    </Typography>{conn.applicationProto && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_ab321066e521c1ff6721", { arg0: conn.applicationProto })}
                                      </Typography>
                                    )}</Grid>{/* Protocol Detection */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_0f85b3805ad82735621e")}
                                    </Typography>{conn.serverPortName && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_509f15265a1b33cfac7c", { arg0: conn.serverPortName })}
                                      </Typography>
                                    )}{conn.detectedProtocolName && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nRichText("ui:m_b737f984d41010cf2530", { arg0: conn.detectedProtocolName })}
                                      </Typography>
                                    )}{conn.sni && (
                                      <Typography variant="body2" color="text.secondary" data-learn={i18nText("ui:m_0907da9d1b4b52e9af8f")}>
                                        {i18nRichText("ui:m_3177e7ec2023a0031933", { arg0: conn.sni, tag0: (chunks: import('react').ReactNode[]) => <Box component="span" sx={{ fontFamily: 'monospace', color: 'success.main', fontWeight: 'medium' }}>{chunks}</Box> })}
                                      </Typography>
                                    )}{!conn.serverPortName && !conn.detectedProtocolName && !conn.sni && (
                                      <Typography variant="body2" color="text.secondary">
                                        {i18nText("ui:m_94ac75a9c8861f596043")}
                                      </Typography>
                                    )}</Grid>{/* Community ID for Cross-Tool Correlation */}{conn.communityId && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_6520556565357b546291")}>
                                        {i18nText("ui:m_05fb20693d84c7cd3199")}
                                      </Typography><CommunityIDChip communityId={conn.communityId} mode="text" /></Grid>
                                  )}{conn.observationId && (
                                    <Grid item xs={12}><RelatedEvidence selector={{ observationId: conn.observationId }} inputFile={evidenceInputFile || undefined} /></Grid>
                                  )}{conn.dnsResolutionState && <Grid item xs={12}><Typography variant="subtitle2">{i18nText("ui:m_a9e08002f11817e777a6")}</Typography><Typography variant="body2" color="text.secondary">{conn.dnsResolutionState === 'resolved' ? i18nText("ui:m_e7bef36cde640c08ffb5", { arg0: conn.dnsResolvedName, arg1: conn.dnsResolvedAtNs }) : i18nText("ui:m_94878c933e87ed00f80a")}</Typography></Grid>}{/* Traffic Statistics */}<Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                      {i18nText("ui:m_3bc8db0bbdf6894658d0")}
                                    </Typography><DirectionalTraffic client={conn.bytesClientToServer} server={conn.bytesServerToClient} /><Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                                      {i18nRichText("ui:m_7cc3d81e820d86bf7152", { arg0: conn.numPackets, arg1: formatBytes(conn.appPayloadSize), arg2: formatBytes(conn.totalSize) })}
                                    </Typography><ProducerConsumerEvidence produced={conn.bytesClientToServer} consumed={conn.bytesServerToClient} /></Grid>{/* Connection Indicators */}{(conn.isExternal || conn.isBroadcast || conn.isMulticast) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_d814f324cb17485c70c2")}>
                                        {i18nText("ui:m_87236b71a5653c110639")}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{conn.isExternal && (
                                          <Chip label={i18nText("ui:m_c711a1ab4dd36a7ab798")} 
                                            size="small" 
                                            color="warning"
                                            sx={{ fontSize: '0.75rem' }}
                                            data-learn={i18nText("ui:m_ba12459c3165c83f1252")} />
                                        )}{conn.isBroadcast && (
                                          <Chip label={i18nText("ui:m_f5d97648864306b44e41")} 
                                            size="small" 
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }}
                                            data-learn={i18nText("ui:m_5b92d678d66ce7a8c6f9")} />
                                        )}{conn.isMulticast && (
                                          <Chip label={i18nText("ui:m_f041ad44f559ef861b34")} 
                                            size="small" 
                                            color="secondary"
                                            sx={{ fontSize: '0.75rem' }}
                                            data-learn={i18nText("ui:m_13bae004766d740fe4fa")} />
                                        )}</Box></Grid>
                                  )}{/* Security Behavioral Analysis */}{(conn.packetsClientToServer > 0 || conn.packetsServerToClient > 0) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom>
                                        {i18nText("ui:m_cf3c421f43031ebc70ae")}
                                      </Typography><Table size="small" aria-label={i18nText("ui:m_bbb18eb2d6e3e6325253")} sx={{ '& td, & th': { px: 1, py: 0.5 }, fontVariantNumeric: 'tabular-nums' }}><TableHead><TableRow><TableCell>{i18nText("ui:m_5f5b47ae9f5f9a2f3aee")}</TableCell><TableCell align="right">{i18nText("ui:m_3ef016cb00567258ba22")}</TableCell><TableCell align="right">{i18nText("ui:m_5c679d5f4ef56da5ae74")}</TableCell></TableRow></TableHead><TableBody><TableRow><TableCell>{i18nText("ui:m_ebe2f7ca86cd1049725b")}</TableCell><TableCell align="right">{conn.packetsClientToServer?.toLocaleString(getUILocale()) || 0}</TableCell><TableCell align="right">{conn.packetsServerToClient?.toLocaleString(getUILocale()) || 0}</TableCell></TableRow><TableRow><TableCell>{i18nText("ui:m_f0d76dd07919d693cf38")}</TableCell><TableCell align="right">{conn.avgPacketSizeClientToServer > 0 ? `${conn.avgPacketSizeClientToServer} B` : '—'}</TableCell><TableCell align="right">{conn.avgPacketSizeServerToClient > 0 ? `${conn.avgPacketSizeServerToClient} B` : '—'}</TableCell></TableRow></TableBody></Table><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mt: 1 }}>{conn.byteRatio > 0 && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}><Typography variant="body2" color="text.secondary">
                                            {i18nText("ui:m_9de546895e7f21ee021c")}
                                          </Typography><Chip label={i18nNumber(conn.byteRatio, { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false })} 
                                            size="small" 
                                            color="default"
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn={i18nText("ui:m_4aabd60e7d4272603c06")} /></Box>
                                      )}{conn.packetRatio > 0 && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}><Typography variant="body2" color="text.secondary">
                                            {i18nText("ui:m_f6b742362978911a4eb9")}
                                          </Typography><Chip label={i18nNumber(conn.packetRatio, { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false })} 
                                            size="small" 
                                            color="default"
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn={i18nText("ui:m_057cf421b252cc96874c")} /></Box>
                                      )}</Box></Grid>
                                  )}{/* TCP Flags */}{conn.transportProto === 'TCP' && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nText("ui:m_904071fc7fd409dfe1b3")}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{conn.numSYNFlags > 0 && (
                                          <Chip label={i18nText("ui:m_6b899f6e285801b1a603", { arg0: conn.numSYNFlags })} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}{conn.numACKFlags > 0 && (
                                          <Chip label={i18nText("ui:m_d12d9ba57b77e31ea07e", { arg0: conn.numACKFlags })} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}{conn.numFINFlags > 0 && (
                                          <Chip label={i18nText("ui:m_c83ca6a2a11eab3c5cf7", { arg0: conn.numFINFlags })} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}{conn.numRSTFlags > 0 && (
                                          <Chip label={i18nText("ui:m_67daab369c25884411b5", { arg0: conn.numRSTFlags })} size="small" variant="outlined" color="error" sx={{ fontSize: '0.75rem' }} />
                                        )}{conn.numPSHFlags > 0 && (
                                          <Chip label={i18nText("ui:m_70df64fbb69194f4469f", { arg0: conn.numPSHFlags })} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}{conn.numURGFlags > 0 && (
                                          <Chip label={i18nText("ui:m_915864e8e0d126c5e262", { arg0: conn.numURGFlags })} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}{conn.numECEFlags > 0 && (
                                          <Chip label={i18nText("ui:m_348dc079f478f24ac5de", { arg0: conn.numECEFlags })} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}{conn.numCWRFlags > 0 && (
                                          <Chip label={i18nText("ui:m_a943d30313a84497fcb5", { arg0: conn.numCWRFlags })} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}{conn.numNSFlags > 0 && (
                                          <Chip label={i18nText("ui:m_06a35cb0d1bb4f056f49", { arg0: conn.numNSFlags })} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}<Chip label={i18nText("ui:m_732f36eee91119ff4eae", { arg0: conn.meanWindowSize })} size="small" variant="outlined" color="info" sx={{ fontSize: '0.75rem' }} /></Box></Grid>
                                  )}{/* JA4L Latency Fingerprints */}{conn.transportProto === 'TCP' && (conn.ja4lClient || conn.ja4lServer) && (
                                    <Grid item xs={12} md={6}><Typography variant="subtitle2" gutterBottom data-learn={i18nText("ui:m_8b160858da38795ee53a")}>
                                        {i18nText("ui:m_8a498eafeba77742227e")}
                                      </Typography>{conn.ja4lClient && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}><Typography variant="body2" color="text.secondary" sx={{ minWidth: '80px' }}>
                                            {i18nText("ui:m_6dec8751e83eb066c39e")}
                                          </Typography><Chip label={conn.ja4lClient} 
                                            size="small" 
                                            color="warning"
                                            variant="outlined"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                                            data-learn={i18nText("ui:m_3507fadff6618eccdf3e")} /><Typography variant="caption" color="text.secondary">
                                            {i18nRichText("ui:m_b58aaf7f569450b43590", { arg0: i18nNumber((conn.tcpRttNanos / 1e6), { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false }) })}
                                          </Typography></Box>
                                      )}{conn.ja4lServer && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}><Typography variant="body2" color="text.secondary" sx={{ minWidth: '80px' }}>
                                            {i18nText("ui:m_ff17783619f47f66e343")}
                                          </Typography><Chip label={conn.ja4lServer} 
                                            size="small" 
                                            color="success"
                                            variant="outlined"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                                            data-learn={i18nText("ui:m_2572ebe85d0fdaa0a8b5")} /><Typography variant="caption" color="text.secondary">
                                            {i18nRichText("ui:m_eccb397c1516acbdd1eb", { arg0: i18nNumber((conn.tlsHandshakeNanos / 1e6), { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false }) })}
                                          </Typography></Box>
                                      )}{conn.synTtl > 0 && (
                                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                                          {i18nRichText("ui:m_cf42f738d2155e773b27", { arg0: conn.synTtl, arg1: 256 - conn.synTtl })}
                                        </Typography>
                                      )}</Grid>
                                  )}{/* All Applications */}{(conn.applications || []).length > 0 && (
                                    <Grid item xs={12}><Typography variant="subtitle2" gutterBottom>
                                        {i18nRichText("ui:m_7977662d224aa0eaa0ec", { arg0: (conn.applications || []).length })}
                                      </Typography><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{(conn.applications || []).map((app) => (
                                          <Chip key={`${rowKey}-app-detail-${app}`}
                                            label={app}
                                            size="small"
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }} />
                                        ))}</Box></Grid>
                                  )}{/* Action Buttons */}<Grid item xs={12}><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>{/* Show Secrets - only show when credentials exist for this connection */}{hasSecrets(conn) && (
                                        <Button data-learn={i18nText("ui:m_14531c1ee0e0abac10b4")}
                                          variant="contained"
                                          color="warning"
                                          startIcon={<VpnKeyIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            const flowIdent = getFlowIdentForSecret(conn);
                                            router.push(`/secrets?search=${encodeURIComponent(flowIdent)}`);
                                          }}
                                          size="small">
                                          {i18nText("ui:m_adeca49d759ca345f2bf")}
                                        </Button>
                                      )}{/* View Conversation - only show when there's actual payload data */}{conn.appPayloadSize > 0 && (
                                        <Button data-learn={i18nText("ui:m_efaa04653c762c701950")}
                                          variant="outlined"
                                          startIcon={<ArticleIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            handleViewConversation(conn);
                                          }}
                                          size="small">
                                          {i18nText("ui:m_905df2e65dcc2d1e18a1")}
                                        </Button>
                                      )}{/* Download PCAP - only for TCP/UDP with ports */}{(conn.transportProto === 'TCP' || conn.transportProto === 'UDP') && (
                                        <Button data-learn={i18nText("ui:m_82b3878b896711109863")}
                                          variant="outlined"
                                          startIcon={<DownloadIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            handleDownloadPCAP(conn);
                                          }}
                                          size="small">
                                          {i18nText("ui:m_c2c52203522b7dc5d8e4")}
                                        </Button>
                                      )}{/* Navigation Buttons */}{[['Client', conn.srcIP], ['Server', conn.dstIP]].filter(([, address]) => address).map(([label, address]) => (
                                        <Button key={label} variant="outlined" size="small" onClick={(event) => { event.stopPropagation(); router.push(`/behavior?asset=${encodeURIComponent(address)}`); }}>
                                          {i18nRichText("ui:m_a307fb9598b2ddd84b61", { arg0: i18nText(label) })}
                                        </Button>
                                      ))}{conn.srcIP && (
                                        <Button data-learn={i18nText("ui:m_fba02971d0134154a552")}
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<ComputerIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/hosts?search=${encodeURIComponent(conn.srcIP)}`);
                                          }}
                                          size="small">
                                          {i18nText("ui:m_ecf8c7d8003c3e4d1f24")}
                                        </Button>
                                      )}{conn.dstIP && (
                                        <Button data-learn={i18nText("ui:m_25a40ba1a3d22dffc3cc")}
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<ComputerIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/hosts?search=${encodeURIComponent(conn.dstIP)}`);
                                          }}
                                          size="small">
                                          {i18nText("ui:m_dee3bdba29105ab5a72b")}
                                        </Button>
                                      )}{(conn.srcMAC || conn.dstMAC) && (
                                        <>{conn.srcMAC && (
                                            <Button data-learn={i18nText("ui:m_edad996e45b128186f66")}
                                              variant="outlined"
                                              color="secondary"
                                              startIcon={<RouterIcon />}
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                router.push(`/devices?search=${encodeURIComponent(conn.srcMAC)}`);
                                              }}
                                              size="small">
                                              {i18nText("ui:m_8910168d81eacd4c1b59")}
                                            </Button>
                                          )}{conn.dstMAC && (
                                            <Button data-learn={i18nText("ui:m_108f1df6485377de8c81")}
                                              variant="outlined"
                                              color="secondary"
                                              startIcon={<RouterIcon />}
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                router.push(`/devices?search=${encodeURIComponent(conn.dstMAC)}`);
                                              }}
                                              size="small">
                                              {i18nText("ui:m_c5342d90ca96c1ce9cd7")}
                                            </Button>
                                          )}</>
                                      )}{conn.dstIP && (
                                        <Button data-learn={i18nText("ui:m_efc61d2ee0a1d7ccfe67")}
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<DnsIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/services?search=${encodeURIComponent(conn.dstIP)}`);
                                          }}
                                          size="small">
                                          {i18nText("ui:m_e1d47e59dd85d4abaa0f")}
                                        </Button>
                                      )}{/* Custom row actions from parent */}{rowActions && rowActions(conn)}</Box></Grid></Grid></Box></Collapse></TableCell></TableRow></>
                    );
                  })}</TableBody></Table></TableContainer>} />
        )}</>
        )}</Box>{/* Conversation Modal */}{selectedConnection && (
        <ConversationModal open={conversationModalOpen}
          onClose={handleCloseConversationModal}
          srcIP={selectedConnection.srcIP}
          srcPort={selectedConnection.srcPort}
          dstIP={selectedConnection.dstIP}
          dstPort={selectedConnection.dstPort}
          protocol={selectedConnection.transportProto}
          onNavigatePrevious={handleNavigatePreviousConnection}
          onNavigateNext={handleNavigateNextConnection}
          hasPrevious={hasPreviousWithPayload}
          hasNext={hasNextWithPayload} />
      )}</Layout>
  );
}
