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
  Grid,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  Typography,
  Alert,
  Collapse,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
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
import Layout from '../components/Layout';
import ConversationModal from '../components/ConversationModal';
import FileSelectorHeader from '../components/FileSelectorHeader';
import CommunityIDChip from '../components/CommunityIDChip';
import SearchInput from '../components/SearchInput';
import StatBox, { StatBoxGrid } from '../components/StatBox';
import { formatBytes, formatTimestamp, getBackendUrl } from '../lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi, useTableKeyboardNavigation, useViewMode } from '../hooks';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

export interface ConnectionSummary {
  timestampFirst: number;
  timestampLast: number;
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

interface CredentialSummary {
  communityId: string;
  flow: string;
}

interface CredentialsResponse {
  credentials: CredentialSummary[];
  totalCount: number;
}

type ConnectionSortField = 'endpoints' | 'protocol' | 'packets' | 'bytes' | 'duration';
type SortOrder = 'asc' | 'desc';

export interface ConnectionsPageProps {
  /** Custom row actions to render in the expanded row details */
  rowActions?: (row: ConnectionSummary) => React.ReactNode;
}

export default function ConnectionsPage({ rowActions }: ConnectionsPageProps = {}) {
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

  // Fetch connections data with layer and IP version filters
  const { data: connectionsData, error, mutate } = useSWR<ConnectionsResponse>(
    ['connections', layerFilter, ipVersionFilter],
    () => fetch(`${getBackendUrl()}/api/connections?layer=${layerFilter}&ipVersion=${ipVersionFilter}`).then(res => res.json()),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  // Fetch credentials to check which connections have secrets
  const { data: credentialsData, mutate: mutateCredentials } = useSWR<CredentialsResponse>(
    'credentials',
    () => fetch(`${getBackendUrl()}/api/credentials`).then(res => res.json()),
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
    if (credentialsData?.credentials) {
      for (const cred of credentialsData.credentials) {
        if (cred.communityId) {
          ids.add(cred.communityId);
        }
      }
    }
    return ids;
  }, [credentialsData]);

  // Helper function to check if a connection has credentials
  const hasCredentials = useCallback((conn: ConnectionSummary): boolean => {
    return conn.communityId ? credentialCommunityIds.has(conn.communityId) : false;
  }, [credentialCommunityIds]);

  // Helper function to get the flow identifier for credentials search
  const getFlowIdentForCredentials = useCallback((conn: ConnectionSummary): string => {
    // Try to find the exact credential for this connection and return its flow
    if (credentialsData?.credentials && conn.communityId) {
      const cred = credentialsData.credentials.find(c => c.communityId === conn.communityId);
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
    let filtered = connections;

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
    mutateCredentials();
    // Also refresh charts
    setChartRefreshKey(prev => prev + 1);
  }, [mutate, mutateCredentials]);

  const handleFileChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      await mutate();
      await mutateCredentials();
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Refresh charts
      setChartRefreshKey(prev => prev + 1);
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert('Failed to switch to this capture');
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate, mutateCredentials]);

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
      });
      const downloadUrl = `${getBackendUrl()}/api/connections/download-pcap?${params}`;
      
      // Fetch the file as a blob
      const response = await fetch(downloadUrl);
      
      if (!response.ok) {
        const errorText = await response.text();
        alert(`Failed to download PCAP: ${errorText}`);
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
      alert(`Failed to download PCAP: ${error}`);
    }
  }, []);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their network connections and flows."
    />
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
      <Layout title="Connections" headerAction={fileSelector}>
        <Alert severity="error">Error loading connections: {error.message}</Alert>
      </Layout>
    );
  }

  return (
    <Layout title="Connections" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        {/* View Mode Toggle and Layer Filter */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 2 }}>
          {/* Filter Toggles */}
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            {/* Layer Filter Toggle */}
            <ToggleButtonGroup
              value={layerFilter}
              exclusive
              onChange={(_e, newValue) => {
                if (newValue !== null) {
                  setLayerFilter(newValue);
                  setPage(0);
                }
              }}
              size="small"
              data-learn="Layer Filter: Filter connections by layer type. 'All' shows all connections. 'Transport' shows TCP/UDP connections. 'Network Only' shows ICMP, IGMP, GRE and other network-layer-only protocols."
            >
              <ToggleButton value="all">
                <LayersIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
                <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                  All
                </Box>
              </ToggleButton>
              <ToggleButton value="transport">
                <HubIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
                <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                  Transport
                </Box>
              </ToggleButton>
              <ToggleButton value="network">
                <DeviceHubIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
                <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                  Network Only
                </Box>
              </ToggleButton>
            </ToggleButtonGroup>

            {/* IP Version Filter Toggle */}
            <ToggleButtonGroup
              value={ipVersionFilter}
              exclusive
              onChange={(_e, newValue) => {
                if (newValue !== null) {
                  setIpVersionFilter(newValue);
                  setPage(0);
                }
              }}
              size="small"
              data-learn="IP Version Filter: Filter connections by IP version. 'All' shows all connections. 'IPv4' shows only IPv4 traffic. 'IPv6' shows only IPv6 traffic."
            >
              <ToggleButton value="all">
                <Box component="span">All IP</Box>
              </ToggleButton>
              <ToggleButton value="ipv4">
                <Box component="span">IPv4</Box>
              </ToggleButton>
              <ToggleButton value="ipv6">
                <Box component="span">IPv6</Box>
              </ToggleButton>
            </ToggleButtonGroup>
          </Box>

          {/* View Mode Toggle */}
          <ToggleButtonGroup
            value={viewMode}
            exclusive
            onChange={(_e, newValue) => {
              if (newValue !== null) {
                setViewMode(newValue);
              }
            }}
            size="small"
            data-learn="View Mode Toggle: Switch between Table mode (showing data in a table) and Chart mode (showing only visualization charts)."
          >
            <ToggleButton value="table">
              <TableChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                Table
              </Box>
            </ToggleButton>
            <ToggleButton value="chart">
              <BarChartIcon sx={{ mr: { xs: 0, sm: 0.5 }, fontSize: 18 }} />
              <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                Chart
              </Box>
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>

        {/* Summary Cards - Only show in table mode */}
        {viewMode === 'table' && (
        <StatBoxGrid>
          <StatBox
            icon={<CableIcon color="primary" />}
            label="Total Connections"
            value={totalCount}
            learnHint="Total Connections: Number of network connections captured in this PCAP file."
          />
          <StatBox
            icon={<TrendingUpIcon color="success" />}
            label="Total Traffic"
            value={formatBytes(stats.totalBytes)}
            learnHint="Total Traffic: Sum of all bytes transferred across all connections."
          />
          <StatBox
            icon={<TimerIcon color="warning" />}
            label="Avg Duration"
            value={`${(stats.avgDuration / 1e9).toFixed(2)}s`}
            learnHint="Avg Duration: Average duration of all network connections."
          />
          <StatBox
            icon={<SpeedIcon color="info" />}
            label="Unique Protocols"
            value={stats.uniqueProtocols}
            learnHint="Unique Protocols: Number of different protocols detected in the connections."
          />
        </StatBoxGrid>
        )}

        {/* Visualization Charts - Only show in chart mode */}
        {viewMode === 'chart' && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Top Connections Chart: Bar chart showing the connections with the most traffic."
                  key={`top-by-traffic-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/top-by-traffic`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Connections by Traffic"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Protocol Distribution: Pie chart showing the distribution of protocols across connections."
                  key={`protocols-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/protocols?showLegend=false`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Protocol Distribution"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Applications Chart: Bar chart showing the top detected applications in the connections."
                  key={`applications-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/applications`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Top Applications"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card sx={{ height: { xs: 300, md: 'calc(50vh - 80px)' }, minHeight: 250, maxHeight: 500 }}>
              <CardContent sx={{ height: '100%', p: 1 }}>
                <iframe
                  data-learn="Duration vs Size: Scatter plot showing the relationship between connection duration and data size."
                  key={`duration-${chartRefreshKey}`}
                  src={`${getBackendUrl()}/api/connections/duration`}
                  style={{
                    width: '100%',
                    height: '100%',
                    border: 'none',
                  }}
                  title="Connection Duration vs Size"
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        )}

        {/* Filters and Actions - Only show in table mode */}
        {viewMode === 'table' && (
        <>
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <SearchInput
            value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0);
            }}
            placeholder="Search connections (comma or space separated)..."
            learnHint="Connection Search: Filter connections by IP addresses, ports, protocols, applications, or full connection strings. Multiple search terms can be separated by commas or spaces (e.g., 192.168.1.1:80->10.0.0.1:443, 172.16.1.1). Use !term to exclude matches."
          />
          
          <Button
            data-learn="Refresh Button: Reload connection data and charts from the server."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
          >
            Refresh
          </Button>
          
          {searchQuery ? (
            <Typography variant="body2" color="text.secondary">
              Showing {filteredConnections.length} of {totalCount} connections
            </Typography>
          ) : null}
        </Box>

        {/* Quick Filters for Threat Hunting */}
        <Box sx={{ mb: 2 }} data-learn="Quick Filters: Click any filter chip to quickly narrow down connections based on common threat hunting patterns. These filters help identify suspicious traffic patterns.">
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            🔍 Quick Filters (Threat Hunting):
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Chip
              label="NONSTANDARD_HTTP"
              size="small"
              color={searchQuery.includes('NONSTANDARD_HTTP') ? 'error' : 'default'}
              variant={searchQuery.includes('NONSTANDARD_HTTP') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('NONSTANDARD_HTTP') ? prev.replace('NONSTANDARD_HTTP', '').trim() : (prev ? `${prev} NONSTANDARD_HTTP` : 'NONSTANDARD_HTTP'));
                setPage(0);
              }}
              title="HTTP-like traffic on non-standard ports or with protocol anomalies (potential C2/tunneling)"
            />
            <Chip
              label="TOR"
              size="small"
              color={searchQuery.includes('TOR') ? 'error' : 'default'}
              variant={searchQuery.includes('TOR') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('TOR') ? prev.replace('TOR', '').trim() : (prev ? `${prev} TOR` : 'TOR'));
                setPage(0);
              }}
              title="Tor anonymization network traffic"
            />
            <Chip
              label="SOCKS"
              size="small"
              color={searchQuery.includes('SOCKS') ? 'warning' : 'default'}
              variant={searchQuery.includes('SOCKS') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('SOCKS') ? prev.replace('SOCKS', '').trim() : (prev ? `${prev} SOCKS` : 'SOCKS'));
                setPage(0);
              }}
              title="SOCKS proxy traffic (potential unauthorized tunneling)"
            />
            <Chip
              label="IRC"
              size="small"
              color={searchQuery.includes('IRC') ? 'warning' : 'default'}
              variant={searchQuery.includes('IRC') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('IRC') ? prev.replace('IRC', '').trim() : (prev ? `${prev} IRC` : 'IRC'));
                setPage(0);
              }}
              title="IRC traffic (commonly used for botnet C2)"
            />
            <Chip
              label="TELNET"
              size="small"
              color={searchQuery.includes('TELNET') ? 'warning' : 'default'}
              variant={searchQuery.includes('TELNET') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('TELNET') ? prev.replace('TELNET', '').trim() : (prev ? `${prev} TELNET` : 'TELNET'));
                setPage(0);
              }}
              title="Unencrypted Telnet traffic (insecure remote access)"
            />
            <Chip
              label="VPN/Tunnel"
              size="small"
              color={searchQuery.includes('OPENVPN') || searchQuery.includes('WIREGUARD') ? 'info' : 'default'}
              variant={searchQuery.includes('OPENVPN') || searchQuery.includes('WIREGUARD') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasVpn = searchQuery.includes('OPENVPN') || searchQuery.includes('WIREGUARD');
                if (hasVpn) {
                  setSearchQuery(prev => prev.replace('OPENVPN', '').replace('WIREGUARD', '').trim());
                } else {
                  setSearchQuery(prev => prev ? `${prev} OPENVPN WIREGUARD` : 'OPENVPN WIREGUARD');
                }
                setPage(0);
              }}
              title="VPN tunnel traffic (OpenVPN, WireGuard)"
            />
            <Chip
              label="Crypto Mining"
              size="small"
              color={searchQuery.includes('MINING') || searchQuery.includes('STRATUM') ? 'error' : 'default'}
              variant={searchQuery.includes('MINING') || searchQuery.includes('STRATUM') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasMining = searchQuery.includes('MINING') || searchQuery.includes('STRATUM');
                if (hasMining) {
                  setSearchQuery(prev => prev.replace('MINING', '').replace('STRATUM', '').trim());
                } else {
                  setSearchQuery(prev => prev ? `${prev} MINING STRATUM` : 'MINING STRATUM');
                }
                setPage(0);
              }}
              title="Cryptocurrency mining traffic (Stratum protocol)"
            />
            <Chip
              label="P2P/BitTorrent"
              size="small"
              color={searchQuery.includes('BITTORRENT') ? 'info' : 'default'}
              variant={searchQuery.includes('BITTORRENT') ? 'filled' : 'outlined'}
              onClick={() => {
                setSearchQuery(prev => prev.includes('BITTORRENT') ? prev.replace('BITTORRENT', '').trim() : (prev ? `${prev} BITTORRENT` : 'BITTORRENT'));
                setPage(0);
              }}
              title="BitTorrent peer-to-peer file sharing"
            />
            <Chip
              label="Remote Desktop"
              size="small"
              color={searchQuery.includes('RDP') || searchQuery.includes('VNC') || searchQuery.includes('TEAMVIEWER') ? 'warning' : 'default'}
              variant={searchQuery.includes('RDP') || searchQuery.includes('VNC') || searchQuery.includes('TEAMVIEWER') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasRemote = searchQuery.includes('RDP') || searchQuery.includes('VNC') || searchQuery.includes('TEAMVIEWER');
                if (hasRemote) {
                  setSearchQuery(prev => prev.replace('RDP', '').replace('VNC', '').replace('TEAMVIEWER', '').trim());
                } else {
                  setSearchQuery(prev => prev ? `${prev} RDP VNC TEAMVIEWER` : 'RDP VNC TEAMVIEWER');
                }
                setPage(0);
              }}
              title="Remote desktop traffic (RDP, VNC, TeamViewer)"
            />
            <Chip
              label="External"
              size="small"
              color={searchQuery === 'external' ? 'primary' : 'default'}
              variant={searchQuery === 'external' ? 'filled' : 'outlined'}
              onClick={() => {
                // Special filter - this will be handled differently in the filter logic
                setSearchQuery(prev => prev === 'external' ? '' : 'external');
                setPage(0);
              }}
              title="Connections to/from external (public) IP addresses"
            />
            <Chip
              label="Database"
              size="small"
              color={searchQuery.includes('MYSQL') || searchQuery.includes('POSTGRES') || searchQuery.includes('MONGODB') ? 'info' : 'default'}
              variant={searchQuery.includes('MYSQL') || searchQuery.includes('POSTGRES') || searchQuery.includes('MONGODB') ? 'filled' : 'outlined'}
              onClick={() => {
                const hasDb = searchQuery.includes('MYSQL') || searchQuery.includes('POSTGRES') || searchQuery.includes('MONGODB');
                if (hasDb) {
                  setSearchQuery(prev => prev.replace('MYSQL', '').replace('POSTGRES', '').replace('MONGODB', '').trim());
                } else {
                  setSearchQuery(prev => prev ? `${prev} MYSQL POSTGRES MONGODB` : 'MYSQL POSTGRES MONGODB');
                }
                setPage(0);
              }}
              title="Database traffic (MySQL, PostgreSQL, MongoDB)"
            />
            {searchQuery && (
              <Chip
                label="Clear All"
                size="small"
                color="secondary"
                onClick={() => {
                  setSearchQuery('');
                  setPage(0);
                }}
              />
            )}
          </Box>
        </Box>

        {/* Connections Table */}
        {!connectionsData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <CableIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Connections Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No connection records have been captured yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small" data-learn="Connections Table: Detailed list of all captured network connections with sorting capabilities.">
                <TableHead>
                  <TableRow>
                    <TableCell width={40}></TableCell>
                    <TableCell>
                      <TableSortLabel
                        data-learn="Sort by Endpoints: Click to sort connections by source and destination IP:port pairs."
                        active={sortField === 'endpoints'}
                        direction={sortField === 'endpoints' ? sortOrder : 'asc'}
                        onClick={() => handleSort('endpoints')}
                      >
                        Connection
                      </TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ width: 80, minWidth: 60 }}>
                      <TableSortLabel
                        data-learn="Sort by Protocol: Click to sort connections by transport protocol (TCP, UDP, etc.)."
                        active={sortField === 'protocol'}
                        direction={sortField === 'protocol' ? sortOrder : 'asc'}
                        onClick={() => handleSort('protocol')}
                      >
                        Protocol
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                      <TableSortLabel
                        data-learn="Sort by Packets: Click to sort connections by packet count."
                        active={sortField === 'packets'}
                        direction={sortField === 'packets' ? sortOrder : 'asc'}
                        onClick={() => handleSort('packets')}
                      >
                        Packets
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel
                        data-learn="Sort by Bytes: Click to sort connections by total data transferred."
                        active={sortField === 'bytes'}
                        direction={sortField === 'bytes' ? sortOrder : 'asc'}
                        onClick={() => handleSort('bytes')}
                      >
                        Bytes
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                      <TableSortLabel
                        data-learn="Sort by Duration: Click to sort connections by how long they lasted."
                        active={sortField === 'duration'}
                        direction={sortField === 'duration' ? sortOrder : 'asc'}
                        onClick={() => handleSort('duration')}
                      >
                        Duration
                      </TableSortLabel>
                    </TableCell>
                    <TableCell data-learn="Server Port: Service name associated with the destination port from IANA database.">
                      Server Port
                    </TableCell>
                    <TableCell data-learn="SNI: TLS Server Name Indication showing the hostname from TLS ClientHello.">
                      SNI
                    </TableCell>
                    <TableCell>Applications</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedConnections.map((conn, idx) => {
                    const rowKey = `${conn.srcIP}-${conn.srcPort}-${conn.dstIP}-${conn.dstPort}-${idx}`;
                    return (
                      <>
                        <TableRow 
                          key={rowKey}
                          data-row-key={rowKey}
                          hover
                          onClick={() => handleRowClick(rowKey)}
                          sx={{ cursor: 'pointer', '& > *': { borderBottom: 'unset !important' } }}
                          data-learn="Connection Row: Click to expand and view detailed information about this connection. Use ↑↓ arrows to navigate between rows when expanded."
                        >
                          <TableCell>
                            <IconButton size="small" data-learn="Expand Button: Click to show/hide detailed connection information.">
                              <ExpandMoreIcon 
                                sx={{ 
                                  transform: expandedRow === rowKey ? 'rotate(180deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.3s'
                                }} 
                              />
                            </IconButton>
                          </TableCell>
                          <TableCell>
                            <Box 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                display: 'flex',
                                alignItems: 'center',
                              }}
                              data-learn="Connection Endpoints: Source IP:port → Destination IP:port showing the direction of the connection. For link-layer only connections, shows MAC addresses."
                            >
                              {conn.srcIP ? (
                                <>
                                  <Box component="span" sx={{ color: '#f44336', fontWeight: 'bold' }}>
                                    {conn.srcIP}
                                  </Box>
                                  {conn.srcPort && (
                                    <>
                                      <Box component="span" sx={{ color: 'text.secondary' }}>:</Box>
                                      <Box component="span" sx={{ color: '#FFB74D', fontWeight: 'medium' }}>
                                        {conn.srcPort}
                                      </Box>
                                    </>
                                  )}
                                  <Box component="span" sx={{ color: 'text.secondary', mx: 0.5 }}>→</Box>
                                  <Box component="span" sx={{ color: '#2196f3', fontWeight: 'bold' }}>
                                    {conn.dstIP}
                                  </Box>
                                  {conn.dstPort && (
                                    <>
                                      <Box component="span" sx={{ color: 'text.secondary' }}>:</Box>
                                      <Box component="span" sx={{ color: '#FFB74D', fontWeight: 'medium' }}>
                                        {conn.dstPort}
                                      </Box>
                                    </>
                                  )}
                                </>
                              ) : (
                                <>
                                  <Box component="span" sx={{ color: '#f44336', fontWeight: 'bold' }}>
                                    {conn.srcMAC || 'N/A'}
                                  </Box>
                                  <Box component="span" sx={{ color: 'text.secondary', mx: 0.5 }}>→</Box>
                                  <Box component="span" sx={{ color: '#2196f3', fontWeight: 'bold' }}>
                                    {conn.dstMAC || 'N/A'}
                                  </Box>
                                </>
                              )}
                            </Box>
                          </TableCell>
                          <TableCell>
                            {conn.transportProto && conn.transportProto !== 'Unknown' && conn.transportProto !== 'Payload' ? (
                              <Chip
                                data-learn="Transport Protocol Tag: Shows the transport layer protocol (TCP, UDP, ICMP, etc.)."
                                label={conn.transportProto}
                                size="small"
                                color="primary"
                                sx={{ fontSize: '0.7rem' }}
                              />
                            ) : null}
                          </TableCell>
                          <TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                            <Typography variant="body2">
                              {conn.numPackets.toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell align="right">
                            <Typography variant="body2">
                              {formatBytes(conn.totalSize)}
                            </Typography>
                          </TableCell>
                          <TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                            <Typography variant="body2">
                              {(conn.duration / 1e9).toFixed(3)}s
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {conn.serverPortName ? (
                              <Chip
                                data-learn="Server Port Name: Official service name for this destination port from IANA port registry."
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
                                }}
                              />
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
                                {conn.dstPort || '-'}
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            {conn.sni ? (
                              <Typography 
                                variant="body2" 
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
                                data-learn="SNI Hostname: TLS Server Name Indication from ClientHello, showing the intended destination hostname."
                              >
                                {conn.sni}
                              </Typography>
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem' }}>
                                -
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                              {(conn.applications || []).slice(0, 2).map((app) => (
                                <Chip
                                  key={`${rowKey}-app-${app}`}
                                  label={app}
                                  size="small"
                                  color="info"
                                  sx={{ fontSize: '0.7rem', height: 20 }}
                                  data-learn="Application Tag: Application detected by Deep Packet Inspection (DPI)."
                                />
                              ))}
                              {(conn.applications || []).length > 2 && (
                                <Chip
                                  label={`+${(conn.applications || []).length - 2}`}
                                  size="small"
                                  color="info"
                                  sx={{ fontSize: '0.7rem', height: 20 }}
                                  data-learn="More Applications: Click the row to see all detected applications."
                                />
                              )}
                            </Box>
                          </TableCell>
                        </TableRow>
                        
                        {/* Expandable Row Details */}
                        <TableRow>
                          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={9}>
                            <Collapse in={expandedRow === rowKey} timeout="auto" unmountOnExit>
                              <Box sx={{ py: 2 }} data-learn="Connection Details: Extended information about this network connection including timestamps, MAC addresses, protocols, flags, and statistics.">
                                <Grid container spacing={2}>
                                  {/* Time Range */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Time Range
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      First: {formatTimestamp(conn.timestampFirst)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Last: {formatTimestamp(conn.timestampLast)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Duration: {(conn.duration / 1e9).toFixed(3)} seconds
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Link Layer */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Link Layer
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Protocol: {conn.linkProto}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Src MAC: {conn.srcMAC}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Dst MAC: {conn.dstMAC}
                                    </Typography>
                                  </Grid>
                                  
                                  {/* Network & Transport Layer */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Network & Transport
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Network Protocol: {conn.networkProto}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Transport Protocol: {conn.transportProto}
                                    </Typography>
                                    {conn.applicationProto && (
                                      <Typography variant="body2" color="text.secondary">
                                        Application Protocol: {conn.applicationProto}
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Protocol Detection */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Protocol Detection
                                    </Typography>
                                    {conn.serverPortName && (
                                      <Typography variant="body2" color="text.secondary">
                                        Server Port Name: {conn.serverPortName}
                                      </Typography>
                                    )}
                                    {conn.detectedProtocolName && (
                                      <Typography variant="body2" color="text.secondary">
                                        Detected Protocol: {conn.detectedProtocolName}
                                      </Typography>
                                    )}
                                    {conn.sni && (
                                      <Typography variant="body2" color="text.secondary" data-learn="TLS SNI: Server Name Indication from TLS ClientHello showing the intended destination hostname.">
                                        TLS SNI: <Box component="span" sx={{ fontFamily: 'monospace', color: 'success.main', fontWeight: 'medium' }}>{conn.sni}</Box>
                                      </Typography>
                                    )}
                                    {!conn.serverPortName && !conn.detectedProtocolName && !conn.sni && (
                                      <Typography variant="body2" color="text.secondary">
                                        No protocol detection information available
                                      </Typography>
                                    )}
                                  </Grid>
                                  
                                  {/* Community ID for Cross-Tool Correlation */}
                                  {conn.communityId && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Community ID: Corelight Community ID v1 for cross-tool correlation with Zeek, Suricata, and other network security tools. Click to filter all pages by this ID.">
                                        Community ID
                                      </Typography>
                                      <CommunityIDChip communityId={conn.communityId} mode="text" />
                                    </Grid>
                                  )}

                                  {/* Traffic Statistics */}
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="subtitle2" gutterBottom>
                                      Traffic Statistics
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Total Size: {formatBytes(conn.totalSize)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      App Payload: {formatBytes(conn.appPayloadSize)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Packets: {conn.numPackets.toLocaleString()}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Client→Server: {formatBytes(conn.bytesClientToServer)}
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                      Server→Client: {formatBytes(conn.bytesServerToClient)}
                                    </Typography>
                                  </Grid>

                                  {/* Connection Indicators */}
                                  {(conn.isExternal || conn.isBroadcast || conn.isMulticast) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Connection Indicators: Flags indicating special connection characteristics.">
                                        Connection Indicators
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {conn.isExternal && (
                                          <Chip 
                                            label="External" 
                                            size="small" 
                                            color="warning"
                                            sx={{ fontSize: '0.75rem' }}
                                            data-learn="External: One or both IPs are public (non-RFC1918 private addresses)."
                                          />
                                        )}
                                        {conn.isBroadcast && (
                                          <Chip 
                                            label="Broadcast" 
                                            size="small" 
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }}
                                            data-learn="Broadcast: Destination is a broadcast address."
                                          />
                                        )}
                                        {conn.isMulticast && (
                                          <Chip 
                                            label="Multicast" 
                                            size="small" 
                                            color="secondary"
                                            sx={{ fontSize: '0.75rem' }}
                                            data-learn="Multicast: Destination is a multicast address."
                                          />
                                        )}
                                      </Box>
                                    </Grid>
                                  )}

                                  {/* Security Behavioral Analysis */}
                                  {(conn.packetsClientToServer > 0 || conn.packetsServerToClient > 0) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="Security Behavioral Analysis: Traffic patterns useful for detecting beaconing, data exfiltration, and other suspicious activity.">
                                        Security Behavioral Analysis
                                      </Typography>
                                      <Typography variant="body2" color="text.secondary">
                                        Packets C→S: {conn.packetsClientToServer?.toLocaleString() || 0}
                                      </Typography>
                                      <Typography variant="body2" color="text.secondary">
                                        Packets S→C: {conn.packetsServerToClient?.toLocaleString() || 0}
                                      </Typography>
                                      {conn.avgPacketSizeClientToServer > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          Avg Pkt Size C→S: {conn.avgPacketSizeClientToServer} bytes
                                        </Typography>
                                      )}
                                      {conn.avgPacketSizeServerToClient > 0 && (
                                        <Typography variant="body2" color="text.secondary">
                                          Avg Pkt Size S→C: {conn.avgPacketSizeServerToClient} bytes
                                        </Typography>
                                      )}
                                      {conn.byteRatio > 0 && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                                          <Typography variant="body2" color="text.secondary">
                                            Byte Ratio (C/S):
                                          </Typography>
                                          <Chip 
                                            label={conn.byteRatio.toFixed(2)} 
                                            size="small" 
                                            color={conn.byteRatio > 0.9 && conn.byteRatio < 1.1 ? 'warning' : 'default'}
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn="Byte Ratio: Client/Server byte ratio close to 1.0 may indicate beaconing behavior."
                                          />
                                        </Box>
                                      )}
                                      {conn.packetRatio > 0 && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                                          <Typography variant="body2" color="text.secondary">
                                            Packet Ratio (C/S):
                                          </Typography>
                                          <Chip 
                                            label={conn.packetRatio.toFixed(2)} 
                                            size="small" 
                                            color={conn.packetRatio > 0.9 && conn.packetRatio < 1.1 ? 'warning' : 'default'}
                                            variant="outlined"
                                            sx={{ fontSize: '0.7rem' }}
                                            data-learn="Packet Ratio: Client/Server packet ratio close to 1.0 may indicate beaconing behavior."
                                          />
                                        </Box>
                                      )}
                                    </Grid>
                                  )}
                                  
                                  {/* TCP Flags */}
                                  {conn.transportProto === 'TCP' && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        TCP Flags
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {conn.numSYNFlags > 0 && (
                                          <Chip label={`SYN: ${conn.numSYNFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numACKFlags > 0 && (
                                          <Chip label={`ACK: ${conn.numACKFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numFINFlags > 0 && (
                                          <Chip label={`FIN: ${conn.numFINFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numRSTFlags > 0 && (
                                          <Chip label={`RST: ${conn.numRSTFlags}`} size="small" variant="outlined" color="error" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numPSHFlags > 0 && (
                                          <Chip label={`PSH: ${conn.numPSHFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numURGFlags > 0 && (
                                          <Chip label={`URG: ${conn.numURGFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numECEFlags > 0 && (
                                          <Chip label={`ECE: ${conn.numECEFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numCWRFlags > 0 && (
                                          <Chip label={`CWR: ${conn.numCWRFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        {conn.numNSFlags > 0 && (
                                          <Chip label={`NS: ${conn.numNSFlags}`} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                                        )}
                                        <Chip label={`Mean Window: ${conn.meanWindowSize}`} size="small" variant="outlined" color="info" sx={{ fontSize: '0.75rem' }} />
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* JA4L Latency Fingerprints */}
                                  {conn.transportProto === 'TCP' && (conn.ja4lClient || conn.ja4lServer) && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" gutterBottom data-learn="JA4L Latency: Network latency fingerprints based on TCP and TLS handshake timing. Format: latency_ms_ttl">
                                        JA4L Latency Fingerprints
                                      </Typography>
                                      {conn.ja4lClient && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                          <Typography variant="body2" color="text.secondary" sx={{ minWidth: '80px' }}>
                                            JA4L-C:
                                          </Typography>
                                          <Chip 
                                            label={conn.ja4lClient} 
                                            size="small" 
                                            color="warning"
                                            variant="outlined"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                                            data-learn="JA4L-C (Client): TCP handshake latency from SYN to SYN-ACK in milliseconds, with TTL value."
                                          />
                                          <Typography variant="caption" color="text.secondary">
                                            (TCP RTT: {(conn.tcpRttNanos / 1e6).toFixed(2)}ms)
                                          </Typography>
                                        </Box>
                                      )}
                                      {conn.ja4lServer && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                          <Typography variant="body2" color="text.secondary" sx={{ minWidth: '80px' }}>
                                            JA4L-S:
                                          </Typography>
                                          <Chip 
                                            label={conn.ja4lServer} 
                                            size="small" 
                                            color="success"
                                            variant="outlined"
                                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                                            data-learn="JA4L-S (Server): TLS handshake latency from ClientHello to ServerHello in milliseconds, with TTL value."
                                          />
                                          <Typography variant="caption" color="text.secondary">
                                            (TLS: {(conn.tlsHandshakeNanos / 1e6).toFixed(2)}ms)
                                          </Typography>
                                        </Box>
                                      )}
                                      {conn.synTtl > 0 && (
                                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                                          SYN TTL: {conn.synTtl} (estimated {256 - conn.synTtl} hops)
                                        </Typography>
                                      )}
                                    </Grid>
                                  )}
                                  
                                  {/* All Applications */}
                                  {(conn.applications || []).length > 0 && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" gutterBottom>
                                        All Detected Applications ({(conn.applications || []).length})
                                      </Typography>
                                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                        {(conn.applications || []).map((app) => (
                                          <Chip
                                            key={`${rowKey}-app-detail-${app}`}
                                            label={app}
                                            size="small"
                                            color="info"
                                            sx={{ fontSize: '0.75rem' }}
                                          />
                                        ))}
                                      </Box>
                                    </Grid>
                                  )}
                                  
                                  {/* Action Buttons */}
                                  <Grid item xs={12}>
                                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                      {/* Show Secrets - only show when credentials exist for this connection */}
                                      {hasCredentials(conn) && (
                                        <Button
                                          data-learn="Show Secrets: View captured credentials (usernames, passwords, hashes) associated with this connection."
                                          variant="contained"
                                          color="warning"
                                          startIcon={<VpnKeyIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            const flowIdent = getFlowIdentForCredentials(conn);
                                            router.push(`/credentials?search=${encodeURIComponent(flowIdent)}`);
                                          }}
                                          size="small"
                                        >
                                          Show Secrets
                                        </Button>
                                      )}
                                      {/* View Conversation - only show when there's actual payload data */}
                                      {conn.appPayloadSize > 0 && (
                                        <Button
                                          data-learn="View Raw Conversation: Display the raw conversation data in Wireshark-style hex dump format, with client data in red and server data in blue."
                                          variant="outlined"
                                          startIcon={<ArticleIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            handleViewConversation(conn);
                                          }}
                                          size="small"
                                        >
                                          View Raw Conversation
                                        </Button>
                                      )}
                                      {/* Download PCAP - only for TCP/UDP with ports */}
                                      {(conn.transportProto === 'TCP' || conn.transportProto === 'UDP') && (
                                        <Button
                                          data-learn="Download as PCAP: Download a filtered PCAP file containing only the packets from this connection."
                                          variant="outlined"
                                          startIcon={<DownloadIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            handleDownloadPCAP(conn);
                                          }}
                                          size="small"
                                        >
                                          Download as PCAP
                                        </Button>
                                      )}
                                      
                                      {/* Navigation Buttons */}
                                      {conn.srcIP && (
                                        <Button
                                          data-learn="View Client in Hosts: Navigate to the Hosts page filtered for the client IP address."
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<ComputerIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/hosts?search=${encodeURIComponent(conn.srcIP)}`);
                                          }}
                                          size="small"
                                        >
                                          Client IP in Hosts
                                        </Button>
                                      )}
                                      
                                      {conn.dstIP && (
                                        <Button
                                          data-learn="View Server in Hosts: Navigate to the Hosts page filtered for the server IP address."
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<ComputerIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/hosts?search=${encodeURIComponent(conn.dstIP)}`);
                                          }}
                                          size="small"
                                        >
                                          Server IP in Hosts
                                        </Button>
                                      )}
                                      
                                      {(conn.srcMAC || conn.dstMAC) && (
                                        <>
                                          {conn.srcMAC && (
                                            <Button
                                              data-learn="View Client MAC in Devices: Navigate to the Devices page filtered for the client MAC address."
                                              variant="outlined"
                                              color="secondary"
                                              startIcon={<RouterIcon />}
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                router.push(`/devices?search=${encodeURIComponent(conn.srcMAC)}`);
                                              }}
                                              size="small"
                                            >
                                              Client MAC in Devices
                                            </Button>
                                          )}
                                          
                                          {conn.dstMAC && (
                                            <Button
                                              data-learn="View Server MAC in Devices: Navigate to the Devices page filtered for the server MAC address."
                                              variant="outlined"
                                              color="secondary"
                                              startIcon={<RouterIcon />}
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                router.push(`/devices?search=${encodeURIComponent(conn.dstMAC)}`);
                                              }}
                                              size="small"
                                            >
                                              Server MAC in Devices
                                            </Button>
                                          )}
                                        </>
                                      )}
                                      
                                      {conn.dstIP && (
                                        <Button
                                          data-learn="View Service: Navigate to the Services page filtered for the server IP address."
                                          variant="outlined"
                                          color="secondary"
                                          startIcon={<DnsIcon />}
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            router.push(`/services?search=${encodeURIComponent(conn.dstIP)}`);
                                          }}
                                          size="small"
                                        >
                                          Service
                                        </Button>
                                      )}
                                      
                                      {/* Custom row actions from parent */}
                                      {rowActions && rowActions(conn)}
                                    </Box>
                                  </Grid>
                                </Grid>
                              </Box>
                            </Collapse>
                          </TableCell>
                        </TableRow>
                      </>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              data-learn="Table Pagination: Navigate through pages of connections and change how many rows to display per page."
              component="div"
              count={filteredConnections.length}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
            />
          </>
        )}
        </>
        )}
      </Box>

      {/* Conversation Modal */}
      {selectedConnection && (
        <ConversationModal
          open={conversationModalOpen}
          onClose={handleCloseConversationModal}
          srcIP={selectedConnection.srcIP}
          srcPort={selectedConnection.srcPort}
          dstIP={selectedConnection.dstIP}
          dstPort={selectedConnection.dstPort}
          protocol={selectedConnection.transportProto}
          onNavigatePrevious={handleNavigatePreviousConnection}
          onNavigateNext={handleNavigateNextConnection}
          hasPrevious={hasPreviousWithPayload}
          hasNext={hasNextWithPayload}
        />
      )}
    </Layout>
  );
}

