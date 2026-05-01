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

import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Box,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Typography,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  ToggleButton,
  ToggleButtonGroup,
  TextField,
  type SelectChangeEvent,
} from '@mui/material';
import {
  BarChart as BarChartIcon,
  ShowChart as ShowChartIcon,
  ScatterPlot as ScatterPlotIcon,
  PieChart as PieChartIcon,
  Timeline as TimelineIcon,
  FilterList as FunnelIcon,
  Radar as RadarIcon,
  Cloud as WordCloudIcon,
  AccountTree as SankeyIcon,
  Hub as GraphIcon,
  ExpandMore as ExpandMoreIcon,
  Code as CodeIcon,
  DataObject as DataObjectIcon,
  Label as LabelIcon,
  LabelOff as LabelOffIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { type ChartFieldsResponse, getBackendUrl } from '../lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi } from '../hooks';

const CHART_TYPES = [
  // Numeric field charts
  { value: 'line', label: 'Line Chart', icon: <ShowChartIcon />, description: 'Time series with smooth lines', forNumeric: true },
  { value: 'bar', label: 'Bar Chart', icon: <BarChartIcon />, description: 'Vertical bars for comparison', forNumeric: true, forCategorical: true },
  { value: 'area', label: 'Area Chart', icon: <TimelineIcon />, description: 'Filled area under line', forNumeric: true },
  { value: 'scatter', label: 'Scatter Plot', icon: <ScatterPlotIcon />, description: 'Individual data points', forNumeric: true },
  { value: 'funnel', label: 'Funnel Chart', icon: <FunnelIcon />, description: 'Value progression funnel', forNumeric: true, forCategorical: true },
  { value: 'radar', label: 'Radar Chart', icon: <RadarIcon />, description: 'Multi-dimensional comparison', forNumeric: true },
  
  // Categorical field charts
  { value: 'pie', label: 'Pie Chart', icon: <PieChartIcon />, description: 'Distribution of categories', forCategorical: true },
  { value: 'wordcloud', label: 'Word Cloud', icon: <WordCloudIcon />, description: 'Text frequency visualization', forCategorical: true },
  { value: 'sankey', label: 'Sankey Diagram', icon: <SankeyIcon />, description: 'Flow and relationships', forCategorical: true },
  { value: 'graph', label: 'Network Graph', icon: <GraphIcon />, description: 'Network relationships', forCategorical: true },
];

// Default field and chart type mappings for each audit record type
// These are the most analytically interesting field and visualization combinations
const DEFAULT_FIELD_MAP: Record<string, { field: string; chartType: string }> = {
  // Connection and Flow Analysis
  'Connection': { field: 'NumPackets', chartType: 'line' },        // Time series of packet counts
  'Service': { field: 'BytesServer', chartType: 'line' },            
  
  // Transport Layer - Time series for packet/payload analysis
  'TCP': { field: 'PayloadSize', chartType: 'line' },              // Payload size over time
  'UDP': { field: 'Length', chartType: 'line' },                   // Packet length over time
  'SCTP': { field: 'Length', chartType: 'line' },                  // Packet length over time
  
  // Network Layer - Time series for packet analysis
  'IPv4': { field: 'Length', chartType: 'line' },                  // Packet length over time
  'IPv6': { field: 'Length', chartType: 'line' },                  // Packet length over time
  'ICMPv4': { field: 'TypeCode', chartType: 'pie' },                // Message type distribution
  'ICMPv6': { field: 'TypeCode', chartType: 'pie' },                // Message type distribution
  'ARP': { field: 'Operation', chartType: 'pie' },                 // Request/Reply distribution
  'IGMP': { field: 'Type', chartType: 'pie' },                     // Message type distribution
  
  // Link Layer
  'Ethernet': { field: 'PayloadSize', chartType: 'line' },         // Payload size over time
  'Dot1Q': { field: 'VLANIdentifier', chartType: 'bar' },          // VLAN usage distribution
  'Dot11': { field: 'Type', chartType: 'pie' },                    // Frame type distribution
  'LLC': { field: 'DSAP', chartType: 'pie' },                      // Protocol distribution
  'SNAP': { field: 'Type', chartType: 'pie' },                     // Protocol distribution
  
  // Application Layer - Web
  'HTTP': { field: 'Method', chartType: 'pie' },            
  'TLSClientHello': { field: 'CipherSuites', chartType: 'wordcloud' }, // Cipher suite popularity
  'TLSServerHello': { field: 'CipherSuite', chartType: 'pie' },    // Cipher suite distribution
  
  // Application Layer - DNS
  'DNS': { field: 'Questions.Name', chartType: 'pie' },              
  
  // Application Layer - Email
  'SMTP': { field: 'StatusCode', chartType: 'pie' },               // Status code distribution
  'POP3': { field: 'StatusCode', chartType: 'pie' },               // Status code distribution
  'Mail': { field: 'From', chartType: 'pie' },                     
  
  // Application Layer - Other
  'SSH': { field: 'Ident', chartType: 'pie' },                   // Version distribution
  'SIP': { field: 'ResponseStatus', chartType: 'bar' },                // Status code distribution
  'NTP': { field: 'Stratum', chartType: 'bar' },                   // Time accuracy levels
  'DHCPv4': { field: 'Operation', chartType: 'pie' },               // Operation type distribution
  'DHCPv6': { field: 'MsgType', chartType: 'pie' },                 // Message type distribution
  
  // Routing Protocols
  'OSPFv2': { field: 'Type', chartType: 'pie' },                   // Message type distribution
  'OSPFv3': { field: 'Type', chartType: 'pie' },                   // Message type distribution
  'VRRPv2': { field: 'Priority', chartType: 'bar' },               // Priority distribution
  
  // Industrial Protocols (ICS/SCADA)
  'Modbus': { field: 'FunctionCode', chartType: 'pie' },           // Function code distribution
  'ENIP': { field: 'Command', chartType: 'pie' },                  // Command distribution
  'CIP': { field: 'Service', chartType: 'pie' },                   // Service distribution
  'OPCUA': { field: 'ServiceName', chartType: 'pie' },             // OPC UA service distribution
  'DNP3': { field: 'FunctionCodeName', chartType: 'pie' },         // DNP3 function code distribution
  'S7Comm': { field: 'FunctionName', chartType: 'pie' },           // Siemens S7 function distribution
  'PROFINET': { field: 'ServiceName', chartType: 'pie' },          // PROFINET service distribution
  'IEC62351': { field: 'MessageTypeName', chartType: 'pie' },      // IEC 62351 security message types
  'BACnetIP': { field: 'ServiceName', chartType: 'pie' },          // BACnet/IP service distribution
  'MQTTSN': { field: 'MessageTypeName', chartType: 'pie' },        // MQTT-SN message type distribution
  
  // Tunneling & Encapsulation
  'GRE': { field: 'Protocol', chartType: 'pie' },                  // Encapsulated protocol distribution
  'VXLAN': { field: 'VNI', chartType: 'bar' },                     // Virtual network usage
  'Geneve': { field: 'VNI', chartType: 'bar' },                    // Virtual network usage
  'MPLS': { field: 'Label', chartType: 'bar' },                    // Label distribution
  
  // Security & VPN
  'IPSecAH': { field: 'SPI', chartType: 'bar' },                   // Security association distribution
  'IPSecESP': { field: 'SPI', chartType: 'bar' },                  // Security association distribution
  
  // Discovery Protocols
  'CiscoDiscovery': { field: 'DeviceID', chartType: 'wordcloud' }, // Device identification
  'NortelDiscovery': { field: 'DeviceID', chartType: 'wordcloud' }, // Device identification
  'LLD': { field: 'ChassisID', chartType: 'pie' },                 // Chassis distribution
  
  // USB
  'USB': { field: 'Length', chartType: 'line' },                   // Transfer length over time
  
  // Other
  'BFD': { field: 'State', chartType: 'pie' },                     // Session state distribution
  'Diameter': { field: 'CommandCode', chartType: 'pie' },          // Command distribution
  'EAP': { field: 'Type', chartType: 'pie' },                      // Auth type distribution
  'EAPOL': { field: 'Type', chartType: 'pie' },                    // Message type distribution
  'FDDI': { field: 'FrameControl', chartType: 'pie' },             // Frame control distribution
  'LCM': { field: 'ChannelName', chartType: 'wordcloud' },         // Channel popularity
  
  // PPP/PPPoE - Link Layer
  'PPPoE': { field: 'CodeName', chartType: 'pie' },                // PPPoE code distribution (PADI/PADO/PADR/PADS/PADT)
  'PPP': { field: 'PPPTypeName', chartType: 'pie' },               // PPP protocol type distribution
  
  // STP - Link Layer
  'STP': { field: 'VersionName', chartType: 'pie' },               // STP version distribution (STP/RSTP/MSTP)
  
  // RMCP - Application Layer (IPMI/BMC management)
  'RMCP': { field: 'ClassName', chartType: 'pie' },                // RMCP class distribution (ASF/IPMI/OEM)
  
  // MLDv2 - Network Layer (IPv6 multicast)
  'MLDv2MulticastListenerQuery': { field: 'IsGeneralQuery', chartType: 'pie' },   // Query type distribution
  'MLDv2MulticastListenerReport': { field: 'HasJoinRecords', chartType: 'pie' },  // Join/leave distribution
  
  // Special Records - Security & Analysis
  'File': { field: 'Size', chartType: 'bar' },                     // File size distribution
  'Secret': { field: 'Service', chartType: 'pie' },           // Service distribution
  'Software': { field: 'Product', chartType: 'wordcloud' },        // Product popularity
  'Vulnerability': { field: 'V2Score', chartType: 'pie' },          
  'Exploit': { field: 'Platform', chartType: 'pie' },              
  'Alert': { field: 'Classification', chartType: 'pie' },          // Alert type distribution
  'DeviceProfile': { field: 'DeviceManufacturer', chartType: 'pie' }, // Device manufacturer distribution
  'IPProfile': { field: 'NumPackets', chartType: 'line' },         // Packet count time series
};

export default function Explore() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const { type: urlType, field: urlField } = router.query;

  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: auditFiles, mutate: mutateAuditFiles } = useSWR('auditFiles', () => api.getAuditFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());

  const [selectedAuditType, setSelectedAuditType] = useState<string>('');
  const [selectedField, setSelectedField] = useState<string>('');
  const [selectedChartType, setSelectedChartType] = useState<string>('line');
  
  const [chartUrl, setChartUrl] = useState<string | null>(null);
  const [fields, setFields] = useState<ChartFieldsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exampleRecord, setExampleRecord] = useState<Record<string, unknown> | null>(null);
  const [loadingExample, setLoadingExample] = useState(false);
  const [showExample, setShowExample] = useState(false);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [autoSelectAttempted, setAutoSelectAttempted] = useState(false);
  const [showLegend, setShowLegend] = useState(false);
  const [maxDataPoints, setMaxDataPoints] = useState<number>(1000);

  // Audit type rotation: get/set the index of the last used audit type
  const getNextAuditTypeIndex = useCallback((availableTypes: string[]): number => {
    if (availableTypes.length === 0) return 0;
    
    const storageKey = 'explore-audit-type-rotation';
    const storedIndex = localStorage.getItem(storageKey);
    
    // If we have a stored index, get the next one (cycling through)
    if (storedIndex !== null) {
      const lastIndex = parseInt(storedIndex, 10);
      const nextIndex = (lastIndex + 1) % availableTypes.length;
      localStorage.setItem(storageKey, nextIndex.toString());
      return nextIndex;
    }
    
    // First time - start with 0 and store it
    localStorage.setItem(storageKey, '0');
    return 0;
  }, []);

  // Auto-select first completed file if no active file is set
  useEffect(() => {
    const autoSelectFirstFile = async () => {
      // Only attempt once
      if (autoSelectAttempted) return;
      
      // Wait for data to be loaded
      if (!inputFiles || !status) return;
      
      const completed = inputFiles.filter((f: any) => f.isCompleted);
      if (completed.length === 0) return;
      
      // Check if we need to auto-select
      const hasActiveFile = status.activeInputFile && completed.some((f: any) => 
        f.path === status.activeInputFile || 
        f.name === status.activeInputFile || 
        f.path.endsWith('/' + status.activeInputFile)
      );
      
      if (!hasActiveFile) {
        console.log('[Explore] Auto-selecting first completed file:', completed[0].path);
        setAutoSelectAttempted(true);
        try {
          await api.setActiveDirectory(completed[0].path);
          await mutateStatus();
          await mutateAuditFiles();
        } catch (err) {
          console.error('[Explore] Failed to auto-select file:', err);
        }
      }
    };
    
    autoSelectFirstFile();
  }, [inputFiles, status, autoSelectAttempted, mutateStatus, mutateAuditFiles]);

  // Listen for directory changes and refresh audit files (for multi-file/service mode)
  useEffect(() => {
    const handleDirectoryChange = () => {
      console.log('Directory changed, refreshing audit files for explore...');
      mutateAuditFiles(); // Refresh audit files
      mutateStatus(); // Refresh status
      // Clear current chart if type is no longer available
      setChartUrl(null);
    };
    
    window.addEventListener('directory-changed', handleDirectoryChange);
    return () => window.removeEventListener('directory-changed', handleDirectoryChange);
  }, [mutateAuditFiles, mutateStatus]);

  // Load example record for the selected audit type
  const loadExampleRecord = useCallback((auditType: string) => {
    setLoadingExample(true);
    let eventSource: EventSource | null = null;
    
    try {
      eventSource = api.streamAuditRecords(
        auditType,
        0, // offset
        1, // limit - just get first record
        (record) => {
          setExampleRecord(record);
          setLoadingExample(false);
          if (eventSource) {
            eventSource.close();
          }
        },
        undefined, // onProgress
        () => {
          setLoadingExample(false);
        },
        (error) => {
          console.error('Failed to load example record:', error);
          setLoadingExample(false);
        }
      );
    } catch (err) {
      console.error('Failed to start stream:', err);
      setLoadingExample(false);
    }
  }, []);

  // Set initial values from URL parameters
  useEffect(() => {
    if (urlType && typeof urlType === 'string') {
      setSelectedAuditType(urlType);
    }
    if (urlField && typeof urlField === 'string') {
      setSelectedField(urlField);
    }
  }, [urlType, urlField]);

  // Load fields when audit type is selected
  useEffect(() => {
    if (selectedAuditType) {
      setLoading(true);
      setError(null);
      api.getChartFields(selectedAuditType)
        .then((data) => {
          setFields(data);
          
          // If a field is already selected from URL, keep it (only on initial load)
          if (urlField && typeof urlField === 'string') {
            setSelectedField(urlField);
            return;
          }
          
          // Try to use default field and chart type from mapping
          const defaultConfig = DEFAULT_FIELD_MAP[selectedAuditType];
          if (defaultConfig) {
            // Check if the default field exists in the available fields
            const fieldExists = data.fields.some(f => f.name === defaultConfig.field);
            if (fieldExists) {
              setSelectedField(defaultConfig.field);
              // Also set the recommended chart type
              setSelectedChartType(defaultConfig.chartType);
            } else if (data.fields.length > 0) {
              // Fallback to first field if default doesn't exist
              setSelectedField(data.fields[0].name);
            }
          } else if (data.fields.length > 0) {
            // No default mapping, use first field
            setSelectedField(data.fields[0].name);
          }
        })
        .catch((err) => {
          setError(err.message);
        })
        .finally(() => {
          setLoading(false);
        });
      
      // Load example record
      loadExampleRecord(selectedAuditType);
    } else {
      setExampleRecord(null);
    }
  }, [selectedAuditType, urlField, loadExampleRecord]);

  const handleAuditTypeChange = (event: SelectChangeEvent) => {
    setSelectedAuditType(event.target.value);
    setSelectedField('');
    setChartUrl(null);
  };

  const handleFieldChange = (event: SelectChangeEvent) => {
    setSelectedField(event.target.value);
  };

  const handleChartTypeChange = (_event: React.MouseEvent<HTMLElement>, newType: string | null) => {
    if (newType !== null) {
      setSelectedChartType(newType);
    }
  };

  // Handler for FileSelectorHeader component (receives path string)
  const handleFileSelectorChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      await mutateAuditFiles(); // Refresh audit files
      await mutateStatus();
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Clear current chart, but keep audit type and field selections
      setChartUrl(null);
      // Note: selectedAuditType and selectedField are preserved for better UX
      
      // Reload example record for the new data source if an audit type is selected
      if (selectedAuditType) {
        loadExampleRecord(selectedAuditType);
      }
      
      // Regenerate chart URL for the new data source if we have audit type and field
      if (selectedAuditType && selectedField) {
        const url = `${getBackendUrl()}/api/chart/data?type=${encodeURIComponent(selectedAuditType)}&field=${encodeURIComponent(selectedField)}&chartType=${encodeURIComponent(selectedChartType)}&showLegend=${showLegend}&maxDataPoints=${maxDataPoints}`;
        setChartUrl(url);
      }
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert('Failed to switch to this capture');
    } finally {
      setSwitchingFile(false);
    }
  }, [mutateAuditFiles, mutateStatus, selectedAuditType, selectedField, selectedChartType, showLegend, maxDataPoints, loadExampleRecord]);

  // Auto-generate chart when configuration changes
  useEffect(() => {
    if (!selectedAuditType || !selectedField) {
      return;
    }

    setLoading(true);
    setError(null);
    
    // Build chart URL - chart will be generated server-side by go-echarts
    // No interval parameter - use all records with actual timestamps
    const url = `${getBackendUrl()}/api/chart/data?type=${encodeURIComponent(selectedAuditType)}&field=${encodeURIComponent(selectedField)}&chartType=${encodeURIComponent(selectedChartType)}&showLegend=${showLegend}&maxDataPoints=${maxDataPoints}`;
    setChartUrl(url);
    setLoading(false);
  }, [selectedAuditType, selectedField, selectedChartType, showLegend, maxDataPoints]);

  // Determine if selected field is categorical
  const isFieldCategorical = useMemo(() => {
    if (!fields || !selectedField) return false;
    const field = fields.fields.find(f => f.name === selectedField);
    return field?.type.startsWith('categorical') || false;
  }, [fields, selectedField]);

  // Filter chart types based on field type
  const availableChartTypes = useMemo(() => {
    if (isFieldCategorical) {
      // For categorical fields, show appropriate charts
      return CHART_TYPES.filter(ct => ct.forCategorical);
    }
    // For numeric fields, show appropriate charts
    return CHART_TYPES.filter(ct => ct.forNumeric);
  }, [isFieldCategorical]);

  // Auto-select appropriate chart type when field changes
  useEffect(() => {
    const currentType = CHART_TYPES.find(ct => ct.value === selectedChartType);
    if (isFieldCategorical && currentType && !currentType.forCategorical) {
      setSelectedChartType('pie');
    } else if (!isFieldCategorical && currentType && !currentType.forNumeric) {
      setSelectedChartType('line');
    }
  }, [isFieldCategorical, selectedChartType]);

  // Group audit files by type
  const auditTypes = useMemo(() => {
    if (!auditFiles) return [];
    return Array.from(new Set(auditFiles.map((f) => f.type))).sort();
  }, [auditFiles]);

  // Auto-select next audit type in rotation when explore tab is opened
  useEffect(() => {
    // Skip if URL has a type parameter
    if (urlType && typeof urlType === 'string') {
      return;
    }
    
    // Auto-select next audit type in rotation when auditTypes are available
    if (auditTypes.length > 0 && !selectedAuditType) {
      const nextIndex = getNextAuditTypeIndex(auditTypes);
      const nextType = auditTypes[nextIndex];
      setSelectedAuditType(nextType);
    }
  }, [urlType, auditTypes, selectedAuditType, getNextAuditTypeIndex]);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileSelectorChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to explore their data and generate custom visualizations."
    />
  );

  // Header action with audit type, field selects, and file selector
  const headerAction = (
    <Box 
      sx={{ 
        display: 'flex', 
        flexDirection: { xs: 'column', sm: 'column', md: 'row' },
        alignItems: { xs: 'stretch', md: 'center' }, 
        gap: { xs: 0.75, sm: 1, md: 2 }, 
        width: '100%'
      }}
    >
      {/* Container for Audit Type and Field selects - show first on mobile */}
      <Box 
        sx={{ 
          display: 'flex', 
          flexDirection: { xs: 'column', sm: 'row' },
          gap: { xs: 0.75, sm: 1, md: 2 },
          flex: 1,
          order: { xs: 1, md: 0 }
        }}
      >
        {/* Audit Type Selection */}
        <FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 150, md: 200 } }}>
          <InputLabel sx={{ color: 'inherit' }}>Audit Record Type</InputLabel>
          <Select
            data-learn="Audit Type Selector: Choose which protocol or record type to visualize (e.g., HTTP, TCP, DNS)."
            value={selectedAuditType}
            onChange={handleAuditTypeChange}
            label="Audit Record Type"
            sx={{
              color: 'inherit',
              '.MuiOutlinedInput-notchedOutline': {
                borderColor: 'rgba(255, 255, 255, 0.23)',
              },
              '&:hover .MuiOutlinedInput-notchedOutline': {
                borderColor: 'rgba(255, 255, 255, 0.4)',
              },
              '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                borderColor: 'primary.light',
              },
              '.MuiSelect-icon': {
                color: 'inherit',
              },
            }}
          >
            {auditTypes.map((type) => (
              <MenuItem key={type} value={type}>
                {type}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {/* Field Selection */}
        <FormControl size="small" disabled={!selectedAuditType || loading} sx={{ minWidth: { xs: '100%', sm: 150, md: 200 } }}>
          <InputLabel sx={{ color: 'inherit' }}>Field</InputLabel>
          <Select
            data-learn="Field Selector: Choose which data field from the audit records to visualize in the chart."
            value={selectedField}
            onChange={handleFieldChange}
            label="Field"
            sx={{
              color: 'inherit',
              '.MuiOutlinedInput-notchedOutline': {
                borderColor: 'rgba(255, 255, 255, 0.23)',
              },
              '&:hover .MuiOutlinedInput-notchedOutline': {
                borderColor: 'rgba(255, 255, 255, 0.4)',
              },
              '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                borderColor: 'primary.light',
              },
              '.MuiSelect-icon': {
                color: 'inherit',
              },
            }}
          >
            {fields?.fields.map((field) => (
              <MenuItem key={field.name} value={field.name}>
                {field.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>

      {/* File selector for multi-file mode - show last on mobile */}
      <Box sx={{ order: { xs: 2, md: 2 } }}>
        {fileSelector}
      </Box>
    </Box>
  );

  return (
    <Layout 
      title="Explore" 
      headerAction={headerAction}
      topPadding={{ xs: '200px', sm: '140px', md: '100px' }}
    >
      {/* Chart type selection buttons and controls - above chart box */}
      {chartUrl && !loading && (
        <Box sx={{ 
          mb: 2,
          display: 'flex', 
          flexDirection: { xs: 'column', sm: 'row' },
          justifyContent: 'space-between', 
          alignItems: { xs: 'stretch', sm: 'center' }, 
          gap: { xs: 1, sm: 2 },
        }}>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
            <ToggleButtonGroup
              data-learn="Chart Type Selector: Choose the visualization style (line, bar, pie, scatter, etc.) based on your data type."
              value={selectedChartType}
              exclusive
              onChange={handleChartTypeChange}
              size="small"
              sx={{
                flexWrap: 'wrap',
                gap: 0.5,
                '& .MuiToggleButtonGroup-grouped': {
                  borderRadius: 1,
                  border: '1px solid',
                  borderColor: 'divider',
                  px: { xs: 1, sm: 2 },
                  '&:not(:first-of-type)': {
                    marginLeft: 0,
                    borderLeft: '1px solid',
                    borderLeftColor: 'divider',
                  },
                  '&:not(:last-of-type)': {
                    borderRight: '1px solid',
                    borderRightColor: 'divider',
                  },
                },
              }}
            >
              {availableChartTypes.map((type) => (
                <ToggleButton 
                  key={type.value} 
                  value={type.value}
                  sx={{ 
                    textTransform: 'none',
                    minWidth: { xs: 48, xl: 'auto' },
                    width: { xs: 48, xl: 'auto' },
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    {type.icon}
                    <Box component="span" sx={{ display: { xs: 'none', xl: 'inline' } }}>
                      {type.label}
                    </Box>
                  </Box>
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
          </Box>

          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            {/* Legend toggle - only show when viewing chart */}
            {!showExample && (
              <ToggleButtonGroup
                data-learn="Legend Toggle: Show or hide the chart legend to save space or improve readability."
                value={showLegend ? 'on' : 'off'}
                exclusive
                onChange={(_e, newValue) => {
                  if (newValue !== null) {
                    setShowLegend(newValue === 'on');
                  }
                }}
                size="small"
                sx={{
                  '& .MuiToggleButton-root': {
                    px: { xs: 1, xl: 1.5 },
                    minWidth: { xs: 48, xl: 'auto' },
                    width: { xs: 48, xl: 'auto' },
                  }
                }}
              >
                <ToggleButton value="on">
                  <LabelIcon sx={{ mr: { xs: 0, xl: 0.5 }, fontSize: 18 }} />
                  <Box component="span" sx={{ display: { xs: 'none', xl: 'inline' } }}>
                    Legend
                  </Box>
                </ToggleButton>
                <ToggleButton value="off">
                  <LabelOffIcon sx={{ mr: { xs: 0, xl: 0.5 }, fontSize: 18 }} />
                  <Box component="span" sx={{ display: { xs: 'none', xl: 'inline' } }}>
                    No Legend
                  </Box>
                </ToggleButton>
              </ToggleButtonGroup>
            )}
            <ToggleButtonGroup
              data-learn="View Toggle: Switch between viewing the chart visualization or an example data record to understand the data structure."
              value={showExample ? 'example' : 'chart'}
              exclusive
              onChange={(_e, newValue) => {
                if (newValue !== null) {
                  setShowExample(newValue === 'example');
                }
              }}
              size="small"
              sx={{
                '& .MuiToggleButton-root': {
                  px: { xs: 1, xl: 1.5 },
                  minWidth: { xs: 48, xl: 'auto' },
                  width: { xs: 48, xl: 'auto' },
                }
              }}
            >
              <ToggleButton value="chart">
                <BarChartIcon sx={{ mr: { xs: 0, xl: 0.5 }, fontSize: 20 }} />
                <Box component="span" sx={{ display: { xs: 'none', xl: 'inline' } }}>
                  Chart
                </Box>
              </ToggleButton>
              <ToggleButton value="example">
                <DataObjectIcon sx={{ mr: { xs: 0, xl: 0.5 }, fontSize: 20 }} />
                <Box component="span" sx={{ display: { xs: 'none', xl: 'inline' } }}>
                  Example Data
                </Box>
              </ToggleButton>
            </ToggleButtonGroup>
          </Box>
        </Box>
      )}

      <Paper sx={{ 
        p: { xs: 2, sm: 2, md: 3 }, 
        height: { xs: 'calc(100vh - 280px)', sm: 'calc(100vh - 240px)', md: 'calc(100vh - 200px)' },
        display: 'flex', 
        flexDirection: 'column',
        overflow: 'hidden'
      }}>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {!chartUrl && !loading && !switchingFile && (
          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            {/* Show example record if available */}
            {exampleRecord && selectedAuditType && (
              <Box sx={{ mb: 3 }}>
                <Accordion defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <CodeIcon />
                      <Typography variant="h6">
                        Example {selectedAuditType} Record
                      </Typography>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      This is the first record from the audit file to help you understand the data structure:
                    </Typography>
                    <Paper 
                      sx={{ 
                        p: 2, 
                        bgcolor: 'grey.900', 
                        overflow: 'auto',
                        maxHeight: 400,
                      }}
                    >
                      <pre style={{ margin: 0, fontSize: '0.85rem', color: '#e0e0e0' }}>
                        {JSON.stringify(exampleRecord, null, 2)}
                      </pre>
                    </Paper>
                  </AccordionDetails>
                </Accordion>
              </Box>
            )}

            {loadingExample && !exampleRecord && (
              <Box sx={{ display: 'flex', justifyContent: 'center', mb: 3 }}>
                <CircularProgress size={24} />
                <Typography variant="body2" color="text.secondary" sx={{ ml: 2 }}>
                  Loading example record...
                </Typography>
              </Box>
            )}

            <Box
              sx={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                minHeight: 300,
                mt: exampleRecord ? 0 : 8,
              }}
            >
              <BarChartIcon sx={{ fontSize: 80, color: 'text.disabled', mb: 2 }} />
              <Typography variant="h6" color="text.secondary">
                Select configuration to view chart
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Choose an audit record type and field to automatically generate a chart
              </Typography>
              <Typography variant="caption" color="text.secondary" align="center" sx={{ maxWidth: 500 }}>
                Charts are generated server-side using go-echarts. All audit records are displayed using their actual timestamps. 
                Numeric fields support line, bar, area, scatter, funnel, and radar charts. 
                Categorical fields support pie, bar, wordcloud, funnel, sankey, and graph visualizations.
              </Typography>
            </Box>
          </Box>
        )}

        {switchingFile && (
          <Box
            sx={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              minHeight: 300,
              flex: 1,
            }}
          >
            <CircularProgress size={60} sx={{ mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              Switching data source...
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Loading chart for new capture file
            </Typography>
          </Box>
        )}

        {chartUrl && !loading && (
          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
            {showExample ? (
              <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                {loadingExample && !exampleRecord ? (
                  <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flex: 1 }}>
                    <CircularProgress size={40} />
                    <Typography variant="body1" color="text.secondary" sx={{ ml: 2 }}>
                      Loading example record...
                    </Typography>
                  </Box>
                ) : exampleRecord ? (
                  <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                    <Alert severity="info" sx={{ mb: 2, flexShrink: 0 }}>
                      This is the first record from the {selectedAuditType} audit file to help you understand the data structure and available fields.
                    </Alert>
                    <Paper 
                      sx={{ 
                        p: 2, 
                        bgcolor: 'grey.900', 
                        overflow: 'auto',
                        flex: 1,
                        minHeight: 0
                      }}
                    >
                      <pre style={{ margin: 0, fontSize: '0.85rem', color: '#e0e0e0', lineHeight: 1.5 }}>
                        {JSON.stringify(exampleRecord, null, 2)}
                      </pre>
                    </Paper>
                  </Box>
                ) : (
                  <Alert severity="warning">
                    No example record available
                  </Alert>
                )}
              </Box>
            ) : (
              <Box sx={{ width: '100%', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                <Box sx={{ flex: 1, position: 'relative', pb: 2 }}>
                  <iframe
                    key={chartUrl}
                    src={chartUrl}
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      height: '100%',
                      border: 'none',
                      borderRadius: '4px',
                    }}
                    title="Chart Visualization"
                  />
                </Box>
                {/* Max Data Points control - positioned below chart */}
                <Box
                  sx={{
                    display: 'flex',
                    justifyContent: 'flex-end',
                    alignItems: 'center',
                    mt: 1,
                    pt: 1,
                    borderTop: '1px solid',
                    borderColor: 'divider',
                    flexShrink: 0,
                  }}
                >
                  <TextField
                    data-learn="Max Data Points: Limit the number of data points displayed in the chart for better performance (default 1,000)."
                    size="small"
                    type="number"
                    label="Max Data Points"
                    value={maxDataPoints}
                    onChange={(e) => {
                      const value = parseInt(e.target.value, 10);
                      if (!Number.isNaN(value) && value > 0) {
                        setMaxDataPoints(value);
                      }
                    }}
                    inputProps={{ min: 100, max: 100000, step: 1000 }}
                    sx={{
                      width: { xs: 110, sm: 130 },
                    }}
                  />
                </Box>
              </Box>
            )}
          </Box>
        )}
      </Paper>
    </Layout>
  );
}

