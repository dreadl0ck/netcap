import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  SelectChangeEvent,
  Typography,
  Alert,
  Chip,
  Stack,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  ToggleButton,
  ToggleButtonGroup,
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
  SwapHoriz as SwapHorizIcon,
  Label as LabelIcon,
  LabelOff as LabelOffIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import { api, type ChartFieldsResponse, formatBytes } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';

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
  
  // Special Records - Security & Analysis
  'File': { field: 'Size', chartType: 'bar' },                     // File size distribution
  'Credentials': { field: 'Service', chartType: 'pie' },           // Service distribution
  'Software': { field: 'Product', chartType: 'wordcloud' },        // Product popularity
  'Vulnerability': { field: 'V2Score', chartType: 'pie' },          
  'Exploit': { field: 'Platform', chartType: 'pie' },              
  'Alert': { field: 'Classification', chartType: 'pie' },          // Alert type distribution
  'DeviceProfile': { field: 'DeviceManufacturer', chartType: 'pie' }, // Device manufacturer distribution
  'IPProfile': { field: 'NumPackets', chartType: 'line' },         // Packet count time series
};

export default function Explore() {
  const router = useRouter();
  const { type: urlType, field: urlField } = router.query;

  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: auditFiles, mutate: mutateAuditFiles } = useSWR('auditFiles', () => api.getAuditFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());

  const [selectedInput, setSelectedInput] = useState<string>('');
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

  const handleChartTypeChange = (event: SelectChangeEvent) => {
    setSelectedChartType(event.target.value);
  };

  const handleFileChange = async (event: SelectChangeEvent<string>) => {
    const newFile = event.target.value;
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(newFile);
      console.log('Directory changed to:', result.outputDir);
      await mutateAuditFiles(); // Refresh audit files
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Clear current chart
      setChartUrl(null);
      setSelectedAuditType('');
      setSelectedField('');
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert('Failed to switch to this file');
    } finally {
      setSwitchingFile(false);
    }
  };

  // Auto-generate chart when configuration changes
  useEffect(() => {
    if (!selectedAuditType || !selectedField) {
      return;
    }

    setLoading(true);
    setError(null);
    
    // Build chart URL - chart will be generated server-side by go-echarts
    // No interval parameter - use all records with actual timestamps
    const url = `/api/chart/data?type=${encodeURIComponent(selectedAuditType)}&field=${encodeURIComponent(selectedField)}&chartType=${encodeURIComponent(selectedChartType)}&showLegend=${showLegend}`;
    setChartUrl(url);
    setLoading(false);
  }, [selectedAuditType, selectedField, selectedChartType, showLegend]);

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

  // Get only completed files for the selector, sorted alphabetically for consistency
  // NOTE: Backend should keep initial pcaps marked as isCompleted forever
  const completedFiles = (inputFiles?.filter((f: any) => f.isCompleted) || [])
    .sort((a: any, b: any) => a.path.localeCompare(b.path));
  
  // Current selected value - use backend's activeInputFile or fallback to first file
  const selectedValue = status?.activeInputFile || completedFiles[0]?.path || '';
  // Match by comparing both full path and basename (activeInputFile might be just filename or full path)
  const selectedFile = completedFiles.find((f: any) => 
    f.path === selectedValue || f.name === selectedValue || f.path.endsWith('/' + selectedValue)
  );

  return (
    <Layout title="Explore">
      <Box sx={{ mb: 3 }}>
        {/* File selector - show when multiple input files are available */}
        {completedFiles.length > 1 && selectedFile && (
          <Box mb={2}>
            <Typography variant="caption" color="text.secondary" display="block" mb={0.5}>
              Viewing capture:
            </Typography>
            <FormControl size="small" disabled={switchingFile} sx={{ minWidth: 500, maxWidth: 800 }}>
              <Select
                value={selectedValue}
                onChange={handleFileChange}
                startAdornment={
                  switchingFile ? (
                    <CircularProgress size={20} sx={{ mr: 1 }} />
                  ) : (
                    <SwapHorizIcon sx={{ mr: 1, color: 'action.active' }} />
                  )
                }
                renderValue={() => (
                  <Box display="flex" alignItems="center" gap={1}>
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                      {selectedFile.name}
                    </Typography>
                    <Chip
                      label={formatBytes(selectedFile.size)}
                      size="small"
                      sx={{ height: 20, fontSize: '0.7rem' }}
                    />
                  </Box>
                )}
                sx={{
                  '& .MuiSelect-select': {
                    display: 'flex',
                    alignItems: 'center',
                  },
                }}
              >
                {completedFiles.map((file: any) => (
                  <MenuItem key={file.path} value={file.path}>
                    <Box display="flex" alignItems="center" gap={1} width="100%">
                      {selectedValue === file.path && (
                        <Chip
                          label="Active"
                          size="small"
                          color="success"
                          sx={{ height: 20, fontSize: '0.7rem' }}
                        />
                      )}
                      <Typography
                        sx={{
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          flex: 1,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {file.name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {formatBytes(file.size)}
                      </Typography>
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
        )}

        <Box>
          <Typography variant="h4" gutterBottom>
            Explore Audit Records
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Generate interactive charts from audit record data
          </Typography>
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* Configuration Panel */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <CardContent sx={{ flex: 1, overflow: 'auto' }}>
              <Typography variant="h6" gutterBottom>
                Chart Configuration
              </Typography>

              <Stack spacing={2}>
                {/* Audit Type Selection */}
                <FormControl fullWidth>
                  <InputLabel>Audit Record Type</InputLabel>
                  <Select
                    value={selectedAuditType}
                    onChange={handleAuditTypeChange}
                    label="Audit Record Type"
                  >
                    {auditTypes.map((type) => (
                      <MenuItem key={type} value={type}>
                        {type}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                {/* Field Selection */}
                <FormControl fullWidth disabled={!selectedAuditType || loading}>
                  <InputLabel>Field</InputLabel>
                  <Select
                    value={selectedField}
                    onChange={handleFieldChange}
                    label="Field"
                  >
                    {fields?.fields.map((field) => (
                      <MenuItem key={field.name} value={field.name}>
                        {field.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                {/* Info about field filtering */}
                {fields && fields.fields.length > 0 && fields.filteredCount > 0 && (
                  <Alert severity="info" sx={{ mt: 1 }}>
                    <Typography variant="caption">
                      {fields.filteredCount} field{fields.filteredCount !== 1 ? 's' : ''} without data hidden from this list.
                    </Typography>
                  </Alert>
                )}

                {/* Chart Type Selection */}
                <FormControl fullWidth>
                  <InputLabel>Chart Type</InputLabel>
                  <Select
                    value={selectedChartType}
                    onChange={handleChartTypeChange}
                    label="Chart Type"
                  >
                    {availableChartTypes.map((type) => (
                      <MenuItem key={type.value} value={type.value}>
                        <Box sx={{ display: 'flex', flexDirection: 'column', py: 0.5 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {type.icon}
                            {type.label}
                          </Box>
                          <Typography variant="caption" color="text.secondary" sx={{ ml: 4 }}>
                            {type.description}
                          </Typography>
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                {selectedAuditType && selectedField && (
                  <Alert severity="success" sx={{ mt: 1 }}>
                    <Typography variant="caption">
                      Chart auto-generates on configuration change
                    </Typography>
                  </Alert>
                )}
              </Stack>

            </CardContent>
          </Card>
        </Grid>

        {/* Chart Display */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3, minHeight: 680, height: '100%', display: 'flex', flexDirection: 'column' }}>
            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            {!chartUrl && !loading && (
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

            {chartUrl && !loading && (
              <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                {/* Toggle between chart and example data */}
                <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
                  <Typography variant="h6">
                    {showExample ? 'Example Audit Record' : 'Chart Visualization'}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    {/* Legend toggle - only show when viewing chart */}
                    {!showExample && (
                      <ToggleButtonGroup
                        value={showLegend ? 'on' : 'off'}
                        exclusive
                        onChange={(_e, newValue) => {
                          if (newValue !== null) {
                            setShowLegend(newValue === 'on');
                          }
                        }}
                        size="small"
                      >
                        <ToggleButton value="on">
                          <LabelIcon sx={{ mr: 0.5, fontSize: 18 }} />
                          Legend
                        </ToggleButton>
                        <ToggleButton value="off">
                          <LabelOffIcon sx={{ mr: 0.5, fontSize: 18 }} />
                          No Legend
                        </ToggleButton>
                      </ToggleButtonGroup>
                    )}
                    <ToggleButtonGroup
                      value={showExample ? 'example' : 'chart'}
                      exclusive
                      onChange={(_e, newValue) => {
                        if (newValue !== null) {
                          setShowExample(newValue === 'example');
                        }
                      }}
                      size="small"
                    >
                      <ToggleButton value="chart">
                        <BarChartIcon sx={{ mr: 1, fontSize: 20 }} />
                        Chart
                      </ToggleButton>
                      <ToggleButton value="example">
                        <DataObjectIcon sx={{ mr: 1, fontSize: 20 }} />
                        Example Data
                      </ToggleButton>
                    </ToggleButtonGroup>
                  </Box>
                </Box>

                {showExample ? (
                  <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                    {loadingExample && !exampleRecord ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flex: 1 }}>
                        <CircularProgress size={40} />
                        <Typography variant="body1" color="text.secondary" sx={{ ml: 2 }}>
                          Loading example record...
                        </Typography>
                      </Box>
                    ) : exampleRecord ? (
                      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                        <Alert severity="info" sx={{ mb: 2 }}>
                          This is the first record from the {selectedAuditType} audit file to help you understand the data structure and available fields.
                        </Alert>
                        <Paper 
                          sx={{ 
                            p: 2, 
                            bgcolor: 'grey.900', 
                            overflow: 'auto',
                            flex: 1,
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
                  <Box sx={{ width: '100%', flex: 1, position: 'relative', minHeight: 600 }}>
                    <iframe
                      src={chartUrl}
                      style={{
                        width: '100%',
                        height: '100%',
                        border: 'none',
                        borderRadius: '4px',
                      }}
                      title="Chart Visualization"
                    />
                  </Box>
                )}
              </Box>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Layout>
  );
}

