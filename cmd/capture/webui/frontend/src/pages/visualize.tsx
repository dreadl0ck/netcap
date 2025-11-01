import { useState, useEffect } from 'react';
import {
  Box,
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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
import {
  AccountTree as SankeyIcon,
  SwapHoriz as SwapHorizIcon,
  GridView as TreemapIcon,
  BarChart as Bar3DIcon,
  BubbleChart as GraphIcon,
  Label as LabelIcon,
  LabelOff as LabelOffIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import { api, formatBytes, type ProtocolHierarchyResponse } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';
import { Chart } from 'react-google-charts';

const CHART_TYPES = [
  { value: 'sankey', label: 'Sankey Diagram', icon: <SankeyIcon /> },
  { value: 'treemap', label: 'Treemap', icon: <TreemapIcon /> },
  { value: 'bar3d', label: '3D Bar Chart', icon: <Bar3DIcon /> },
  { value: 'graph', label: 'Network Graph', icon: <GraphIcon /> },
];

export default function Visualize() {
  const router = useRouter();
  const { file: urlFile } = router.query;

  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());

  const [switchingFile, setSwitchingFile] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hierarchyData, setHierarchyData] = useState<ProtocolHierarchyResponse | null>(null);
  const [selectedChartType, setSelectedChartType] = useState<string>('sankey');
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
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
        console.log('[Visualize] Auto-selecting first completed file:', completed[0].path);
        setAutoSelectAttempted(true);
        try {
          await api.setActiveDirectory(completed[0].path);
          await mutateStatus();
          // Reload hierarchy if sankey is selected
          if (selectedChartType === 'sankey') {
            loadHierarchy();
          }
        } catch (err) {
          console.error('[Visualize] Failed to auto-select file:', err);
        }
      }
    };
    
    autoSelectFirstFile();
  }, [inputFiles, status, autoSelectAttempted, mutateStatus, selectedChartType]);

  // Listen for directory changes and refresh
  useEffect(() => {
    const handleDirectoryChange = () => {
      console.log('Directory changed, refreshing for visualize...');
      mutateStatus(); // Refresh status
      // Clear current visualization
      setHierarchyData(null);
      // Reload hierarchy if sankey is selected
      if (selectedChartType === 'sankey') {
        loadHierarchy();
      }
    };
    
    window.addEventListener('directory-changed', handleDirectoryChange);
    return () => window.removeEventListener('directory-changed', handleDirectoryChange);
  }, [mutateStatus, selectedChartType]);

  // Set initial file from URL parameter
  useEffect(() => {
    if (urlFile && typeof urlFile === 'string') {
      handleFileChange({ target: { value: urlFile } } as SelectChangeEvent<string>);
    }
  }, [urlFile]);

  const handleFileChange = async (event: SelectChangeEvent<string>) => {
    const newFile = event.target.value;
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(newFile);
      console.log('Directory changed to:', result.outputDir);
      await mutateStatus(); // Refresh status
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Clear current visualization
      setHierarchyData(null);
      
      // Refresh chart by incrementing key (forces iframe reload for echarts)
      setChartRefreshKey(prev => prev + 1);
      
      // Load new data based on chart type
      if (selectedChartType === 'sankey') {
        await loadHierarchy();
      }
      // For other chart types (treemap, bar3d, graph), the iframe will reload automatically due to key change
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert('Failed to switch to this file');
    } finally {
      setSwitchingFile(false);
    }
  };

  const loadHierarchy = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getProtocolHierarchy();
      setHierarchyData(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load protocol hierarchy');
    } finally {
      setLoading(false);
    }
  };

  // Load hierarchy on mount if sankey is selected
  useEffect(() => {
    if (selectedChartType === 'sankey') {
      loadHierarchy();
    }
  }, [selectedChartType]);

  const handleChartTypeChange = (event: SelectChangeEvent) => {
    setSelectedChartType(event.target.value);
    setError(null);
    // Refresh chart key to force reload
    setChartRefreshKey(prev => prev + 1);
    // Load hierarchy data for sankey
    if (event.target.value === 'sankey') {
      loadHierarchy();
    }
  };

  // Get only completed files for the selector, sorted alphabetically for consistency
  const completedFiles = (inputFiles?.filter((f: any) => f.isCompleted) || [])
    .sort((a: any, b: any) => a.path.localeCompare(b.path));
  
  // Current selected value - use backend's activeInputFile or fallback to first file
  const selectedValue = status?.activeInputFile || completedFiles[0]?.path || '';
  // Match by comparing both full path and basename
  const selectedFile = completedFiles.find((f: any) => 
    f.path === selectedValue || f.name === selectedValue || f.path.endsWith('/' + selectedValue)
  );

  // Prepare data for Sankey diagram
  const sankeyData = hierarchyData ? (() => {
    // Google Charts Sankey format: [['From', 'To', Weight], ...]
    const data: Array<[string, string, string | number]> = [['From', 'To', 'Packet Count']];
    
    hierarchyData.links.forEach(link => {
      data.push([link.source, link.target, link.value]);
    });
    
    return data;
  })() : null;

  // Chart options
  const sankeyOptions = {
    sankey: {
      node: {
        colors: ['#a61d4c'],
        label: {
          fontName: 'Roboto',
          fontSize: 14,
          color: '#333',
        },
        nodePadding: 20,
        width: 8,
      },
      link: {
        colorMode: 'gradient',
        colors: ['#b3d9ff', '#66b3ff', '#3399ff', '#0073e6', '#004d99'],
      },
    },
    tooltip: {
      textStyle: {
        fontName: 'Roboto',
        fontSize: 13,
      },
    },
  };

  // Get layer color
  const getLayerColor = (layer: string) => {
    const colors: Record<string, string> = {
      'Link Layer': 'primary',
      'Network Layer': 'secondary',
      'Transport Layer': 'success',
      'Application Layer': 'warning',
      'Custom Abstraction': 'default',
    };
    return colors[layer] || 'default';
  };

  // Get chart URL for echarts-based visualizations
  const getChartUrl = () => {
    const baseUrl = (() => {
      switch (selectedChartType) {
        case 'treemap':
          return '/api/visualize/treemap';
        case 'bar3d':
          return '/api/visualize/bar3d';
        case 'graph':
          return '/api/visualize/graph';
        default:
          return null;
      }
    })();
    
    if (!baseUrl) return null;
    
    // Add showLegend parameter
    return `${baseUrl}?showLegend=${showLegend}`;
  };

  const chartUrl = getChartUrl();
  
  // Refresh chart when legend toggle changes
  useEffect(() => {
    setChartRefreshKey(prev => prev + 1);
  }, [showLegend]);

  return (
    <Layout title="Visualize">
      <Box sx={{ mb: selectedChartType === 'sankey' ? 3 : 1 }}>
        {/* File selector and chart type selector on same row */}
        <Box display="flex" gap={2} mb={selectedChartType === 'sankey' ? 2 : 1} alignItems="center">
          {/* File selector - show when multiple input files are available */}
          {completedFiles.length > 1 && selectedFile && (
            <Box flex={1}>
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

          {/* Chart Type Selector */}
          <Box>
            <Typography variant="caption" color="text.secondary" display="block" mb={0.5}>
              Chart Type:
            </Typography>
            <FormControl size="small" sx={{ minWidth: 200 }}>
              <Select
                value={selectedChartType}
                onChange={handleChartTypeChange}
              >
                {CHART_TYPES.map((type) => (
                  <MenuItem key={type.value} value={type.value}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {type.icon}
                      {type.label}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>

          {/* Legend Toggle - Only show for echarts-based visualizations */}
          {selectedChartType !== 'sankey' && (
            <Box>
              <Typography variant="caption" color="text.secondary" display="block" mb={0.5}>
                Legend:
              </Typography>
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
                  On
                </ToggleButton>
                <ToggleButton value="off">
                  <LabelOffIcon sx={{ mr: 0.5, fontSize: 18 }} />
                  Off
                </ToggleButton>
              </ToggleButtonGroup>
            </Box>
          )}
        </Box>

        {selectedChartType === 'sankey' && (
          <Box>
            <Typography variant="h4" gutterBottom>
              Protocol Hierarchy Visualization
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Explore protocol encapsulation and relationships using different chart types
            </Typography>
          </Box>
        )}
      </Box>

      <Grid container spacing={3}>
        {/* Protocol Statistics Panel - Only show for Sankey */}
        {selectedChartType === 'sankey' && (
          <Grid item xs={12} md={4}>
            <Card sx={{ height: 'calc(100vh - 300px)', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flex: 1, overflow: 'auto' }}>
                <Typography variant="h6" gutterBottom>
                  Protocol Statistics
                </Typography>

                {loading && (
                  <Box display="flex" justifyContent="center" alignItems="center" minHeight={200}>
                    <CircularProgress />
                  </Box>
                )}

                {error && (
                  <Alert severity="error" sx={{ mb: 2 }}>
                    {error}
                  </Alert>
                )}

                {hierarchyData && hierarchyData.stats && (
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Protocol</TableCell>
                          <TableCell align="right">Count</TableCell>
                          <TableCell>Layer</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {Object.entries(hierarchyData.stats)
                          .sort((a, b) => b[1].count - a[1].count)
                          .map(([protocol, stats]) => (
                            <TableRow key={protocol} hover>
                              <TableCell>
                                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                  {protocol}
                                </Typography>
                              </TableCell>
                              <TableCell align="right">
                                <Typography variant="body2">
                                  {stats.count.toLocaleString()}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={stats.layer}
                                  size="small"
                                  color={getLayerColor(stats.layer) as any}
                                  sx={{ fontSize: '0.7rem' }}
                                />
                              </TableCell>
                            </TableRow>
                          ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}

                {!hierarchyData && !loading && !error && (
                  <Box
                    sx={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      minHeight: 200,
                    }}
                  >
                    <SankeyIcon sx={{ fontSize: 60, color: 'text.disabled', mb: 2 }} />
                    <Typography variant="body2" color="text.secondary">
                      No protocol data available
                    </Typography>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Chart Display */}
        <Grid item xs={12} md={selectedChartType === 'sankey' ? 8 : 12}>
          <Paper sx={{ p: selectedChartType === 'sankey' ? 3 : 2, height: selectedChartType === 'sankey' ? 'calc(100vh - 300px)' : 'calc(100vh - 180px)', display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h6" gutterBottom sx={{ mb: selectedChartType === 'sankey' ? 2 : 1 }}>
              {CHART_TYPES.find(ct => ct.value === selectedChartType)?.label || 'Visualization'}
            </Typography>
            
            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            {/* Sankey Diagram */}
            {selectedChartType === 'sankey' && (
              <>
                {loading && (
                  <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flex: 1 }}>
                    <CircularProgress size={60} />
                  </Box>
                )}

                {!loading && !error && sankeyData && sankeyData.length > 1 && (
                  <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      This diagram shows how protocols are encapsulated within each other. 
                      The width of the flows represents the number of packets for each protocol relationship.
                    </Alert>
                    <Box sx={{ width: '100%', height: 'calc(100vh - 460px)' }}>
                      <Chart
                        chartType="Sankey"
                        width="100%"
                        height="100%"
                        data={sankeyData}
                        options={sankeyOptions}
                      />
                    </Box>
                  </Box>
                )}

                {!loading && !error && sankeyData && sankeyData.length === 1 && (
                  <Box
                    sx={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flex: 1,
                    }}
                  >
                    <SankeyIcon sx={{ fontSize: 80, color: 'text.disabled', mb: 2 }} />
                    <Typography variant="h6" color="text.secondary">
                      No protocol relationships found
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                      The capture file may not contain enough data to build a protocol hierarchy.
                    </Typography>
                  </Box>
                )}
              </>
            )}

            {/* ECharts-based visualizations (Treemap, Bar3D, Graph) */}
            {chartUrl && (
              <Box sx={{ width: '100%', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                <Alert severity="info" sx={{ mb: 1, py: 0.5, flexShrink: 0 }}>
                  {selectedChartType === 'treemap' && 'Treemap shows audit record types grouped by protocol layer with size representing record count.'}
                  {selectedChartType === 'bar3d' && '3D bar chart displays audit record types organized by layer with interactive rotation.'}
                  {selectedChartType === 'graph' && 'Network graph visualizes protocol relationships with node size based on record count.'}
                </Alert>
                <Box sx={{ flex: 1, position: 'relative', minHeight: 650 }}>
                  <iframe
                    key={chartRefreshKey}
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
                    title={`${selectedChartType} Visualization`}
                  />
                </Box>
              </Box>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Layout>
  );
}
