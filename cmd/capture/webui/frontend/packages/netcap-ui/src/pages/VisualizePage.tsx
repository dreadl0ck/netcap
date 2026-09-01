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

import { useState, useEffect, useCallback } from 'react';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import CircularProgress from '@mui/material/CircularProgress';
import FormControl from '@mui/material/FormControl';
import Grid from '@mui/material/Grid';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import Select, { type SelectChangeEvent } from '@mui/material/Select';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import Chip from '@mui/material/Chip';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import Slider from '@mui/material/Slider';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import GridViewIcon from '@mui/icons-material/GridView';
import BarChartIcon from '@mui/icons-material/BarChart';
import BubbleChartIcon from '@mui/icons-material/BubbleChart';
import LabelIcon from '@mui/icons-material/Label';
import LabelOffIcon from '@mui/icons-material/LabelOff';
import PublicIcon from '@mui/icons-material/Public';
import ScatterPlotIcon from '@mui/icons-material/ScatterPlot';
import HubIcon from '@mui/icons-material/Hub';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { getBackendUrl, type ProtocolHierarchyResponse } from '../lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useNetcapRouter, useNetcapApi } from '../hooks';

import { ChartFrame } from '../components/ChartFrame';
const CHART_TYPES = [
  { value: 'sankey', label: 'Sankey Diagram', icon: <AccountTreeIcon /> },
  { value: 'treemap', label: 'Treemap', icon: <GridViewIcon /> },
  { value: 'bar3d', label: '3D Bar Chart', icon: <BarChartIcon /> },
  { value: 'graph', label: 'Network Graph', icon: <BubbleChartIcon /> },
  { value: 'geo', label: 'Geo Map', icon: <PublicIcon /> },
  { value: 'scatter3d', label: '3D Scatter', icon: <ScatterPlotIcon /> },
  { value: 'hosts-graph', label: 'Hosts Graph', icon: <HubIcon /> },
];

export default function Visualize() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
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
  const [chartTypeRotationAttempted, setChartTypeRotationAttempted] = useState(false);
  const [maxNodes, setMaxNodes] = useState(100);
  const [maxConnections, setMaxConnections] = useState(100000);
  const [graphLayout, setGraphLayout] = useState('circular');

  // Chart type rotation: get/set the index of the last used chart type
  const getNextChartTypeIndex = useCallback((availableTypes: typeof CHART_TYPES): number => {
    if (availableTypes.length === 0) return 0;
    
    const storageKey = 'visualize-chart-type-rotation';
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

  // Auto-select next chart type in rotation when visualize tab is opened
  useEffect(() => {
    // Only attempt once per page load
    if (chartTypeRotationAttempted) return;
    
    // Auto-select next chart type in rotation
    const nextIndex = getNextChartTypeIndex(CHART_TYPES);
    const nextType = CHART_TYPES[nextIndex].value;
    setSelectedChartType(nextType);
    setChartTypeRotationAttempted(true);
    
    // Note: If the selected type is sankey, the existing useEffect at line ~178 will handle loading hierarchy
  }, [chartTypeRotationAttempted, getNextChartTypeIndex]);

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

  // Handler for FileSelectorHeader component (receives path string)
  const handleFileSelectorChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
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
      alert('Failed to switch to this capture');
    } finally {
      setSwitchingFile(false);
    }
  }, [mutateStatus, selectedChartType]);

  // Set initial file from URL parameter
  useEffect(() => {
    if (urlFile && typeof urlFile === 'string') {
      handleFileSelectorChange(urlFile);
    }
  }, [urlFile, handleFileSelectorChange]);

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

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileSelectorChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to visualize their protocol hierarchy and statistics."
    />
  );


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
      const backend = getBackendUrl();
      switch (selectedChartType) {
        case 'sankey':
          return `${backend}/api/visualize/sankey`;
        case 'treemap':
          return `${backend}/api/visualize/treemap`;
        case 'bar3d':
          return `${backend}/api/visualize/bar3d`;
        case 'graph':
          return `${backend}/api/visualize/graph`;
        case 'geo':
          return `${backend}/api/visualize/geo`;
        case 'scatter3d':
          return `${backend}/api/visualize/scatter3d`;
        case 'hosts-graph':
          return `${backend}/api/visualize/hosts-graph`;
        default:
          return null;
      }
    })();
    
    if (!baseUrl) return null;
    
    // Add showLegend parameter
    const params = new URLSearchParams({ showLegend: showLegend.toString() });
    
    // Add maxNodes parameter for hosts-graph
    if (selectedChartType === 'hosts-graph') {
      params.append('maxNodes', maxNodes.toString());
    }
    
    // Add maxConnections parameter for scatter3d
    if (selectedChartType === 'scatter3d') {
      params.append('maxConnections', maxConnections.toString());
    }
    
    // Add layout parameter for graph-based charts
    if (selectedChartType === 'graph' || selectedChartType === 'hosts-graph') {
      params.append('layout', graphLayout);
    }
    
    return `${baseUrl}?${params.toString()}`;
  };

  const chartUrl = getChartUrl();
  
  // Refresh chart when legend toggle, maxNodes, maxConnections, or graphLayout changes
  useEffect(() => {
    setChartRefreshKey(prev => prev + 1);
  }, [showLegend, maxNodes, maxConnections, graphLayout]);

  return (
    <Layout title="Visualize" headerAction={fileSelector}>
      {/* Chart type selector and legend toggle - wraps on mobile */}
      <Box 
        sx={{ 
          mb: selectedChartType === 'sankey' ? 3 : 1,
          display: 'flex',
          flexDirection: { xs: 'column', md: 'row' },
          alignItems: { xs: 'stretch', md: 'center' },
          justifyContent: 'space-between',
          gap: 2
        }}
      >
        {/* Chart Type Buttons - scrollable on mobile */}
        <Box sx={{ 
          overflowX: { xs: 'auto', md: 'visible' },
          overflowY: 'visible',
          width: { xs: '100%', md: 'auto' },
          // Hide scrollbar on webkit browsers
          '&::-webkit-scrollbar': { display: 'none' },
          msOverflowStyle: 'none',
          scrollbarWidth: 'none',
        }}>
          <ToggleButtonGroup
            data-learn="Visualization Type: Choose between Sankey diagram, Treemap, 3D Bar Chart, Network Graph, Geo Map, 3D Scatter plot, or Hosts Graph to visualize protocol data in different ways."
            value={selectedChartType}
            exclusive
            onChange={(_e, newValue) => {
              if (newValue !== null) {
                setSelectedChartType(newValue);
                setError(null);
                // Refresh chart key to force reload
                setChartRefreshKey(prev => prev + 1);
                // Load hierarchy data for sankey
                if (newValue === 'sankey') {
                  loadHierarchy();
                }
              }
            }}
            size="small"
            sx={{
              display: 'flex',
              flexWrap: { xs: 'nowrap', md: 'wrap' },
            }}
          >
            {CHART_TYPES.map((type) => (
              <ToggleButton 
                key={type.value} 
                value={type.value}
                sx={{
                  px: { xs: 1, xl: 2 },
                  minWidth: { xs: 48, xl: 'auto' },
                  width: { xs: 48, xl: 'auto' },
                  flexShrink: { xs: 0, md: 1 },
                }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: { xs: 0, xl: 1 } }}>
                  {type.icon}
                  <Box component="span" sx={{ display: { xs: 'none', xl: 'inline' } }}>
                    {type.label}
                  </Box>
                </Box>
              </ToggleButton>
            ))}
          </ToggleButtonGroup>
        </Box>

        {/* Legend Toggle and Layout Selector - Always shown on the right */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {/* Graph Layout Selector - Only for graph-based charts */}
          {(selectedChartType === 'graph' || selectedChartType === 'hosts-graph') && (
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <Select
                data-learn="Graph Layout: Choose the layout algorithm for the graph visualization. Force uses physics simulation, Circular arranges nodes in a circle, and None uses fixed positions."
                value={graphLayout}
                onChange={(e) => setGraphLayout(e.target.value)}
                sx={{
                  '& .MuiOutlinedInput-notchedOutline': {
                    borderColor: 'rgba(255, 255, 255, 0.23)',
                  },
                  '&:hover .MuiOutlinedInput-notchedOutline': {
                    borderColor: 'rgba(255, 255, 255, 0.4)',
                  },
                  '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                    borderColor: 'primary.light',
                  },
                }}
              >
                <MenuItem value="force">Force Layout</MenuItem>
                <MenuItem value="circular">Circular Layout</MenuItem>
                <MenuItem value="none">Fixed Layout</MenuItem>
              </Select>
            </FormControl>
          )}
          
          <ToggleButtonGroup
            data-learn="Legend Toggle: Show or hide the chart legend that explains the visualization's color coding and labels."
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
                px: { xs: 1, xl: 2 },
                minWidth: { xs: 48, xl: 'auto' },
                width: { xs: 48, xl: 'auto' },
              }
            }}
          >
            <ToggleButton value="on">
              <LabelIcon sx={{ mr: { xs: 0, xl: 0.5 }, fontSize: 18 }} />
              <Box component="span" sx={{ display: { xs: 'none', xl: 'inline' } }}>
                On
              </Box>
            </ToggleButton>
            <ToggleButton value="off">
              <LabelOffIcon sx={{ mr: { xs: 0, xl: 0.5 }, fontSize: 18 }} />
              <Box component="span" sx={{ display: { xs: 'none', xl: 'inline' } }}>
                Off
              </Box>
            </ToggleButton>
          </ToggleButtonGroup>
          
          {/* Max Nodes Slider - Only for hosts-graph */}
          {selectedChartType === 'hosts-graph' && (
            <Box 
              data-learn="Max Nodes Limit: Control the maximum number of host nodes displayed in the network graph to optimize performance and readability."
              sx={{ 
                display: { xs: 'none', sm: 'flex' }, 
                alignItems: 'center', 
                gap: 2, 
                minWidth: 250 
              }}
            >
              <Typography variant="body2" sx={{ whiteSpace: 'nowrap', minWidth: 85 }}>
                Max Nodes:
              </Typography>
              <Slider
                value={maxNodes}
                onChange={(_e, newValue) => setMaxNodes(newValue as number)}
                min={100}
                max={5000}
                step={100}
                valueLabelDisplay="auto"
                sx={{ width: 150 }}
              />
              <Typography variant="body2" sx={{ minWidth: 40, textAlign: 'right' }}>
                {maxNodes}
              </Typography>
            </Box>
          )}
          
          {/* Max Connections Slider - Only for scatter3d */}
          {selectedChartType === 'scatter3d' && (
            <Box 
              data-learn="Max Connections Limit: Control the maximum number of network connections displayed in the 3D scatter plot to optimize rendering performance."
              sx={{ 
                display: { xs: 'none', sm: 'flex' }, 
                alignItems: 'center', 
                gap: 2, 
                minWidth: 280 
              }}
            >
              <Typography variant="body2" sx={{ whiteSpace: 'nowrap', minWidth: 120 }}>
                Max Connections:
              </Typography>
              <Slider
                value={maxConnections}
                onChange={(_e, newValue) => setMaxConnections(newValue as number)}
                min={1000}
                max={500000}
                step={1000}
                valueLabelDisplay="auto"
                sx={{ width: 150 }}
              />
              <Typography variant="body2" sx={{ minWidth: 60, textAlign: 'right' }}>
                {maxConnections.toLocaleString()}
              </Typography>
            </Box>
          )}
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* Protocol Statistics Panel - Only show for Sankey */}
        {selectedChartType === 'sankey' && (
          <Grid item xs={12} lg={4} sx={{ order: { xs: 2, lg: 1 } }}>
            <Card 
              data-learn="Protocol Statistics: Detailed breakdown of network protocols found in the capture, organized by OSI layer (Link, Network, Transport, Application) with packet counts."
              sx={{ height: 'calc(100vh - 300px)', display: 'flex', flexDirection: 'column' }}
            >
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
                    <AccountTreeIcon sx={{ fontSize: 60, color: 'text.disabled', mb: 2 }} />
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
        <Grid item xs={12} lg={selectedChartType === 'sankey' ? 8 : 12} sx={{ order: { xs: 1, lg: 2 } }}>
          <Paper sx={{ p: selectedChartType === 'sankey' ? 3 : 2, height: selectedChartType === 'sankey' ? 'calc(100vh - 300px)' : 'calc(100vh - 180px)', display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h6" gutterBottom sx={{ mb: selectedChartType === 'sankey' ? 2 : 1 }}>
              {CHART_TYPES.find(ct => ct.value === selectedChartType)?.label || 'Visualization'}
            </Typography>
            
            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            {/* ECharts-based visualizations (Sankey, Treemap, Bar3D, Graph, Geo, Scatter3D, Hosts Graph) */}
            {chartUrl && (
              <Box sx={{ width: '100%', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                <Box sx={{ flex: 1, position: 'relative', minHeight: 400 }}>
                  <ChartFrame
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
