import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  IconButton,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  SelectChangeEvent,
  Typography,
} from '@mui/material';
import {
  ChevronRight as ChevronRightIcon,
  ExpandMore as ExpandMoreIcon,
  Folder as FolderIcon,
  InsertDriveFile as FileIcon,
  SwapHoriz as SwapHorizIcon,
  Download as DownloadIcon,
  BarChart as BarChartIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import { api, formatBytes } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';

interface LayerGroup {
  layerName: string;
  files: any[];
}

export default function AuditRecords() {
  const router = useRouter();
  const { data: files, error, mutate } = useSWR('auditFiles', () => api.getAuditFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: sessions } = useSWR(
    status?.isTryService ? 'try-sessions' : null, 
    () => api.getAllSessions()
  );
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [switchingSession, setSwitchingSession] = useState(false);
  // Expand all sections by default
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set([
    'Link Layer', 
    'Network Layer', 
    'Transport Layer', 
    'Application Layer',
    'Stream Decoders',
    'Abstract Decoders',
    'Other',
    'Unknown Layer'
  ]));
  const [switchingFile, setSwitchingFile] = useState(false);
  const [autoSelectAttempted, setAutoSelectAttempted] = useState(false);

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
        console.log('[Audit] Auto-selecting first completed file:', completed[0].path);
        setAutoSelectAttempted(true);
        try {
          await api.setActiveDirectory(completed[0].path);
          await mutateStatus();
          await mutate();
        } catch (err) {
          console.error('[Audit] Failed to auto-select file:', err);
        }
      }
    };
    
    autoSelectFirstFile();
  }, [inputFiles, status, autoSelectAttempted, mutateStatus, mutate]);
  
  // Listen for directory changes and refresh audit files
  useEffect(() => {
    const handleDirectoryChange = () => {
      console.log('Directory changed, refreshing audit files...');
      mutate(); // Refresh audit files
    };
    
    window.addEventListener('directory-changed', handleDirectoryChange);
    return () => window.removeEventListener('directory-changed', handleDirectoryChange);
  }, [mutate]);
  
  const [records, setRecords] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [total, setTotal] = useState(0);
  const [streamError, setStreamError] = useState<string | null>(null);

  const handleViewRecords = (type: string) => {
    setSelectedType(type);
    setRecords([]);
    setProgress(0);
    setTotal(0);
    setLoading(true);
    setStreamError(null);

    const eventSource = api.streamAuditRecords(
      type,
      0,
      1000,
      (record) => {
        setRecords((prev) => [...prev, record]);
      },
      (count) => {
        setProgress(count);
      },
      (total) => {
        setTotal(total);
        setLoading(false);
      },
      (error) => {
        console.error('Stream error:', error);
        setStreamError(error);
        setLoading(false);
      }
    );

    return () => eventSource.close();
  };

  const handleClose = () => {
    setSelectedType(null);
    setRecords([]);
    setStreamError(null);
  };

  const handleSessionChange = async (event: SelectChangeEvent<string>) => {
    const sessionId = event.target.value;
    setSwitchingSession(true);
    try {
      await api.selectSession(sessionId);
      // Refresh data
      await mutate();
      await mutateStatus();
    } catch (error) {
      console.error('Failed to switch session:', error);
      alert('Failed to switch to selected session');
    } finally {
      setSwitchingSession(false);
    }
  };

  const toggleLayer = (layerName: string) => {
    setExpandedLayers(prev => {
      const newSet = new Set(prev);
      if (newSet.has(layerName)) {
        newSet.delete(layerName);
      } else {
        newSet.add(layerName);
      }
      return newSet;
    });
  };

  const handleFileChange = async (event: SelectChangeEvent<string>) => {
    const newFile = event.target.value;
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(newFile);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      await mutate();
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert('Failed to switch to this file');
    } finally {
      setSwitchingFile(false);
    }
  };

  const handleDownloadAll = () => {
    // Get session ID from status or construct download URL
    const sessionId = status?.sessionId;
    if (!sessionId) {
      console.error('No session ID available for download');
      alert('Unable to download: session information not available');
      return;
    }

    // Trigger download by opening the download URL
    const downloadUrl = `/api/download/${sessionId}`;
    window.open(downloadUrl, '_blank');
  };

  // Get only completed files for the selector, sorted alphabetically for consistency
  // NOTE: Backend should keep initial pcaps marked as isCompleted forever
  const completedFiles = (inputFiles?.filter((f: any) => f.isCompleted) || [])
    .sort((a: any, b: any) => a.path.localeCompare(b.path));
  const isMultiFile = status?.isMultiFile || false;
  
  // Current selected value - use backend's activeInputFile or fallback to first file
  const selectedValue = status?.activeInputFile || completedFiles[0]?.path || '';
  // Match by comparing both full path and basename (activeInputFile might be just filename or full path)
  const selectedFile = completedFiles.find((f: any) => 
    f.path === selectedValue || f.name === selectedValue || f.path.endsWith('/' + selectedValue)
  );

  // Debug logging
  console.log('[Audit] Debug info:', {
    completedFilesCount: completedFiles.length,
    completedFilesPaths: completedFiles.map((f: any) => f.path),
    statusActiveInputFile: status?.activeInputFile,
    selectedValue,
    selectedFileFound: !!selectedFile,
    selectedFileName: selectedFile?.name,
    willShowSelector: completedFiles.length > 1 && !!selectedFile
  });

  // Group files by layer, filtering out empty files
  const layerGroups: LayerGroup[] = React.useMemo(() => {
    if (!files) return [];
    
    // Filter out files with no records or zero size
    const nonEmptyFiles = files.filter((file: any) => {
      const hasRecords = file.recordCount && file.recordCount > 0;
      const hasSize = file.size > 0;
      return hasRecords && hasSize;
    });
    
    const groups = new Map<string, any[]>();
    nonEmptyFiles.forEach((file: any) => {
      const layer = file.layer || 'Other';
      if (!groups.has(layer)) {
        groups.set(layer, []);
      }
      groups.get(layer)!.push(file);
    });

    // Define layer order matching netcap's hierarchy
    const layerOrder = [
      'Link Layer',
      'Network Layer',
      'Transport Layer',
      'Application Layer',
      'Stream Decoders',
      'Abstract Decoders',
      'Other'
    ];

    // Only return layers that have files with data
    return layerOrder
      .filter(layerName => groups.has(layerName) && groups.get(layerName)!.length > 0)
      .map(layerName => ({
        layerName,
        files: groups.get(layerName)!
      }));
  }, [files]);

  if (!files && !error) {
    return (
      <Layout title="Audit Records">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Audit Records">
        <Box>
          <Typography color="error">Error loading audit records</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Audit Records">
      <Box>
        {/* Session Selector for Try Service */}
        {status?.isTryService && sessions && sessions.length > 1 && (
          <Box mb={3}>
            <FormControl size="small" sx={{ minWidth: 300 }}>
              <Select
                value={status?.sessionId || ''}
                onChange={handleSessionChange}
                disabled={switchingSession}
                displayEmpty
                renderValue={(value) => {
                  const session = sessions.find(s => s.sessionId === value);
                  return session ? `Session: ${session.inputFilename}` : 'Select Session';
                }}
              >
                {sessions
                  .filter(s => s.resultsReady)
                  .map((session) => (
                    <MenuItem key={session.sessionId} value={session.sessionId}>
                      <Box>
                        <Typography variant="body2">{session.inputFilename}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(session.uploadTimestamp).toLocaleString()}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
              </Select>
            </FormControl>
          </Box>
        )}

        <Box mb={3}>
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

          <Box display="flex" justifyContent="space-between" alignItems="flex-start" gap={2}>
            <Box>
              <Typography variant="h4" gutterBottom>
                Network Protocol Analysis
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {layerGroups.reduce((sum, group) => sum + group.files.length, 0)} protocol type(s) found • Hierarchical by encapsulation layer
              </Typography>
            </Box>
            
            {/* Download All Button */}
            <Button
              variant="contained"
              color="success"
              startIcon={<DownloadIcon />}
              onClick={handleDownloadAll}
              disabled={!status?.sessionId}
              sx={{ minWidth: 180 }}
            >
              Download All
            </Button>
          </Box>
        </Box>

        {layerGroups.length > 0 ? (
          <Paper sx={{ p: 2 }}>
            {layerGroups.map((group, groupIdx) => (
              <Box key={group.layerName} sx={{ mb: groupIdx < layerGroups.length - 1 ? 2 : 0 }}>
                {/* Layer Header */}
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    cursor: 'pointer',
                    p: 1,
                    borderRadius: 1,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                  onClick={() => toggleLayer(group.layerName)}
                >
                  <IconButton size="small" sx={{ mr: 1 }}>
                    {expandedLayers.has(group.layerName) ? <ExpandMoreIcon /> : <ChevronRightIcon />}
                  </IconButton>
                  <Box
                    sx={{
                      width: 3,
                      height: 24,
                      bgcolor: getLayerColor(group.layerName),
                      mr: 2,
                      borderRadius: 1,
                    }}
                  />
                  <Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>
                    {group.layerName}
                  </Typography>
                  <Chip
                    label={`${group.files.length} type${group.files.length !== 1 ? 's' : ''}`}
                    size="small"
                    variant="outlined"
                  />
                </Box>

                {/* Layer Content */}
                <Collapse in={expandedLayers.has(group.layerName)}>
                  <Box sx={{ ml: 6, mt: 1 }}>
                    {group.files.map((file, fileIdx) => (
                      <Box
                        key={file.path}
                        onClick={() => handleViewRecords(file.type)}
                        sx={{
                          display: 'flex',
                          alignItems: 'center',
                          p: 1.5,
                          mb: fileIdx < group.files.length - 1 ? 1 : 0,
                          borderLeft: 2,
                          borderColor: 'divider',
                          bgcolor: 'background.default',
                          borderRadius: 1,
                          cursor: 'pointer',
                          '&:hover': { bgcolor: 'action.hover' },
                        }}
                      >
                        {/* Tree connector visualization */}
                        <Box
                          sx={{
                            width: 20,
                            height: 2,
                            bgcolor: 'divider',
                            mr: 1,
                          }}
                        />
                        <FileIcon sx={{ mr: 2, color: 'text.secondary', fontSize: 20 }} />
                        
                        <Box sx={{ flex: 1 }}>
                          <Typography
                            sx={{
                              fontFamily: 'monospace',
                              fontWeight: 600,
                              fontSize: '0.95rem',
                            }}
                          >
                            {file.type}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                            {file.name}
                          </Typography>
                        </Box>

                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mr: 2 }}>
                          <Box sx={{ textAlign: 'right' }}>
                            <Typography variant="body2" sx={{ fontWeight: 500 }}>
                              {file.recordCount ? file.recordCount.toLocaleString() : 'N/A'}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              records
                            </Typography>
                          </Box>
                          <Box sx={{ textAlign: 'right', minWidth: 60 }}>
                            <Typography variant="body2" sx={{ fontWeight: 500 }}>
                              {formatBytes(file.size)}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              size
                            </Typography>
                          </Box>
                        </Box>

                        <Box sx={{ display: 'flex', gap: 1 }}>
                          <Button
                            variant="outlined"
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleViewRecords(file.type);
                            }}
                            sx={{ minWidth: 100 }}
                          >
                            View Records
                          </Button>
                          <Button
                            variant="contained"
                            size="small"
                            startIcon={<BarChartIcon />}
                            onClick={(e) => {
                              e.stopPropagation();
                              router.push(`/explore?type=${encodeURIComponent(file.type)}`);
                            }}
                            sx={{ minWidth: 100 }}
                          >
                            Explore
                          </Button>
                        </Box>
                      </Box>
                    ))}
                  </Box>
                </Collapse>
              </Box>
            ))}
          </Paper>
        ) : (
          <Box mt={3}>
            <Typography color="text.secondary">No audit record files found</Typography>
          </Box>
        )}
      </Box>

      {/* Record Viewer Dialog */}
      <Dialog open={selectedType !== null} onClose={handleClose} maxWidth="lg" fullWidth>
        <DialogTitle>
          {selectedType} Records
          {loading && <LinearProgress sx={{ mt: 1 }} />}
        </DialogTitle>
        <DialogContent>
          {streamError ? (
            <Box p={3}>
              <Typography color="error" variant="h6" gutterBottom>
                Unable to load records
              </Typography>
              <Typography color="text.secondary" paragraph>
                {streamError}
              </Typography>
              {streamError.includes('incomplete') && (
                <Box mt={2}>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    This file is currently being written. Please wait for processing to complete and try again.
                  </Typography>
                  <Button 
                    variant="outlined" 
                    onClick={() => handleViewRecords(selectedType!)}
                    sx={{ mt: 1 }}
                  >
                    Retry
                  </Button>
                </Box>
              )}
            </Box>
          ) : loading && records.length === 0 ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : records.length > 0 ? (
            <Box>
              <Typography variant="body2" gutterBottom>
                Showing {records.length} {total > 0 ? `of ${total}` : ''} records
              </Typography>
              <Box
                sx={{
                  maxHeight: '60vh',
                  overflow: 'auto',
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                }}
              >
                {records.map((record, idx) => (
                  <Paper key={idx} sx={{ p: 2, mb: 1, bgcolor: 'background.default' }}>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                      {JSON.stringify(record, null, 2)}
                    </pre>
                  </Paper>
                ))}
              </Box>
            </Box>
          ) : (
            <Typography>No records available</Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>Close</Button>
        </DialogActions>
      </Dialog>
    </Layout>
  );
}

// Helper function to assign colors to layers
function getLayerColor(layerName: string): string {
  const colorMap: Record<string, string> = {
    'Link Layer': '#2196F3',        // Blue
    'Network Layer': '#4CAF50',     // Green
    'Transport Layer': '#FF9800',   // Orange
    'Application Layer': '#9C27B0', // Purple
    'Stream Decoders': '#00BCD4',   // Cyan
    'Abstract Decoders': '#F44336', // Red
    'Other': '#9E9E9E',            // Grey
  };
  return colorMap[layerName] || '#9E9E9E';
}
