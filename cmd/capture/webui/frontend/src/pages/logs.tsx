import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  MenuItem,
  Paper,
  Select,
  SelectChangeEvent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { SwapHoriz as SwapHorizIcon } from '@mui/icons-material';
import Layout from '@/components/Layout';
import { api, formatBytes, formatTimestamp } from '@/lib/api';
import useSWR from 'swr';

export default function Logs() {
  const { data: files, error, mutate } = useSWR('logFiles', () => api.getLogFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: sessions } = useSWR(
    status?.isTryService ? 'try-sessions' : null, 
    () => api.getAllSessions()
  );
  const [selectedLog, setSelectedLog] = useState<string | null>(null);
  const [logContent, setLogContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [switchingSession, setSwitchingSession] = useState(false);

  // Listen for directory changes and refresh log files
  useEffect(() => {
    const handleDirectoryChange = () => {
      console.log('Directory changed, refreshing log files...');
      mutate(); // Refresh log files
    };
    
    window.addEventListener('directory-changed', handleDirectoryChange);
    return () => window.removeEventListener('directory-changed', handleDirectoryChange);
  }, [mutate]);

  const handleViewLog = async (name: string) => {
    setSelectedLog(name);
    setLoading(true);
    try {
      const content = await api.getLogContent(name);
      setLogContent(content);
    } catch (err) {
      console.error('Failed to load log:', err);
      setLogContent('Error loading log file');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setSelectedLog(null);
    setLogContent('');
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

  const handleFileChange = async (event: SelectChangeEvent<string>) => {
    const newFile = event.target.value;
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(newFile);
      console.log('Directory changed to:', result.outputDir);
      await mutateStatus(); // Refresh status
      await mutate(); // Refresh log files
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert('Failed to switch to this file');
    } finally {
      setSwitchingFile(false);
    }
  };

  // Get only completed files for the selector
  const completedFiles = inputFiles?.filter((f: any) => f.isCompleted) || [];
  const isMultiFile = status?.isMultiFile || false;

  if (!files && !error) {
    return (
      <Layout title="Logs">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Logs">
        <Box>
          <Typography color="error">Error loading log files</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Logs">
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

        <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={3} gap={2}>
          <Box>
            <Typography variant="h4" gutterBottom>
              Log Files
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {files?.length || 0} log file(s) available
            </Typography>
          </Box>
          
          {/* File selector for multi-file mode */}
          {isMultiFile && completedFiles.length > 0 && (
            <Box sx={{ minWidth: 300 }}>
              <Typography variant="caption" color="text.secondary" display="block" mb={0.5}>
                Viewing capture:
              </Typography>
              <FormControl fullWidth size="small" disabled={switchingFile}>
                <Select
                  value={status?.activeInputFile || ''}
                  onChange={handleFileChange}
                  startAdornment={
                    switchingFile ? (
                      <CircularProgress size={20} sx={{ mr: 1 }} />
                    ) : (
                      <SwapHorizIcon sx={{ mr: 1, color: 'action.active' }} />
                    )
                  }
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
                        {status?.activeInputFile === file.path && (
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
        </Box>

        {files && files.length > 0 ? (
          <TableContainer component={Paper} sx={{ mt: 3 }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Filename</TableCell>
                  <TableCell align="right">Size</TableCell>
                  <TableCell align="right">Modified</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {files.map((file) => (
                  <TableRow 
                    key={file.path}
                    onClick={() => handleViewLog(file.name)}
                    sx={{
                      cursor: 'pointer',
                      '&:hover': { bgcolor: 'action.hover' },
                    }}
                  >
                    <TableCell>
                      <Typography sx={{ fontFamily: 'monospace' }}>{file.name}</Typography>
                    </TableCell>
                    <TableCell align="right">{formatBytes(file.size)}</TableCell>
                    <TableCell align="right">{formatTimestamp(file.modifiedTime)}</TableCell>
                    <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() => handleViewLog(file.name)}
                      >
                        View Log
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        ) : (
          <Box mt={3}>
            <Typography color="text.secondary">No log files found</Typography>
          </Box>
        )}
      </Box>

      <Dialog open={selectedLog !== null} onClose={handleClose} maxWidth="lg" fullWidth>
        <DialogTitle>{selectedLog}</DialogTitle>
        <DialogContent>
          {loading ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : (
            <Paper
              sx={{
                p: 2,
                bgcolor: 'grey.900',
                maxHeight: '70vh',
                overflow: 'auto',
              }}
            >
              <pre
                style={{
                  margin: 0,
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {logContent || 'Empty log file'}
              </pre>
            </Paper>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>Close</Button>
        </DialogActions>
      </Dialog>
    </Layout>
  );
}

