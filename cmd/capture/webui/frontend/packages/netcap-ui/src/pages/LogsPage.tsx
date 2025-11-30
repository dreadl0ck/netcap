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

import React, { useState, useEffect, useMemo, useCallback } from 'react';
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
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { formatBytes, formatTimestamp } from '../lib/api';
import { useNetcapApi } from '../hooks';
import useSWR, { mutate as globalMutate } from 'swr';

export default function Logs() {
  const api = useNetcapApi();
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
        console.log('[Logs] Auto-selecting first completed file:', completed[0].path);
        setAutoSelectAttempted(true);
        try {
          await api.setActiveDirectory(completed[0].path);
          await mutateStatus();
          await mutate();
        } catch (err) {
          console.error('[Logs] Failed to auto-select file:', err);
        }
      }
    };
    
    autoSelectFirstFile();
  }, [api, inputFiles, status, autoSelectAttempted, mutateStatus, mutate]);

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

  // Memoize event handler to prevent recreation on every render
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
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert('Failed to switch to this file');
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate]);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their processing logs and debug information."
    />
  );

  if (!files && !error) {
    return (
      <Layout title="Logs" headerAction={fileSelector}>
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Logs" headerAction={fileSelector}>
        <Box>
          <Typography color="error">Error loading log files</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Logs" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        {/* Session Selector for Try Service */}
        {status?.isTryService && sessions && sessions.length > 1 && (
          <Box mb={3}>
            <FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 300 } }}>
              <Select
                data-learn="Session Selector: Switch between different analysis sessions to view their logs."
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

        {files && files.length > 0 ? (
          <TableContainer component={Paper} sx={{ mt: 3, overflowX: 'auto', maxWidth: '100%' }}>
            <Table sx={{ minWidth: { xs: 600, md: 'auto' } }}>
              <TableHead>
                <TableRow>
                  <TableCell>Filename</TableCell>
                  <TableCell align="right">Size</TableCell>
                  <TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>Modified</TableCell>
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
                      <Typography 
                        sx={{ 
                          fontFamily: 'monospace',
                          maxWidth: { xs: 200, sm: 300, md: 'none' },
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}
                      >
                        {file.name}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">{formatBytes(file.size)}</TableCell>
                    <TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>{formatTimestamp(file.modifiedTime)}</TableCell>
                    <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                      <Button
                        data-learn="View Log: Open this log file in a viewer to see its contents."
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
          <Button data-learn="Close Dialog: Close the log file viewer." onClick={handleClose}>Close</Button>
        </DialogActions>
      </Dialog>
    </Layout>
  );
}

