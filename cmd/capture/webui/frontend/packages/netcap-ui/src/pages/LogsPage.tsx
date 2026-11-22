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
  IconButton,
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
import { Close as CloseIcon } from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { formatBytes, formatTimestamp } from '../lib/api';
import { useNetcapApi, useIsMobile } from '../hooks';

import { translate as i18nText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { translate } from "../lib/i18n";
import { type MessageText, message } from "../lib/i18n";
import { renderText } from "../lib/i18n";
import { rawCode } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";








export default function Logs() {
  const __uiLocale = useUILocale();
  const isMobile = useIsMobile();
  const api = useNetcapApi();
  const { data: files, error, mutate } = useSWR('logFiles', () => api.getLogFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: sessions } = useSWR(
    status?.isTryService ? 'try-sessions' : null, 
    () => api.getAllSessions()
  );
  const [selectedLog, setSelectedLog] = useState<string | null>(null);
  const [logContent, setLogContent] = useState<MessageText>('');
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
      setLogContent(message("ui:m_c930d8a00393da23f303"));
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
      alert(i18nText("ui:m_c621cba9a2fca09e49af"));
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
      alert(i18nText("ui:m_03a2ad41452d2a456747"));
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate, __uiLocale]);

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_47c4590aa3dfac73dab5")} />
  );

  if (!files && !error) {
    return (
      <Layout title={i18nText("ui:m_7ac9f812f77b5c758026")} headerAction={fileSelector}><Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh"><CircularProgress /></Box></Layout>
    );
  }

  if (error) {
    return (
      <Layout title={i18nText("ui:m_7ac9f812f77b5c758026")} headerAction={fileSelector}><Box><Typography color="error">{i18nText("ui:m_ab97cd3630b239f50389")}</Typography></Box></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_7ac9f812f77b5c758026")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* Session Selector for Try Service */}{status?.isTryService && sessions && sessions.length > 1 && (
          <Box mb={3}><FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 300 } }}><Select data-learn={i18nText("ui:m_e44dda9d15025011ffec")}
                value={status?.sessionId || ''}
                onChange={handleSessionChange}
                disabled={switchingSession}
                displayEmpty
                renderValue={(value) => {
                  const session = sessions.find(s => s.sessionId === value);
                  return session ? i18nText("ui:m_98ea5107ce31d865f187", { arg0: session.inputFilename }) : translate("ui:m_6a62a54b5077b61e7565");
                }}>{sessions
                  .filter(s => s.resultsReady)
                  .map((session) => (
                    <MenuItem key={session.sessionId} value={session.sessionId}><Box><Typography variant="body2">{session.inputFilename}</Typography><Typography variant="caption" color="text.secondary">{new Date(session.uploadTimestamp).toLocaleString(getUILocale())}</Typography></Box></MenuItem>
                  ))}</Select></FormControl></Box>
        )}{files && files.length > 0 ? (
          <TableContainer component={Paper} sx={{ mt: 3, overflowX: 'auto', maxWidth: '100%' }}><Table sx={{ minWidth: { xs: 600, md: 'auto' } }}><TableHead><TableRow><TableCell>{i18nText("ui:m_5db319049aa1bfb24183")}</TableCell><TableCell align="right">{i18nText("ui:m_9f40c21a49494ff4c88e")}</TableCell><TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>{i18nText("ui:m_b335bad6aaf88c35cb6c")}</TableCell><TableCell align="right">{i18nText("ui:m_8b59af6a47204b74041c")}</TableCell></TableRow></TableHead><TableBody>{files.map((file) => (
                  <TableRow key={file.path}
                    onClick={() => handleViewLog(file.name)}
                    sx={{
                      cursor: 'pointer',
                      '&:hover': { bgcolor: 'action.hover' },
                    }}><TableCell><Typography sx={{ 
                          fontFamily: 'monospace',
                          maxWidth: { xs: 200, sm: 300, md: 'none' },
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}>{file.name}</Typography></TableCell><TableCell align="right">{formatBytes(file.size)}</TableCell><TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>{formatTimestamp(file.modifiedTime, 'seconds')}</TableCell><TableCell align="right" onClick={(e) => e.stopPropagation()}><Button data-learn={i18nText("ui:m_7407114ec324034efe0a")}
                        variant="outlined"
                        size="small"
                        onClick={() => handleViewLog(file.name)}>
                        {i18nText("ui:m_5d4bb3e683a2d3751cc5")}
                      </Button></TableCell></TableRow>
                ))}</TableBody></Table></TableContainer>
        ) : (
          <Box mt={3}><Typography color="text.secondary">{i18nText("ui:m_c1a966ada7023cf18120")}</Typography></Box>
        )}</Box><Dialog open={selectedLog !== null} onClose={handleClose} maxWidth="lg" fullWidth fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">{selectedLog}{isMobile && (
              <IconButton onClick={handleClose} edge="end"><CloseIcon /></IconButton>
            )}</Box></DialogTitle><DialogContent>{loading ? (
            <Box display="flex" justifyContent="center" p={3}><CircularProgress /></Box>
          ) : (
            <Paper sx={{
                p: 2,
                bgcolor: 'background.default',
                maxHeight: '70vh',
                overflow: 'auto',
              }}><pre style={{
                  margin: 0,
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}>{renderText(logContent) || rawCode("Empty log file")}</pre></Paper>
          )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_836153f3d369fcd7c376")} onClick={handleClose}>{i18nText("ui:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog></Layout>
  );
}
