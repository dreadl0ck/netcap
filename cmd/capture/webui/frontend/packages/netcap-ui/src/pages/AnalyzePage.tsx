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
import {
  Box,
  Card,
  CardContent,
  Typography,
  Alert,
  Chip,
  IconButton,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  LinearProgress,
} from '@mui/material';
import Layout from '../components/Layout';
import { type TrySession, type ConfigResponse, type BPFInfoResponse } from '../lib/api';
import { BPFExpressionBlock } from '../components/BPFExpressionHighlight';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ShareIcon from '@mui/icons-material/Share';
import DescriptionIcon from '@mui/icons-material/Description';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import { NetcapLink } from '../components/NetcapLink';
import { useNetcapRouter, useNetcapApi } from '../hooks';

interface QuotaInfo {
  limit: number;
  remaining: number;
  allowed: boolean;
  storage: {
    current: number;
    max: number;
    available: number;
    percentUsed: number;
    unlimited: boolean;
  };
}

export default function AnalyzePage() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [quota, setQuota] = useState<QuotaInfo | null>(null);
  const [sessions, setSessions] = useState<TrySession[]>([]);
  const [copiedSessionId, setCopiedSessionId] = useState<string | null>(null);
  const [isServiceMode, setIsServiceMode] = useState(false);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [inputFiles, setInputFiles] = useState<any[]>([]);
  const [activeInputFile, setActiveInputFile] = useState<string>('');
  const [bpfData, setBpfData] = useState<BPFInfoResponse | null>(null);
  const [quotaError, setQuotaError] = useState<string | null>(null);

  const loadQuota = useCallback(async () => {
    try {
      const quotaData = await api.getQuota();
      setQuota(quotaData);
      setQuotaError(null);
    } catch (error) {
      console.error('Failed to load quota:', error);
      setQuotaError('Failed to load quota information');
    }
  }, []);

  const loadConfig = useCallback(async () => {
    try {
      const configData = await api.getConfig();
      setConfig(configData);
    } catch (error) {
      console.error('Failed to load config:', error);
    }
  }, []);

  const loadSessions = useCallback(async () => {
    try {
      const allSessions = await api.getAllSessions();
      // Sort by upload timestamp, newest first
      allSessions.sort((a, b) => 
        new Date(b.uploadTimestamp).getTime() - new Date(a.uploadTimestamp).getTime()
      );
      setSessions(allSessions);
    } catch (error) {
      console.error('Failed to load sessions:', error);
    }
  }, []);

  const loadInputFiles = useCallback(async () => {
    try {
      const files = await api.getInputFiles();
      setInputFiles(files || []);
    } catch (error) {
      console.error('Failed to load input files:', error);
    }
  }, []);

  const loadBPFInfo = useCallback(async () => {
    try {
      const bpfInfo = await api.getBPFInfo();
      setBpfData(bpfInfo);
    } catch (error) {
      console.error('Failed to load BPF info:', error);
    }
  }, []);

  // Check if we're in service mode and load initial data
  useEffect(() => {
    const checkServiceMode = async () => {
      try {
        const status = await api.getStatus();
        setIsServiceMode(status.isServiceMode === true);
        setActiveInputFile(status.activeInputFile || '');
      } catch (error) {
        console.error('Failed to get status:', error);
      }
    };
    checkServiceMode();
    loadInputFiles();
    loadBPFInfo();
  }, [loadInputFiles, loadBPFInfo]);

  // Load quota, config, and sessions on mount (only in service mode)
  useEffect(() => {
    if (isServiceMode) {
      loadQuota();
      loadConfig();
      loadSessions();
    }
  }, [isServiceMode, loadQuota, loadConfig, loadSessions]);

  const handleCopySessionLink = async (sessionUrl: string, sessionId: string) => {
    try {
      await navigator.clipboard.writeText(sessionUrl);
      setCopiedSessionId(sessionId);
      setTimeout(() => setCopiedSessionId(null), 2000);
    } catch (error) {
      console.error('Failed to copy link:', error);
    }
  };

  const handleViewSession = async (sessionId: string) => {
    try {
      await api.selectSession(sessionId);
      router.push('/records');
    } catch (error) {
      console.error('Failed to select session:', error);
      alert('Failed to load session');
    }
  };

  const handleViewLogs = async (sessionId: string) => {
    try {
      await api.selectSession(sessionId);
      router.push('/logs');
    } catch (error) {
      console.error('Failed to select session:', error);
      alert('Failed to load session logs');
    }
  };

  const handleViewFile = async (filePath: string) => {
    try {
      const result = await api.setActiveDirectory(filePath);
      // Force refresh by triggering a global event
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      router.push('/records');
    } catch (error) {
      console.error('Failed to select file:', error);
      alert('Failed to load file');
    }
  };

  const handleViewFileLogs = async (filePath: string) => {
    try {
      const result = await api.setActiveDirectory(filePath);
      // Force refresh by triggering a global event
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      router.push('/logs');
    } catch (error) {
      console.error('Failed to select file:', error);
      alert('Failed to load file logs');
    }
  };

  const getStatusColor = (status: string): 'success' | 'warning' | 'info' | 'error' | 'default' => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'processing':
        return 'warning';
      case 'queued':
        return 'info';
      case 'failed':
        return 'error';
      default:
        return 'default';
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatTimestamp = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  return (
    <Layout title="Analyze PCAP Files">
      <Box sx={{ minWidth: 0 }}>
        {/* Quota Error (service mode only) */}
        {isServiceMode && quotaError && (
          <Alert severity="warning" sx={{ mb: 3 }}>
            {quotaError}. Some features may not work correctly.
          </Alert>
        )}

        {/* Quota Information (service mode only) */}
        {isServiceMode && quota && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={2}>
                <Box>
                  <Typography variant="body2" color="text.secondary">
                    Remaining Analyses
                  </Typography>
                  <Typography variant="h5">
                    {quota.remaining} / {quota.limit} this hour
                  </Typography>
                </Box>
                
                <Box flex={1} minWidth={{ xs: 0, sm: 300 }}>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Storage Usage
                  </Typography>
                  {quota.storage.unlimited ? (
                    <Typography variant="body1" color="text.primary">
                      Unlimited
                    </Typography>
                  ) : (
                    <Box display="flex" alignItems="center" gap={2}>
                      <Box flex={1}>
                        <LinearProgress 
                          variant="determinate" 
                          value={quota.storage.percentUsed}
                          color={quota.storage.percentUsed >= 90 ? 'error' : quota.storage.percentUsed >= 75 ? 'warning' : 'primary'}
                          sx={{ height: 8, borderRadius: 1 }}
                        />
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        {formatBytes(quota.storage.current)} / {formatBytes(quota.storage.max)}
                        ({quota.storage.percentUsed.toFixed(1)}%)
                      </Typography>
                    </Box>
                  )}
                </Box>
              </Box>

              {quota.remaining === 0 && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  You have reached the maximum number of analyses per hour. Please try again later.
                </Alert>
              )}

              {!quota.storage.unlimited && quota.storage.percentUsed >= 95 && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  Storage limit reached. Uploads are disabled until cleanup frees up space.
                </Alert>
              )}
            </CardContent>
          </Card>
        )}

        {/* BPF Filter Display */}
        {bpfData && bpfData.currentFilter && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={1}>
                <FilterAltIcon color="primary" />
                <Typography variant="h6">
                  Active BPF Filter
                </Typography>
              </Box>
              <Alert severity="info" sx={{ mb: 2 }}>
                The following Berkeley Packet Filter will be applied to your analysis:
              </Alert>
              <BPFExpressionBlock expression={bpfData.currentFilter} />
              <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
                <NetcapLink href="/bpf" style={{ color: 'inherit', textDecoration: 'none' }}>
                  <Button 
                    data-learn="Edit BPF Filter: Modify the Berkeley Packet Filter to include or exclude specific network traffic."
                    variant="outlined" 
                    size="small"
                  >
                    Edit Filter
                  </Button>
                </NetcapLink>
              </Box>
            </CardContent>
          </Card>
        )}

        {/* Drag and Drop Note */}
        <Card>
          <CardContent>
            <Box
              sx={{
                p: 4,
                textAlign: 'center',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 2,
              }}
            >
              <CloudUploadIcon sx={{ fontSize: 64, color: 'primary.main' }} />
              <Typography variant="h5" color="primary">
                Drag &amp; Drop PCAP Files Anywhere
              </Typography>
              <Typography variant="body1" color="text.secondary">
                You can drag and drop your .pcap or .pcapng files anywhere on the screen to upload and analyze them.
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Supported formats: .pcap, .pcapng, .cap
              </Typography>
              {isServiceMode && (
                <Alert severity="info" sx={{ mt: 2, maxWidth: 600 }}>
                  You can also browse results from pre-analyzed files on the <NetcapLink href="/pcaps" style={{ color: 'inherit', fontWeight: 'bold' }}>PCAPs page</NetcapLink>.
                </Alert>
              )}
            </Box>
          </CardContent>
        </Card>

        {/* Service Limits (service mode only) */}
        {isServiceMode && (
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom color="primary">
                Service Limits
              </Typography>
              <Box component="ul" sx={{ m: 0, pl: 2 }}>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Maximum file size: {config ? (() => {
                    const maxFileSizeOption = config.options.find(opt => opt.name === 'max-file-size');
                    if (maxFileSizeOption && typeof maxFileSizeOption.value === 'number') {
                      return Math.round(maxFileSizeOption.value / (1024 * 1024)) + 'MB';
                    }
                    return '100MB';
                  })() : '100MB'}
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Supported formats: PCAP, PCAPNG
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Rate limit: {quota?.limit ?? 10} analyses per hour
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Results expire after 1 hour
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary">
                  DPI analysis enabled
                </Typography>
              </Box>
            </CardContent>
          </Card>
        )}

        {/* Local Mode Info */}
        {!isServiceMode && (
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom color="primary">
                Upload Information
              </Typography>
              <Box component="ul" sx={{ m: 0, pl: 2 }}>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Maximum file size: No limit (local mode)
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Supported formats: PCAP, PCAPNG
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Files are saved to the uploads directory
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary">
                  Analysis starts automatically after upload
                </Typography>
              </Box>
            </CardContent>
          </Card>
        )}

        {/* Previous Analyses (service mode) or Available Files (local mode) */}
        {((isServiceMode && sessions.length > 0) || (!isServiceMode && inputFiles.filter(f => f.isCompleted).length > 0)) && (
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                {isServiceMode ? 'Your Recent Analyses' : 'Available Analysis Files'}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                {isServiceMode ? 'View and share your analysis results' : 'View results and logs for processed files'}
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>File</TableCell>
                      <TableCell>{isServiceMode ? 'Uploaded' : 'Modified'}</TableCell>
                      <TableCell>Size</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {isServiceMode ? sessions.map((session) => (
                      <TableRow key={session.sessionId}>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {session.inputFilename}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {new Date(session.uploadTimestamp).toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {formatBytes(session.inputFileSize)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={session.status}
                            color={getStatusColor(session.status)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell align="right">
                          <Box display="flex" justifyContent="flex-end" gap={1}>
                            {session.resultsReady && (
                              <>
                                <Tooltip title="View Results">
                                  <IconButton
                                    data-learn="View Analysis Results: Open the audit records page to explore the analyzed network traffic data."
                                    size="small"
                                    color="primary"
                                    onClick={() => handleViewSession(session.sessionId)}
                                  >
                                    <VisibilityIcon />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="View Logs">
                                  <IconButton
                                    data-learn="View Processing Logs: Check logs for details about the analysis process and any errors encountered."
                                    size="small"
                                    color="default"
                                    onClick={() => handleViewLogs(session.sessionId)}
                                  >
                                    <DescriptionIcon />
                                  </IconButton>
                                </Tooltip>
                              </>
                            )}
                            <Tooltip title={copiedSessionId === session.sessionId ? "Copied!" : "Copy Share Link"}>
                              <IconButton
                                data-learn="Copy Share Link: Copy the shareable URL for this analysis session to share with others."
                                size="small"
                                color={copiedSessionId === session.sessionId ? "success" : "default"}
                                onClick={() => handleCopySessionLink(session.shareUrl, session.sessionId)}
                              >
                                {copiedSessionId === session.sessionId ? <CheckCircleIcon /> : <ShareIcon />}
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </TableRow>
                    )) : inputFiles.filter(f => f.isCompleted).map((file) => (
                      <TableRow key={file.path} sx={{ backgroundColor: activeInputFile === file.path ? 'action.selected' : 'inherit' }}>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {file.name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {formatTimestamp(file.modifiedTime)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {formatBytes(file.size)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={activeInputFile === file.path ? 'Active' : 'Ready'}
                            color={activeInputFile === file.path ? 'success' : 'default'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell align="right">
                          <Box display="flex" justifyContent="flex-end" gap={1}>
                            {file.isCompleted && (
                              <>
                                <Tooltip title="View Results">
                                  <IconButton
                                    data-learn="View File Results: Open the audit records page for this specific PCAP file."
                                    size="small"
                                    color="primary"
                                    onClick={() => handleViewFile(file.path)}
                                  >
                                    <VisibilityIcon />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="View Logs">
                                  <IconButton
                                    data-learn="View File Logs: Check processing logs for this specific PCAP file."
                                    size="small"
                                    color="default"
                                    onClick={() => handleViewFileLogs(file.path)}
                                  >
                                    <DescriptionIcon />
                                  </IconButton>
                                </Tooltip>
                              </>
                            )}
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        )}
      </Box>
    </Layout>
  );
}
