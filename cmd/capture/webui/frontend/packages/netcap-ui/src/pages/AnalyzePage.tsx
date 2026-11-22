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
import { message as i18nMessage, translate as i18nText, renderText as i18nRenderText, richText as i18nRichText, formatNumber as i18nNumber, getLocale as getUILocale, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { translate } from "../lib/i18n";
import { getLocale } from "../lib/i18n";
import { formatTimestamp as displayTimestamp, formatBytes as formatDisplayBytes } from '../lib/api';





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
  const __uiLocale = useUILocale();
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
  const [quotaError, setQuotaError] = useState<UIMessageText | null>(null);

  const loadQuota = useCallback(async () => {
    try {
      const quotaData = await api.getQuota();
      setQuota(quotaData);
      setQuotaError(null);
    } catch (error) {
      console.error('Failed to load quota:', error);
      setQuotaError(i18nMessage("ui:m_10bc27140f27b18a5a3e"));
    }
  }, [__uiLocale]);

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
      alert(i18nText("ui:m_aa00ed96ae5520f69e35"));
    }
  };

  const handleViewLogs = async (sessionId: string) => {
    try {
      await api.selectSession(sessionId);
      router.push('/logs');
    } catch (error) {
      console.error('Failed to select session:', error);
      alert(i18nText("ui:m_3a7fc30874bc49ac499e"));
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
      alert(i18nText("ui:m_03033b68c0bd841b2740"));
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
      alert(i18nText("ui:m_1f150a17f200b50af81b"));
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

  const formatBytes = (bytes: number): string => formatDisplayBytes(bytes);

  const formatTimestamp = (timestamp: number, unit: 'seconds' | 'milliseconds' | 'nanoseconds') => displayTimestamp(timestamp, unit);

  return (
    <Layout title={i18nText("ui:m_4d7a87e770a7f678291a")}><Box sx={{ minWidth: 0 }}>{/* Quota Error (service mode only) */}{isServiceMode && i18nRenderText(quotaError) && (
          <Alert severity="warning" sx={{ mb: 3 }}>
            {i18nRichText("ui:m_e0125e6551a8061ed94d", { arg0: i18nRenderText(quotaError) })}
          </Alert>
        )}{/* Quota Information (service mode only) */}{isServiceMode && quota && (
          <Card sx={{ mb: 3 }}><CardContent><Box display="flex" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={2}><Box><Typography variant="body2" color="text.secondary">
                    {i18nText("ui:m_47dca1652a96eb961eb1")}
                  </Typography><Typography variant="h5">
                    {i18nRichText("ui:m_546061cf79d5389e2c1b", { arg0: quota.remaining, arg1: quota.limit })}
                  </Typography></Box><Box flex={1} minWidth={{ xs: 0, sm: 300 }}><Typography variant="body2" color="text.secondary" gutterBottom>
                    {i18nText("ui:m_35146e9f54daa728d8a4")}
                  </Typography>{quota.storage.unlimited ? (
                    <Typography variant="body1" color="text.primary">
                      {i18nText("ui:m_5cdb93f484806224abe6")}
                    </Typography>
                  ) : (
                    <Box display="flex" alignItems="center" gap={2}><Box flex={1}><LinearProgress variant="determinate" 
                          value={quota.storage.percentUsed}
                          color={quota.storage.percentUsed >= 90 ? 'error' : quota.storage.percentUsed >= 75 ? 'warning' : 'primary'}
                          sx={{ height: 8, borderRadius: 1 }} /></Box><Typography variant="body2" color="text.secondary">{formatBytes(quota.storage.current)}/ {formatBytes(quota.storage.max)}({i18nNumber(quota.storage.percentUsed, { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false })}%)
                      </Typography></Box>
                  )}</Box></Box>{quota.remaining === 0 && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {i18nText("ui:m_50d64f2d3c7b9cfa134b")}
                </Alert>
              )}{!quota.storage.unlimited && quota.storage.percentUsed >= 95 && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {i18nText("ui:m_8acf9051f7c075e443d6")}
                </Alert>
              )}</CardContent></Card>
        )}{/* BPF Filter Display */}{bpfData && bpfData.currentFilter && (
          <Card sx={{ mb: 3 }}><CardContent><Box display="flex" alignItems="center" gap={1} mb={1}><FilterAltIcon color="primary" /><Typography variant="h6">
                  {i18nText("ui:m_f0b8356b25ff613b547e")}
                </Typography></Box><Alert severity="info" sx={{ mb: 2 }}>
                {i18nText("ui:m_98a5b0cb97c3a667fa8b")}
              </Alert><BPFExpressionBlock expression={bpfData.currentFilter} /><Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}><NetcapLink href="/bpf" style={{ color: 'inherit', textDecoration: 'none' }}><Button data-learn={i18nText("ui:m_0f5d15eaec93903dd183")}
                    variant="outlined" 
                    size="small">
                    {i18nText("ui:m_29f2bacbcd9d1d769779")}
                  </Button></NetcapLink></Box></CardContent></Card>
        )}{/* Drag and Drop Note */}<Card><CardContent><Box sx={{
                p: 4,
                textAlign: 'center',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 2,
              }}><CloudUploadIcon sx={{ fontSize: 64, color: 'primary.main' }} /><Typography variant="h5" color="primary">
                {i18nText("ui:m_bd7fd4846d31a3ef7a8f")}
              </Typography><Typography variant="body1" color="text.secondary">
                {i18nText("ui:m_2a2d3393eeef6bb9003a")}
              </Typography><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_15977a91b38842e08835")}
              </Typography>{isServiceMode && (
                <Alert severity="info" sx={{ mt: 2, maxWidth: 600 }}>
                  {i18nText("ui:m_f212c0b5c11e071fecc1")}<NetcapLink href="/pcaps" style={{ color: 'inherit', fontWeight: 'bold' }}>{i18nText("ui:m_7593e4da0e719d7db646")}</NetcapLink>.
                </Alert>
              )}</Box></CardContent></Card>{/* Service Limits (service mode only) */}{isServiceMode && (
          <Card sx={{ mt: 3 }}><CardContent><Typography variant="h6" gutterBottom color="primary">
                {i18nText("ui:m_772a5d3289942bfd39ef")}
              </Typography><Box component="ul" sx={{ m: 0, pl: 2 }}><Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  {i18nRichText("ui:m_367e3793e79785205cc3", { arg0: config ? (() => {
                    const maxFileSizeOption = config.options.find(opt => opt.name === 'max-file-size');
                    if (maxFileSizeOption && typeof maxFileSizeOption.value === 'number') {
                      return Math.round(maxFileSizeOption.value / (1024 * 1024)) + 'MB';
                    }
                    return '100MB';
                  })() : i18nText("ui:m_52f5819c261ed9c3f06f") })}
                </Typography><Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  {i18nText("ui:m_ed9788e696f913e308d1")}
                </Typography><Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  {i18nRichText("ui:m_bc8b0f6cfeb8f84b6b89", { arg0: quota?.limit ?? 10 })}
                </Typography><Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  {i18nText("ui:m_ac6ad85e43fda0a52a03")}
                </Typography><Typography component="li" variant="body2" color="text.secondary">
                  {i18nText("ui:m_bfe90d7997939f1623e6")}
                </Typography></Box></CardContent></Card>
        )}{/* Local Mode Info */}{!isServiceMode && (
          <Card sx={{ mt: 3 }}><CardContent><Typography variant="h6" gutterBottom color="primary">
                {i18nText("ui:m_d33ff75f822a29fd4d54")}
              </Typography><Box component="ul" sx={{ m: 0, pl: 2 }}><Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  {i18nText("ui:m_f90d35c8d3cd251d2835")}
                </Typography><Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  {i18nText("ui:m_ed9788e696f913e308d1")}
                </Typography><Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  {i18nText("ui:m_4a53e0acdaaf9a774353")}
                </Typography><Typography component="li" variant="body2" color="text.secondary">
                  {i18nText("ui:m_2b2b7f08fa46b8cbfc4f")}
                </Typography></Box></CardContent></Card>
        )}{/* Previous Analyses (service mode) or Available Files (local mode) */}{((isServiceMode && sessions.length > 0) || (!isServiceMode && inputFiles.filter(f => f.isCompleted).length > 0)) && (
          <Card sx={{ mt: 3 }}><CardContent><Typography variant="h6" gutterBottom>{isServiceMode ? i18nText("ui:m_cf228446d8a5aae85bcd") : i18nText("ui:m_bf633a8009d15bd302a5")}</Typography><Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{isServiceMode ? i18nText("ui:m_617b839d7f0e24085665") : i18nText("ui:m_c6fe6d1245f1136275ba")}</Typography><TableContainer><Table><TableHead><TableRow><TableCell>{i18nText("ui:m_de894275a403ef797d92")}</TableCell><TableCell>{isServiceMode ? i18nText("ui:m_89c8f46532e0e41f4371") : i18nText("ui:m_b335bad6aaf88c35cb6c")}</TableCell><TableCell>{i18nText("ui:m_9f40c21a49494ff4c88e")}</TableCell><TableCell>{i18nText("ui:m_cf025c2b66b1d8e97700")}</TableCell><TableCell align="right">{i18nText("ui:m_8b59af6a47204b74041c")}</TableCell></TableRow></TableHead><TableBody>{isServiceMode ? sessions.map((session) => (
                      <TableRow key={session.sessionId}><TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{session.inputFilename}</Typography></TableCell><TableCell><Typography variant="body2" color="text.secondary">{new Date(session.uploadTimestamp).toLocaleString(getUILocale())}</Typography></TableCell><TableCell><Typography variant="body2">{formatBytes(session.inputFileSize)}</Typography></TableCell><TableCell><Chip label={session.status}
                            color={getStatusColor(session.status)}
                            size="small" /></TableCell><TableCell align="right"><Box display="flex" justifyContent="flex-end" gap={1}>{session.resultsReady && (
                              <><Tooltip title={i18nText("ui:m_a1fc31c82b49b57f045e")}><IconButton data-learn={i18nText("ui:m_9c0257bfed90a02fcaeb")}
                                    size="small"
                                    color="primary"
                                    onClick={() => handleViewSession(session.sessionId)}><VisibilityIcon /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_a338251f0ba68c52c8ea")}><IconButton data-learn={i18nText("ui:m_fa851e28a3d34d45b07d")}
                                    size="small"
                                    color="default"
                                    onClick={() => handleViewLogs(session.sessionId)}><DescriptionIcon /></IconButton></Tooltip></>
                            )}<Tooltip title={copiedSessionId === session.sessionId ? i18nText("ui:m_b37111d1a8bc99f7c4d4") : i18nText("ui:m_0f4d7665ea73a8d4649a")}><IconButton data-learn={i18nText("ui:m_4bad5bc9cee8c44fe743")}
                                size="small"
                                color={copiedSessionId === session.sessionId ? "success" : "default"}
                                onClick={() => handleCopySessionLink(session.shareUrl, session.sessionId)}>{copiedSessionId === session.sessionId ? <CheckCircleIcon /> : <ShareIcon />}</IconButton></Tooltip></Box></TableCell></TableRow>
                    )) : inputFiles.filter(f => f.isCompleted).map((file) => (
                      <TableRow key={file.path} sx={{ backgroundColor: activeInputFile === file.path ? 'action.selected' : 'inherit' }}><TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{file.name}</Typography></TableCell><TableCell><Typography variant="body2" color="text.secondary">{formatTimestamp(file.modifiedTime, 'seconds')}</Typography></TableCell><TableCell><Typography variant="body2">{formatBytes(file.size)}</Typography></TableCell><TableCell><Chip label={activeInputFile === file.path ? i18nText("ui:m_32854ec0180ee3fbf4f7") : i18nText("ui:m_9ebf1338819dd094cfb2")}
                            color={activeInputFile === file.path ? 'success' : 'default'}
                            size="small" /></TableCell><TableCell align="right"><Box display="flex" justifyContent="flex-end" gap={1}>{file.isCompleted && (
                              <><Tooltip title={i18nText("ui:m_a1fc31c82b49b57f045e")}><IconButton data-learn={i18nText("ui:m_3258a12eb37b66945924")}
                                    size="small"
                                    color="primary"
                                    onClick={() => handleViewFile(file.path)}><VisibilityIcon /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_a338251f0ba68c52c8ea")}><IconButton data-learn={i18nText("ui:m_431cef26a676aea1b0c6")}
                                    size="small"
                                    color="default"
                                    onClick={() => handleViewFileLogs(file.path)}><DescriptionIcon /></IconButton></Tooltip></>
                            )}</Box></TableCell></TableRow>
                    ))}</TableBody></Table></TableContainer></CardContent></Card>
        )}</Box></Layout>
  );
}
