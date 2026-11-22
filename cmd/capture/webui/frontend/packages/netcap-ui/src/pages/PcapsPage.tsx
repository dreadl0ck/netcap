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

import { useState, useEffect } from 'react';
import {
  Box,
  Alert,
  Button,
  Chip,
  CircularProgress,
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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  TextField,
  Tooltip,
  Typography,
  type SelectChangeEvent,
} from '@mui/material';
import { CheckCircle as CheckCircleIcon, Visibility as VisibilityIcon, HourglassEmpty as HourglassEmptyIcon, Error as ErrorIcon, Share as ShareIcon, Description as DescriptionIcon, BubbleChart as VisualizeIcon, Report as ReportIcon, BugReport as BugReportIcon, Download as DownloadIcon, Notifications as NotificationsIcon, Refresh as RefreshIcon, Close as CloseIcon } from '@mui/icons-material';
import { useNetcapRouter, useNetcapApi, useIsMobile } from '../hooks';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import { formatBytes, formatTimestamp, formatDuration, type FileInfo, type ChildAnalysisOptions } from '../lib/api';
import { useNetcapConfig } from '../providers';
import { parseSearchQuery, matchesSingleValue } from '../lib/tableSearch';

import ReportIssueDialog from '../components/ReportIssueDialog';
import SearchInput from '../components/SearchInput';
import ReproductionDownload from '../components/ReproductionDownload';
import { translate as i18nText, renderText as i18nRenderText, richText as i18nRichText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { translate, message, displayError } from "../lib/i18n";
import { formatNumber } from "../lib/i18n";
import { type MessageText, errorText } from "../lib/i18n";
import { renderText, metadataMessage } from "../lib/i18n";
import { rawCode } from "../lib/i18n";








type SortField = 'name' | 'size' | 'modifiedTime';
type SortOrder = 'asc' | 'desc';

/** One polled observation of a file's analysis progress. */
interface ProgressEntry {
  percent: number;
  message: MessageText;
  status: string;
  errorMessage?: string;
}

/** Pulsing red halo marking the button that explains a failed analysis. */
const errorGlowSx = {
  animation: 'glow-red 2s ease-in-out infinite',
  '@keyframes glow-red': {
    '0%, 100%': {
      boxShadow: '0 0 5px rgba(244, 67, 54, 0.5)',
    },
    '50%': {
      boxShadow: '0 0 20px rgba(244, 67, 54, 1), 0 0 30px rgba(244, 67, 54, 0.8)',
    },
  },
} as const;

export default function PCAPs() {
  const __uiLocale = useUILocale();
  const isMobile = useIsMobile();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const config = useNetcapConfig();
  const { data: files, error, mutate } = useSWR('inputFiles', () => api.getInputFiles(), {
    refreshInterval: 5000, // Auto-refresh every 5 seconds to catch new uploads
  });
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const [activating, setActivating] = useState<string | null>(null);
  const [progressData, setProgressData] = useState<Record<string, ProgressEntry>>({});

  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [copiedFileId, setCopiedFileId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<SortField>('name');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const [reportIssueOpen, setReportIssueOpen] = useState(false);
  const [reportingFile, setReportingFile] = useState<{ sessionId: string; filename: string } | null>(null);
  const [selectedErrorLog, setSelectedErrorLog] = useState<{ sessionId: string; filename: string } | null>(null);
  const [errorLogContent, setErrorLogContent] = useState<MessageText>('');
  const [loadingErrorLog, setLoadingErrorLog] = useState(false);
  const [reanalyzeFile, setReanalyzeFile] = useState<{ path: string; name: string; sessionId?: string } | null>(null);
  const [reanalyzing, setReanalyzing] = useState<string | null>(null);
  const [analysisScope, setAnalysisScope] = useState('whole');
  const [selectionBPF, setSelectionBPF] = useState('');
  const [selectionStart, setSelectionStart] = useState('');
  const [selectionEnd, setSelectionEnd] = useState('');
  const [reanalysisError, setReanalysisError] = useState<UIMessageText>('');
  
  // Listen for directory changes and refresh input files
  useEffect(() => {
    const handleDirectoryChange = () => {
      console.log('Directory changed, refreshing input files...');
      mutate(); // Refresh input files
    };
    
    window.addEventListener('directory-changed', handleDirectoryChange);
    return () => window.removeEventListener('directory-changed', handleDirectoryChange);
  }, [mutate]);

  // Poll progress for non-completed files
  useEffect(() => {
    if (!files || files.length === 0) {
      return;
    }

    // Find files that are being processed (not completed and no error)
    const processingFiles = files.filter(f => !f.isCompleted && !f.error);
    
    if (processingFiles.length === 0) {
      return;
    }

    console.log('[PCAPs] Polling progress for', processingFiles.length, 'file(s)');

    let cancelled = false;

    const interval = setInterval(async () => {
      const newProgressData: Record<string, ProgressEntry> = {};
      let sawTerminalStatus = false;

      for (const file of processingFiles) {
        try {
          // Use file ID for progress tracking
          const progress = await api.getProgress(file.id);

          newProgressData[file.path] = {
            percent: progress.progressPercent,
            message: metadataMessage(progress, 'message'),
            status: progress.status,
            errorMessage: progress.errorMessage,
          };

          // The status and errorMessage fields were fetched and thrown away,
          // so a job that failed between two list refreshes kept rendering as
          // "processing...". Re-fetch the list as soon as one settles.
          if (progress.status === 'failed' || progress.status === 'completed') {
            sawTerminalStatus = true;
          }
        } catch (error) {
          console.error(`[PCAPs] Failed to get progress for ${file.name}:`, error);
          newProgressData[file.path] = {
            percent: 0,
            message: message('ui:m_7040ae816d4c6cc25e94'),
            status: 'unknown',
            errorMessage: error instanceof Error ? error.message : String(error),
          };
        }
      }

      if (cancelled) return;

      setProgressData(prev => ({ ...prev, ...newProgressData }));

      if (sawTerminalStatus) {
        mutate();
      }
    }, 2000); // Poll every 2 seconds

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [files, mutate]);

  const handleSelectFile = async (file: string) => {
    setActivating(file);
    try {
      const result = await api.setActiveDirectory(file);
      console.log('Directory changed to:', result.outputDir);
      await mutateStatus(); // Refresh status
      
      // Force refresh of audit files by triggering a global event
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Navigate to records page
      router.push('/records');
    } catch (err) {
      console.error('Failed to set active directory:', err);
      alert(i18nText("ui:m_03a2ad41452d2a456747"));
    } finally {
      setActivating(null);
    }
  };

  const parentFile = (file: FileInfo) => files?.find(candidate =>
    file.parentSessionId ? candidate.sessionId === file.parentSessionId : candidate.path === file.parentInputFile);

  const selectionLabel = (file: FileInfo) => file.packetSelection
    ? translate("ui:m_0c2d1a742c71d2542e0e", { arg0: file.packetSelection.bpf || translate('ui:selection.allPackets'), arg1: file.packetSelection.startNs ? `; ${file.packetSelection.startNs}–${file.packetSelection.endNs} ns` : '' })
    : file.analysisSelector === 'whole-capture' ? translate("ui:m_7cb88c338151cb164ea1") : '';

  const handleSelectParent = async (file: FileInfo) => {
    const parent = parentFile(file);
    if (!parent) return;
    try {
      await api.setActiveDirectory(parent.path);
      await mutateStatus();
      window.dispatchEvent(new CustomEvent('directory-changed'));
    } catch (err) {
      setReanalysisError(err instanceof Error ? errorText(err) : String(err));
    }
  };

  const handleViewLogs = async (file: string) => {
    setActivating(file);
    try {
      const result = await api.setActiveDirectory(file);
      console.log('Directory changed to:', result.outputDir);
      await mutateStatus(); // Refresh status
      
      // Force refresh of log files by triggering a global event
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Navigate to logs page
      router.push('/logs');
    } catch (err) {
      console.error('Failed to set active directory:', err);
      alert(i18nText("ui:m_03a2ad41452d2a456747"));
    } finally {
      setActivating(null);
    }
  };

  const handleVisualize = async (file: string) => {
    setActivating(file);
    try {
      const result = await api.setActiveDirectory(file);
      console.log('Directory changed to:', result.outputDir);
      await mutateStatus(); // Refresh status
      
      // Force refresh by triggering a global event
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Navigate to visualize page
      router.push('/visualize');
    } catch (err) {
      console.error('Failed to set active directory:', err);
      alert(i18nText("ui:m_03a2ad41452d2a456747"));
    } finally {
      setActivating(null);
    }
  };

  const handleDownload = (identifier: string, filename: string) => {
    // Create a temporary link element and trigger download
    const downloadUrl = api.downloadInputFile(identifier);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleShowAlerts = async (file: string) => {
    setActivating(file);
    try {
      const result = await api.setActiveDirectory(file);
      console.log('Directory changed to:', result.outputDir);
      await mutateStatus(); // Refresh status
      
      // Force refresh by triggering a global event
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Navigate to alerts page
      router.push('/alerts');
    } catch (err) {
      console.error('Failed to set active directory:', err);
      alert(i18nText("ui:m_03a2ad41452d2a456747"));
    } finally {
      setActivating(null);
    }
  };

  const handleCopyShareLink = async (sessionId: string, filePath: string) => {
    const protocol = window.location.protocol;
    const host = window.location.host;
    const shareUrl = `${protocol}//${host}/view/${sessionId}`;
    
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopiedFileId(filePath);
      setTimeout(() => setCopiedFileId(null), 2000);
    } catch (err) {
      console.error('Failed to copy share link:', err);
      alert(i18nText("ui:m_948faba6a9ebd05a3925"));
    }
  };

  const handleReportIssue = (sessionId: string, filename: string) => {
    setReportingFile({ sessionId, filename });
    setReportIssueOpen(true);
  };

  const handleCloseReportDialog = () => {
    setReportIssueOpen(false);
    setReportingFile(null);
    // Trigger a refresh of the file list
    mutate();
  };

  /**
   * Identifier to pass to /api/error-log for a file.
   *
   * errorLogId is set by both modes; sessionId only by service mode, and
   * requiring it is what hid every failure from the desktop app. id is the
   * same hash the backend resolves errorLogId to, so it is a safe last resort
   * for a backend older than this field.
   */
  const errorLogIdFor = (file: { errorLogId?: string; sessionId?: string; id?: string }) =>
    file.errorLogId || file.sessionId || file.id || '';

  const handleViewErrorLog = async (file: {
    path: string;
    name: string;
    id?: string;
    sessionId?: string;
    errorLogId?: string;
    errorLogPath?: string;
  }) => {
    const logId = errorLogIdFor(file);
    console.log('[PCAPs] View error log clicked for:', file.name, 'logId:', logId);

    if (!logId) {
      alert(i18nText("ui:m_297c281ecfc95de1d048"));
      return;
    }

    setSelectedErrorLog({ sessionId: logId, filename: file.name });
    setLoadingErrorLog(true);
    setErrorLogContent('');

    try {
      const content = await api.getErrorLogContent(logId);
      console.log('[PCAPs] Error log content received, length:', content.length);
      setErrorLogContent(content);
    } catch (error) {
      console.error('[PCAPs] Failed to load error log:', error);
      setErrorLogContent(message("ui:m_c0073d3f519362353d3f", { arg0: error instanceof Error ? error.message : String(error) }));
    } finally {
      setLoadingErrorLog(false);
    }
  };

  const handleCloseErrorLog = () => {
    setSelectedErrorLog(null);
    setErrorLogContent('');
  };

  const handleReanalyzeClick = (file: { path: string; name: string; sessionId?: string }) => {
    setAnalysisScope('whole');
    setSelectionBPF('');
    setSelectionStart('');
    setSelectionEnd('');
    setReanalysisError('');
    setReanalyzeFile(file);
  };

  const handleCloseReanalyzeDialog = () => {
    setReanalyzeFile(null);
  };

  const handleConfirmReanalyze = async () => {
    if (!reanalyzeFile) return;
    if (status?.childAnalysisVersion !== 1) return;
    
    setReanalyzing(reanalyzeFile.path);
    setReanalysisError('');
    
    try {
      let options: ChildAnalysisOptions | undefined;
      if (analysisScope === 'subset') {
        if (!selectionBPF.trim() && !selectionStart) throw displayError(message("ui:m_95d5b4071e7138a6d0e4"));
        if (Boolean(selectionStart) !== Boolean(selectionEnd)) throw displayError(message("ui:m_43c5f03bc1c5fa374e57"));
        if (selectionStart && (!/^-?\d+$/.test(selectionStart) || !/^-?\d+$/.test(selectionEnd) || BigInt(selectionStart) > BigInt(selectionEnd))) throw displayError(message("ui:m_1c241a100a42e8e557a6"));
        const query = new URLSearchParams(reanalyzeFile.sessionId ? { sessionId: reanalyzeFile.sessionId } : { inputFile: reanalyzeFile.path });
        const response = await (config.fetch ?? fetch)(`${config.apiBaseUrl}/investigation/capture?${query}`);
        if (!response.ok) throw displayError(await response.text() || message("ui:m_f67b258f2b8fc0e284c0"));
        const parent = await response.json() as { runId?: string; inputSHA256?: string };
        if (!parent.runId || !parent.inputSHA256) throw displayError(message("ui:m_d8a4bff4d1a741c81b8f"));
        options = { runId: parent.runId, selection: { version: 1, sourceSHA256: parent.inputSHA256,
          bpf: selectionBPF.trim(), ...(selectionStart ? { startNs: selectionStart, endNs: selectionEnd } : {}) } };
      }
      const result = await api.reanalyzeFile(reanalyzeFile.path, reanalyzeFile.sessionId, options);
      if (!result.success) throw displayError(result.message || message("ui:m_996ace73b229943a582a"));
      console.log('[PCAPs] Reanalysis queued:', result);
      
      // Refresh the file list to show the file as processing
      await mutate();
      handleCloseReanalyzeDialog();
      
      // Show success feedback (you could also use a snackbar here)
      console.log('[PCAPs] File queued for reanalysis successfully');
    } catch (err) {
      console.error('[PCAPs] Failed to reanalyze file:', err);
      setReanalysisError(err instanceof Error ? errorText(err) : String(err));
    } finally {
      setReanalyzing(null);
    }
  };

  const isActive = (file: string) => {
    return status?.activeInputFile === file;
  };

  const isMultiFile = status?.isMultiFile || false;

  // Handle sort column click
  const handleSort = (field: SortField) => {
    if (sortField === field) {
      // Toggle sort order if clicking the same field
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new field and default to ascending
      setSortField(field);
      setSortOrder('asc');
    }
    setPage(0); // Reset to first page when sorting changes
  };

  // Filter files by search query with negation support (e.g., "!test" excludes test files)
  const filteredFiles = files ? files.filter(file => {
    if (!searchQuery) return true;
    const searchTerms = parseSearchQuery(searchQuery);
    return matchesSingleValue(file.name, searchTerms);
  }) : [];

  // Sort files: completed files first, then by selected sort field
  const sortedFiles = filteredFiles ? [...filteredFiles].sort((a, b) => {
    // Completed files come first
    if (a.isCompleted && !b.isCompleted) return -1;
    if (!a.isCompleted && b.isCompleted) return 1;
    
    // Within same completion status, sort by selected field
    let comparison = 0;
    switch (sortField) {
      case 'name':
        comparison = a.name.localeCompare(b.name);
        break;
      case 'size':
        comparison = a.size - b.size;
        break;
      case 'modifiedTime':
        comparison = new Date(a.modifiedTime).getTime() - new Date(b.modifiedTime).getTime();
        break;
    }
    
    return sortOrder === 'asc' ? comparison : -comparison;
  }) : [];

  // Paginate files
  const paginatedFiles = sortedFiles.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  const handleChangePage = (_event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPageSelect = (event: SelectChangeEvent<number>) => {
    setRowsPerPage(Number(event.target.value));
    setPage(0);
  };

  const handleChangeRowsPerPageTable = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  if (!files && !error) {
    return (
      <Layout title={i18nText("ui:m_5a06e6c9c844a68d3622")}><Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh"><CircularProgress /></Box></Layout>
    );
  }

  if (error) {
    return (
      <Layout title={i18nText("ui:m_5a06e6c9c844a68d3622")}><Box><Typography color="error">{i18nText("ui:m_86ec2d19b2feb3674b77")}</Typography></Box></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_5a06e6c9c844a68d3622")}><Box sx={{ minWidth: 0 }}>{i18nRenderText(reanalysisError) && !reanalyzeFile && <Alert severity="error">{i18nRenderText(reanalysisError)}</Alert>}{/* Search Bar */}<Box mb={3}><SearchInput value={searchQuery}
            onChange={(value) => {
              setSearchQuery(value);
              setPage(0); // Reset to first page when search changes
            }}
            placeholder={i18nText("ui:m_4367aaf9784d294dffb8")}
            learnHint={translate("ui:m_35a0e86cb2569ada8e20")}
            sx={{ maxWidth: { xs: '100%', sm: 600 }, width: '100%' }} /></Box><Box display="flex" gap={{ xs: 1, sm: 2 }} alignItems="center" mb={2} flexWrap="wrap"><Typography variant="body2" color="text.secondary">
            {i18nRichText("ui:m_f321f4ba6e9740da7f60", { arg0: sortedFiles.length, arg1: files?.length || 0, arg2: searchQuery && i18nText("ui:m_13d214056478beb08303") })}
          </Typography><Chip label={isMultiFile || status?.isServiceMode ? i18nText("ui:m_756494c0998a5b13f26b") : i18nText("ui:m_5a0e67cc698690f0f4e2")}
            color="primary" 
            size="small" 
            variant="outlined" />{sortedFiles.length > 10 && (
            <Box display="flex" alignItems="center" gap={1} ml="auto"><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_95a1150c2dd17b35d3b2")}
              </Typography><FormControl size="small" variant="outlined"><Select data-learn={i18nText("ui:m_b13f9f64981c29c84dfe")}
                  value={rowsPerPage}
                  onChange={handleChangeRowsPerPageSelect}
                  sx={{ minWidth: 80 }}><MenuItem value={10}>10</MenuItem><MenuItem value={25}>25</MenuItem><MenuItem value={50}>50</MenuItem><MenuItem value={100}>100</MenuItem><MenuItem value={sortedFiles.length}>{i18nText("ui:m_ed51cc5c39b7605ac39e")}</MenuItem></Select></FormControl></Box>
          )}</Box>{paginatedFiles && paginatedFiles.length > 0 ? (
          <Box sx={{ mt: 3 }}><ResponsiveDataView data={paginatedFiles}
            totalCount={sortedFiles.length}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPageTable}
            rowsPerPageOptions={[10, 25, 50, 100]}
            onCardClick={(file) => {
              if ((isMultiFile || status?.isServiceMode) && file.isCompleted) {
                handleSelectFile(file.path);
              }
            }}
            desktopTable={<TableContainer component={Paper} sx={{ overflowX: 'auto', maxWidth: '100%' }}><Table sx={{ minWidth: { xs: 700, md: 'auto' } }}><TableHead><TableRow><TableCell><TableSortLabel active={sortField === 'name'}
                          direction={sortField === 'name' ? sortOrder : 'asc'}
                          onClick={() => handleSort('name')}>
                          {i18nText("ui:m_5db319049aa1bfb24183")}
                        </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel active={sortField === 'size'}
                          direction={sortField === 'size' ? sortOrder : 'asc'}
                          onClick={() => handleSort('size')}>
                          {i18nText("ui:m_9f40c21a49494ff4c88e")}
                        </TableSortLabel></TableCell><TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}><TableSortLabel active={sortField === 'modifiedTime'}
                          direction={sortField === 'modifiedTime' ? sortOrder : 'asc'}
                          onClick={() => handleSort('modifiedTime')}>
                          {i18nText("ui:m_b335bad6aaf88c35cb6c")}
                        </TableSortLabel></TableCell><TableCell align="right" sx={{ display: { xs: 'none', md: 'table-cell' } }}>{i18nText("ui:m_03f1db1fbcfa360aeb35")}</TableCell><TableCell align="right">{i18nText("ui:m_8b59af6a47204b74041c")}</TableCell></TableRow></TableHead><TableBody>{paginatedFiles.map((file) => {
                      return (
                      <TableRow key={file.path}
                        sx={{
                          backgroundColor: isActive(file.path) ? 'action.selected' : 'inherit',
                          opacity: file.isCompleted ? 1 : 0.6,
                          '&:hover': ((isMultiFile || status?.isServiceMode) && file.isCompleted) ? { backgroundColor: 'action.hover', cursor: 'pointer' } : {}
                        }}
                        onClick={((isMultiFile || status?.isServiceMode) && file.isCompleted) ? event => {
                          if (event.target instanceof Element && event.target.closest("button, a, [role=\"button\"]")) return;
                          handleSelectFile(file.path);
                        } : undefined}><TableCell><Box display="flex" alignItems="center" gap={1}>{file.error ? (
                            <Tooltip title={i18nText("ui:m_d47fa33706b87799ca0e", { arg0: file.error })}><ErrorIcon color="error" fontSize="small" /></Tooltip>
                          ) : isActive(file.path) && file.isCompleted ? (
                            <CheckCircleIcon color="success" fontSize="small" />
                          ) : !file.isCompleted ? (
                            <HourglassEmptyIcon color="disabled" fontSize="small" />
                          ) : null}<Box sx={{ minWidth: 0, flex: 1 }}><Typography sx={{
                                fontFamily: 'monospace',
                                maxWidth: { xs: 200, sm: 300, md: 'none' },
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}>{file.name}{(file.parentSessionId || file.parentInputFile) && i18nText("ui:m_1a35cbe43d7d6e7c2d67")}{(file.parentSessionId || file.parentInputFile) && <Button size="small" onClick={() => handleSelectParent(file)} disabled={!parentFile(file)}>{i18nText("ui:m_b94110eda666cfa039d0")}</Button>}{selectionLabel(file) && <Typography component="span" display="block" variant="caption" sx={{ overflowWrap: 'anywhere' }}>{selectionLabel(file)}</Typography>}{!file.isCompleted && !file.error && (
                                <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>{progressData[file.path]?.percent > 0 ? `(${formatNumber(progressData[file.path].percent, { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false })}%)` : i18nText("ui:m_6f3d643cb3020fb47d7e")}</Typography>
                              )}{file.error && (
                                <Typography component="span" variant="caption" color="error" sx={{ ml: 1 }}>
                                  {i18nText("ui:m_3bc899ff7c7689a07e3b")}
                                </Typography>
                              )}</Typography>{/*
                              * Progress bar for processing files.
                              *
                              * Indeterminate until the first percentage
                              * arrives: the helper only writes one every five
                              * seconds, so a determinate bar pinned at 0 was
                              * the whole feedback a short capture ever gave,
                              * and it is indistinguishable from a stall.
                              */}{!file.isCompleted && !file.error && (
                              <Box sx={{ mt: 0.5, width: '100%', maxWidth: 300 }}><LinearProgress variant={progressData[file.path]?.percent > 0 ? 'determinate' : 'indeterminate'}
                                  value={progressData[file.path]?.percent ?? 0}
                                  sx={{ height: 4, borderRadius: 1 }} />{progressData[file.path]?.message && (
                                  <Typography variant="caption" color="text.secondary" display="block">{renderText(progressData[file.path].message)}</Typography>
                                )}</Box>
                            )}{file.bpfFilter && (
                              <Box sx={{ mt: 0.5 }}><Chip label={i18nText("ui:m_af0ed5376907b70fc19c", { arg0: file.bpfFilter })}
                                  size="small"
                                  color="info"
                                  variant="outlined"
                                  sx={{
                                    fontFamily: 'monospace',
                                    fontSize: '0.75rem',
                                    height: '20px'
                                  }} /></Box>
                            )}{file.error && (
                              <Box><Typography variant="caption" color="error" display="block" sx={{ mt: 0.5 }}>{file.error}</Typography><ReproductionDownload selection={file.sessionId || file.id ? { sessionId: file.sessionId || file.id } : { inputFile: file.path }} /></Box>
                            )}</Box></Box></TableCell><TableCell align="right">{formatBytes(file.size)}</TableCell><TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>{formatTimestamp(file.modifiedTime, 'seconds')}</TableCell><TableCell align="right" sx={{ display: { xs: 'none', md: 'table-cell' } }}>{file.processingTime && file.isCompleted ? (
                            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{formatDuration(file.processingTime)}</Typography>
                          ) : (
                            <Typography variant="body2" color="text.secondary">-
                            </Typography>
                          )}</TableCell><TableCell align="right" onClick={(e) => e.stopPropagation()}><Box display="flex" justifyContent="flex-end" gap={1}><Tooltip title={file.error ? i18nText("ui:m_175cd4d3d587257ef916") : !file.isCompleted ? i18nText("ui:m_0447e249f8b47ede30a7") : isActive(file.path) ? i18nText("ui:m_d8b333a7d09371ab7120") : i18nText("ui:m_15a0f28508ec275a3deb")}><span><IconButton size="small"
                                  onClick={() => handleSelectFile(file.path)}
                                  disabled={!file.isCompleted || activating === file.path || isActive(file.path) || !!file.error}
                                  color={isActive(file.path) ? "success" : file.error ? "error" : "default"}>{activating === file.path ? (
                                    <CircularProgress size={20} />
                                  ) : file.error ? (
                                    <ErrorIcon />
                                  ) : (
                                    <VisibilityIcon />
                                  )}</IconButton></span></Tooltip>{file.isCompleted && !file.error && (
                              <><Tooltip title={i18nText("ui:m_a338251f0ba68c52c8ea")}><IconButton size="small"
                                    onClick={() => handleViewLogs(file.path)}
                                    disabled={activating === file.path}><DescriptionIcon /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_8762647aecbcc7e19f47")}><IconButton size="small"
                                    onClick={() => handleVisualize(file.path)}
                                    disabled={activating === file.path}
                                    color="primary"><VisualizeIcon /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_866ab5d39a9b8045fa5c")}><IconButton size="small"
                                    onClick={() => handleDownload(
                                      status?.isServiceMode && file.sessionId ? file.sessionId : file.path,
                                      file.name
                                    )}
                                    disabled={activating === file.path}
                                    color="default"><DownloadIcon /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_a01f69689a06261be170")}><IconButton size="small"
                                    onClick={() => handleShowAlerts(file.path)}
                                    disabled={activating === file.path}
                                    color="warning"><NotificationsIcon /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_b515b22e7109cd318503")}><span><IconButton size="small"
                                       aria-label={i18nText("ui:m_66f594d2904676812d9e", { arg0: file.name })}
                                      onClick={() => handleReanalyzeClick({ path: file.path, name: file.name, sessionId: file.sessionId })}
                                      disabled={activating === file.path || reanalyzing === file.path}
                                      color="secondary">{reanalyzing === file.path ? (
                                        <CircularProgress size={20} />
                                      ) : (
                                        <RefreshIcon />
                                      )}</IconButton></span></Tooltip></>
                            )}{/*
                              * Local mode error actions.
                              *
                              * The crash-log button used to live only in the
                              * service-mode block below, so the desktop app —
                              * which is always local mode — offered a retry
                              * and nothing else. Retrying a deterministic
                              * failure just fails again, which is exactly what
                              * users reported.
                              */}{!status?.isServiceMode && file.error && (
                              <><Tooltip title={i18nText("ui:m_d9203e63b4a92370a8d4")}><IconButton size="small"
                                    color="error"
                                    aria-label={i18nText("ui:m_d3f75e0d58b575882069", { arg0: file.name })}
                                    onClick={() => handleViewErrorLog(file)}
                                    sx={errorGlowSx}><BugReportIcon /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_02c2bfa87d5a228065d5")}><span><IconButton size="small"
                                      aria-label={i18nText("ui:m_441c8c74a65a7b43043b", { arg0: file.name })}
                                      onClick={() => handleReanalyzeClick({ path: file.path, name: file.name })}
                                      disabled={reanalyzing === file.path}
                                      color="secondary">{reanalyzing === file.path ? (
                                        <CircularProgress size={20} />
                                      ) : (
                                        <RefreshIcon />
                                      )}</IconButton></span></Tooltip></>
                            )}{status?.isServiceMode && file.sessionId && (
                                <><Tooltip title={copiedFileId === file.path ? i18nText("ui:m_b37111d1a8bc99f7c4d4") : i18nText("ui:m_0f4d7665ea73a8d4649a")}><IconButton size="small"
                                      color={copiedFileId === file.path ? "success" : "default"}
                                      onClick={() => file.sessionId && handleCopyShareLink(file.sessionId, file.path)}>{copiedFileId === file.path ? <CheckCircleIcon /> : <ShareIcon />}</IconButton></Tooltip>{file.isCompleted && !file.error && (
                                    <Tooltip title={file.hasReportedIssue ? i18nText("ui:m_2b8a1bf8a1f45d607b32") : i18nText("ui:m_bc4ff55ee5c11e1d1149")}><span><IconButton size="small"
                                          color="error"
                                          onClick={() => file.sessionId && handleReportIssue(file.sessionId, file.name)}
                                          disabled={file.hasReportedIssue}><ReportIcon /></IconButton></span></Tooltip>
                                  )}{/*
                                    * Not gated on errorLogPath: the backend
                                    * also serves the decoder's errors.log, and
                                    * a failure with no log at all is better
                                    * answered by the dialog saying so than by
                                    * a button that is not there.
                                    */}{file.error && (
                                    <Tooltip title={i18nText("ui:m_771225462ec1063421f3")}><IconButton size="small"
                                        color="error"
                                        aria-label={i18nText("ui:m_d3f75e0d58b575882069", { arg0: file.name })}
                                        onClick={() => {
                                          console.log('[PCAPs] Crash log button clicked for:', file.name);
                                          handleViewErrorLog(file);
                                        }}
                                        sx={errorGlowSx}><BugReportIcon /></IconButton></Tooltip>
                                  )}{file.error && (
                                    <Tooltip title={i18nText("ui:m_02c2bfa87d5a228065d5")}><span><IconButton size="small"
                                          onClick={() => handleReanalyzeClick({ path: file.path, name: file.name, sessionId: file.sessionId })}
                                          disabled={reanalyzing === file.path}
                                          color="secondary">{reanalyzing === file.path ? (
                                            <CircularProgress size={20} />
                                          ) : (
                                            <RefreshIcon />
                                          )}</IconButton></span></Tooltip>
                                  )}</>
                              )}</Box></TableCell></TableRow>
                      );
                    })}</TableBody></Table></TableContainer>}
            renderCard={(file) => (
              <Card variant="outlined" sx={{ opacity: file.isCompleted ? 1 : 0.6 }}><CardContent sx={{ pb: 1, '&:last-child': { pb: 1 } }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>{file.error ? (
                      <ErrorIcon color="error" fontSize="small" />
                    ) : isActive(file.path) && file.isCompleted ? (
                      <CheckCircleIcon color="success" fontSize="small" />
                    ) : !file.isCompleted ? (
                      <HourglassEmptyIcon color="disabled" fontSize="small" />
                    ) : null}<Typography variant="subtitle2" noWrap sx={{ fontFamily: 'monospace', flex: 1 }}>{file.name}{(file.parentSessionId || file.parentInputFile) && i18nText("ui:m_1a35cbe43d7d6e7c2d67")}{(file.parentSessionId || file.parentInputFile) && <Button size="small" onClick={() => handleSelectParent(file)} disabled={!parentFile(file)}>{i18nText("ui:m_b94110eda666cfa039d0")}</Button>}{selectionLabel(file) && <Typography component="span" display="block" variant="caption">{selectionLabel(file)}</Typography>}</Typography></Box><Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}><Typography variant="caption" color="text.secondary">{formatBytes(file.size)}</Typography>{file.isCompleted && !file.error && (
                      <Chip label={i18nText("ui:m_73703ef405a907cfd2e4")} size="small" color="success" variant="outlined" sx={{ fontSize: '0.7rem' }} />
                    )}{file.error && (
                      <Chip label={i18nText("ui:m_f87e14c01921623b1b00")} size="small" color="error" variant="outlined" sx={{ fontSize: '0.7rem' }} />
                    )}{!file.isCompleted && !file.error && (
                      <Chip label={i18nText("ui:m_7f2a7d8bf9d246a87194")} size="small" color="warning" variant="outlined" sx={{ fontSize: '0.7rem' }} />
                    )}</Box>{!file.isCompleted && !file.error && progressData[file.path]?.percent > 0 && (
                    <LinearProgress variant="determinate"
                      value={progressData[file.path].percent}
                      sx={{ mt: 0.5, height: 4, borderRadius: 1 }} />
                  )}{/*
                    * The card used to show an "Error" chip and stop there, so
                    * on a narrow window the failure was unreadable and
                    * unactionable no matter which mode was running.
                    */}{file.error && (
                    <><Typography variant="caption" color="error" display="block" sx={{ mt: 0.5 }}>{file.error}</Typography><Box sx={{ display: 'flex', gap: 1, mt: 1 }}><Button size="small"
                          color="error"
                          variant="outlined"
                          startIcon={<BugReportIcon />}
                          onClick={() => handleViewErrorLog(file)}>
                          {i18nText("ui:m_e3d2e6315fcb5bfaf3c9")}
                        </Button><Button size="small"
                          color="secondary"
                          variant="outlined"
                          startIcon={reanalyzing === file.path ? <CircularProgress size={16} /> : <RefreshIcon />}
                          disabled={reanalyzing === file.path}
                          onClick={() => handleReanalyzeClick({
                            path: file.path,
                            name: file.name,
                            sessionId: file.sessionId,
                          })}>
                          {i18nText("ui:m_3c4b66117cf7e2a0bf82")}
                        </Button></Box><ReproductionDownload selection={file.sessionId || file.id ? { sessionId: file.sessionId || file.id } : { inputFile: file.path }} /></>
                  )}</CardContent></Card>
            )} /></Box>
        ) : (
          <Box mt={3}><Typography color="text.secondary">{searchQuery ? i18nText("ui:m_d9da362d5a318b49d7a3", { arg0: searchQuery }) : i18nText("ui:m_118088facff274ff7b5e")}</Typography></Box>
        )}{/* Report Issue Dialog */}{reportingFile && (
          <ReportIssueDialog open={reportIssueOpen}
            onClose={handleCloseReportDialog}
            sessionId={reportingFile.sessionId}
            filename={reportingFile.filename} />
        )}{/* Crash Log Dialog */}<Dialog open={selectedErrorLog !== null}
          onClose={handleCloseErrorLog}
          maxWidth="lg"
          fullWidth
          fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center"><Box display="flex" alignItems="center" gap={1}><BugReportIcon color="error" /><Typography variant="h6">{i18nText("ui:m_dd6c47de73c47f0f715c")}</Typography></Box>{isMobile && (
                <IconButton onClick={handleCloseErrorLog} edge="end"><CloseIcon /></IconButton>
              )}</Box>{selectedErrorLog && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {i18nRichText("ui:m_ed583e188e35fa06c5d1", { arg0: selectedErrorLog.sessionId, arg1: selectedErrorLog.filename })}
              </Typography>
            )}</DialogTitle><DialogContent>{loadingErrorLog ? (
              <Box display="flex" justifyContent="center" alignItems="center" p={3}><CircularProgress /></Box>
            ) : (
              <Paper sx={{
                  p: 2,
                  bgcolor: 'background.default',
                  color: 'error.main',
                  maxHeight: '70vh',
                  overflow: 'auto',
                }}><pre style={{
                    margin: 0,
                    fontFamily: 'var(--netcap-mono, monospace)',
                    fontSize: '0.85rem',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                    color: 'inherit',
                  }}>{renderText(errorLogContent) || rawCode("No error log content available")}</pre></Paper>
            )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_009c8455105d1d26f623")} onClick={handleCloseErrorLog}>{i18nText("ui:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog>{/* Reanalyze Confirmation Dialog */}<Dialog open={reanalyzeFile !== null}
          onClose={() => { if (!reanalyzing) handleCloseReanalyzeDialog(); }}
          maxWidth="sm"
          fullWidth
          fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center"><Box display="flex" alignItems="center" gap={1}><RefreshIcon color="secondary" /><Typography variant="h6">{i18nText("ui:m_8fbe48a3ce25e57c024b")}</Typography></Box>{isMobile && (
                <IconButton onClick={handleCloseReanalyzeDialog} edge="end" disabled={Boolean(reanalyzing)}><CloseIcon /></IconButton>
              )}</Box></DialogTitle><DialogContent><Typography variant="body1" paragraph>
              {i18nText("ui:m_1df61ccfa1e3f799dc18")}
            </Typography>{status?.childAnalysisVersion !== 1 && <Alert severity="warning">{i18nText("ui:m_2d215916eb512e6d0a7b")}</Alert>}{i18nRenderText(reanalysisError) && <Alert severity="error">{i18nRenderText(reanalysisError)}</Alert>}{reanalyzeFile && (
              <Paper sx={{ p: 2, bgcolor: 'background.default', mb: 2 }}><Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{reanalyzeFile.name}</Typography></Paper>
            )}<Typography variant="body2" paragraph>
              {i18nText("ui:m_2b82d9a995fabe9128f4")}
            </Typography><Typography variant="body2" color="text.secondary">
              {i18nText("ui:m_7a67fb506fdb09965184")}
            </Typography><TextField select label={i18nText("ui:m_48df810321c95f1bd645")} value={analysisScope} onChange={event => setAnalysisScope(event.target.value)} fullWidth margin="normal" disabled={Boolean(reanalyzing)}><MenuItem value="whole">{i18nText("ui:m_d44b571aa180fb43c1aa")}</MenuItem><MenuItem value="subset">{i18nText("ui:m_b3e85eab4acff471edaa")}</MenuItem></TextField>{analysisScope === 'subset' && <Box><TextField label={i18nText("ui:m_65ae9a83cea7f153bf7c")} value={selectionBPF} onChange={event => setSelectionBPF(event.target.value)} placeholder={rawCode("host 192.0.2.10 and tcp port 9243")} fullWidth margin="normal" disabled={Boolean(reanalyzing)} /><TextField label={i18nText("ui:m_c592fa758234bd04c4b0")} value={selectionStart} onChange={event => setSelectionStart(event.target.value)} fullWidth margin="normal" disabled={Boolean(reanalyzing)} /><TextField label={i18nText("ui:m_e8c13deecbecd014e15e")} value={selectionEnd} onChange={event => setSelectionEnd(event.target.value)} fullWidth margin="normal" disabled={Boolean(reanalyzing)} /><Typography variant="caption">{i18nText("ui:m_6381bfe3cacf17a4b662")}</Typography></Box>}</DialogContent><DialogActions><Button onClick={handleCloseReanalyzeDialog} disabled={Boolean(reanalyzing)}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button onClick={handleConfirmReanalyze}
              variant="contained"
              color="secondary"
              startIcon={reanalyzing ? <CircularProgress size={16} /> : <RefreshIcon />}
              disabled={Boolean(reanalyzing) || status?.childAnalysisVersion !== 1}>{reanalyzing ? i18nText("ui:m_e18ab30799adfed66a56") : i18nText("ui:m_9055014eecf94fa7f47b")}</Button></DialogActions></Dialog></Box></Layout>
  );
}
