import { useState, useEffect } from 'react';
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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  TextField,
  Tooltip,
  Typography,
  type SelectChangeEvent,
} from '@mui/material';
import { CheckCircle as CheckCircleIcon, Visibility as VisibilityIcon, HourglassEmpty as HourglassEmptyIcon, Error as ErrorIcon, Share as ShareIcon, Description as DescriptionIcon, Search as SearchIcon, BubbleChart as VisualizeIcon, Report as ReportIcon, BugReport as BugReportIcon } from '@mui/icons-material';
import { useRouter } from 'next/router';
import Layout from '@/components/Layout';
import { api, formatBytes, formatTimestamp, formatDuration } from '@/lib/api';
import useSWR from 'swr';
import ReportIssueDialog from '@/components/ReportIssueDialog';

type SortField = 'name' | 'size' | 'modifiedTime';
type SortOrder = 'asc' | 'desc';

export default function PCAPs() {
  const router = useRouter();
  const { data: files, error, mutate } = useSWR('inputFiles', () => api.getInputFiles(), {
    refreshInterval: 5000, // Auto-refresh every 5 seconds to catch new uploads
  });
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const [activating, setActivating] = useState<string | null>(null);

  // Debug: Log files when they change
  useEffect(() => {
    if (files) {
      console.log('[PCAPs] Loaded files:', files.length);
      const filesWithErrors = files.filter(f => f.error);
      const filesWithErrorLogs = files.filter(f => f.errorLogPath);
      console.log('[PCAPs] Files with errors:', filesWithErrors.length);
      console.log('[PCAPs] Files with errorLogPath:', filesWithErrorLogs.length);
      if (filesWithErrorLogs.length > 0) {
        console.log('[PCAPs] Files with errorLogPath:', filesWithErrorLogs.map(f => ({
          name: f.name,
          error: f.error,
          errorLogPath: f.errorLogPath,
          sessionId: f.sessionId,
        })));
      }
    }
  }, [files]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [copiedFileId, setCopiedFileId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<SortField>('name');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const [reportIssueOpen, setReportIssueOpen] = useState(false);
  const [reportingFile, setReportingFile] = useState<{ sessionId: string; filename: string } | null>(null);
  const [selectedErrorLog, setSelectedErrorLog] = useState<{ sessionId: string; filename: string } | null>(null);
  const [errorLogContent, setErrorLogContent] = useState<string>('');
  const [loadingErrorLog, setLoadingErrorLog] = useState(false);
  
  // Listen for directory changes and refresh input files
  useEffect(() => {
    const handleDirectoryChange = () => {
      console.log('Directory changed, refreshing input files...');
      mutate(); // Refresh input files
    };
    
    window.addEventListener('directory-changed', handleDirectoryChange);
    return () => window.removeEventListener('directory-changed', handleDirectoryChange);
  }, [mutate]);

  const handleSelectFile = async (file: string) => {
    setActivating(file);
    try {
      const result = await api.setActiveDirectory(file);
      console.log('Directory changed to:', result.outputDir);
      await mutateStatus(); // Refresh status
      
      // Force refresh of audit files by triggering a global event
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      // Navigate to audit records page
      router.push('/audit');
    } catch (err) {
      console.error('Failed to set active directory:', err);
      alert('Failed to switch to this file');
    } finally {
      setActivating(null);
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
      alert('Failed to switch to this file');
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
      alert('Failed to switch to this file');
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
      alert('Failed to copy share link to clipboard');
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

  const handleViewErrorLog = async (file: { path: string; name: string; sessionId?: string; errorLogPath?: string }) => {
    console.log('[PCAPs] View error log clicked for:', file.name, 'errorLogPath:', file.errorLogPath);
    
    if (!file.errorLogPath) {
      console.log('[PCAPs] No errorLogPath available for this file');
      alert('Error log not available for this file');
      return;
    }

    if (!file.sessionId) {
      console.log('[PCAPs] No sessionId available for this file');
      alert('Session ID not available');
      return;
    }

    setSelectedErrorLog({ sessionId: file.sessionId, filename: file.name });
    setLoadingErrorLog(true);
    setErrorLogContent('');
    
    try {
      console.log('[PCAPs] Fetching error log for session:', file.sessionId);
      const content = await api.getErrorLogContent(file.sessionId);
      console.log('[PCAPs] Error log content received, length:', content.length);
      setErrorLogContent(content);
    } catch (error) {
      console.error('[PCAPs] Failed to load error log:', error);
      setErrorLogContent(`Failed to load error log: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setLoadingErrorLog(false);
    }
  };

  const handleCloseErrorLog = () => {
    setSelectedErrorLog(null);
    setErrorLogContent('');
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

  // Filter files by search query
  const filteredFiles = files ? files.filter(file => 
    file.name.toLowerCase().includes(searchQuery.toLowerCase())
  ) : [];

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
      <Layout title="PCAP Files">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="PCAP Files">
        <Box>
          <Typography color="error">Error loading PCAP files</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="PCAP Files">
      <Box sx={{ minWidth: 0 }}>
        {/* Search Bar */}
        <Box mb={3}>
          <TextField
            fullWidth
            variant="outlined"
            placeholder="Search files by name..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0); // Reset to first page when search changes
            }}
            InputProps={{
              startAdornment: <SearchIcon sx={{ color: 'text.secondary', mr: 1 }} />,
            }}
            size="small"
            sx={{ maxWidth: { xs: '100%', sm: 600 } }}
          />
        </Box>

        <Box display="flex" gap={{ xs: 1, sm: 2 }} alignItems="center" mb={2} flexWrap="wrap">
          <Typography variant="body2" color="text.secondary">
            {sortedFiles.length} of {files?.length || 0} file(s) {searchQuery && 'matching search'}
          </Typography>
          <Chip 
            label={
              isMultiFile || status?.isServiceMode
                ? "Click a file or use the view button to see its audit records"
                : "Use action buttons to view audit records, logs, and visualizations"
            }
            color="primary" 
            size="small" 
            variant="outlined"
          />
          {sortedFiles.length > 10 && (
            <Box display="flex" alignItems="center" gap={1} ml="auto">
              <Typography variant="body2" color="text.secondary">
                Show:
              </Typography>
              <FormControl size="small" variant="outlined">
                <Select
                  value={rowsPerPage}
                  onChange={handleChangeRowsPerPageSelect}
                  sx={{ minWidth: 80 }}
                >
                  <MenuItem value={10}>10</MenuItem>
                  <MenuItem value={25}>25</MenuItem>
                  <MenuItem value={50}>50</MenuItem>
                  <MenuItem value={100}>100</MenuItem>
                  <MenuItem value={sortedFiles.length}>All</MenuItem>
                </Select>
              </FormControl>
            </Box>
          )}
        </Box>

        {paginatedFiles && paginatedFiles.length > 0 ? (
          <TableContainer component={Paper} sx={{ mt: 3, overflowX: 'auto', maxWidth: '100%' }}>
            <Table sx={{ minWidth: { xs: 700, md: 'auto' } }}>
              <TableHead>
                <TableRow>
                  <TableCell>
                    <TableSortLabel
                      active={sortField === 'name'}
                      direction={sortField === 'name' ? sortOrder : 'asc'}
                      onClick={() => handleSort('name')}
                    >
                      Filename
                    </TableSortLabel>
                  </TableCell>
                  <TableCell align="right">
                    <TableSortLabel
                      active={sortField === 'size'}
                      direction={sortField === 'size' ? sortOrder : 'asc'}
                      onClick={() => handleSort('size')}
                    >
                      Size
                    </TableSortLabel>
                  </TableCell>
                  <TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                    <TableSortLabel
                      active={sortField === 'modifiedTime'}
                      direction={sortField === 'modifiedTime' ? sortOrder : 'asc'}
                      onClick={() => handleSort('modifiedTime')}
                    >
                      Modified
                    </TableSortLabel>
                  </TableCell>
                  <TableCell align="right" sx={{ display: { xs: 'none', md: 'table-cell' } }}>Processing Time</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedFiles.map((file) => {
                  // Debug log for each file
                  console.log('[PCAPs] File:', file.name, {
                    error: file.error,
                    errorLogPath: file.errorLogPath,
                    sessionId: file.sessionId,
                    hasError: !!file.error,
                    hasErrorLogPath: !!file.errorLogPath,
                    hasSessionId: !!file.sessionId,
                  });
                  
                  return (
                  <TableRow 
                    key={file.path}
                    sx={{ 
                      backgroundColor: isActive(file.path) ? 'action.selected' : 'inherit',
                      opacity: file.isCompleted ? 1 : 0.6,
                      '&:hover': ((isMultiFile || status?.isServiceMode) && file.isCompleted) ? { backgroundColor: 'action.hover', cursor: 'pointer' } : {}
                    }}
                    onClick={((isMultiFile || status?.isServiceMode) && file.isCompleted) ? () => handleSelectFile(file.path) : undefined}
                  >
                  <TableCell>
                    <Box display="flex" alignItems="center" gap={1}>
                      {file.error ? (
                        <Tooltip title={`Error: ${file.error}`}>
                          <ErrorIcon color="error" fontSize="small" />
                        </Tooltip>
                      ) : isActive(file.path) && file.isCompleted ? (
                        <CheckCircleIcon color="success" fontSize="small" />
                      ) : !file.isCompleted ? (
                        <HourglassEmptyIcon color="disabled" fontSize="small" />
                      ) : null}
                      <Box sx={{ minWidth: 0, flex: 1 }}>
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
                          {!file.isCompleted && !file.error && (
                            <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                              (processing...)
                            </Typography>
                          )}
                          {file.error && (
                            <Typography component="span" variant="caption" color="error" sx={{ ml: 1 }}>
                              (error)
                            </Typography>
                          )}
                        </Typography>
                        {file.bpfFilter && (
                          <Box sx={{ mt: 0.5 }}>
                            <Chip 
                              label={`BPF: ${file.bpfFilter}`}
                              size="small"
                              color="info"
                              variant="outlined"
                              sx={{ 
                                fontFamily: 'monospace',
                                fontSize: '0.75rem',
                                height: '20px'
                              }}
                            />
                          </Box>
                        )}
                        {file.error && (
                          <Typography variant="caption" color="error" display="block" sx={{ mt: 0.5 }}>
                            {file.error}
                          </Typography>
                        )}
                      </Box>
                    </Box>
                  </TableCell>
                    <TableCell align="right">{formatBytes(file.size)}</TableCell>
                    <TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>{formatTimestamp(file.modifiedTime)}</TableCell>
                    <TableCell align="right" sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                      {file.processingTime && file.isCompleted ? (
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {formatDuration(file.processingTime)}
                        </Typography>
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          -
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                      <Box display="flex" justifyContent="flex-end" gap={1}>
                        <Tooltip title={
                          file.error ? "File encountered an error" :
                          !file.isCompleted ? "Processing not complete" :
                          isActive(file.path) ? "Currently viewing" : 
                          "View audit records"
                        }>
                          <span>
                            <IconButton
                              size="small"
                              onClick={() => handleSelectFile(file.path)}
                              disabled={!file.isCompleted || activating === file.path || isActive(file.path) || !!file.error}
                              color={isActive(file.path) ? "success" : file.error ? "error" : "default"}
                            >
                              {activating === file.path ? (
                                <CircularProgress size={20} />
                              ) : file.error ? (
                                <ErrorIcon />
                              ) : (
                                <VisibilityIcon />
                              )}
                            </IconButton>
                          </span>
                        </Tooltip>
                        {file.isCompleted && !file.error && (
                          <>
                            <Tooltip title="View Logs">
                              <IconButton
                                size="small"
                                onClick={() => handleViewLogs(file.path)}
                                disabled={activating === file.path}
                              >
                                <DescriptionIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Visualize Protocols">
                              <IconButton
                                size="small"
                                onClick={() => handleVisualize(file.path)}
                                disabled={activating === file.path}
                                color="primary"
                              >
                                <VisualizeIcon />
                              </IconButton>
                            </Tooltip>
                          </>
                        )}
                        {status?.isServiceMode && file.sessionId && (
                            <>
                              <Tooltip title={copiedFileId === file.path ? "Copied!" : "Copy Share Link"}>
                                <IconButton
                                  size="small"
                                  color={copiedFileId === file.path ? "success" : "default"}
                                  onClick={() => file.sessionId && handleCopyShareLink(file.sessionId, file.path)}
                                >
                                  {copiedFileId === file.path ? <CheckCircleIcon /> : <ShareIcon />}
                                </IconButton>
                              </Tooltip>
                              {file.isCompleted && !file.error && (
                                <Tooltip title={file.hasReportedIssue ? "Issue already reported for this file" : "Report Issue"}>
                                  <span>
                                    <IconButton
                                      size="small"
                                      color="error"
                                      onClick={() => file.sessionId && handleReportIssue(file.sessionId, file.name)}
                                      disabled={file.hasReportedIssue}
                                    >
                                      <ReportIcon />
                                    </IconButton>
                                  </span>
                                </Tooltip>
                              )}
                              {file.error && file.errorLogPath && file.sessionId && (
                                <Tooltip title="View Crash Log">
                                  <IconButton
                                    size="small"
                                    color="error"
                                    onClick={() => {
                                      console.log('[PCAPs] Crash log button clicked for:', file.name);
                                      handleViewErrorLog(file);
                                    }}
                                    sx={{
                                      animation: 'glow-red 2s ease-in-out infinite',
                                      '@keyframes glow-red': {
                                        '0%, 100%': {
                                          boxShadow: '0 0 5px rgba(244, 67, 54, 0.5)',
                                        },
                                        '50%': {
                                          boxShadow: '0 0 20px rgba(244, 67, 54, 1), 0 0 30px rgba(244, 67, 54, 0.8)',
                                        },
                                      },
                                    }}
                                  >
                                    <BugReportIcon />
                                  </IconButton>
                                </Tooltip>
                              )}
                            </>
                          )}
                      </Box>
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {sortedFiles.length > rowsPerPage && (
              <TablePagination
                rowsPerPageOptions={[10, 25, 50, 100, { label: 'All', value: sortedFiles.length }]}
                component="div"
                count={sortedFiles.length}
                rowsPerPage={rowsPerPage}
                page={page}
                onPageChange={handleChangePage}
                onRowsPerPageChange={handleChangeRowsPerPageTable}
                labelRowsPerPage="Files per page:"
              />
            )}
          </TableContainer>
        ) : (
          <Box mt={3}>
            <Typography color="text.secondary">
              {searchQuery 
                ? `No PCAP files matching "${searchQuery}"`
                : 'No PCAP files found'}
            </Typography>
          </Box>
        )}

        {/* Report Issue Dialog */}
        {reportingFile && (
          <ReportIssueDialog
            open={reportIssueOpen}
            onClose={handleCloseReportDialog}
            sessionId={reportingFile.sessionId}
            filename={reportingFile.filename}
          />
        )}

        {/* Crash Log Dialog */}
        <Dialog
          open={selectedErrorLog !== null}
          onClose={handleCloseErrorLog}
          maxWidth="lg"
          fullWidth
        >
          <DialogTitle>
            <Box display="flex" alignItems="center" gap={1}>
              <BugReportIcon color="error" />
              <Typography variant="h6">Analysis Crash Log</Typography>
            </Box>
            {selectedErrorLog && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Session: {selectedErrorLog.sessionId} - {selectedErrorLog.filename}
              </Typography>
            )}
          </DialogTitle>
          <DialogContent>
            {loadingErrorLog ? (
              <Box display="flex" justifyContent="center" alignItems="center" p={3}>
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
                    color: '#ff6b6b',
                  }}
                >
                  {errorLogContent || 'No error log content available'}
                </pre>
              </Paper>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={handleCloseErrorLog}>Close</Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Layout>
  );
}

