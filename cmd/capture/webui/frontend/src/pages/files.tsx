import { useState } from 'react';
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
  Tooltip,
  Typography,
  type SelectChangeEvent,
} from '@mui/material';
import { CheckCircle as CheckCircleIcon, Visibility as VisibilityIcon, HourglassEmpty as HourglassEmptyIcon, Error as ErrorIcon, Share as ShareIcon, BugReport as BugReportIcon } from '@mui/icons-material';
import { useRouter } from 'next/router';
import Layout from '@/components/Layout';
import { api, formatBytes, formatTimestamp } from '@/lib/api';
import useSWR from 'swr';

export default function DataSources() {
  const router = useRouter();
  const { data: files, error } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: networkInterfaces } = useSWR('networkInterfaces', () => api.getNetworkInterfaces());
  const [activating, setActivating] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [copiedFileId, setCopiedFileId] = useState<string | null>(null);
  const [copiedInterface, setCopiedInterface] = useState<string | null>(null);
  const [selectedErrorLog, setSelectedErrorLog] = useState<{filename: string; path: string} | null>(null);
  const [errorLogContent, setErrorLogContent] = useState<string>('');
  const [loadingErrorLog, setLoadingErrorLog] = useState(false);

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

  const handleCopyInterfaceCommand = async (interfaceName: string) => {
    const command = `net capture -iface ${interfaceName} -out /path/to/output`;
    try {
      await navigator.clipboard.writeText(command);
      setCopiedInterface(interfaceName);
      setTimeout(() => setCopiedInterface(null), 2000);
    } catch (err) {
      console.error('Failed to copy command:', err);
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

  const handleViewErrorLog = async (filename: string, path: string) => {
    setSelectedErrorLog({ filename, path });
    setLoadingErrorLog(true);
    setErrorLogContent('');
    
    try {
      const content = await api.getErrorLogContent(path);
      setErrorLogContent(content);
    } catch (err) {
      console.error('Failed to load error log:', err);
      setErrorLogContent(`Failed to load error log: ${err instanceof Error ? err.message : 'Unknown error'}`);
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

  // Sort files: completed files first, then by name
  const sortedFiles = files ? [...files].sort((a, b) => {
    // Completed files come first
    if (a.isCompleted && !b.isCompleted) return -1;
    if (!a.isCompleted && b.isCompleted) return 1;
    // Within same completion status, sort by name
    return a.name.localeCompare(b.name);
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
      <Layout title="Data Sources">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Data Sources">
        <Box>
          <Typography color="error">Error loading data sources</Typography>
        </Box>
      </Layout>
    );
  }

  // Check if we're in local mode (not try service) and if we have network interfaces
  const isLocalMode = !status?.isTryService;
  const hasNetworkInterfaces = networkInterfaces && networkInterfaces.length > 0;

  return (
    <Layout title="Data Sources">
      <Box>
        <Typography variant="h4" gutterBottom>
          Data Sources
        </Typography>

        {/* Network Interfaces Section (only in local mode) */}
        {isLocalMode && hasNetworkInterfaces && (
          <Box mb={4}>
            <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
              Network Interfaces
            </Typography>
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Index</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Flags</TableCell>
                    <TableCell>Hardware Address</TableCell>
                    <TableCell>IP Addresses</TableCell>
                    <TableCell align="right">MTU</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {networkInterfaces.map((iface) => (
                    <TableRow 
                      key={iface.index}
                      hover
                      sx={{ cursor: 'pointer' }}
                      onClick={() => handleCopyInterfaceCommand(iface.name)}
                    >
                      <TableCell>{iface.index}</TableCell>
                      <TableCell>
                        <Typography sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>
                          {iface.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {iface.flags}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                          {iface.hardwareAddr || 'N/A'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {iface.addrs && iface.addrs.length > 0 ? (
                          <Box>
                            {iface.addrs.map((addr) => (
                              <Typography 
                                key={addr} 
                                sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                              >
                                {addr}
                              </Typography>
                            ))}
                          </Box>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            N/A
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell align="right">{iface.mtu}</TableCell>
                      <TableCell align="right">
                        <Tooltip title={copiedInterface === iface.name ? "Command copied!" : "Click to copy capture command"}>
                          <IconButton
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopyInterfaceCommand(iface.name);
                            }}
                            color={copiedInterface === iface.name ? "success" : "primary"}
                          >
                            {copiedInterface === iface.name ? <CheckCircleIcon /> : <ShareIcon />}
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* PCAP Files Section */}
        <Typography variant="h6" gutterBottom sx={{ mt: isLocalMode && hasNetworkInterfaces ? 2 : 0 }}>
          PCAP Files
        </Typography>
        <Box display="flex" gap={2} alignItems="center" mb={2} flexWrap="wrap">
          <Typography variant="body2" color="text.secondary">
            {files?.length || 0} file(s) processed
          </Typography>
          {isMultiFile && (
            <Chip 
              label="Multi-file mode - Click a file to view its audit records" 
              color="primary" 
              size="small" 
              variant="outlined"
            />
          )}
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
          <TableContainer component={Paper} sx={{ mt: 3 }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Filename</TableCell>
                  <TableCell>Path</TableCell>
                  <TableCell align="right">Size</TableCell>
                  <TableCell align="right">Modified</TableCell>
                  {(isMultiFile || status?.isTryService) && <TableCell align="right">Actions</TableCell>}
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedFiles.map((file) => (
                  <TableRow 
                    key={file.path}
                    sx={{ 
                      backgroundColor: isActive(file.path) ? 'action.selected' : 'inherit',
                      opacity: file.isCompleted ? 1 : 0.6,
                      '&:hover': (isMultiFile && file.isCompleted) ? { backgroundColor: 'action.hover', cursor: 'pointer' } : {}
                    }}
                    onClick={(isMultiFile && file.isCompleted) ? () => handleSelectFile(file.path) : undefined}
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
                      <Box>
                        <Typography sx={{ fontFamily: 'monospace' }}>
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
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                        {file.path}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">{formatBytes(file.size)}</TableCell>
                    <TableCell align="right">{formatTimestamp(file.modifiedTime)}</TableCell>
                    {(isMultiFile || status?.isTryService) && (
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                        <Box display="flex" justifyContent="flex-end" gap={1}>
                          {isMultiFile && (
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
                          )}
                          {file.error && file.errorLogPath && (
                            <Tooltip title="View detailed error log">
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleViewErrorLog(file.name, file.errorLogPath!)}
                              >
                                <BugReportIcon />
                              </IconButton>
                            </Tooltip>
                          )}
                          {status?.isTryService && file.sessionId && (
                            <Tooltip title={copiedFileId === file.path ? "Copied!" : "Copy Share Link"}>
                              <IconButton
                                size="small"
                                color={copiedFileId === file.path ? "success" : "default"}
                                onClick={() => file.sessionId && handleCopyShareLink(file.sessionId, file.path)}
                              >
                                {copiedFileId === file.path ? <CheckCircleIcon /> : <ShareIcon />}
                              </IconButton>
                            </Tooltip>
                          )}
                        </Box>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
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
            <Typography color="text.secondary">No input files found</Typography>
          </Box>
        )}

        {/* Error Log Dialog */}
        <Dialog 
          open={selectedErrorLog !== null} 
          onClose={handleCloseErrorLog} 
          maxWidth="lg" 
          fullWidth
        >
          <DialogTitle>
            <Box display="flex" alignItems="center" gap={1}>
              <ErrorIcon color="error" />
              <Typography variant="h6">Analysis Error Log</Typography>
            </Box>
            {selectedErrorLog && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {selectedErrorLog.filename}
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
