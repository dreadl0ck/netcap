import { useState, useEffect } from 'react';
import {
  Box,
  Chip,
  CircularProgress,
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
import { CheckCircle as CheckCircleIcon, Visibility as VisibilityIcon, HourglassEmpty as HourglassEmptyIcon, Error as ErrorIcon, Share as ShareIcon, Description as DescriptionIcon, Search as SearchIcon } from '@mui/icons-material';
import { useRouter } from 'next/router';
import Layout from '@/components/Layout';
import { api, formatBytes, formatTimestamp } from '@/lib/api';
import useSWR from 'swr';

type SortField = 'name' | 'size' | 'modifiedTime';
type SortOrder = 'asc' | 'desc';

export default function PCAPs() {
  const router = useRouter();
  const { data: files, error, mutate } = useSWR('inputFiles', () => api.getInputFiles(), {
    refreshInterval: 5000, // Auto-refresh every 5 seconds to catch new uploads
  });
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const [activating, setActivating] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [copiedFileId, setCopiedFileId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<SortField>('name');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  
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
      <Box>
        <Typography variant="h4" gutterBottom>
          PCAP Files
        </Typography>

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
            sx={{ maxWidth: 600 }}
          />
        </Box>

        <Box display="flex" gap={2} alignItems="center" mb={2} flexWrap="wrap">
          <Typography variant="body2" color="text.secondary">
            {sortedFiles.length} of {files?.length || 0} file(s) {searchQuery && 'matching search'}
          </Typography>
          {(isMultiFile || status?.isTryService) && (
            <Chip 
              label="Click a file or use the view button to see its audit records" 
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
                  <TableCell>
                    <TableSortLabel
                      active={sortField === 'name'}
                      direction={sortField === 'name' ? sortOrder : 'asc'}
                      onClick={() => handleSort('name')}
                    >
                      Filename
                    </TableSortLabel>
                  </TableCell>
                  <TableCell>Path</TableCell>
                  <TableCell align="right">
                    <TableSortLabel
                      active={sortField === 'size'}
                      direction={sortField === 'size' ? sortOrder : 'asc'}
                      onClick={() => handleSort('size')}
                    >
                      Size
                    </TableSortLabel>
                  </TableCell>
                  <TableCell align="right">
                    <TableSortLabel
                      active={sortField === 'modifiedTime'}
                      direction={sortField === 'modifiedTime' ? sortOrder : 'asc'}
                      onClick={() => handleSort('modifiedTime')}
                    >
                      Modified
                    </TableSortLabel>
                  </TableCell>
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
                      '&:hover': ((isMultiFile || status?.isTryService) && file.isCompleted) ? { backgroundColor: 'action.hover', cursor: 'pointer' } : {}
                    }}
                    onClick={((isMultiFile || status?.isTryService) && file.isCompleted) ? () => handleSelectFile(file.path) : undefined}
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
                          {(isMultiFile || status?.isTryService) && (
                            <>
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
                                <Tooltip title="View Logs">
                                  <IconButton
                                    size="small"
                                    onClick={() => handleViewLogs(file.path)}
                                    disabled={activating === file.path}
                                  >
                                    <DescriptionIcon />
                                  </IconButton>
                                </Tooltip>
                              )}
                            </>
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
            <Typography color="text.secondary">
              {searchQuery 
                ? `No PCAP files matching "${searchQuery}"`
                : 'No PCAP files found'}
            </Typography>
          </Box>
        )}
      </Box>
    </Layout>
  );
}

