import React, { useState } from 'react';
import {
  Box,
  Chip,
  CircularProgress,
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
  TablePagination,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import { CheckCircle as CheckCircleIcon, Visibility as VisibilityIcon, HourglassEmpty as HourglassEmptyIcon, Error as ErrorIcon } from '@mui/icons-material';
import { useRouter } from 'next/router';
import Layout from '@/components/Layout';
import { api, formatBytes, formatTimestamp } from '@/lib/api';
import useSWR from 'swr';

export default function InputFiles() {
  const router = useRouter();
  const { data: files, error } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const [activating, setActivating] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);

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

  const handleChangePage = (event: unknown, newPage: number) => {
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
      <Layout title="Input Files">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Input Files">
        <Box>
          <Typography color="error">Error loading input files</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Input Files">
      <Box>
        <Typography variant="h4" gutterBottom>
          Input PCAP Files
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
                  {isMultiFile && <TableCell align="right">Actions</TableCell>}
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
                    {isMultiFile && (
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
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
      </Box>
    </Layout>
  );
}
