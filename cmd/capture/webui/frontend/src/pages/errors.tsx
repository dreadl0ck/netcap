import { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TableSortLabel,
  Typography,
  Alert as MuiAlert,
  IconButton,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import ErrorIcon from '@mui/icons-material/Error';
import RefreshIcon from '@mui/icons-material/Refresh';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CloseIcon from '@mui/icons-material/Close';
import AssessmentIcon from '@mui/icons-material/Assessment';
import Layout from '@/components/Layout';
import { api, ErrorLogInfo, AggregatedError, formatBytes } from '@/lib/api';
import useSWR from 'swr';

type SortField = 'errorCount' | 'inputFilename' | 'inputFileSize';
type SortOrder = 'asc' | 'desc';

export default function ErrorsPage() {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [sortField, setSortField] = useState<SortField>('errorCount');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [selectedError, setSelectedError] = useState<ErrorLogInfo | null>(null);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [errorLogContent, setErrorLogContent] = useState<string>('');
  const [loadingContent, setLoadingContent] = useState(false);
  const [aggregatedDialogOpen, setAggregatedDialogOpen] = useState(false);
  const [aggregatedErrors, setAggregatedErrors] = useState<AggregatedError[]>([]);
  const [loadingAggregated, setLoadingAggregated] = useState(false);

  // Fetch error logs
  const { data: errorLogs, error, mutate: mutateErrorLogs } = useSWR(
    'errorLogs',
    () => api.getErrorLogs(),
    {
      refreshInterval: 10000, // Refresh every 10 seconds
    }
  );

  // Sort error logs
  const sortedErrorLogs = errorLogs ? [...errorLogs].sort((a, b) => {
    let aValue: string | number;
    let bValue: string | number;

    switch (sortField) {
      case 'errorCount':
        aValue = a.errorCount;
        bValue = b.errorCount;
        break;
      case 'inputFilename':
        aValue = a.inputFilename;
        bValue = b.inputFilename;
        break;
      case 'inputFileSize':
        aValue = a.inputFileSize;
        bValue = b.inputFileSize;
        break;
      default:
        aValue = a.errorCount;
        bValue = b.errorCount;
    }

    if (typeof aValue === 'string' && typeof bValue === 'string') {
      return sortOrder === 'asc' ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
    }

    return sortOrder === 'asc' ? (aValue as number) - (bValue as number) : (bValue as number) - (aValue as number);
  }) : [];

  // Paginate
  const paginatedErrorLogs = sortedErrorLogs.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleRefresh = () => {
    mutateErrorLogs();
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      // Toggle sort order if clicking the same column
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new column and default to descending
      setSortField(field);
      setSortOrder('desc');
    }
    setPage(0); // Reset to first page when sorting changes
  };

  const handleViewErrors = async (errorLog: ErrorLogInfo) => {
    setSelectedError(errorLog);
    setDetailsDialogOpen(true);
    setLoadingContent(true);
    setErrorLogContent('');

    try {
      // Use sessionId if available (service mode), otherwise use inputFile
      const identifier = errorLog.sessionId || errorLog.inputFile || errorLog.inputFilename;
      const content = await api.getErrorLogContent(identifier);
      setErrorLogContent(content);
    } catch (err) {
      setErrorLogContent(`Failed to load error log: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setLoadingContent(false);
    }
  };

  const handleCloseDialog = () => {
    setDetailsDialogOpen(false);
    setSelectedError(null);
    setErrorLogContent('');
  };

  const handleShowAggregated = async () => {
    setAggregatedDialogOpen(true);
    setLoadingAggregated(true);

    try {
      const errors = await api.getAggregatedErrors();
      setAggregatedErrors(errors);
    } catch (err) {
      console.error('Failed to load aggregated errors:', err);
      setAggregatedErrors([]);
    } finally {
      setLoadingAggregated(false);
    }
  };

  const handleCloseAggregated = () => {
    setAggregatedDialogOpen(false);
    setAggregatedErrors([]);
  };

  return (
    <Layout title="Capture Errors">
      <Box sx={{ minWidth: 0 }}>
        <Box sx={{ 
          display: 'flex', 
          flexDirection: { xs: 'column', sm: 'row' },
          justifyContent: 'space-between', 
          alignItems: { xs: 'stretch', sm: 'center' }, 
          gap: 2,
          mb: 3 
        }}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="body1" fontWeight="medium">
              {sortedErrorLogs.length} capture file{sortedErrorLogs.length !== 1 ? 's' : ''} with errors
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              Showing capture files that have errors recorded in their errors.log files
            </Typography>
          </Box>
          <Button 
            data-learn="Refresh Error Logs: Reload the list of captures with errors to check for new error logs."
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
            sx={{ alignSelf: { xs: 'stretch', sm: 'center' } }}
          >
            Refresh
          </Button>
        </Box>

        {error && (
          <MuiAlert severity="error" sx={{ mb: 2 }}>
            Failed to load error logs: {error.message}
          </MuiAlert>
        )}

        {!errorLogs && !error && (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
            <CircularProgress />
          </Box>
        )}

        {errorLogs && (
          <>
            {/* Summary Card */}
            {sortedErrorLogs.length > 0 && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Box sx={{ 
                    display: 'flex', 
                    flexDirection: { xs: 'column', sm: 'row' },
                    justifyContent: 'space-between', 
                    alignItems: { xs: 'stretch', sm: 'center' },
                    gap: 2
                  }}>
                    <Box>
                      <Typography color="text.secondary" gutterBottom>
                        Total Errors Across All Captures
                      </Typography>
                      <Typography variant="h4" color="error">
                        {sortedErrorLogs.reduce((sum, log) => sum + log.errorCount, 0).toLocaleString()}
                      </Typography>
                    </Box>
                    <Button
                      data-learn="Show All Errors: View a consolidated list of all unique errors across all captures, sorted by frequency."
                      variant="contained"
                      startIcon={<AssessmentIcon />}
                      onClick={handleShowAggregated}
                      size="small"
                      sx={{ height: 'fit-content' }}
                      fullWidth={false}
                    >
                      Show All Errors
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            )}

            {/* Errors Table */}
            <TableContainer component={Paper} sx={{ overflowX: 'auto', maxWidth: '100%' }}>
              <Table sx={{ minWidth: { xs: 600, md: 'auto' } }}>
                <TableHead>
                  <TableRow>
                    <TableCell>
                      <TableSortLabel
                        active={sortField === 'inputFilename'}
                        direction={sortField === 'inputFilename' ? sortOrder : 'asc'}
                        onClick={() => handleSort('inputFilename')}
                      >
                        Capture File
                      </TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                      <TableSortLabel
                        active={sortField === 'inputFileSize'}
                        direction={sortField === 'inputFileSize' ? sortOrder : 'asc'}
                        onClick={() => handleSort('inputFileSize')}
                      >
                        File Size
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel
                        active={sortField === 'errorCount'}
                        direction={sortField === 'errorCount' ? sortOrder : 'asc'}
                        onClick={() => handleSort('errorCount')}
                      >
                        Error Count
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedErrorLogs.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} align="center">
                        <Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                          No capture files with errors found. Errors will appear here when packet decoding issues occur.
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    paginatedErrorLogs.map((errorLog, index) => (
                      <TableRow 
                        key={index} 
                        hover 
                        onClick={() => handleViewErrors(errorLog)}
                        sx={{ cursor: 'pointer' }}
                      >
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
                            <ErrorIcon color="error" fontSize="small" sx={{ flexShrink: 0 }} />
                            <Typography
                              variant="body2"
                              sx={{
                                fontFamily: 'monospace',
                                fontSize: '0.85rem',
                                maxWidth: { xs: 200, sm: 300, md: 400 },
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                            >
                              {errorLog.inputFilename}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                          <Typography variant="body2">
                            {formatBytes(errorLog.inputFileSize)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={errorLog.errorCount.toLocaleString()}
                            size="small"
                            color="error"
                            sx={{ fontWeight: 'bold' }}
                          />
                        </TableCell>
                        <TableCell>
                          <Button
                            data-learn="View Errors: Open a detailed view of all errors from this capture's error log file."
                            size="small"
                            variant="outlined"
                            startIcon={<VisibilityIcon />}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleViewErrors(errorLog);
                            }}
                          >
                            View Errors
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
              {sortedErrorLogs.length > 0 && (
                <TablePagination
                  rowsPerPageOptions={[10, 25, 50, 100]}
                  component="div"
                  count={sortedErrorLogs.length}
                  rowsPerPage={rowsPerPage}
                  page={page}
                  onPageChange={handleChangePage}
                  onRowsPerPageChange={handleChangeRowsPerPage}
                />
              )}
            </TableContainer>
          </>
        )}

        {/* Error Details Dialog */}
        <Dialog
          open={detailsDialogOpen}
          onClose={handleCloseDialog}
          maxWidth="lg"
          fullWidth
        >
          <DialogTitle>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                Error Log: {selectedError?.inputFilename}
              </Box>
              <IconButton onClick={handleCloseDialog} size="small">
                <CloseIcon />
              </IconButton>
            </Box>
          </DialogTitle>
          <DialogContent>
            {selectedError && (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                  <Chip
                    label={`${selectedError.errorCount} errors`}
                    size="small"
                    color="error"
                  />
                  <Typography variant="body2" color="text.secondary">
                    File size: {formatBytes(selectedError.inputFileSize)}
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Error Log Content
                  </Typography>
                  {loadingContent ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
                      <CircularProgress />
                    </Box>
                  ) : (
                    <Paper
                      sx={{
                        p: 2,
                        backgroundColor: '#1e1e1e',
                        overflow: 'auto',
                        maxHeight: 500,
                      }}
                    >
                      <pre
                        style={{
                          margin: 0,
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                          color: '#f0f0f0',
                        }}
                      >
                        {errorLogContent || 'No content available'}
                      </pre>
                    </Paper>
                  )}
                </Box>
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button data-learn="Close Dialog: Close the error details viewer." onClick={handleCloseDialog}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Aggregated Errors Dialog */}
        <Dialog
          open={aggregatedDialogOpen}
          onClose={handleCloseAggregated}
          maxWidth="lg"
          fullWidth
        >
          <DialogTitle>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                Aggregated Errors Across All Captures
              </Box>
              <IconButton onClick={handleCloseAggregated} size="small">
                <CloseIcon />
              </IconButton>
            </Box>
          </DialogTitle>
          <DialogContent>
            {loadingAggregated ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
                <CircularProgress />
              </Box>
            ) : aggregatedErrors.length === 0 ? (
              <Box sx={{ p: 4, textAlign: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  No errors found across all captures
                </Typography>
              </Box>
            ) : (
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 2 }}>
                  Showing {aggregatedErrors.length} unique error types aggregated from all error logs
                </Typography>
                <Paper sx={{ maxHeight: 600, overflow: 'auto' }}>
                  <List>
                    {aggregatedErrors.map((error, index) => (
                      <ListItem
                        key={index}
                        sx={{
                          borderBottom: index < aggregatedErrors.length - 1 ? '1px solid rgba(0,0,0,0.1)' : 'none',
                          '&:hover': { backgroundColor: 'rgba(0,0,0,0.02)' },
                        }}
                      >
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
                              <Chip
                                label={`[${error.count}]`}
                                size="small"
                                color="error"
                                sx={{ fontWeight: 'bold', minWidth: 60 }}
                              />
                              <Typography
                                variant="body2"
                                sx={{
                                  fontFamily: 'monospace',
                                  fontSize: '0.9rem',
                                  flex: 1,
                                  wordBreak: 'break-word',
                                }}
                              >
                                {error.errorMessage}
                              </Typography>
                            </Box>
                          }
                          secondary={
                            error.firstSeen && (
                              <Typography variant="caption" color="text.secondary">
                                First seen: {error.firstSeen}
                              </Typography>
                            )
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button data-learn="Close Dialog: Close the aggregated errors viewer." onClick={handleCloseAggregated}>Close</Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Layout>
  );
}

