import { useState, useMemo } from 'react';
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
  Alert,
  Tab,
  Tabs,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import DownloadIcon from '@mui/icons-material/Download';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CloseIcon from '@mui/icons-material/Close';
import CodeIcon from '@mui/icons-material/Code';
import ImageIcon from '@mui/icons-material/Image';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import AudiotrackIcon from '@mui/icons-material/Audiotrack';
import VideocamIcon from '@mui/icons-material/Videocam';
import Layout from '@/components/Layout';
import { api, formatBytes, formatTimestamp, type ExtractedFileInfo } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import ReactECharts from 'echarts-for-react';

export default function ExtractedFilesPage() {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [mimeTypeFilter, setMimeTypeFilter] = useState<string>('');
  const [switchingFile, setSwitchingFile] = useState(false);
  const [previewFile, setPreviewFile] = useState<ExtractedFileInfo | null>(null);
  const [previewContent, setPreviewContent] = useState<string>('');
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string>('');
  const [previewTab, setPreviewTab] = useState<'rendered' | 'raw'>('rendered');

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch extracted files
  const { data: extractedFilesData, error, mutate } = useSWR(
    'extractedFiles',
    () => api.getExtractedFiles(),
    {
      refreshInterval: 5000,
    }
  );

  // Extract files data
  const files = extractedFilesData?.files || [];
  const totalCount = extractedFilesData?.totalCount || 0;

  // Get unique MIME types for filter
  const mimeTypes = Array.from(new Set(files.map(f => f.mimeType).filter(Boolean)));

  // Calculate MIME type distribution for pie chart
  const mimeTypeDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    files.forEach(file => {
      const mimeType = file.mimeType || 'unknown';
      counts[mimeType] = (counts[mimeType] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [files]);

  // ECharts pie chart option
  const pieChartOption = useMemo(() => ({
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      right: 10,
      top: 'center',
      type: 'scroll',
      textStyle: {
        fontSize: 11
      }
    },
    series: [
      {
        name: 'MIME Types',
        type: 'pie',
        radius: ['40%', '70%'],
        avoidLabelOverlap: true,
        itemStyle: {
          borderRadius: 8,
          borderColor: '#fff',
          borderWidth: 2
        },
        label: {
          show: false,
          position: 'center'
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold'
          }
        },
        labelLine: {
          show: false
        },
        data: mimeTypeDistribution
      }
    ]
  }), [mimeTypeDistribution]);

  // Apply MIME type filter
  const filteredFiles = mimeTypeFilter
    ? files.filter(f => f.mimeType === mimeTypeFilter)
    : files;

  // Paginate files
  const paginatedFiles = filteredFiles.slice(
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
    mutate();
  };

  const handleFileChange = async (event: SelectChangeEvent<string>) => {
    const newFile = event.target.value;
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(newFile);
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
      alert('Failed to switch to this capture');
    } finally {
      setSwitchingFile(false);
    }
  };

  const handleDownloadFile = (relativePath: string) => {
    const downloadUrl = api.downloadExtractedFile(relativePath);
    window.open(downloadUrl, '_blank');
  };

  const handlePreviewFile = async (file: ExtractedFileInfo) => {
    setPreviewFile(file);
    setPreviewContent('');
    setPreviewError('');
    setPreviewLoading(true);
    // Default to 'raw' view for HTML files for security, 'rendered' for others
    setPreviewTab(file.mimeType === 'text/html' ? 'raw' : 'rendered');

    try {
      const downloadUrl = api.downloadExtractedFile(file.path);
      
      // For text-based files, fetch content as text
      if (isTextFile(file.mimeType)) {
        const response = await fetch(downloadUrl);
        if (!response.ok) throw new Error('Failed to fetch file content');
        const text = await response.text();
        setPreviewContent(text);
      }
      // For binary files, we'll just display them via iframe/embed
    } catch (err) {
      console.error('Failed to load file preview:', err);
      setPreviewError(err instanceof Error ? err.message : 'Failed to load file preview');
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleClosePreview = () => {
    setPreviewFile(null);
    setPreviewContent('');
    setPreviewError('');
    setPreviewLoading(false);
    setPreviewTab('rendered');
  };

  // Helper function to determine if file is text-based
  const isTextFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return (
      mimeType.startsWith('text/') ||
      mimeType.includes('json') ||
      mimeType.includes('xml') ||
      mimeType.includes('javascript') ||
      mimeType.includes('css') ||
      mimeType.includes('html') ||
      mimeType.includes('svg+xml')
    );
  };

  // Helper function to determine if file is an image
  const isImageFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return mimeType.startsWith('image/');
  };

  // Helper function to determine if file is a video
  const isVideoFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return mimeType.startsWith('video/');
  };

  // Helper function to determine if file is audio
  const isAudioFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return mimeType.startsWith('audio/');
  };

  // Helper function to determine if file is a PDF
  const isPDFFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return mimeType === 'application/pdf';
  };

  // Get file type category for icon display
  const getFileTypeIcon = (mimeType: string) => {
    if (isTextFile(mimeType)) return <CodeIcon fontSize="small" color="info" />;
    if (isImageFile(mimeType)) return <ImageIcon fontSize="small" color="success" />;
    if (isPDFFile(mimeType)) return <PictureAsPdfIcon fontSize="small" color="error" />;
    if (isVideoFile(mimeType)) return <VideocamIcon fontSize="small" color="secondary" />;
    if (isAudioFile(mimeType)) return <AudiotrackIcon fontSize="small" color="primary" />;
    return <InsertDriveFileIcon fontSize="small" color="action" />;
  };

  // Get only completed files for the selector, sorted alphabetically for consistency
  const completedFiles = (inputFiles?.filter((f: any) => f.isCompleted) || [])
    .sort((a: any, b: any) => a.path.localeCompare(b.path));
  const isMultiFile = status?.isMultiFile || false;
  
  // Current selected value - use backend's activeInputFile or fallback to first file
  const selectedValue = status?.activeInputFile || completedFiles[0]?.path || '';
  // Match by comparing both full path and basename
  const selectedFile = completedFiles.find((f: any) => 
    f.path === selectedValue || f.name === selectedValue || f.path.endsWith('/' + selectedValue)
  );

  // File selector for header
  const fileSelector = completedFiles.length > 1 && selectedFile ? (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
      <Typography variant="body2" color="text.secondary">
        Capture:
      </Typography>
      <FormControl size="small" sx={{ minWidth: 300 }}>
        <Select
          value={selectedValue}
          onChange={handleFileChange}
          disabled={switchingFile}
          sx={{ bgcolor: 'background.paper' }}
        >
          {completedFiles.map((file: any) => (
            <MenuItem key={file.path} value={file.path}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                <Typography 
                  sx={{ 
                    fontFamily: 'monospace',
                    fontSize: '0.875rem',
                    flex: 1,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}
                >
                  {file.name}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  ({formatBytes(file.size)})
                </Typography>
              </Box>
            </MenuItem>
          ))}
        </Select>
      </FormControl>
      {switchingFile && <CircularProgress size={20} />}
    </Box>
  ) : null;

  if (error) {
    return (
      <Layout title="Extracted Files" headerAction={fileSelector}>
        <Box>
          <Typography color="error">Error loading extracted files: {error.message}</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Extracted Files" headerAction={fileSelector}>
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
          <Box>
            {selectedFile && (
              <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center', mt: 1 }}>
                <Typography variant="body1" fontWeight="medium">
                  {totalCount.toLocaleString()} file{totalCount !== 1 ? 's' : ''} extracted
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  for capture:
                </Typography>
                <Chip
                  label={selectedFile.name}
                  size="small"
                  sx={{ 
                    fontFamily: 'monospace', 
                    fontSize: '0.8rem',
                    maxWidth: 400,
                    '& .MuiChip-label': {
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }
                  }}
                />
                <Chip
                  label={formatBytes(selectedFile.size)}
                  size="small"
                  variant="outlined"
                  sx={{ fontSize: '0.75rem' }}
                />
              </Box>
            )}
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleRefresh}>
              Refresh
            </Button>
          </Box>
        </Box>

        {/* MIME Type Distribution Pie Chart */}
        {totalCount > 0 && mimeTypeDistribution.length > 0 && (
          <Paper sx={{ mb: 3, p: 2 }}>
            <Typography variant="h6" gutterBottom>
              MIME Type Distribution
            </Typography>
            <ReactECharts 
              option={pieChartOption} 
              style={{ height: '250px', width: '100%' }}
              opts={{ renderer: 'canvas' }}
            />
          </Paper>
        )}

        {/* Filters */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center' }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <Select
              value={mimeTypeFilter}
              onChange={(e) => {
                setMimeTypeFilter(e.target.value);
                setPage(0);
              }}
              displayEmpty
            >
              <MenuItem value="">
                <em>All MIME Types</em>
              </MenuItem>
              {mimeTypes.sort().map((mimeType) => (
                <MenuItem key={mimeType} value={mimeType}>
                  {mimeType}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          {mimeTypeFilter && (
            <Typography variant="body2" color="text.secondary">
              {filteredFiles.length} of {totalCount} files
            </Typography>
          )}
        </Box>

        {/* Files Table */}
        {!extractedFilesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <InsertDriveFileIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Extracted Files
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No files have been extracted from this capture yet.
            </Typography>
          </Paper>
        ) : (
          <>
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>File Name</TableCell>
                    <TableCell>MIME Type</TableCell>
                    <TableCell>Path</TableCell>
                    <TableCell align="right">Size</TableCell>
                    <TableCell align="right">Modified</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedFiles.map((file, index) => (
                    <TableRow 
                      key={index} 
                      hover 
                      onClick={() => handlePreviewFile(file)}
                      sx={{ cursor: 'pointer' }}
                    >
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {getFileTypeIcon(file.mimeType)}
                          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                            {file.name}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={file.mimeType || 'unknown'}
                          size="small"
                          variant="outlined"
                          sx={{ fontSize: '0.75rem' }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography 
                          variant="body2" 
                          sx={{ 
                            fontFamily: 'monospace', 
                            fontSize: '0.75rem',
                            color: 'text.secondary'
                          }}
                        >
                          {file.path}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Typography variant="body2">
                          {formatBytes(file.size)}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Typography variant="body2">
                          {formatTimestamp(file.modifiedTime)}
                        </Typography>
                      </TableCell>
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                        <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'flex-end' }}>
                          <Tooltip title="Preview file">
                            <IconButton
                              size="small"
                              color="secondary"
                              onClick={(e) => {
                                e.stopPropagation();
                                handlePreviewFile(file);
                              }}
                            >
                              <VisibilityIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Download file">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDownloadFile(file.path);
                              }}
                            >
                              <DownloadIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              component="div"
              count={filteredFiles.length}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
            />
          </>
        )}

        {/* File Preview Dialog */}
        <Dialog
          open={previewFile !== null}
          onClose={handleClosePreview}
          maxWidth="lg"
          fullWidth
          PaperProps={{
            sx: { height: '90vh' }
          }}
        >
          <DialogTitle>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                {previewFile && getFileTypeIcon(previewFile.mimeType)}
                <Box>
                  <Typography variant="h6">{previewFile?.name}</Typography>
                  <Box sx={{ display: 'flex', gap: 1.5, mt: 0.5 }}>
                    <Chip label={previewFile?.mimeType || 'unknown'} size="small" variant="outlined" />
                    <Chip label={formatBytes(previewFile?.size || 0)} size="small" variant="outlined" />
                  </Box>
                </Box>
              </Box>
              <IconButton onClick={handleClosePreview} size="small">
                <CloseIcon />
              </IconButton>
            </Box>
          </DialogTitle>
          <DialogContent dividers sx={{ p: 0, display: 'flex', flexDirection: 'column' }}>
            {previewLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                <CircularProgress />
              </Box>
            ) : previewError ? (
              <Box sx={{ p: 3 }}>
                <Alert severity="error">{previewError}</Alert>
              </Box>
            ) : previewFile ? (
              <>
                {/* Tabs for text files to switch between rendered and raw view */}
                {isTextFile(previewFile.mimeType) && previewContent && (
                  <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
                    <Tabs value={previewTab} onChange={(_, v) => setPreviewTab(v)}>
                      <Tab label="Rendered" value="rendered" />
                      <Tab label="Raw Source" value="raw" />
                    </Tabs>
                  </Box>
                )}

                <Box sx={{ flex: 1, overflow: 'auto', p: isTextFile(previewFile.mimeType) && previewTab === 'raw' ? 0 : 2 }}>
                  {/* Text Files */}
                  {isTextFile(previewFile.mimeType) && previewContent && (
                    <>
                      {previewTab === 'rendered' ? (
                        // Rendered view for HTML
                        previewFile.mimeType === 'text/html' ? (
                          <>
                            <Alert severity="warning" sx={{ m: 2, mb: 1 }}>
                              <strong>Security Warning:</strong> Viewing untrusted HTML in rendered mode. 
                              JavaScript execution is disabled, but CSS and images will be loaded.
                            </Alert>
                            <iframe
                              srcDoc={previewContent}
                              style={{
                                width: '100%',
                                height: '100%',
                                minHeight: '500px',
                                border: 'none',
                                backgroundColor: 'white'
                              }}
                              sandbox=""
                              title={previewFile.name}
                            />
                          </>
                        ) : (
                          // Code view for other text files
                          <Paper
                            sx={{
                              bgcolor: 'grey.900',
                              p: 2,
                              overflow: 'auto',
                              maxHeight: 'calc(90vh - 200px)'
                            }}
                          >
                            <pre
                              style={{
                                margin: 0,
                                fontFamily: 'monospace',
                                fontSize: '0.875rem',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                                color: '#e0e0e0',
                              }}
                            >
                              {previewContent}
                            </pre>
                          </Paper>
                        )
                      ) : (
                        // Raw source view
                        <Paper
                          sx={{
                            bgcolor: 'grey.900',
                            p: 2,
                            overflow: 'auto',
                            maxHeight: 'calc(90vh - 250px)'
                          }}
                        >
                          <pre
                            style={{
                              margin: 0,
                              fontFamily: 'monospace',
                              fontSize: '0.875rem',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                              color: '#e0e0e0',
                            }}
                          >
                            {previewContent}
                          </pre>
                        </Paper>
                      )}
                    </>
                  )}

                  {/* Images */}
                  {isImageFile(previewFile.mimeType) && (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
                      <img
                        src={api.downloadExtractedFile(previewFile.path)}
                        alt={previewFile.name}
                        style={{
                          maxWidth: '100%',
                          maxHeight: 'calc(90vh - 250px)',
                          objectFit: 'contain'
                        }}
                      />
                    </Box>
                  )}

                  {/* PDFs */}
                  {isPDFFile(previewFile.mimeType) && (
                    <iframe
                      src={api.downloadExtractedFile(previewFile.path)}
                      style={{
                        width: '100%',
                        height: 'calc(90vh - 200px)',
                        border: 'none'
                      }}
                      title={previewFile.name}
                    />
                  )}

                  {/* Videos */}
                  {isVideoFile(previewFile.mimeType) && (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
                      <video
                        controls
                        style={{
                          maxWidth: '100%',
                          maxHeight: 'calc(90vh - 250px)',
                        }}
                      >
                        <source src={api.downloadExtractedFile(previewFile.path)} type={previewFile.mimeType} />
                        Your browser does not support the video tag.
                      </video>
                    </Box>
                  )}

                  {/* Audio */}
                  {isAudioFile(previewFile.mimeType) && (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 200, flexDirection: 'column', gap: 2 }}>
                      <AudiotrackIcon sx={{ fontSize: 80, color: 'primary.main' }} />
                      <audio
                        controls
                        style={{ width: '100%', maxWidth: 500 }}
                      >
                        <source src={api.downloadExtractedFile(previewFile.path)} type={previewFile.mimeType} />
                        Your browser does not support the audio tag.
                      </audio>
                    </Box>
                  )}

                  {/* Unsupported file types */}
                  {!isTextFile(previewFile.mimeType) &&
                   !isImageFile(previewFile.mimeType) &&
                   !isPDFFile(previewFile.mimeType) &&
                   !isVideoFile(previewFile.mimeType) &&
                   !isAudioFile(previewFile.mimeType) && (
                    <Box sx={{ textAlign: 'center', py: 4 }}>
                      <InsertDriveFileIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                      <Typography variant="h6" color="text.secondary" gutterBottom>
                        Preview Not Available
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        This file type cannot be previewed in the browser.
                      </Typography>
                      <Button
                        variant="contained"
                        startIcon={<DownloadIcon />}
                        onClick={() => handleDownloadFile(previewFile.path)}
                      >
                        Download File
                      </Button>
                    </Box>
                  )}
                </Box>
              </>
            ) : null}
          </DialogContent>
          <DialogActions>
            <Button onClick={handleClosePreview}>Close</Button>
            {previewFile && (
              <Button
                variant="contained"
                startIcon={<DownloadIcon />}
                onClick={() => handleDownloadFile(previewFile.path)}
              >
                Download
              </Button>
            )}
          </DialogActions>
        </Dialog>
      </Box>
    </Layout>
  );
}

