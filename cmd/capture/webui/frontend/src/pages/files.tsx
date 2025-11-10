import { useState, useMemo, useEffect, useCallback } from 'react';
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
  Card,
  CardMedia,
  CardContent,
  CardActions,
  Grid,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import DownloadIcon from '@mui/icons-material/Download';
import DownloadForOfflineIcon from '@mui/icons-material/DownloadForOffline';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CloseIcon from '@mui/icons-material/Close';
import CodeIcon from '@mui/icons-material/Code';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import ImageIcon from '@mui/icons-material/Image';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import AudiotrackIcon from '@mui/icons-material/Audiotrack';
import VideocamIcon from '@mui/icons-material/Videocam';
import ViewListIcon from '@mui/icons-material/ViewList';
import ViewModuleIcon from '@mui/icons-material/ViewModule';
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
  const [viewMode, setViewMode] = useState<'table' | 'gallery'>('table');
  const [galleryPage, setGalleryPage] = useState(0);
  const [galleryRowsPerPage, setGalleryRowsPerPage] = useState(50);

  // Helper functions - declared early to avoid temporal dead zone issues
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

  // Extract files data and deduplicate by hash
  const allFiles = extractedFilesData?.files || [];
  const totalCount = extractedFilesData?.totalCount || 0;

  // Deduplicate files by hash - keep first occurrence of each unique hash
  const files = useMemo(() => {
    const uniqueFiles: ExtractedFileInfo[] = [];
    const seenHashes = new Set<string>();
    
    for (const file of allFiles) {
      // If file has no hash or hash hasn't been seen, include it
      if (!file.hash || !seenHashes.has(file.hash)) {
        uniqueFiles.push(file);
        if (file.hash) {
          seenHashes.add(file.hash);
        }
      }
    }
    
    return uniqueFiles;
  }, [allFiles]);

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

  // Filter image files for gallery view
  const imageFiles = files.filter(f => isImageFile(f.mimeType));
  const filteredImageFiles = mimeTypeFilter
    ? imageFiles.filter(f => f.mimeType === mimeTypeFilter)
    : imageFiles;

  // Paginate files (table view)
  const paginatedFiles = filteredFiles.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Paginate image files (gallery view)
  const paginatedImageFiles = filteredImageFiles.slice(
    galleryPage * galleryRowsPerPage,
    galleryPage * galleryRowsPerPage + galleryRowsPerPage
  );

  const handleChangePage = (_event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleGalleryChangePage = (_event: unknown, newPage: number) => {
    setGalleryPage(newPage);
  };

  const handleGalleryChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setGalleryRowsPerPage(parseInt(event.target.value, 10));
    setGalleryPage(0);
  };

  const handleRefresh = () => {
    mutate();
  };

  const handleViewModeChange = (_event: React.MouseEvent<HTMLElement>, newMode: 'table' | 'gallery' | null) => {
    if (newMode !== null) {
      setViewMode(newMode);
      // Auto-filter to images when switching to gallery view
      if (newMode === 'gallery' && !mimeTypeFilter) {
        // Keep filter as is - gallery will show all images regardless
      }
    }
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

  const handleDownloadAll = () => {
    const downloadUrl = api.downloadAllExtractedFiles();
    window.open(downloadUrl, '_blank');
  };

  // Helper function to determine if file is text-based
  const isTextFile = useCallback((mimeType: string): boolean => {
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
  }, []);

  const handlePreviewFile = useCallback(async (file: ExtractedFileInfo) => {
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
  }, [isTextFile]);

  const handleClosePreview = useCallback(() => {
    setPreviewFile(null);
    setPreviewContent('');
    setPreviewError('');
    setPreviewLoading(false);
    setPreviewTab('rendered');
  }, []);

  // Get the current file list based on view mode and filter
  const getCurrentFileList = useCallback(() => {
    if (viewMode === 'gallery') {
      return filteredImageFiles;
    }
    return filteredFiles;
  }, [viewMode, filteredImageFiles, filteredFiles]);

  // Navigate to previous file
  const handlePreviousFile = useCallback(() => {
    if (!previewFile) return;
    
    const currentList = getCurrentFileList();
    const currentIndex = currentList.findIndex(f => f.path === previewFile.path);
    
    if (currentIndex > 0) {
      handlePreviewFile(currentList[currentIndex - 1]);
    }
  }, [previewFile, getCurrentFileList, handlePreviewFile]);

  // Navigate to next file
  const handleNextFile = useCallback(() => {
    if (!previewFile) return;
    
    const currentList = getCurrentFileList();
    const currentIndex = currentList.findIndex(f => f.path === previewFile.path);
    
    if (currentIndex >= 0 && currentIndex < currentList.length - 1) {
      handlePreviewFile(currentList[currentIndex + 1]);
    }
  }, [previewFile, getCurrentFileList, handlePreviewFile]);

  // Add keyboard navigation for arrow keys
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Only handle keyboard events when preview dialog is open
      if (!previewFile) return;

      if (event.key === 'ArrowLeft') {
        event.preventDefault();
        handlePreviousFile();
      } else if (event.key === 'ArrowRight') {
        event.preventDefault();
        handleNextFile();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        handleClosePreview();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [previewFile, handlePreviousFile, handleNextFile, handleClosePreview]);

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
      <Layout title="Files" headerAction={fileSelector}>
        <Box>
          <Typography color="error">Error loading extracted files: {error.message}</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Files" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        <Box sx={{ 
          display: 'flex', 
          flexDirection: { xs: 'column', md: 'row' },
          justifyContent: 'space-between', 
          alignItems: { xs: 'stretch', md: 'flex-start' }, 
          gap: 2,
          mb: 3 
        }}>
          <Box sx={{ minWidth: 0, flex: 1 }}>
            {selectedFile && (
              <Box sx={{ 
                display: 'flex', 
                gap: { xs: 1, sm: 1.5 }, 
                alignItems: 'center', 
                mt: 1,
                flexWrap: 'wrap'
              }}>
                <Typography variant="body1" fontWeight="medium">
                  {files.length.toLocaleString()} unique file{files.length !== 1 ? 's' : ''}
                </Typography>
                {totalCount !== files.length && (
                  <Chip
                    label={`${totalCount - files.length} duplicate${totalCount - files.length !== 1 ? 's' : ''} hidden`}
                    size="small"
                    color="info"
                    variant="outlined"
                    sx={{ fontSize: '0.75rem' }}
                  />
                )}
                <Typography variant="body2" color="text.secondary" sx={{ display: { xs: 'none', sm: 'block' } }}>
                  for capture:
                </Typography>
                <Chip
                  label={selectedFile.name}
                  size="small"
                  sx={{ 
                    fontFamily: 'monospace', 
                    fontSize: { xs: '0.7rem', sm: '0.8rem' },
                    maxWidth: { xs: '200px', sm: '400px' },
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
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <ToggleButtonGroup
              value={viewMode}
              exclusive
              onChange={handleViewModeChange}
              size="small"
              aria-label="view mode"
            >
              <ToggleButton value="table" aria-label="table view">
                <Tooltip title="Table View">
                  <ViewListIcon />
                </Tooltip>
              </ToggleButton>
              <ToggleButton value="gallery" aria-label="gallery view">
                <Tooltip title="Image Gallery">
                  <ViewModuleIcon />
                </Tooltip>
              </ToggleButton>
            </ToggleButtonGroup>
            <Button 
              variant="outlined" 
              startIcon={<RefreshIcon />} 
              onClick={handleRefresh}
              size="small"
              sx={{ display: { xs: 'flex', sm: 'inline-flex' } }}
            >
              Refresh
            </Button>
            <Button 
              variant="contained" 
              startIcon={<DownloadForOfflineIcon />} 
              onClick={handleDownloadAll}
              size="small"
              disabled={totalCount === 0}
              sx={{ display: { xs: 'flex', sm: 'inline-flex' } }}
            >
              Download All
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

        {/* Files Table or Gallery */}
        {!extractedFilesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <InsertDriveFileIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Files
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No files have been extracted from this capture yet.
            </Typography>
          </Paper>
        ) : viewMode === 'gallery' ? (
          <>
            {/* Gallery View */}
            {imageFiles.length === 0 ? (
              <Paper sx={{ p: 4, textAlign: 'center' }}>
                <ImageIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  No Images Found
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  No image files have been extracted from this capture.
                </Typography>
              </Paper>
            ) : (
              <>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  {paginatedImageFiles.map((file) => (
                    <Grid item xs={12} sm={6} md={4} lg={3} xl={2} key={file.path}>
                      <Card 
                        sx={{ 
                          height: '100%', 
                          display: 'flex', 
                          flexDirection: 'column',
                          cursor: 'pointer',
                          '&:hover': {
                            boxShadow: 6,
                            transform: 'translateY(-2px)',
                            transition: 'all 0.2s ease-in-out',
                          },
                        }}
                        onClick={() => handlePreviewFile(file)}
                      >
                        <CardMedia
                          component="img"
                          height="200"
                          image={api.downloadExtractedFile(file.path)}
                          alt={file.name}
                          sx={{ 
                            objectFit: 'contain', 
                            bgcolor: 'grey.100',
                            p: 1,
                          }}
                        />
                        <CardContent sx={{ flexGrow: 1, pb: 1 }}>
                          <Tooltip title={file.name}>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                fontFamily: 'monospace',
                                fontSize: '0.75rem',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                mb: 0.5,
                              }}
                            >
                              {file.name}
                            </Typography>
                          </Tooltip>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            <Chip
                              label={file.mimeType || 'unknown'}
                              size="small"
                              variant="outlined"
                              sx={{ fontSize: '0.65rem', height: 20 }}
                            />
                            <Chip
                              label={formatBytes(file.size)}
                              size="small"
                              variant="outlined"
                              sx={{ fontSize: '0.65rem', height: 20 }}
                            />
                          </Box>
                        </CardContent>
                        <CardActions sx={{ pt: 0, px: 2, pb: 1, gap: 0.5 }}>
                          <Tooltip title="Preview">
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
                          <Tooltip title="Download">
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
                        </CardActions>
                      </Card>
                    </Grid>
                  ))}
                </Grid>

                <TablePagination
                  component="div"
                  count={filteredImageFiles.length}
                  page={galleryPage}
                  onPageChange={handleGalleryChangePage}
                  rowsPerPage={galleryRowsPerPage}
                  onRowsPerPageChange={handleGalleryChangeRowsPerPage}
                  rowsPerPageOptions={[25, 50, 100, 200]}
                  labelDisplayedRows={({ from, to, count }) => 
                    `${from}-${to} of ${count} image${count !== 1 ? 's' : ''}`
                  }
                />
              </>
            )}
          </>
        ) : (
          <>
            <TableContainer component={Paper} sx={{ overflowX: 'auto', maxWidth: '100%' }}>
              <Table size="small" sx={{ minWidth: { xs: 700, md: 'auto' } }}>
                <TableHead>
                  <TableRow>
                    <TableCell>File Name</TableCell>
                    <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>MIME Type</TableCell>
                    <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>Path</TableCell>
                    <TableCell align="right">Size</TableCell>
                    <TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>Modified</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedFiles.map((file) => (
                    <TableRow 
                      key={file.path} 
                      hover 
                      onClick={() => handlePreviewFile(file)}
                      sx={{ cursor: 'pointer' }}
                    >
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {getFileTypeIcon(file.mimeType)}
                          <Typography 
                            sx={{ 
                              fontFamily: 'monospace', 
                              fontSize: '0.85rem',
                              maxWidth: { xs: 150, sm: 250, md: 'none' },
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}
                          >
                            {file.name}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                        <Chip
                          label={file.mimeType || 'unknown'}
                          size="small"
                          variant="outlined"
                          sx={{ fontSize: '0.75rem' }}
                        />
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                        <Typography 
                          variant="body2" 
                          sx={{ 
                            fontFamily: 'monospace', 
                            fontSize: '0.75rem',
                            color: 'text.secondary',
                            maxWidth: 300,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
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
                      <TableCell align="right" sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
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
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flex: 1 }}>
                {previewFile && getFileTypeIcon(previewFile.mimeType)}
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography variant="h6" sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {previewFile?.name}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1.5, mt: 0.5, flexWrap: 'wrap' }}>
                    <Chip label={previewFile?.mimeType || 'unknown'} size="small" variant="outlined" />
                    <Chip label={formatBytes(previewFile?.size || 0)} size="small" variant="outlined" />
                    {(() => {
                      const currentList = getCurrentFileList();
                      const currentIndex = previewFile ? currentList.findIndex(f => f.path === previewFile.path) : -1;
                      if (currentIndex >= 0) {
                        return (
                          <Chip 
                            label={`${currentIndex + 1} / ${currentList.length}`} 
                            size="small" 
                            color="primary"
                            variant="outlined"
                          />
                        );
                      }
                      return null;
                    })()}
                  </Box>
                </Box>
              </Box>
              <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                <Tooltip title="Previous file (Left Arrow)">
                  <span>
                    <IconButton 
                      onClick={handlePreviousFile} 
                      size="small"
                      disabled={(() => {
                        const currentList = getCurrentFileList();
                        const currentIndex = previewFile ? currentList.findIndex(f => f.path === previewFile.path) : -1;
                        return currentIndex <= 0;
                      })()}
                    >
                      <ArrowBackIcon />
                    </IconButton>
                  </span>
                </Tooltip>
                <Tooltip title="Next file (Right Arrow)">
                  <span>
                    <IconButton 
                      onClick={handleNextFile} 
                      size="small"
                      disabled={(() => {
                        const currentList = getCurrentFileList();
                        const currentIndex = previewFile ? currentList.findIndex(f => f.path === previewFile.path) : -1;
                        return currentIndex < 0 || currentIndex >= currentList.length - 1;
                      })()}
                    >
                      <ArrowForwardIcon />
                    </IconButton>
                  </span>
                </Tooltip>
                <IconButton onClick={handleClosePreview} size="small">
                  <CloseIcon />
                </IconButton>
              </Box>
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
