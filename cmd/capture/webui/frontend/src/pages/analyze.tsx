import { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Alert,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
} from '@mui/material';
import Layout from '@/components/Layout';
import { api, type TrySession, type ConfigResponse, type BPFInfoResponse } from '@/lib/api';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ShareIcon from '@mui/icons-material/Share';
import DescriptionIcon from '@mui/icons-material/Description';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import Link from 'next/link';
import { mutate as globalMutate } from 'swr';

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

interface UploadStatus {
  type: 'idle' | 'uploading' | 'success' | 'error' | 'processing' | 'completed';
  message: string;
}

export default function AnalyzePage() {
  const [files, setFiles] = useState<File[]>([]);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus>({ type: 'idle', message: '' });
  const [uploadProgress, setUploadProgress] = useState(0);
  const [quota, setQuota] = useState<QuotaInfo | null>(null);
  const [sessionIds, setSessionIds] = useState<string[]>([]);
  const [shareUrls, setShareUrls] = useState<string[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);
  const [sessions, setSessions] = useState<TrySession[]>([]);
  const [copiedSessionId, setCopiedSessionId] = useState<string | null>(null);
  const [currentUploadIndex, setCurrentUploadIndex] = useState(0);
  const [isServiceMode, setIsServiceMode] = useState(false);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [inputFiles, setInputFiles] = useState<any[]>([]);
  const [isMultiFile, setIsMultiFile] = useState(false);
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
        setIsMultiFile(status.isMultiFile === true);
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

  // Poll session status when uploading
  useEffect(() => {
    if (sessionIds.length === 0 || uploadStatus.type === 'completed' || uploadStatus.type === 'error') {
      return;
    }

    const interval = setInterval(async () => {
      try {
        // Check status of all sessions
        const allCompleted = [];
        for (const sessionId of sessionIds) {
          const status = await api.getSessionStatus(sessionId);
          
          if (status.status === 'completed') {
            allCompleted.push(sessionId);
          } else if (status.status === 'failed') {
            setUploadStatus({
              type: 'error',
              message: `Analysis failed for ${status.inputFilename}: ${status.errorMessage || 'Unknown error'}`,
            });
            loadQuota();
            return;
          } else if (status.status === 'processing') {
            const elapsed = status.startTime 
              ? Math.floor((Date.now() - new Date(status.startTime).getTime()) / 1000)
              : 0;
            setUploadStatus({
              type: 'processing',
              message: `Processing ${status.inputFilename}... (${elapsed}s elapsed, ${allCompleted.length}/${sessionIds.length} completed)`,
            });
          } else if (status.status === 'queued') {
            setUploadStatus({
              type: 'processing',
              message: `Queued for analysis... (${allCompleted.length}/${sessionIds.length} completed)`,
            });
          }
        }

        // All completed
        if (allCompleted.length === sessionIds.length) {
          setUploadStatus({
            type: 'completed',
            message: `All ${sessionIds.length} file(s) analyzed successfully! Redirecting to results...`,
          });
          
          // Redirect to dashboard after 1 second
          setTimeout(() => {
            window.location.href = '/';
          }, 1000);
        }
      } catch (error) {
        console.error('Failed to check status:', error);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [sessionIds, uploadStatus.type, loadQuota]);

  const handleFileSelect = (selectedFiles: File[]) => {
    setFiles(selectedFiles);
    setUploadStatus({ type: 'idle', message: '' });
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);

    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles.length > 0) {
      handleFileSelect(Array.from(droppedFiles));
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = e.target.files;
    if (selectedFiles && selectedFiles.length > 0) {
      handleFileSelect(Array.from(selectedFiles));
    }
  };

  const handleRemoveFile = (index: number) => {
    setFiles(prevFiles => prevFiles.filter((_, i) => i !== index));
  };

  const handleUpload = async () => {
    if (files.length === 0) {
      setUploadStatus({ type: 'error', message: 'Please select at least one file' });
      return;
    }

    // Get max file size from config or use defaults
    let maxSize = 200 * 1024 * 1024; // 200MB default for local mode
    if (isServiceMode && config) {
      const maxFileSizeOption = config.options.find(opt => opt.name === 'max-file-size');
      if (maxFileSizeOption && typeof maxFileSizeOption.value === 'number') {
        maxSize = maxFileSizeOption.value;
      } else {
        maxSize = 100 * 1024 * 1024; // 100MB fallback for service mode
      }
    }

    // Validate file sizes
    for (const file of files) {
      if (file.size > maxSize) {
        const maxSizeMB = Math.round(maxSize / (1024 * 1024));
        setUploadStatus({ type: 'error', message: `File ${file.name} exceeds ${maxSizeMB}MB limit` });
        return;
      }

      // Validate file extension
      const ext = file.name.toLowerCase();
      if (!ext.endsWith('.pcap') && !ext.endsWith('.pcapng')) {
        setUploadStatus({ type: 'error', message: `Invalid file format for ${file.name}. Only .pcap and .pcapng files are allowed.` });
        return;
      }
    }

    setUploadStatus({ type: 'uploading', message: `Uploading ${files.length} file(s)...` });
    setCurrentUploadIndex(0);
    
    const allSessionIds: string[] = [];
    const allShareUrls: string[] = [];

    try {
      // Upload files one by one
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setCurrentUploadIndex(i);
        setUploadProgress(Math.floor(((i + 0.5) / files.length) * 100));
        setUploadStatus({ type: 'uploading', message: `Uploading ${i + 1}/${files.length}: ${file.name}...` });

        const response = await api.uploadFile(file);
        
        // Service mode returns sessionId and shareUrl
        if (isServiceMode && response.sessionId) {
          allSessionIds.push(response.sessionId);
          allShareUrls.push(response.shareUrl);
        }
        
        setUploadProgress(Math.floor(((i + 1) / files.length) * 100));
      }
      
      if (isServiceMode) {
        setSessionIds(allSessionIds);
        setShareUrls(allShareUrls);
        setUploadStatus({ type: 'success', message: `All ${files.length} file(s) uploaded successfully! Starting analysis...` });
        
        // Reload quota and sessions to show updated values
        await loadQuota();
        await loadSessions();
        await loadInputFiles();
        
        // Invalidate SWR cache for input files so other pages (like PCAPs) will refresh
        globalMutate('inputFiles');
      } else {
        // Local mode - files are saved and ready for manual analysis
        setUploadStatus({ 
          type: 'completed', 
          message: `All ${files.length} file(s) uploaded successfully! Files saved to uploads directory.` 
        });
        setFiles([]);
        
        // Invalidate SWR cache for input files
        globalMutate('inputFiles');
        
        // Redirect to dashboard after 2 seconds
        setTimeout(() => {
          window.location.href = '/';
        }, 2000);
      }
    } catch (error) {
      setUploadProgress(0);
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      setUploadStatus({ 
        type: 'error', 
        message: errorMessage
      });
      if (isServiceMode) {
        await loadQuota();
      }
    }
  };

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
      window.location.href = '/audit';
    } catch (error) {
      console.error('Failed to select session:', error);
      alert('Failed to load session');
    }
  };

  const handleViewLogs = async (sessionId: string) => {
    try {
      await api.selectSession(sessionId);
      window.location.href = '/logs';
    } catch (error) {
      console.error('Failed to select session:', error);
      alert('Failed to load session logs');
    }
  };

  const handleViewFile = async (filePath: string) => {
    try {
      await api.setActiveDirectory(filePath);
      window.location.href = '/audit';
    } catch (error) {
      console.error('Failed to select file:', error);
      alert('Failed to load file');
    }
  };

  const handleViewFileLogs = async (filePath: string) => {
    try {
      await api.setActiveDirectory(filePath);
      window.location.href = '/logs';
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

  const isUploadDisabled = isServiceMode && (!quota?.allowed || 
    (quota && !quota.storage.unlimited && quota.storage.percentUsed >= 95));

  const totalFileSize = files.reduce((sum, file) => sum + file.size, 0);

  return (
    <Layout title="Analyze PCAP Files">
      <Box>
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
                
                <Box flex={1} minWidth={300}>
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
              <Paper
                sx={{
                  p: 2,
                  bgcolor: 'action.hover',
                  fontFamily: 'monospace',
                  fontSize: '0.95rem',
                  overflow: 'auto',
                }}
              >
                {bpfData.currentFilter}
              </Paper>
              <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
                <Link href="/bpf" style={{ color: 'inherit', textDecoration: 'none' }}>
                  <Button variant="outlined" size="small">
                    Edit Filter
                  </Button>
                </Link>
              </Box>
            </CardContent>
          </Card>
        )}

        {/* Analyze Area */}
        <Card>
          <CardContent>
            {isServiceMode && (
              <Alert severity="info" sx={{ mb: 2 }}>
                You can upload your own PCAP files or browse results from pre-analyzed files. 
                Visit the <Link href="/pcaps" style={{ color: 'inherit', fontWeight: 'bold' }}>PCAPs page</Link> to explore available analyses.
              </Alert>
            )}

            <Paper
              sx={{
                p: 6,
                textAlign: 'center',
                cursor: isUploadDisabled ? 'not-allowed' : 'pointer',
                border: '2px dashed',
                borderColor: dragOver ? 'primary.main' : files.length > 0 ? 'success.main' : 'divider',
                bgcolor: dragOver ? 'action.hover' : files.length > 0 ? 'success.dark' : 'background.default',
                transition: 'all 0.2s',
                opacity: isUploadDisabled ? 0.5 : 1,
              }}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => {
                if (!isUploadDisabled) {
                  const input = document.querySelector('input[type="file"]') as HTMLInputElement;
                  input?.click();
                }
              }}
            >
              <input
                type="file"
                accept=".pcap,.pcapng"
                multiple
                style={{ display: 'none' }}
                onChange={handleFileInputChange}
                disabled={isUploadDisabled}
              />
              
              <CloudUploadIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
              
              {files.length > 0 ? (
                <Box>
                  <Typography variant="h6" gutterBottom>
                    {files.length} file(s) selected
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total size: {formatBytes(totalFileSize)}
                  </Typography>
                  <Box sx={{ mt: 2, maxHeight: 200, overflow: 'auto' }}>
                    {files.map((file, index) => (
                      <Chip
                        key={index}
                        label={`${file.name} (${formatBytes(file.size)})`}
                        onDelete={() => handleRemoveFile(index)}
                        sx={{ m: 0.5 }}
                      />
                    ))}
                  </Box>
                </Box>
              ) : (
                <Box>
                  <Typography variant="body1" gutterBottom>
                    Click to select PCAP files
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    or drag and drop here (multiple files supported)
                  </Typography>
                </Box>
              )}
            </Paper>

            {/* Progress Bar */}
            {uploadStatus.type === 'uploading' && (
              <Box sx={{ mt: 2 }}>
                <LinearProgress variant="determinate" value={uploadProgress} />
              </Box>
            )}

            {/* Status Messages */}
            {uploadStatus.message && (
              <Alert 
                severity={
                  uploadStatus.type === 'error' ? 'error' : 
                  uploadStatus.type === 'success' || uploadStatus.type === 'completed' ? 'success' : 
                  'info'
                }
                icon={
                  uploadStatus.type === 'error' ? <ErrorIcon /> :
                  uploadStatus.type === 'success' || uploadStatus.type === 'completed' ? <CheckCircleIcon /> :
                  undefined
                }
                sx={{ mt: 2 }}
              >
                {uploadStatus.message}
              </Alert>
            )}

            {/* Share Links */}
            {shareUrls.length > 0 && (
              <Card sx={{ mt: 3, bgcolor: 'action.hover' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={1} mb={2}>
                    <ShareIcon color="primary" />
                    <Typography variant="h6">
                      Shareable Links
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {shareUrls.length === 1 
                      ? 'Share this link with others to view the analysis results:' 
                      : `Share these ${shareUrls.length} links with others to view the analysis results:`}
                  </Typography>
                  {shareUrls.map((url, index) => (
                    <Box key={index} display="flex" gap={1} alignItems="center" sx={{ mb: shareUrls.length > 1 ? 1 : 0 }}>
                      {shareUrls.length > 1 && (
                        <Chip label={`File ${index + 1}`} size="small" sx={{ minWidth: 60 }} />
                      )}
                      <Paper
                        sx={{
                          flex: 1,
                          p: 1.5,
                          bgcolor: 'background.default',
                          fontFamily: 'monospace',
                          fontSize: '0.875rem',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {url}
                      </Paper>
                      <Button
                        variant="contained"
                        size="small"
                        startIcon={copySuccess ? <CheckCircleIcon /> : <ContentCopyIcon />}
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(url);
                            setCopySuccess(true);
                            setTimeout(() => setCopySuccess(false), 2000);
                          } catch (error) {
                            console.error('Failed to copy:', error);
                          }
                        }}
                        color={copySuccess ? 'success' : 'primary'}
                      >
                        {copySuccess ? 'Copied!' : 'Copy'}
                      </Button>
                    </Box>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Analyze Button */}
            <Button
              fullWidth
              variant="contained"
              size="large"
              startIcon={<CloudUploadIcon />}
              onClick={handleUpload}
              disabled={
                files.length === 0 || 
                uploadStatus.type === 'uploading' || 
                uploadStatus.type === 'processing' ||
                uploadStatus.type === 'completed' ||
                isUploadDisabled
              }
              sx={{ mt: 2 }}
            >
              {uploadStatus.type === 'uploading' ? `Uploading... (${currentUploadIndex + 1}/${files.length})` :
               uploadStatus.type === 'processing' ? 'Processing...' :
               uploadStatus.type === 'completed' ? 'Completed' :
               files.length > 1 ? `Analyze ${files.length} Files` : 'Analyze'}
            </Button>
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
                  Maximum file size: 200MB
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Supported formats: PCAP, PCAPNG
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  Files are saved to the uploads directory
                </Typography>
                <Typography component="li" variant="body2" color="text.secondary">
                  Use the command line to analyze uploaded files
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
                                    size="small"
                                    color="primary"
                                    onClick={() => handleViewSession(session.sessionId)}
                                  >
                                    <VisibilityIcon />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="View Logs">
                                  <IconButton
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
                                    size="small"
                                    color="primary"
                                    onClick={() => handleViewFile(file.path)}
                                  >
                                    <VisibilityIcon />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="View Logs">
                                  <IconButton
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

