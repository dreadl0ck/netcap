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
} from '@mui/material';
import Layout from '@/components/Layout';
import { api, TrySession } from '@/lib/api';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import LinkIcon from '@mui/icons-material/Link';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ShareIcon from '@mui/icons-material/Share';

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

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus>({ type: 'idle', message: '' });
  const [uploadProgress, setUploadProgress] = useState(0);
  const [quota, setQuota] = useState<QuotaInfo | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);
  const [sessions, setSessions] = useState<TrySession[]>([]);
  const [copiedSessionId, setCopiedSessionId] = useState<string | null>(null);

  const loadQuota = useCallback(async () => {
    try {
      const quotaData = await api.getQuota();
      setQuota(quotaData);
    } catch (error) {
      console.error('Failed to load quota:', error);
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

  // Load quota and sessions on mount
  useEffect(() => {
    loadQuota();
    loadSessions();
  }, [loadQuota, loadSessions]);

  // Poll session status when uploading
  useEffect(() => {
    if (!sessionId || uploadStatus.type === 'completed' || uploadStatus.type === 'error') {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const status = await api.getSessionStatus(sessionId);
        
        if (status.status === 'completed') {
          setUploadStatus({
            type: 'completed',
            message: 'Analysis complete! Redirecting to results...',
          });
          
          // Redirect to dashboard after 1 second
          setTimeout(() => {
            window.location.href = '/';
          }, 1000);
        } else if (status.status === 'failed') {
          setUploadStatus({
            type: 'error',
            message: `Analysis failed: ${status.errorMessage || 'Unknown error'}`,
          });
          loadQuota(); // Reload quota to update storage/rate limit
        } else if (status.status === 'processing') {
          const elapsed = status.startTime 
            ? Math.floor((Date.now() - new Date(status.startTime).getTime()) / 1000)
            : 0;
          setUploadStatus({
            type: 'processing',
            message: `Processing ${status.inputFilename}... (${elapsed}s elapsed)`,
          });
        } else if (status.status === 'queued') {
          setUploadStatus({
            type: 'processing',
            message: 'Queued for analysis...',
          });
        }
      } catch (error) {
        console.error('Failed to check status:', error);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [sessionId, uploadStatus.type, loadQuota]);

  const handleFileSelect = (selectedFile: File) => {
    setFile(selectedFile);
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

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileSelect(files[0]);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileSelect(files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setUploadStatus({ type: 'error', message: 'Please select a file' });
      return;
    }

    // Validate file size (50MB limit)
    const maxSize = 50 * 1024 * 1024;
    if (file.size > maxSize) {
      setUploadStatus({ type: 'error', message: 'File size exceeds 50MB limit' });
      return;
    }

    // Validate file extension
    const ext = file.name.toLowerCase();
    if (!ext.endsWith('.pcap') && !ext.endsWith('.pcapng')) {
      setUploadStatus({ type: 'error', message: 'Invalid file format. Only .pcap and .pcapng files are allowed.' });
      return;
    }

    setUploadStatus({ type: 'uploading', message: 'Uploading...' });
    setUploadProgress(30);

    try {
      const response = await api.uploadFile(file);
      
      setSessionId(response.sessionId);
      setShareUrl(response.shareUrl);
      setUploadProgress(100);
      setUploadStatus({ type: 'success', message: 'Upload successful! Starting analysis...' });
      
      // Reload quota and sessions to show updated values
      await loadQuota();
      await loadSessions();
    } catch (error) {
      setUploadProgress(0);
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      setUploadStatus({ 
        type: 'error', 
        message: errorMessage
      });
      await loadQuota();
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
      window.location.href = '/';
    } catch (error) {
      console.error('Failed to select session:', error);
      alert('Failed to load session');
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

  const handleCopyShareLink = async () => {
    if (!shareUrl) return;

    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const isUploadDisabled = !quota?.allowed || 
    (quota && !quota.storage.unlimited && quota.storage.percentUsed >= 95);

  return (
    <Layout title="Upload PCAP File">
      <Box>
        {/* Quota Information */}
        {quota && (
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
                
                {!quota.storage.unlimited && (
                  <Box flex={1} minWidth={300}>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Storage Usage
                    </Typography>
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
                  </Box>
                )}
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

        {/* Upload Area */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Upload PCAP File
            </Typography>

            <Paper
              sx={{
                p: 6,
                textAlign: 'center',
                cursor: isUploadDisabled ? 'not-allowed' : 'pointer',
                border: '2px dashed',
                borderColor: dragOver ? 'primary.main' : file ? 'success.main' : 'divider',
                bgcolor: dragOver ? 'action.hover' : file ? 'success.dark' : 'background.default',
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
                style={{ display: 'none' }}
                onChange={handleFileInputChange}
                disabled={isUploadDisabled}
              />
              
              <CloudUploadIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
              
              {file ? (
                <Box>
                  <Typography variant="h6" gutterBottom>
                    {file.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {formatBytes(file.size)}
                  </Typography>
                </Box>
              ) : (
                <Box>
                  <Typography variant="body1" gutterBottom>
                    Click to select a PCAP file
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    or drag and drop here
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

            {/* Share Link */}
            {shareUrl && (
              <Card sx={{ mt: 3, bgcolor: 'action.hover' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={1} mb={2}>
                    <LinkIcon color="primary" />
                    <Typography variant="h6">
                      Shareable Link
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Share this link with others to view the analysis results:
                  </Typography>
                  <Box display="flex" gap={1} alignItems="center">
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
                      {shareUrl}
                    </Paper>
                    <Button
                      variant="contained"
                      startIcon={copySuccess ? <CheckCircleIcon /> : <ContentCopyIcon />}
                      onClick={handleCopyShareLink}
                      color={copySuccess ? 'success' : 'primary'}
                    >
                      {copySuccess ? 'Copied!' : 'Copy'}
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            )}

            {/* Upload Button */}
            <Button
              fullWidth
              variant="contained"
              size="large"
              startIcon={<CloudUploadIcon />}
              onClick={handleUpload}
              disabled={
                !file || 
                uploadStatus.type === 'uploading' || 
                uploadStatus.type === 'processing' ||
                uploadStatus.type === 'completed' ||
                isUploadDisabled
              }
              sx={{ mt: 2 }}
            >
              {uploadStatus.type === 'uploading' ? 'Uploading...' :
               uploadStatus.type === 'processing' ? 'Processing...' :
               uploadStatus.type === 'completed' ? 'Completed' :
               'Upload and Analyze'}
            </Button>
          </CardContent>
        </Card>

        {/* Service Limits */}
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom color="primary">
              Service Limits
            </Typography>
            <Box component="ul" sx={{ m: 0, pl: 2 }}>
              <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                Maximum file size: 50MB
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                Supported formats: PCAP, PCAPNG
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                Rate limit: 2 analyses per hour
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

        {/* Previous Uploads */}
        {sessions.length > 0 && (
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Your Recent Uploads
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                View and share your analysis results
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>File</TableCell>
                      <TableCell>Uploaded</TableCell>
                      <TableCell>Size</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {sessions.map((session) => (
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
                              <Tooltip title="View Results">
                                <IconButton
                                  size="small"
                                  color="primary"
                                  onClick={() => handleViewSession(session.sessionId)}
                                >
                                  <VisibilityIcon />
                                </IconButton>
                              </Tooltip>
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

