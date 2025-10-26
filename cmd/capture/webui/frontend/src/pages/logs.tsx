import React, { useState } from 'react';
import {
  Box,
  Button,
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
  Typography,
} from '@mui/material';
import Layout from '@/components/Layout';
import { api, formatBytes, formatTimestamp } from '@/lib/api';
import useSWR from 'swr';

export default function Logs() {
  const { data: files, error } = useSWR('logFiles', () => api.getLogFiles());
  const [selectedLog, setSelectedLog] = useState<string | null>(null);
  const [logContent, setLogContent] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const handleViewLog = async (name: string) => {
    setSelectedLog(name);
    setLoading(true);
    try {
      const content = await api.getLogContent(name);
      setLogContent(content);
    } catch (err) {
      console.error('Failed to load log:', err);
      setLogContent('Error loading log file');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setSelectedLog(null);
    setLogContent('');
  };

  if (!files && !error) {
    return (
      <Layout title="Logs">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Logs">
        <Box>
          <Typography color="error">Error loading log files</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Logs">
      <Box>
        <Typography variant="h4" gutterBottom>
          Log Files
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          {files?.length || 0} log file(s) available
        </Typography>

        {files && files.length > 0 ? (
          <TableContainer component={Paper} sx={{ mt: 3 }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Filename</TableCell>
                  <TableCell align="right">Size</TableCell>
                  <TableCell align="right">Modified</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {files.map((file) => (
                  <TableRow key={file.path}>
                    <TableCell>
                      <Typography sx={{ fontFamily: 'monospace' }}>{file.name}</Typography>
                    </TableCell>
                    <TableCell align="right">{formatBytes(file.size)}</TableCell>
                    <TableCell align="right">{formatTimestamp(file.modifiedTime)}</TableCell>
                    <TableCell align="right">
                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() => handleViewLog(file.name)}
                      >
                        View Log
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        ) : (
          <Box mt={3}>
            <Typography color="text.secondary">No log files found</Typography>
          </Box>
        )}
      </Box>

      <Dialog open={selectedLog !== null} onClose={handleClose} maxWidth="lg" fullWidth>
        <DialogTitle>{selectedLog}</DialogTitle>
        <DialogContent>
          {loading ? (
            <Box display="flex" justifyContent="center" p={3}>
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
                }}
              >
                {logContent || 'Empty log file'}
              </pre>
            </Paper>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>Close</Button>
        </DialogActions>
      </Dialog>
    </Layout>
  );
}

