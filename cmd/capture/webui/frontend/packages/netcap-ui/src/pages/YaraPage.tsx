/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useState, useCallback } from 'react';
import {
  Alert,
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
  Grid,
  IconButton,
  LinearProgress,
  Snackbar,
  Switch,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ShieldIcon from '@mui/icons-material/Shield';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { useNetcapRouter, useNetcapApi } from '../hooks';
import Layout from '../components/Layout';
import { YaraRuleInfo, YaraScanResult } from '../lib/api';
import useSWR, { mutate } from 'swr';

export default function YaraPage() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [tabIndex, setTabIndex] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<YaraScanResult[]>([]);
  const [scanStats, setScanStats] = useState<{ totalFiles: number; totalMatches: number; scanTimeMs: number } | null>(null);
  const [viewDialog, setViewDialog] = useState<{ open: boolean; filename: string; content: string }>({ open: false, filename: '', content: '' });
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({ open: false, message: '', severity: 'success' });

  const { data: status } = useSWR('yara-status', () => api.getYaraStatus());
  const { data: rulesData } = useSWR('yara-rules', () => api.getYaraRules());
  const rules = rulesData?.rules ?? [];

  const showSnackbar = (message: string, severity: 'success' | 'error') => {
    setSnackbar({ open: true, message, severity });
  };

  const handleUpload = useCallback(async () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.yar,.yara';
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const result = await api.uploadYaraRule(file);
        showSnackbar(`Uploaded ${result.filename} (${result.ruleCount} rules)`, 'success');
        mutate('yara-rules');
        mutate('yara-status');
      } catch (err: any) {
        showSnackbar(err.message || 'Upload failed', 'error');
      }
    };
    input.click();
  }, [api]);

  const handleToggle = useCallback(async (rule: YaraRuleInfo) => {
    try {
      await api.updateYaraRule(rule.filename, { enabled: !rule.enabled });
      mutate('yara-rules');
      mutate('yara-status');
    } catch (err: any) {
      showSnackbar(err.message || 'Failed to toggle rule', 'error');
    }
  }, [api]);

  const handleDelete = useCallback(async (filename: string) => {
    try {
      await api.deleteYaraRule(filename);
      showSnackbar('Rule deleted', 'success');
      mutate('yara-rules');
      mutate('yara-status');
    } catch (err: any) {
      showSnackbar(err.message || 'Failed to delete rule', 'error');
    }
  }, [api]);

  const handleView = useCallback(async (filename: string) => {
    try {
      const result = await api.getYaraRuleContent(filename);
      setViewDialog({ open: true, filename, content: result.content });
    } catch (err: any) {
      showSnackbar(err.message || 'Failed to load rule', 'error');
    }
  }, [api]);

  const handleScan = useCallback(async () => {
    setScanning(true);
    setScanResults([]);
    setScanStats(null);
    try {
      const result = await api.scanWithYara();
      setScanResults(result.results);
      setScanStats({ totalFiles: result.totalFiles, totalMatches: result.totalMatches, scanTimeMs: result.scanTimeMs });
      showSnackbar(`Scan complete: ${result.totalMatches} matches in ${result.totalFiles} files`, 'success');
    } catch (err: any) {
      showSnackbar(err.message || 'Scan failed', 'error');
    } finally {
      setScanning(false);
    }
  }, [api]);

  const available = status?.available ?? false;
  const hasRules = rules.length > 0;

  return (
    <Layout title="YARA Rules">
      <Box sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 3, gap: 2 }}>
          <ShieldIcon sx={{ fontSize: 32 }} />
          <Typography variant="h5">YARA Rules</Typography>
        </Box>

        {!available && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            YARA support is not available in this build. Build without the <code>noyara</code> tag and ensure <code>libyara_x_capi</code> is installed.
          </Alert>
        )}

        <Tabs value={tabIndex} onChange={(_, v) => setTabIndex(v)} sx={{ mb: 2 }}>
          <Tab label="Rules" />
          <Tab label="Scan Results" />
        </Tabs>

        {/* Rules Tab */}
        {tabIndex === 0 && (
          <Box>
            <Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center' }}>
              <Button variant="contained" startIcon={<CloudUploadIcon />} onClick={handleUpload} disabled={!available}>
                Upload Rule
              </Button>
              <Typography variant="body2" color="text.secondary">
                {status ? `${status.enabledRules} compiled rules from ${rules.length} files` : ''}
              </Typography>
            </Box>

            {rules.length === 0 ? (
              <Alert severity="info">No YARA rules uploaded yet. Upload .yar or .yara files to get started.</Alert>
            ) : (
              <Grid container spacing={2}>
                {rules.map((rule) => (
                  <Grid item xs={12} sm={6} md={4} key={rule.filename}>
                    <Card sx={{ height: '100%' }}>
                      <CardContent>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                          <Typography variant="subtitle1" fontWeight="bold" noWrap>
                            {rule.name}
                          </Typography>
                          <Switch
                            size="small"
                            checked={rule.enabled}
                            onChange={() => handleToggle(rule)}
                          />
                        </Box>
                        {rule.description && (
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1 }} noWrap>
                            {rule.description}
                          </Typography>
                        )}
                        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
                          <Chip label={`${rule.ruleCount} rules`} size="small" color="primary" variant="outlined" />
                          <Chip label={api.formatBytes(rule.size)} size="small" variant="outlined" />
                        </Box>
                        <Box sx={{ display: 'flex', gap: 0.5, mt: 1, justifyContent: 'flex-end' }}>
                          <Tooltip title="View content">
                            <IconButton size="small" onClick={() => handleView(rule.filename)}>
                              <VisibilityIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton size="small" onClick={() => handleDelete(rule.filename)} color="error">
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            )}
          </Box>
        )}

        {/* Scan Results Tab */}
        {tabIndex === 1 && (
          <Box>
            <Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center' }}>
              <Button
                variant="contained"
                startIcon={scanning ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />}
                onClick={handleScan}
                disabled={!available || !hasRules || scanning}
              >
                {scanning ? 'Scanning...' : 'Scan All Files'}
              </Button>
              {!hasRules && available && (
                <Typography variant="body2" color="text.secondary">Upload YARA rules first</Typography>
              )}
            </Box>

            {scanning && <LinearProgress sx={{ mb: 2 }} />}

            {scanStats && (
              <Alert severity={scanStats.totalMatches > 0 ? 'warning' : 'success'} sx={{ mb: 2 }}>
                Scanned {scanStats.totalFiles} files in {scanStats.scanTimeMs}ms — {scanStats.totalMatches} match{scanStats.totalMatches !== 1 ? 'es' : ''} found
              </Alert>
            )}

            {scanResults.length > 0 && (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>File</TableCell>
                      <TableCell>Matched Rules</TableCell>
                      <TableCell align="right">Scan Time</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {scanResults.map((result, i) => (
                      <TableRow key={i}>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">{result.fileName}</Typography>
                          <Typography variant="caption" color="text.secondary">{result.filePath}</Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {result.matches.map((m) => (
                              <Chip key={m} label={m} size="small" color="error" variant="outlined" />
                            ))}
                          </Box>
                        </TableCell>
                        <TableCell align="right">{result.scanTimeMs}ms</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}

            {scanStats && scanResults.length === 0 && (
              <Typography color="text.secondary">No matches found.</Typography>
            )}
          </Box>
        )}

        {/* View Rule Dialog */}
        <Dialog open={viewDialog.open} onClose={() => setViewDialog({ ...viewDialog, open: false })} maxWidth="md" fullWidth>
          <DialogTitle>{viewDialog.filename}</DialogTitle>
          <DialogContent>
            <TextField
              multiline
              fullWidth
              value={viewDialog.content}
              InputProps={{ readOnly: true, sx: { fontFamily: 'monospace', fontSize: 13 } }}
              minRows={15}
              maxRows={30}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setViewDialog({ ...viewDialog, open: false })}>Close</Button>
          </DialogActions>
        </Dialog>

        <Snackbar
          open={snackbar.open}
          autoHideDuration={4000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
        >
          <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
            {snackbar.message}
          </Alert>
        </Snackbar>
      </Box>
    </Layout>
  );
}
