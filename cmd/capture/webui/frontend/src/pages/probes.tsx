import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  TextField,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Grid,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  TablePagination,
  Alert,
  Snackbar,
  FormHelperText,
} from '@mui/material';
import {
  Edit as EditIcon,
  Science as TestIcon,
  FileUpload as ImportIcon,
  FileDownload as ExportIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import useSWR from 'swr';
import Layout from '@/components/Layout';
import type { ServiceProbeInfo, TestProbeRequest, TestProbeResponse } from '@/lib/api';
import { api, getBackendUrl } from '@/lib/api';

// Syntax highlighting component for regex patterns
const RegexHighlighter = ({ pattern }: { pattern: string }) => {
  const highlightRegex = (regex: string) => {
    const parts: Array<{ text: string; type: string }> = [];
    let currentPos = 0;
    
    // Define regex tokens with colors
    const tokenPatterns = [
      { pattern: /\(\?[imsxUXJ]+\)/g, type: 'flag', color: '#9C27B0' }, // Flags like (?i), (?m)
      { pattern: /\((?!\?)/g, type: 'group', color: '#2196F3' }, // Capturing groups
      { pattern: /\)/g, type: 'group', color: '#2196F3' },
      { pattern: /\[(?:[^\]\\]|\\.)*\]/g, type: 'charclass', color: '#00BCD4' }, // Character classes
      { pattern: /\\[wWdDsSnrt]/g, type: 'escape', color: '#4CAF50' }, // Escapes
      { pattern: /\\x[0-9A-Fa-f]{2}/g, type: 'hex', color: '#FF9800' }, // Hex codes
      { pattern: /\\[0-7]{3}/g, type: 'octal', color: '#FF9800' }, // Octal codes
      { pattern: /[*+?{}\|]/g, type: 'quantifier', color: '#F44336' }, // Quantifiers
      { pattern: /\$[0-9]+/g, type: 'backref', color: '#E91E63' }, // Backreferences
      { pattern: /\^|\$/g, type: 'anchor', color: '#FF5722' }, // Anchors
      { pattern: /\\\\/g, type: 'escape', color: '#4CAF50' }, // Escaped backslash
      { pattern: /\\./g, type: 'escape', color: '#4CAF50' }, // Other escapes
    ];

    // Simple tokenizer
    const tokens: Array<{ start: number; end: number; type: string; color: string }> = [];
    
    tokenPatterns.forEach(({ pattern, type, color }) => {
      const matches = [...regex.matchAll(pattern)];
      matches.forEach((match) => {
        if (match.index !== undefined) {
          tokens.push({
            start: match.index,
            end: match.index + match[0].length,
            type,
            color,
          });
        }
      });
    });

    // Sort tokens by position
    tokens.sort((a, b) => a.start - b.start);

    // Build highlighted parts
    let pos = 0;
    const result: React.ReactElement[] = [];

    tokens.forEach((token, idx) => {
      // Add plain text before token
      if (pos < token.start) {
        const text = regex.slice(pos, token.start);
        result.push(
          <span key={`plain-${idx}`} style={{ color: '#333' }}>
            {text}
          </span>
        );
      }

      // Add highlighted token
      const text = regex.slice(token.start, token.end);
      result.push(
        <span key={`token-${idx}`} style={{ color: token.color, fontWeight: 500 }}>
          {text}
        </span>
      );

      pos = token.end;
    });

    // Add remaining plain text
    if (pos < regex.length) {
      result.push(
        <span key="plain-end" style={{ color: '#333' }}>
          {regex.slice(pos)}
        </span>
      );
    }

    return result;
  };

  return (
    <Box
      sx={{
        fontFamily: "'Fira Code', 'Monaco', 'Courier New', monospace",
        fontSize: '0.875rem',
        backgroundColor: '#f5f5f5',
        border: '1px solid #e0e0e0',
        borderRadius: 1,
        p: 1.5,
        overflow: 'auto',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-all',
        lineHeight: 1.6,
      }}
    >
      {highlightRegex(pattern)}
    </Box>
  );
};

export default function ServiceProbes() {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocol, setProtocol] = useState('all');
  const [service, setService] = useState('all');
  const [matchType, setMatchType] = useState('all');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [testModalOpen, setTestModalOpen] = useState(false);
  const [selectedProbe, setSelectedProbe] = useState<ServiceProbeInfo | null>(null);
  const [editForm, setEditForm] = useState<Partial<ServiceProbeInfo>>({});
  const [testPattern, setTestPattern] = useState('');
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState<TestProbeResponse | null>(null);
  const [snackbar, setSnackbar] = useState<{open: boolean; message: string; severity: 'success' | 'error'}>({
    open: false,
    message: '',
    severity: 'success',
  });
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);

  // Fetch service probes with filters
  const { data: probesData, error: probesError, mutate } = useSWR(
    ['service-probes', searchTerm, protocol, service, matchType, page, rowsPerPage],
    () => api.getServiceProbes({
      search: searchTerm || undefined,
      protocol: protocol !== 'all' ? protocol : undefined,
      service: service !== 'all' ? service : undefined,
      matchType: matchType !== 'all' ? matchType : undefined,
      offset: page * rowsPerPage,
      limit: rowsPerPage,
    }),
    {
      revalidateOnFocus: false,
    }
  );

  // Extract unique services for filter
  const uniqueServices = probesData?.probes
    ? Array.from(new Set(probesData.probes.map(p => p.service))).sort()
    : [];

  const handleEditClick = (probe: ServiceProbeInfo) => {
    setSelectedProbe(probe);
    setEditForm({
      ...probe,
      ports: probe.ports || [],
      sslPorts: probe.sslPorts || [],
      cpes: probe.cpes || [],
    });
    setEditModalOpen(true);
  };

  const handleTestClick = (probe: ServiceProbeInfo) => {
    setSelectedProbe(probe);
    setTestPattern(probe.pattern);
    setTestInput('');
    setTestResult(null);
    setTestModalOpen(true);
  };

  const handleSaveEdit = async () => {
    if (!selectedProbe) return;

    try {
      await api.updateServiceProbe(selectedProbe.id, editForm);
      setSnackbar({
        open: true,
        message: 'Service probe updated successfully',
        severity: 'success',
      });
      setEditModalOpen(false);
      mutate();
    } catch (error) {
      setSnackbar({
        open: true,
        message: `Failed to update probe: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: 'error',
      });
    }
  };

  const handleTest = async () => {
    try {
      const request: TestProbeRequest = {
        pattern: testPattern,
        sampleInput: testInput,
      };
      const result = await api.testServiceProbe(request);
      setTestResult(result);
    } catch (error) {
      setTestResult({
        matches: false,
        capturedGroups: {},
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  };

  const handleExport = () => {
    const url = api.exportServiceProbes();
    window.open(url, '_blank');
  };

  const handleImport = async () => {
    if (!selectedFile) return;

    setImporting(true);
    try {
      const result = await api.importServiceProbes(selectedFile);
      setSnackbar({
        open: true,
        message: `Successfully imported ${result.importedCount} service probes`,
        severity: 'success',
      });
      setImportDialogOpen(false);
      setSelectedFile(null);
      mutate();
    } catch (error) {
      setSnackbar({
        open: true,
        message: `Import failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: 'error',
      });
    } finally {
      setImporting(false);
    }
  };

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  if (probesError) {
    return (
      <Layout title="Service Probes">
        <Box sx={{ p: 3 }}>
          <Typography color="error">Failed to load service probes: {probesError.message}</Typography>
        </Box>
      </Layout>
    );
  }

  if (!probesData) {
    return (
      <Layout title="Service Probes">
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Service Probes">
      <Box sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box>
            <Typography variant="h4" gutterBottom>
              Service Probes
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Manage {probesData.totalCount} nmap service fingerprinting probes for network service identification.
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={<ImportIcon />}
              onClick={() => setImportDialogOpen(true)}
            >
              Import
            </Button>
            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              onClick={handleExport}
            >
              Export
            </Button>
          </Box>
        </Box>

        {/* Search & Filter Card */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Search"
                  variant="outlined"
                  value={searchTerm}
                  onChange={(e) => {
                    setSearchTerm(e.target.value);
                    setPage(0);
                  }}
                  placeholder="Search by service, product, pattern, or probe name..."
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Protocol</InputLabel>
                  <Select
                    value={protocol}
                    label="Protocol"
                    onChange={(e) => {
                      setProtocol(e.target.value);
                      setPage(0);
                    }}
                  >
                    <MenuItem value="all">All</MenuItem>
                    <MenuItem value="TCP">TCP</MenuItem>
                    <MenuItem value="UDP">UDP</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Service</InputLabel>
                  <Select
                    value={service}
                    label="Service"
                    onChange={(e) => {
                      setService(e.target.value);
                      setPage(0);
                    }}
                  >
                    <MenuItem value="all">All</MenuItem>
                    {uniqueServices.map((svc) => (
                      <MenuItem key={svc} value={svc}>
                        {svc}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Match Type</InputLabel>
                  <Select
                    value={matchType}
                    label="Match Type"
                    onChange={(e) => {
                      setMatchType(e.target.value);
                      setPage(0);
                    }}
                  >
                    <MenuItem value="all">All</MenuItem>
                    <MenuItem value="match">Match</MenuItem>
                    <MenuItem value="softmatch">Softmatch</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {/* Probes Table */}
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell><strong>Protocol</strong></TableCell>
                <TableCell><strong>Probe Name</strong></TableCell>
                <TableCell><strong>Service</strong></TableCell>
                <TableCell><strong>Product</strong></TableCell>
                <TableCell><strong>Ports</strong></TableCell>
                <TableCell><strong>Rarity</strong></TableCell>
                <TableCell><strong>Type</strong></TableCell>
                <TableCell align="right"><strong>Actions</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {probesData.probes.length > 0 ? (
                probesData.probes.map((probe) => (
                  <TableRow key={probe.id} hover>
                    <TableCell>
                      <Chip 
                        label={probe.protocol} 
                        size="small" 
                        color={probe.protocol === 'TCP' ? 'primary' : 'secondary'}
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {probe.probeName}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {probe.service}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {probe.product || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {probe.ports && probe.ports.length > 0 ? (
                          probe.ports.slice(0, 3).map((port) => (
                            <Chip
                              key={port}
                              label={port}
                              size="small"
                              variant="outlined"
                            />
                          ))
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            -
                          </Typography>
                        )}
                        {probe.ports && probe.ports.length > 3 && (
                          <Chip
                            label={`+${probe.ports.length - 3}`}
                            size="small"
                            variant="outlined"
                          />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {probe.rarity || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={probe.isSoftMatch ? 'Softmatch' : 'Match'}
                        size="small"
                        color={probe.isSoftMatch ? 'default' : 'success'}
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Test probe">
                        <IconButton
                          size="small"
                          color="primary"
                          onClick={() => handleTestClick(probe)}
                        >
                          <TestIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit probe">
                        <IconButton
                          size="small"
                          color="primary"
                          onClick={() => handleEditClick(probe)}
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={8} align="center">
                    <Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                      {searchTerm || protocol !== 'all' || service !== 'all' || matchType !== 'all'
                        ? 'No service probes match your search criteria'
                        : 'No service probes available'}
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={probesData.totalCount}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </TableContainer>

        {/* Info Card */}
        <Card sx={{ mt: 3, bgcolor: 'info.main', color: 'info.contrastText' }}>
          <CardContent>
            <Typography variant="body2">
              <strong>Note:</strong> Service probes are used by Netcap's service decoder to identify network services 
              based on their banners and response patterns. The probes are loaded from the nmap-service-probes database.
            </Typography>
          </CardContent>
        </Card>

        {/* Edit Modal */}
        <Dialog
          open={editModalOpen}
          onClose={() => setEditModalOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="h6">Edit Service Probe</Typography>
              <IconButton onClick={() => setEditModalOpen(false)} size="small">
                <CloseIcon />
              </IconButton>
            </Box>
          </DialogTitle>
          <DialogContent dividers>
            <Grid container spacing={2} sx={{ mt: 0.5 }}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Service"
                  value={editForm.service || ''}
                  onChange={(e) => setEditForm({ ...editForm, service: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Product"
                  value={editForm.product || ''}
                  onChange={(e) => setEditForm({ ...editForm, product: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Pattern (Regex)
                  </Typography>
                  <TextField
                    fullWidth
                    value={editForm.pattern || ''}
                    onChange={(e) => setEditForm({ ...editForm, pattern: e.target.value })}
                    size="small"
                    multiline
                    rows={3}
                    placeholder="Enter regex pattern..."
                    sx={{
                      '& .MuiInputBase-input': {
                        fontFamily: "'Fira Code', 'Monaco', 'Courier New', monospace",
                        fontSize: '0.875rem',
                      },
                    }}
                  />
                  {editForm.pattern && (
                    <Box sx={{ mt: 1 }}>
                      <Typography variant="caption" color="text.secondary">
                        Preview:
                      </Typography>
                      <RegexHighlighter pattern={editForm.pattern} />
                    </Box>
                  )}
                  <FormHelperText>Regular expression pattern to match service banner</FormHelperText>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Version"
                  value={editForm.version || ''}
                  onChange={(e) => setEditForm({ ...editForm, version: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Info"
                  value={editForm.info || ''}
                  onChange={(e) => setEditForm({ ...editForm, info: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Hostname"
                  value={editForm.hostname || ''}
                  onChange={(e) => setEditForm({ ...editForm, hostname: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="OS"
                  value={editForm.os || ''}
                  onChange={(e) => setEditForm({ ...editForm, os: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Device Type"
                  value={editForm.deviceType || ''}
                  onChange={(e) => setEditForm({ ...editForm, deviceType: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Rarity"
                  type="number"
                  value={editForm.rarity || 0}
                  onChange={(e) => setEditForm({ ...editForm, rarity: parseInt(e.target.value) })}
                  size="small"
                  helperText="1-9, lower is more common"
                />
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setEditModalOpen(false)}>Cancel</Button>
            <Button onClick={handleSaveEdit} variant="contained" color="primary">
              Save Changes
            </Button>
          </DialogActions>
        </Dialog>

        {/* Test Modal */}
        <Dialog
          open={testModalOpen}
          onClose={() => setTestModalOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="h6">Test Service Probe</Typography>
              <IconButton onClick={() => setTestModalOpen(false)} size="small">
                <CloseIcon />
              </IconButton>
            </Box>
          </DialogTitle>
          <DialogContent dividers>
            <Grid container spacing={2} sx={{ mt: 0.5 }}>
              <Grid item xs={12}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Pattern (Regex)
                  </Typography>
                  <RegexHighlighter pattern={testPattern} />
                </Box>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Sample Input"
                  value={testInput}
                  onChange={(e) => setTestInput(e.target.value)}
                  size="small"
                  multiline
                  rows={5}
                  placeholder="Enter sample banner or service response to test against the pattern..."
                  helperText="Enter the text you want to test the regex pattern against"
                />
              </Grid>
              <Grid item xs={12}>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<TestIcon />}
                  onClick={handleTest}
                  disabled={!testInput}
                  fullWidth
                >
                  Test Pattern
                </Button>
              </Grid>
              {testResult && (
                <Grid item xs={12}>
                  {testResult.error ? (
                    <Alert severity="error">
                      <Typography variant="body2">
                        <strong>Error:</strong> {testResult.error}
                      </Typography>
                    </Alert>
                  ) : testResult.matches ? (
                    <Alert severity="success">
                      <Typography variant="body2" gutterBottom>
                        <strong>Match Found!</strong>
                      </Typography>
                      {Object.keys(testResult.capturedGroups).length > 0 && (
                        <>
                          <Typography variant="body2" sx={{ mt: 1, mb: 0.5 }}>
                            <strong>Captured Groups:</strong>
                          </Typography>
                          <Box component="pre" sx={{ 
                            fontSize: '0.85rem', 
                            bgcolor: 'rgba(0,0,0,0.1)', 
                            p: 1, 
                            borderRadius: 1,
                            overflow: 'auto',
                          }}>
                            {JSON.stringify(testResult.capturedGroups, null, 2)}
                          </Box>
                        </>
                      )}
                    </Alert>
                  ) : (
                    <Alert severity="warning">
                      <Typography variant="body2">
                        <strong>No Match:</strong> The pattern did not match the input.
                      </Typography>
                    </Alert>
                  )}
                </Grid>
              )}
            </Grid>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setTestModalOpen(false)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Import Dialog */}
        <Dialog
          open={importDialogOpen}
          onClose={() => !importing && setImportDialogOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Import Service Probes</DialogTitle>
          <DialogContent dividers>
            <Typography variant="body2" color="text.secondary" paragraph>
              Select an nmap-service-probes file to import. This will replace the current service probes database.
              A backup will be created automatically.
            </Typography>
            <Box sx={{ mt: 2 }}>
              <Button
                variant="outlined"
                component="label"
                fullWidth
              >
                Choose File
                <input
                  type="file"
                  hidden
                  accept="*/*"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      setSelectedFile(e.target.files[0]);
                    }
                  }}
                />
              </Button>
              {selectedFile && (
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Selected: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(2)} KB)
                </Typography>
              )}
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setImportDialogOpen(false)} disabled={importing}>
              Cancel
            </Button>
            <Button
              onClick={handleImport}
              variant="contained"
              color="primary"
              disabled={!selectedFile || importing}
            >
              {importing ? <CircularProgress size={24} /> : 'Import'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Snackbar for notifications */}
        <Snackbar
          open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        >
          <Alert
            onClose={() => setSnackbar({ ...snackbar, open: false })}
            severity={snackbar.severity}
            sx={{ width: '100%' }}
          >
            {snackbar.message}
          </Alert>
        </Snackbar>
      </Box>
    </Layout>
  );
}

