/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import type React from 'react';
import { useState, useEffect } from 'react';
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
  FormControlLabel,
  InputLabel,
  TablePagination,
  Alert,
  Snackbar,
  Switch,
} from '@mui/material';
import {
  Edit as EditIcon,
  Science as TestIcon,
  FileUpload as ImportIcon,
  FileDownload as ExportIcon,
  Close as CloseIcon,
  Add as AddIcon,
} from '@mui/icons-material';
import useSWR from 'swr';
import { useNetcapRouter, useNetcapApi } from '../hooks';
import Layout from '../components/Layout';
import type { ServiceProbeInfo, TestProbeRequest, TestProbeResponse } from '../lib/api';
import type { api as apiType } from '../lib/api';
import { SyntaxHighlightedTextArea } from '../components/SyntaxHighlightedInput';

export default function ServiceProbes() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearchTerm, setDebouncedSearchTerm] = useState('');
  
  // Debounce search term to prevent re-fetching on every keystroke
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearchTerm(searchTerm);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm]);
  
  // Initialize search term from URL parameter
  useEffect(() => {
    if (router.isReady && router.query.search && typeof router.query.search === 'string') {
      setSearchTerm(router.query.search);
      setDebouncedSearchTerm(router.query.search);
      setPage(0);
    }
  }, [router.isReady, router.query.search]);

  // Handle create mode from URL parameter (e.g., /probes?create=true&banner=...)
  useEffect(() => {
    if (router.isReady && router.query.create === 'true') {
      // Open create modal
      setCreateModalOpen(true);
      // Pre-fill banner as test input if provided
      if (router.query.banner && typeof router.query.banner === 'string') {
        setCreateTestInput(router.query.banner);
      }
      // Clear URL parameters after handling
      router.replace?.('/probes');
    }
  }, [router.isReady, router.query.create, router.query.banner]);
  const [protocol, setProtocol] = useState('all');
  const [service, setService] = useState('all');
  const [matchType, setMatchType] = useState('all');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [selectedProbe, setSelectedProbe] = useState<ServiceProbeInfo | null>(null);
  const [editForm, setEditForm] = useState<Partial<ServiceProbeInfo>>({});
  const [snackbar, setSnackbar] = useState<{open: boolean; message: string; severity: 'success' | 'error'}>({
    open: false,
    message: '',
    severity: 'success',
  });
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  // Test within edit modal
  const [editTestInput, setEditTestInput] = useState('');
  const [editTestResult, setEditTestResult] = useState<TestProbeResponse | null>(null);
  const [editTestLoading, setEditTestLoading] = useState(false);
  
  // Create modal state
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createForm, setCreateForm] = useState<{
    service: string;
    pattern: string;
    product: string;
    version: string;
    info: string;
    hostname: string;
    os: string;
    deviceType: string;
    protocol: string;
    enabled: boolean;
  }>({
    service: '',
    pattern: '',
    product: '',
    version: '',
    info: '',
    hostname: '',
    os: '',
    deviceType: '',
    protocol: 'TCP',
    enabled: true,
  });
  const [createTestInput, setCreateTestInput] = useState('');
  const [createTestResult, setCreateTestResult] = useState<TestProbeResponse | null>(null);
  const [createTestLoading, setCreateTestLoading] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);

  // Fetch service probes with filters
  const { data: probesData, error: probesError, mutate } = useSWR(
    ['service-probes', debouncedSearchTerm, protocol, service, matchType, page, rowsPerPage],
    () => api.getServiceProbes({
      search: debouncedSearchTerm || undefined,
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
    // Reset test state for edit modal
    setEditTestInput('');
    setEditTestResult(null);
    setEditTestLoading(false);
    setEditModalOpen(true);
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


  // Test pattern within the edit modal using the current editForm.pattern
  const handleEditTest = async () => {
    if (!editForm.pattern || !editTestInput) return;
    
    setEditTestLoading(true);
    try {
      const request: TestProbeRequest = {
        pattern: editForm.pattern,
        sampleInput: editTestInput,
      };
      const result = await api.testServiceProbe(request);
      setEditTestResult(result);
    } catch (error) {
      setEditTestResult({
        matches: false,
        capturedGroups: {},
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    } finally {
      setEditTestLoading(false);
    }
  };

  const handleExport = () => {
    const url = api.exportServiceProbes();
    window.open(url, '_blank');
  };

  // Open create modal
  const handleOpenCreate = () => {
    setCreateForm({
      service: '',
      pattern: '',
      product: '',
      version: '',
      info: '',
      hostname: '',
      os: '',
      deviceType: '',
      protocol: 'TCP',
      enabled: true,
    });
    setCreateTestInput('');
    setCreateTestResult(null);
    setCreateTestLoading(false);
    setCreateModalOpen(true);
  };

  // Test pattern in create modal
  const handleCreateTest = async () => {
    if (!createForm.pattern || !createTestInput) return;
    
    setCreateTestLoading(true);
    try {
      const request: TestProbeRequest = {
        pattern: createForm.pattern,
        sampleInput: createTestInput,
      };
      const result = await api.testServiceProbe(request);
      setCreateTestResult(result);
    } catch (error) {
      setCreateTestResult({
        matches: false,
        capturedGroups: {},
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    } finally {
      setCreateTestLoading(false);
    }
  };

  // Save new probe
  const handleCreateProbe = async () => {
    if (!createForm.service || !createForm.pattern) {
      setSnackbar({
        open: true,
        message: 'Service name and pattern are required',
        severity: 'error',
      });
      return;
    }

    setCreateLoading(true);
    try {
      await api.createServiceProbe({
        service: createForm.service,
        pattern: createForm.pattern,
        product: createForm.product || undefined,
        version: createForm.version || undefined,
        info: createForm.info || undefined,
        hostname: createForm.hostname || undefined,
        os: createForm.os || undefined,
        deviceType: createForm.deviceType || undefined,
        protocol: createForm.protocol,
        enabled: createForm.enabled,
      });
      setSnackbar({
        open: true,
        message: 'Service probe created successfully',
        severity: 'success',
      });
      setCreateModalOpen(false);
      mutate(); // Refresh the list
    } catch (error) {
      setSnackbar({
        open: true,
        message: `Failed to create probe: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: 'error',
      });
    } finally {
      setCreateLoading(false);
    }
  };

  const handleToggleEnabled = async (probe: ServiceProbeInfo, enabled: boolean) => {
    try {
      await api.toggleServiceProbe(probe.id, enabled);
      setSnackbar({
        open: true,
        message: `Probe "${probe.service}" ${enabled ? 'enabled' : 'disabled'}`,
        severity: 'success',
      });
      mutate(); // Refresh the data
    } catch (error) {
      setSnackbar({
        open: true,
        message: `Failed to toggle probe: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: 'error',
      });
    }
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

  const handleChangePage = (_event: unknown, newPage: number) => {
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
            <Typography variant="body2" color="text.secondary" data-learn="Service Probes Info: Service probes use regex patterns to identify network services, protocols, and applications by matching their banners and responses. Based on nmap's service detection.">
              Manage {probesData.totalCount} nmap service fingerprinting probes for network service identification.
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="contained"
              color="primary"
              startIcon={<AddIcon />}
              onClick={handleOpenCreate}
              data-learn="Create Probe: Add a new service probe with a custom regex pattern to identify network services."
            >
              Create Probe
            </Button>
            <Button
              variant="outlined"
              startIcon={<ImportIcon />}
              onClick={() => setImportDialogOpen(true)}
              data-learn="Import Probes: Upload a nmap-service-probes file to replace the current service probe database. A backup is created automatically."
            >
              Import
            </Button>
            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              onClick={handleExport}
              data-learn="Export Probes: Download the current service probes database as a file for backup, sharing, or editing."
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
                  data-learn="Search Probes: Filter service probes by typing keywords from service names, products, regex patterns, or probe identifiers."
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
                    data-learn="Protocol Filter: Filter service probes by transport protocol (TCP or UDP)."
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
                    data-learn="Service Filter: Filter service probes by the specific service or protocol they detect (e.g., http, ssh, ftp, smtp)."
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
                    data-learn="Match Type Filter: Filter by probe match type. 'Match' patterns are strict matches for specific services, 'Softmatch' patterns are less specific fallback matches."
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
                <TableCell><strong>Enabled</strong></TableCell>
                <TableCell align="right"><strong>Actions</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {probesData.probes.length > 0 ? (
                probesData.probes.map((probe) => (
                  <TableRow 
                    key={probe.id} 
                    hover
                    sx={{ 
                      opacity: probe.enabled ? 1 : 0.5,
                      bgcolor: probe.enabled ? 'inherit' : 'action.disabledBackground',
                    }}
                  >
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
                    <TableCell>
                      <Switch
                        size="small"
                        checked={probe.enabled}
                        onChange={(e) => handleToggleEnabled(probe, e.target.checked)}
                        color="success"
                        data-learn="Enable/Disable: Toggle this probe on or off. Disabled probes are commented out in the file and won't be used for service detection."
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Edit probe">
                        <IconButton
                          size="small"
                          color="primary"
                          onClick={() => handleEditClick(probe)}
                          data-learn="Edit Probe: Modify this probe's properties including service name, product, regex pattern, version extraction, and metadata."
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={9} align="center">
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
                  data-learn="Service Name: The primary service or protocol name that this probe detects (e.g., http, ssh, smtp, mysql)."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Product"
                  value={editForm.product || ''}
                  onChange={(e) => setEditForm({ ...editForm, product: e.target.value })}
                  size="small"
                  data-learn="Product Name: The specific product or software implementation name (e.g., Apache httpd, OpenSSH, Microsoft Exchange). Can use capture groups like $1, $2."
                />
              </Grid>
              <Grid item xs={12}>
                <SyntaxHighlightedTextArea
                  syntaxType="regex"
                  value={editForm.pattern || ''}
                  onChange={(value) => setEditForm({ ...editForm, pattern: value })}
                  label="Pattern (Regex)"
                  placeholder="Enter regex pattern..."
                  helperText="Regular expression pattern to match service banner"
                  rows={3}
                  fullWidth
                  size="small"
                  data-learn="Pattern: Regular expression pattern to match against service banners and responses. Use capture groups () to extract version info, product names, etc."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Version"
                  value={editForm.version || ''}
                  onChange={(e) => setEditForm({ ...editForm, version: e.target.value })}
                  size="small"
                  data-learn="Version: Version string extraction pattern using capture groups from the regex (e.g., $1.$2 to combine groups into version number)."
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
                  data-learn="Rarity: Probe rarity score (1-9) where 1 is most common and 9 is rare. Affects the order in which probes are tried during service detection."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={editForm.enabled ?? true}
                      onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })}
                      color="success"
                    />
                  }
                  label="Enabled"
                  data-learn="Enabled: When disabled, this probe is commented out in the file and won't be used for service detection."
                />
              </Grid>

              {/* Test Pattern Section */}
              <Grid item xs={12}>
                <Box sx={{ 
                  mt: 2, 
                  pt: 2, 
                  borderTop: 1, 
                  borderColor: 'divider'
                }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <TestIcon fontSize="small" />
                    Test Pattern
                  </Typography>
                  <TextField
                    fullWidth
                    label="Sample Input"
                    value={editTestInput}
                    onChange={(e) => {
                      setEditTestInput(e.target.value);
                      // Clear previous result when input changes
                      if (editTestResult) setEditTestResult(null);
                    }}
                    size="small"
                    multiline
                    rows={3}
                    placeholder="Enter sample banner or service response to test against the pattern..."
                    helperText="Enter the text you want to test the regex pattern against"
                    sx={{ mb: 2 }}
                    data-learn="Sample Input: Paste a sample service banner or response text to test if the regex pattern matches correctly and extracts the expected data."
                  />
                  <Button
                    variant="outlined"
                    color="primary"
                    startIcon={editTestLoading ? <CircularProgress size={16} /> : <TestIcon />}
                    onClick={handleEditTest}
                    disabled={!editTestInput || !editForm.pattern || editTestLoading}
                    fullWidth
                    sx={{ mb: 2 }}
                    data-learn="Test Pattern: Execute the regex pattern against the sample input to verify if it matches and see what data is captured by groups."
                  >
                    {editTestLoading ? 'Testing...' : 'Test Pattern'}
                  </Button>
                  {editTestResult && (
                    <Box>
                      {editTestResult.error ? (
                        <Alert severity="error">
                          <Typography variant="body2">
                            <strong>Error:</strong> {editTestResult.error}
                          </Typography>
                        </Alert>
                      ) : editTestResult.matches ? (
                        <Alert severity="success">
                          <Typography variant="body2" gutterBottom>
                            <strong>Match Found!</strong>
                          </Typography>
                          {Object.keys(editTestResult.capturedGroups).length > 0 && (
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
                                maxHeight: 150,
                              }}>
                                {JSON.stringify(editTestResult.capturedGroups, null, 2)}
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
                    </Box>
                  )}
                </Box>
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setEditModalOpen(false)}>Cancel</Button>
            <Button onClick={handleSaveEdit} variant="contained" color="primary" data-learn="Save Changes: Update the service probe with the modified configuration. Changes take effect immediately for new captures.">
              Save Changes
            </Button>
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
                data-learn="Choose File: Select an nmap-service-probes file from your computer to import into the database."
              >
                Choose File
                <input
                  type="file"
                  hidden
                  accept="*/*"
                  onChange={(e) => {
                    if (e.target.files?.[0]) {
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
              data-learn="Import: Upload and process the selected nmap-service-probes file, replacing the current database. A backup is created first."
            >
              {importing ? <CircularProgress size={24} /> : 'Import'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Create Probe Modal */}
        <Dialog
          open={createModalOpen}
          onClose={() => setCreateModalOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="h6">Create New Service Probe</Typography>
              <IconButton onClick={() => setCreateModalOpen(false)} size="small">
                <CloseIcon />
              </IconButton>
            </Box>
          </DialogTitle>
          <DialogContent dividers>
            <Grid container spacing={2} sx={{ mt: 0.5 }}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Service Name"
                  value={createForm.service}
                  onChange={(e) => setCreateForm({ ...createForm, service: e.target.value })}
                  size="small"
                  required
                  placeholder="e.g., http, ssh, mysql"
                  helperText="The service/protocol name this probe identifies"
                  data-learn="Service Name: The primary service or protocol name that this probe detects (e.g., http, ssh, smtp, mysql)."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth size="small">
                  <InputLabel>Protocol</InputLabel>
                  <Select
                    value={createForm.protocol}
                    label="Protocol"
                    onChange={(e) => setCreateForm({ ...createForm, protocol: e.target.value })}
                  >
                    <MenuItem value="TCP">TCP</MenuItem>
                    <MenuItem value="UDP">UDP</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12}>
                <SyntaxHighlightedTextArea
                  syntaxType="regex"
                  value={createForm.pattern}
                  onChange={(value) => setCreateForm({ ...createForm, pattern: value })}
                  label="Pattern (Regex)"
                  placeholder="Enter regex pattern to match service banner..."
                  helperText="Regular expression pattern to match service banner. Use capture groups () to extract version info."
                  rows={3}
                  fullWidth
                  size="small"
                  data-learn="Pattern: Regular expression pattern to match against service banners and responses. Use capture groups () to extract version info, product names, etc."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Product"
                  value={createForm.product}
                  onChange={(e) => setCreateForm({ ...createForm, product: e.target.value })}
                  size="small"
                  placeholder="e.g., Apache httpd, OpenSSH"
                  helperText="Can use $1, $2 to reference capture groups"
                  data-learn="Product Name: The specific product or software implementation name (e.g., Apache httpd, OpenSSH). Can use capture groups like $1, $2."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Version"
                  value={createForm.version}
                  onChange={(e) => setCreateForm({ ...createForm, version: e.target.value })}
                  size="small"
                  placeholder="e.g., $1.$2"
                  helperText="Use capture groups like $1.$2"
                  data-learn="Version: Version string extraction pattern using capture groups from the regex (e.g., $1.$2 to combine groups into version number)."
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Info"
                  value={createForm.info}
                  onChange={(e) => setCreateForm({ ...createForm, info: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="OS"
                  value={createForm.os}
                  onChange={(e) => setCreateForm({ ...createForm, os: e.target.value })}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={createForm.enabled}
                      onChange={(e) => setCreateForm({ ...createForm, enabled: e.target.checked })}
                      color="success"
                    />
                  }
                  label="Enabled"
                />
              </Grid>

              {/* Test Pattern Section */}
              <Grid item xs={12}>
                <Box sx={{ 
                  mt: 2, 
                  pt: 2, 
                  borderTop: 1, 
                  borderColor: 'divider'
                }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <TestIcon fontSize="small" />
                    Test Pattern
                  </Typography>
                  <TextField
                    fullWidth
                    label="Sample Input (Banner)"
                    value={createTestInput}
                    onChange={(e) => {
                      setCreateTestInput(e.target.value);
                      if (createTestResult) setCreateTestResult(null);
                    }}
                    size="small"
                    multiline
                    rows={4}
                    placeholder="Enter or paste a service banner to test..."
                    helperText="Paste a service banner/response to test your regex pattern"
                    sx={{ mb: 2 }}
                    data-learn="Sample Input: Paste a sample service banner or response text to test if the regex pattern matches correctly and extracts the expected data."
                  />
                  <Button
                    variant="outlined"
                    color="primary"
                    startIcon={createTestLoading ? <CircularProgress size={16} /> : <TestIcon />}
                    onClick={handleCreateTest}
                    disabled={!createTestInput || !createForm.pattern || createTestLoading}
                    fullWidth
                    sx={{ mb: 2 }}
                  >
                    {createTestLoading ? 'Testing...' : 'Test Pattern'}
                  </Button>
                  {createTestResult && (
                    <Box>
                      {createTestResult.error ? (
                        <Alert severity="error">
                          <Typography variant="body2">
                            <strong>Error:</strong> {createTestResult.error}
                          </Typography>
                        </Alert>
                      ) : createTestResult.matches ? (
                        <Alert severity="success">
                          <Typography variant="body2" gutterBottom>
                            <strong>Match Found!</strong>
                          </Typography>
                          {Object.keys(createTestResult.capturedGroups).length > 0 && (
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
                                maxHeight: 150,
                              }}>
                                {JSON.stringify(createTestResult.capturedGroups, null, 2)}
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
                    </Box>
                  )}
                </Box>
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setCreateModalOpen(false)}>Cancel</Button>
            <Button 
              onClick={handleCreateProbe} 
              variant="contained" 
              color="primary"
              disabled={!createForm.service || !createForm.pattern || createLoading}
            >
              {createLoading ? <CircularProgress size={24} /> : 'Create Probe'}
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

