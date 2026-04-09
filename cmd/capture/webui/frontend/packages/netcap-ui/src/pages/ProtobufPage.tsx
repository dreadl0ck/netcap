/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useState, useRef } from 'react';
import useSWR from 'swr';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import TextField from '@mui/material/TextField';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Collapse from '@mui/material/Collapse';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import RefreshIcon from '@mui/icons-material/Refresh';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CloseIcon from '@mui/icons-material/Close';
import { useNetcapApi } from '../hooks/useNetcapApi';
import { useIsMobile } from '../hooks/useIsMobile';
import Layout from '../components/Layout';
import type { ProtoMessageInfo } from '../lib/api';

export default function ProtobufPage() {
  const api = useNetcapApi();
  const isMobile = useIsMobile();

  // Data fetching
  const { data: status, mutate: mutateStatus } = useSWR('proto-status', () => api.getProtoStatus(), { refreshInterval: 10000 });
  const { data: messagesData, mutate: mutateMessages } = useSWR('proto-messages', () => api.getProtoMessages());

  // UI state
  const [addPathOpen, setAddPathOpen] = useState(false);
  const [newPath, setNewPath] = useState('');
  const [addMappingOpen, setAddMappingOpen] = useState(false);
  const [mappingPort, setMappingPort] = useState('');
  const [mappingType, setMappingType] = useState('');
  const [editingMapping, setEditingMapping] = useState<{ port: number; messageType: string } | null>(null);
  const [uploadFiles, setUploadFiles] = useState<File[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedMessages, setExpandedMessages] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const showSuccess = (msg: string) => {
    setSuccess(msg);
    setError(null);
    setTimeout(() => setSuccess(null), 3000);
  };

  const showError = (msg: string) => {
    setError(msg);
    setSuccess(null);
  };

  const refreshAll = () => {
    mutateStatus();
    mutateMessages();
  };

  // --- Handlers ---

  const handleAddPath = async () => {
    if (!newPath.trim()) return;
    setSaving(true);
    try {
      await api.addProtoSearchPath(newPath.trim());
      showSuccess(`Added search path: ${newPath}`);
      setNewPath('');
      setAddPathOpen(false);
      refreshAll();
    } catch (e: any) {
      showError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleRemovePath = async (path: string) => {
    setSaving(true);
    try {
      await api.removeProtoSearchPath(path);
      showSuccess(`Removed search path: ${path}`);
      refreshAll();
    } catch (e: any) {
      showError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleUpload = async () => {
    if (uploadFiles.length === 0) return;
    setSaving(true);
    try {
      const result = await api.uploadProtoFiles(uploadFiles);
      showSuccess(result.message || `Uploaded ${uploadFiles.length} file(s)`);
      setUploadFiles([]);
      refreshAll();
    } catch (e: any) {
      showError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleAddMapping = async () => {
    const port = parseInt(mappingPort, 10);
    if (!port || !mappingType.trim()) return;
    setSaving(true);
    try {
      await api.addProtoMapping(port, mappingType.trim());
      showSuccess(`Mapping added: port ${port} -> ${mappingType}`);
      setMappingPort('');
      setMappingType('');
      setAddMappingOpen(false);
      setEditingMapping(null);
      refreshAll();
    } catch (e: any) {
      showError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveMapping = async (port: number) => {
    setSaving(true);
    try {
      await api.removeProtoMapping(port);
      showSuccess(`Removed mapping for port ${port}`);
      refreshAll();
    } catch (e: any) {
      showError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleToggleAlternatives = async (current: boolean) => {
    setSaving(true);
    try {
      await api.setProtoPreferences({ showAlternatives: !current });
      showSuccess(`Show alternatives: ${!current}`);
      mutateStatus();
    } catch (e: any) {
      showError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleRecompile = async () => {
    setSaving(true);
    try {
      await api.recompileProtos();
      showSuccess('Recompilation complete');
      refreshAll();
    } catch (e: any) {
      showError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const toggleMessage = (fullName: string) => {
    setExpandedMessages(prev => {
      const next = new Set(prev);
      if (next.has(fullName)) next.delete(fullName);
      else next.add(fullName);
      return next;
    });
  };

  // Group messages by package
  const messages = messagesData?.messages || [];
  const filteredMessages = searchTerm
    ? messages.filter(m => m.fullName.toLowerCase().includes(searchTerm.toLowerCase()))
    : messages;

  const packageGroups = new Map<string, ProtoMessageInfo[]>();
  for (const msg of filteredMessages) {
    const pkg = msg.package || '(default)';
    if (!packageGroups.has(pkg)) packageGroups.set(pkg, []);
    packageGroups.get(pkg)!.push(msg);
  }

  const getTypeColor = (type: string): 'primary' | 'secondary' | 'info' | 'warning' | 'success' | 'default' => {
    switch (type) {
      case 'string': return 'info';
      case 'int32': case 'int64': case 'uint32': case 'uint64': case 'sint32': case 'sint64': return 'secondary';
      case 'bool': return 'primary';
      case 'enum': return 'warning';
      case 'message': case 'group': return 'success';
      case 'bytes': return 'default';
      case 'float': case 'double': return 'secondary';
      default: return 'default';
    }
  };

  return (
    <Layout title="Protobuf Schemas">
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {/* Feedback alerts */}
        {success && <Alert severity="success" onClose={() => setSuccess(null)}>{success}</Alert>}
        {error && <Alert severity="error" onClose={() => setError(null)}>{error}</Alert>}

        {/* Status Banner */}
        {status && (
          <Alert
            severity={status.errors.length > 0 ? 'error' : status.loaded ? 'success' : 'info'}
            action={
              <Button color="inherit" size="small" startIcon={<RefreshIcon />} onClick={handleRecompile} disabled={saving}>
                Recompile
              </Button>
            }
          >
            {status.loaded
              ? `${status.fileCount} proto file(s) loaded, ${status.messageCount} message type(s) indexed`
              : 'No protobuf schemas loaded. Add search paths or upload .proto files to enable schema-aware decoding.'}
            {status.errors.length > 0 && (
              <Box component="pre" sx={{ mt: 1, fontSize: '0.8rem', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                {status.errors.join('\n')}
              </Box>
            )}
          </Alert>
        )}

        {/* Search Paths */}
        <Accordion defaultExpanded>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontSize: '1rem' }}>
              Search Paths
              {status && status.searchPaths.length > 0 && (
                <Chip label={status.searchPaths.length} size="small" sx={{ ml: 1 }} />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Box sx={{ mb: 1 }}>
              <Button startIcon={<AddIcon />} variant="outlined" size="small" onClick={() => setAddPathOpen(true)}>
                Add Path
              </Button>
            </Box>
            {status && status.searchPaths.length > 0 ? (
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 'bold' }}>Directory Path</TableCell>
                      <TableCell width={60} />
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {status.searchPaths.map((path) => (
                      <TableRow key={path} hover>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{path}</TableCell>
                        <TableCell>
                          <IconButton size="small" onClick={() => handleRemovePath(path)} disabled={saving}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Typography variant="body2" color="text.secondary">No search paths configured.</Typography>
            )}
          </AccordionDetails>
        </Accordion>

        {/* Upload */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontSize: '1rem' }}>Upload .proto Files</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: uploadFiles.length > 0 ? 1 : 0 }}>
              <input
                ref={fileInputRef}
                type="file"
                accept=".proto"
                multiple
                style={{ display: 'none' }}
                onChange={(e) => {
                  const files = Array.from(e.target.files || []);
                  setUploadFiles(prev => [...prev, ...files]);
                  e.target.value = '';
                }}
              />
              <Button startIcon={<UploadFileIcon />} variant="outlined" size="small" onClick={() => fileInputRef.current?.click()}>
                Choose Files
              </Button>
              {uploadFiles.length > 0 && (
                <Button variant="contained" size="small" onClick={handleUpload} disabled={saving}>
                  {saving ? <CircularProgress size={16} sx={{ mr: 1 }} /> : null}
                  Upload & Compile ({uploadFiles.length})
                </Button>
              )}
            </Box>
            {uploadFiles.length > 0 && (
              <List dense>
                {uploadFiles.map((file, idx) => (
                  <ListItem key={`${file.name}-${idx}`}>
                    <ListItemText primary={file.name} secondary={`${(file.size / 1024).toFixed(1)} KB`} />
                    <ListItemSecondaryAction>
                      <IconButton edge="end" size="small" onClick={() => setUploadFiles(prev => prev.filter((_, i) => i !== idx))}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            )}
          </AccordionDetails>
        </Accordion>

        {/* Preferences */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontSize: '1rem' }}>Preferences</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <FormControlLabel
              control={
                <Switch
                  checked={status?.showAlternatives ?? false}
                  onChange={() => handleToggleAlternatives(status?.showAlternatives ?? false)}
                  disabled={saving}
                />
              }
              label="Show field alternatives (display multiple type interpretations for unknown fields)"
            />
          </AccordionDetails>
        </Accordion>

        {/* Port-to-Message Mappings */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontSize: '1rem' }}>
              Port-to-Message Mappings
              {status && status.portMappings.length > 0 && (
                <Chip label={status.portMappings.length} size="small" sx={{ ml: 1 }} />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Box sx={{ mb: 1 }}>
              <Button startIcon={<AddIcon />} variant="outlined" size="small" onClick={() => {
                setEditingMapping(null);
                setMappingPort('');
                setMappingType('');
                setAddMappingOpen(true);
              }}>
                Add Mapping
              </Button>
            </Box>
            {status && status.portMappings.length > 0 ? (
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 'bold' }}>Port</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Message Type</TableCell>
                      <TableCell width={90} />
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {status.portMappings.map((m) => (
                      <TableRow key={m.port} hover>
                        <TableCell>{m.port}</TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{m.messageType}</TableCell>
                        <TableCell>
                          <IconButton size="small" onClick={() => {
                            setEditingMapping(m);
                            setMappingPort(String(m.port));
                            setMappingType(m.messageType);
                            setAddMappingOpen(true);
                          }}>
                            <EditIcon fontSize="small" />
                          </IconButton>
                          <IconButton size="small" onClick={() => handleRemoveMapping(m.port)} disabled={saving}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Typography variant="body2" color="text.secondary">
                No port mappings configured. Mappings tell the decoder which message type to expect on a given port.
              </Typography>
            )}
          </AccordionDetails>
        </Accordion>

        {/* Message Type Browser */}
        <Accordion defaultExpanded={messages.length > 0}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" sx={{ fontSize: '1rem' }}>
              Loaded Message Types
              {messages.length > 0 && <Chip label={messages.length} size="small" sx={{ ml: 1 }} />}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {messages.length > 0 && (
              <TextField
                fullWidth
                size="small"
                placeholder="Search message types..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                sx={{ mb: 2 }}
              />
            )}
            {filteredMessages.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {messages.length === 0
                  ? 'No message types loaded. Add search paths or upload .proto files.'
                  : 'No messages match your search.'}
              </Typography>
            ) : (
              Array.from(packageGroups.entries()).sort(([a], [b]) => a.localeCompare(b)).map(([pkg, msgs]) => (
                <Accordion key={pkg} variant="outlined" sx={{ '&:before': { display: 'none' } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography sx={{ fontFamily: 'monospace', fontWeight: 'bold', fontSize: '0.9rem' }}>
                      {pkg}
                    </Typography>
                    <Chip label={msgs.length} size="small" sx={{ ml: 1 }} />
                  </AccordionSummary>
                  <AccordionDetails sx={{ p: 0 }}>
                    <List dense disablePadding>
                      {msgs.sort((a, b) => a.name.localeCompare(b.name)).map((msg) => (
                        <Box key={msg.fullName}>
                          <ListItem
                            component="div"
                            onClick={() => toggleMessage(msg.fullName)}
                            sx={{ cursor: 'pointer', '&:hover': { backgroundColor: 'action.hover' } }}
                          >
                            <ListItemText
                              primary={
                                <Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                                  {msg.name}
                                </Typography>
                              }
                              secondary={`${msg.fields.length} fields - ${msg.protoFile}`}
                            />
                            {expandedMessages.has(msg.fullName) ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                          </ListItem>
                          <Collapse in={expandedMessages.has(msg.fullName)} timeout="auto" unmountOnExit>
                            <TableContainer sx={{ pl: 2, pr: 2, pb: 1 }}>
                              <Table size="small">
                                <TableHead>
                                  <TableRow>
                                    <TableCell sx={{ fontWeight: 'bold' }}>#</TableCell>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Name</TableCell>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Type</TableCell>
                                    <TableCell sx={{ fontWeight: 'bold' }}>Label</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {msg.fields.map((f) => (
                                    <TableRow key={f.number}>
                                      <TableCell>{f.number}</TableCell>
                                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{f.name}</TableCell>
                                      <TableCell>
                                        <Chip
                                          label={f.typeName || f.type}
                                          size="small"
                                          color={getTypeColor(f.type)}
                                          variant="outlined"
                                        />
                                        {f.enumValues && f.enumValues.length > 0 && (
                                          <Box sx={{ mt: 0.5 }}>
                                            {f.enumValues.map((ev) => (
                                              <Chip
                                                key={ev.number}
                                                label={`${ev.name}=${ev.number}`}
                                                size="small"
                                                variant="outlined"
                                                sx={{ mr: 0.5, mb: 0.5, fontSize: '0.7rem' }}
                                              />
                                            ))}
                                          </Box>
                                        )}
                                      </TableCell>
                                      <TableCell>
                                        {f.label && <Chip label={f.label} size="small" variant="outlined" />}
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            </TableContainer>
                          </Collapse>
                        </Box>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              ))
            )}
          </AccordionDetails>
        </Accordion>

        {/* Add Path Dialog */}
        <Dialog open={addPathOpen} onClose={() => setAddPathOpen(false)} maxWidth="sm" fullWidth fullScreen={isMobile}>
          <DialogTitle>
            Add Search Path
            {isMobile && (
              <IconButton onClick={() => setAddPathOpen(false)} sx={{ position: 'absolute', right: 8, top: 8 }}>
                <CloseIcon />
              </IconButton>
            )}
          </DialogTitle>
          <DialogContent>
            <TextField
              autoFocus
              fullWidth
              label="Directory path"
              placeholder="/path/to/proto/files"
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              sx={{ mt: 1 }}
              helperText="Path to a directory containing .proto files, or a single .proto file"
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setAddPathOpen(false)}>Cancel</Button>
            <Button onClick={handleAddPath} variant="contained" disabled={!newPath.trim() || saving}>
              {saving ? <CircularProgress size={16} sx={{ mr: 1 }} /> : null}
              Add
            </Button>
          </DialogActions>
        </Dialog>

        {/* Add/Edit Mapping Dialog */}
        <Dialog open={addMappingOpen} onClose={() => setAddMappingOpen(false)} maxWidth="sm" fullWidth fullScreen={isMobile}>
          <DialogTitle>
            {editingMapping ? 'Edit Mapping' : 'Add Port Mapping'}
            {isMobile && (
              <IconButton onClick={() => setAddMappingOpen(false)} sx={{ position: 'absolute', right: 8, top: 8 }}>
                <CloseIcon />
              </IconButton>
            )}
          </DialogTitle>
          <DialogContent>
            <TextField
              autoFocus
              fullWidth
              type="number"
              label="Port"
              value={mappingPort}
              onChange={(e) => setMappingPort(e.target.value)}
              inputProps={{ min: 1, max: 65535 }}
              sx={{ mt: 1, mb: 2 }}
            />
            <TextField
              fullWidth
              label="Message Type"
              placeholder="package.MessageName"
              value={mappingType}
              onChange={(e) => setMappingType(e.target.value)}
              helperText="Fully qualified protobuf message name (e.g., tutorial.AddressBook)"
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setAddMappingOpen(false)}>Cancel</Button>
            <Button
              onClick={handleAddMapping}
              variant="contained"
              disabled={!mappingPort || !mappingType.trim() || saving}
            >
              {saving ? <CircularProgress size={16} sx={{ mr: 1 }} /> : null}
              Save
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Layout>
  );
}
