/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useState, useRef } from 'react';

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
import { translate as i18nText, renderText as i18nRenderText, richText as i18nRichText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { formatNumber } from "../lib/i18n";
import { fieldLabel } from "../lib/i18n";
import { rawCode } from "../lib/i18n";
import { message, metadataMessage, errorText } from "../lib/i18n";
import { message as i18nMessage } from "../lib/i18n";







export default function ProtobufPage() {
  const __uiLocale = useUILocale();
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
  const [error, setError] = useState<UIMessageText | null>(null);
  const [success, setSuccess] = useState<UIMessageText | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const showSuccess = (msg: UIMessageText) => {
    setSuccess(msg);
    setError(null);
    setTimeout(() => setSuccess(null), 3000);
  };

  const showError = (msg: UIMessageText) => {
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
      showSuccess(i18nMessage("ui:m_6a288835b6b3ddc0301b", { arg0: newPath }));
      setNewPath('');
      setAddPathOpen(false);
      refreshAll();
    } catch (e: any) {
      showError(errorText(e));
    } finally {
      setSaving(false);
    }
  };

  const handleRemovePath = async (path: string) => {
    setSaving(true);
    try {
      await api.removeProtoSearchPath(path);
      showSuccess(i18nMessage("ui:m_fd688d86fc3d888244b8", { arg0: path }));
      refreshAll();
    } catch (e: any) {
      showError(errorText(e));
    } finally {
      setSaving(false);
    }
  };

  const handleUpload = async () => {
    if (uploadFiles.length === 0) return;
    setSaving(true);
    try {
      const result = await api.uploadProtoFiles(uploadFiles);
      showSuccess(result.message ? metadataMessage(result, 'message') : message('ui:protobuf.uploaded', { count: uploadFiles.length }));
      setUploadFiles([]);
      refreshAll();
    } catch (e: any) {
      showError(errorText(e));
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
      showSuccess(i18nMessage("ui:m_39024b24e96ff7a05fce", { arg0: String(port), arg1: mappingType }));
      setMappingPort('');
      setMappingType('');
      setAddMappingOpen(false);
      setEditingMapping(null);
      refreshAll();
    } catch (e: any) {
      showError(errorText(e));
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveMapping = async (port: number) => {
    setSaving(true);
    try {
      await api.removeProtoMapping(port);
      showSuccess(i18nMessage("ui:m_cec163b8bb05565fce57", { arg0: String(port) }));
      refreshAll();
    } catch (e: any) {
      showError(errorText(e));
    } finally {
      setSaving(false);
    }
  };

  const handleToggleAlternatives = async (current: boolean) => {
    setSaving(true);
    try {
      await api.setProtoPreferences({ showAlternatives: !current });
      showSuccess(message('ui:protobuf.alternatives', { enabled: String(!current) }));
      mutateStatus();
    } catch (e: any) {
      showError(errorText(e));
    } finally {
      setSaving(false);
    }
  };

  const handleRecompile = async () => {
    setSaving(true);
    try {
      await api.recompileProtos();
      showSuccess(i18nMessage("ui:m_121baa07481966a162cb"));
      refreshAll();
    } catch (e: any) {
      showError(errorText(e));
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
    const pkg = msg.package || '';
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
    <Layout title={i18nText("ui:m_da874ae5c84c3206a7c3")}><Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>{/* Feedback alerts */}{i18nRenderText(success) && <Alert severity="success" onClose={() => setSuccess(null)}>{i18nRenderText(success)}</Alert>}{i18nRenderText(error) && <Alert severity="error" onClose={() => setError(null)}>{i18nRenderText(error)}</Alert>}{/* Status Banner */}{status && (
          <Alert severity={status.errors.length > 0 ? 'error' : status.loaded ? 'success' : 'info'}
            action={<Button color="inherit" size="small" startIcon={<RefreshIcon />} onClick={handleRecompile} disabled={saving}>
                {i18nText("ui:m_17bedefbd26d989b6753")}
              </Button>}>{status.loaded ? i18nText("ui:m_49df38594597586f51b7", { arg0: status.fileCount, arg1: status.messageCount }) : i18nText("ui:m_f7eef9bbb8b56f500629")}{status.errors.length > 0 && (
              <Box component="pre" sx={{ mt: 1, fontSize: '0.8rem', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>{status.errors.join('\n')}</Box>
            )}</Alert>
        )}{/* Search Paths */}<Accordion defaultExpanded><AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography variant="h6" sx={{ fontSize: '1rem' }}>
              {i18nRichText("ui:m_137131a57b4a9e329049", { arg0: status && status.searchPaths.length > 0 && (
                <Chip label={status.searchPaths.length} size="small" sx={{ ml: 1 }} />
              ) })}
            </Typography></AccordionSummary><AccordionDetails><Box sx={{ mb: 1 }}><Button startIcon={<AddIcon />} variant="outlined" size="small" onClick={() => setAddPathOpen(true)}>
                {i18nText("ui:m_90d1db578ee6c27dafe0")}
              </Button></Box>{status && status.searchPaths.length > 0 ? (
              <TableContainer component={Paper} variant="outlined"><Table size="small"><TableHead><TableRow><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_de85d2885acf5b4aa1e5")}</TableCell><TableCell width={60} /></TableRow></TableHead><TableBody>{status.searchPaths.map((path) => (
                      <TableRow key={path} hover><TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{path}</TableCell><TableCell><IconButton size="small" onClick={() => handleRemovePath(path)} disabled={saving}><DeleteIcon fontSize="small" /></IconButton></TableCell></TableRow>
                    ))}</TableBody></Table></TableContainer>
            ) : (
              <Typography variant="body2" color="text.secondary">{i18nText("ui:m_27bd45eae51e6cfcc724")}</Typography>
            )}</AccordionDetails></Accordion>{/* Upload */}<Accordion><AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography variant="h6" sx={{ fontSize: '1rem' }}>{i18nText("ui:m_35fa14ae00724c37767a")}</Typography></AccordionSummary><AccordionDetails><Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: uploadFiles.length > 0 ? 1 : 0 }}><input ref={fileInputRef}
                type="file"
                accept=".proto"
                multiple
                style={{ display: 'none' }}
                onChange={(e) => {
                  const files = Array.from(e.target.files || []);
                  setUploadFiles(prev => [...prev, ...files]);
                  e.target.value = '';
                }} /><Button startIcon={<UploadFileIcon />} variant="outlined" size="small" onClick={() => fileInputRef.current?.click()}>
                {i18nText("ui:m_94a5eb09500bf3633776")}
              </Button>{uploadFiles.length > 0 && (
                <Button variant="contained" size="small" onClick={handleUpload} disabled={saving}>
                  {i18nRichText("ui:m_c69674af692a09483287", { arg0: saving ? <CircularProgress size={16} sx={{ mr: 1 }} /> : null, arg1: uploadFiles.length })}
                </Button>
              )}</Box>{uploadFiles.length > 0 && (
              <List dense>{uploadFiles.map((file, idx) => (
                  <ListItem key={`${file.name}-${idx}`}><ListItemText primary={file.name} secondary={`${formatNumber((file.size / 1024), { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: false })} KB`} /><ListItemSecondaryAction><IconButton edge="end" size="small" onClick={() => setUploadFiles(prev => prev.filter((_, i) => i !== idx))}><DeleteIcon fontSize="small" /></IconButton></ListItemSecondaryAction></ListItem>
                ))}</List>
            )}</AccordionDetails></Accordion>{/* Preferences */}<Accordion><AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography variant="h6" sx={{ fontSize: '1rem' }}>{i18nText("ui:m_d376214d66d28123e9cd")}</Typography></AccordionSummary><AccordionDetails><FormControlLabel control={<Switch checked={status?.showAlternatives ?? false}
                  onChange={() => handleToggleAlternatives(status?.showAlternatives ?? false)}
                  disabled={saving} />}
              label={i18nText("ui:m_a16c9e2e7e5c196016ee")} /></AccordionDetails></Accordion>{/* Port-to-Message Mappings */}<Accordion><AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography variant="h6" sx={{ fontSize: '1rem' }}>
              {i18nRichText("ui:m_ee99e4a693dd93f72352", { arg0: status && status.portMappings.length > 0 && (
                <Chip label={status.portMappings.length} size="small" sx={{ ml: 1 }} />
              ) })}
            </Typography></AccordionSummary><AccordionDetails><Box sx={{ mb: 1 }}><Button startIcon={<AddIcon />} variant="outlined" size="small" onClick={() => {
                setEditingMapping(null);
                setMappingPort('');
                setMappingType('');
                setAddMappingOpen(true);
              }}>
                {i18nText("ui:m_f0aabfbb8682a5ddd8c2")}
              </Button></Box>{status && status.portMappings.length > 0 ? (
              <TableContainer component={Paper} variant="outlined"><Table size="small"><TableHead><TableRow><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_e3ee61fa78ee06ea77cc")}</TableCell><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_b3541c04af4289ac6c7c")}</TableCell><TableCell width={90} /></TableRow></TableHead><TableBody>{status.portMappings.map((m) => (
                      <TableRow key={m.port} hover><TableCell>{m.port}</TableCell><TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{m.messageType}</TableCell><TableCell><IconButton size="small" onClick={() => {
                            setEditingMapping(m);
                            setMappingPort(String(m.port));
                            setMappingType(m.messageType);
                            setAddMappingOpen(true);
                          }}><EditIcon fontSize="small" /></IconButton><IconButton size="small" onClick={() => handleRemoveMapping(m.port)} disabled={saving}><DeleteIcon fontSize="small" /></IconButton></TableCell></TableRow>
                    ))}</TableBody></Table></TableContainer>
            ) : (
              <Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_7396cf3f7d8b167b9a63")}
              </Typography>
            )}</AccordionDetails></Accordion>{/* Message Type Browser */}<Accordion defaultExpanded={messages.length > 0}><AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography variant="h6" sx={{ fontSize: '1rem' }}>
              {i18nRichText("ui:m_66c55288588caf9ef80e", { arg0: messages.length > 0 && <Chip label={messages.length} size="small" sx={{ ml: 1 }} /> })}
            </Typography></AccordionSummary><AccordionDetails>{messages.length > 0 && (
              <TextField fullWidth
                size="small"
                placeholder={i18nText("ui:m_5420fa5d7069c8218d7a")}
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                sx={{ mb: 2 }} />
            )}{filteredMessages.length === 0 ? (
              <Typography variant="body2" color="text.secondary">{messages.length === 0 ? i18nText("ui:m_ed82c3ab88b21b0ae55a") : i18nText("ui:m_3cd7bf98446e726f2a1b")}</Typography>
            ) : (
              Array.from(packageGroups.entries()).sort(([a], [b]) => a.localeCompare(b)).map(([pkg, msgs]) => (
                <Accordion key={pkg} variant="outlined" sx={{ '&:before': { display: 'none' } }}><AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography sx={{ fontFamily: 'monospace', fontWeight: 'bold', fontSize: '0.9rem' }}>{pkg || i18nText('ui:protobuf.defaultPackage')}</Typography><Chip label={msgs.length} size="small" sx={{ ml: 1 }} /></AccordionSummary><AccordionDetails sx={{ p: 0 }}><List dense disablePadding>{msgs.sort((a, b) => a.name.localeCompare(b.name)).map((msg) => (
                        <Box key={msg.fullName}><ListItem component="div"
                            onClick={() => toggleMessage(msg.fullName)}
                            sx={{ cursor: 'pointer', '&:hover': { backgroundColor: 'action.hover' } }}><ListItemText primary={<Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{msg.name}</Typography>}
                              secondary={i18nText("ui:m_8333031449e52edbebe6", { arg0: msg.fields.length, arg1: msg.protoFile })} />{expandedMessages.has(msg.fullName) ? <ExpandLessIcon /> : <ExpandMoreIcon />}</ListItem><Collapse in={expandedMessages.has(msg.fullName)} timeout="auto" unmountOnExit><TableContainer sx={{ pl: 2, pr: 2, pb: 1 }}><Table size="small"><TableHead><TableRow><TableCell sx={{ fontWeight: 'bold' }}>#</TableCell><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_e707e3dfaa88e6753600")}</TableCell><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_3da346bd3b7d84ce65d6")}</TableCell><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_a2eafa5f1d6707660144")}</TableCell></TableRow></TableHead><TableBody>{msg.fields.map((f) => (
                                    <TableRow key={f.number}><TableCell>{f.number}</TableCell><TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{f.name}</TableCell><TableCell><Chip label={f.typeName || f.type}
                                          size="small"
                                          color={getTypeColor(f.type)}
                                          variant="outlined" />{f.enumValues && f.enumValues.length > 0 && (
                                          <Box sx={{ mt: 0.5 }}>{f.enumValues.map((ev) => (
                                              <Chip key={ev.number}
                                                label={`${ev.name}=${ev.number}`}
                                                size="small"
                                                variant="outlined"
                                                sx={{ mr: 0.5, mb: 0.5, fontSize: '0.7rem' }} />
                                            ))}</Box>
                                        )}</TableCell><TableCell>{f.label && <Chip label={f.label} size="small" variant="outlined" />}</TableCell></TableRow>
                                  ))}</TableBody></Table></TableContainer></Collapse></Box>
                      ))}</List></AccordionDetails></Accordion>
              ))
            )}</AccordionDetails></Accordion>{/* Add Path Dialog */}<Dialog open={addPathOpen} onClose={() => setAddPathOpen(false)} maxWidth="sm" fullWidth fullScreen={isMobile}><DialogTitle>
            {i18nRichText("ui:m_b45b5c38213e372c9e99", { arg0: isMobile && (
              <IconButton onClick={() => setAddPathOpen(false)} sx={{ position: 'absolute', right: 8, top: 8 }}><CloseIcon /></IconButton>
            ) })}
          </DialogTitle><DialogContent><TextField autoFocus
              fullWidth
              label={i18nText("ui:m_3a1dad38d0c79766a79e")}
              placeholder={rawCode("/path/to/proto/files")}
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              sx={{ mt: 1 }}
              helperText={i18nText("ui:m_48da6473b94fc5bf32e8")} /></DialogContent><DialogActions><Button onClick={() => setAddPathOpen(false)}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button onClick={handleAddPath} variant="contained" disabled={!newPath.trim() || saving}>
              {i18nRichText("ui:m_5125e8e165707f905f13", { arg0: saving ? <CircularProgress size={16} sx={{ mr: 1 }} /> : null })}
            </Button></DialogActions></Dialog>{/* Add/Edit Mapping Dialog */}<Dialog open={addMappingOpen} onClose={() => setAddMappingOpen(false)} maxWidth="sm" fullWidth fullScreen={isMobile}><DialogTitle>{editingMapping ? i18nText("ui:m_c69056147954a302edd1") : i18nText("ui:m_6263bbf975bcd8948465")}{isMobile && (
              <IconButton onClick={() => setAddMappingOpen(false)} sx={{ position: 'absolute', right: 8, top: 8 }}><CloseIcon /></IconButton>
            )}</DialogTitle><DialogContent><TextField autoFocus
              fullWidth
              type="number"
              label={i18nText("ui:m_e3ee61fa78ee06ea77cc")}
              value={mappingPort}
              onChange={(e) => setMappingPort(e.target.value)}
              inputProps={{ min: 1, max: 65535 }}
              sx={{ mt: 1, mb: 2 }} /><TextField fullWidth
              label={i18nText("ui:m_b3541c04af4289ac6c7c")}
              placeholder={rawCode("package.MessageName")}
              value={mappingType}
              onChange={(e) => setMappingType(e.target.value)}
              helperText={i18nText("ui:m_c0f4010b79d924263281")} /></DialogContent><DialogActions><Button onClick={() => setAddMappingOpen(false)}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button onClick={handleAddMapping}
              variant="contained"
              disabled={!mappingPort || !mappingType.trim() || saving}>
              {i18nRichText("ui:m_3f348cb4b7a04bb926c3", { arg0: saving ? <CircularProgress size={16} sx={{ mr: 1 }} /> : null })}
            </Button></DialogActions></Dialog></Box></Layout>
  );
}
