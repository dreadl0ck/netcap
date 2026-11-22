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
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ShieldIcon from '@mui/icons-material/Shield';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { useNetcapRouter, useNetcapApi } from '../hooks';
import Layout from '../components/Layout';
import { YaraRuleInfo, YaraScanResult } from '../lib/api';

import { translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as mutate } from "../lib/i18n";
import { type MessageText, message } from "../lib/i18n";
import { rawCode } from "../lib/i18n";
import { errorText } from "../lib/i18n";
import { message as i18nParameterMessage } from "../lib/i18n";







export default function YaraPage() {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [tabIndex, setTabIndex] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<YaraScanResult[]>([]);
  const [scanStats, setScanStats] = useState<{ totalFiles: number; filesScanned: number; totalMatches: number; scanTimeMs: number; state: string; failed: number } | null>(null);
  const [viewDialog, setViewDialog] = useState<{ open: boolean; filename: string; content: string }>({ open: false, filename: '', content: '' });
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: UIMessageText; severity: 'success' | 'error' | 'warning' }>({ open: false, message: '', severity: 'success' });

  const { data: status } = useSWR('yara-status', () => api.getYaraStatus());
  const { data: rulesData } = useSWR('yara-rules', () => api.getYaraRules());
  const rules = rulesData?.rules ?? [];

  const showSnackbar = (message: MessageText, severity: 'success' | 'error' | 'warning') => {
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
        showSnackbar(message("removed:m_d14fd76e6f72c8ad3c7f", { arg0: result.filename, arg1: result.ruleCount }), 'success');
        mutate('yara-rules');
        mutate('yara-status');
      } catch (err: any) {
        showSnackbar(errorText(err) || message("removed:m_f8e877c74c2b6062c4cd"), 'error');
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
      showSnackbar(errorText(err) || message("removed:m_0ae8350fc10d70316974"), 'error');
    }
  }, [api]);

  const handleDelete = useCallback(async (filename: string) => {
    try {
      await api.deleteYaraRule(filename);
      showSnackbar(message("removed:m_bb729f06b49545463cd0"), 'success');
      mutate('yara-rules');
      mutate('yara-status');
    } catch (err: any) {
      showSnackbar(errorText(err) || message("removed:m_f5401b1701c733b124c4"), 'error');
    }
  }, [api]);

  const handleView = useCallback(async (filename: string) => {
    try {
      const result = await api.getYaraRuleContent(filename);
      setViewDialog({ open: true, filename, content: result.content });
    } catch (err: any) {
      showSnackbar(errorText(err) || message("removed:m_31305667027904727610"), 'error');
    }
  }, [api]);

  const handleScan = useCallback(async () => {
    setScanning(true);
    setScanResults([]);
    setScanStats(null);
    try {
      const result = await api.scanWithYara();
      setScanResults(result.results);
      setScanStats({ totalFiles: result.totalFiles, filesScanned: result.filesScanned, totalMatches: result.totalMatches, scanTimeMs: result.scanTimeMs, state: result.state || 'unavailable', failed: result.failed || 0 });
      showSnackbar(message("removed:m_afbecd88e5f5e9d3c83e", { arg0: result.state || i18nParameterMessage("removed:m_db099c16558518a20832"), arg1: result.totalMatches, arg2: result.filesScanned }), result.state === 'complete' ? 'success' : 'warning');
    } catch (err: any) {
      showSnackbar(errorText(err) || message("removed:m_134198138f47ac86131b"), 'error');
    } finally {
      setScanning(false);
    }
  }, [api]);

  const available = status?.available ?? false;
  const hasRules = rules.length > 0;

  return (
    <Layout title={i18nText("removed:m_cf9dce7499c811b57829")}><Box sx={{ p: 3 }}><Box sx={{ display: 'flex', alignItems: 'center', mb: 3, gap: 2 }}><ShieldIcon sx={{ fontSize: 32 }} /><Typography variant="h5">{i18nText("removed:m_cf9dce7499c811b57829")}</Typography></Box>{!available && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            {((__codeValues: Record<string, unknown>) => i18nRichText("removed:m_48b14d0e9cbc3dcb961f", { ...__codeValues, code0: rawCode("noyara", __codeValues), code1: rawCode("libyara_x_capi", __codeValues) }))({ tag0: (chunks: import('react').ReactNode[]) => <code>{chunks}</code>, tag1: (chunks: import('react').ReactNode[]) => <code>{chunks}</code> })}
          </Alert>
        )}<Tabs value={tabIndex} onChange={(_, v) => setTabIndex(v)} sx={{ mb: 2 }}><Tab label={i18nText("removed:m_0669d31220e647cb9221")} /><Tab label={i18nText("removed:m_3c638989bce6640cdc65")} /></Tabs>{/* Rules Tab */}{tabIndex === 0 && (
          <Box><Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center' }}><Button variant="contained" startIcon={<CloudUploadIcon />} onClick={handleUpload} disabled={!available}>
                {i18nText("removed:m_cf268743245199dd1b5b")}
              </Button><Typography variant="body2" color="text.secondary">{status ? i18nText("removed:m_eb2678074f768dc416ca", { arg0: status.enabledRules, arg1: rules.length }) : ''}</Typography></Box>{rules.length === 0 ? (
              <Alert severity="info">{i18nText("removed:m_349868b96fe334756a6d")}</Alert>
            ) : (
              <Grid container spacing={2}>{rules.map((rule) => (
                  <Grid item xs={12} sm={6} md={4} key={rule.filename}><Card sx={{ height: '100%' }}><CardContent><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}><Typography variant="subtitle1" fontWeight="bold" noWrap>{rule.name}</Typography><Switch size="small"
                            checked={rule.enabled}
                            onChange={() => handleToggle(rule)} /></Box>{rule.description && (
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1 }} noWrap>{rule.description}</Typography>
                        )}<Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}><Chip label={i18nText("removed:m_651b6db37082f37aeb63", { arg0: rule.ruleCount })} size="small" color="primary" variant="outlined" /><Chip label={api.formatBytes(rule.size)} size="small" variant="outlined" /></Box><Box sx={{ display: 'flex', gap: 0.5, mt: 1, justifyContent: 'flex-end' }}><Tooltip title={i18nText("removed:m_e7c4970758ff6c649512")}><IconButton size="small" onClick={() => handleView(rule.filename)}><VisibilityIcon fontSize="small" /></IconButton></Tooltip><Tooltip title={i18nText("removed:m_c1be408539d8c22dfb4a")}><IconButton size="small" onClick={() => handleDelete(rule.filename)} color="error"><DeleteIcon fontSize="small" /></IconButton></Tooltip></Box></CardContent></Card></Grid>
                ))}</Grid>
            )}</Box>
        )}{/* Scan Results Tab */}{tabIndex === 1 && (
          <Box><Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center' }}><Button variant="contained"
                startIcon={scanning ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />}
                onClick={handleScan}
                disabled={!available || !hasRules || scanning}>{scanning ? i18nText("removed:m_9ae638b2de63c6ee0914") : i18nText("removed:m_86a2c95d6cffa4b0e8f2")}</Button>{!hasRules && available && (
                <Typography variant="body2" color="text.secondary">{i18nText("removed:m_7f97987bac5d5ee0adb0")}</Typography>
              )}</Box>{scanning && <LinearProgress sx={{ mb: 2 }} />}{scanStats && (
              <Alert severity={scanStats.state !== 'complete' || scanStats.totalMatches > 0 ? 'warning' : 'success'} sx={{ mb: 2 }}>
                {i18nRichText("removed:m_b0e067602a93a729d22b", { arg0: scanStats.state, arg1: scanStats.filesScanned, arg2: scanStats.totalFiles, arg3: scanStats.scanTimeMs, arg4: scanStats.totalMatches, arg5: scanStats.failed })}
              </Alert>
            )}{scanResults.length > 0 && (
              <TableContainer><Table size="small"><TableHead><TableRow><TableCell>{i18nText("removed:m_de894275a403ef797d92")}</TableCell><TableCell>{i18nText("removed:m_58b38fc01db34a4285a1")}</TableCell><TableCell>{i18nText("removed:m_f215e6103d218b17d0fc")}</TableCell><TableCell align="right">{i18nText("removed:m_169d7684a8979db9dcf9")}</TableCell></TableRow></TableHead><TableBody>{scanResults.map((result, i) => (
                      <TableRow key={i}><TableCell><Typography variant="body2" fontFamily="monospace">{result.fileName}</Typography><Typography variant="caption" color="text.secondary">{result.filePath}</Typography></TableCell><TableCell>{result.state || i18nText("removed:m_ddddc9fec2c62ce5d4b3")}{result.outcome ? ` · ${result.outcome}` : ''}{result.error ? ` · ${result.error}` : ''}</TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>{result.matches.map((m) => (
                              <Chip key={m} label={m} size="small" color="error" variant="outlined" />
                            ))}</Box></TableCell><TableCell align="right">{result.scanTimeMs}ms</TableCell></TableRow>
                    ))}</TableBody></Table></TableContainer>
            )}{scanStats && scanResults.length === 0 && (
              <Typography color="text.secondary">{scanStats.state === 'complete' && scanStats.filesScanned > 0 ? i18nText("removed:m_9ef1dfea537b99eb8e6c") : i18nText("removed:m_b1edc9aa01b9f1d36ef0")}</Typography>
            )}</Box>
        )}{/* View Rule Dialog */}<Dialog open={viewDialog.open} onClose={() => setViewDialog({ ...viewDialog, open: false })} maxWidth="md" fullWidth><DialogTitle>{viewDialog.filename}</DialogTitle><DialogContent><TextField multiline
              fullWidth
              value={viewDialog.content}
              InputProps={{ readOnly: true, sx: { fontFamily: 'monospace', fontSize: 13 } }}
              minRows={15}
              maxRows={30} /></DialogContent><DialogActions><Button onClick={() => setViewDialog({ ...viewDialog, open: false })}>{i18nText("removed:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog><Snackbar open={snackbar.open}
          autoHideDuration={4000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}><Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>{i18nRenderText(snackbar.message)}</Alert></Snackbar></Box></Layout>
  );
}
