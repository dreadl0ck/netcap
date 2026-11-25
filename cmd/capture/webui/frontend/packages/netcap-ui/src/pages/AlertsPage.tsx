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

import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  TextField,
  Tooltip,
  Typography,
  Alert as MuiAlert,
  Snackbar,
  IconButton,
} from '@mui/material';
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CheckIcon from '@mui/icons-material/Check';
import UndoIcon from '@mui/icons-material/Undo';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import CloseIcon from '@mui/icons-material/Close';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import ResponsiveDataView from '../components/ResponsiveDataView';
import { Alert, GroupedAlert, AlertStatsResponse, formatBytes } from '../lib/api';
import { useNetcapApi, useIsMobile } from '../hooks';

import { FilterExpressionBlock } from '../components/FilterExpressionHighlight';

import { syntaxHighlightJSON } from '../lib/html';
import { useTheme } from '@mui/material/styles';
import { appearanceTokens } from '../lib/appearance';
import NetworkDetectionEvidence, { NetworkDetectionCoverage } from '../components/NetworkDetectionEvidence';
import RelatedEvidence from '../components/RelatedEvidence';
import { selectorForAlert } from '../lib/evidenceLinks';
import { message as i18nMessage, translate as i18nText, richText as i18nRichText, getLocale as getUILocale, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as mutate, mutatePresentation as globalMutate } from "../lib/i18n";
import { renderError, translate } from "../lib/i18n";
import { getLocale } from "../lib/i18n";
import { recordTypeLabel } from "../lib/i18n";
import { formatTimestamp as displayTimestamp } from '../lib/api';
import { errorText } from "../lib/i18n";
import { rawCode } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";









import { formatEvidenceJSON as formatMatchedRecord } from '../lib/evidenceJSON';

export default function AlertsPage({ renderEvidenceActions }: { renderEvidenceActions?: (alert: Alert) => React.ReactNode } = {}) {
  const __uiLocale = useUILocale();
  const colors = appearanceTokens(useTheme().palette.mode);
  const api = useNetcapApi();
  const isMobile = useIsMobile();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [ruleFilter, setRuleFilter] = useState<string>(() => typeof window === 'undefined' ? '' : new URLSearchParams(window.location.search).get('rule') || '');
  const [classificationFilter, setClassificationFilter] = useState('');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [sortBy, setSortBy] = useState<'count' | 'lastSeen' | 'firstSeen' | 'severity'>('lastSeen');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const [showResolved, setShowResolved] = useState(true);
  const [showInventory, setShowInventory] = useState(false);
  const alertKind = showInventory ? 'all' : 'finding';
  const [resolvingGroups, setResolvingGroups] = useState<Set<string>>(new Set());
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: UIMessageText; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: offlineHistory, error: offlineHistoryError } = useSWR(
    status && ['offline-evaluations', status.sessionId, status.activeInputFile, status.outputDir],
    () => api.getOfflineEvaluations(status?.sessionId ? { sessionId: status.sessionId } : { inputFile: status?.activeInputFile }),
    { refreshInterval: 10000, shouldRetryOnError: false },
  );
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: detectionCoverage, error: detectionCoverageError } = useSWR(['network-detection', status?.sessionId || status?.activeInputFile], () => api.getNetworkDetectionStats(status?.isServiceMode ? undefined : status?.activeInputFile || undefined), { refreshInterval: 5000 });

  // Compute selected file from status and inputFiles
  const selectedFile = useMemo(() => {
    if (!status?.outputDir || !inputFiles) return null;
    return inputFiles.find(f => f.path === status.outputDir) || null;
  }, [status?.outputDir, inputFiles]);

  // Fetch grouped alerts
  const { data: groupedAlertsData, error } = useSWR(
    ['groupedAlerts', page, rowsPerPage, severityFilter, ruleFilter, sortOrder, sortBy, classificationFilter, showResolved, showInventory],
    () =>
      api.getGroupedAlerts({
        limit: rowsPerPage,
        offset: page * rowsPerPage,
        severity: severityFilter || undefined,
        ruleName: ruleFilter || undefined,
        classification: classificationFilter || undefined,
        sort: sortOrder,
        sortBy: sortBy,
        hideResolved: !showResolved,
        kind: alertKind,
      }),
    {
      refreshInterval: 5000,
    }
  );

  // Fetch alert statistics
  const { data: stats } = useSWR<AlertStatsResponse>(['alertStats', alertKind], () => api.getAlertStats(alertKind), {
    refreshInterval: 5000,
  });

  // Extract grouped alerts data and filter based on showResolved
  // Backends may send null for empty lists (e.g. a rule without tags).
  const allGroups = (groupedAlertsData?.groups || []).map(g => ({
    ...g,
    tags: g.tags || [],
    uniqueSrcIPs: g.uniqueSrcIPs || [],
    uniqueDstIPs: g.uniqueDstIPs || [],
    uniqueSrcPorts: g.uniqueSrcPorts || [],
    uniqueDstPorts: g.uniqueDstPorts || [],
    sampleAlerts: g.sampleAlerts || [],
  }));
  // The server filters resolved groups, so its groupCount pages correctly.
  const groups = allGroups;
  const totalCount = groupedAlertsData?.totalCount || 0;
  const groupCount = groupedAlertsData?.groupCount || 0;

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleRefresh = () => {
    mutate(['groupedAlerts', page, rowsPerPage, severityFilter, ruleFilter, sortOrder, sortBy, classificationFilter, showResolved, showInventory]);
    mutate(['alertStats', alertKind]); mutate('alertStats');
  };

  const handleSort = (column: 'count' | 'lastSeen' | 'firstSeen' | 'severity') => {
    if (sortBy === column) {
      // Toggle sort order if clicking the same column
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new column and default to descending
      setSortBy(column);
      setSortOrder('desc');
    }
    setPage(0); // Reset to first page when sorting changes
  };

  // Memoize event handler to prevent recreation on every render
  const handleFileChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      await mutate(['groupedAlerts', page, rowsPerPage, severityFilter, ruleFilter, sortOrder, sortBy, classificationFilter, showResolved, showInventory]);
      await mutate(['alertStats', alertKind]); mutate('alertStats');
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
    } catch (err) {
      console.error('Failed to switch file:', err);
      setSnackbar({ open: true, message: i18nMessage("ui:m_7ab800e4d59917b1d34c"), severity: 'error' });
    } finally {
      setSwitchingFile(false);
    }
  }, [mutateStatus, mutate, page, rowsPerPage, severityFilter, ruleFilter, sortOrder, sortBy, classificationFilter, showResolved, showInventory, __uiLocale]);

  const handleClearAlerts = async () => {
    if (!confirm(i18nText("ui:m_a42e250b515343cd36cf"))) return;

    try {
      await api.clearAlerts();
      setSnackbar({ open: true, message: i18nMessage("ui:m_e5eebd11d0be4d493491"), severity: 'success' });
      handleRefresh();
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("ui:m_83302aaa9554beb6daa9"), severity: 'error' });
    }
  };

  const handleViewDetails = (alert: Alert) => {
    setSelectedAlert(alert);
    setDetailsDialogOpen(true);
  };

  const handleResolveGroup = async (groupId: string) => {
    setResolvingGroups(prev => new Set(prev).add(groupId));
    try {
      await api.resolveAlert(undefined, groupId);
      setSnackbar({ open: true, message: i18nMessage("ui:m_f0408e12c492dc1f1d34"), severity: 'success' });
      handleRefresh();
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("ui:m_59a736b3ef70f037614b"), severity: 'error' });
    } finally {
      setResolvingGroups(prev => {
        const next = new Set(prev);
        next.delete(groupId);
        return next;
      });
    }
  };

  const handleUnresolveGroup = async (groupId: string) => {
    setResolvingGroups(prev => new Set(prev).add(groupId));
    try {
      await api.unresolveAlert(undefined, groupId);
      setSnackbar({ open: true, message: i18nMessage("ui:m_baef1de56e99528cfa74"), severity: 'success' });
      handleRefresh();
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("ui:m_b506ee0cfe37d866683e"), severity: 'error' });
    } finally {
      setResolvingGroups(prev => {
        const next = new Set(prev);
        next.delete(groupId);
        return next;
      });
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <ErrorIcon color="error" />;
      case 'high':
        return <WarningIcon color="warning" />;
      case 'medium':
        return <InfoIcon color="info" />;
      case 'low':
        return <CheckCircleIcon color="success" />;
      case 'info':
        return <InfoIcon color="disabled" />;
      default:
        return <InfoIcon />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      case 'info':
        return 'default';
      default:
        return 'default';
    }
  };

  const formatTimestamp = (timestamp: number, unit: 'seconds' | 'milliseconds' | 'nanoseconds') => displayTimestamp(timestamp, unit);

  // Get unique rule names for filter
  const uniqueRules = Array.from(new Set(stats?.byRule ? Object.keys(stats.byRule) : []));

  // Get only completed files for the selector
  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_d413445dc7844e3a4ec6")} />
  );

  return (
    <Layout title={i18nText("ui:m_451e6181764a06e7c139")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{offlineHistory?.evaluations.some(report => report.status !== 'complete') && <MuiAlert severity="warning" sx={{ mb: 2 }}>{i18nText("ui:m_49618d0c10d77081350b")}</MuiAlert>}{(groupedAlertsData?.skippedOversizedAlerts ?? 0) > 0 && <MuiAlert severity="warning" sx={{ mb: 2 }}>{i18nText("ui:m_2b500365c4a97ed05a4f", { arg0: groupedAlertsData?.skippedOversizedAlerts ?? 0 })}</MuiAlert>}{offlineHistoryError && offlineHistoryError.status !== 404 && offlineHistoryError.status !== 409 && <MuiAlert severity="error" sx={{ mb: 2 }}>{i18nRichText("ui:m_1a51b1fa92b0c5f873fa", { arg0: renderError(offlineHistoryError) })}</MuiAlert>}<Box sx={{ 
          display: 'flex', 
          flexDirection: { xs: 'column', md: 'row' },
          justifyContent: 'space-between', 
          alignItems: { xs: 'stretch', md: 'flex-start' }, 
          gap: 2,
          mb: 3 
        }}><Box sx={{ minWidth: 0, flex: 1 }}>{selectedFile && (
              <Box sx={{ 
                display: 'flex', 
                gap: { xs: 1, sm: 1.5 }, 
                alignItems: 'center', 
                mt: 1,
                flexWrap: 'wrap'
              }}><Typography variant="body1" fontWeight="medium">
                  {i18nRichText("ui:m_108b30ec5d9fba5e66b8", { arg0: totalCount })}
                </Typography><Typography variant="body2" color="text.secondary" sx={{ display: { xs: 'none', sm: 'block' } }}>
                  {i18nText("ui:m_500d5a66ed6c66e71b80")}
                </Typography><Chip label={selectedFile.name}
                  size="small"
                  sx={{ 
                    fontFamily: 'monospace', 
                    fontSize: { xs: '0.7rem', sm: '0.8rem' },
                    maxWidth: { xs: '200px', sm: '400px' },
                    '& .MuiChip-label': {
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }
                  }} /><Chip label={formatBytes(selectedFile.size)}
                  size="small"
                  variant="outlined"
                  sx={{ fontSize: '0.75rem' }} /></Box>
            )}</Box><Box sx={{ 
            display: 'flex', 
            gap: 1,
            flexWrap: 'wrap',
            justifyContent: { xs: 'stretch', md: 'flex-end' }
          }}><Button data-learn={i18nText("ui:m_94d69d96ded302a37efd")}
              variant={showResolved ? "contained" : "outlined"}
              startIcon={<FilterAltIcon />} 
              onClick={() => { setShowResolved(!showResolved); setPage(0); }}
              size="small"
              sx={{ flex: { xs: 1, sm: 'none' } }}>{showResolved ? i18nText("ui:m_9ae02100760198ff9fd0") : i18nText("ui:m_bbdbb9a6cb91944ace7b")}</Button><Button variant={showInventory ? "contained" : "outlined"}
              startIcon={<FilterAltIcon />}
              onClick={() => { setShowInventory(!showInventory); setPage(0); }}
              size="small"
              sx={{ flex: { xs: 1, sm: 'none' } }}>{showInventory ? i18nText("ui:m_93fb8662cab0f6871021") : i18nText("ui:m_ff4c032ec3a05f603be4", { arg0: (stats?.byKind?.inventory ?? 0).toLocaleString(getUILocale()) })}</Button><Button data-learn={i18nText("ui:m_a3d69e25d47882759349")}
              variant="outlined" 
              startIcon={<RefreshIcon />} 
              onClick={handleRefresh}
              size="small"
              sx={{ flex: { xs: 1, sm: 'none' } }}>
              {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
            </Button><Button data-learn={i18nText("ui:m_1ece4019ce6aa19d7799")}
              variant="outlined" 
              color="error" 
              startIcon={<DeleteIcon />} 
              onClick={handleClearAlerts}
              disabled={totalCount === 0}
              size="small"
              sx={{ flex: { xs: 1, sm: 'none' } }}>
              {i18nText("ui:m_0cb3d73ec88de1474e7b")}
            </Button></Box></Box>{error && (
          <MuiAlert severity="error" sx={{ mb: 2 }}>
            {i18nRichText("ui:m_d1fec055a51de9318b59", { arg0: renderError(error) })}
          </MuiAlert>
        )}<Box sx={{ mb: 2 }}><NetworkDetectionCoverage stats={detectionCoverage ?? undefined} unavailable={Boolean(detectionCoverageError) || detectionCoverage === null} /></Box><FormControl size="small" sx={{ mb: 2, minWidth: 240 }}><InputLabel id="finding-class-label">{i18nText("ui:m_ce0227fef732712341e3")}</InputLabel><Select labelId="finding-class-label" label={i18nText("ui:m_ce0227fef732712341e3")} value={classificationFilter} onChange={event => { setClassificationFilter(event.target.value); setPage(0); }}><MenuItem value="">{i18nText("ui:m_7543b75b9150514fd1a1")}</MenuItem><MenuItem value="indicator-match">{i18nText("ui:m_4927de4ce6e603ca7260")}</MenuItem><MenuItem value="behavioral-suspicion">{i18nText("ui:m_252e1f238d91fa786162")}</MenuItem><MenuItem value="policy-observation">{i18nText("ui:m_6d9badd743a5785976f6")}</MenuItem></Select></FormControl>{/* Statistics Cards */}{stats && (
          <Grid container spacing={2} sx={{ mb: 3 }}><Grid item xs={12} sm={6} md={3}><Card sx={{ height: '100%' }}><CardContent><Typography color="text.secondary" gutterBottom>
                    {i18nText("ui:m_bd3b66813b0e0d1b31ac")}
                  </Typography><Typography variant="h4">{stats.totalAlerts}</Typography></CardContent></Card></Grid><Grid item xs={12} sm={6} md={3}><Card sx={{ height: '100%' }}><CardContent><Typography color="text.secondary" gutterBottom>
                    {i18nText("ui:m_0b6c65025445659a60b3")}
                  </Typography><Typography variant="h4" color="error">{stats.criticalAlerts}</Typography></CardContent></Card></Grid><Grid item xs={12} sm={6} md={3}><Card sx={{ height: '100%' }}><CardContent><Typography color="text.secondary" gutterBottom>
                    {i18nText("ui:m_6b642f61f2505b500f84")}
                  </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>{Object.entries(stats.bySeverity).map(([severity, count]) => (
                      <Chip key={severity}
                        label={`${severity}: ${count}`}
                        size="small"
                        color={getSeverityColor(severity) as any} />
                    ))}</Box></CardContent></Card></Grid><Grid item xs={12} sm={6} md={3}><Card sx={{ height: '100%' }}><CardContent><Typography color="text.secondary" gutterBottom>
                    {i18nText("ui:m_410c86407a7428204db4")}
                  </Typography><Typography variant="h4">{Object.keys(stats.byRule).length}</Typography></CardContent></Card></Grid></Grid>
        )}{/* Filters */}<Paper sx={{ p: 2, mb: 2 }}><Grid container spacing={2} alignItems="center"><Grid item xs={12} sm={3}><FormControl fullWidth size="small"><InputLabel>{i18nText("ui:m_2c83187c8d6ef78ec584")}</InputLabel><Select data-learn={i18nText("ui:m_56caae8fe9d03f61f020")}
                  value={severityFilter}
                  label={i18nText("ui:m_2c83187c8d6ef78ec584")}
                  onChange={(e) => {
                    setSeverityFilter(e.target.value);
                    setPage(0);
                  }}><MenuItem value="">{i18nText("ui:m_348cb66057ba9fd3babc")}</MenuItem><MenuItem value="info">{i18nText("ui:m_e23ead341eca901e52be")}</MenuItem><MenuItem value="low">{i18nText("ui:m_f421fc8ad1242ca9d49f")}</MenuItem><MenuItem value="medium">{i18nText("ui:m_793aaa27ac92c4e93090")}</MenuItem><MenuItem value="high">{i18nText("ui:m_222fd33d915d779d6af3")}</MenuItem><MenuItem value="critical">{i18nText("ui:m_fa8cf458bd646a3d049e")}</MenuItem></Select></FormControl></Grid><Grid item xs={12} sm={3}><FormControl fullWidth size="small"><InputLabel>{i18nText("ui:m_2cbe86c7c53f33f1b4c8")}</InputLabel><Select data-learn={i18nText("ui:m_2cee6ae9f14d25e958ff")}
                  value={ruleFilter}
                  label={i18nText("ui:m_2cbe86c7c53f33f1b4c8")}
                  onChange={(e) => {
                    setRuleFilter(e.target.value);
                    setPage(0);
                  }}><MenuItem value="">{i18nText("ui:m_cd3ecfc631ecc41922b4")}</MenuItem>{uniqueRules.map((rule) => (
                    <MenuItem key={rule} value={rule}>{rule}</MenuItem>
                  ))}</Select></FormControl></Grid><Grid item xs={12} sm={3}><FormControl fullWidth size="small"><InputLabel>{i18nText("ui:m_b662f864c87d05763b4d")}</InputLabel><Select data-learn={i18nText("ui:m_2d2efcf5c8f01db39e49")}
                  value={sortBy}
                  label={i18nText("ui:m_b662f864c87d05763b4d")}
                  onChange={(e) => setSortBy(e.target.value as 'count' | 'lastSeen' | 'firstSeen' | 'severity')}><MenuItem value="lastSeen">{i18nText("ui:m_b5d1cbf759286ef6d5c9")}</MenuItem><MenuItem value="firstSeen">{i18nText("ui:m_e7368473dd089d37c0a2")}</MenuItem><MenuItem value="count">{i18nText("ui:m_9cc2c6f927f2cbb0421c")}</MenuItem><MenuItem value="severity">{i18nText("ui:m_d1de98cbf475009ee57d")}</MenuItem></Select></FormControl></Grid><Grid item xs={12} sm={3}><FormControl fullWidth size="small"><InputLabel>{i18nText("ui:m_e47f31c8ff75b06da2d6")}</InputLabel><Select data-learn={i18nText("ui:m_a10eb80a064c233508e4")}
                  value={sortOrder}
                  label={i18nText("ui:m_e47f31c8ff75b06da2d6")}
                  onChange={(e) => setSortOrder(e.target.value as 'asc' | 'desc')}><MenuItem value="desc">{i18nText("ui:m_81b9877e1ef78776e7fb")}</MenuItem><MenuItem value="asc">{i18nText("ui:m_078698fd3381a74bad23")}</MenuItem></Select></FormControl></Grid></Grid></Paper>{/* Grouped Alerts Table */}<ResponsiveDataView data={groups}
          totalCount={groupCount}
          page={page}
          rowsPerPage={rowsPerPage}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
          rowsPerPageOptions={[10, 25, 50, 100]}
          labelDisplayedRows={({ from, to, count }) =>
            translate("ui:m_b05d201872a5873dd2ba", { arg0: from, arg1: to, arg2: count, arg3: totalCount })}
          onCardClick={(group) => {
            const groupKey = group.groupId;
            setExpandedGroup(expandedGroup === groupKey ? null : groupKey);
          }}
          renderCard={(group) => (
            <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Box display="flex" alignItems="center" gap={1} mb={0.5}><Chip label={group.severity.toUpperCase()} size="small" color={getSeverityColor(group.severity) as any} /><Chip label={i18nText("ui:m_c81c321b7df174588572", { arg0: group.count.toLocaleString(getUILocale()) })}
                    size="small"
                    color="primary"
                    sx={{ fontWeight: 'bold' }} />{group.resolved && (
                    <Chip label={i18nText("ui:m_6409fda6c1b6bad4d325")} size="small" variant="outlined" color="success" />
                  )}</Box><Typography variant="body2" noWrap fontWeight="medium">{group.ruleName}</Typography><Typography variant="caption" color="text.secondary" display="block" mt={0.5}>{group.description}</Typography><Box display="flex" justifyContent="space-between" alignItems="center" mt={0.5}><Typography variant="caption" color="text.secondary">{formatTimestamp(group.firstSeen, 'nanoseconds')}</Typography>{group.resolved ? (
                    <IconButton size="small"
                      color="default"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleUnresolveGroup(group.groupId);
                      }}
                      disabled={resolvingGroups.has(group.groupId)}><UndoIcon fontSize="small" /></IconButton>
                  ) : (
                    <IconButton size="small"
                      color="success"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleResolveGroup(group.groupId);
                      }}
                      disabled={resolvingGroups.has(group.groupId)}><CheckIcon fontSize="small" /></IconButton>
                  )}</Box></CardContent></Card>
          )}
          desktopTable={<TableContainer component={Paper} sx={{ overflowX: 'auto', maxWidth: '100%' }}><Table sx={{ minWidth: { xs: 800, md: 'auto' } }}><TableHead><TableRow><TableCell width="40px"></TableCell><TableCell><TableSortLabel active={sortBy === 'severity'}
                        direction={sortBy === 'severity' ? sortOrder : 'desc'}
                        onClick={() => handleSort('severity')}>
                        {i18nText("ui:m_d1de98cbf475009ee57d")}
                      </TableSortLabel></TableCell><TableCell>{i18nText("ui:m_752576a3b0b2dca4ab6a")}</TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>{i18nText("ui:m_3da346bd3b7d84ce65d6")}</TableCell><TableCell><TableSortLabel active={sortBy === 'count'}
                        direction={sortBy === 'count' ? sortOrder : 'desc'}
                        onClick={() => handleSort('count')}>
                        {i18nText("ui:m_9cc2c6f927f2cbb0421c")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel active={sortBy === 'firstSeen'}
                        direction={sortBy === 'firstSeen' ? sortOrder : 'desc'}
                        onClick={() => handleSort('firstSeen')}>
                        {i18nText("ui:m_e7368473dd089d37c0a2")}
                      </TableSortLabel></TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}><TableSortLabel active={sortBy === 'lastSeen'}
                        direction={sortBy === 'lastSeen' ? sortOrder : 'desc'}
                        onClick={() => handleSort('lastSeen')}>
                        {i18nText("ui:m_b5d1cbf759286ef6d5c9")}
                      </TableSortLabel></TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>{i18nText("ui:m_619b4801dd549151fd61")}</TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>{i18nText("ui:m_47846a266ab7374ce1aa")}</TableCell><TableCell>{i18nText("ui:m_8b59af6a47204b74041c")}</TableCell></TableRow></TableHead><TableBody>{groups.length === 0 ? (
                    <TableRow><TableCell colSpan={10} align="center"><Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                          {i18nText("ui:m_93a3d921adb7f9e44c8d")}
                        </Typography></TableCell></TableRow>
                  ) : (
                    groups.map((group, index) => {
                      const groupKey = group.groupId;
                      const isExpanded = expandedGroup === groupKey;

                      return (
                        <><TableRow key={groupKey}
                            hover
                            sx={{
                              cursor: 'pointer',
                              opacity: group.resolved ? 0.6 : 1,
                              backgroundColor: group.resolved ? 'action.selected' : 'inherit',
                            }}><TableCell><IconButton size="small"
                                onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}>{isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}</IconButton></TableCell><TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>{getSeverityIcon(group.severity)}<Chip label={group.severity.toUpperCase()}
                                  size="small"
                                  color={getSeverityColor(group.severity) as any} /></Box></TableCell><TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}><Tooltip title={group.description}><Typography variant="body2"
                                  fontWeight="medium"
                                  sx={{
                                    maxWidth: 300,
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap'
                                  }}>{group.ruleName}</Typography></Tooltip></TableCell><TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)} sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Chip label={recordTypeLabel(group.recordType)} size="small" variant="outlined" /></TableCell><TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}><Chip label={group.count.toLocaleString(getUILocale())}
                                size="small"
                                color="primary"
                                sx={{ fontWeight: 'bold' }} /></TableCell><TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}><Typography variant="body2">{formatTimestamp(group.firstSeen, 'nanoseconds')}</Typography></TableCell><TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)} sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Typography variant="body2">{formatTimestamp(group.lastSeen, 'nanoseconds')}</Typography></TableCell><TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)} sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}><Typography variant="caption" color="text.secondary">
                                  {i18nRichText("ui:m_98ad4aa030dde6b61875", { arg0: group.uniqueSrcIPs.length, arg1: group.uniqueDstIPs.length })}
                                </Typography>{group.uniqueSrcPorts.length > 0 && (
                                  <Typography variant="caption" color="text.secondary">
                                    {i18nRichText("ui:m_44f1db4fe5b60203be56", { arg0: group.uniqueSrcPorts.length + group.uniqueDstPorts.length })}
                                  </Typography>
                                )}</Box></TableCell><TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)} sx={{ display: { xs: 'none', lg: 'table-cell' } }}><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{group.tags.slice(0, 2).map((tag) => (
                                  <Chip key={tag} label={tag} size="small" />
                                ))}{group.tags.length > 2 && (
                                  <Chip label={`+${group.tags.length - 2}`} size="small" variant="outlined" />
                                )}</Box></TableCell><TableCell><Box sx={{ display: 'flex', gap: 0.5 }}>{group.resolved ? (
                                  <Tooltip title={i18nText("ui:m_9b3c382b6c1a611357d6")}><IconButton data-learn={i18nText("ui:m_33bf7480c073e5d22831")}
                                      size="small"
                                      color="default"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleUnresolveGroup(group.groupId);
                                      }}
                                      disabled={resolvingGroups.has(group.groupId)}><UndoIcon fontSize="small" /></IconButton></Tooltip>
                                ) : (
                                  <Tooltip title={i18nText("ui:m_3a6ca6a59b03b40a01b4")}><IconButton data-learn={i18nText("ui:m_d1637304822bf48b6b3d")}
                                      size="small"
                                      color="success"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleResolveGroup(group.groupId);
                                      }}
                                      disabled={resolvingGroups.has(group.groupId)}><CheckIcon fontSize="small" /></IconButton></Tooltip>
                                )}</Box></TableCell></TableRow>{/* Expanded Details */}{isExpanded && (
                            <TableRow><TableCell colSpan={10} sx={{ backgroundColor: 'action.hover', py: 2 }}><Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, px: 2 }}><Typography variant="subtitle2" fontWeight="bold">
                                    {i18nText("ui:m_be2ebd0da19653315021")}
                                  </Typography><Grid container spacing={2}><Grid item xs={12} md={6}><Typography variant="caption" color="text.secondary" display="block">
                                        {i18nText("ui:m_a02602e322c10d1a5449")}
                                      </Typography><Typography variant="body2">{group.description}</Typography></Grid>{group.mitre && (
                                      <Grid item xs={12} md={6}><Typography variant="caption" color="text.secondary" display="block">MITRE ATT&CK
                                        </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>{group.mitre.split(',').map((mitre) => (
                                            <Chip key={mitre.trim()} label={mitre.trim()} size="small" color="warning" />
                                          ))}</Box></Grid>
                                    )}{group.threshold > 0 && (
                                      <Grid item xs={12} md={6}><Typography variant="caption" color="text.secondary" display="block">
                                          {i18nText("ui:m_f18493203543b86d8aea")}
                                        </Typography><Paper sx={{
                                            p: 1,
                                            mt: 0.5,
                                            backgroundColor: 'background.paper',
                                            border: 1,
                                            borderColor: 'primary.main',
                                          }}><Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                                            {i18nRichText("ui:m_bbe66995f187c4d85bff", { arg0: group.threshold, arg1: group.thresholdWindow, tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong>, tag1: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}
                                          </Typography></Paper></Grid>
                                    )}{group.uniqueSrcIPs.length > 0 && (
                                      <Grid item xs={12} md={6}><Typography variant="caption" color="text.secondary" display="block">
                                          {i18nRichText("ui:m_799713ee073e034bfddf", { arg0: group.uniqueSrcIPs.length })}
                                        </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>{group.uniqueSrcIPs.slice(0, 10).map((ip) => (
                                            <Chip key={ip}
                                              label={ip}
                                              size="small"
                                              variant="outlined"
                                              sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }} />
                                          ))}{group.uniqueSrcIPs.length > 10 && (
                                            <Chip label={i18nText("ui:m_5000f686d6d8f94a73f9", { arg0: group.uniqueSrcIPs.length - 10 })}
                                              size="small"
                                              variant="outlined" />
                                          )}</Box></Grid>
                                    )}{group.uniqueDstIPs.length > 0 && (
                                      <Grid item xs={12} md={6}><Typography variant="caption" color="text.secondary" display="block">
                                          {i18nRichText("ui:m_409eb164227b2121213d", { arg0: group.uniqueDstIPs.length })}
                                        </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>{group.uniqueDstIPs.slice(0, 10).map((ip) => (
                                            <Chip key={ip}
                                              label={ip}
                                              size="small"
                                              variant="outlined"
                                              sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }} />
                                          ))}{group.uniqueDstIPs.length > 10 && (
                                            <Chip label={i18nText("ui:m_5000f686d6d8f94a73f9", { arg0: group.uniqueDstIPs.length - 10 })}
                                              size="small"
                                              variant="outlined" />
                                          )}</Box></Grid>
                                    )}{(group.uniqueSrcPorts.length > 0 || group.uniqueDstPorts.length > 0) && (
                                      <Grid item xs={12}><Typography variant="caption" color="text.secondary" display="block">
                                          {i18nRichText("ui:m_4790572cc2081c3b5516", { arg0: group.uniqueSrcPorts.length, arg1: group.uniqueDstPorts.length })}
                                        </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>{[...group.uniqueSrcPorts, ...group.uniqueDstPorts].slice(0, 20).map((port, idx) => (
                                            <Chip key={`${port}-${idx}`}
                                              label={port}
                                              size="small"
                                              variant="outlined"
                                              sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }} />
                                          ))}</Box></Grid>
                                    )}{group.ruleExpression && (
                                      <Grid item xs={12}><Typography variant="caption" color="text.secondary" display="block">
                                          {i18nText("ui:m_edcc62c2a8de54c01945")}
                                        </Typography><FilterExpressionBlock expression={group.ruleExpression}
                                          sx={{
                                            mt: 0.5,
                                            p: 1.5,
                                          }} /></Grid>
                                    )}</Grid><GroupAlerts groupId={group.groupId} count={group.count} kind={alertKind} onView={handleViewDetails} /></Box></TableCell></TableRow>
                          )}</>
                      );
                    })
                  )}</TableBody></Table></TableContainer>} />{/* Alert Details Dialog */}<Dialog open={detailsDialogOpen}
          onClose={() => setDetailsDialogOpen(false)}
          maxWidth="md"
          fullWidth
          fullScreen={isMobile}><style>{rawCode("\n            .json-key '{' color: {arg0}; '}'\n            .json-string '{' color: {arg1}; '}'\n            .json-number '{' color: {arg2}; '}'\n            .json-boolean, .json-null '{' color: {arg3}; '}'\n          ", { arg0: colors.syntax.key, arg1: colors.syntax.string, arg2: colors.syntax.number, arg3: colors.syntax.keyword })}</style><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">
              {i18nRichText("ui:m_eb67d170e54ff2cff928", { arg0: isMobile && (
                <IconButton onClick={() => setDetailsDialogOpen(false)} edge="end"><CloseIcon /></IconButton>
              ) })}
            </Box></DialogTitle><DialogContent>{selectedAlert && (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}><NetworkDetectionEvidence alert={selectedAlert} />{selectedAlert.recordType === 'NetworkDetection' && renderEvidenceActions?.(selectedAlert)}{selectorForAlert(selectedAlert.recordType, selectedAlert.matchedRecord) && <RelatedEvidence selector={selectorForAlert(selectedAlert.recordType, selectedAlert.matchedRecord)} />}<Box><Typography variant="subtitle2" color="text.secondary">
                    {i18nText("ui:m_f68524a5a2e8c875738d")}
                  </Typography><Typography variant="body1">{formatTimestamp(selectedAlert.timestamp, 'nanoseconds')}</Typography></Box><Box><Typography variant="subtitle2" color="text.secondary">
                    {i18nText("ui:m_752576a3b0b2dca4ab6a")}
                  </Typography><Typography variant="body1" fontWeight="medium">{selectedAlert.ruleName}</Typography></Box><Box><Typography variant="subtitle2" color="text.secondary">
                    {i18nText("ui:m_a02602e322c10d1a5449")}
                  </Typography><Typography variant="body1">{selectedAlert.description}</Typography></Box><Box><Typography variant="subtitle2" color="text.secondary">
                    {i18nText("ui:m_d1de98cbf475009ee57d")}
                  </Typography><Chip label={selectedAlert.severity.toUpperCase()}
                    color={getSeverityColor(selectedAlert.severity) as any} /></Box><Box><Typography variant="subtitle2" color="text.secondary">
                    {i18nText("ui:m_21e984a0c1b0479051bc")}
                  </Typography><Typography variant="body1">{recordTypeLabel(selectedAlert.recordType)}</Typography></Box>{selectedAlert.ruleExpression && (
                  <Box><Typography variant="subtitle2" color="text.secondary">
                      {i18nText("ui:m_edcc62c2a8de54c01945")}
                    </Typography><FilterExpressionBlock expression={selectedAlert.ruleExpression}
                      sx={{ backgroundColor: 'background.default' }} /></Box>
                )}{selectedAlert.threshold > 0 && (
                  <Box><Typography variant="subtitle2" color="text.secondary">
                      {i18nText("ui:m_f18493203543b86d8aea")}
                    </Typography><Paper sx={{
                        p: 1.5,
                        backgroundColor: 'action.hover',
                        border: 1,
                        borderColor: 'primary.main',
                      }}><Typography variant="body2" sx={{ mb: 0.5 }}>
                        {i18nRichText("ui:m_34c77a44b73fb194fd79", { arg0: selectedAlert.threshold, tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}
                      </Typography><Typography variant="body2">
                        {i18nRichText("ui:m_74f881b9b70d1adeb8f7", { arg0: selectedAlert.thresholdWindow, tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}
                      </Typography><Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                        {i18nRichText("ui:m_6960f89f241719ebeb3c", { arg0: selectedAlert.threshold, arg1: selectedAlert.thresholdWindow })}
                      </Typography></Paper></Box>
                )}<Grid container spacing={2}><Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">
                      {i18nText("ui:m_e540837f52427c6b32ef")}
                    </Typography><Typography variant="body1"
                      sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>{selectedAlert.srcIP || '-'}</Typography></Grid><Grid item xs={6}><Typography variant="subtitle2" color="text.secondary">
                      {i18nText("ui:m_c687f3a957a05117cce7")}
                    </Typography><Typography variant="body1"
                      sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>{selectedAlert.dstIP || '-'}</Typography></Grid></Grid>{selectedAlert.mitre && (
                  <Box><Typography variant="subtitle2" color="text.secondary">MITRE ATT&CK
                    </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>{selectedAlert.mitre.split(',').map((mitre) => (
                        <Chip key={mitre.trim()} label={mitre.trim()} size="small" color="warning" />
                      ))}</Box></Box>
                )}{(selectedAlert.tags || []).length > 0 && (
                  <Box><Typography variant="subtitle2" color="text.secondary">
                      {i18nText("ui:m_47846a266ab7374ce1aa")}
                    </Typography><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>{(selectedAlert.tags || []).map((tag) => (
                        <Chip key={tag} label={tag} size="small" />
                      ))}</Box></Box>
                )}{(selectedAlert.count ?? 0) > 0 && <Box><Typography variant="subtitle2" color="text.secondary">{i18nText("ui:m_c8f9cd63288678efe780", { arg0: selectedAlert.count })}</Typography>{selectedAlert.firstSeenNs && selectedAlert.lastSeenNs && <Typography variant="body2">{formatTimestamp(Number(selectedAlert.firstSeenNs), 'nanoseconds')} – {formatTimestamp(Number(selectedAlert.lastSeenNs), 'nanoseconds')}</Typography>}</Box>}
                {!!selectedAlert.examples?.length && <AlertEvidenceExamples examples={selectedAlert.examples} />}
                {selectedAlert.groupedEvaluation && <Box><Typography variant="subtitle2">{i18nText("ui:m_d607679de2b23948c496")}</Typography><Typography variant="body2">{i18nRichText("ui:m_79f12a5a00887e8b8f2d", { arg0: selectedAlert.groupedEvaluation.count, arg1: selectedAlert.groupedEvaluation.ruleId })}</Typography><Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 }}>{JSON.stringify(selectedAlert.groupedEvaluation, null, 2)}</Box></Box>}{selectedAlert.matchedRecord && (
                  <Box><Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      {i18nText("ui:m_8771965c4afc3da2f3e2")}
                    </Typography><Paper sx={{
                        p: 2,
                        backgroundColor: 'background.default',
                        overflow: 'auto',
                        maxHeight: 300,
                      }}><pre style={{
                          margin: 0,
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                        }}
                        dangerouslySetInnerHTML={{
                          __html: syntaxHighlightJSON(formatMatchedRecord(selectedAlert.matchedRecord))
                        }} /></Paper></Box>
                )}</Box>
            )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_2622a207dff4b5c4caf5")} onClick={() => setDetailsDialogOpen(false)}>{i18nText("ui:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog>{/* Snackbar for notifications */}<Snackbar open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}><MuiAlert onClose={() => setSnackbar({ ...snackbar, open: false })}
            severity={snackbar.severity}
            sx={{ width: '100%' }}>{i18nRenderText(snackbar.message)}</MuiAlert></Snackbar></Box></Layout>
  );
}

const GROUP_ALERTS_PAGE = 10;

// Pages through every alert of a group; the group summary keeps only samples.
function AlertEvidenceExamples({ examples }: { examples: string[] }) {
  const matched: string[] = [];
  const related: string[] = [];
  examples.forEach(example => {
    let kind: string | undefined;
    try { kind = JSON.parse(example)?.kind; } catch { /* legacy examples may be plain text */ }
    (kind === 'related-evidence' || kind === 'related-evidence-limit' ? related : matched).push(example);
  });
  const style = { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12, maxHeight: 240, overflow: 'auto' } as const;
  return <>
    {!!matched.length && <Box component="pre" sx={style}>{matched.join('\n')}</Box>}
    {!!related.length && <Box><Typography variant="subtitle2" color="text.secondary">{i18nText("ui:m_e88c8ee8b22fc69dbf66")}</Typography><Box component="pre" sx={style}>{related.join('\n')}</Box></Box>}
  </>;
}

function GroupAlerts({ groupId, count, kind, onView }: { groupId: string; count: number; kind: 'finding' | 'all'; onView: (alert: Alert) => void }) {
  const api = useNetcapApi();
  const [offset, setOffset] = useState(0);
  const { data } = useSWR(['groupAlerts', groupId, offset, kind], () => api.getAlerts({ groupId, limit: GROUP_ALERTS_PAGE, offset, kind }));
  const alerts = data?.alerts || [];
  const total = data?.totalCount ?? count;
  return (
    <Box sx={{ mt: 2 }}><Typography variant="subtitle2" fontWeight="bold" gutterBottom>{i18nText("ui:m_1f88304c2357bb0a6512", { arg0: total.toLocaleString(getUILocale()) })}</Typography><Table size="small"><TableHead><TableRow><TableCell>{i18nText("ui:m_f68524a5a2e8c875738d")}</TableCell><TableCell>{i18nText("ui:m_e540837f52427c6b32ef")}</TableCell><TableCell>{i18nText("ui:m_c687f3a957a05117cce7")}</TableCell><TableCell>{i18nText("ui:m_cf025c2b66b1d8e97700")}</TableCell><TableCell /></TableRow></TableHead><TableBody>{alerts.map(alert => (
      <TableRow key={alert.alertId}><TableCell>{displayTimestamp(alert.timestamp, 'nanoseconds')}</TableCell><TableCell sx={{ fontFamily: 'monospace' }}>{alert.srcIP || alert.deviceMAC || '-'}</TableCell><TableCell sx={{ fontFamily: 'monospace' }}>{alert.dstIP || '-'}</TableCell><TableCell>{alert.resolved && <Chip label={i18nText("ui:m_6409fda6c1b6bad4d325")} size="small" color="success" variant="outlined" />}</TableCell><TableCell align="right"><Tooltip title={i18nText("ui:m_0e07624e3854b301c0e2")}><IconButton size="small" aria-label={i18nText("ui:m_0e07624e3854b301c0e2")} onClick={() => onView(alert)}><VisibilityIcon fontSize="small" /></IconButton></Tooltip></TableCell></TableRow>
    ))}</TableBody></Table><Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 1, mt: 1 }}><Typography variant="caption" color="text.secondary">{i18nText("ui:m_6fa96ac45775b8cea8af", { arg0: total === 0 ? 0 : offset + 1, arg1: Math.min(offset + GROUP_ALERTS_PAGE, total), arg2: total })}</Typography><Button size="small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - GROUP_ALERTS_PAGE))}>{i18nText("ui:m_ff496f592bb0ad0ee2c7")}</Button><Button size="small" disabled={offset + GROUP_ALERTS_PAGE >= total} onClick={() => setOffset(offset + GROUP_ALERTS_PAGE)}>{i18nText("ui:m_d169a90acabd9d48bf7b")}</Button></Box></Box>
  );
}
