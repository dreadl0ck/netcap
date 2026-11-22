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
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  TextField,
  Tooltip,
  Typography,
  Alert,
  Snackbar,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import CodeIcon from '@mui/icons-material/Code';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ErrorIcon from '@mui/icons-material/Error';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import SecurityIcon from '@mui/icons-material/Security';
import BlockIcon from '@mui/icons-material/Block';
import CloseIcon from '@mui/icons-material/Close';
import { useNetcapRouter, useNetcapApi, useIsMobile } from '../hooks';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { Rule, CreateRuleRequest, UpdateRuleRequest, ResponseAction, formatBytes } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';

import { FilterExpressionInline, FilterExpressionBlock } from '../components/FilterExpressionHighlight';
import { SyntaxHighlightedTextArea } from '../components/SyntaxHighlightedInput';
import SearchInput from '../components/SearchInput';
import OfflineRulesPanel from '../components/OfflineRulesPanel';
import { message as i18nMessage, translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as mutate, mutatePresentation as globalMutate } from "../lib/i18n";
import { translate, renderError } from "../lib/i18n";
import { recordTypeLabel } from "../lib/i18n";
import { errorText, metadataMessage, joinMessages } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";







export default function RulesPage() {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const isMobile = useIsMobile();
  const [openDialog, setOpenDialog] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [formData, setFormData] = useState<CreateRuleRequest>({
    name: '',
    description: '',
    type: 'TCP',
    expression: '',
    severity: 'medium',
    mitre: [],
    tags: [],
    enabled: true,
    threshold: undefined,
    thresholdWindow: undefined,
    distinctField: '',
    distinctThreshold: undefined,
    actions: [],
  });
  const [mitreInput, setMitreInput] = useState('');
  const [tagInput, setTagInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [switchingFile, setSwitchingFile] = useState(false);
  const [executingRule, setExecutingRule] = useState<string | null>(null);
  const [executingAllRules, setExecutingAllRules] = useState(false);
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [tagsExpanded, setTagsExpanded] = useState(false);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [sortBy, setSortBy] = useState<'severity' | 'enabled' | 'executionTime' | 'error' | null>(null);
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [ruleExecutionData, setRuleExecutionData] = useState<Record<string, {
    executionTimeMs: number;
    error?: UIMessageText;
    lastRun?: number;
  }>>({});
  const [errorDialogOpen, setErrorDialogOpen] = useState(false);
  const [selectedError, setSelectedError] = useState<{ ruleName: string; error: UIMessageText } | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: UIMessageText; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch rules
  const { data: rulesData, error } = useSWR('rules', () => api.getRules(), {
    refreshInterval: 5000,
  });

  const rules = rulesData?.rules || [];

  // Extract all unique tags from all rules
  const allTags = Array.from(new Set(rules.flatMap((rule) => rule.tags))).sort();

  // Handle tag query parameter from URL (e.g., coming from rule sets page)
  useEffect(() => {
    if (router.isReady && router.query.tag) {
      const tagFromQuery = router.query.tag as string;
      if (allTags.includes(tagFromQuery) && !selectedTags.includes(tagFromQuery)) {
        setSelectedTags([tagFromQuery]);
        setTagsExpanded(false);  // Collapse tags to show results directly
        // Remove the query param from URL after applying it
        router.replace?.('/rules');
      }
    }
  }, [router.isReady, router.query.tag, allTags]);

  // Filter rules by search query and selected tags (supports negation with !term)
  const filteredRules = rules.filter((rule) => {
    // Filter by search query with negation support
    if (searchQuery) {
      const searchTerms = parseSearchQuery(searchQuery);
      const matchesSearch = matchesSearchTerms([
        rule.name,
        rule.description,
        rule.expression,
        rule.severity,
        ...(rule.tags || []),
      ], searchTerms);
      if (!matchesSearch) return false;
    }
    
    // Filter by selected tags
    if (selectedTags.length > 0) {
      return selectedTags.some((tag) => rule.tags.includes(tag));
    }
    
    return true;
  });

  // Sort rules
  const sortedRules = [...filteredRules];
  if (sortBy) {
    sortedRules.sort((a, b) => {
      let comparison = 0;
      
      switch (sortBy) {
        case 'severity':
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          comparison = (severityOrder[a.severity.toLowerCase() as keyof typeof severityOrder] || 0) - 
                       (severityOrder[b.severity.toLowerCase() as keyof typeof severityOrder] || 0);
          break;
        case 'enabled':
          comparison = (a.enabled === b.enabled) ? 0 : a.enabled ? 1 : -1;
          break;
        case 'executionTime':
          const aTime = ruleExecutionData[a.id]?.executionTimeMs || 0;
          const bTime = ruleExecutionData[b.id]?.executionTimeMs || 0;
          comparison = aTime - bTime;
          break;
        case 'error':
          const aHasError = ruleExecutionData[a.id]?.error ? 1 : 0;
          const bHasError = ruleExecutionData[b.id]?.error ? 1 : 0;
          comparison = aHasError - bHasError;
          break;
      }
      
      return sortOrder === 'asc' ? comparison : -comparison;
    });
  }

  // Paginate the sorted rules
  const paginatedRules = sortedRules.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  const handleOpenDialog = (rule?: Rule) => {
    if (rule) {
      setEditingRule(rule);
      setFormData({
        name: rule.name,
        description: rule.description,
        type: rule.type,
        expression: rule.expression,
        severity: rule.severity,
        mitre: rule.mitre,
        tags: rule.tags,
        enabled: rule.enabled,
        threshold: rule.threshold,
        thresholdWindow: rule.thresholdWindow,
        distinctField: rule.distinctField,
        distinctThreshold: rule.distinctThreshold,
        actions: rule.actions || [],
      });
    } else {
      setEditingRule(null);
      setFormData({
        name: '',
        description: '',
        type: 'TCP',
        expression: '',
        severity: 'medium',
        mitre: [],
        tags: [],
        enabled: true,
        threshold: undefined,
        thresholdWindow: undefined,
        distinctField: '',
        distinctThreshold: undefined,
        actions: [],
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingRule(null);
    setMitreInput('');
    setTagInput('');
  };

  const handleSave = async () => {
    try {
      if (editingRule) {
        await api.updateRule(editingRule.id, formData as UpdateRuleRequest);
        setSnackbar({ open: true, message: i18nMessage("ui:m_809de1f4ccf68532c307"), severity: 'success' });
      } else {
        await api.createRule(formData);
        setSnackbar({ open: true, message: i18nMessage("ui:m_6549bb84db581880cf89"), severity: 'success' });
      }
      mutate('rules');
      handleCloseDialog();
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("ui:m_93793a471832e33496b0"), severity: 'error' });
    }
  };

  const handleDelete = async (ruleId: string) => {
    if (!confirm(i18nText("ui:m_384b2597f8205a8a6ead"))) return;
    
    try {
      await api.deleteRule(ruleId);
      setSnackbar({ open: true, message: i18nMessage("ui:m_ae874b4636641cae91f1"), severity: 'success' });
      mutate('rules');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("ui:m_f5401b1701c733b124c4"), severity: 'error' });
    }
  };

  const handleAddMitre = () => {
    if (mitreInput.trim() && !formData.mitre.includes(mitreInput.trim())) {
      setFormData({ ...formData, mitre: [...formData.mitre, mitreInput.trim()] });
      setMitreInput('');
    }
  };

  const handleRemoveMitre = (mitre: string) => {
    setFormData({ ...formData, mitre: formData.mitre.filter((m) => m !== mitre) });
  };

  const handleAddTag = () => {
    if (tagInput.trim() && !formData.tags.includes(tagInput.trim())) {
      setFormData({ ...formData, tags: [...formData.tags, tagInput.trim()] });
      setTagInput('');
    }
  };

  const handleRemoveTag = (tag: string) => {
    setFormData({ ...formData, tags: formData.tags.filter((t) => t !== tag) });
  };

  // Memoize event handler to prevent recreation on every render
  const handleFileChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      setSnackbar({ open: true, message: i18nMessage("ui:m_dd3e40f7911220ab0dd7", { arg0: filePath.split('/').pop() }), severity: 'success' });
    } catch (err) {
      console.error('Failed to switch file:', err);
      setSnackbar({ open: true, message: i18nMessage("ui:m_7ab800e4d59917b1d34c"), severity: 'error' });
    } finally {
      setSwitchingFile(false);
    }
  }, [mutateStatus, __uiLocale]);

  const handleExecuteRule = async (ruleId: string) => {
    if (!status?.activeInputFile) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_b59aadf6be932aff6b2b"), severity: 'error' });
      return;
    }

    setExecutingRule(ruleId);
    try {
      const result = await api.executeRule(ruleId);
      
      // Store execution data for display in table
      setRuleExecutionData(prev => ({
        ...prev,
        [ruleId]: {
          executionTimeMs: result.executionTimeMs,
          lastRun: Date.now(),
        }
      }));
      
      setSnackbar({ open: true, message: i18nMessage("ui:m_623ea698e48c29501035", { arg0: result.alertsCount, arg1: result.recordsRead, arg2: result.executionTimeMs }), severity: 'success' });
      
      // Refresh alerts to show new ones
      await globalMutate('alertStats');
    } catch (err) {
      // Store error for display in table
      setRuleExecutionData(prev => ({
        ...prev,
        [ruleId]: {
          executionTimeMs: 0,
          error: err instanceof Error ? errorText(err) : i18nMessage('ui:m_7b41bfb23e0b222578aa'),
          lastRun: Date.now(),
        }
      }));
      
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("ui:m_7b41bfb23e0b222578aa"), severity: 'error' });
    } finally {
      setExecutingRule(null);
    }
  };

  const handleExecuteAllRules = async () => {
    if (!status?.activeInputFile) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_b59aadf6be932aff6b2b"), severity: 'error' });
      return;
    }

    const enabledCount = rules.filter(r => r.enabled).length;
    if (enabledCount === 0) {
      setSnackbar({ open: true, message: i18nMessage("ui:m_28fb785c8899fb21fd91"), severity: 'error' });
      return;
    }

    setExecutingAllRules(true);
    try {
      const result = await api.executeAllRules();
      
      // Store execution data per rule
      const newExecutionData: Record<string, { executionTimeMs: number; error?: UIMessageText; lastRun: number }> = {};
      for (const ruleResult of result.ruleResults) {
        newExecutionData[ruleResult.ruleName] = {
          executionTimeMs: ruleResult.executionTimeMs,
          error: metadataMessage(ruleResult, 'error'),
          lastRun: Date.now(),
        };
      }
      setRuleExecutionData(newExecutionData);
      
      // Show summary message
      const failedRules = result.ruleResults.filter(r => !r.success);
      const summary = i18nMessage("ui:m_1623bcad249f81799c64", { arg0: metadataMessage(result, 'message'), arg1: result.executionTimeMs });
      const summaryMessage = failedRules.length
        ? joinMessages([summary, i18nMessage('ui:rules.failedCount', { count: failedRules.length })], ' - ')
        : summary;
      
      setSnackbar({ open: true, message: summaryMessage, severity: failedRules.length > 0 ? 'error' : 'success' });
      
      // Refresh alerts to show new ones
      await globalMutate('alertStats');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("ui:m_f5671b434db8d6900157"), severity: 'error' });
    } finally {
      setExecutingAllRules(false);
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

  const handleSort = (column: 'severity' | 'enabled' | 'executionTime' | 'error') => {
    if (sortBy === column) {
      // Toggle sort order if clicking the same column
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new column and default to ascending
      setSortBy(column);
      setSortOrder('asc');
    }
  };

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  // Reset page to 0 when search query or selected tags change
  useEffect(() => {
    setPage(0);
  }, [searchQuery, selectedTags]);

  // Get only completed files for the selector
  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_bea0066334604c21d3e0")} />
  );

  return (
    <Layout title={i18nText("ui:m_a6abc207b58ddbf5f8bf")} headerAction={fileSelector}><Box><OfflineRulesPanel status={status} /><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}><Typography variant="body2" color="text.secondary">
            {i18nRichText("ui:m_e6698a56358cd1d80d90", { arg0: rules.length, arg2: rules.filter(r => r.enabled).length })}
          </Typography><Box sx={{ display: 'flex', gap: 1 }}><Button data-learn={i18nText("ui:m_99348b55e9b07f9820cf")}
              variant="outlined"
              color="success"
              startIcon={executingAllRules ? <CircularProgress size={20} /> : <PlayArrowIcon />}
              onClick={handleExecuteAllRules}
              disabled={executingAllRules || !status?.activeInputFile || rules.filter(r => r.enabled).length === 0}>{executingAllRules ? i18nText("ui:m_7b608bec5b5cf9cae5cb") : i18nText("ui:m_cd31817446589ecf9e60")}</Button><Button data-learn={i18nText("ui:m_b9d6d275c74f2050d6a6")}
              variant="contained"
              color="primary"
              startIcon={<AddIcon />}
              onClick={() => handleOpenDialog()}>
              {i18nText("ui:m_547415eac67b0ddf2af6")}
            </Button></Box></Box>{/* Search Input */}<Box sx={{ mb: 3, display: 'flex', flexDirection: 'column', gap: 0.5 }}><SearchInput value={searchQuery}
            onChange={setSearchQuery}
            placeholder={i18nText("ui:m_bc23905fb65d891e6407")}
            learnHint={translate("ui:m_6852bc13f0df12576ff5")}
            sx={{ width: '100%' }} />{searchQuery && (
            <Typography variant="caption" color="text.secondary">
              {i18nRichText("ui:m_cbadba89a9889143602c", { arg0: filteredRules.length, arg2: searchQuery })}
            </Typography>
          )}</Box>{/* Tag Filter */}{allTags.length > 0 && (
          <Box sx={{ mb: 3 }}><Box sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }} onClick={() => setTagsExpanded(!tagsExpanded)}><Typography variant="subtitle2">
                {i18nText("ui:m_e63ed7e1a5ce36d58ac2")}
              </Typography><IconButton size="small" sx={{ ml: 0.5 }}>{tagsExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}</IconButton><Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                {i18nRichText("ui:m_68a1eae685401c7894b8", { arg0: allTags.length, arg1: selectedTags.length > 0 ? i18nText("ui:m_8d31103e0a3566a533c4", { arg0: selectedTags.length }) : '' })}
              </Typography></Box>{tagsExpanded && (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>{allTags.map((tag) => (
                  <Chip key={tag}
                    label={tag}
                    color={selectedTags.includes(tag) ? 'primary' : 'default'}
                    onClick={() => {
                      setSelectedTags((prev) =>
                        prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]
                      );
                    }}
                    variant={selectedTags.includes(tag) ? 'filled' : 'outlined'} />
                ))}{selectedTags.length > 0 && (
                  <Chip label={i18nText("ui:m_0cb3d73ec88de1474e7b")}
                    color="secondary"
                    onClick={() => setSelectedTags([])}
                    variant="outlined" />
                )}</Box>
            )}{(selectedTags.length > 0 || searchQuery) && (
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                {i18nRichText("ui:m_0deabc2da7f12ff2a1ac", { arg0: filteredRules.length, arg1: rules.length, arg2: selectedTags.length > 0 && i18nText("ui:m_4aa8099fdde1ce04365d", { arg0: selectedTags.length }), arg3: searchQuery && i18nText("ui:m_47bcfd5611a30782ba97", { arg0: searchQuery }) })}
              </Typography>
            )}</Box>
        )}{error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {i18nRichText("ui:m_a2dd36495062693ce248", { arg0: renderError(error) })}
          </Alert>
        )}<TableContainer component={Paper} sx={{ mt: 3 }}><Table><TableHead><TableRow><TableCell>{i18nText("ui:m_e707e3dfaa88e6753600")}</TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>{i18nText("ui:m_3da346bd3b7d84ce65d6")}</TableCell><TableCell><TableSortLabel active={sortBy === 'severity'}
                    direction={sortBy === 'severity' ? sortOrder : 'asc'}
                    onClick={() => handleSort('severity')}>
                    {i18nText("ui:m_d1de98cbf475009ee57d")}
                  </TableSortLabel></TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>{i18nText("ui:m_a5c510d332d1b044bf9a")}</TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>{i18nText("ui:m_47846a266ab7374ce1aa")}</TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}><TableSortLabel active={sortBy === 'enabled'}
                    direction={sortBy === 'enabled' ? sortOrder : 'asc'}
                    onClick={() => handleSort('enabled')}>
                    {i18nText("ui:m_23052c4fec9eb3ac70e9")}
                  </TableSortLabel></TableCell><TableCell align="right"><TableSortLabel active={sortBy === 'executionTime'}
                    direction={sortBy === 'executionTime' ? sortOrder : 'asc'}
                    onClick={() => handleSort('executionTime')}>
                    {i18nText("ui:m_9777689642640ff1e001")}
                  </TableSortLabel></TableCell><TableCell align="center"><TableSortLabel active={sortBy === 'error'}
                    direction={sortBy === 'error' ? sortOrder : 'asc'}
                    onClick={() => handleSort('error')}>
                    {i18nText("ui:m_f87e14c01921623b1b00")}
                  </TableSortLabel></TableCell><TableCell align="right">{i18nText("ui:m_8b59af6a47204b74041c")}</TableCell><TableCell align="right">{i18nText("ui:m_ec286449beb2d40913b2")}</TableCell></TableRow></TableHead><TableBody>{filteredRules.length === 0 ? (
                <TableRow><TableCell colSpan={10} align="center"><Typography variant="body2" color="text.secondary">{rules.length === 0 ? i18nText("ui:m_d0ae9690619d668afe1d") : i18nText("ui:m_28906e3b7d0f0dea0c10")}</Typography></TableCell></TableRow>
              ) : (
                paginatedRules.map((rule) => (
                  <TableRow key={rule.id} 
                    hover
                    onClick={() => handleOpenDialog(rule)}
                    sx={{ cursor: 'pointer' }}><TableCell><Box><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Typography variant="body1" fontWeight="medium">{rule.name}</Typography>{(rule.distinctField || (rule.threshold && rule.threshold > 0)) && (
                            <Tooltip title={rule.distinctField ? i18nText("ui:m_ed12d4537a74a15c1a45", { arg0: Math.max(2, rule.distinctThreshold || 2), arg1: rule.distinctField, arg2: rule.thresholdWindow || 60 }) : i18nText("ui:m_ac22d2cf75bbd7baa126", { arg0: rule.threshold, arg1: rule.thresholdWindow || 60 })}><Chip label={i18nText("ui:m_023cfbe2165f816ad207")} 
                                size="small" 
                                color="info" 
                                variant="outlined"
                                sx={{ height: 20, fontSize: '0.7rem' }} /></Tooltip>
                          )}{rule.actions && rule.actions.length > 0 && (
                            <Tooltip title={i18nText("ui:m_bbb04c58dfa37cb42973", { arg0: rule.actions.map(a => a.type.replace('iptables_', '')).join(', ') })}><Chip icon={<SecurityIcon sx={{ fontSize: '0.9rem !important' }} />}
                                label={rule.actions.length} 
                                size="small" 
                                color="error" 
                                variant="outlined"
                                sx={{ height: 20, fontSize: '0.7rem' }} /></Tooltip>
                          )}</Box>{/* <Typography variant="caption" color="text.secondary">
                          {rule.description}
                        </Typography> */}</Box></TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Chip label={recordTypeLabel(rule.type)} size="small" variant="outlined" /></TableCell><TableCell><Chip label={rule.severity.toUpperCase()}
                        size="small"
                        color={getSeverityColor(rule.severity) as any} /></TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}><Tooltip title={rule.expression}><Box><FilterExpressionInline expression={rule.expression} maxWidth={300} /></Box></Tooltip></TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{rule.tags.map((tag) => (
                          <Chip key={tag} label={tag} size="small" />
                        ))}</Box></TableCell><TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}><Chip label={rule.enabled ? i18nText("ui:m_23052c4fec9eb3ac70e9") : i18nText("ui:m_5e51003ed903b62900ec")}
                        size="small"
                        color={rule.enabled ? 'success' : 'default'} /></TableCell><TableCell align="right">{ruleExecutionData[rule.name] ? (
                        <Typography variant="body2" color="text.secondary">{ruleExecutionData[rule.name].executionTimeMs}ms
                        </Typography>
                      ) : rule.executionTimeMs ? (
                        <Typography variant="body2" color="text.secondary">{rule.executionTimeMs}ms
                        </Typography>
                      ) : (
                        <Typography variant="body2" color="text.disabled">-
                        </Typography>
                      )}</TableCell><TableCell align="center">{ruleExecutionData[rule.name]?.error ? (
                        <Tooltip title={i18nText("ui:m_a2faa7069a817b740ab8")}><IconButton size="small" 
                            color="error"
                            onClick={() => {
                              setSelectedError({
                                ruleName: rule.name,
                                error: ruleExecutionData[rule.name].error || i18nMessage("ui:m_3f0f714149c18490a32b")
                              });
                              setErrorDialogOpen(true);
                            }}><ErrorIcon /></IconButton></Tooltip>
                      ) : ruleExecutionData[rule.name] ? (
                        <Chip label={i18nText("ui:m_18a168caf537c3f7737b")} size="small" color="success" />
                      ) : (
                        <Typography variant="body2" color="text.disabled">-
                        </Typography>
                      )}</TableCell><TableCell align="right"><Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'flex-end' }}><IconButton data-learn={i18nText("ui:m_9118ce87842de3dac3a1")} 
                          size="small" 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDialog(rule);
                          }} 
                          color="primary"><EditIcon /></IconButton><IconButton data-learn={i18nText("ui:m_0c247f766d610e087f02")} 
                          size="small" 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDelete(rule.id);
                          }} 
                          color="error"><DeleteIcon /></IconButton></Box></TableCell><TableCell align="right"><Tooltip title={i18nText("ui:m_977bd98675a19d9d0f5e")}><span><IconButton data-learn={i18nText("ui:m_44288451b64a5e152589")}
                            size="small" 
                            onClick={(e) => {
                              e.stopPropagation();
                              handleExecuteRule(rule.id);
                            }} 
                            color="success"
                            disabled={!rule.enabled || executingRule === rule.id || !status?.activeInputFile}>{executingRule === rule.id ? (
                              <CircularProgress size={20} />
                            ) : (
                              <PlayArrowIcon />
                            )}</IconButton></span></Tooltip></TableCell></TableRow>
                ))
              )}</TableBody></Table><TablePagination rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={filteredRules.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage} /></TableContainer>{/* Rule Dialog */}<Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">{editingRule ? i18nText("ui:m_1f057b63cb42262e8576") : i18nText("ui:m_e8835d94e4ac919af501")}{isMobile && (
                <IconButton onClick={handleCloseDialog} edge="end"><CloseIcon /></IconButton>
              )}</Box></DialogTitle><DialogContent><Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}><TextField label={i18nText("ui:m_752576a3b0b2dca4ab6a")}
                fullWidth
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                helperText={i18nText("ui:m_5cce691a40a9153b4fc0")} /><TextField label={i18nText("ui:m_a02602e322c10d1a5449")}
                fullWidth
                multiline
                rows={2}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                helperText={i18nText("ui:m_e2e468d98eff9344c2f2")} /><FormControl fullWidth required><InputLabel>{i18nText("ui:m_21e984a0c1b0479051bc")}</InputLabel><Select value={formData.type}
                  label={i18nText("ui:m_21e984a0c1b0479051bc")}
                  onChange={(e) => setFormData({ ...formData, type: e.target.value })}><MenuItem value="Alert">{i18nText("ui:m_b3a9d5ac5b220ce3d1df")}</MenuItem><MenuItem value="ARP">ARP</MenuItem><MenuItem value="BACnetIP">{i18nText("ui:m_98e5b0ca9c053e8c00da")}</MenuItem><MenuItem value="BFD">{i18nText("ui:m_9aa148318228f048dd59")}</MenuItem><MenuItem value="BGP">{i18nText("ui:m_728c9086365a22db41dd")}</MenuItem><MenuItem value="CIP">{i18nText("ui:m_fb72f7431fc9a425aa6d")}</MenuItem><MenuItem value="CiscoDiscovery">{i18nText("ui:m_91be825836bcbc376aad")}</MenuItem><MenuItem value="Connection">{i18nText("ui:m_6e3eaaf519e2d29c1f65")}</MenuItem><MenuItem value="Secret">{i18nText("ui:m_cfc0bf0f6fd46e6edf26")}</MenuItem><MenuItem value="DeviceProfile">{i18nText("ui:m_a72bf176a07d89d561e2")}</MenuItem><MenuItem value="DHCPv4">{i18nText("ui:m_e9b559684a422a78ef4e")}</MenuItem><MenuItem value="DHCPv6">{i18nText("ui:m_9920adcc450807b016dc")}</MenuItem><MenuItem value="Diameter">{i18nText("ui:m_59662f95057dd5009c3b")}</MenuItem><MenuItem value="DNS">DNS</MenuItem><MenuItem value="DNP3">{i18nText("ui:m_241ea6e69aea860ab57a")}</MenuItem><MenuItem value="Dot11">{i18nText("ui:m_fea2e3af72609dad0c98")}</MenuItem><MenuItem value="Dot1Q">{i18nText("ui:m_66cb204b1b86b4cd5c93")}</MenuItem><MenuItem value="EAP">{i18nText("ui:m_ff70f3812795fd3c30f3")}</MenuItem><MenuItem value="EAPOL">{i18nText("ui:m_83957389ef9226cbaa30")}</MenuItem><MenuItem value="EAPOLKey">{i18nText("ui:m_fb20fdf3b72bbfb75e83")}</MenuItem><MenuItem value="ENIP">{i18nText("ui:m_e6ab639f5bcf2cc924ae")}</MenuItem><MenuItem value="Ethernet">{i18nText("ui:m_2791087a36aa29c47d91")}</MenuItem><MenuItem value="EthernetCTP">{i18nText("ui:m_38be303adfee2ca6783c")}</MenuItem><MenuItem value="EthernetCTPReply">{i18nText("ui:m_8e92d2a6b5f43520f851")}</MenuItem><MenuItem value="Exploit">{i18nText("ui:m_d4abed4a6af1130e1735")}</MenuItem><MenuItem value="FDDI">{i18nText("ui:m_58b530fec2cf6834cc98")}</MenuItem><MenuItem value="File">{i18nText("ui:m_de894275a403ef797d92")}</MenuItem><MenuItem value="FTP">FTP</MenuItem><MenuItem value="Geneve">{i18nText("ui:m_b0ffc15a10c85970a53a")}</MenuItem><MenuItem value="PKTAP">{i18nText("ui:m_607c02b7474f0104768f")}</MenuItem><MenuItem value="TLSRecord">{i18nText("ui:m_db50fe3dc450b2f1581e")}</MenuItem><MenuItem value="GRE">GRE</MenuItem><MenuItem value="GTP">GTP</MenuItem><MenuItem value="HTTP">HTTP</MenuItem><MenuItem value="ICMPv4">{i18nText("ui:m_7e3752209583fe744c65")}</MenuItem><MenuItem value="ICMPv6">ICMPv6</MenuItem><MenuItem value="ICMPv6Echo">{i18nText("ui:m_0246db9b4eb8aad97318")}</MenuItem><MenuItem value="ICMPv6NeighborAdvertisement">{i18nText("ui:m_ef0ab159c5c1b59ba087")}</MenuItem><MenuItem value="ICMPv6NeighborSolicitation">{i18nText("ui:m_9c2b4e92f076d09034a2")}</MenuItem><MenuItem value="ICMPv6RouterAdvertisement">{i18nText("ui:m_01a7a086e7e255496044")}</MenuItem><MenuItem value="ICMPv6RouterSolicitation">{i18nText("ui:m_e44b677d898fb2c0189a")}</MenuItem><MenuItem value="IEC62351">{i18nText("ui:m_db617ad336816680bb6d")}</MenuItem><MenuItem value="IGMP">{i18nText("ui:m_0243721196cd1cce1143")}</MenuItem><MenuItem value="IMAP">IMAP</MenuItem><MenuItem value="Host">{i18nText("ui:m_d36e3ee418e39309c3c7")}</MenuItem><MenuItem value="IRC">{i18nText("ui:m_c5faa71c567c7657640c")}</MenuItem><MenuItem value="IPSecAH">{i18nText("ui:m_4663aa57b4246fb145fa")}</MenuItem><MenuItem value="IPSecESP">{i18nText("ui:m_9b4b071b8915396f4ca5")}</MenuItem><MenuItem value="IPv4">IPv4</MenuItem><MenuItem value="IPv6">IPv6</MenuItem><MenuItem value="IPv6Fragment">{i18nText("ui:m_e9661e1588984525c32e")}</MenuItem><MenuItem value="IPv6HopByHop">{i18nText("ui:m_14d3a3af33104ca622cc")}</MenuItem><MenuItem value="LCM">{i18nText("ui:m_ba21929b889c9b40136a")}</MenuItem><MenuItem value="LinkLayerDiscovery">{i18nText("ui:m_253036d003d48d2c6921")}</MenuItem><MenuItem value="LinkLayerDiscoveryInfo">{i18nText("ui:m_f6146a8d4a2fa6c403ec")}</MenuItem><MenuItem value="LLC">{i18nText("ui:m_37be9cdfdff66eb71f95")}</MenuItem><MenuItem value="Mail">{i18nText("ui:m_53ea46a0ea3402094b6c")}</MenuItem><MenuItem value="Modbus">{i18nText("ui:m_c9ab8220b225bdd502d9")}</MenuItem><MenuItem value="MPLS">MPLS</MenuItem><MenuItem value="MQTTSN">{i18nText("ui:m_9e10255a4d697cbfa3d1")}</MenuItem><MenuItem value="NortelDiscovery">{i18nText("ui:m_cd90eb231300b3fff014")}</MenuItem><MenuItem value="NTP">NTP</MenuItem><MenuItem value="OPCUA">{i18nText("ui:m_3e3c63f67db62cb01da9")}</MenuItem><MenuItem value="OSPFv2">{i18nText("ui:m_645051a16d39de2072e0")}</MenuItem><MenuItem value="OSPFv3">{i18nText("ui:m_0d72257f29beac184598")}</MenuItem><MenuItem value="POP3">POP3</MenuItem><MenuItem value="PPP">{i18nText("ui:m_a8c335a6fd13e3bf414c")}</MenuItem><MenuItem value="PPPoE">{i18nText("ui:m_755df67794d179058dd1")}</MenuItem><MenuItem value="PROFINET">{i18nText("ui:m_83c209a923bd89fe5b65")}</MenuItem><MenuItem value="Radius">{i18nText("ui:m_4402d6fbf3547df0df64")}</MenuItem><MenuItem value="RDP">RDP</MenuItem><MenuItem value="RMCP">{i18nText("ui:m_678e8e552276c2229700")}</MenuItem><MenuItem value="S7Comm">{i18nText("ui:m_f12f4b80888133995cb3")}</MenuItem><MenuItem value="SCTP">{i18nText("ui:m_6c64024b1e0c10bb1481")}</MenuItem><MenuItem value="Service">{i18nText("ui:m_e1d47e59dd85d4abaa0f")}</MenuItem><MenuItem value="SIP">SIP</MenuItem><MenuItem value="SMTP">SMTP</MenuItem><MenuItem value="SMB">SMB</MenuItem><MenuItem value="SNAP">{i18nText("ui:m_a47455e3571110189d60")}</MenuItem><MenuItem value="SOCKS">{i18nText("ui:m_a989dfe6d1912f90b8d6")}</MenuItem><MenuItem value="Software">{i18nText("ui:m_99c431556bb898cfc4c6")}</MenuItem><MenuItem value="SSH">SSH</MenuItem><MenuItem value="STP">{i18nText("ui:m_0a0b5c65ac75a6054183")}</MenuItem><MenuItem value="Syslog">{i18nText("ui:m_23976cdf5b50b39ba904")}</MenuItem><MenuItem value="TCP">TCP</MenuItem><MenuItem value="TLSClientHello">{i18nText("ui:m_5d975d7f386d49c77568")}</MenuItem><MenuItem value="TLSServerHello">{i18nText("ui:m_66db27f1f4e345662f82")}</MenuItem><MenuItem value="UDP">UDP</MenuItem><MenuItem value="USB">{i18nText("ui:m_1361f6ada5ae79fc78e0")}</MenuItem><MenuItem value="USBRequestBlockSetup">{i18nText("ui:m_2c5d4565cdd1126ef246")}</MenuItem><MenuItem value="VRRPv2">{i18nText("ui:m_c815eea5ca5bea2e40f4")}</MenuItem><MenuItem value="Vulnerability">{i18nText("ui:m_0e9cf825d60a59ff26c7")}</MenuItem><MenuItem value="VXLAN">VXLAN</MenuItem></Select></FormControl><SyntaxHighlightedTextArea syntaxType="filter"
                value={formData.expression}
                onChange={(value) => setFormData({ ...formData, expression: value })}
                label={i18nText("ui:m_a5c510d332d1b044bf9a")}
                helperText={i18nText("ui:m_bbad6b9f87c0e32c9140")}
                rows={4}
                fullWidth /><FormControl fullWidth required><InputLabel>{i18nText("ui:m_d1de98cbf475009ee57d")}</InputLabel><Select value={formData.severity}
                  label={i18nText("ui:m_d1de98cbf475009ee57d")}
                  onChange={(e) => setFormData({ ...formData, severity: e.target.value })}><MenuItem value="info">{i18nText("ui:m_e23ead341eca901e52be")}</MenuItem><MenuItem value="low">{i18nText("ui:m_f421fc8ad1242ca9d49f")}</MenuItem><MenuItem value="medium">{i18nText("ui:m_793aaa27ac92c4e93090")}</MenuItem><MenuItem value="high">{i18nText("ui:m_222fd33d915d779d6af3")}</MenuItem><MenuItem value="critical">{i18nText("ui:m_fa8cf458bd646a3d049e")}</MenuItem></Select></FormControl><Box><Typography variant="subtitle2" gutterBottom>
                  {i18nText("ui:m_13861898d75220f91f6c")}
                </Typography><Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                  {i18nText("ui:m_b2b2eff26d55d474c150")}
                </Typography><Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, gap: 2, mt: 1 }}><TextField label={i18nText("ui:m_5266ad7c59f9dbdb16b4")}
                    disabled={!!formData.distinctField}
                    type="number"
                    size="small"
                    value={formData.threshold || ''}
                    onChange={(e) => {
                      const val = e.target.value ? parseInt(e.target.value) : undefined;
                      setFormData({ ...formData, threshold: val });
                    }}
                    helperText={i18nText("ui:m_3886ac5ea3abec8568d2")}
                    InputProps={{
                      inputProps: { min: 0 }
                    }}
                    sx={{ flex: 1 }} /><TextField label={i18nText("ui:m_17ef7272cbeb207fc7a6")}
                    type="number"
                    size="small"
                    value={formData.thresholdWindow || ''}
                    onChange={(e) => {
                      const val = e.target.value ? parseInt(e.target.value) : undefined;
                      setFormData({ ...formData, thresholdWindow: val });
                    }}
                    helperText={i18nText("ui:m_a5302bbd14979e8f4ea0")}
                    InputProps={{
                      inputProps: { min: 0 }
                    }}
                    sx={{ flex: 1 }} /></Box><Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, gap: 2, mt: 2 }}><TextField label={i18nText("ui:m_2d6cafd988c27a1fa410")}
                    size="small"
                    value={formData.distinctField || ''}
                    onChange={(e) => setFormData({ ...formData, distinctField: e.target.value })}
                    helperText={i18nText("ui:m_0b7d8f8dd3d434a0efa7")}
                    sx={{ flex: 1 }} /><TextField label={i18nText("ui:m_74d6b2c62fb2f34a2706")}
                    type="number"
                    size="small"
                    value={formData.distinctThreshold ?? ''}
                    onChange={(e) => setFormData({ ...formData, distinctThreshold: e.target.value ? parseInt(e.target.value) : undefined })}
                    helperText={i18nText("ui:m_c6ef80535bc345634e0a")}
                    InputProps={{ inputProps: { min: 0 } }}
                    sx={{ flex: 1 }} /></Box></Box><Box><Typography variant="subtitle2" gutterBottom>
                  {i18nText("ui:m_2e16e88761eb4368b1cd")}
                </Typography><Box sx={{ display: 'flex', gap: 1, mb: 1 }}><TextField size="small"
                    fullWidth
                    placeholder={i18nText("ui:m_55428f113e50cb4d55be")}
                    value={mitreInput}
                    onChange={(e) => setMitreInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddMitre();
                      }
                    }} /><Button data-learn={i18nText("ui:m_6d1fa6f2efc562a8c400")} variant="outlined" onClick={handleAddMitre}>
                    {i18nText("ui:m_44184266e152017ac805")}
                  </Button></Box><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{formData.mitre.map((mitre) => (
                    <Chip key={mitre}
                      label={mitre}
                      onDelete={() => handleRemoveMitre(mitre)}
                      size="small" />
                  ))}</Box></Box><Box><Typography variant="subtitle2" gutterBottom>
                  {i18nText("ui:m_47846a266ab7374ce1aa")}
                </Typography><Box sx={{ display: 'flex', gap: 1, mb: 1 }}><TextField size="small"
                    fullWidth
                    placeholder={i18nText("ui:m_7e25865a709ae1611427")}
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddTag();
                      }
                    }} /><Button data-learn={i18nText("ui:m_16802ff30802f2605ac8")} variant="outlined" onClick={handleAddTag}>
                    {i18nText("ui:m_44184266e152017ac805")}
                  </Button></Box><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{formData.tags.map((tag) => (
                    <Chip key={tag} label={tag} onDelete={() => handleRemoveTag(tag)} size="small" />
                  ))}</Box></Box>{/* Response Actions Section */}<Box sx={{ 
                border: '1px solid', 
                borderColor: 'divider', 
                borderRadius: 1, 
                p: 2,
                bgcolor: 'background.default'
              }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}><SecurityIcon color="primary" /><Typography variant="subtitle1" fontWeight="medium">
                    {i18nText("ui:m_3a5cbb0fec62a31971a3")}
                  </Typography><Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                    {i18nText("ui:m_6f91dc7604905f998fca")}
                  </Typography></Box><Typography variant="body2" color="text.secondary" gutterBottom>
                  {i18nText("ui:m_8afe3417f6de353e9eb2")}
                </Typography>{/* Existing Actions */}{(formData.actions || []).map((action, index) => (
                  <Card key={index} variant="outlined" sx={{ mt: 2, bgcolor: 'background.paper' }}><CardContent sx={{ pb: '16px !important' }}><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><BlockIcon color={action.enabled !== false ? 'error' : 'disabled'} fontSize="small" /><Typography variant="subtitle2">{action.type.replace('iptables_', '').replace('_', ' ').toUpperCase()}</Typography><Chip label={action.enabled !== false ? i18nText("ui:m_23052c4fec9eb3ac70e9") : i18nText("ui:m_5e51003ed903b62900ec")} 
                            size="small" 
                            color={action.enabled !== false ? 'success' : 'default'} /></Box><IconButton size="small" 
                          color="error"
                          onClick={() => {
                            const newActions = [...(formData.actions || [])];
                            newActions.splice(index, 1);
                            setFormData({ ...formData, actions: newActions });
                          }}><DeleteIcon fontSize="small" /></IconButton></Box><Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}><FormControl size="small" sx={{ minWidth: 150 }}><InputLabel>{i18nText("ui:m_2a4239d0a517269d853e")}</InputLabel><Select value={action.type}
                            label={i18nText("ui:m_2a4239d0a517269d853e")}
                            onChange={(e) => {
                              const newActions = [...(formData.actions || [])];
                              newActions[index] = { ...action, type: e.target.value as ResponseAction['type'] };
                              setFormData({ ...formData, actions: newActions });
                            }}><MenuItem value="iptables_block">{i18nText("ui:m_bae58943a4d16cb6ae02")}</MenuItem><MenuItem value="iptables_reject">{i18nText("ui:m_002039ffb74ecbca4178")}</MenuItem><MenuItem value="iptables_log">{i18nText("ui:m_bbdab175248d8e90a352")}</MenuItem><MenuItem value="iptables_rate_limit">{i18nText("ui:m_c032f41302d836e12d44")}</MenuItem></Select></FormControl>{(action.type === 'iptables_block' || action.type === 'iptables_reject') && (
                          <><FormControl size="small" sx={{ minWidth: 130 }}><InputLabel>{i18nText("ui:m_7a7c4ee691dac0ada303")}</InputLabel><Select value={action.config?.target || 'source'}
                                label={i18nText("ui:m_7a7c4ee691dac0ada303")}
                                onChange={(e) => {
                                  const newActions = [...(formData.actions || [])];
                                  newActions[index] = { 
                                    ...action, 
                                    config: { ...action.config, target: e.target.value as 'source' | 'destination' }
                                  };
                                  setFormData({ ...formData, actions: newActions });
                                }}><MenuItem value="source">{i18nText("ui:m_e540837f52427c6b32ef")}</MenuItem><MenuItem value="destination">{i18nText("ui:m_d0c510489f3705429ca7")}</MenuItem></Select></FormControl><TextField size="small"
                              label={i18nText("ui:m_9777689642640ff1e001")}
                              placeholder={i18nText("ui:m_016d74a2d4d24c314bfd")}
                              value={action.config?.duration || ''}
                              onChange={(e) => {
                                const newActions = [...(formData.actions || [])];
                                newActions[index] = { 
                                  ...action, 
                                  config: { ...action.config, duration: e.target.value }
                                };
                                setFormData({ ...formData, actions: newActions });
                              }}
                              sx={{ width: 130 }}
                              helperText={i18nText("ui:m_c983a3cf96f98ceda39d")} /></>
                        )}{action.type === 'iptables_log' && (
                          <TextField size="small"
                            label={i18nText("ui:m_ca74d66d79223a6dff7f")}
                            placeholder={i18nText("ui:m_c35639d02caabdfed66e")}
                            value={action.config?.prefix || ''}
                            onChange={(e) => {
                              const newActions = [...(formData.actions || [])];
                              newActions[index] = { 
                                ...action, 
                                config: { ...action.config, prefix: e.target.value }
                              };
                              setFormData({ ...formData, actions: newActions });
                            }}
                            sx={{ width: 200 }} />
                        )}{action.type === 'iptables_rate_limit' && (
                          <><TextField size="small"
                              label={i18nText("ui:m_6aa28c30f636a1c44437")}
                              placeholder={i18nText("ui:m_270a8402603a44bbede2")}
                              value={action.config?.rate || ''}
                              onChange={(e) => {
                                const newActions = [...(formData.actions || [])];
                                newActions[index] = { 
                                  ...action, 
                                  config: { ...action.config, rate: e.target.value }
                                };
                                setFormData({ ...formData, actions: newActions });
                              }}
                              sx={{ width: 130 }} /><TextField size="small"
                              label={i18nText("ui:m_883129f97c895be05fc1")}
                              type="number"
                              value={action.config?.burst || ''}
                              onChange={(e) => {
                                const newActions = [...(formData.actions || [])];
                                newActions[index] = { 
                                  ...action, 
                                  config: { ...action.config, burst: parseInt(e.target.value) || undefined }
                                };
                                setFormData({ ...formData, actions: newActions });
                              }}
                              sx={{ width: 100 }}
                              InputProps={{ inputProps: { min: 1 } }} /></>
                        )}<FormControlLabel control={<Switch size="small"
                              checked={action.enabled !== false}
                              onChange={(e) => {
                                const newActions = [...(formData.actions || [])];
                                newActions[index] = { ...action, enabled: e.target.checked };
                                setFormData({ ...formData, actions: newActions });
                              }} />}
                          label={i18nText("ui:m_32854ec0180ee3fbf4f7")} /></Box></CardContent></Card>
                ))}{/* Add Action Button */}<Button variant="outlined"
                  size="small"
                  startIcon={<AddIcon />}
                  sx={{ mt: 2 }}
                  onClick={() => {
                    const newAction: ResponseAction = {
                      type: 'iptables_block',
                      config: { target: 'source', duration: '30m' },
                      enabled: true,
                    };
                    setFormData({ 
                      ...formData, 
                      actions: [...(formData.actions || []), newAction] 
                    });
                  }}>
                  {i18nText("ui:m_922580aaf366d5f385c2")}
                </Button>{(formData.actions || []).length === 0 && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                    {i18nText("ui:m_1448350dabf6a73cf4f0")}
                  </Typography>
                )}</Box><FormControlLabel control={<Switch checked={formData.enabled}
                    onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })} />}
                label={i18nText("ui:m_b03a203cf0357413cb65")} /></Box></DialogContent><DialogActions><Button data-learn={i18nText("ui:m_8085c11b03f4cc992297")} onClick={handleCloseDialog}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button data-learn={i18nText("ui:m_06889553e574cd7e53bc")}
              onClick={handleSave}
              variant="contained"
              disabled={!formData.name || !formData.type || !formData.expression || !formData.severity}>{editingRule ? i18nText("ui:m_6adbe4e719554c8ff213") : i18nText("ui:m_a09c62c4acf8363f90e2")}</Button></DialogActions></Dialog>{/* Error Details Dialog */}<Dialog open={errorDialogOpen}
          onClose={() => setErrorDialogOpen(false)}
          maxWidth="md"
          fullWidth
          fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center"><Box display="flex" alignItems="center" gap={1}><ErrorIcon color="error" />
                {i18nText("ui:m_b234b373492288ad64ee")}
              </Box>{isMobile && (
                <IconButton onClick={() => setErrorDialogOpen(false)} edge="end"><CloseIcon /></IconButton>
              )}</Box></DialogTitle><DialogContent>{selectedError && (
              <Box><Typography variant="subtitle2" gutterBottom>
                  {i18nRichText("ui:m_12d9a0c30c4fa90b6958", { arg0: selectedError.ruleName })}
                </Typography><Box sx={{ 
                    mt: 2, 
                    p: 2, 
                    bgcolor: 'error.main',
                    color: 'error.contrastText',
                    borderRadius: 1,
                    fontFamily: 'monospace',
                    fontSize: '0.9rem',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word'
                  }}>{i18nRenderText(selectedError.error)}</Box></Box>
            )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_10126e26ffc19adfd8d7")} onClick={() => setErrorDialogOpen(false)}>{i18nText("ui:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog>{/* Snackbar for notifications */}<Snackbar open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}><Alert onClose={() => setSnackbar({ ...snackbar, open: false })}
            severity={snackbar.severity}
            sx={{ width: '100%' }}>{i18nRenderText(snackbar.message)}</Alert></Snackbar></Box></Layout>
  );
}
