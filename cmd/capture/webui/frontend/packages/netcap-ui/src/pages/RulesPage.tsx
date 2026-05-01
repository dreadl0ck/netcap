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
import useSWR, { mutate, mutate as globalMutate } from 'swr';
import { FilterExpressionInline, FilterExpressionBlock } from '../components/FilterExpressionHighlight';
import { SyntaxHighlightedTextArea } from '../components/SyntaxHighlightedInput';
import SearchInput from '../components/SearchInput';

export default function RulesPage() {
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
    error?: string;
    lastRun?: number;
  }>>({});
  const [errorDialogOpen, setErrorDialogOpen] = useState(false);
  const [selectedError, setSelectedError] = useState<{ ruleName: string; error: string } | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
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
        setSnackbar({ open: true, message: 'Rule updated successfully', severity: 'success' });
      } else {
        await api.createRule(formData);
        setSnackbar({ open: true, message: 'Rule created successfully', severity: 'success' });
      }
      mutate('rules');
      handleCloseDialog();
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Failed to save rule', severity: 'error' });
    }
  };

  const handleDelete = async (ruleId: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    
    try {
      await api.deleteRule(ruleId);
      setSnackbar({ open: true, message: 'Rule deleted successfully', severity: 'success' });
      mutate('rules');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Failed to delete rule', severity: 'error' });
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
      
      setSnackbar({ open: true, message: `Switched to capture: ${filePath.split('/').pop()}`, severity: 'success' });
    } catch (err) {
      console.error('Failed to switch file:', err);
      setSnackbar({
        open: true,
        message: 'Failed to switch to this capture',
        severity: 'error',
      });
    } finally {
      setSwitchingFile(false);
    }
  }, [mutateStatus]);

  const handleExecuteRule = async (ruleId: string) => {
    if (!status?.activeInputFile) {
      setSnackbar({ open: true, message: 'No capture file selected', severity: 'error' });
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
      
      setSnackbar({ 
        open: true, 
        message: `Rule executed: ${result.alertsCount} alerts generated from ${result.recordsRead} records (${result.executionTimeMs}ms)`, 
        severity: 'success' 
      });
      
      // Refresh alerts to show new ones
      await globalMutate('alertStats');
    } catch (err) {
      // Store error for display in table
      setRuleExecutionData(prev => ({
        ...prev,
        [ruleId]: {
          executionTimeMs: 0,
          error: err instanceof Error ? err.message : 'Failed to execute rule',
          lastRun: Date.now(),
        }
      }));
      
      setSnackbar({ 
        open: true, 
        message: err instanceof Error ? err.message : 'Failed to execute rule', 
        severity: 'error' 
      });
    } finally {
      setExecutingRule(null);
    }
  };

  const handleExecuteAllRules = async () => {
    if (!status?.activeInputFile) {
      setSnackbar({ open: true, message: 'No capture file selected', severity: 'error' });
      return;
    }

    const enabledCount = rules.filter(r => r.enabled).length;
    if (enabledCount === 0) {
      setSnackbar({ open: true, message: 'No enabled rules to execute', severity: 'error' });
      return;
    }

    setExecutingAllRules(true);
    try {
      const result = await api.executeAllRules();
      
      // Store execution data per rule
      const newExecutionData: Record<string, { executionTimeMs: number; error?: string; lastRun: number }> = {};
      for (const ruleResult of result.ruleResults) {
        newExecutionData[ruleResult.ruleName] = {
          executionTimeMs: ruleResult.executionTimeMs,
          error: ruleResult.error,
          lastRun: Date.now(),
        };
      }
      setRuleExecutionData(newExecutionData);
      
      // Show summary message
      const failedRules = result.ruleResults.filter(r => !r.success);
      let message = `${result.message} (${result.executionTimeMs}ms)`;
      
      if (failedRules.length > 0) {
        message += ` - ${failedRules.length} rule(s) failed`;
      }
      
      setSnackbar({ 
        open: true, 
        message, 
        severity: failedRules.length > 0 ? 'error' : 'success' 
      });
      
      // Refresh alerts to show new ones
      await globalMutate('alertStats');
    } catch (err) {
      setSnackbar({ 
        open: true, 
        message: err instanceof Error ? err.message : 'Failed to execute all rules', 
        severity: 'error' 
      });
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
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view and manage their detection rules."
    />
  );

  return (
    <Layout title="Detection Rules" headerAction={fileSelector}>
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="body2" color="text.secondary">
            Total: {rules.length} rule{rules.length !== 1 ? 's' : ''} • Enabled: {rules.filter(r => r.enabled).length}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              data-learn="Execute All Rules: Run all enabled detection rules against the current PCAP data to generate alerts."
              variant="outlined"
              color="success"
              startIcon={executingAllRules ? <CircularProgress size={20} /> : <PlayArrowIcon />}
              onClick={handleExecuteAllRules}
              disabled={executingAllRules || !status?.activeInputFile || rules.filter(r => r.enabled).length === 0}
            >
              {executingAllRules ? 'Executing...' : 'Execute All Rules'}
            </Button>
            <Button
              data-learn="Create Rule: Open a dialog to create a new detection rule with custom filter expressions."
              variant="contained"
              color="primary"
              startIcon={<AddIcon />}
              onClick={() => handleOpenDialog()}
            >
              Create Rule
            </Button>
          </Box>
        </Box>

        {/* Search Input */}
        <Box sx={{ mb: 3, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
          <SearchInput
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search rules by name, description, or expression..."
            learnHint="Search Rules: Filter the rules list by typing keywords from rule names, descriptions, or expressions. Use !term to exclude matches."
            sx={{ width: '100%' }}
          />
          {searchQuery && (
            <Typography variant="caption" color="text.secondary">
              Found {filteredRules.length} rule{filteredRules.length !== 1 ? 's' : ''} matching "{searchQuery}"
            </Typography>
          )}
        </Box>

        {/* Tag Filter */}
        {allTags.length > 0 && (
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }} onClick={() => setTagsExpanded(!tagsExpanded)}>
              <Typography variant="subtitle2">
                Filter by Tags
              </Typography>
              <IconButton size="small" sx={{ ml: 0.5 }}>
                {tagsExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </IconButton>
              <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                ({allTags.length} tags available{selectedTags.length > 0 ? `, ${selectedTags.length} selected` : ''})
              </Typography>
            </Box>
            {tagsExpanded && (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
                {allTags.map((tag) => (
                  <Chip
                    key={tag}
                    label={tag}
                    color={selectedTags.includes(tag) ? 'primary' : 'default'}
                    onClick={() => {
                      setSelectedTags((prev) =>
                        prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]
                      );
                    }}
                    variant={selectedTags.includes(tag) ? 'filled' : 'outlined'}
                  />
                ))}
                {selectedTags.length > 0 && (
                  <Chip
                    label="Clear All"
                    color="secondary"
                    onClick={() => setSelectedTags([])}
                    variant="outlined"
                  />
                )}
              </Box>
            )}
            {(selectedTags.length > 0 || searchQuery) && (
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                Showing {filteredRules.length} of {rules.length} rules
                {selectedTags.length > 0 && ` (filtered by ${selectedTags.length} tag${selectedTags.length > 1 ? 's' : ''})`}
                {searchQuery && ` (search: "${searchQuery}")`}
              </Typography>
            )}
          </Box>
        )}

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            Failed to load rules: {error.message}
          </Alert>
        )}

        <TableContainer component={Paper} sx={{ mt: 3 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>Type</TableCell>
                <TableCell>
                  <TableSortLabel
                    active={sortBy === 'severity'}
                    direction={sortBy === 'severity' ? sortOrder : 'asc'}
                    onClick={() => handleSort('severity')}
                  >
                    Severity
                  </TableSortLabel>
                </TableCell>
                <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>Expression</TableCell>
                <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>Tags</TableCell>
                <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                  <TableSortLabel
                    active={sortBy === 'enabled'}
                    direction={sortBy === 'enabled' ? sortOrder : 'asc'}
                    onClick={() => handleSort('enabled')}
                  >
                    Enabled
                  </TableSortLabel>
                </TableCell>
                <TableCell align="right">
                  <TableSortLabel
                    active={sortBy === 'executionTime'}
                    direction={sortBy === 'executionTime' ? sortOrder : 'asc'}
                    onClick={() => handleSort('executionTime')}
                  >
                    Duration
                  </TableSortLabel>
                </TableCell>
                <TableCell align="center">
                  <TableSortLabel
                    active={sortBy === 'error'}
                    direction={sortBy === 'error' ? sortOrder : 'asc'}
                    onClick={() => handleSort('error')}
                  >
                    Error
                  </TableSortLabel>
                </TableCell>
                <TableCell align="right">Actions</TableCell>
                <TableCell align="right">Execute</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredRules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} align="center">
                    <Typography variant="body2" color="text.secondary">
                      {rules.length === 0 
                        ? "No rules defined. Click \"Create Rule\" to add your first rule."
                        : "No rules match the selected filters."}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                paginatedRules.map((rule) => (
                  <TableRow 
                    key={rule.id} 
                    hover
                    onClick={() => handleOpenDialog(rule)}
                    sx={{ cursor: 'pointer' }}
                  >
                    <TableCell>
                      <Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="body1" fontWeight="medium">
                            {rule.name}
                          </Typography>
                          {rule.threshold && rule.threshold > 0 && (
                            <Tooltip title={`Threshold: ${rule.threshold} matches in ${rule.thresholdWindow || 60}s`}>
                              <Chip 
                                label="THRESHOLD" 
                                size="small" 
                                color="info" 
                                variant="outlined"
                                sx={{ height: 20, fontSize: '0.7rem' }}
                              />
                            </Tooltip>
                          )}
                          {rule.actions && rule.actions.length > 0 && (
                            <Tooltip title={`Response Actions: ${rule.actions.map(a => a.type.replace('iptables_', '')).join(', ')}`}>
                              <Chip 
                                icon={<SecurityIcon sx={{ fontSize: '0.9rem !important' }} />}
                                label={rule.actions.length} 
                                size="small" 
                                color="error" 
                                variant="outlined"
                                sx={{ height: 20, fontSize: '0.7rem' }}
                              />
                            </Tooltip>
                          )}
                        </Box>
                        {/* <Typography variant="caption" color="text.secondary">
                          {rule.description}
                        </Typography> */}
                      </Box>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                      <Chip label={rule.type} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.severity.toUpperCase()}
                        size="small"
                        color={getSeverityColor(rule.severity) as any}
                      />
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                      <Tooltip title={rule.expression}>
                        <Box>
                          <FilterExpressionInline expression={rule.expression} maxWidth={300} />
                        </Box>
                      </Tooltip>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {rule.tags.map((tag) => (
                          <Chip key={tag} label={tag} size="small" />
                        ))}
                      </Box>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                      <Chip
                        label={rule.enabled ? 'Enabled' : 'Disabled'}
                        size="small"
                        color={rule.enabled ? 'success' : 'default'}
                      />
                    </TableCell>
                    <TableCell align="right">
                      {ruleExecutionData[rule.name] ? (
                        <Typography variant="body2" color="text.secondary">
                          {ruleExecutionData[rule.name].executionTimeMs}ms
                        </Typography>
                      ) : rule.executionTimeMs ? (
                        <Typography variant="body2" color="text.secondary">
                          {rule.executionTimeMs}ms
                        </Typography>
                      ) : (
                        <Typography variant="body2" color="text.disabled">
                          -
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell align="center">
                      {ruleExecutionData[rule.name]?.error ? (
                        <Tooltip title="View error details">
                          <IconButton 
                            size="small" 
                            color="error"
                            onClick={() => {
                              setSelectedError({
                                ruleName: rule.name,
                                error: ruleExecutionData[rule.name].error || 'Unknown error'
                              });
                              setErrorDialogOpen(true);
                            }}
                          >
                            <ErrorIcon />
                          </IconButton>
                        </Tooltip>
                      ) : ruleExecutionData[rule.name] ? (
                        <Chip label="OK" size="small" color="success" />
                      ) : (
                        <Typography variant="body2" color="text.disabled">
                          -
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell align="right">
                      <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'flex-end' }}>
                        <IconButton 
                          data-learn="Edit Rule: Modify this rule's properties, expression, severity, and settings." 
                          size="small" 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDialog(rule);
                          }} 
                          color="primary"
                        >
                          <EditIcon />
                        </IconButton>
                        <IconButton 
                          data-learn="Delete Rule: Permanently remove this rule from the system." 
                          size="small" 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDelete(rule.id);
                          }} 
                          color="error"
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Box>
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Execute this rule on current capture">
                        <span>
                          <IconButton 
                            data-learn="Execute Rule: Run this specific rule against the current PCAP data to generate matching alerts."
                            size="small" 
                            onClick={(e) => {
                              e.stopPropagation();
                              handleExecuteRule(rule.id);
                            }} 
                            color="success"
                            disabled={!rule.enabled || executingRule === rule.id || !status?.activeInputFile}
                          >
                            {executingRule === rule.id ? (
                              <CircularProgress size={20} />
                            ) : (
                              <PlayArrowIcon />
                            )}
                          </IconButton>
                        </span>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={filteredRules.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </TableContainer>

        {/* Rule Dialog */}
        <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth fullScreen={isMobile}>
          <DialogTitle>
            <Box display="flex" justifyContent="space-between" alignItems="center">
              {editingRule ? 'Edit Rule' : 'Create New Rule'}
              {isMobile && (
                <IconButton onClick={handleCloseDialog} edge="end">
                  <CloseIcon />
                </IconButton>
              )}
            </Box>
          </DialogTitle>
          <DialogContent>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
              <TextField
                label="Rule Name"
                fullWidth
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                helperText="Unique identifier for this rule"
              />

              <TextField
                label="Description"
                fullWidth
                multiline
                rows={2}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                helperText="Human-readable description of what this rule detects"
              />

              <FormControl fullWidth required>
                <InputLabel>Record Type</InputLabel>
                <Select
                  value={formData.type}
                  label="Record Type"
                  onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                >
                  <MenuItem value="Alert">Alert</MenuItem>
                  <MenuItem value="ARP">ARP</MenuItem>
                  <MenuItem value="BACnetIP">BACnetIP</MenuItem>
                  <MenuItem value="BFD">BFD</MenuItem>
                  <MenuItem value="BGP">BGP</MenuItem>
                  <MenuItem value="CIP">CIP</MenuItem>
                  <MenuItem value="CiscoDiscovery">CiscoDiscovery</MenuItem>
                  <MenuItem value="Connection">Connection</MenuItem>
                  <MenuItem value="Secret">Secret</MenuItem>
                  <MenuItem value="DeviceProfile">DeviceProfile</MenuItem>
                  <MenuItem value="DHCPv4">DHCPv4</MenuItem>
                  <MenuItem value="DHCPv6">DHCPv6</MenuItem>
                  <MenuItem value="Diameter">Diameter</MenuItem>
                  <MenuItem value="DNS">DNS</MenuItem>
                  <MenuItem value="DNP3">DNP3</MenuItem>
                  <MenuItem value="Dot11">Dot11</MenuItem>
                  <MenuItem value="Dot1Q">Dot1Q</MenuItem>
                  <MenuItem value="EAP">EAP</MenuItem>
                  <MenuItem value="EAPOL">EAPOL</MenuItem>
                  <MenuItem value="EAPOLKey">EAPOLKey</MenuItem>
                  <MenuItem value="ENIP">ENIP</MenuItem>
                  <MenuItem value="Ethernet">Ethernet</MenuItem>
                  <MenuItem value="EthernetCTP">EthernetCTP</MenuItem>
                  <MenuItem value="EthernetCTPReply">EthernetCTPReply</MenuItem>
                  <MenuItem value="Exploit">Exploit</MenuItem>
                  <MenuItem value="FDDI">FDDI</MenuItem>
                  <MenuItem value="File">File</MenuItem>
                  <MenuItem value="FTP">FTP</MenuItem>
                  <MenuItem value="Geneve">Geneve</MenuItem>
                  <MenuItem value="GRE">GRE</MenuItem>
                  <MenuItem value="GTP">GTP</MenuItem>
                  <MenuItem value="HTTP">HTTP</MenuItem>
                  <MenuItem value="ICMPv4">ICMPv4</MenuItem>
                  <MenuItem value="ICMPv6">ICMPv6</MenuItem>
                  <MenuItem value="ICMPv6Echo">ICMPv6Echo</MenuItem>
                  <MenuItem value="ICMPv6NeighborAdvertisement">ICMPv6NeighborAdvertisement</MenuItem>
                  <MenuItem value="ICMPv6NeighborSolicitation">ICMPv6NeighborSolicitation</MenuItem>
                  <MenuItem value="ICMPv6RouterAdvertisement">ICMPv6RouterAdvertisement</MenuItem>
                  <MenuItem value="ICMPv6RouterSolicitation">ICMPv6RouterSolicitation</MenuItem>
                  <MenuItem value="IEC62351">IEC62351</MenuItem>
                  <MenuItem value="IGMP">IGMP</MenuItem>
                  <MenuItem value="IMAP">IMAP</MenuItem>
                  <MenuItem value="Host">Host</MenuItem>
                  <MenuItem value="IRC">IRC</MenuItem>
                  <MenuItem value="IPSecAH">IPSecAH</MenuItem>
                  <MenuItem value="IPSecESP">IPSecESP</MenuItem>
                  <MenuItem value="IPv4">IPv4</MenuItem>
                  <MenuItem value="IPv6">IPv6</MenuItem>
                  <MenuItem value="IPv6Fragment">IPv6Fragment</MenuItem>
                  <MenuItem value="IPv6HopByHop">IPv6HopByHop</MenuItem>
                  <MenuItem value="LCM">LCM</MenuItem>
                  <MenuItem value="LinkLayerDiscovery">LinkLayerDiscovery</MenuItem>
                  <MenuItem value="LinkLayerDiscoveryInfo">LinkLayerDiscoveryInfo</MenuItem>
                  <MenuItem value="LLC">LLC</MenuItem>
                  <MenuItem value="Mail">Mail</MenuItem>
                  <MenuItem value="Modbus">Modbus</MenuItem>
                  <MenuItem value="MPLS">MPLS</MenuItem>
                  <MenuItem value="MQTTSN">MQTTSN</MenuItem>
                  <MenuItem value="NortelDiscovery">NortelDiscovery</MenuItem>
                  <MenuItem value="NTP">NTP</MenuItem>
                  <MenuItem value="OPCUA">OPCUA</MenuItem>
                  <MenuItem value="OSPFv2">OSPFv2</MenuItem>
                  <MenuItem value="OSPFv3">OSPFv3</MenuItem>
                  <MenuItem value="POP3">POP3</MenuItem>
                  <MenuItem value="PPP">PPP</MenuItem>
                  <MenuItem value="PPPoE">PPPoE</MenuItem>
                  <MenuItem value="PROFINET">PROFINET</MenuItem>
                  <MenuItem value="Radius">Radius</MenuItem>
                  <MenuItem value="RDP">RDP</MenuItem>
                  <MenuItem value="RMCP">RMCP</MenuItem>
                  <MenuItem value="S7Comm">S7Comm</MenuItem>
                  <MenuItem value="SCTP">SCTP</MenuItem>
                  <MenuItem value="Service">Service</MenuItem>
                  <MenuItem value="SIP">SIP</MenuItem>
                  <MenuItem value="SMTP">SMTP</MenuItem>
                  <MenuItem value="SMB">SMB</MenuItem>
                  <MenuItem value="SNAP">SNAP</MenuItem>
                  <MenuItem value="SOCKS">SOCKS</MenuItem>
                  <MenuItem value="Software">Software</MenuItem>
                  <MenuItem value="SSH">SSH</MenuItem>
                  <MenuItem value="STP">STP</MenuItem>
                  <MenuItem value="Syslog">Syslog</MenuItem>
                  <MenuItem value="TCP">TCP</MenuItem>
                  <MenuItem value="TLSClientHello">TLSClientHello</MenuItem>
                  <MenuItem value="TLSServerHello">TLSServerHello</MenuItem>
                  <MenuItem value="UDP">UDP</MenuItem>
                  <MenuItem value="USB">USB</MenuItem>
                  <MenuItem value="USBRequestBlockSetup">USBRequestBlockSetup</MenuItem>
                  <MenuItem value="VRRPv2">VRRPv2</MenuItem>
                  <MenuItem value="Vulnerability">Vulnerability</MenuItem>
                  <MenuItem value="VXLAN">VXLAN</MenuItem>
                </Select>
              </FormControl>

              <SyntaxHighlightedTextArea
                syntaxType="filter"
                value={formData.expression}
                onChange={(value) => setFormData({ ...formData, expression: value })}
                label="Expression"
                helperText="Expr-lang expression to evaluate (e.g., 'SYN && !ACK', 'DstPort == 22')"
                rows={4}
                fullWidth
              />

              <FormControl fullWidth required>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={formData.severity}
                  label="Severity"
                  onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                >
                  <MenuItem value="info">Info</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                </Select>
              </FormControl>

              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Threshold Settings (Optional)
                </Typography>
                <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                  Configure threshold-based alerting to trigger only after N matches within a time window
                </Typography>
                <Box sx={{ display: 'flex', gap: 2, mt: 1 }}>
                  <TextField
                    label="Threshold Count"
                    type="number"
                    size="small"
                    value={formData.threshold || ''}
                    onChange={(e) => {
                      const val = e.target.value ? parseInt(e.target.value) : undefined;
                      setFormData({ ...formData, threshold: val });
                    }}
                    helperText="Number of matches required"
                    InputProps={{
                      inputProps: { min: 0 }
                    }}
                    sx={{ flex: 1 }}
                  />
                  <TextField
                    label="Time Window (seconds)"
                    type="number"
                    size="small"
                    value={formData.thresholdWindow || ''}
                    onChange={(e) => {
                      const val = e.target.value ? parseInt(e.target.value) : undefined;
                      setFormData({ ...formData, thresholdWindow: val });
                    }}
                    helperText="Time window in seconds"
                    InputProps={{
                      inputProps: { min: 0 }
                    }}
                    sx={{ flex: 1 }}
                  />
                </Box>
              </Box>

              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  MITRE ATT&CK Techniques
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField
                    size="small"
                    fullWidth
                    placeholder="e.g., T1046"
                    value={mitreInput}
                    onChange={(e) => setMitreInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddMitre();
                      }
                    }}
                  />
                  <Button data-learn="Add MITRE Technique: Add this MITRE ATT&CK technique ID to the rule to categorize the attack pattern." variant="outlined" onClick={handleAddMitre}>
                    Add
                  </Button>
                </Box>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {formData.mitre.map((mitre) => (
                    <Chip
                      key={mitre}
                      label={mitre}
                      onDelete={() => handleRemoveMitre(mitre)}
                      size="small"
                    />
                  ))}
                </Box>
              </Box>

              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Tags
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField
                    size="small"
                    fullWidth
                    placeholder="e.g., reconnaissance"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddTag();
                      }
                    }}
                  />
                  <Button data-learn="Add Tag: Add this tag to the rule for easier filtering and organization of detection rules." variant="outlined" onClick={handleAddTag}>
                    Add
                  </Button>
                </Box>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {formData.tags.map((tag) => (
                    <Chip key={tag} label={tag} onDelete={() => handleRemoveTag(tag)} size="small" />
                  ))}
                </Box>
              </Box>

              {/* Response Actions Section */}
              <Box sx={{ 
                border: '1px solid', 
                borderColor: 'divider', 
                borderRadius: 1, 
                p: 2,
                bgcolor: 'background.default'
              }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <SecurityIcon color="primary" />
                  <Typography variant="subtitle1" fontWeight="medium">
                    Response Actions
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                    (Linux only - requires iptables)
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Automatically execute firewall actions when this rule triggers an alert.
                </Typography>

                {/* Existing Actions */}
                {(formData.actions || []).map((action, index) => (
                  <Card key={index} variant="outlined" sx={{ mt: 2, bgcolor: 'background.paper' }}>
                    <CardContent sx={{ pb: '16px !important' }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <BlockIcon color={action.enabled !== false ? 'error' : 'disabled'} fontSize="small" />
                          <Typography variant="subtitle2">
                            {action.type.replace('iptables_', '').replace('_', ' ').toUpperCase()}
                          </Typography>
                          <Chip 
                            label={action.enabled !== false ? 'Enabled' : 'Disabled'} 
                            size="small" 
                            color={action.enabled !== false ? 'success' : 'default'}
                          />
                        </Box>
                        <IconButton 
                          size="small" 
                          color="error"
                          onClick={() => {
                            const newActions = [...(formData.actions || [])];
                            newActions.splice(index, 1);
                            setFormData({ ...formData, actions: newActions });
                          }}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Box>

                      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                        <FormControl size="small" sx={{ minWidth: 150 }}>
                          <InputLabel>Action Type</InputLabel>
                          <Select
                            value={action.type}
                            label="Action Type"
                            onChange={(e) => {
                              const newActions = [...(formData.actions || [])];
                              newActions[index] = { ...action, type: e.target.value as ResponseAction['type'] };
                              setFormData({ ...formData, actions: newActions });
                            }}
                          >
                            <MenuItem value="iptables_block">Block (DROP)</MenuItem>
                            <MenuItem value="iptables_reject">Reject</MenuItem>
                            <MenuItem value="iptables_log">Log</MenuItem>
                            <MenuItem value="iptables_rate_limit">Rate Limit</MenuItem>
                          </Select>
                        </FormControl>

                        {(action.type === 'iptables_block' || action.type === 'iptables_reject') && (
                          <>
                            <FormControl size="small" sx={{ minWidth: 130 }}>
                              <InputLabel>Target</InputLabel>
                              <Select
                                value={action.config?.target || 'source'}
                                label="Target"
                                onChange={(e) => {
                                  const newActions = [...(formData.actions || [])];
                                  newActions[index] = { 
                                    ...action, 
                                    config: { ...action.config, target: e.target.value as 'source' | 'destination' }
                                  };
                                  setFormData({ ...formData, actions: newActions });
                                }}
                              >
                                <MenuItem value="source">Source IP</MenuItem>
                                <MenuItem value="destination">Dest IP</MenuItem>
                              </Select>
                            </FormControl>

                            <TextField
                              size="small"
                              label="Duration"
                              placeholder="e.g., 30m, 1h, 24h"
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
                              helperText="Block duration"
                            />
                          </>
                        )}

                        {action.type === 'iptables_log' && (
                          <TextField
                            size="small"
                            label="Log Prefix"
                            placeholder="e.g., ATTACK: "
                            value={action.config?.prefix || ''}
                            onChange={(e) => {
                              const newActions = [...(formData.actions || [])];
                              newActions[index] = { 
                                ...action, 
                                config: { ...action.config, prefix: e.target.value }
                              };
                              setFormData({ ...formData, actions: newActions });
                            }}
                            sx={{ width: 200 }}
                          />
                        )}

                        {action.type === 'iptables_rate_limit' && (
                          <>
                            <TextField
                              size="small"
                              label="Rate"
                              placeholder="e.g., 10/minute"
                              value={action.config?.rate || ''}
                              onChange={(e) => {
                                const newActions = [...(formData.actions || [])];
                                newActions[index] = { 
                                  ...action, 
                                  config: { ...action.config, rate: e.target.value }
                                };
                                setFormData({ ...formData, actions: newActions });
                              }}
                              sx={{ width: 130 }}
                            />
                            <TextField
                              size="small"
                              label="Burst"
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
                              InputProps={{ inputProps: { min: 1 } }}
                            />
                          </>
                        )}

                        <FormControlLabel
                          control={
                            <Switch
                              size="small"
                              checked={action.enabled !== false}
                              onChange={(e) => {
                                const newActions = [...(formData.actions || [])];
                                newActions[index] = { ...action, enabled: e.target.checked };
                                setFormData({ ...formData, actions: newActions });
                              }}
                            />
                          }
                          label="Active"
                        />
                      </Box>
                    </CardContent>
                  </Card>
                ))}

                {/* Add Action Button */}
                <Button
                  variant="outlined"
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
                  }}
                >
                  Add Response Action
                </Button>

                {(formData.actions || []).length === 0 && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                    No response actions configured. Rules will only generate alerts.
                  </Typography>
                )}
              </Box>

              <FormControlLabel
                control={
                  <Switch
                    checked={formData.enabled}
                    onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                  />
                }
                label="Enable this rule"
              />
            </Box>
          </DialogContent>
          <DialogActions>
            <Button data-learn="Cancel: Close the rule editor without saving changes." onClick={handleCloseDialog}>Cancel</Button>
            <Button
              data-learn="Save Rule: Save the rule with the current configuration to the rules database."
              onClick={handleSave}
              variant="contained"
              disabled={!formData.name || !formData.type || !formData.expression || !formData.severity}
            >
              {editingRule ? 'Update' : 'Create'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Error Details Dialog */}
        <Dialog
          open={errorDialogOpen}
          onClose={() => setErrorDialogOpen(false)}
          maxWidth="md"
          fullWidth
          fullScreen={isMobile}
        >
          <DialogTitle>
            <Box display="flex" justifyContent="space-between" alignItems="center">
              <Box display="flex" alignItems="center" gap={1}>
                <ErrorIcon color="error" />
                Rule Execution Error
              </Box>
              {isMobile && (
                <IconButton onClick={() => setErrorDialogOpen(false)} edge="end">
                  <CloseIcon />
                </IconButton>
              )}
            </Box>
          </DialogTitle>
          <DialogContent>
            {selectedError && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Rule: {selectedError.ruleName}
                </Typography>
                <Box 
                  sx={{ 
                    mt: 2, 
                    p: 2, 
                    bgcolor: 'error.light', 
                    color: 'error.contrastText',
                    borderRadius: 1,
                    fontFamily: 'monospace',
                    fontSize: '0.9rem',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word'
                  }}
                >
                  {selectedError.error}
                </Box>
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button data-learn="Close Dialog: Close the rule execution error viewer." onClick={() => setErrorDialogOpen(false)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Snackbar for notifications */}
        <Snackbar
          open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
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

