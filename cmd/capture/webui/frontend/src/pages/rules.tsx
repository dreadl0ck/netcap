import { useState, useEffect } from 'react';
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
  SelectChangeEvent,
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
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import ErrorIcon from '@mui/icons-material/Error';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { useRouter } from 'next/router';
import Layout from '@/components/Layout';
import { api, Rule, CreateRuleRequest, UpdateRuleRequest, formatBytes } from '@/lib/api';
import useSWR, { mutate, mutate as globalMutate } from 'swr';

export default function RulesPage() {
  const router = useRouter();
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
        router.replace('/rules', undefined, { shallow: true });
      }
    }
  }, [router.isReady, router.query.tag, allTags]);

  // Filter rules by search query and selected tags
  const filteredRules = rules.filter((rule) => {
    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const matchesSearch = 
        rule.name.toLowerCase().includes(query) ||
        rule.description.toLowerCase().includes(query) ||
        rule.expression.toLowerCase().includes(query);
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
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
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

  const handleFileChange = async (event: SelectChangeEvent<string>) => {
    const newFile = event.target.value;
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(newFile);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
      
      setSnackbar({ open: true, message: `Switched to capture: ${newFile.split('/').pop()}`, severity: 'success' });
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
  };

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
  const completedFiles = (inputFiles?.filter((f: any) => f.isCompleted) || [])
    .sort((a: any, b: any) => a.path.localeCompare(b.path));
  
  // Current selected value
  const selectedValue = status?.activeInputFile || completedFiles[0]?.path || '';
  const selectedFile = completedFiles.find((f: any) => 
    f.path === selectedValue || f.name === selectedValue || f.path.endsWith('/' + selectedValue)
  );

  // File selector for header
  const fileSelector = completedFiles.length > 1 && selectedFile ? (
    <FormControl size="small" disabled={switchingFile} sx={{ minWidth: 300, maxWidth: 400 }}>
      <Select
        value={selectedValue}
        onChange={handleFileChange}
        startAdornment={
          switchingFile ? (
            <CircularProgress size={20} sx={{ mr: 1, color: 'inherit' }} />
          ) : (
            <SwapHorizIcon sx={{ mr: 1, color: 'inherit' }} />
          )
        }
        renderValue={() => (
          <Box display="flex" alignItems="center" gap={1}>
            <Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'inherit' }}>
              {selectedFile.name}
            </Typography>
          </Box>
        )}
        sx={{
          color: 'inherit',
          '.MuiOutlinedInput-notchedOutline': {
            borderColor: 'rgba(255, 255, 255, 0.23)',
          },
          '&:hover .MuiOutlinedInput-notchedOutline': {
            borderColor: 'rgba(255, 255, 255, 0.4)',
          },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
            borderColor: 'primary.light',
          },
          '.MuiSelect-icon': {
            color: 'inherit',
          },
          '& .MuiSelect-select': {
            display: 'flex',
            alignItems: 'center',
          },
        }}
      >
        {completedFiles.map((file: any) => (
          <MenuItem key={file.path} value={file.path}>
            <Box display="flex" alignItems="center" gap={1} width="100%">
              {selectedValue === file.path && (
                <Chip
                  label="Active"
                  size="small"
                  color="success"
                  sx={{ height: 20, fontSize: '0.7rem' }}
                />
              )}
              <Typography
                sx={{
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  flex: 1,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {file.name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {formatBytes(file.size)}
              </Typography>
            </Box>
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  ) : null;

  return (
    <Layout title="Detection Rules" headerAction={fileSelector}>
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="body2" color="text.secondary">
            Total: {rules.length} rule{rules.length !== 1 ? 's' : ''} • Enabled: {rules.filter(r => r.enabled).length}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              color="success"
              startIcon={executingAllRules ? <CircularProgress size={20} /> : <PlayArrowIcon />}
              onClick={handleExecuteAllRules}
              disabled={executingAllRules || !status?.activeInputFile || rules.filter(r => r.enabled).length === 0}
            >
              {executingAllRules ? 'Executing...' : 'Execute All Rules'}
            </Button>
            <Button
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
        <Box sx={{ mb: 3 }}>
          <TextField
            fullWidth
            placeholder="Search rules by name, description, or expression..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: <SearchIcon sx={{ color: 'action.active', mr: 1 }} />,
              endAdornment: searchQuery && (
                <IconButton
                  size="small"
                  onClick={() => setSearchQuery('')}
                  edge="end"
                >
                  <ClearIcon />
                </IconButton>
              ),
            }}
            variant="outlined"
            size="small"
          />
          {searchQuery && (
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
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
                <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>Type</TableCell>
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
                <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>Tags</TableCell>
                <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
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
                  <TableRow key={rule.id} hover>
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
                        </Box>
                        {/* <Typography variant="caption" color="text.secondary">
                          {rule.description}
                        </Typography> */}
                      </Box>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
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
                        <Box
                          sx={{
                            fontFamily: 'monospace',
                            fontSize: '0.85rem',
                            maxWidth: 300,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {rule.expression}
                        </Box>
                      </Tooltip>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {rule.tags.map((tag) => (
                          <Chip key={tag} label={tag} size="small" />
                        ))}
                      </Box>
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
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
                        <IconButton size="small" onClick={() => handleOpenDialog(rule)} color="primary">
                          <EditIcon />
                        </IconButton>
                        <IconButton size="small" onClick={() => handleDelete(rule.id)} color="error">
                          <DeleteIcon />
                        </IconButton>
                      </Box>
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Execute this rule on current capture">
                        <span>
                          <IconButton 
                            size="small" 
                            onClick={() => handleExecuteRule(rule.id)} 
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
        <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth>
          <DialogTitle>
            {editingRule ? 'Edit Rule' : 'Create New Rule'}
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
                  <MenuItem value="TCP">TCP</MenuItem>
                  <MenuItem value="UDP">UDP</MenuItem>
                  <MenuItem value="ICMP">ICMP</MenuItem>
                  <MenuItem value="ICMPv4">ICMPv4</MenuItem>
                  <MenuItem value="ICMPv6">ICMPv6</MenuItem>
                  <MenuItem value="HTTP">HTTP</MenuItem>
                  <MenuItem value="DNS">DNS</MenuItem>
                  <MenuItem value="TLS">TLS</MenuItem>
                  <MenuItem value="ARP">ARP</MenuItem>
                  <MenuItem value="IPv4">IPv4</MenuItem>
                  <MenuItem value="IPv6">IPv6</MenuItem>
                </Select>
              </FormControl>

              <TextField
                label="Expression"
                fullWidth
                required
                multiline
                rows={4}
                value={formData.expression}
                onChange={(e) => setFormData({ ...formData, expression: e.target.value })}
                helperText="Expr-lang expression to evaluate (e.g., 'SYN && !ACK', 'DstPort == 22')"
                InputProps={{
                  style: { 
                    fontFamily: 'monospace',
                    fontSize: '0.95rem',
                  },
                }}
                sx={{
                  '& .MuiInputBase-root': {
                    fontFamily: 'monospace',
                    backgroundColor: 'rgba(0, 0, 0, 0.2)',
                  },
                  '& .MuiInputBase-input': {
                    color: 'text.primary',
                  },
                }}
              />

              <FormControl fullWidth required>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={formData.severity}
                  label="Severity"
                  onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                >
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
                  <Button variant="outlined" onClick={handleAddMitre}>
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
                  <Button variant="outlined" onClick={handleAddTag}>
                    Add
                  </Button>
                </Box>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {formData.tags.map((tag) => (
                    <Chip key={tag} label={tag} onDelete={() => handleRemoveTag(tag)} size="small" />
                  ))}
                </Box>
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
            <Button onClick={handleCloseDialog}>Cancel</Button>
            <Button
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
        >
          <DialogTitle>
            <Box display="flex" alignItems="center" gap={1}>
              <ErrorIcon color="error" />
              Rule Execution Error
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
            <Button onClick={() => setErrorDialogOpen(false)}>Close</Button>
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

