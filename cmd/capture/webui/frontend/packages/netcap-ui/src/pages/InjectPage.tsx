import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Alert,
  AlertTitle,
  Badge,
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
  Divider,
  FormControl,
  FormControlLabel,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Snackbar,
  Switch,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import RefreshIcon from '@mui/icons-material/Refresh';
import ClearAllIcon from '@mui/icons-material/ClearAll';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import SecurityIcon from '@mui/icons-material/Security';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import FilterListIcon from '@mui/icons-material/FilterList';
import Layout from '../components/Layout';
import { InjectionRule, InjectionEvent, InjectionAction, CreateInjectionRuleRequest, UpdateInjectionRuleRequest, formatTimestamp } from '../lib/api';
import { useNetcapApi } from '../hooks';
import useSWR, { mutate } from 'swr';
import { SyntaxHighlightedTextArea } from '../components/SyntaxHighlightedInput';
import { FilterExpressionInline } from '../components/FilterExpressionHighlight';

// Format relative time (e.g., "2 minutes ago")
function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp / 1_000_000; // Convert nanoseconds to milliseconds
  
  if (diff < 60_000) return 'just now';
  if (diff < 3600_000) {
    const mins = Math.floor(diff / 60_000);
    return `${mins} minute${mins > 1 ? 's' : ''} ago`;
  }
  if (diff < 86400_000) {
    const hours = Math.floor(diff / 3600_000);
    return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  }
  const days = Math.floor(diff / 86400_000);
  return `${days} day${days > 1 ? 's' : ''} ago`;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`inject-tabpanel-${index}`}
      aria-labelledby={`inject-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

export default function InjectPage() {
  const api = useNetcapApi();
  const [tabValue, setTabValue] = useState(0);
  const [openDialog, setOpenDialog] = useState(false);
  const [editingRule, setEditingRule] = useState<InjectionRule | null>(null);
  const [formData, setFormData] = useState<CreateInjectionRuleRequest>({
    name: '',
    description: '',
    type: 'TCP',
    expression: '',
    action: 'accept',
    actionConfig: {},
    enabled: true,
    priority: 50,
    stopOnMatch: false,
    tags: [],
  });
  const [tagInput, setTagInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [tagsExpanded, setTagsExpanded] = useState(false);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [eventsPage, setEventsPage] = useState(0);
  const [eventsRowsPerPage, setEventsRowsPerPage] = useState(25);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });
  const [eventFilterRule, setEventFilterRule] = useState<string>('');
  const [eventFilterResult, setEventFilterResult] = useState<string>('');
  const [eventFilterAction, setEventFilterAction] = useState<string>('');
  const [showEventFilters, setShowEventFilters] = useState(false);

  // Fetch injection rules
  const { data: rulesData, error: rulesError } = useSWR('injectionRules', () => api.getInjectionRules(), {
    refreshInterval: 5000,
  });

  // Build filter key for SWR
  const eventFilterKey = useMemo(() => {
    const filters: string[] = [];
    if (eventFilterRule) filters.push(`rule=${eventFilterRule}`);
    if (eventFilterResult) filters.push(`result=${eventFilterResult}`);
    if (eventFilterAction) filters.push(`action=${eventFilterAction}`);
    return `injectionEvents${filters.length > 0 ? `?${filters.join('&')}` : ''}`;
  }, [eventFilterRule, eventFilterResult, eventFilterAction]);

  // Fetch injection events
  const { data: eventsData, error: eventsError } = useSWR(
    eventFilterKey,
    () => api.getInjectionEvents({
      rule: eventFilterRule || undefined,
      result: eventFilterResult || undefined,
      action: eventFilterAction || undefined,
    }),
    { refreshInterval: 3000 }
  );

  // Fetch injection stats
  const { data: statsData } = useSWR('injectionStats', () => api.getInjectionStats(), {
    refreshInterval: 5000,
  });

  // Fetch available actions
  const { data: actionsData } = useSWR('injectionActions', () => api.getInjectionActions());

  const rules = rulesData?.rules || [];
  const events = eventsData?.events || [];
  const actions = actionsData?.actions || [];

  // Extract all unique tags from all rules
  const allTags = useMemo(() => {
    return Array.from(new Set(rules.flatMap((rule) => rule.tags))).sort();
  }, [rules]);

  // Filter rules by search query and selected tags
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      // Filter by search query
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch =
          rule.name.toLowerCase().includes(query) ||
          rule.description.toLowerCase().includes(query) ||
          rule.expression.toLowerCase().includes(query) ||
          rule.action.toLowerCase().includes(query);
        if (!matchesSearch) return false;
      }

      // Filter by selected tags
      if (selectedTags.length > 0) {
        return selectedTags.some((tag) => rule.tags.includes(tag));
      }

      return true;
    });
  }, [rules, searchQuery, selectedTags]);

  // Paginate rules
  const paginatedRules = useMemo(() => {
    return filteredRules.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
  }, [filteredRules, page, rowsPerPage]);

  // Paginate events
  const paginatedEvents = useMemo(() => {
    return events.slice(eventsPage * eventsRowsPerPage, eventsPage * eventsRowsPerPage + eventsRowsPerPage);
  }, [events, eventsPage, eventsRowsPerPage]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleOpenDialog = (rule?: InjectionRule) => {
    if (rule) {
      setEditingRule(rule);
      setFormData({
        name: rule.name,
        description: rule.description,
        type: rule.type,
        expression: rule.expression,
        action: rule.action,
        actionConfig: rule.actionConfig || {},
        enabled: rule.enabled,
        priority: rule.priority,
        stopOnMatch: rule.stopOnMatch,
        tags: rule.tags,
      });
    } else {
      setEditingRule(null);
      setFormData({
        name: '',
        description: '',
        type: 'TCP',
        expression: '',
        action: 'accept',
        actionConfig: {},
        enabled: true,
        priority: 50,
        stopOnMatch: false,
        tags: [],
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingRule(null);
    setTagInput('');
  };

  const handleSave = async () => {
    try {
      if (editingRule) {
        await api.updateInjectionRule(editingRule.id, formData as UpdateInjectionRuleRequest);
        setSnackbar({ open: true, message: 'Injection rule updated successfully', severity: 'success' });
      } else {
        await api.createInjectionRule(formData);
        setSnackbar({ open: true, message: 'Injection rule created successfully', severity: 'success' });
      }
      mutate('injectionRules');
      mutate('injectionStats');
      handleCloseDialog();
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Failed to save rule', severity: 'error' });
    }
  };

  const handleDelete = async (ruleId: string) => {
    if (!confirm('Are you sure you want to delete this injection rule?')) return;

    try {
      await api.deleteInjectionRule(ruleId);
      setSnackbar({ open: true, message: 'Injection rule deleted successfully', severity: 'success' });
      mutate('injectionRules');
      mutate('injectionStats');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Failed to delete rule', severity: 'error' });
    }
  };

  const handleToggleEnabled = async (rule: InjectionRule, enabled: boolean) => {
    try {
      await api.toggleInjectionRule(rule.id, enabled);
      setSnackbar({
        open: true,
        message: `Rule "${rule.name}" ${enabled ? 'enabled' : 'disabled'}`,
        severity: 'success',
      });
      mutate('injectionRules');
      mutate('injectionStats');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Failed to toggle rule', severity: 'error' });
    }
  };

  const handleDuplicate = (rule: InjectionRule) => {
    setEditingRule(null);
    setFormData({
      name: `${rule.name} (copy)`,
      description: rule.description,
      type: rule.type,
      expression: rule.expression,
      action: rule.action,
      actionConfig: rule.actionConfig || {},
      enabled: false, // Start disabled for safety
      priority: rule.priority,
      stopOnMatch: rule.stopOnMatch,
      tags: [...rule.tags],
    });
    setOpenDialog(true);
  };

  const handleClearEvents = async () => {
    if (!confirm('Are you sure you want to clear all injection events?')) return;

    try {
      await api.clearInjectionEvents();
      setSnackbar({ open: true, message: 'Injection events cleared successfully', severity: 'success' });
      mutate(eventFilterKey);
      mutate('injectionStats');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Failed to clear events', severity: 'error' });
    }
  };

  const handleAddTag = () => {
    if (tagInput.trim() && !formData.tags?.includes(tagInput.trim())) {
      setFormData({ ...formData, tags: [...(formData.tags || []), tagInput.trim()] });
      setTagInput('');
    }
  };

  const handleRemoveTag = (tag: string) => {
    setFormData({ ...formData, tags: (formData.tags || []).filter((t) => t !== tag) });
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'accept':
        return 'success';
      case 'drop':
        return 'error';
      case 'delay':
        return 'warning';
      case 'inject_tcp_rst':
      case 'inject_dns':
      case 'inject_arp':
        return 'info';
      case 'iptables_block':
      case 'iptables_reject':
        return 'error';
      case 'iptables_rate_limit':
      case 'iptables_log':
        return 'warning';
      default:
        return 'default';
    }
  };

  const getResultIcon = (result: string) => {
    switch (result) {
      case 'success':
        return <CheckCircleIcon color="success" fontSize="small" />;
      case 'failed':
        return <ErrorIcon color="error" fontSize="small" />;
      case 'skipped':
        return <WarningIcon color="warning" fontSize="small" />;
      default:
        return null;
    }
  };

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleChangeEventsPage = (event: unknown, newPage: number) => {
    setEventsPage(newPage);
  };

  const handleChangeEventsRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setEventsRowsPerPage(parseInt(event.target.value, 10));
    setEventsPage(0);
  };

  // Reset page when search or tags change
  useEffect(() => {
    setPage(0);
  }, [searchQuery, selectedTags]);

  // Get current action config fields
  const currentActionFields = useMemo(() => {
    const action = actions.find((a) => a.value === formData.action);
    return action?.configFields || [];
  }, [actions, formData.action]);

  return (
    <Layout title="Injection Rules">
      <Box>
        {/* Warning Banner */}
        <Alert 
          severity="warning" 
          sx={{ mb: 3, borderLeft: 4, borderLeftColor: 'warning.main' }}
          icon={<SecurityIcon />}
        >
          <AlertTitle>Authorized Testing Only</AlertTitle>
          <Typography variant="body2">
            Injection rules are for <strong>authorized security testing</strong> only. 
            Ensure you have proper authorization before enabling any rules that modify or inject network traffic.
            Unauthorized use may violate laws and regulations.
          </Typography>
        </Alert>

        {/* Stats Overview */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Card sx={{ minWidth: 140 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">
                Total Rules
              </Typography>
              <Typography variant="h5">{statsData?.totalRules ?? 0}</Typography>
            </CardContent>
          </Card>
          <Card sx={{ minWidth: 140 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">
                Enabled
              </Typography>
              <Typography variant="h5" color="success.main">
                {statsData?.enabledRules ?? 0}
              </Typography>
            </CardContent>
          </Card>
          <Divider orientation="vertical" flexItem />
          <Card sx={{ minWidth: 140 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">
                Total Events
              </Typography>
              <Typography variant="h5">{statsData?.totalEvents ?? 0}</Typography>
            </CardContent>
          </Card>
          <Card sx={{ minWidth: 120 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">
                Success
              </Typography>
              <Typography variant="h5" color="success.main">
                {statsData?.eventsByResult?.success ?? 0}
              </Typography>
            </CardContent>
          </Card>
          <Card sx={{ minWidth: 120 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">
                Failed
              </Typography>
              <Typography variant="h5" color="error.main">
                {statsData?.eventsByResult?.failed ?? 0}
              </Typography>
            </CardContent>
          </Card>
        </Box>

        {/* Tabs */}
        <Paper sx={{ mb: 2 }}>
          <Tabs value={tabValue} onChange={handleTabChange} aria-label="injection tabs">
            <Tab 
              label={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  Rules
                  <Chip 
                    label={`${statsData?.enabledRules ?? 0}/${statsData?.totalRules ?? 0}`} 
                    size="small" 
                    variant="outlined"
                    color={statsData?.enabledRules ? 'success' : 'default'}
                  />
                </Box>
              }
              id="inject-tab-0" 
              aria-controls="inject-tabpanel-0" 
            />
            <Tab
              label={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  Events
                  {(statsData?.totalEvents ?? 0) > 0 && (
                    <Badge 
                      badgeContent={statsData?.eventsByResult?.failed ?? 0} 
                      color="error"
                      max={99}
                    >
                      <Chip label={statsData?.totalEvents} size="small" color="primary" />
                    </Badge>
                  )}
                </Box>
              }
              id="inject-tab-1"
              aria-controls="inject-tabpanel-1"
            />
          </Tabs>
        </Paper>

        {/* Rules Tab */}
        <TabPanel value={tabValue} index={0}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="body2" color="text.secondary">
              Total: {rules.length} rule{rules.length !== 1 ? 's' : ''} • Enabled: {rules.filter((r) => r.enabled).length}
            </Typography>
            <Button
              data-learn="Create Injection Rule: Create a new packet manipulation rule for network injection."
              variant="contained"
              color="primary"
              startIcon={<AddIcon />}
              onClick={() => handleOpenDialog()}
            >
              Create Rule
            </Button>
          </Box>

          {/* Search Input */}
          <Box sx={{ mb: 3 }}>
            <TextField
              data-learn="Search Rules: Filter injection rules by name, description, expression, or action."
              fullWidth
              placeholder="Search rules by name, description, expression, or action..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: <SearchIcon sx={{ color: 'action.active', mr: 1 }} />,
                endAdornment: searchQuery && (
                  <IconButton size="small" onClick={() => setSearchQuery('')} edge="end">
                    <ClearIcon />
                  </IconButton>
                ),
              }}
              variant="outlined"
              size="small"
            />
          </Box>

          {/* Tag Filter */}
          {allTags.length > 0 && (
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }} onClick={() => setTagsExpanded(!tagsExpanded)}>
                <Typography variant="subtitle2">Filter by Tags</Typography>
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
                    <Chip label="Clear All" color="secondary" onClick={() => setSelectedTags([])} variant="outlined" />
                  )}
                </Box>
              )}
            </Box>
          )}

          {rulesError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              Failed to load injection rules: {rulesError.message}
            </Alert>
          )}

          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Action</TableCell>
                  <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>Expression</TableCell>
                  <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>Priority</TableCell>
                  <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>Tags</TableCell>
                  <TableCell>Enabled</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredRules.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <Typography variant="body2" color="text.secondary">
                        {rules.length === 0
                          ? 'No injection rules defined. Click "Create Rule" to add your first rule.'
                          : 'No rules match the selected filters.'}
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
                          <Typography variant="body1" fontWeight="medium">
                            {rule.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {rule.description}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip label={rule.type} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          {rule.action.startsWith('iptables_') && (
                            <Tooltip title="Firewall action (Linux only)">
                              <SecurityIcon fontSize="small" color="error" />
                            </Tooltip>
                          )}
                          <Chip
                            label={rule.action.replace(/_/g, ' ')}
                            size="small"
                            color={getActionColor(rule.action) as any}
                          />
                        </Box>
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                        <Tooltip title={rule.expression}>
                          <Box>
                            <FilterExpressionInline expression={rule.expression} maxWidth={250} />
                          </Box>
                        </Tooltip>
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                        <Typography variant="body2">{rule.priority}</Typography>
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {rule.tags.slice(0, 3).map((tag) => (
                            <Chip key={tag} label={tag} size="small" />
                          ))}
                          {rule.tags.length > 3 && (
                            <Chip label={`+${rule.tags.length - 3}`} size="small" variant="outlined" />
                          )}
                        </Box>
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Switch
                          size="small"
                          checked={rule.enabled}
                          onChange={(e) => handleToggleEnabled(rule, e.target.checked)}
                          color="success"
                        />
                      </TableCell>
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                        <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'flex-end' }}>
                          <Tooltip title="Duplicate">
                            <IconButton
                              size="small"
                              onClick={() => handleDuplicate(rule)}
                              color="default"
                            >
                              <ContentCopyIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Edit">
                            <IconButton
                              size="small"
                              onClick={() => handleOpenDialog(rule)}
                              color="primary"
                            >
                              <EditIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              onClick={() => handleDelete(rule.id)}
                              color="error"
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
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
        </TabPanel>

        {/* Events Tab */}
        <TabPanel value={tabValue} index={1}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Typography variant="body2" color="text.secondary">
                Showing: {events.length} event{events.length !== 1 ? 's' : ''}
                {(eventFilterRule || eventFilterResult || eventFilterAction) && (
                  <Chip 
                    label="Filtered" 
                    size="small" 
                    color="primary" 
                    sx={{ ml: 1 }} 
                    onDelete={() => {
                      setEventFilterRule('');
                      setEventFilterResult('');
                      setEventFilterAction('');
                    }}
                  />
                )}
              </Typography>
              <Button
                size="small"
                startIcon={<FilterListIcon />}
                onClick={() => setShowEventFilters(!showEventFilters)}
                variant={showEventFilters ? 'contained' : 'text'}
              >
                Filters
              </Button>
            </Box>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="outlined"
                size="small"
                startIcon={<RefreshIcon />}
                onClick={() => {
                  mutate(eventFilterKey);
                  mutate('injectionStats');
                }}
              >
                Refresh
              </Button>
              <Button
                variant="outlined"
                size="small"
                color="error"
                startIcon={<ClearAllIcon />}
                onClick={handleClearEvents}
                disabled={events.length === 0}
              >
                Clear All
              </Button>
            </Box>
          </Box>

          {/* Event Filters */}
          {showEventFilters && (
            <Paper sx={{ p: 2, mb: 2 }} variant="outlined">
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', alignItems: 'center' }}>
                <FormControl size="small" sx={{ minWidth: 180 }}>
                  <InputLabel>Filter by Rule</InputLabel>
                  <Select
                    value={eventFilterRule}
                    label="Filter by Rule"
                    onChange={(e) => setEventFilterRule(e.target.value)}
                  >
                    <MenuItem value="">All Rules</MenuItem>
                    {rules.map((rule) => (
                      <MenuItem key={rule.id} value={rule.name}>
                        {rule.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 140 }}>
                  <InputLabel>Filter by Result</InputLabel>
                  <Select
                    value={eventFilterResult}
                    label="Filter by Result"
                    onChange={(e) => setEventFilterResult(e.target.value)}
                  >
                    <MenuItem value="">All Results</MenuItem>
                    <MenuItem value="success">Success</MenuItem>
                    <MenuItem value="failed">Failed</MenuItem>
                    <MenuItem value="skipped">Skipped</MenuItem>
                  </Select>
                </FormControl>
                <FormControl size="small" sx={{ minWidth: 160 }}>
                  <InputLabel>Filter by Action</InputLabel>
                  <Select
                    value={eventFilterAction}
                    label="Filter by Action"
                    onChange={(e) => setEventFilterAction(e.target.value)}
                  >
                    <MenuItem value="">All Actions</MenuItem>
                    {actions.map((action) => (
                      <MenuItem key={action.value} value={action.value}>
                        {action.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                {(eventFilterRule || eventFilterResult || eventFilterAction) && (
                  <Button
                    size="small"
                    onClick={() => {
                      setEventFilterRule('');
                      setEventFilterResult('');
                      setEventFilterAction('');
                    }}
                  >
                    Clear Filters
                  </Button>
                )}
              </Box>
            </Paper>
          )}

          {eventsError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              Failed to load injection events: {eventsError.message}
            </Alert>
          )}

          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Time</TableCell>
                  <TableCell>Rule</TableCell>
                  <TableCell>Action</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Destination</TableCell>
                  <TableCell>Result</TableCell>
                  <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>Details</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {events.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <Typography variant="body2" color="text.secondary">
                        No injection events recorded yet.
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  paginatedEvents.map((event) => (
                    <TableRow key={event.id} hover>
                      <TableCell>
                        <Tooltip title={formatTimestamp(event.timestamp)}>
                          <Typography variant="body2" sx={{ cursor: 'help' }}>
                            {formatRelativeTime(event.timestamp)}
                          </Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {event.ruleName}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={event.ruleAction.replace(/_/g, ' ')}
                          size="small"
                          color={getActionColor(event.ruleAction) as any}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip label={event.recordType} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {event.srcIP}
                          {event.srcPort ? `:${event.srcPort}` : ''}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {event.dstIP}
                          {event.dstPort ? `:${event.dstPort}` : ''}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          {getResultIcon(event.result)}
                          <Typography variant="body2">{event.result}</Typography>
                        </Box>
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                        {event.error ? (
                          <Tooltip title={event.error}>
                            <Typography variant="body2" color="error" sx={{ maxWidth: 200 }} noWrap>
                              {event.error}
                            </Typography>
                          </Tooltip>
                        ) : event.actionData ? (
                          <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 200 }} noWrap>
                            {JSON.stringify(event.actionData)}
                          </Typography>
                        ) : (
                          <Typography variant="body2" color="text.disabled">
                            -
                          </Typography>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            <TablePagination
              rowsPerPageOptions={[10, 25, 50, 100]}
              component="div"
              count={events.length}
              rowsPerPage={eventsRowsPerPage}
              page={eventsPage}
              onPageChange={handleChangeEventsPage}
              onRowsPerPageChange={handleChangeEventsRowsPerPage}
            />
          </TableContainer>
        </TabPanel>

        {/* Rule Dialog */}
        <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth>
          <DialogTitle>{editingRule ? 'Edit Injection Rule' : 'Create New Injection Rule'}</DialogTitle>
          <DialogContent>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
              <TextField
                label="Rule Name"
                fullWidth
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                helperText="Unique identifier for this injection rule"
              />

              <TextField
                label="Description"
                fullWidth
                multiline
                rows={2}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                helperText="Human-readable description of what this rule does"
              />

              <Box sx={{ display: 'flex', gap: 2 }}>
                <FormControl fullWidth required>
                  <InputLabel>Record Type</InputLabel>
                  <Select
                    value={formData.type}
                    label="Record Type"
                    onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  >
                    <MenuItem value="TCP">TCP</MenuItem>
                    <MenuItem value="UDP">UDP</MenuItem>
                    <MenuItem value="DNS">DNS</MenuItem>
                    <MenuItem value="ARP">ARP</MenuItem>
                    <MenuItem value="HTTP">HTTP</MenuItem>
                    <MenuItem value="ICMPv4">ICMPv4</MenuItem>
                    <MenuItem value="ICMPv6">ICMPv6</MenuItem>
                    <MenuItem value="IPv4">IPv4</MenuItem>
                    <MenuItem value="IPv6">IPv6</MenuItem>
                    <MenuItem value="Ethernet">Ethernet</MenuItem>
                  </Select>
                </FormControl>

                <FormControl fullWidth required>
                  <InputLabel>Action</InputLabel>
                  <Select
                    value={formData.action}
                    label="Action"
                    onChange={(e) => setFormData({ ...formData, action: e.target.value, actionConfig: {} })}
                  >
                    {/* Group actions by category */}
                    {['basic', 'injection', 'modification', 'http', 'firewall'].map((category) => {
                      const categoryActions = actions.filter((a) => a.category === category);
                      if (categoryActions.length === 0) return null;
                      return [
                        <MenuItem key={`cat-${category}`} disabled sx={{ opacity: 0.7, fontWeight: 'bold', textTransform: 'uppercase', fontSize: '0.75rem', mt: 1 }}>
                          {category === 'firewall' ? '🔒 Firewall (Linux only)' : category}
                        </MenuItem>,
                        ...categoryActions.map((action) => (
                          <MenuItem key={action.value} value={action.value} sx={{ pl: 3 }}>
                            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, width: '100%' }}>
                              {action.category === 'firewall' && <SecurityIcon fontSize="small" color="error" sx={{ mt: 0.5 }} />}
                              <Box>
                                <Typography variant="body2">{action.label}</Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {action.description}
                                </Typography>
                              </Box>
                            </Box>
                          </MenuItem>
                        )),
                      ];
                    })}
                  </Select>
                </FormControl>
              </Box>

              <SyntaxHighlightedTextArea
                syntaxType="filter"
                value={formData.expression}
                onChange={(value) => setFormData({ ...formData, expression: value })}
                label="Expression"
                helperText="Expr-lang expression to evaluate (e.g., 'SYN && !ACK', 'DstPort == 22')"
                rows={4}
                fullWidth
              />

              {/* Linux-only warning for iptables actions */}
              {formData.action.startsWith('iptables_') && (
                <Alert severity="info" icon={<InfoOutlinedIcon />}>
                  <Typography variant="body2">
                    <strong>Linux Required:</strong> This action uses iptables and only works on Linux systems with root/CAP_NET_ADMIN privileges.
                  </Typography>
                </Alert>
              )}

              {/* Action Config Fields */}
              {currentActionFields.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    Action Configuration
                  </Typography>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {currentActionFields.map((field) => {
                      if (field.type === 'select' && field.options) {
                        const options = field.options.split(',');
                        return (
                          <FormControl key={field.name} fullWidth size="small">
                            <InputLabel>{field.label}</InputLabel>
                            <Select
                              value={(formData.actionConfig?.[field.name] as string) || ''}
                              label={field.label}
                              onChange={(e) =>
                                setFormData({
                                  ...formData,
                                  actionConfig: { ...formData.actionConfig, [field.name]: e.target.value },
                                })
                              }
                            >
                              {options.map((opt) => (
                                <MenuItem key={opt} value={opt}>
                                  {opt}
                                </MenuItem>
                              ))}
                            </Select>
                          </FormControl>
                        );
                      }
                      return (
                        <TextField
                          key={field.name}
                          label={field.label}
                          type={field.type === 'number' ? 'number' : 'text'}
                          fullWidth
                          size="small"
                          required={field.required === 'true'}
                          value={(formData.actionConfig?.[field.name] as string | number) || ''}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              actionConfig: {
                                ...formData.actionConfig,
                                [field.name]: field.type === 'number' ? parseInt(e.target.value) || 0 : e.target.value,
                              },
                            })
                          }
                        />
                      );
                    })}
                  </Box>
                </Box>
              )}

              <Box sx={{ display: 'flex', gap: 2 }}>
                <TextField
                  label="Priority"
                  type="number"
                  size="small"
                  value={formData.priority || 50}
                  onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 50 })}
                  helperText="Higher = evaluated first"
                  sx={{ width: 150 }}
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.stopOnMatch || false}
                      onChange={(e) => setFormData({ ...formData, stopOnMatch: e.target.checked })}
                    />
                  }
                  label="Stop on Match"
                />
              </Box>

              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Tags
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField
                    size="small"
                    fullWidth
                    placeholder="e.g., dns, spoofing"
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
                  {(formData.tags || []).map((tag) => (
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
              disabled={!formData.name || !formData.type || !formData.expression || !formData.action}
            >
              {editingRule ? 'Update' : 'Create'}
            </Button>
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

