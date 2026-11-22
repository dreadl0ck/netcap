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
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import SecurityIcon from '@mui/icons-material/Security';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { Close as CloseIcon } from '@mui/icons-material';
import FilterListIcon from '@mui/icons-material/FilterList';
import Layout from '../components/Layout';
import { InjectionRule, InjectionEvent, InjectionAction, CreateInjectionRuleRequest, UpdateInjectionRuleRequest, formatTimestamp } from '../lib/api';
import { parseSearchQuery, matchesSearchTerms } from '../lib/tableSearch';
import { useNetcapApi, useIsMobile } from '../hooks';

import { SyntaxHighlightedTextArea } from '../components/SyntaxHighlightedInput';
import { FilterExpressionInline } from '../components/FilterExpressionHighlight';
import SearchInput from '../components/SearchInput';
import { translate as i18nText, message as i18nMessage, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as mutate } from "../lib/i18n";
import { translate, renderError } from "../lib/i18n";
import { recordTypeLabel, metadataText } from "../lib/i18n";
import { errorText, formatRelativeTime as relativeTime } from "../lib/i18n";
import { message as i18nParameterMessage } from "../lib/i18n";







// Format relative time (e.g., "2 minutes ago")
function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp / 1_000_000; // Convert nanoseconds to milliseconds
  
  if (diff < 60_000) return i18nText("removed:m_e2710ce9add021533c91");
  if (diff < 3600_000) {
    const mins = Math.floor(diff / 60_000);
    return relativeTime(-mins, 'minute');
  }
  if (diff < 86400_000) {
    const hours = Math.floor(diff / 3600_000);
    return relativeTime(-hours, 'hour');
  }
  const days = Math.floor(diff / 86400_000);
  return relativeTime(-days, 'day');
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const __uiLocale = useUILocale();
  const { children, value, index, ...other } = props;

  return (
    <div role="tabpanel"
      hidden={value !== index}
      id={`inject-tabpanel-${index}`}
      aria-labelledby={`inject-tab-${index}`}
      {...other}>{value === index && <Box sx={{ py: 3 }}>{children}</Box>}</div>
  );
}

export default function InjectPage() {
  const __uiLocale = useUILocale();
  const isMobile = useIsMobile();
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
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: UIMessageText; severity: 'success' | 'error' }>({
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

  // Filter rules by search query and selected tags (supports negation with !term)
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      // Filter by search query with negation support
      if (searchQuery) {
        const searchTerms = parseSearchQuery(searchQuery);
        const matchesSearch = matchesSearchTerms([
          rule.name,
          rule.description,
          rule.expression,
          rule.action,
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
        setSnackbar({ open: true, message: i18nMessage("removed:m_6cfc0ebe7f49f76ed52d"), severity: 'success' });
      } else {
        await api.createInjectionRule(formData);
        setSnackbar({ open: true, message: i18nMessage("removed:m_5da9d036192ceefb4067"), severity: 'success' });
      }
      mutate('injectionRules');
      mutate('injectionStats');
      handleCloseDialog();
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("removed:m_93793a471832e33496b0"), severity: 'error' });
    }
  };

  const handleDelete = async (ruleId: string) => {
    if (!confirm(i18nText("removed:m_0e0120e8ba9f5a6850ee"))) return;

    try {
      await api.deleteInjectionRule(ruleId);
      setSnackbar({ open: true, message: i18nMessage("removed:m_d98c77640a84a6540f0e"), severity: 'success' });
      mutate('injectionRules');
      mutate('injectionStats');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("removed:m_f5401b1701c733b124c4"), severity: 'error' });
    }
  };

  const handleToggleEnabled = async (rule: InjectionRule, enabled: boolean) => {
    try {
      await api.toggleInjectionRule(rule.id, enabled);
      setSnackbar({ open: true, message: i18nMessage("removed:m_b2369527aa2ef9612e38", { arg0: rule.name, arg1: enabled ? i18nParameterMessage("removed:m_e51446f30214e1d15adb") : i18nParameterMessage("removed:m_16cbf16002fe9b16eeed") }), severity: 'success' });
      mutate('injectionRules');
      mutate('injectionStats');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("removed:m_0ae8350fc10d70316974"), severity: 'error' });
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
    if (!confirm(i18nText("removed:m_04b8863dc15a9d3811f7"))) return;

    try {
      await api.clearInjectionEvents();
      setSnackbar({ open: true, message: i18nMessage("removed:m_67a12185f5f8ec68f1c1"), severity: 'success' });
      mutate(eventFilterKey);
      mutate('injectionStats');
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? errorText(err) : i18nMessage("removed:m_87ff8f554ac209762fc9"), severity: 'error' });
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
    <Layout title={i18nText("removed:m_6db9a2ef5f84e9c8c95b")}><Box>{/* Stats Overview */}<Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}><Card sx={{ minWidth: 140 }}><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="caption" color="text.secondary">
                {i18nText("removed:m_75e77800e8f4e850f00b")}
              </Typography><Typography variant="h5">{statsData?.totalRules ?? 0}</Typography></CardContent></Card><Card sx={{ minWidth: 140 }}><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="caption" color="text.secondary">
                {i18nText("removed:m_23052c4fec9eb3ac70e9")}
              </Typography><Typography variant="h5" color="success.main">{statsData?.enabledRules ?? 0}</Typography></CardContent></Card><Divider orientation="vertical" flexItem /><Card sx={{ minWidth: 140 }}><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="caption" color="text.secondary">
                {i18nText("removed:m_fe2f0a2f72970ce0e415")}
              </Typography><Typography variant="h5">{statsData?.totalEvents ?? 0}</Typography></CardContent></Card><Card sx={{ minWidth: 120 }}><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="caption" color="text.secondary">
                {i18nText("removed:m_74720a7ce02c9b30dc05")}
              </Typography><Typography variant="h5" color="success.main">{statsData?.eventsByResult?.success ?? 0}</Typography></CardContent></Card><Card sx={{ minWidth: 120 }}><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Typography variant="caption" color="text.secondary">
                {i18nText("removed:m_84467753c7ab0e9cbb37")}
              </Typography><Typography variant="h5" color="error.main">{statsData?.eventsByResult?.failed ?? 0}</Typography></CardContent></Card></Box>{/* Tabs */}<Paper sx={{ mb: 2 }}><Tabs value={tabValue} onChange={handleTabChange} aria-label={i18nText("removed:m_d62d80acbab81298d6b2")}><Tab label={<Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {i18nText("removed:m_0669d31220e647cb9221")}
                  <Chip label={`${statsData?.enabledRules ?? 0}/${statsData?.totalRules ?? 0}`} 
                    size="small" 
                    variant="outlined"
                    color={statsData?.enabledRules ? 'success' : 'default'} /></Box>}
              id="inject-tab-0" 
              aria-controls="inject-tabpanel-0" /><Tab label={<Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {i18nRichText("removed:m_4a4d40183c63a762c46a", { arg0: (statsData?.totalEvents ?? 0) > 0 && (
                    <Badge badgeContent={statsData?.eventsByResult?.failed ?? 0} 
                      color="error"
                      max={99}><Chip label={statsData?.totalEvents} size="small" color="primary" /></Badge>
                  ) })}
                </Box>}
              id="inject-tab-1"
              aria-controls="inject-tabpanel-1" /></Tabs></Paper>{/* Rules Tab */}<TabPanel value={tabValue} index={0}><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}><Typography variant="body2" color="text.secondary">
              {i18nRichText("removed:m_e6698a56358cd1d80d90", { arg0: rules.length, arg2: rules.filter((r) => r.enabled).length })}
            </Typography><Button data-learn={i18nText("removed:m_3f9afcc5ff4ef9b9d1d7")}
              variant="contained"
              color="primary"
              startIcon={<AddIcon />}
              onClick={() => handleOpenDialog()}>
              {i18nText("removed:m_547415eac67b0ddf2af6")}
            </Button></Box>{/* Search Input */}<Box sx={{ mb: 3 }}><SearchInput value={searchQuery}
              onChange={setSearchQuery}
              placeholder={i18nText("removed:m_614640590e80ae6d9539")}
              learnHint={translate("removed:m_84204fb297944127e555")}
              sx={{ width: '100%' }} /></Box>{/* Tag Filter */}{allTags.length > 0 && (
            <Box sx={{ mb: 3 }}><Box sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }} onClick={() => setTagsExpanded(!tagsExpanded)}><Typography variant="subtitle2">{i18nText("removed:m_e63ed7e1a5ce36d58ac2")}</Typography><IconButton size="small" sx={{ ml: 0.5 }}>{tagsExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}</IconButton><Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                  {i18nRichText("removed:m_68a1eae685401c7894b8", { arg0: allTags.length, arg1: selectedTags.length > 0 ? i18nText("removed:m_8d31103e0a3566a533c4", { arg0: selectedTags.length }) : '' })}
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
                    <Chip label={i18nText("removed:m_0cb3d73ec88de1474e7b")} color="secondary" onClick={() => setSelectedTags([])} variant="outlined" />
                  )}</Box>
              )}</Box>
          )}{rulesError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {i18nRichText("removed:m_4842ed3ec8dbb496d60c", { arg0: renderError(rulesError) })}
            </Alert>
          )}<TableContainer component={Paper}><Table><TableHead><TableRow><TableCell>{i18nText("removed:m_e707e3dfaa88e6753600")}</TableCell><TableCell>{i18nText("removed:m_3da346bd3b7d84ce65d6")}</TableCell><TableCell>{i18nText("removed:m_1a3caa8a333177645dfb")}</TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>{i18nText("removed:m_a5c510d332d1b044bf9a")}</TableCell><TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>{i18nText("removed:m_10027345b7680efef5c8")}</TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>{i18nText("removed:m_47846a266ab7374ce1aa")}</TableCell><TableCell>{i18nText("removed:m_23052c4fec9eb3ac70e9")}</TableCell><TableCell align="right">{i18nText("removed:m_8b59af6a47204b74041c")}</TableCell></TableRow></TableHead><TableBody>{filteredRules.length === 0 ? (
                  <TableRow><TableCell colSpan={8} align="center"><Typography variant="body2" color="text.secondary">{rules.length === 0 ? i18nText("removed:m_0db790baabc00d6d63ed") : i18nText("removed:m_28906e3b7d0f0dea0c10")}</Typography></TableCell></TableRow>
                ) : (
                  paginatedRules.map((rule) => (
                    <TableRow key={rule.id}
                      hover
                      onClick={() => handleOpenDialog(rule)}
                      sx={{ cursor: 'pointer' }}><TableCell><Box><Typography variant="body1" fontWeight="medium">{rule.name}</Typography><Typography variant="caption" color="text.secondary">{rule.description}</Typography></Box></TableCell><TableCell><Chip label={recordTypeLabel(rule.type)} size="small" variant="outlined" /></TableCell><TableCell><Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>{rule.action.startsWith('iptables_') && (
                            <Tooltip title={i18nText("removed:m_7a2a9e0c82166fb79701")}><SecurityIcon fontSize="small" color="error" /></Tooltip>
                          )}<Chip label={rule.action.replace(/_/g, ' ')}
                            size="small"
                            color={getActionColor(rule.action) as any} /></Box></TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}><Tooltip title={rule.expression}><Box><FilterExpressionInline expression={rule.expression} maxWidth={250} /></Box></Tooltip></TableCell><TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}><Typography variant="body2">{rule.priority}</Typography></TableCell><TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{rule.tags.slice(0, 3).map((tag) => (
                            <Chip key={tag} label={tag} size="small" />
                          ))}{rule.tags.length > 3 && (
                            <Chip label={`+${rule.tags.length - 3}`} size="small" variant="outlined" />
                          )}</Box></TableCell><TableCell onClick={(e) => e.stopPropagation()}><Switch size="small"
                          checked={rule.enabled}
                          onChange={(e) => handleToggleEnabled(rule, e.target.checked)}
                          color="success" /></TableCell><TableCell align="right" onClick={(e) => e.stopPropagation()}><Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'flex-end' }}><Tooltip title={i18nText("removed:m_234043da016bd5cc8db4")}><IconButton size="small"
                              onClick={() => handleDuplicate(rule)}
                              color="default"><ContentCopyIcon fontSize="small" /></IconButton></Tooltip><Tooltip title={i18nText("removed:m_5ecc9e41cd95e17be85f")}><IconButton size="small"
                              onClick={() => handleOpenDialog(rule)}
                              color="primary"><EditIcon fontSize="small" /></IconButton></Tooltip><Tooltip title={i18nText("removed:m_c1be408539d8c22dfb4a")}><IconButton size="small"
                              onClick={() => handleDelete(rule.id)}
                              color="error"><DeleteIcon fontSize="small" /></IconButton></Tooltip></Box></TableCell></TableRow>
                  ))
                )}</TableBody></Table><TablePagination rowsPerPageOptions={[10, 25, 50, 100]}
              component="div"
              count={filteredRules.length}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={handleChangePage}
              onRowsPerPageChange={handleChangeRowsPerPage} /></TableContainer></TabPanel>{/* Events Tab */}<TabPanel value={tabValue} index={1}><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}><Typography variant="body2" color="text.secondary">
                {i18nRichText("removed:m_5b530b1c88f7c1971123", { arg0: events.length, arg2: (eventFilterRule || eventFilterResult || eventFilterAction) && (
                  <Chip label={i18nText("removed:m_487f3f5ce7bd438fdb8c")} 
                    size="small" 
                    color="primary" 
                    sx={{ ml: 1 }} 
                    onDelete={() => {
                      setEventFilterRule('');
                      setEventFilterResult('');
                      setEventFilterAction('');
                    }} />
                ) })}
              </Typography><Button size="small"
                startIcon={<FilterListIcon />}
                onClick={() => setShowEventFilters(!showEventFilters)}
                variant={showEventFilters ? 'contained' : 'text'}>
                {i18nText("removed:m_80ec630a8859e539ec99")}
              </Button></Box><Box sx={{ display: 'flex', gap: 1 }}><Button variant="outlined"
                size="small"
                startIcon={<RefreshIcon />}
                onClick={() => {
                  mutate(eventFilterKey);
                  mutate('injectionStats');
                }}>
                {i18nText("removed:m_230fc1b63eb3ef4e6a34")}
              </Button><Button variant="outlined"
                size="small"
                color="error"
                startIcon={<ClearAllIcon />}
                onClick={handleClearEvents}
                disabled={events.length === 0}>
                {i18nText("removed:m_0cb3d73ec88de1474e7b")}
              </Button></Box></Box>{/* Event Filters */}{showEventFilters && (
            <Paper sx={{ p: 2, mb: 2 }} variant="outlined"><Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', alignItems: 'center' }}><FormControl size="small" sx={{ minWidth: 180 }}><InputLabel>{i18nText("removed:m_1efc4c170dbfe57c4d63")}</InputLabel><Select value={eventFilterRule}
                    label={i18nText("removed:m_1efc4c170dbfe57c4d63")}
                    onChange={(e) => setEventFilterRule(e.target.value)}><MenuItem value="">{i18nText("removed:m_cd3ecfc631ecc41922b4")}</MenuItem>{rules.map((rule) => (
                      <MenuItem key={rule.id} value={rule.name}>{rule.name}</MenuItem>
                    ))}</Select></FormControl><FormControl size="small" sx={{ minWidth: 140 }}><InputLabel>{i18nText("removed:m_2aa5d3510227a164df7e")}</InputLabel><Select value={eventFilterResult}
                    label={i18nText("removed:m_2aa5d3510227a164df7e")}
                    onChange={(e) => setEventFilterResult(e.target.value)}><MenuItem value="">{i18nText("removed:m_901d133658e0655f7e32")}</MenuItem><MenuItem value="success">{i18nText("removed:m_74720a7ce02c9b30dc05")}</MenuItem><MenuItem value="failed">{i18nText("removed:m_84467753c7ab0e9cbb37")}</MenuItem><MenuItem value="skipped">{i18nText("removed:m_4b96e6eb6676d2f65e93")}</MenuItem></Select></FormControl><FormControl size="small" sx={{ minWidth: 160 }}><InputLabel>{i18nText("removed:m_c092e6e908739e4a2ed8")}</InputLabel><Select value={eventFilterAction}
                    label={i18nText("removed:m_c092e6e908739e4a2ed8")}
                    onChange={(e) => setEventFilterAction(e.target.value)}><MenuItem value="">{i18nText("removed:m_6ae8a9aa006c6fc6462c")}</MenuItem>{actions.map((action) => (
                      <MenuItem key={action.value} value={action.value}>{metadataText(action, "label")}</MenuItem>
                    ))}</Select></FormControl>{(eventFilterRule || eventFilterResult || eventFilterAction) && (
                  <Button size="small"
                    onClick={() => {
                      setEventFilterRule('');
                      setEventFilterResult('');
                      setEventFilterAction('');
                    }}>
                    {i18nText("removed:m_aa5d7c554e15b940ae39")}
                  </Button>
                )}</Box></Paper>
          )}{eventsError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {i18nRichText("removed:m_aaeb9eee1c3a7f221d5d", { arg0: renderError(eventsError) })}
            </Alert>
          )}<TableContainer component={Paper}><Table><TableHead><TableRow><TableCell>{i18nText("removed:m_b62418ba3d29bf760ea0")}</TableCell><TableCell>{i18nText("removed:m_302f3877c278fc8de616")}</TableCell><TableCell>{i18nText("removed:m_1a3caa8a333177645dfb")}</TableCell><TableCell>{i18nText("removed:m_3da346bd3b7d84ce65d6")}</TableCell><TableCell>{i18nText("removed:m_4113167561ccea5b6c6b")}</TableCell><TableCell>{i18nText("removed:m_4b35e0eccce697e20a4d")}</TableCell><TableCell>{i18nText("removed:m_58b38fc01db34a4285a1")}</TableCell><TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>{i18nText("removed:m_0e07624e3854b301c0e2")}</TableCell></TableRow></TableHead><TableBody>{events.length === 0 ? (
                  <TableRow><TableCell colSpan={8} align="center"><Typography variant="body2" color="text.secondary">
                        {i18nText("removed:m_21047fb9aacbb697c0a4")}
                      </Typography></TableCell></TableRow>
                ) : (
                  paginatedEvents.map((event) => (
                    <TableRow key={event.id} hover><TableCell><Tooltip title={formatTimestamp(event.timestamp, 'nanoseconds')}><Typography variant="body2" sx={{ cursor: 'help' }}>{formatRelativeTime(event.timestamp)}</Typography></Tooltip></TableCell><TableCell><Typography variant="body2" fontWeight="medium">{event.ruleName}</Typography></TableCell><TableCell><Chip label={event.ruleAction.replace(/_/g, ' ')}
                          size="small"
                          color={getActionColor(event.ruleAction) as any} /></TableCell><TableCell><Chip label={recordTypeLabel(event.recordType)} size="small" variant="outlined" /></TableCell><TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{event.srcIP}{event.srcPort ? `:${event.srcPort}` : ''}</Typography></TableCell><TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{event.dstIP}{event.dstPort ? `:${event.dstPort}` : ''}</Typography></TableCell><TableCell><Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>{getResultIcon(event.result)}<Typography variant="body2">{event.result}</Typography></Box></TableCell><TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>{event.error ? (
                          <Tooltip title={event.error}><Typography variant="body2" color="error" sx={{ maxWidth: 200 }} noWrap>{event.error}</Typography></Tooltip>
                        ) : event.actionData ? (
                          <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 200 }} noWrap>{JSON.stringify(event.actionData)}</Typography>
                        ) : (
                          <Typography variant="body2" color="text.disabled">-
                          </Typography>
                        )}</TableCell></TableRow>
                  ))
                )}</TableBody></Table><TablePagination rowsPerPageOptions={[10, 25, 50, 100]}
              component="div"
              count={events.length}
              rowsPerPage={eventsRowsPerPage}
              page={eventsPage}
              onPageChange={handleChangeEventsPage}
              onRowsPerPageChange={handleChangeEventsRowsPerPage} /></TableContainer></TabPanel>{/* Rule Dialog */}<Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">{editingRule ? i18nText("removed:m_b7e3faf1505e7198700f") : i18nText("removed:m_5a423ea36788720192ce")}{isMobile && (
                <IconButton onClick={handleCloseDialog} edge="end"><CloseIcon /></IconButton>
              )}</Box></DialogTitle><DialogContent><Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}><TextField label={i18nText("removed:m_752576a3b0b2dca4ab6a")}
                fullWidth
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                helperText={i18nText("removed:m_6c6efe97edb022eb3065")} /><TextField label={i18nText("removed:m_a02602e322c10d1a5449")}
                fullWidth
                multiline
                rows={2}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                helperText={i18nText("removed:m_c545179432fabe641eb0")} /><Box sx={{ display: 'flex', gap: 2 }}><FormControl fullWidth required><InputLabel>{i18nText("removed:m_21e984a0c1b0479051bc")}</InputLabel><Select value={formData.type}
                    label={i18nText("removed:m_21e984a0c1b0479051bc")}
                    onChange={(e) => setFormData({ ...formData, type: e.target.value })}><MenuItem value="TCP">TCP</MenuItem><MenuItem value="UDP">UDP</MenuItem><MenuItem value="DNS">DNS</MenuItem><MenuItem value="ARP">ARP</MenuItem><MenuItem value="HTTP">HTTP</MenuItem><MenuItem value="ICMPv4">{i18nText("removed:m_7e3752209583fe744c65")}</MenuItem><MenuItem value="ICMPv6">ICMPv6</MenuItem><MenuItem value="IPv4">IPv4</MenuItem><MenuItem value="IPv6">IPv6</MenuItem><MenuItem value="Ethernet">{i18nText("removed:m_2791087a36aa29c47d91")}</MenuItem></Select></FormControl><FormControl fullWidth required><InputLabel>{i18nText("removed:m_1a3caa8a333177645dfb")}</InputLabel><Select value={formData.action}
                    label={i18nText("removed:m_1a3caa8a333177645dfb")}
                    onChange={(e) => setFormData({ ...formData, action: e.target.value, actionConfig: {} })}>{/* Group actions by category */}{['basic', 'injection', 'modification', 'http', 'firewall'].map((category) => {
                      const categoryActions = actions.filter((a) => a.category === category);
                      if (categoryActions.length === 0) return null;
                      return [
                        <MenuItem key={`cat-${category}`} disabled sx={{ opacity: 0.7, fontWeight: 'bold', textTransform: 'uppercase', fontSize: '0.75rem', mt: 1 }}>{category === 'firewall' ? i18nText("removed:m_7b88ee7a10074ebfa882") : i18nText(category)}</MenuItem>,
                        ...categoryActions.map((action) => (
                          <MenuItem key={action.value} value={action.value} sx={{ pl: 3 }}><Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, width: '100%' }}>{action.category === 'firewall' && <SecurityIcon fontSize="small" color="error" sx={{ mt: 0.5 }} />}<Box><Typography variant="body2">{metadataText(action, "label")}</Typography><Typography variant="caption" color="text.secondary">{metadataText(action, "description")}</Typography></Box></Box></MenuItem>
                        )),
                      ];
                    })}</Select></FormControl></Box><SyntaxHighlightedTextArea syntaxType="filter"
                value={formData.expression}
                onChange={(value) => setFormData({ ...formData, expression: value })}
                label={i18nText("removed:m_a5c510d332d1b044bf9a")}
                helperText={i18nText("removed:m_bbad6b9f87c0e32c9140")}
                rows={4}
                fullWidth />{/* Linux-only warning for iptables actions */}{formData.action.startsWith('iptables_') && (
                <Alert severity="info" icon={<InfoOutlinedIcon />}><Typography variant="body2">
                    {i18nRichText("removed:m_c5ad96bfbeb893a745d5", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}
                  </Typography></Alert>
              )}{/* Action Config Fields */}{currentActionFields.length > 0 && (
                <Box><Typography variant="subtitle2" gutterBottom>
                    {i18nText("removed:m_68b502047f6d9f0c761e")}
                  </Typography><Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>{currentActionFields.map((field) => {
                      if (field.type === 'select' && field.options) {
                        const options = field.options.split(',');
                        return (
                          <FormControl key={field.name} fullWidth size="small"><InputLabel>{field.label}</InputLabel><Select value={(formData.actionConfig?.[field.name] as string) || ''}
                              label={field.label}
                              onChange={(e) =>
                                setFormData({
                                  ...formData,
                                  actionConfig: { ...formData.actionConfig, [field.name]: e.target.value },
                                })}>{options.map((opt) => (
                                <MenuItem key={opt} value={opt}>{opt}</MenuItem>
                              ))}</Select></FormControl>
                        );
                      }
                      return (
                        <TextField key={field.name}
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
                            })} />
                      );
                    })}</Box></Box>
              )}<Box sx={{ display: 'flex', gap: 2 }}><TextField label={i18nText("removed:m_10027345b7680efef5c8")}
                  type="number"
                  size="small"
                  value={formData.priority || 50}
                  onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 50 })}
                  helperText={i18nText("removed:m_525c38fad3395cebdb3a")}
                  sx={{ width: 150 }} /><FormControlLabel control={<Switch checked={formData.stopOnMatch || false}
                      onChange={(e) => setFormData({ ...formData, stopOnMatch: e.target.checked })} />}
                  label={i18nText("removed:m_abb283298cc6f95e50f8")} /></Box><Box><Typography variant="subtitle2" gutterBottom>
                  {i18nText("removed:m_47846a266ab7374ce1aa")}
                </Typography><Box sx={{ display: 'flex', gap: 1, mb: 1 }}><TextField size="small"
                    fullWidth
                    placeholder={i18nText("removed:m_7695c74e737c90f91250")}
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddTag();
                      }
                    }} /><Button variant="outlined" onClick={handleAddTag}>
                    {i18nText("removed:m_44184266e152017ac805")}
                  </Button></Box><Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{(formData.tags || []).map((tag) => (
                    <Chip key={tag} label={tag} onDelete={() => handleRemoveTag(tag)} size="small" />
                  ))}</Box></Box><FormControlLabel control={<Switch checked={formData.enabled}
                    onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })} />}
                label={i18nText("removed:m_b03a203cf0357413cb65")} /></Box></DialogContent><DialogActions><Button onClick={handleCloseDialog}>{i18nText("removed:m_0095547326bed510a824")}</Button><Button onClick={handleSave}
              variant="contained"
              disabled={!formData.name || !formData.type || !formData.expression || !formData.action}>{editingRule ? i18nText("removed:m_6adbe4e719554c8ff213") : i18nText("removed:m_a09c62c4acf8363f90e2")}</Button></DialogActions></Dialog>{/* Snackbar for notifications */}<Snackbar open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}><Alert onClose={() => setSnackbar({ ...snackbar, open: false })}
            severity={snackbar.severity}
            sx={{ width: '100%' }}>{i18nRenderText(snackbar.message)}</Alert></Snackbar></Box></Layout>
  );
}
