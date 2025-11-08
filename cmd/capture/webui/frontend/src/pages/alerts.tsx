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
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  SelectChangeEvent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TableSortLabel,
  TextField,
  Tooltip,
  Typography,
  Alert as MuiAlert,
  Snackbar,
  IconButton,
} from '@mui/material';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';
import VisibilityIcon from '@mui/icons-material/Visibility';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import Layout from '@/components/Layout';
import { api, Alert, GroupedAlert, AlertStatsResponse, formatBytes } from '@/lib/api';
import useSWR, { mutate, mutate as globalMutate } from 'swr';

// Helper function to convert unix timestamps to human-readable format
// fieldName parameter helps identify if we should convert this number
function convertTimestamps(obj: any, fieldName?: string): any {
  if (obj === null || obj === undefined) return obj;
  
  // Only convert numbers if they're in a timestamp field
  if (typeof obj === 'number' && obj > 1000000000 && fieldName) {
    const lowerFieldName = fieldName.toLowerCase();
    const isTimestampField = lowerFieldName === 'timestamp' || 
                             lowerFieldName === 'time' ||
                             lowerFieldName.endsWith('timestamp') ||
                             lowerFieldName.endsWith('time');
    
    if (!isTimestampField) {
      return obj; // Not a timestamp field, return as-is
    }
    
    // Determine if timestamp is in nanoseconds (19 digits), microseconds (16 digits), milliseconds (13 digits), or seconds (10 digits)
    let timestampMs: number;
    if (obj > 1e15) {
      // Nanoseconds (19 digits) or microseconds (16 digits)
      if (obj > 1e17) {
        // Nanoseconds - divide by 1,000,000
        timestampMs = obj / 1000000;
      } else {
        // Microseconds - divide by 1,000
        timestampMs = obj / 1000;
      }
    } else if (obj > 1e12) {
      // Already in milliseconds (13 digits)
      timestampMs = obj;
    } else {
      // Seconds (10 digits) - multiply by 1000
      timestampMs = obj * 1000;
    }
    
    try {
      const date = new Date(timestampMs);
      if (isNaN(date.getTime())) {
        return obj; // Return original if invalid
      }
      return date.toISOString();
    } catch (e) {
      return obj; // Return original on error
    }
  }
  
  if (typeof obj !== 'object') return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(item => convertTimestamps(item));
  }
  
  const result: any = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = convertTimestamps(value, key);
  }
  return result;
}

// Syntax highlighting for JSON
function syntaxHighlight(json: string) {
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
    let cls = 'number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'key';
      } else {
        cls = 'string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'boolean';
    } else if (/null/.test(match)) {
      cls = 'null';
    }
    return '<span class="json-' + cls + '">' + match + '</span>';
  });
}

export default function AlertsPage() {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [ruleFilter, setRuleFilter] = useState<string>('');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [sortBy, setSortBy] = useState<'count' | 'lastSeen' | 'firstSeen' | 'severity'>('lastSeen');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [switchingFile, setSwitchingFile] = useState(false);
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Fetch grouped alerts
  const { data: groupedAlertsData, error } = useSWR(
    ['groupedAlerts', page, rowsPerPage, severityFilter, ruleFilter, sortOrder, sortBy],
    () =>
      api.getGroupedAlerts({
        limit: rowsPerPage,
        offset: page * rowsPerPage,
        severity: severityFilter || undefined,
        ruleName: ruleFilter || undefined,
        sort: sortOrder,
        sortBy: sortBy,
      }),
    {
      refreshInterval: 5000,
    }
  );

  // Fetch alert statistics
  const { data: stats } = useSWR<AlertStatsResponse>('alertStats', () => api.getAlertStats(), {
    refreshInterval: 5000,
  });

  // Extract grouped alerts data
  const groups = groupedAlertsData?.groups || [];
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
    mutate(['groupedAlerts', page, rowsPerPage, severityFilter, ruleFilter, sortOrder, sortBy]);
    mutate('alertStats');
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

  const handleFileChange = async (event: SelectChangeEvent<string>) => {
    const newFile = event.target.value;
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(newFile);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      await mutate(['groupedAlerts', page, rowsPerPage, severityFilter, ruleFilter, sortOrder, sortBy]);
      await mutate('alertStats');
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
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

  const handleClearAlerts = async () => {
    if (!confirm('Are you sure you want to clear all alerts? This action cannot be undone.')) return;

    try {
      await api.clearAlerts();
      setSnackbar({ open: true, message: 'All alerts cleared successfully', severity: 'success' });
      handleRefresh();
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to clear alerts',
        severity: 'error',
      });
    }
  };

  const handleViewDetails = (alert: Alert) => {
    setSelectedAlert(alert);
    setDetailsDialogOpen(true);
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
      default:
        return 'default';
    }
  };

  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp).toLocaleString();
  };

  // Get unique rule names for filter
  const uniqueRules = Array.from(new Set(stats?.byRule ? Object.keys(stats.byRule) : []));

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
    <Layout title="Security Alerts" headerAction={fileSelector}>
      <Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
          <Box>
            {selectedFile && (
              <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center', mt: 1 }}>
                <Typography variant="body1" fontWeight="medium">
                  {totalCount.toLocaleString()} alert{totalCount !== 1 ? 's' : ''}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  for capture:
                </Typography>
                <Chip
                  label={selectedFile.name}
                  size="small"
                  sx={{ 
                    fontFamily: 'monospace', 
                    fontSize: '0.8rem',
                    maxWidth: 400,
                    '& .MuiChip-label': {
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }
                  }}
                />
                <Chip
                  label={formatBytes(selectedFile.size)}
                  size="small"
                  variant="outlined"
                  sx={{ fontSize: '0.75rem' }}
                />
              </Box>
            )}
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleRefresh}>
              Refresh
            </Button>
            <Button 
              variant="outlined" 
              color="error" 
              startIcon={<DeleteIcon />} 
              onClick={handleClearAlerts}
              disabled={totalCount === 0}
            >
              Clear All
            </Button>
          </Box>
        </Box>

        {error && (
          <MuiAlert severity="error" sx={{ mb: 2 }}>
            Failed to load alerts: {error.message}
          </MuiAlert>
        )}

        {/* Statistics Cards */}
        {stats && (
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Typography color="text.secondary" gutterBottom>
                    Total Alerts
                  </Typography>
                  <Typography variant="h4">{stats.totalAlerts}</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Typography color="text.secondary" gutterBottom>
                    Critical Alerts
                  </Typography>
                  <Typography variant="h4" color="error">
                    {stats.criticalAlerts}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Typography color="text.secondary" gutterBottom>
                    By Severity
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
                    {Object.entries(stats.bySeverity).map(([severity, count]) => (
                      <Chip
                        key={severity}
                        label={`${severity}: ${count}`}
                        size="small"
                        color={getSeverityColor(severity) as any}
                      />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Typography color="text.secondary" gutterBottom>
                    Active Rules
                  </Typography>
                  <Typography variant="h4">{Object.keys(stats.byRule).length}</Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        )}

        {/* Filters */}
        <Paper sx={{ p: 2, mb: 2 }}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Severity Filter</InputLabel>
                <Select
                  value={severityFilter}
                  label="Severity Filter"
                  onChange={(e) => {
                    setSeverityFilter(e.target.value);
                    setPage(0);
                  }}
                >
                  <MenuItem value="">All Severities</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Rule Filter</InputLabel>
                <Select
                  value={ruleFilter}
                  label="Rule Filter"
                  onChange={(e) => {
                    setRuleFilter(e.target.value);
                    setPage(0);
                  }}
                >
                  <MenuItem value="">All Rules</MenuItem>
                  {uniqueRules.map((rule) => (
                    <MenuItem key={rule} value={rule}>
                      {rule}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Sort By</InputLabel>
                <Select
                  value={sortBy}
                  label="Sort By"
                  onChange={(e) => setSortBy(e.target.value as 'count' | 'lastSeen' | 'firstSeen' | 'severity')}
                >
                  <MenuItem value="lastSeen">Last Seen</MenuItem>
                  <MenuItem value="firstSeen">First Seen</MenuItem>
                  <MenuItem value="count">Count</MenuItem>
                  <MenuItem value="severity">Severity</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Sort Order</InputLabel>
                <Select
                  value={sortOrder}
                  label="Sort Order"
                  onChange={(e) => setSortOrder(e.target.value as 'asc' | 'desc')}
                >
                  <MenuItem value="desc">Descending</MenuItem>
                  <MenuItem value="asc">Ascending</MenuItem>
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </Paper>

        {/* Grouped Alerts Table */}
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell width="40px"></TableCell>
                <TableCell>
                  <TableSortLabel
                    active={sortBy === 'severity'}
                    direction={sortBy === 'severity' ? sortOrder : 'desc'}
                    onClick={() => handleSort('severity')}
                  >
                    Severity
                  </TableSortLabel>
                </TableCell>
                <TableCell>Rule Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>
                  <TableSortLabel
                    active={sortBy === 'count'}
                    direction={sortBy === 'count' ? sortOrder : 'desc'}
                    onClick={() => handleSort('count')}
                  >
                    Count
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={sortBy === 'firstSeen'}
                    direction={sortBy === 'firstSeen' ? sortOrder : 'desc'}
                    onClick={() => handleSort('firstSeen')}
                  >
                    First Seen
                  </TableSortLabel>
                </TableCell>
                <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                  <TableSortLabel
                    active={sortBy === 'lastSeen'}
                    direction={sortBy === 'lastSeen' ? sortOrder : 'desc'}
                    onClick={() => handleSort('lastSeen')}
                  >
                    Last Seen
                  </TableSortLabel>
                </TableCell>
                <TableCell>Unique IPs</TableCell>
                <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>Tags</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {groups.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} align="center">
                    <Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                      No alerts found. Alerts will appear here when detection rules match network traffic.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                groups.map((group, index) => {
                  const groupKey = `${group.ruleName}-${group.severity}`;
                  const isExpanded = expandedGroup === groupKey;
                  
                  return (
                    <>
                      <TableRow key={groupKey} hover sx={{ cursor: 'pointer' }}>
                        <TableCell>
                          <IconButton
                            size="small"
                            onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}
                          >
                            {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                          </IconButton>
                        </TableCell>
                        <TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {getSeverityIcon(group.severity)}
                            <Chip
                              label={group.severity.toUpperCase()}
                              size="small"
                              color={getSeverityColor(group.severity) as any}
                            />
                          </Box>
                        </TableCell>
                        <TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}>
                          <Tooltip title={group.description}>
                            <Typography variant="body2" fontWeight="medium">
                              {group.ruleName}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}>
                          <Chip label={group.recordType} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}>
                          <Chip 
                            label={group.count.toLocaleString()} 
                            size="small" 
                            color="primary"
                            sx={{ fontWeight: 'bold' }}
                          />
                        </TableCell>
                        <TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}>
                          <Typography variant="body2">
                            {formatTimestamp(group.firstSeen)}
                          </Typography>
                        </TableCell>
                        <TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)} sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                          <Typography variant="body2">
                            {formatTimestamp(group.lastSeen)}
                          </Typography>
                        </TableCell>
                        <TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)}>
                          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                            <Typography variant="caption" color="text.secondary">
                              Src: {group.uniqueSrcIPs.length} | Dst: {group.uniqueDstIPs.length}
                            </Typography>
                            {group.uniqueSrcPorts.length > 0 && (
                              <Typography variant="caption" color="text.secondary">
                                Ports: {group.uniqueSrcPorts.length + group.uniqueDstPorts.length}
                              </Typography>
                            )}
                          </Box>
                        </TableCell>
                        <TableCell onClick={() => setExpandedGroup(isExpanded ? null : groupKey)} sx={{ display: { xs: 'none', lg: 'table-cell' } }}>
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                            {group.tags.slice(0, 2).map((tag) => (
                              <Chip key={tag} label={tag} size="small" />
                            ))}
                            {group.tags.length > 2 && (
                              <Chip label={`+${group.tags.length - 2}`} size="small" variant="outlined" />
                            )}
                          </Box>
                        </TableCell>
                      </TableRow>
                      
                      {/* Expanded Details */}
                      {isExpanded && (
                        <TableRow>
                          <TableCell colSpan={9} sx={{ backgroundColor: 'action.hover', py: 2 }}>
                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, px: 2 }}>
                              <Typography variant="subtitle2" fontWeight="bold">
                                Alert Details
                              </Typography>
                              
                              <Grid container spacing={2}>
                                <Grid item xs={12} md={6}>
                                  <Typography variant="caption" color="text.secondary" display="block">
                                    Description
                                  </Typography>
                                  <Typography variant="body2">{group.description}</Typography>
                                </Grid>
                                
                                {group.mitre && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      MITRE ATT&CK
                                    </Typography>
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                                      {group.mitre.split(',').map((mitre) => (
                                        <Chip key={mitre.trim()} label={mitre.trim()} size="small" color="warning" />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {group.threshold > 0 && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      Threshold Configuration
                                    </Typography>
                                    <Paper
                                      sx={{
                                        p: 1,
                                        mt: 0.5,
                                        backgroundColor: 'background.paper',
                                        border: 1,
                                        borderColor: 'primary.main',
                                      }}
                                    >
                                      <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                                        <strong>{group.threshold}</strong> matches within <strong>{group.thresholdWindow}s</strong>
                                      </Typography>
                                    </Paper>
                                  </Grid>
                                )}
                                
                                {group.uniqueSrcIPs.length > 0 && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      Unique Source IPs ({group.uniqueSrcIPs.length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                                      {group.uniqueSrcIPs.slice(0, 10).map((ip) => (
                                        <Chip 
                                          key={ip} 
                                          label={ip} 
                                          size="small" 
                                          variant="outlined"
                                          sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                                        />
                                      ))}
                                      {group.uniqueSrcIPs.length > 10 && (
                                        <Chip 
                                          label={`+${group.uniqueSrcIPs.length - 10} more`} 
                                          size="small" 
                                          variant="outlined" 
                                        />
                                      )}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {group.uniqueDstIPs.length > 0 && (
                                  <Grid item xs={12} md={6}>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      Unique Destination IPs ({group.uniqueDstIPs.length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                                      {group.uniqueDstIPs.slice(0, 10).map((ip) => (
                                        <Chip 
                                          key={ip} 
                                          label={ip} 
                                          size="small" 
                                          variant="outlined"
                                          sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                                        />
                                      ))}
                                      {group.uniqueDstIPs.length > 10 && (
                                        <Chip 
                                          label={`+${group.uniqueDstIPs.length - 10} more`} 
                                          size="small" 
                                          variant="outlined" 
                                        />
                                      )}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {(group.uniqueSrcPorts.length > 0 || group.uniqueDstPorts.length > 0) && (
                                  <Grid item xs={12}>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      Ports (Src: {group.uniqueSrcPorts.length}, Dst: {group.uniqueDstPorts.length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                                      {[...group.uniqueSrcPorts, ...group.uniqueDstPorts].slice(0, 20).map((port, idx) => (
                                        <Chip 
                                          key={`${port}-${idx}`} 
                                          label={port} 
                                          size="small" 
                                          variant="outlined"
                                          sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                                        />
                                      ))}
                                    </Box>
                                  </Grid>
                                )}
                                
                                {group.ruleExpression && (
                                  <Grid item xs={12}>
                                    <Typography variant="caption" color="text.secondary" display="block">
                                      Rule Expression
                                    </Typography>
                                    <Paper
                                      sx={{
                                        p: 1.5,
                                        backgroundColor: 'grey.900',
                                        overflow: 'auto',
                                        mt: 0.5,
                                      }}
                                    >
                                      <Typography
                                        variant="body2"
                                        sx={{
                                          fontFamily: 'monospace',
                                          fontSize: '0.85rem',
                                          whiteSpace: 'pre-wrap',
                                          wordBreak: 'break-word',
                                        }}
                                      >
                                        {group.ruleExpression}
                                      </Typography>
                                    </Paper>
                                  </Grid>
                                )}
                              </Grid>
                              
                              {/* Sample Alerts */}
                              {group.sampleAlerts.length > 0 && (
                                <Box sx={{ mt: 2 }}>
                                  <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                                    Sample Alerts ({group.sampleAlerts.length} of {group.count})
                                  </Typography>
                                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                    {group.sampleAlerts.map((alert, idx) => (
                                      <Button
                                        key={idx}
                                        size="small"
                                        variant="outlined"
                                        startIcon={<VisibilityIcon />}
                                        onClick={() => handleViewDetails(alert)}
                                      >
                                        View Sample {idx + 1}
                                      </Button>
                                    ))}
                                  </Box>
                                </Box>
                              )}
                            </Box>
                          </TableCell>
                        </TableRow>
                      )}
                    </>
                  );
                })
              )}
            </TableBody>
          </Table>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={groupCount}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            labelDisplayedRows={({ from, to, count }) => 
              `${from}-${to} of ${count} groups (${totalCount.toLocaleString()} total alerts)`
            }
          />
        </TableContainer>

        {/* Alert Details Dialog */}
        <Dialog
          open={detailsDialogOpen}
          onClose={() => setDetailsDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <style>{`
            .json-key { color: #9cdcfe; }
            .json-string { color: #ce9178; }
            .json-number { color: #b5cea8; }
            .json-boolean { color: #569cd6; }
            .json-null { color: #569cd6; }
          `}</style>
          <DialogTitle>Alert Details</DialogTitle>
          <DialogContent>
            {selectedAlert && (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Timestamp
                  </Typography>
                  <Typography variant="body1">{formatTimestamp(selectedAlert.timestamp)}</Typography>
                </Box>

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Rule Name
                  </Typography>
                  <Typography variant="body1" fontWeight="medium">
                    {selectedAlert.ruleName}
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Description
                  </Typography>
                  <Typography variant="body1">{selectedAlert.description}</Typography>
                </Box>

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Severity
                  </Typography>
                  <Chip
                    label={selectedAlert.severity.toUpperCase()}
                    color={getSeverityColor(selectedAlert.severity) as any}
                  />
                </Box>

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Record Type
                  </Typography>
                  <Typography variant="body1">{selectedAlert.recordType}</Typography>
                </Box>

                {selectedAlert.ruleExpression && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary">
                      Rule Expression
                    </Typography>
                    <Paper
                      sx={{
                        p: 1.5,
                        backgroundColor: 'grey.900',
                        overflow: 'auto',
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          fontSize: '0.9rem',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                        }}
                      >
                        {selectedAlert.ruleExpression}
                      </Typography>
                    </Paper>
                  </Box>
                )}

                {selectedAlert.threshold > 0 && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary">
                      Threshold Configuration
                    </Typography>
                    <Paper
                      sx={{
                        p: 1.5,
                        backgroundColor: 'action.hover',
                        border: 1,
                        borderColor: 'primary.main',
                      }}
                    >
                      <Typography variant="body2" sx={{ mb: 0.5 }}>
                        <strong>Threshold:</strong> {selectedAlert.threshold} matches
                      </Typography>
                      <Typography variant="body2">
                        <strong>Time Window:</strong> {selectedAlert.thresholdWindow} seconds
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                        This alert was triggered after {selectedAlert.threshold} matching events occurred within a {selectedAlert.thresholdWindow}-second window.
                      </Typography>
                    </Paper>
                  </Box>
                )}

                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Source IP
                    </Typography>
                    <Typography
                      variant="body1"
                      sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
                    >
                      {selectedAlert.srcIP || '-'}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="subtitle2" color="text.secondary">
                      Destination IP
                    </Typography>
                    <Typography
                      variant="body1"
                      sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
                    >
                      {selectedAlert.dstIP || '-'}
                    </Typography>
                  </Grid>
                </Grid>

                {selectedAlert.mitre && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary">
                      MITRE ATT&CK
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                      {selectedAlert.mitre.split(',').map((mitre) => (
                        <Chip key={mitre.trim()} label={mitre.trim()} size="small" color="warning" />
                      ))}
                    </Box>
                  </Box>
                )}

                {selectedAlert.tags.length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary">
                      Tags
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                      {selectedAlert.tags.map((tag) => (
                        <Chip key={tag} label={tag} size="small" />
                      ))}
                    </Box>
                  </Box>
                )}

                {selectedAlert.matchedRecord && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                      Matched Record
                    </Typography>
                    <Paper
                      sx={{
                        p: 2,
                        backgroundColor: '#1e1e1e',
                        overflow: 'auto',
                        maxHeight: 300,
                      }}
                    >
                      <pre
                        style={{
                          margin: 0,
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                        }}
                        dangerouslySetInnerHTML={{
                          __html: syntaxHighlight(JSON.stringify(convertTimestamps(JSON.parse(selectedAlert.matchedRecord)), null, 2))
                        }}
                      />
                    </Paper>
                  </Box>
                )}
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDetailsDialogOpen(false)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Snackbar for notifications */}
        <Snackbar
          open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
        >
          <MuiAlert
            onClose={() => setSnackbar({ ...snackbar, open: false })}
            severity={snackbar.severity}
            sx={{ width: '100%' }}
          >
            {snackbar.message}
          </MuiAlert>
        </Snackbar>
      </Box>
    </Layout>
  );
}

