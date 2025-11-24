import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Autocomplete,
  Box,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  IconButton,
  InputAdornment,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  SelectChangeEvent,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  ChevronRight as ChevronRightIcon,
  ExpandMore as ExpandMoreIcon,
  Folder as FolderIcon,
  InsertDriveFile as FileIcon,
  Download as DownloadIcon,
  BarChart as BarChartIcon,
  Search as SearchIcon,
  Clear as ClearIcon,
  FilterAlt as FilterAltIcon,
  HelpOutline as HelpOutlineIcon,
  ContentCopy as ContentCopyIcon,
} from '@mui/icons-material';
import Layout from '@/components/Layout';
import FileSelectorHeader from '@/components/FileSelectorHeader';
import { api, formatBytes, getBackendUrl } from '@/lib/api';
import useSWR, { mutate as globalMutate } from 'swr';
import { useRouter } from 'next/router';
import FilterExpressionHighlight, { FilterExpressionBlock } from '@/components/FilterExpressionHighlight';
import { highlightFilterExpression } from '@/lib/filterSyntaxHighlight';

interface LayerGroup {
  layerName: string;
  files: any[];
}

// Helper function to generate consistent colors for field names
function getFieldColor(fieldName: string): string {
  // Simple hash function to generate consistent colors
  let hash = 0;
  for (let i = 0; i < fieldName.length; i++) {
    hash = fieldName.charCodeAt(i) + ((hash << 5) - hash);
  }
  
  // Generate HSL color with good saturation and darker lightness for better contrast
  const hue = Math.abs(hash % 360);
  const saturation = 65 + (Math.abs(hash) % 20); // 65-85%
  const lightness = 35 + (Math.abs(hash >> 8) % 15); // 35-50% - darker for better contrast
  
  return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
}

// Component to render record as UI elements
interface RecordUIProps {
  data: any;
  level?: number;
}

function RecordUI({ data, level = 0 }: RecordUIProps) {
  if (data === null || data === undefined) {
    return <Typography variant="body2" color="text.secondary">—</Typography>;
  }
  
  if (typeof data === 'boolean') {
    return (
      <Chip 
        label={String(data)} 
        size="small" 
        color={data ? "success" : "default"}
        sx={{ fontFamily: 'monospace', height: 22 }}
      />
    );
  }
  
  if (typeof data === 'number') {
    return (
      <Typography 
        component="span" 
        sx={{ 
          fontFamily: 'monospace', 
          color: 'primary.main',
          fontWeight: 500,
          fontSize: '0.9rem'
        }}
      >
        {data.toLocaleString()}
      </Typography>
    );
  }
  
  if (typeof data === 'string') {
    // Check if it's an IP address
    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(data);
    // Check if it's a timestamp (ISO format)
    const isTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(data);
    
    if (isIP) {
      return (
        <Chip 
          label={data} 
          size="small"
          sx={{ 
            fontFamily: 'monospace',
            bgcolor: 'info.light',
            color: 'info.contrastText',
            height: 22,
            fontSize: '0.8rem'
          }}
        />
      );
    }
    
    if (isTimestamp) {
      return (
        <Typography 
          component="span"
          sx={{ 
            fontFamily: 'monospace',
            color: 'text.secondary',
            fontSize: '0.85rem'
          }}
        >
          {data}
        </Typography>
      );
    }
    
    return (
      <Typography 
        component="span"
        sx={{ 
          fontFamily: 'monospace',
          fontSize: '0.9rem'
        }}
      >
        {data}
      </Typography>
    );
  }
  
  if (Array.isArray(data)) {
    if (data.length === 0) {
      return <Typography variant="body2" color="text.secondary">[]</Typography>;
    }
    
    // For simple arrays (primitives), show inline
    if (data.every(item => typeof item !== 'object' || item === null)) {
      return (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {data.map((item, idx) => (
            <RecordUI key={`${String(item)}-${idx}`} data={item} level={level + 1} />
          ))}
        </Box>
      );
    }
    
    // For complex arrays, show as list
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mt: 0.5 }}>
        {data.map((item, idx) => (
          <Paper key={`item-${idx}-${JSON.stringify(item).substring(0, 50)}`} sx={{ p: 1, bgcolor: 'background.default' }}>
            <RecordUI data={item} level={level + 1} />
          </Paper>
        ))}
      </Box>
    );
  }
  
  if (typeof data === 'object') {
    const entries = Object.entries(data);
    if (entries.length === 0) {
      return <Typography variant="body2" color="text.secondary">{'{}'}</Typography>;
    }
    
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: level === 0 ? 0.75 : 0.5 }}>
        {entries.map(([key, value]) => {
          const fieldColor = getFieldColor(key);
          
          return (
            <Box 
              key={key}
              sx={{ 
                display: 'flex',
                flexDirection: 'row',
                alignItems: 'flex-start',
                gap: 1.5,
                borderLeft: level > 0 ? 2 : 0,
                borderColor: 'divider',
                pl: level > 0 ? 1.5 : 0
              }}
            >
              <Box 
                sx={{ 
                  minWidth: level === 0 ? 180 : 140,
                  maxWidth: level === 0 ? 180 : 140,
                  pt: 0.2
                }}
              >
                <Chip
                  label={key}
                  size="small"
                  sx={{
                    bgcolor: fieldColor,
                    color: 'white',
                    fontWeight: 600,
                    fontFamily: 'monospace',
                    fontSize: '0.8rem',
                    height: 22,
                    maxWidth: '100%',
                    '& .MuiChip-label': {
                      px: 1.2
                    }
                  }}
                />
              </Box>
              <Box sx={{ flex: 1, minWidth: 0, pt: 0.2 }}>
                <RecordUI data={value} level={level + 1} />
              </Box>
            </Box>
          );
        })}
      </Box>
    );
  }
  
  return (
    <Typography component="span" sx={{ fontFamily: 'monospace' }}>
      {String(data)}
    </Typography>
  );
}

// Helper function to convert unix timestamps to human-readable format
function convertTimestamps(obj: any): any {
  if (obj === null || obj === undefined) return obj;
  
  if (typeof obj === 'number' && obj > 1000000000) {
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
  
  if (typeof obj === 'string' && obj.match(/^\d{10,19}$/)) {
    // String that looks like a unix timestamp
    const num = parseInt(obj, 10);
    if (num > 1000000000) {
      return convertTimestamps(num); // Recursively convert as number
    }
  }
  
  if (typeof obj !== 'object') return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(item => convertTimestamps(item));
  }
  
  const result: any = {};
  for (const [key, value] of Object.entries(obj)) {
    // Check if this is a timestamp field by name
    if ((key.toLowerCase().includes('timestamp') || 
         key.toLowerCase().includes('time') ||
         key === 'Timestamp' ||
         key === 'Time') && 
        typeof value === 'number' && 
        value > 1000000000) {
      result[key] = convertTimestamps(value);
    } else {
      result[key] = convertTimestamps(value);
    }
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

export default function AuditRecords() {
  const router = useRouter();
  const { data: files, error, mutate } = useSWR('auditFiles', () => api.getAuditFiles());
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: sessions } = useSWR(
    status?.isServiceMode ? 'try-sessions' : null, 
    () => api.getAllSessions()
  );
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [switchingSession, setSwitchingSession] = useState(false);
  const filterInputRef = React.useRef<HTMLInputElement>(null);
  const [filterInputFocused, setFilterInputFocused] = useState(false);
  // Expand all sections by default
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set([
    'Link Layer', 
    'Network Layer', 
    'Transport Layer', 
    'Application Layer',
    'Stream Decoders',
    'Abstract Decoders',
    'Other',
    'Unknown Layer'
  ]));
  const [switchingFile, setSwitchingFile] = useState(false);
  const [autoSelectAttempted, setAutoSelectAttempted] = useState(false);

  // Auto-select first completed file if no active file is set
  useEffect(() => {
    const autoSelectFirstFile = async () => {
      // Only attempt once
      if (autoSelectAttempted) return;
      
      // Wait for data to be loaded
      if (!inputFiles || !status) return;
      
      const completed = inputFiles.filter((f: any) => f.isCompleted);
      if (completed.length === 0) return;
      
      // Check if we need to auto-select
      const hasActiveFile = status.activeInputFile && completed.some((f: any) => 
        f.path === status.activeInputFile || 
        f.name === status.activeInputFile || 
        f.path.endsWith('/' + status.activeInputFile)
      );
      
      if (!hasActiveFile) {
        console.log('[Audit] Auto-selecting first completed file:', completed[0].path);
        setAutoSelectAttempted(true);
        try {
          await api.setActiveDirectory(completed[0].path);
          await mutateStatus();
          await mutate();
        } catch (err) {
          console.error('[Audit] Failed to auto-select file:', err);
        }
      }
    };
    
    autoSelectFirstFile();
  }, [inputFiles, status, autoSelectAttempted, mutateStatus, mutate]);
  
  // Listen for directory changes and refresh audit files
  useEffect(() => {
    const handleDirectoryChange = () => {
      console.log('Directory changed, refreshing audit files...');
      mutate(); // Refresh audit files
    };
    
    window.addEventListener('directory-changed', handleDirectoryChange);
    return () => window.removeEventListener('directory-changed', handleDirectoryChange);
  }, [mutate]);
  
  const [records, setRecords] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [total, setTotal] = useState(0);
  const [scanned, setScanned] = useState(0);
  const [executionTime, setExecutionTime] = useState(0);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [filterExpression, setFilterExpression] = useState('');
  const [activeFilter, setActiveFilter] = useState('');
  const [showFilterHelp, setShowFilterHelp] = useState(false);
  const [fieldSuggestions, setFieldSuggestions] = useState<string[]>([]);
  const [fieldValues, setFieldValues] = useState<Record<string, string[]>>({});
  const [fieldTypes, setFieldTypes] = useState<Record<string, string>>({});
  const [loadingFields, setLoadingFields] = useState(false);
  const [valuesSampleInfo, setValuesSampleInfo] = useState<{ sampleSize: number; maxPerField: number; recordsScanned: number } | null>(null);
  const [autocompleteOpen, setAutocompleteOpen] = useState(false);
  const [highlightedOption, setHighlightedOption] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'ui' | 'json'>('json');

  // Load field suggestions and values when record type is selected
  useEffect(() => {
    if (!selectedType) {
      setFieldSuggestions([]);
      setFieldValues({});
      setFieldTypes({});
      setValuesSampleInfo(null);
      return;
    }

    const loadFieldsAndValues = async () => {
      setLoadingFields(true);
      try {
        // Load field names and helper functions
        const fieldsData = await api.getAuditRecordFields(selectedType);
        const fieldNames = fieldsData.fields.map(f => f.name);
        const helpers = fieldsData.helpers;
        
        // Store field types for smart value quoting
        const types: Record<string, string> = {};
        fieldsData.fields.forEach(f => {
          types[f.name] = f.type;
        });
        setFieldTypes(types);
        
        // Combine field names and helper functions
        setFieldSuggestions([...fieldNames, ...helpers]);

        // Load sample field values
        try {
          const valuesData = await api.getAuditRecordFieldValues(selectedType);
          setFieldValues(valuesData.fieldValues);
          setValuesSampleInfo({
            sampleSize: valuesData.sampleSize,
            maxPerField: valuesData.maxPerField,
            recordsScanned: valuesData.recordsScanned,
          });
        } catch (err) {
          console.warn('Failed to load field values:', err);
          setFieldValues({});
          setValuesSampleInfo(null);
        }
      } catch (err) {
        console.error('Failed to load field suggestions:', err);
        setFieldSuggestions([]);
        setFieldValues({});
        setFieldTypes({});
      } finally {
        setLoadingFields(false);
      }
    };

    loadFieldsAndValues();
  }, [selectedType]);

  // Prevent browser TAB navigation when dialog is open
  useEffect(() => {
    if (!selectedType) return;

    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Tab') {
        e.preventDefault();
        return false;
      }
    };

    document.addEventListener('keydown', handleGlobalKeyDown);
    return () => {
      document.removeEventListener('keydown', handleGlobalKeyDown);
    };
  }, [selectedType]);

  // Auto-focus filter input when dialog opens
  useEffect(() => {
    if (selectedType && filterInputRef.current) {
      // Delay to ensure dialog animation completes
      const timer = setTimeout(() => {
        filterInputRef.current?.focus();
      }, 200);
      return () => clearTimeout(timer);
    }
  }, [selectedType]);

  const handleViewRecords = (type: string, filter?: string) => {
    setSelectedType(type);
    setRecords([]);
    setProgress(0);
    setTotal(0);
    setScanned(0);
    setExecutionTime(0);
    setLoading(true);
    setStreamError(null);
    setActiveFilter(filter || '');

    const eventSource = api.streamAuditRecords(
      type,
      0,
      100, // Return up to 100 records (backend scans all records to get accurate count)
      (record) => {
        setRecords((prev) => [...prev, record]);
      },
      (count, scanned) => {
        setProgress(count);
        if (scanned !== undefined) setScanned(scanned);
      },
      (total, scanned, executionTimeMs) => {
        setTotal(total);
        if (scanned !== undefined) setScanned(scanned);
        if (executionTimeMs !== undefined) setExecutionTime(executionTimeMs);
        setLoading(false);
      },
      (error) => {
        console.error('Stream error:', error);
        setStreamError(error);
        setLoading(false);
      },
      filter
    );

    return () => eventSource.close();
  };

  const handleApplyFilter = () => {
    if (selectedType) {
      handleViewRecords(selectedType, filterExpression);
    }
  };

  const handleClearFilter = () => {
    setFilterExpression('');
    if (selectedType) {
      handleViewRecords(selectedType, '');
    }
  };

  const handleInsertExample = (example: string) => {
    setFilterExpression(example);
  };

  // Check if a field type is numeric
  const isNumericType = (fieldType: string): boolean => {
    return /^(int|uint|float|int8|int16|int32|int64|uint8|uint16|uint32|uint64|float32|float64|byte)$/i.test(fieldType);
  };

  // Operators for autocompletion
  const operators = [
    '==',  // Equal
    '!=',  // Not equal
    '<',   // Less than
    '>',   // Greater than
    '<=',  // Less than or equal
    '>=',  // Greater than or equal
    '&&',  // Logical AND
    '||',  // Logical OR
    '!',   // Logical NOT
  ];

  // Get smart suggestions based on context
  const getContextualSuggestions = (inputValue: string): string[] => {
    if (!inputValue) return fieldSuggestions;

    // Find cursor position (use end of string for simplicity)
    const cursorPos = inputValue.length;
    
    // Find the current token being typed
    const beforeCursor = inputValue.substring(0, cursorPos);
    
    // Check if we just completed a value (e.g., "SrcPort == 1883 " or "DstIP == '192.168.1.1' ")
    // This suggests logical operators (&&, ||) for chaining conditions
    // NOTE: Requires a space AFTER the value to consider it "completed"
    // Changed: Added mandatory space after the value: \s+ instead of \s*
    const completedValueMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*(==|!=|<|>|<=|>=)\s+(?:\d+\s+|['"][^'"]*['"]\s+)$/);
    
    if (completedValueMatch) {
      // We've completed a comparison - suggest logical operators to chain conditions
      return ['&&', '||'];
    }
    
    // Check if we're after a comparison operator (==, !=, <, >, etc.)
    // This should match partial values being typed, including digits
    const comparisonMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*(==|!=|<|>|<=|>=)\s*['"]?([\w.]*)$/);
    
    if (comparisonMatch) {
      // We're typing a value - suggest field values
      const fieldName = comparisonMatch[1];
      const partialValue = comparisonMatch[3];
      
      if (fieldValues[fieldName]) {
        const values = fieldValues[fieldName];
        const fieldType = fieldTypes[fieldName] || '';
        const isNumeric = isNumericType(fieldType);
        
        if (partialValue) {
          // Case-sensitive matching for values
          return values
            .filter(v => v.startsWith(partialValue))
            .map(v => isNumeric ? v : `"${v}"`); // Only wrap strings in quotes
        }
        return values.map(v => isNumeric ? v : `"${v}"`);
      }
    }

    // Check if we're after a logical operator (&& or ||) - suggest field names
    const afterLogicalOpMatch = beforeCursor.match(/(&&|\|\|)\s*$/);
    if (afterLogicalOpMatch) {
      return fieldSuggestions;
    }

    // Check if we might be typing an operator after a field name
    // Match field name followed by optional whitespace and partial operator
    const operatorMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*([=!<>&|]*)$/);
    
    if (operatorMatch && operatorMatch[2]) {
      // We're typing an operator - suggest matching operators
      const partialOp = operatorMatch[2];
      const matchingOps = operators.filter(op => 
        op.startsWith(partialOp) && op !== partialOp
      );
      
      if (matchingOps.length > 0) {
        return matchingOps;
      }
    }

    // Check if we're typing a field name or helper function
    const words = beforeCursor.split(/[\s()&|,]+/);
    const currentWord = words[words.length - 1] || '';
    
    if (currentWord.length >= 1) {
      // Case-sensitive matching: field name must start with exact case
      return fieldSuggestions.filter(option =>
        option.startsWith(currentWord)
      );
    }

    // If we have a complete field name followed by whitespace (no operator yet),
    // don't show suggestions - wait for user to start typing an operator
    // This matches: "SrcPort " or "SrcPort && DstPort "
    const fieldNameWithSpaceMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s+$/);
    if (fieldNameWithSpaceMatch && !beforeCursor.match(/(==|!=|<|>|<=|>=)\s*$/)) {
      // We have a field name followed by space, but no operator
      // Don't show field suggestions - wait for operator input
      return [];
    }

    return fieldSuggestions;
  };

  // Helper function to intelligently insert a suggestion into the current expression
  const insertSuggestion = (currentExpression: string, suggestion: string): string => {
    const beforeCursor = currentExpression;
    const words = beforeCursor.split(/[\s()&|,]+/);
    const currentWord = words[words.length - 1] || '';
    
    // Check if we're completing a value (after comparison operator)
    // Updated regex to handle partial digits and other characters
    const comparisonMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*(==|!=|<|>|<=|>=)\s*['"]?([\w.]*)$/);
    
    if (comparisonMatch) {
      // Completing a value - replace only the partial value part
      const partialValue = comparisonMatch[3];
      const beforeValue = beforeCursor.substring(0, beforeCursor.length - partialValue.length);
      // Add a trailing space after the value for better flow into next operator
      return beforeValue + suggestion + ' ';
    }
    
    // Check if we're completing an operator
    const operatorMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*([=!<>&|]*)$/);
    
    if (operatorMatch && operatorMatch[2] && operators.includes(suggestion)) {
      // Completing an operator
      const partialOp = operatorMatch[2];
      const beforeOp = beforeCursor.substring(0, beforeCursor.length - partialOp.length);
      // Add space before and after operator for readability
      return beforeOp + ' ' + suggestion + ' ';
    }
    
    // Completing a field name
    if (currentWord) {
      // Remove quotes if present in suggestion for comparison
      const cleanSuggestion = suggestion.replace(/^["']|["']$/g, '');
      
      // Case-sensitive matching: must start with exact case
      if (cleanSuggestion.startsWith(currentWord)) {
        // Append only the remaining part + space to allow operator suggestions
        const remainder = cleanSuggestion.substring(currentWord.length);
        return currentExpression + remainder + ' ';
      } else {
        // If it doesn't start with current word, replace the whole word + space
        const beforeWord = beforeCursor.substring(0, beforeCursor.length - currentWord.length);
        return beforeWord + suggestion + ' ';
      }
    }
    
    // No current word, just append
    return currentExpression + suggestion;
  };

  const handleClose = () => {
    setSelectedType(null);
    setRecords([]);
    setStreamError(null);
  };

  const handleSessionChange = async (event: SelectChangeEvent<string>) => {
    const sessionId = event.target.value;
    setSwitchingSession(true);
    try {
      await api.selectSession(sessionId);
      // Refresh data
      await mutate();
      await mutateStatus();
    } catch (error) {
      console.error('Failed to switch session:', error);
      alert('Failed to switch to selected session');
    } finally {
      setSwitchingSession(false);
    }
  };

  const toggleLayer = (layerName: string) => {
    setExpandedLayers(prev => {
      const newSet = new Set(prev);
      if (newSet.has(layerName)) {
        newSet.delete(layerName);
      } else {
        newSet.add(layerName);
      }
      return newSet;
    });
  };

  // Memoize event handler to prevent recreation on every render
  const handleFileChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      
      // Refresh local data
      await mutateStatus();
      await mutate();
      
      // Globally invalidate status cache for all pages
      await globalMutate('status');
      
      // Trigger global event for other components
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert('Failed to switch to this file');
    } finally {
      setSwitchingFile(false);
    }
  }, [mutateStatus, mutate]);

  const handleDownloadAll = () => {
    console.log('[Audit] Download All clicked');
    console.log('[Audit] Status:', status);
    console.log('[Audit] Layer groups count:', layerGroups.length);
    console.log('[Audit] Total files:', layerGroups.reduce((sum, group) => sum + group.files.length, 0));
    
    // In service mode, use sessionId. In local mode, use activeInputFile
    const identifier = status?.sessionId || status?.activeInputFile;
    
    if (!identifier) {
      console.error('[Audit] No identifier available for download (sessionId or activeInputFile)');
      console.error('[Audit] Status object:', JSON.stringify(status, null, 2));
      alert('Unable to download: no session or file information available');
      return;
    }

    console.log('[Audit] Using identifier:', identifier);
    
    // Trigger download by opening the download URL
    const downloadUrl = `${getBackendUrl()}/api/download/${encodeURIComponent(identifier)}`;
    console.log('[Audit] Opening download URL:', downloadUrl);
    window.open(downloadUrl, '_blank');
  };

  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their audit records and extracted protocol data."
    />
  );

  // Group files by layer, filtering out empty files
  const layerGroups: LayerGroup[] = React.useMemo(() => {
    if (!files) return [];
    
    // Filter out files with no records or zero size
    const nonEmptyFiles = files.filter((file: any) => {
      const hasRecords = file.recordCount && file.recordCount > 0;
      const hasSize = file.size > 0;
      return hasRecords && hasSize;
    });
    
    const groups = new Map<string, any[]>();
    nonEmptyFiles.forEach((file: any) => {
      const layer = file.layer || 'Other';
      if (!groups.has(layer)) {
        groups.set(layer, []);
      }
      groups.get(layer)!.push(file);
    });

    // Define layer order matching netcap's hierarchy
    const layerOrder = [
      'Link Layer',
      'Network Layer',
      'Transport Layer',
      'Application Layer',
      'Stream Decoders',
      'Abstract Decoders',
      'Other'
    ];

    // Only return layers that have files with data
    return layerOrder
      .filter(layerName => groups.has(layerName) && groups.get(layerName)!.length > 0)
      .map(layerName => ({
        layerName,
        files: groups.get(layerName)!
      }));
  }, [files]);

  if (!files && !error) {
    return (
      <Layout title="Records" headerAction={fileSelector}>
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Records" headerAction={fileSelector}>
        <Box>
          <Typography color="error">Error loading audit records</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Audit Records" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        {/* Session Selector for Try Service */}
        {status?.isServiceMode && sessions && sessions.length > 1 && (
          <Box mb={3}>
            <FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 300 } }}>
              <Select
                value={status?.sessionId || ''}
                onChange={handleSessionChange}
                disabled={switchingSession}
                displayEmpty
                renderValue={(value) => {
                  const session = sessions.find(s => s.sessionId === value);
                  return session ? `Session: ${session.inputFilename}` : 'Select Session';
                }}
              >
                {sessions
                  .filter(s => s.resultsReady)
                  .map((session) => (
                    <MenuItem key={session.sessionId} value={session.sessionId}>
                      <Box>
                        <Typography variant="body2">{session.inputFilename}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(session.uploadTimestamp).toLocaleString()}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
              </Select>
            </FormControl>
          </Box>
        )}

        <Box mb={3}>
          <Box 
            display="flex" 
            flexDirection={{ xs: 'column', sm: 'row' }}
            justifyContent="space-between" 
            alignItems={{ xs: 'stretch', sm: 'flex-start' }} 
            gap={2}
          >
            <Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
              {layerGroups.reduce((sum, group) => sum + group.files.length, 0)} protocol type(s) found • Hierarchical by encapsulation layer
            </Typography>
            
            {/* Download All Button */}
            <Button
              data-learn="Download All Records: Download all record files as a compressed archive for offline analysis."
              variant="contained"
              color="success"
              startIcon={<DownloadIcon />}
              onClick={handleDownloadAll}
              disabled={
                // Require either sessionId (service mode) or activeInputFile (local mode)
                (!status?.sessionId && !status?.activeInputFile) || 
                // Also require at least one audit file available
                layerGroups.reduce((sum, group) => sum + group.files.length, 0) === 0
              }
              size="small"
              sx={{ minWidth: { xs: 'auto', sm: 180 } }}
              fullWidth={false}
            >
              Download All
            </Button>
          </Box>
        </Box>

        {layerGroups.length > 0 ? (
          <Paper sx={{ p: 2 }}>
            {layerGroups.map((group, groupIdx) => (
              <Box key={group.layerName} sx={{ mb: groupIdx < layerGroups.length - 1 ? 2 : 0 }}>
                {/* Layer Header */}
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    cursor: 'pointer',
                    p: 1,
                    borderRadius: 1,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                  onClick={() => toggleLayer(group.layerName)}
                >
                  <IconButton size="small" sx={{ mr: 1 }}>
                    {expandedLayers.has(group.layerName) ? <ExpandMoreIcon /> : <ChevronRightIcon />}
                  </IconButton>
                  <Box
                    sx={{
                      width: 3,
                      height: 24,
                      bgcolor: getLayerColor(group.layerName),
                      mr: 2,
                      borderRadius: 1,
                    }}
                  />
                  <Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>
                    {group.layerName}
                  </Typography>
                  <Chip
                    label={`${group.files.length} type${group.files.length !== 1 ? 's' : ''}`}
                    size="small"
                    variant="outlined"
                  />
                </Box>

                {/* Layer Content */}
                <Collapse in={expandedLayers.has(group.layerName)}>
                  <Box sx={{ ml: 6, mt: 1 }}>
                    {group.files.map((file, fileIdx) => (
                      <Box
                        key={file.path}
                        onClick={() => handleViewRecords(file.type)}
                        sx={{
                          display: 'flex',
                          flexDirection: { xs: 'column', md: 'row' },
                          alignItems: { xs: 'stretch', md: 'center' },
                          p: 1.5,
                          mb: fileIdx < group.files.length - 1 ? 1 : 0,
                          borderLeft: 2,
                          borderColor: 'divider',
                          bgcolor: 'background.default',
                          borderRadius: 1,
                          cursor: 'pointer',
                          '&:hover': { bgcolor: 'action.hover' },
                          gap: { xs: 1.5, md: 0 },
                        }}
                      >
                        <Box sx={{ display: 'flex', alignItems: 'center', flex: 1, minWidth: 0 }}>
                          {/* Tree connector visualization */}
                          <Box
                            sx={{
                              width: 20,
                              height: 2,
                              bgcolor: 'divider',
                              mr: 1,
                              display: { xs: 'none', md: 'block' },
                            }}
                          />
                          <FileIcon sx={{ mr: 2, color: 'text.secondary', fontSize: 20, flexShrink: 0 }} />
                          
                          <Box sx={{ flex: 1, minWidth: 0 }}>
                            <Typography
                              sx={{
                                fontFamily: 'monospace',
                                fontWeight: 600,
                                fontSize: '0.95rem',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                            >
                              {file.type}
                            </Typography>
                            <Typography 
                              variant="caption" 
                              color="text.secondary" 
                              sx={{ 
                                fontFamily: 'monospace',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                display: 'block'
                              }}
                            >
                              {file.name}
                            </Typography>
                          </Box>
                        </Box>

                        <Box sx={{ 
                          display: 'flex', 
                          flexDirection: { xs: 'row', md: 'row' },
                          alignItems: 'center', 
                          gap: { xs: 1, md: 2 }, 
                          justifyContent: { xs: 'space-between', md: 'flex-end' },
                          mr: { xs: 0, md: 2 }
                        }}>
                          <Box sx={{ textAlign: { xs: 'left', md: 'right' } }}>
                            <Typography variant="body2" sx={{ fontWeight: 500, fontSize: { xs: '0.8rem', md: 'inherit' } }}>
                              {file.recordCount ? file.recordCount.toLocaleString() : 'N/A'}
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: { xs: '0.7rem', md: 'inherit' } }}>
                              records
                            </Typography>
                          </Box>
                          <Box sx={{ textAlign: { xs: 'left', md: 'right' }, minWidth: { xs: 50, md: 60 } }}>
                            <Typography variant="body2" sx={{ fontWeight: 500, fontSize: { xs: '0.8rem', md: 'inherit' } }}>
                              {formatBytes(file.size)}
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: { xs: '0.7rem', md: 'inherit' } }}>
                              size
                            </Typography>
                          </Box>
                        </Box>

                        <Box sx={{ display: 'flex', gap: 1, flexWrap: { xs: 'wrap', sm: 'nowrap' } }}>
                          <Button
                            data-learn="View Records: Open a detailed view of all records for this protocol type with filtering capabilities."
                            variant="outlined"
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleViewRecords(file.type);
                            }}
                            sx={{ minWidth: { xs: 'auto', md: 100 }, flex: { xs: 1, sm: 'none' } }}
                          >
                            View Records
                          </Button>
                          <Button
                            data-learn="Explore in Charts: Create interactive visualizations and charts for this protocol's data fields."
                            variant="contained"
                            size="small"
                            startIcon={<BarChartIcon />}
                            onClick={(e) => {
                              e.stopPropagation();
                              router.push(`/explore?type=${encodeURIComponent(file.type)}`);
                            }}
                            sx={{ minWidth: { xs: 'auto', md: 100 }, flex: { xs: 1, sm: 'none' } }}
                          >
                            Explore
                          </Button>
                        </Box>
                      </Box>
                    ))}
                  </Box>
                </Collapse>
              </Box>
            ))}
          </Paper>
        ) : (
          <Box mt={3}>
            <Typography color="text.secondary">No audit record files found</Typography>
          </Box>
        )}
      </Box>

      {/* Record Viewer Dialog */}
      <Dialog open={selectedType !== null} onClose={handleClose} maxWidth="lg" fullWidth>
        <style>{`
          .json-key { color: #9cdcfe; }
          .json-string { color: #ce9178; }
          .json-number { color: #b5cea8; }
          .json-boolean { color: #569cd6; }
          .json-null { color: #569cd6; }
        `}</style>
        <DialogTitle>
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={2}>
              <Typography variant="h6">{selectedType} Records</Typography>
              <Box sx={{ display: 'flex', gap: 0.5 }}>
                <Button
                  data-learn="JSON View: Display records as raw JSON format for technical analysis and debugging."
                  size="small"
                  variant={viewMode === 'json' ? 'contained' : 'outlined'}
                  onClick={() => setViewMode('json')}
                  sx={{ minWidth: 60 }}
                >
                  JSON
                </Button>
                <Button
                  data-learn="UI View: Display records in a structured, user-friendly format with visual elements."
                  size="small"
                  variant={viewMode === 'ui' ? 'contained' : 'outlined'}
                  onClick={() => setViewMode('ui')}
                  sx={{ minWidth: 60 }}
                >
                  UI
                </Button>
              </Box>
            </Box>
            {executionTime > 0 && (
              <Tooltip title="Execution time">
                <Chip 
                  label={`${executionTime}ms`} 
                  size="small" 
                  color="info"
                  icon={<FilterAltIcon />}
                />
              </Tooltip>
            )}
          </Box>
          {loading && <LinearProgress sx={{ mt: 1 }} />}
        </DialogTitle>
        <DialogContent>
          {/* Filter Input */}
          <Box sx={{ mb: 2, pt: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
              <Box sx={{ position: 'relative', width: '100%' }}>
                {/* Syntax-highlighted overlay - only show when NOT focused */}
                {!filterInputFocused && filterExpression && highlightFilterExpression(filterExpression).length > 0 && (
                  <Box
                    sx={{
                      position: 'absolute',
                      top: '8.5px',
                      left: '52px', // Account for filter icon (14px padding + 24px icon + 14px spacing)
                      right: activeFilter ? '90px' : '50px', // Account for clear button if present
                      pointerEvents: 'none',
                      overflow: 'hidden',
                      zIndex: 1,
                      fontFamily: 'monospace',
                      fontSize: '0.9rem',
                      lineHeight: '1.4375em',
                      whiteSpace: 'nowrap',
                      color: 'transparent',
                      userSelect: 'none',
                    }}
                  >
                    {highlightFilterExpression(filterExpression).map((token, i) => {
                      if (token.type === 'text' && token.color === 'inherit') {
                        return <span key={i}>{token.value}</span>;
                      }
                      return (
                        <span key={i} style={{ color: token.color }}>
                          {token.value}
                        </span>
                      );
                    })}
                  </Box>
                )}

                {/* Original Autocomplete */}
                <Autocomplete
                  data-learn="Filter Expression: Enter conditions to filter records (e.g., DstPort == 443). Press TAB or CTRL+SPACE for autocomplete suggestions, ENTER to apply."
                  freeSolo
                  fullWidth
                  open={autocompleteOpen}
                  onOpen={() => {
                    // Don't auto-open - only open via Tab key
                  }}
                  onClose={(event, reason) => {
                    // Close on all reasons including blur (clicking outside)
                    setAutocompleteOpen(false);
                    setHighlightedOption(null);
                  }}
                  onHighlightChange={(event, option, reason) => {
                    // Track the currently highlighted option for Tab key selection
                    setHighlightedOption(option);
                  }}
                  options={getContextualSuggestions(filterExpression)}
                  value={filterExpression}
                  onChange={(event, newValue, reason) => {
                    if (reason === 'selectOption' && typeof newValue === 'string') {
                      // User selected from dropdown (via click, Enter, or TAB)
                      const updatedExpression = insertSuggestion(filterExpression, newValue);
                      setFilterExpression(updatedExpression);
                      
                      // Close the dropdown after selection
                      setAutocompleteOpen(false);
                      setHighlightedOption(null);
                      
                      // Reopen dropdown with new suggestions after a short delay (only via Tab)
                      // Remove auto-reopen behavior
                    }
                  }}
                  onInputChange={(event, newValue, reason) => {
                    if (reason === 'input') {
                      // User is typing - update value but DON'T auto-open dropdown
                      setFilterExpression(newValue);
                    } else if (reason === 'clear') {
                      setFilterExpression('');
                      setAutocompleteOpen(false);
                      setHighlightedOption(null);
                    }
                  }}
                  loading={loadingFields}
                  disabled={loading}
                  // Auto-select first option when there's only one match
                  autoHighlight
                  selectOnFocus={false}
                  clearOnBlur={false}
                  handleHomeEndKeys
                  disableClearable={true}
                  filterOptions={(options) => options} // Don't filter, we handle it in getContextualSuggestions
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      inputRef={filterInputRef}
                      size="small"
                      label="Filter Expression"
                      placeholder="e.g., DstPort == 443 or SrcIP == '192.168.1.1'"
                      onFocus={() => setFilterInputFocused(true)}
                      onBlur={() => setFilterInputFocused(false)}
                      onKeyDown={(e) => {
                        // Handle CMD+ENTER or CTRL+ENTER to execute query immediately
                        if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                          e.preventDefault();
                          e.stopPropagation();
                          // Close dropdown and execute filter immediately
                          setAutocompleteOpen(false);
                          handleApplyFilter();
                          return;
                        }
                        
                        // Handle Enter key - close dropdown if open, otherwise apply filter
                        if (e.key === 'Enter') {
                          if (autocompleteOpen) {
                            // Dropdown is open - let Autocomplete handle selection, then close
                            // The onChange handler will close it
                            return;
                          } else {
                            // Dropdown is closed - apply filter
                            e.preventDefault();
                            handleApplyFilter();
                          }
                          return;
                        }
                        
                        // Handle TAB or Ctrl+Space for autocomplete - ONLY ways to open dropdown
                        if ((e.key === 'Tab' && !e.shiftKey) || (e.key === ' ' && e.ctrlKey)) {
                          e.preventDefault();
                          e.stopPropagation();
                          
                          const suggestions = getContextualSuggestions(filterExpression);
                          
                          if (autocompleteOpen && suggestions.length > 0) {
                            // Dropdown is open - select the currently highlighted option (or first if none highlighted)
                            const suggestionToUse = highlightedOption || suggestions[0];
                            const updatedExpression = insertSuggestion(filterExpression, suggestionToUse);
                            setFilterExpression(updatedExpression);
                            setHighlightedOption(null);
                            
                            // Keep dropdown open with new suggestions
                            setTimeout(() => {
                              const newSuggestions = getContextualSuggestions(updatedExpression);
                              if (newSuggestions.length > 0) {
                                setAutocompleteOpen(true);
                              } else {
                                setAutocompleteOpen(false);
                              }
                            }, 100);
                          } else if (suggestions.length > 0) {
                            // Dropdown is closed but we have suggestions - open it
                            setAutocompleteOpen(true);
                          }
                          
                          // Keep focus and cursor position
                          // Capture the element before requestAnimationFrame
                          const currentTarget = e.currentTarget;
                          requestAnimationFrame(() => {
                            const inputElement = currentTarget?.querySelector('input');
                            if (inputElement) {
                              inputElement.focus();
                            }
                          });
                        }
                      }}
                      InputProps={{
                        ...params.InputProps,
                        startAdornment: (
                          <>
                            <InputAdornment position="start">
                              <FilterAltIcon color="action" />
                            </InputAdornment>
                            {params.InputProps.startAdornment}
                          </>
                        ),
                        endAdornment: (
                          <>
                            {params.InputProps.endAdornment}
                            {activeFilter && (
                              <InputAdornment position="end">
                                <Tooltip title="Clear filter">
                                  <IconButton size="small" onClick={handleClearFilter} edge="end">
                                    <ClearIcon />
                                  </IconButton>
                                </Tooltip>
                              </InputAdornment>
                            )}
                          </>
                        ),
                        style: { 
                          fontFamily: 'monospace', 
                          fontSize: '0.9rem',
                        },
                        sx: {
                          '& input': {
                            // Only make text transparent when not focused and we have an expression
                            color: (!filterInputFocused && filterExpression) ? 'transparent' : 'text.primary',
                            caretColor: 'text.primary !important',
                            '&::selection': {
                              backgroundColor: 'rgba(100, 150, 255, 0.3)',
                            },
                            '&:focus': {
                              caretColor: 'text.primary !important',
                              color: 'text.primary', // Always show text when focused
                            },
                          },
                        },
                      }}
                      helperText={
                        activeFilter 
                          ? `Active filter: ${activeFilter}` 
                          : valuesSampleInfo
                          ? `Press TAB or CTRL+SPACE to show suggestions, ENTER to apply filter. CMD+ENTER to execute immediately. Values sampled from ${valuesSampleInfo.recordsScanned} records (max ${valuesSampleInfo.maxPerField} per field).`
                          : "Press TAB or CTRL+SPACE to show autocomplete suggestions, ENTER to apply filter, CMD+ENTER to execute immediately."
                      }
                    />
                  )}
                  slotProps={{
                    popper: {
                      sx: {
                        '& .MuiAutocomplete-listbox': {
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                        },
                        '& .MuiAutocomplete-option': {
                          '&[data-focus="true"]': {
                            backgroundColor: 'action.hover',
                          },
                        },
                      },
                    },
                  }}
                />
              </Box>
              <Tooltip title="Show filter examples">
                <IconButton 
                  data-learn="Filter Help: Toggle display of example filter expressions and syntax documentation."
                  size="small" 
                  onClick={() => {
                    setShowFilterHelp(!showFilterHelp);
                    setAutocompleteOpen(false); // Close autocomplete dropdown
                  }}
                  color={showFilterHelp ? "primary" : "default"}
                  sx={{ mt: 0.5 }}
                >
                  <HelpOutlineIcon />
                </IconButton>
              </Tooltip>
            </Box>
            
            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
              <Button
                data-learn="Apply Filter: Execute the filter expression to show only matching records."
                variant="contained"
                size="small"
                startIcon={<SearchIcon />}
                onClick={handleApplyFilter}
                disabled={loading || !filterExpression}
              >
                Apply Filter
              </Button>
              {activeFilter && (
                <Button
                  data-learn="Clear Filter: Remove the active filter and show all records."
                  variant="outlined"
                  size="small"
                  startIcon={<ClearIcon />}
                  onClick={handleClearFilter}
                  disabled={loading}
                >
                  Clear Filter
                </Button>
              )}
            </Box>

            {/* Filter Help/Examples */}
            <Collapse in={showFilterHelp}>
              <Paper 
                sx={{ 
                  mt: 2, 
                  p: 2, 
                  bgcolor: 'background.default',
                  border: 1,
                  borderColor: 'divider',
                  maxHeight: '70vh',
                  overflowY: 'auto'
                }}
              >
                <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600, mb: 2 }}>
                  Filter Expression Examples
                </Typography>
                
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {/* Helper to render examples with insert button */}
                  {[
                    {
                      category: 'Basic Comparisons',
                      examples: [
                        { expr: 'DstPort == 443', desc: 'Exact match' },
                        { expr: 'SrcPort > 1024', desc: 'Numeric comparison' },
                        { expr: 'Protocol == "TCP"', desc: 'String match' },
                      ]
                    },
                    {
                      category: 'Logical Operators',
                      examples: [
                        { expr: 'SrcPort == 80 && DstPort == 443', desc: 'AND operator' },
                        { expr: 'DstPort == 80 || DstPort == 443', desc: 'OR operator' },
                        { expr: 'SYN && !ACK', desc: 'NOT operator (TCP flags)' },
                      ]
                    },
                    {
                      category: 'Nested Fields (Arrays & Structs)',
                      examples: [
                        { expr: 'SrcPorts[0].PortNumber == 80', desc: 'Array element field' },
                        { expr: 'DstPorts[0].Protocol == "TCP"', desc: 'Nested string field' },
                        { expr: 'SrcPorts[0].PortNumber < DstPorts[0].PortNumber', desc: 'Compare nested fields' },
                      ]
                    },
                    {
                      category: 'Network Helper Functions',
                      examples: [
                        { expr: 'IsPrivateIP(SrcIP)', desc: 'Check if IP is private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)' },
                        { expr: 'IsPublicIP(DstIP)', desc: 'Check if IP is public (non-private)' },
                        { expr: 'InSubnet(SrcIP, "192.168.0.0/16")', desc: 'Check if IP is in a CIDR subnet' },
                        { expr: 'ParsePort("8080")', desc: 'Convert port string to integer' },
                        { expr: 'PortInRange(DstPort, 8000, 9000)', desc: 'Check if port is in range (inclusive)' },
                      ]
                    },
                    {
                      category: 'Time Helper Functions',
                      examples: [
                        { expr: 'TimeInRange(Timestamp, 1234567890, 1234567999)', desc: 'Check if timestamp is in range (nanoseconds)' },
                        { expr: 'DurationSince(Timestamp) > 3600000000000', desc: 'Check if more than 1 hour has passed (nanoseconds)' },
                        { expr: 'FormatTime(Timestamp, "2006-01-02 15:04:05")', desc: 'Format timestamp to string (Go time format)' },
                      ]
                    },
                    {
                      category: 'String Helper Functions',
                      examples: [
                        { expr: 'ContainsAny(Payload, ["password", "secret"])', desc: 'Check if string contains any substring from array' },
                        { expr: 'MatchesPattern(Payload, ".*password.*")', desc: 'Check if string matches regex pattern' },
                      ]
                    },
                    {
                      category: 'Complex Examples',
                      examples: [
                        { expr: 'IsPrivateIP(SrcIP) && IsPublicIP(DstIP) && DstPort == 443', desc: 'Private to public HTTPS traffic' },
                        { expr: '(DstPort == 80 || DstPort == 443) && Length > 1000', desc: 'HTTP/HTTPS with large packets' },
                        { expr: 'SYN && !ACK && DstPort < 1024', desc: 'SYN scan to privileged ports' },
                        { expr: 'InSubnet(SrcIP, "10.0.0.0/8") && PortInRange(DstPort, 20, 21)', desc: 'Internal FTP traffic' },
                      ]
                    },
                  ].map((section) => (
                    <Box key={section.category}>
                      <Typography variant="caption" color="primary" sx={{ fontWeight: 600 }}>
                        {section.category}
                      </Typography>
                      <Box sx={{ ml: 2, mt: 0.5, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                        {section.examples.map((example, idx) => (
                          <Box key={example.expr} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <Box sx={{ 
                              bgcolor: 'action.hover', 
                              px: 0.75, 
                              py: 0.25, 
                              borderRadius: 0.5,
                              border: 1,
                              borderColor: 'divider',
                              flex: 1,
                            }}>
                              <FilterExpressionHighlight 
                                expression={example.expr} 
                                fontSize="0.85rem"
                                wrap={true}
                              />
                            </Box>
                            <Tooltip title="Insert into filter">
                              <IconButton
                                data-learn="Insert Example: Copy this example filter expression into the filter input field."
                                size="small"
                                onClick={() => handleInsertExample(example.expr)}
                                sx={{ p: 0.25 }}
                              >
                                <ContentCopyIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Typography variant="caption" color="text.secondary" sx={{ flex: 2 }}>
                              {example.desc}
                            </Typography>
                          </Box>
                        ))}
                      </Box>
                    </Box>
                  ))}

                  <Box sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
                    <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                      💡 <strong>Tip:</strong> Field names are case-sensitive. Use TAB or CTRL+SPACE for autocompletion or check the record structure for available fields.
                    </Typography>
                    <Typography variant="caption" color="text.secondary" display="block">
                      📚 <strong>All Helper Functions:</strong> InSubnet, IsPrivateIP, IsPublicIP, ParsePort, PortInRange, TimeInRange, DurationSince, FormatTime, ContainsAny, MatchesPattern
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Collapse>
          </Box>

          {streamError ? (
            <Box p={3}>
              <Typography color="error" variant="h6" gutterBottom>
                Unable to load records
              </Typography>
              <Typography color="text.secondary" paragraph>
                {streamError}
              </Typography>
              {streamError.includes('incomplete') && (
                <Box mt={2}>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    This file is currently being written. Please wait for processing to complete and try again.
                  </Typography>
                  <Button 
                    variant="outlined" 
                    onClick={() => handleViewRecords(selectedType!, activeFilter)}
                    sx={{ mt: 1 }}
                  >
                    Retry
                  </Button>
                </Box>
              )}
            </Box>
          ) : loading && records.length === 0 && total === 0 ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : records.length > 0 ? (
            <Box>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 1 }}>
                <Typography variant="body2">
                  Showing {records.length} of {total > 0 ? total : records.length} records
                </Typography>
                {scanned > 0 && (
                  <Typography variant="body2" color="text.secondary">
                    (Scanned: {scanned.toLocaleString()} total records)
                  </Typography>
                )}
              </Box>
              <Box
                sx={{
                  maxHeight: '60vh',
                  overflow: 'auto',
                }}
              >
                {records.map((record, idx) => (
                  <Paper 
                    key={`record-${idx}-${JSON.stringify(record).substring(0, 100)}`} 
                    elevation={2}
                    sx={{ 
                      p: 2, 
                      mb: 1.5, 
                      bgcolor: viewMode === 'json' ? '#1e1e1e' : 'action.hover',
                      borderRadius: 2,
                      border: 1,
                      borderColor: 'divider',
                      '&:hover': {
                        boxShadow: 4,
                        borderColor: 'primary.main'
                      }
                    }}
                  >
                    {viewMode === 'json' ? (
                      <pre
                        style={{
                          margin: 0,
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                        }}
                        dangerouslySetInnerHTML={{
                          __html: syntaxHighlight(JSON.stringify(convertTimestamps(record), null, 2))
                        }}
                      />
                    ) : (
                      <RecordUI data={convertTimestamps(record)} />
                    )}
                  </Paper>
                ))}
              </Box>
            </Box>
          ) : !loading && total === 0 && activeFilter ? (
            <Box p={3} textAlign="center">
              <Typography variant="h6" color="text.secondary" gutterBottom>
                No records match the filter
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                The filter expression didn't match any records. Try adjusting your filter or clearing it to see all records.
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, justifyContent: 'center', mt: 2 }}>
                <Button
                  data-learn="Clear Filter: Remove the current filter to show all available records."
                  variant="outlined"
                  onClick={handleClearFilter}
                  startIcon={<ClearIcon />}
                >
                  Clear Filter
                </Button>
                <Button
                  data-learn="Show Examples: Display filter expression examples and syntax help."
                  variant="text"
                  onClick={() => setShowFilterHelp(true)}
                  startIcon={<HelpOutlineIcon />}
                >
                  Show Examples
                </Button>
              </Box>
            </Box>
          ) : (
            <Box p={3} textAlign="center">
              <Typography variant="body2" color="text.secondary">
                No records available
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button data-learn="Close Dialog: Close the record viewer and return to the audit records list." onClick={handleClose}>Close</Button>
        </DialogActions>
      </Dialog>
    </Layout>
  );
}

// Helper function to assign colors to layers
function getLayerColor(layerName: string): string {
  const colorMap: Record<string, string> = {
    'Link Layer': '#2196F3',        // Blue
    'Network Layer': '#4CAF50',     // Green
    'Transport Layer': '#FF9800',   // Orange
    'Application Layer': '#9C27B0', // Purple
    'Stream Decoders': '#00BCD4',   // Cyan
    'Abstract Decoders': '#F44336', // Red
    'Other': '#9E9E9E',            // Grey
  };
  return colorMap[layerName] || '#9E9E9E';
}
