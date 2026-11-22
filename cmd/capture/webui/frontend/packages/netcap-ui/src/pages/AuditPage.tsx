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
  Close as CloseIcon,
} from '@mui/icons-material';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { formatBytes, getBackendUrl } from '../lib/api';

import { useNetcapRouter, useNetcapApi, useIsMobile } from '../hooks';
import FilterExpressionHighlight, { FilterExpressionBlock } from '../components/FilterExpressionHighlight';

import { syntaxHighlightJSON } from '../lib/html';
import { useTheme } from '@mui/material/styles';
import { appearanceTokens, categoryAppearance, type AppearanceMode } from '../lib/appearance';
import { formatRecordUnits as convertTimestamps } from '../lib/recordUnits';
import { getLocale as getUILocale, translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, messageSource, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { translate } from "../lib/i18n";
import { recordTypeLabel } from "../lib/i18n";
import { type MessageText } from "../lib/i18n";
import { rawCode } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";







interface LayerGroup {
  layerName: string;
  files: any[];
}

// Component to render record as UI elements
interface RecordUIProps {
  data: any;
  level?: number;
}

function RecordUI({ data, level = 0 }: RecordUIProps) {
  const __uiLocale = useUILocale();
  const mode = useTheme().palette.mode;
  if (data === null || data === undefined) {
    return <Typography variant="body2" color="text.secondary">—</Typography>;
  }
  
  if (typeof data === 'boolean') {
    return (
      <Chip label={String(data)} 
        size="small" 
        color={data ? "success" : "default"}
        sx={{ fontFamily: 'monospace', height: 22 }} />
    );
  }
  
  if (typeof data === 'number') {
    return (
      <Typography component="span" 
        sx={{ 
          fontFamily: 'monospace', 
          color: 'primary.main',
          fontWeight: 500,
          fontSize: '0.9rem'
        }}>{data.toLocaleString(getUILocale())}</Typography>
    );
  }
  
  if (typeof data === 'string') {
    // Check if it's an IP address
    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(data);
    // Check if it's a timestamp (ISO format)
    const isTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(data);
    
    if (isIP) {
      return (
        <Chip label={data} 
          size="small"
          sx={{ 
            fontFamily: 'monospace',
            bgcolor: 'info.main',
            color: 'info.contrastText',
            height: 22,
            fontSize: '0.8rem'
          }} />
      );
    }
    
    if (isTimestamp) {
      return (
        <Typography component="span"
          sx={{ 
            fontFamily: 'monospace',
            color: 'text.secondary',
            fontSize: '0.85rem'
          }}>{data}</Typography>
      );
    }
    
    return (
      <Typography component="span"
        sx={{ 
          fontFamily: 'monospace',
          fontSize: '0.9rem'
        }}>{data}</Typography>
    );
  }
  
  if (Array.isArray(data)) {
    if (data.length === 0) {
      return <Typography variant="body2" color="text.secondary">[]</Typography>;
    }
    
    // For simple arrays (primitives), show inline
    if (data.every(item => typeof item !== 'object' || item === null)) {
      return (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>{data.map((item, idx) => (
            <RecordUI key={`${String(item)}-${idx}`} data={item} level={level + 1} />
          ))}</Box>
      );
    }
    
    // For complex arrays, show as list
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mt: 0.5 }}>{data.map((item, idx) => (
          <Paper key={`item-${idx}-${JSON.stringify(item).substring(0, 50)}`} sx={{ p: 1, bgcolor: 'background.default' }}><RecordUI data={item} level={level + 1} /></Paper>
        ))}</Box>
    );
  }
  
  if (typeof data === 'object') {
    const entries = Object.entries(data);
    if (entries.length === 0) {
      return <Typography variant="body2" color="text.secondary">{'{}'}</Typography>;
    }
    
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: level === 0 ? 0.75 : 0.5 }}>{entries.map(([key, value]) => {
          const fieldColor = categoryAppearance(key, mode);
          
          return (
            <Box key={key}
              sx={{ 
                display: 'flex',
                flexDirection: 'row',
                alignItems: 'flex-start',
                gap: 1.5,
                borderLeft: level > 0 ? 2 : 0,
                borderColor: 'divider',
                pl: level > 0 ? 1.5 : 0
              }}><Box sx={{ 
                  minWidth: level === 0 ? 180 : 140,
                  maxWidth: level === 0 ? 180 : 140,
                  pt: 0.2
                }}><Chip label={key}
                  size="small"
                  sx={{
                    bgcolor: fieldColor.background,
                    color: fieldColor.foreground,
                    border: '1px solid', borderColor: fieldColor.border,
                    fontWeight: 600,
                    fontFamily: 'monospace',
                    fontSize: '0.8rem',
                    height: 22,
                    maxWidth: '100%',
                    '& .MuiChip-label': {
                      px: 1.2
                    }
                  }} /></Box><Box sx={{ flex: 1, minWidth: 0, pt: 0.2 }}><RecordUI data={value} level={level + 1} /></Box></Box>
          );
        })}</Box>
    );
  }
  
  return (
    <Typography component="span" sx={{ fontFamily: 'monospace' }}>{String(data)}</Typography>
  );
}

// Syntax highlighting for JSON

export default function AuditRecords() {
  const __uiLocale = useUILocale();
  const colors = appearanceTokens(useTheme().palette.mode);
  const isMobile = useIsMobile();
  const router = useNetcapRouter();
  const api = useNetcapApi();
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
  }, [api, inputFiles, status, autoSelectAttempted, mutateStatus, mutate]);
  
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
  const [streamError, setStreamError] = useState<UIMessageText | null>(null);
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
      (error, presentation?: MessageText) => {
        console.error('Stream error:', error);
        setStreamError(presentation ?? error);
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
      alert(i18nText("ui:m_c621cba9a2fca09e49af"));
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
      alert(i18nText("ui:m_03a2ad41452d2a456747"));
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate, __uiLocale]);

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
      alert(i18nText("ui:m_85ac94fb0f2259d34cf7"));
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
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_275fdcca8e700b8b3b2c")} />
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
      <Layout title={i18nText("ui:m_b4278c403d07ec43e879")} headerAction={fileSelector}><Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh"><CircularProgress /></Box></Layout>
    );
  }

  if (error) {
    return (
      <Layout title={i18nText("ui:m_b4278c403d07ec43e879")} headerAction={fileSelector}><Box><Typography color="error">{i18nText("ui:m_5e92b00915d41fb64012")}</Typography></Box></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_b4278c403d07ec43e879")} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}>{/* Session Selector for Try Service */}{status?.isServiceMode && sessions && sessions.length > 1 && (
          <Box mb={3}><FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 300 } }}><Select value={status?.sessionId || ''}
                onChange={handleSessionChange}
                disabled={switchingSession}
                displayEmpty
                renderValue={(value) => {
                  const session = sessions.find(s => s.sessionId === value);
                  return session ? i18nText("ui:m_98ea5107ce31d865f187", { arg0: session.inputFilename }) : translate("ui:m_6a62a54b5077b61e7565");
                }}>{sessions
                  .filter(s => s.resultsReady)
                  .map((session) => (
                    <MenuItem key={session.sessionId} value={session.sessionId}><Box><Typography variant="body2">{session.inputFilename}</Typography><Typography variant="caption" color="text.secondary">{new Date(session.uploadTimestamp).toLocaleString(getUILocale())}</Typography></Box></MenuItem>
                  ))}</Select></FormControl></Box>
        )}<Box mb={3}><Box display="flex" 
            flexDirection={{ xs: 'column', sm: 'row' }}
            justifyContent="space-between" 
            alignItems={{ xs: 'stretch', sm: 'flex-start' }} 
            gap={2}><Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
              {i18nRichText("ui:m_cc25a03d5b8298496c30", { arg0: layerGroups.reduce((sum, group) => sum + group.files.length, 0) })}
            </Typography>{/* Download All Button */}<Button data-learn={i18nText("ui:m_433b98d81c4f3bdacbd4")}
              variant="contained"
              color="success"
              startIcon={<DownloadIcon />}
              onClick={handleDownloadAll}
              disabled={(!status?.sessionId && !status?.activeInputFile) || 
                // Also require at least one audit file available
                layerGroups.reduce((sum, group) => sum + group.files.length, 0) === 0}
              size="small"
              sx={{ minWidth: { xs: 'auto', sm: 180 } }}
              fullWidth={false}>
              {i18nText("ui:m_733fd6c3bfd4d9f84cee")}
            </Button></Box></Box>{layerGroups.length > 0 ? (
          <Paper sx={{ p: 2 }}>{layerGroups.map((group, groupIdx) => (
              <Box key={group.layerName} sx={{ mb: groupIdx < layerGroups.length - 1 ? 2 : 0 }}>{/* Layer Header */}<Box sx={{
                    display: 'flex',
                    alignItems: 'center',
                    cursor: 'pointer',
                    p: 1,
                    borderRadius: 1,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                  onClick={() => toggleLayer(group.layerName)}><IconButton size="small" sx={{ mr: 1 }}>{expandedLayers.has(group.layerName) ? <ExpandMoreIcon /> : <ChevronRightIcon />}</IconButton><Box sx={{
                      width: 3,
                      height: 24,
                      bgcolor: getLayerColor(group.layerName, colors.mode),
                      mr: 2,
                      borderRadius: 1,
                    }} /><Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>{group.layerName}</Typography><Chip label={i18nText("ui:m_be7ad8c575b1b0c9e195", { arg0: group.files.length })}
                    size="small"
                    variant="outlined" /></Box>{/* Layer Content */}<Collapse in={expandedLayers.has(group.layerName)}><Box sx={{ ml: 6, mt: 1 }}>{group.files.map((file, fileIdx) => (
                      <Box key={file.path}
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
                        }}><Box sx={{ display: 'flex', alignItems: 'center', flex: 1, minWidth: 0 }}>{/* Tree connector visualization */}<Box sx={{
                              width: 20,
                              height: 2,
                              bgcolor: 'divider',
                              mr: 1,
                              display: { xs: 'none', md: 'block' },
                            }} /><FileIcon sx={{ mr: 2, color: 'text.secondary', fontSize: 20, flexShrink: 0 }} /><Box sx={{ flex: 1, minWidth: 0 }}><Typography sx={{
                                fontFamily: 'monospace',
                                fontWeight: 600,
                                fontSize: '0.95rem',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}>{recordTypeLabel(file.type)}</Typography><Typography variant="caption" 
                              color="text.secondary" 
                              sx={{ 
                                fontFamily: 'monospace',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                display: 'block'
                              }}>{file.name}</Typography></Box></Box><Box sx={{ 
                          display: 'flex', 
                          flexDirection: { xs: 'row', md: 'row' },
                          alignItems: 'center', 
                          gap: { xs: 1, md: 2 }, 
                          justifyContent: { xs: 'space-between', md: 'flex-end' },
                          mr: { xs: 0, md: 2 }
                        }}><Box sx={{ textAlign: { xs: 'left', md: 'right' } }}><Typography variant="body2" sx={{ fontWeight: 500, fontSize: { xs: '0.8rem', md: 'inherit' } }}>{file.recordCount ? file.recordCount.toLocaleString(getUILocale()) : i18nText("ui:m_8dc598ebf1e055830140")}</Typography><Typography variant="caption" color="text.secondary" sx={{ fontSize: { xs: '0.7rem', md: 'inherit' } }}>
                              {i18nText("ui:m_0980f77190e168c4b086")}
                            </Typography></Box><Box sx={{ textAlign: { xs: 'left', md: 'right' }, minWidth: { xs: 50, md: 60 } }}><Typography variant="body2" sx={{ fontWeight: 500, fontSize: { xs: '0.8rem', md: 'inherit' } }}>{formatBytes(file.size)}</Typography><Typography variant="caption" color="text.secondary" sx={{ fontSize: { xs: '0.7rem', md: 'inherit' } }}>
                              {i18nText("ui:m_6d4a28882311f19a72d3")}
                            </Typography></Box></Box><Box sx={{ display: 'flex', gap: 1, flexWrap: { xs: 'wrap', sm: 'nowrap' } }}><Button data-learn={i18nText("ui:m_d988e8ea5c69394edf59")}
                            variant="outlined"
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleViewRecords(file.type);
                            }}
                            sx={{ minWidth: { xs: 'auto', md: 100 }, flex: { xs: 1, sm: 'none' } }}>
                            {i18nText("ui:m_d38aa5e68d2692031355")}
                          </Button><Button data-learn={i18nText("ui:m_1adc5d39207960e169b0")}
                            variant="contained"
                            size="small"
                            startIcon={<BarChartIcon />}
                            onClick={(e) => {
                              e.stopPropagation();
                              router.push(`/explore?type=${encodeURIComponent(file.type)}`);
                            }}
                            sx={{ minWidth: { xs: 'auto', md: 100 }, flex: { xs: 1, sm: 'none' } }}>
                            {i18nText("ui:m_29a8a9d5e1d2154e8a3f")}
                          </Button></Box></Box>
                    ))}</Box></Collapse></Box>
            ))}</Paper>
        ) : (
          <Box mt={3}><Typography color="text.secondary">{i18nText("ui:m_532efa9969cf66450d88")}</Typography></Box>
        )}</Box>{/* Record Viewer Dialog */}<Dialog open={selectedType !== null} onClose={handleClose} maxWidth="lg" fullWidth fullScreen={isMobile}><style>{rawCode("\n          .json-key '{' color: {arg0}; '}'\n          .json-string '{' color: {arg1}; '}'\n          .json-number '{' color: {arg2}; '}'\n          .json-boolean, .json-null '{' color: {arg3}; '}'\n        ", { arg0: colors.syntax.key, arg1: colors.syntax.string, arg2: colors.syntax.number, arg3: colors.syntax.keyword })}</style><DialogTitle><Box display="flex" alignItems="center" justifyContent="space-between"><Box display="flex" alignItems="center" gap={2}><Typography variant="h6">{i18nRichText("ui:m_bdedd0ee231db7004d55", { arg0: selectedType })}</Typography><Box sx={{ display: 'flex', gap: 0.5 }}><Button data-learn={i18nText("ui:m_d852769d923c7e55894b")}
                  size="small"
                  variant={viewMode === 'json' ? 'contained' : 'outlined'}
                  onClick={() => setViewMode('json')}
                  sx={{ minWidth: 60 }}>JSON
                </Button><Button data-learn={i18nText("ui:m_e68c5d60122a3462629f")}
                  size="small"
                  variant={viewMode === 'ui' ? 'contained' : 'outlined'}
                  onClick={() => setViewMode('ui')}
                  sx={{ minWidth: 60 }}>
                  {i18nText("ui:m_c38c2ff44b00e57d6eb4")}
                </Button></Box></Box>{executionTime > 0 && (
              <Tooltip title={i18nText("ui:m_c32a702c1f15f7edf49c")}><Chip label={`${executionTime}ms`}
                  size="small"
                  color="info"
                  icon={<FilterAltIcon />} /></Tooltip>
            )}{isMobile && (
              <IconButton onClick={handleClose} edge="end"><CloseIcon /></IconButton>
            )}</Box>{loading && <LinearProgress sx={{ mt: 1 }} />}</DialogTitle><DialogContent>{/* Filter Input */}<Box sx={{ mb: 2, pt: 1 }}><Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}><Autocomplete data-learn={i18nText("ui:m_9f313249696461bde1cb")}
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
                  <TextField {...params}
                    inputRef={filterInputRef}
                    size="small"
                    label={i18nText("ui:m_5162adf432ea067f13f3")}
                    placeholder={i18nText("ui:m_1e160cafaff1d99a7e9a")}
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
                        requestAnimationFrame(() => {
                          const inputElement = e.currentTarget.querySelector('input');
                          if (inputElement) {
                            inputElement.focus();
                          }
                        });
                      }
                    }}
                    InputProps={{
                      ...params.InputProps,
                      startAdornment: (
                        <><InputAdornment position="start"><FilterAltIcon color="action" /></InputAdornment>{params.InputProps.startAdornment}</>
                      ),
                      endAdornment: (
                        <>{params.InputProps.endAdornment}{activeFilter && (
                            <InputAdornment position="end"><Tooltip title={i18nText("ui:m_b727dea40e180cc79e3e")}><IconButton size="small" onClick={handleClearFilter} edge="end"><ClearIcon /></IconButton></Tooltip></InputAdornment>
                          )}</>
                      ),
                      style: { fontFamily: 'monospace', fontSize: '0.9rem' }
                    }}
                    helperText={activeFilter ? i18nText("ui:m_0daa26447ccf767fdc9e", { arg0: activeFilter }) : valuesSampleInfo ? i18nText("ui:m_5cbfa96e5d7bc8ea8fc8", { arg0: valuesSampleInfo.recordsScanned, arg1: valuesSampleInfo.maxPerField }) : i18nText("ui:m_75cb4fbf2ce87be02677")} />
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
                }} /><Tooltip title={i18nText("ui:m_0be7b7b33eb1d95c2198")}><IconButton data-learn={i18nText("ui:m_71e2b47e8dfd39ece284")}
                  size="small" 
                  onClick={() => {
                    setShowFilterHelp(!showFilterHelp);
                    setAutocompleteOpen(false); // Close autocomplete dropdown
                  }}
                  color={showFilterHelp ? "primary" : "default"}
                  sx={{ mt: 0.5 }}><HelpOutlineIcon /></IconButton></Tooltip></Box><Box sx={{ display: 'flex', gap: 1, mt: 1 }}><Button data-learn={i18nText("ui:m_ef194d924de4abb17126")}
                variant="contained"
                size="small"
                startIcon={<SearchIcon />}
                onClick={handleApplyFilter}
                disabled={loading || !filterExpression}>
                {i18nText("ui:m_7b2c4962d82fb230a818")}
              </Button>{activeFilter && (
                <Button data-learn={i18nText("ui:m_0b9306d02a3e810535b9")}
                  variant="outlined"
                  size="small"
                  startIcon={<ClearIcon />}
                  onClick={handleClearFilter}
                  disabled={loading}>
                  {i18nText("ui:m_cfdaafce54dddd3e0005")}
                </Button>
              )}</Box>{/* Filter Preview with Syntax Highlighting */}{filterExpression && (
              <Box sx={{ mt: 2 }}><Typography variant="caption" color="text.secondary" gutterBottom>
                  {i18nText("ui:m_9d7b31307a5300a91fc8")}
                </Typography><FilterExpressionBlock expression={filterExpression} /></Box>
            )}{/* Active Filter Display */}{activeFilter && activeFilter !== filterExpression && (
              <Box sx={{ mt: 2 }}><Typography variant="caption" color="text.secondary" gutterBottom>
                  {i18nText("ui:m_29ab9df955ed2fd79486")}
                </Typography><FilterExpressionBlock expression={activeFilter} sx={{ bgcolor: 'background.default', border: '1px solid', borderColor: 'success.main' }} /></Box>
            )}{/* Filter Help/Examples */}<Collapse in={showFilterHelp}><Paper sx={{ 
                  mt: 2, 
                  p: 2, 
                  bgcolor: 'background.default',
                  border: 1,
                  borderColor: 'divider',
                  maxHeight: '70vh',
                  overflowY: 'auto'
                }}><Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600, mb: 2 }}>
                  {i18nText("ui:m_2391238e82e02056d299")}
                </Typography><Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>{/* Helper to render examples with insert button */}{[
                    {
                      category: 'Basic Comparisons',
                      examples: [
                        { expr: rawCode("DstPort == 443"), desc: translate("ui:m_6759505d4ed37d923f7e") },
                        { expr: rawCode("SrcPort > 1024"), desc: translate("ui:m_b2d83801b53acc2898bc") },
                        { expr: rawCode("Protocol == \"TCP\""), desc: translate("ui:m_79ded4e53c441865e577") },
                      ]
                    },
                    {
                      category: 'Logical Operators',
                      examples: [
                        { expr: rawCode("SrcPort == 80 && DstPort == 443"), desc: translate("ui:m_4a8eca31cfbaea4fdbe8") },
                        { expr: rawCode("DstPort == 80 || DstPort == 443"), desc: translate("ui:m_ed3433c09e02e4c34545") },
                        { expr: translate("ui:m_a5996a4c80100a7e392c"), desc: translate("ui:m_dc7e743f58318c740080") },
                      ]
                    },
                    {
                      category: 'Nested Fields (Arrays & Structs)',
                      examples: [
                        { expr: rawCode("SrcPorts[0].PortNumber == 80"), desc: translate("ui:m_3431b83af4796badc495") },
                        { expr: rawCode("DstPorts[0].Protocol == \"TCP\""), desc: translate("ui:m_ee50f0bf9298c5077e6b") },
                        { expr: rawCode("SrcPorts[0].PortNumber '<' DstPorts[0].PortNumber"), desc: translate("ui:m_6f65648f16cfc06fd341") },
                      ]
                    },
                    {
                      category: 'Network Helper Functions',
                      examples: [
                        { expr: 'IsPrivateIP(SrcIP)', desc: translate("ui:m_7d18840997e49a497f0f") },
                        { expr: 'IsPublicIP(DstIP)', desc: translate("ui:m_1532f48dad00425d3f59") },
                        { expr: rawCode("InSubnet(SrcIP, \"192.168.0.0/16\")"), desc: translate("ui:m_fa26ce1fa037b3528a11") },
                        { expr: 'ParsePort("8080")', desc: translate("ui:m_e2c5ec0fbbc4b0abf873") },
                        { expr: rawCode("PortInRange(DstPort, 8000, 9000)"), desc: translate("ui:m_fab8dbd7f9da36152130") },
                      ]
                    },
                    {
                      category: 'Time Helper Functions',
                      examples: [
                        { expr: rawCode("TimeInRange(Timestamp, 1234567890, 1234567999)"), desc: translate("ui:m_0e24dbd5538800051d9d") },
                        { expr: rawCode("DurationSince(Timestamp) > 3600000000000"), desc: translate("ui:m_45e74e5c8e47fc5f60bd") },
                        { expr: rawCode("FormatTime(Timestamp, \"2006-01-02 15:04:05\")"), desc: translate("ui:m_1f2be265f83df9815b2a") },
                      ]
                    },
                    {
                      category: 'String Helper Functions',
                      examples: [
                        { expr: rawCode("ContainsAny(Payload, [\"password\", \"secret\"])"), desc: translate("ui:m_4be557839212a68c4765") },
                        { expr: rawCode("MatchesPattern(Payload, \".*password.*\")"), desc: translate("ui:m_6b5961b7171dc74bc447") },
                      ]
                    },
                    {
                      category: 'Complex Examples',
                      examples: [
                        { expr: rawCode("IsPrivateIP(SrcIP) && IsPublicIP(DstIP) && DstPort == 443"), desc: translate("ui:m_e2a421325dbff9dd7190") },
                        { expr: rawCode("(DstPort == 80 || DstPort == 443) && Length > 1000"), desc: translate("ui:m_2f35b59db2b3b2394363") },
                        { expr: rawCode("SYN && !ACK && DstPort '<' 1024"), desc: translate("ui:m_a371df81c722dacb4da9") },
                        { expr: rawCode("InSubnet(SrcIP, \"10.0.0.0/8\") && PortInRange(DstPort, 20, 21)"), desc: translate("ui:m_dd64f90fb0de776b5e1e") },
                      ]
                    },
                  ].map((section) => (
                    <Box key={section.category}><Typography variant="caption" color="primary" sx={{ fontWeight: 600 }}>{i18nText(section.category)}</Typography><Box sx={{ ml: 2, mt: 0.5, display: 'flex', flexDirection: 'column', gap: 0.5 }}>{section.examples.map((example, idx) => (
                          <Box key={example.expr} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}><Box sx={{ 
                              bgcolor: 'action.hover', 
                              px: 0.75, 
                              py: 0.25, 
                              borderRadius: 0.5,
                              border: 1,
                              borderColor: 'divider',
                              flex: 1,
                            }}><FilterExpressionHighlight expression={example.expr} 
                                fontSize="0.85rem"
                                wrap={true} /></Box><Tooltip title={i18nText("ui:m_2735936eb7e4043ab1c6")}><IconButton data-learn={i18nText("ui:m_bd978a103fddeba95e1f")}
                                size="small"
                                onClick={() => handleInsertExample(example.expr)}
                                sx={{ p: 0.25 }}><ContentCopyIcon fontSize="small" /></IconButton></Tooltip><Typography variant="caption" color="text.secondary" sx={{ flex: 2 }}>{example.desc}</Typography></Box>
                        ))}</Box></Box>
                  ))}<Box sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}><Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                      {i18nRichText("ui:m_c7bfd06638a8584c5ecb", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}
                    </Typography><Typography variant="caption" color="text.secondary" display="block">
                      {i18nRichText("ui:m_7e7b6fb74fd485652d05", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}
                    </Typography></Box></Box></Paper></Collapse></Box>{streamError ? (
            <Box p={3}><Typography color="error" variant="h6" gutterBottom>
                {i18nText("ui:m_7230ad509765abc55b6d")}
              </Typography><Typography color="text.secondary" paragraph>{i18nRenderText(streamError)}</Typography>{messageSource(streamError).includes('incomplete') && (
                <Box mt={2}><Typography variant="body2" color="text.secondary" paragraph>
                    {i18nText("ui:m_00b19e66f19f1d252fb6")}
                  </Typography><Button variant="outlined" 
                    onClick={() => handleViewRecords(selectedType!, activeFilter)}
                    sx={{ mt: 1 }}>
                    {i18nText("ui:m_3c4b66117cf7e2a0bf82")}
                  </Button></Box>
              )}</Box>
          ) : loading && records.length === 0 && total === 0 ? (
            <Box display="flex" justifyContent="center" p={3}><CircularProgress /></Box>
          ) : records.length > 0 ? (
            <Box><Box sx={{ mb: 1 }}><Typography variant="body2">
                  {i18nRichText("ui:m_7391de27d333529940ce", { arg0: records.length, arg1: total > 0 ? total : records.length, arg2: scanned > 0 && i18nText("ui:m_9bff7685c04f40a15f28", { arg0: scanned }) })}
                </Typography></Box><Box sx={{
                  maxHeight: '60vh',
                  overflow: 'auto',
                }}>{records.map((record, idx) => (
                  <Paper key={`record-${idx}-${JSON.stringify(record).substring(0, 100)}`} 
                    elevation={2}
                    sx={{ 
                      p: 2, 
                      mb: 1.5, 
                      bgcolor: viewMode === 'json' ? 'background.default' : 'action.hover',
                      borderRadius: 2,
                      border: 1,
                      borderColor: 'divider',
                      '&:hover': {
                        boxShadow: 4,
                        borderColor: 'primary.main'
                      }
                    }}>{viewMode === 'json' ? (
                      <pre style={{
                          margin: 0,
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                        }}
                        dangerouslySetInnerHTML={{
                          __html: syntaxHighlightJSON(JSON.stringify(convertTimestamps(record), null, 2))
                        }} />
                    ) : (
                      <RecordUI data={convertTimestamps(record)} />
                    )}</Paper>
                ))}</Box></Box>
          ) : !loading && total === 0 && activeFilter ? (
            <Box p={3} textAlign="center"><Typography variant="h6" color="text.secondary" gutterBottom>
                {i18nText("ui:m_59e6eb72ba3595691ace")}
              </Typography><Typography variant="body2" color="text.secondary" paragraph>
                {i18nText("ui:m_35cf8faba86eec0db80d")}
              </Typography><Box sx={{ display: 'flex', gap: 1, justifyContent: 'center', mt: 2 }}><Button data-learn={i18nText("ui:m_a308e786a57a55f5588e")}
                  variant="outlined"
                  onClick={handleClearFilter}
                  startIcon={<ClearIcon />}>
                  {i18nText("ui:m_cfdaafce54dddd3e0005")}
                </Button><Button data-learn={i18nText("ui:m_a3f28c753e28a4075760")}
                  variant="text"
                  onClick={() => setShowFilterHelp(true)}
                  startIcon={<HelpOutlineIcon />}>
                  {i18nText("ui:m_a7828b58a07c43cf46bb")}
                </Button></Box></Box>
          ) : (
            <Box p={3} textAlign="center"><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_fe0c3f514943e70a52ce")}
              </Typography></Box>
          )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_c1416f6fbf52c9dc91a9")} onClick={handleClose}>{i18nText("ui:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog></Layout>
  );
}

// Helper function to assign colors to layers
function getLayerColor(layerName: string, mode: AppearanceMode): string {
  const c = appearanceTokens(mode);
  const colorMap: Record<string, string> = {
    'Link Layer': c.primary,
    'Network Layer': c.secondary,
    'Transport Layer': c.info,
    'Application Layer': c.secondary,
    'Stream Decoders': c.success,
    'Abstract Decoders': c.warning,
    'Other': c.muted,
  };
  return colorMap[layerName] || c.muted;
}
