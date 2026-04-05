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

import { useState, useMemo, useEffect, useCallback } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControl from '@mui/material/FormControl';
import IconButton from '@mui/material/IconButton';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import Select, { type SelectChangeEvent } from '@mui/material/Select';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TablePagination from '@mui/material/TablePagination';
import TableRow from '@mui/material/TableRow';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import Card from '@mui/material/Card';
import CardMedia from '@mui/material/CardMedia';
import CardContent from '@mui/material/CardContent';
import CardActions from '@mui/material/CardActions';
import Grid from '@mui/material/Grid';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import LinearProgress from '@mui/material/LinearProgress';
import Pagination from '@mui/material/Pagination';
import RefreshIcon from '@mui/icons-material/Refresh';
import DownloadIcon from '@mui/icons-material/Download';
import DownloadForOfflineIcon from '@mui/icons-material/DownloadForOffline';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CloseIcon from '@mui/icons-material/Close';
import CodeIcon from '@mui/icons-material/Code';
import KeyboardArrowUpIcon from '@mui/icons-material/KeyboardArrowUp';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import NavigateBeforeIcon from '@mui/icons-material/NavigateBefore';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import GridOnIcon from '@mui/icons-material/GridOn';
import ViewHeadlineIcon from '@mui/icons-material/ViewHeadline';
import ImageIcon from '@mui/icons-material/Image';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import AudiotrackIcon from '@mui/icons-material/Audiotrack';
import VideocamIcon from '@mui/icons-material/Videocam';
import ViewListIcon from '@mui/icons-material/ViewList';
import ViewModuleIcon from '@mui/icons-material/ViewModule';
import Layout from '../components/Layout';
import FileSelectorHeader from '../components/FileSelectorHeader';
import { formatBytes, formatTimestamp, type ExtractedFileInfo } from '../lib/api';
import { useNetcapApi, useTableKeyboardNavigation } from '../hooks';
import useSWR, { mutate as globalMutate } from 'swr';
import OptimizedPieChart from '../components/OptimizedPieChart';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { tomorrow } from 'react-syntax-highlighter/dist/esm/styles/prism';

export default function ExtractedFilesPage() {
  const api = useNetcapApi();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [mimeTypeFilter, setMimeTypeFilter] = useState<string>('');
  const [protocolFilter, setProtocolFilter] = useState<string>('');
  const [switchingFile, setSwitchingFile] = useState(false);
  const [previewFile, setPreviewFile] = useState<ExtractedFileInfo | null>(null);
  const [previewContent, setPreviewContent] = useState<string>('');
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string>('');
  const [previewTab, setPreviewTab] = useState<'rendered' | 'source' | 'raw'>('rendered');
  const [viewMode, setViewMode] = useState<'table' | 'gallery'>('table');
  const [galleryPage, setGalleryPage] = useState(0);
  const [galleryRowsPerPage, setGalleryRowsPerPage] = useState(50);
  const [selectedFileKey, setSelectedFileKey] = useState<string | null>(null);
  
  // Binary file hex dump state
  const [binaryContent, setBinaryContent] = useState<string>('');
  const [binaryOffset, setBinaryOffset] = useState(0);
  const [binaryTotalSize, setBinaryTotalSize] = useState(0);
  const [binaryHasMore, setBinaryHasMore] = useState(false);
  const [binaryLoading, setBinaryLoading] = useState(false);
  const [hexViewMode, setHexViewMode] = useState<'ascii' | 'hex'>('hex');

  // Helper functions - declared early to avoid temporal dead zone issues
  // Helper function to determine if file is an image
  const isImageFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return mimeType.startsWith('image/');
  };

  // Helper function to determine if file is a video
  const isVideoFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return mimeType.startsWith('video/');
  };

  // Helper function to determine if file is audio
  const isAudioFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return mimeType.startsWith('audio/');
  };

  // Helper function to truncate file names exceeding 50 characters
  const truncateFileName = (name: string, maxLength: number = 50): string => {
    if (!name || name.length <= maxLength) return name;
    const extension = name.lastIndexOf('.') > 0 ? name.slice(name.lastIndexOf('.')) : '';
    const baseName = extension ? name.slice(0, name.lastIndexOf('.')) : name;
    const truncateLength = maxLength - extension.length - 3; // 3 for '...'
    if (truncateLength <= 0) return name.slice(0, maxLength - 3) + '...';
    return baseName.slice(0, truncateLength) + '...' + extension;
  };

  // Helper function to determine if file is a PDF
  const isPDFFile = (mimeType: string): boolean => {
    if (!mimeType) return false;
    return mimeType === 'application/pdf';
  };

  // Helper function to determine if file is a binary (non-text, non-media) file
  const isBinaryFile = (mimeType: string): boolean => {
    if (!mimeType) return true; // Default to binary for unknown types
    return !isTextFile(mimeType) &&
           !isImageFile(mimeType) &&
           !isPDFFile(mimeType) &&
           !isVideoFile(mimeType) &&
           !isAudioFile(mimeType);
  };

  // Hex dump helper functions
  const BINARY_CHUNK_SIZE = 16 * 1024; // 16KB chunks

  // Convert byte to hex string
  const byteToHex = (byte: number): string => {
    return byte.toString(16).padStart(2, '0');
  };

  // Convert byte to ASCII character (or dot for non-printable)
  const byteToAscii = (byte: number): string => {
    if (byte === 10 || byte === 13) return '.'; // Show dots for \n and \r in hex view
    return byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
  };

  // Generate hex dump rows from hex-encoded data
  interface HexRow {
    offset: number;
    hexBytes: string[];
    asciiChars: string[];
  }

  const generateHexRows = useCallback((hexData: string, baseOffset: number): HexRow[] => {
    const rows: HexRow[] = [];
    // Convert hex string to bytes
    const bytes: number[] = [];
    for (let i = 0; i < hexData.length; i += 2) {
      bytes.push(parseInt(hexData.substring(i, i + 2), 16));
    }

    for (let i = 0; i < bytes.length; i += 16) {
      const hexBytes: string[] = [];
      const asciiChars: string[] = [];

      for (let j = 0; j < 16; j++) {
        if (i + j < bytes.length) {
          hexBytes.push(byteToHex(bytes[i + j]));
          asciiChars.push(byteToAscii(bytes[i + j]));
        } else {
          hexBytes.push('  ');
          asciiChars.push(' ');
        }
      }

      rows.push({
        offset: baseOffset + i,
        hexBytes,
        asciiChars,
      });
    }

    return rows;
  }, []);

  // Calculate pagination for binary view
  const binaryTotalPages = useMemo(() => {
    if (binaryTotalSize === 0) return 1;
    return Math.ceil(binaryTotalSize / BINARY_CHUNK_SIZE);
  }, [binaryTotalSize]);

  const binaryCurrentPage = useMemo(() => {
    return Math.floor(binaryOffset / BINARY_CHUNK_SIZE) + 1;
  }, [binaryOffset]);

  // Generate hex rows from current binary content
  const hexRows = useMemo(() => {
    if (!binaryContent) return [];
    return generateHexRows(binaryContent, binaryOffset);
  }, [binaryContent, binaryOffset, generateHexRows]);

  // Load binary file content
  const loadBinaryContent = useCallback(async (filePath: string, offset: number = 0) => {
    setBinaryLoading(true);
    try {
      const data = await api.getExtractedFileContent(filePath, offset, BINARY_CHUNK_SIZE);
      setBinaryContent(data.data);
      setBinaryOffset(data.offset);
      setBinaryTotalSize(data.totalSize);
      setBinaryHasMore(data.hasMore);
    } catch (err) {
      console.error('Failed to load binary content:', err);
      setPreviewError(err instanceof Error ? err.message : 'Failed to load binary content');
    } finally {
      setBinaryLoading(false);
    }
  }, [api]);

  // Binary pagination handlers
  const handleBinaryNext = useCallback(() => {
    if (previewFile && binaryHasMore) {
      const newOffset = binaryOffset + BINARY_CHUNK_SIZE;
      loadBinaryContent(previewFile.path, newOffset);
    }
  }, [previewFile, binaryHasMore, binaryOffset, loadBinaryContent]);

  const handleBinaryPrevious = useCallback(() => {
    if (previewFile && binaryOffset > 0) {
      const newOffset = Math.max(0, binaryOffset - BINARY_CHUNK_SIZE);
      loadBinaryContent(previewFile.path, newOffset);
    }
  }, [previewFile, binaryOffset, loadBinaryContent]);

  const handleBinaryPageChange = useCallback((_event: React.ChangeEvent<unknown>, page: number) => {
    if (previewFile) {
      const newOffset = (page - 1) * BINARY_CHUNK_SIZE;
      loadBinaryContent(previewFile.path, newOffset);
    }
  }, [previewFile, loadBinaryContent]);

  // Fetch status and input files for capture selector
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());

  // Compute selected file from status and inputFiles
  const selectedFile = useMemo(() => {
    if (!status?.outputDir || !inputFiles) return null;
    return inputFiles.find(f => f.path === status.outputDir) || null;
  }, [status?.outputDir, inputFiles]);

  // Fetch extracted files
  const { data: extractedFilesData, error, mutate } = useSWR(
    'extractedFiles',
    () => api.getExtractedFiles(),
    {
      // Disable auto-refresh to prevent table from reordering while user is viewing
      refreshInterval: 0,
    }
  );

  // Extract files data and deduplicate by hash
  const allFiles = extractedFilesData?.files || [];
  const totalCount = extractedFilesData?.totalCount || 0;

  // Deduplicate files by hash - keep first occurrence of each unique hash
  const files = useMemo(() => {
    const uniqueFiles: ExtractedFileInfo[] = [];
    const seenHashes = new Set<string>();
    
    for (const file of allFiles) {
      // If file has no hash or hash hasn't been seen, include it
      if (!file.hash || !seenHashes.has(file.hash)) {
        uniqueFiles.push(file);
        if (file.hash) {
          seenHashes.add(file.hash);
        }
      }
    }
    
    return uniqueFiles;
  }, [allFiles]);

  // Get unique MIME types for filter
  const mimeTypes = Array.from(new Set(files.map(f => f.mimeType).filter(Boolean)));

  // Get unique protocols for filter
  const protocols = Array.from(new Set(files.map(f => f.protocol).filter(Boolean)));

  // Calculate MIME type distribution for pie chart
  const mimeTypeDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    files.forEach(file => {
      const mimeType = file.mimeType || 'unknown';
      counts[mimeType] = (counts[mimeType] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [files]);

  // Calculate protocol distribution for pie chart
  const protocolDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    files.forEach(file => {
      const protocol = file.protocol || 'unknown';
      counts[protocol] = (counts[protocol] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [files]);

  // ECharts pie chart option for MIME types
  const mimeTypePieChartOption = useMemo(() => ({
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      right: 10,
      top: 'center',
      type: 'scroll',
      textStyle: {
        fontSize: 11
      }
    },
    series: [
      {
        name: 'MIME Types',
        type: 'pie',
        radius: ['40%', '70%'],
        avoidLabelOverlap: true,
        itemStyle: {
          borderRadius: 8,
          borderColor: '#fff',
          borderWidth: 2
        },
        label: {
          show: false,
          position: 'center'
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold'
          }
        },
        labelLine: {
          show: false
        },
        data: mimeTypeDistribution
      }
    ]
  }), [mimeTypeDistribution]);

  // ECharts pie chart option for protocols
  const protocolPieChartOption = useMemo(() => ({
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      right: 10,
      top: 'center',
      type: 'scroll',
      textStyle: {
        fontSize: 11
      }
    },
    series: [
      {
        name: 'Protocols',
        type: 'pie',
        radius: ['40%', '70%'],
        avoidLabelOverlap: true,
        itemStyle: {
          borderRadius: 8,
          borderColor: '#fff',
          borderWidth: 2
        },
        label: {
          show: false,
          position: 'center'
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold'
          }
        },
        labelLine: {
          show: false
        },
        data: protocolDistribution
      }
    ]
  }), [protocolDistribution]);

  // Handler for MIME type chart click
  const handleMimeTypeChartClick = useCallback((params: { name: string }) => {
    // Toggle filter: if already filtered by this type, clear the filter
    if (mimeTypeFilter === params.name) {
      setMimeTypeFilter('');
    } else {
      setMimeTypeFilter(params.name === 'unknown' ? '' : params.name);
    }
    setPage(0);
  }, [mimeTypeFilter]);

  // Handler for protocol chart click
  const handleProtocolChartClick = useCallback((params: { name: string }) => {
    // Toggle filter: if already filtered by this protocol, clear the filter
    if (protocolFilter === params.name) {
      setProtocolFilter('');
    } else {
      setProtocolFilter(params.name === 'unknown' ? '' : params.name);
    }
    setPage(0);
  }, [protocolFilter]);

  // Apply MIME type and protocol filters
  const filteredFiles = files.filter(f => {
    if (mimeTypeFilter && f.mimeType !== mimeTypeFilter) return false;
    if (protocolFilter && f.protocol !== protocolFilter) return false;
    return true;
  });

  // Filter image files for gallery view
  const imageFiles = files.filter(f => isImageFile(f.mimeType));
  const filteredImageFiles = imageFiles.filter(f => {
    if (mimeTypeFilter && f.mimeType !== mimeTypeFilter) return false;
    if (protocolFilter && f.protocol !== protocolFilter) return false;
    return true;
  });

  // Sort images in gallery mode - prioritize common image formats (jpg, png, tiff, webp)
  const sortedGalleryImages = useMemo(() => {
    const priorityImageTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/tiff', 'image/webp'];
    
    return [...filteredImageFiles].sort((a, b) => {
      const aPriority = priorityImageTypes.includes(a.mimeType || '');
      const bPriority = priorityImageTypes.includes(b.mimeType || '');
      
      // Sort priority images first
      if (aPriority && !bPriority) return -1;
      if (!aPriority && bPriority) return 1;
      
      // Within same priority level, maintain original order
      return 0;
    });
  }, [filteredImageFiles]);

  // Paginate files (table view)
  const paginatedFiles = filteredFiles.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Paginate image files (gallery view)
  const paginatedImageFiles = sortedGalleryImages.slice(
    galleryPage * galleryRowsPerPage,
    galleryPage * galleryRowsPerPage + galleryRowsPerPage
  );

  // Generate row keys for keyboard navigation (table view)
  const rowKeys = useMemo(() => 
    paginatedFiles.map((file) => file.path),
    [paginatedFiles]
  );

  // Generate row keys for gallery view
  const galleryRowKeys = useMemo(() => 
    paginatedImageFiles.map((file) => file.path),
    [paginatedImageFiles]
  );

  // Use appropriate row keys based on view mode
  const currentRowKeys = viewMode === 'gallery' ? galleryRowKeys : rowKeys;

  // Enable keyboard navigation for file selection (UP/DOWN arrows)
  useTableKeyboardNavigation(selectedFileKey, currentRowKeys, setSelectedFileKey);

  // Helper function to determine if file is text-based - defined here before handlePreviewFile
  const isTextFile = useCallback((mimeType: string): boolean => {
    if (!mimeType) return false;
    return (
      mimeType.startsWith('text/') ||
      mimeType.includes('json') ||
      mimeType.includes('xml') ||
      mimeType.includes('javascript') ||
      mimeType.includes('css') ||
      mimeType.includes('html') ||
      mimeType.includes('svg+xml')
    );
  }, []);

  // Helper function to get file extension from filename
  const getFileExtension = useCallback((filename: string): string => {
    if (!filename) return '';
    const lastDot = filename.lastIndexOf('.');
    if (lastDot === -1 || lastDot === filename.length - 1) return '';
    return filename.slice(lastDot + 1).toLowerCase();
  }, []);

  // Helper function to get syntax highlighting language from MIME type and/or filename
  const getSyntaxLanguage = useCallback((mimeType: string, filename?: string): string | null => {
    // First try to detect from MIME type
    if (mimeType) {
      if (mimeType.includes('json')) return 'json';
      if (mimeType.includes('javascript') || mimeType.includes('ecmascript')) return 'javascript';
      if (mimeType === 'text/html' || mimeType.includes('/html')) return 'html';
      if (mimeType.includes('xml') || mimeType.includes('svg')) return 'xml';
      if (mimeType.includes('css')) return 'css';
      if (mimeType.includes('typescript')) return 'typescript';
      if (mimeType.includes('python')) return 'python';
      if (mimeType.includes('yaml') || mimeType.includes('yml')) return 'yaml';
      if (mimeType.includes('markdown')) return 'markdown';
      if (mimeType.includes('sql')) return 'sql';
      if (mimeType.includes('shell') || mimeType.includes('bash')) return 'bash';
    }
    
    // Fall back to file extension detection
    if (filename) {
      const ext = getFileExtension(filename);
      switch (ext) {
        case 'json': return 'json';
        case 'js': case 'mjs': case 'cjs': return 'javascript';
        case 'jsx': return 'jsx';
        case 'ts': case 'mts': case 'cts': return 'typescript';
        case 'tsx': return 'tsx';
        case 'html': case 'htm': case 'xhtml': return 'html';
        case 'xml': case 'xsl': case 'xslt': case 'svg': return 'xml';
        case 'css': return 'css';
        case 'scss': return 'scss';
        case 'less': return 'less';
        case 'py': case 'pyw': return 'python';
        case 'yaml': case 'yml': return 'yaml';
        case 'md': case 'markdown': return 'markdown';
        case 'sql': return 'sql';
        case 'sh': case 'bash': case 'zsh': return 'bash';
        case 'go': return 'go';
        case 'rs': return 'rust';
        case 'java': return 'java';
        case 'c': case 'h': return 'c';
        case 'cpp': case 'cc': case 'cxx': case 'hpp': return 'cpp';
        case 'php': return 'php';
        case 'rb': return 'ruby';
        case 'swift': return 'swift';
        case 'kt': case 'kts': return 'kotlin';
        case 'lua': return 'lua';
        case 'pl': case 'pm': return 'perl';
        case 'r': return 'r';
        case 'toml': return 'toml';
        case 'ini': case 'cfg': case 'conf': return 'ini';
        case 'dockerfile': return 'dockerfile';
        case 'makefile': return 'makefile';
        default: return null;
      }
    }
    
    return null;
  }, [getFileExtension]);

  // Helper function to format content (e.g., prettify JSON)
  // Simple HTML formatter
  const formatHtml = useCallback((html: string): string => {
    let formatted = '';
    let indent = 0;
    const indentStr = '  ';
    
    // Split by tags while preserving them
    const tokens = html.split(/(<[^>]+>)/g).filter(t => t.trim());
    
    for (const token of tokens) {
      if (token.startsWith('</')) {
        // Closing tag - decrease indent first
        indent = Math.max(0, indent - 1);
        formatted += indentStr.repeat(indent) + token.trim() + '\n';
      } else if (token.startsWith('<') && !token.startsWith('<!') && !token.endsWith('/>') && !token.match(/^<(img|br|hr|input|meta|link|area|base|col|embed|param|source|track|wbr)/i)) {
        // Opening tag (not self-closing, not void element)
        formatted += indentStr.repeat(indent) + token.trim() + '\n';
        indent++;
      } else if (token.startsWith('<')) {
        // Self-closing, comment, doctype, or void elements
        formatted += indentStr.repeat(indent) + token.trim() + '\n';
      } else {
        // Text content
        const trimmed = token.trim();
        if (trimmed) {
          formatted += indentStr.repeat(indent) + trimmed + '\n';
        }
      }
    }
    
    return formatted.trim();
  }, []);
  
  // Simple JavaScript formatter
  const formatJavaScript = useCallback((js: string): string => {
    let formatted = '';
    let indent = 0;
    const indentStr = '  ';
    let inString = false;
    let stringChar = '';
    let prevChar = '';
    let currentLine = '';
    
    for (let i = 0; i < js.length; i++) {
      const char = js[i];
      
      // Track string state
      if ((char === '"' || char === "'" || char === '`') && prevChar !== '\\') {
        if (!inString) {
          inString = true;
          stringChar = char;
        } else if (char === stringChar) {
          inString = false;
        }
      }
      
      if (inString) {
        currentLine += char;
        prevChar = char;
        continue;
      }
      
      if (char === '{' || char === '[') {
        currentLine += char;
        formatted += currentLine.trim() + '\n';
        currentLine = '';
        indent++;
        formatted += indentStr.repeat(indent);
      } else if (char === '}' || char === ']') {
        if (currentLine.trim()) {
          formatted += currentLine.trim() + '\n';
          currentLine = '';
        }
        indent = Math.max(0, indent - 1);
        formatted += indentStr.repeat(indent) + char;
        currentLine = '';
      } else if (char === ';') {
        currentLine += char;
        formatted += currentLine.trim() + '\n' + indentStr.repeat(indent);
        currentLine = '';
      } else if (char === '\n' || char === '\r') {
        if (currentLine.trim()) {
          formatted += currentLine.trim() + '\n' + indentStr.repeat(indent);
          currentLine = '';
        }
      } else {
        currentLine += char;
      }
      
      prevChar = char;
    }
    
    if (currentLine.trim()) {
      formatted += currentLine.trim();
    }
    
    return formatted.trim();
  }, []);
  
  // Simple CSS formatter
  const formatCss = useCallback((css: string): string => {
    let formatted = '';
    let indent = 0;
    const indentStr = '  ';
    
    // Remove existing whitespace and normalize
    const normalized = css.replace(/\s+/g, ' ').trim();
    
    let i = 0;
    while (i < normalized.length) {
      const char = normalized[i];
      
      if (char === '{') {
        formatted += ' {\n';
        indent++;
        formatted += indentStr.repeat(indent);
      } else if (char === '}') {
        indent = Math.max(0, indent - 1);
        formatted = formatted.trimEnd() + '\n' + indentStr.repeat(indent) + '}\n\n' + indentStr.repeat(indent);
      } else if (char === ';') {
        formatted += ';\n' + indentStr.repeat(indent);
      } else if (char === ':' && indent > 0) {
        formatted += ': ';
        // Skip whitespace after colon
        while (i + 1 < normalized.length && normalized[i + 1] === ' ') i++;
      } else {
        formatted += char;
      }
      
      i++;
    }
    
    return formatted.trim();
  }, []);

  const formatContent = useCallback((content: string, mimeType: string, filename?: string): string => {
    if (!content) return content;
    
    const ext = filename ? getFileExtension(filename) : '';
    
    // Format JSON - check both mime type and extension
    const isJson = mimeType?.includes('json') || ext === 'json';
    if (isJson) {
      try {
        const parsed = JSON.parse(content);
        return JSON.stringify(parsed, null, 2);
      } catch {
        // If parsing fails, return original content
        return content;
      }
    }
    
    // Format HTML
    const isHtml = mimeType === 'text/html' || mimeType?.includes('/html') || ext === 'html' || ext === 'htm' || ext === 'xhtml';
    if (isHtml) {
      try {
        return formatHtml(content);
      } catch {
        return content;
      }
    }
    
    // Format JavaScript
    const isJavaScript = mimeType?.includes('javascript') || mimeType?.includes('ecmascript') || 
                         ['js', 'mjs', 'cjs', 'jsx'].includes(ext);
    if (isJavaScript) {
      try {
        return formatJavaScript(content);
      } catch {
        return content;
      }
    }
    
    // Format TypeScript (similar to JS)
    const isTypeScript = mimeType?.includes('typescript') || ['ts', 'mts', 'cts', 'tsx'].includes(ext);
    if (isTypeScript) {
      try {
        return formatJavaScript(content);
      } catch {
        return content;
      }
    }
    
    // Format CSS
    const isCss = mimeType?.includes('css') || ['css', 'scss', 'less'].includes(ext);
    if (isCss) {
      try {
        return formatCss(content);
      } catch {
        return content;
      }
    }
    
    // Format XML/SVG
    const isXml = mimeType?.includes('xml') || mimeType?.includes('svg') || ['xml', 'svg', 'xsl', 'xslt'].includes(ext);
    if (isXml) {
      try {
        return formatHtml(content); // HTML formatter works for XML too
      } catch {
        return content;
      }
    }
    
    return content;
  }, [getFileExtension, formatHtml, formatJavaScript, formatCss]);

  // Helper function to check if content should use syntax highlighting
  const shouldUseSyntaxHighlighting = useCallback((mimeType: string, filename?: string): boolean => {
    return getSyntaxLanguage(mimeType, filename) !== null;
  }, [getSyntaxLanguage]);

  // Handler to preview file - defined here to be available for keyboard navigation
  const handlePreviewFile = useCallback(async (file: ExtractedFileInfo) => {
    setPreviewFile(file);
    setSelectedFileKey(file.path); // Keep selection in sync with preview
    setPreviewContent('');
    setPreviewError('');
    setPreviewLoading(true);
    // Reset binary content state
    setBinaryContent('');
    setBinaryOffset(0);
    setBinaryTotalSize(0);
    setBinaryHasMore(false);
    // Default to 'raw' view for HTML files for security, 'rendered' for others
    setPreviewTab(file.mimeType === 'text/html' ? 'raw' : 'rendered');

    try {
      const downloadUrl = api.downloadExtractedFile(file.path);
      
      // For text-based files, fetch content as text
      if (isTextFile(file.mimeType)) {
        const response = await fetch(downloadUrl);
        if (!response.ok) throw new Error('Failed to fetch file content');
        const text = await response.text();
        setPreviewContent(text);
      }
      // For binary files (non-text, non-media), load hex dump content
      else if (isBinaryFile(file.mimeType)) {
        await loadBinaryContent(file.path, 0);
      }
      // For media files (image, video, audio, pdf), we'll display them via iframe/embed
    } catch (err) {
      console.error('Failed to load file preview:', err);
      setPreviewError(err instanceof Error ? err.message : 'Failed to load file preview');
    } finally {
      setPreviewLoading(false);
    }
  }, [api, isTextFile, isBinaryFile, loadBinaryContent]);

  // Spacebar to toggle preview for selected file
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger when typing in input fields
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }
      
      // Check for spacebar
      if (e.code === 'Space') {
        e.preventDefault();
        
        // If preview is open, close it
        if (previewFile) {
          setPreviewFile(null);
          return;
        }
        
        // If we have a selected file, open preview
        if (selectedFileKey) {
          // Find the file by path
          const currentFiles = viewMode === 'gallery' ? paginatedImageFiles : paginatedFiles;
          const file = currentFiles.find(f => f.path === selectedFileKey);
          if (file) {
            handlePreviewFile(file);
          }
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [selectedFileKey, paginatedFiles, paginatedImageFiles, viewMode, previewFile, handlePreviewFile]);

  const handleChangePage = (_event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleGalleryChangePage = (_event: unknown, newPage: number) => {
    setGalleryPage(newPage);
  };

  const handleGalleryChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setGalleryRowsPerPage(parseInt(event.target.value, 10));
    setGalleryPage(0);
  };

  const handleRefresh = () => {
    mutate();
  };

  const handleViewModeChange = (_event: React.MouseEvent<HTMLElement>, newMode: 'table' | 'gallery' | null) => {
    if (newMode !== null) {
      setViewMode(newMode);
      // Auto-filter to images when switching to gallery view
      if (newMode === 'gallery' && !mimeTypeFilter) {
        // Keep filter as is - gallery will show all images regardless
      }
    }
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
      alert('Failed to switch to this capture');
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, mutate]);

  const handleDownloadFile = (relativePath: string) => {
    const downloadUrl = api.downloadExtractedFile(relativePath);
    window.open(downloadUrl, '_blank');
  };

  const handleDownloadAll = () => {
    const downloadUrl = api.downloadAllExtractedFiles();
    window.open(downloadUrl, '_blank');
  };

  const handleClosePreview = useCallback(() => {
    setPreviewFile(null);
    setPreviewContent('');
    setPreviewError('');
    setPreviewLoading(false);
    setPreviewTab('rendered');
    // Reset binary state
    setBinaryContent('');
    setBinaryOffset(0);
    setBinaryTotalSize(0);
    setBinaryHasMore(false);
  }, []);

  // Get the current file list based on view mode and filter
  const getCurrentFileList = useCallback(() => {
    if (viewMode === 'gallery') {
      return sortedGalleryImages;
    }
    return filteredFiles;
  }, [viewMode, sortedGalleryImages, filteredFiles]);

  // Navigate to previous file
  const handlePreviousFile = useCallback(() => {
    if (!previewFile) return;
    
    const currentList = getCurrentFileList();
    const currentIndex = currentList.findIndex(f => f.path === previewFile.path);
    
    if (currentIndex > 0) {
      handlePreviewFile(currentList[currentIndex - 1]);
    }
  }, [previewFile, getCurrentFileList, handlePreviewFile]);

  // Navigate to next file
  const handleNextFile = useCallback(() => {
    if (!previewFile) return;
    
    const currentList = getCurrentFileList();
    const currentIndex = currentList.findIndex(f => f.path === previewFile.path);
    
    if (currentIndex >= 0 && currentIndex < currentList.length - 1) {
      handlePreviewFile(currentList[currentIndex + 1]);
    }
  }, [previewFile, getCurrentFileList, handlePreviewFile]);

  // Add keyboard navigation for arrow keys
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Only handle keyboard events when preview dialog is open
      if (!previewFile) return;

      if (event.key === 'ArrowUp') {
        event.preventDefault();
        handlePreviousFile();
      } else if (event.key === 'ArrowDown') {
        event.preventDefault();
        handleNextFile();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        handleClosePreview();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [previewFile, handlePreviousFile, handleNextFile, handleClosePreview]);

  // Get file type category for icon display
  const getFileTypeIcon = (mimeType: string) => {
    if (isTextFile(mimeType)) return <CodeIcon fontSize="small" color="info" />;
    if (isImageFile(mimeType)) return <ImageIcon fontSize="small" color="success" />;
    if (isPDFFile(mimeType)) return <PictureAsPdfIcon fontSize="small" color="error" />;
    if (isVideoFile(mimeType)) return <VideocamIcon fontSize="small" color="secondary" />;
    if (isAudioFile(mimeType)) return <AudiotrackIcon fontSize="small" color="primary" />;
    return <InsertDriveFileIcon fontSize="small" color="action" />;
  };

  // Get only completed files for the selector, sorted alphabetically for consistency
  // Use shared FileSelectorHeader component
  const fileSelector = (
    <FileSelectorHeader
      inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint="Capture Selector: Switch between different analyzed PCAP files to view their extracted files."
    />
  );

  if (error) {
    return (
      <Layout title="Files" headerAction={fileSelector}>
        <Box>
          <Typography color="error">Error loading extracted files: {error.message}</Typography>
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="Files" headerAction={fileSelector}>
      <Box sx={{ minWidth: 0 }}>
        <Box sx={{ 
          display: 'flex', 
          flexDirection: { xs: 'column', md: 'row' },
          justifyContent: 'space-between', 
          alignItems: { xs: 'stretch', md: 'flex-start' }, 
          gap: 2,
          mb: 3 
        }}>
          <Box sx={{ minWidth: 0, flex: 1 }}>
            {selectedFile && (
              <Box sx={{ 
                display: 'flex', 
                gap: { xs: 1, sm: 1.5 }, 
                alignItems: 'center', 
                mt: 1,
                flexWrap: 'wrap'
              }}>
                <Typography variant="body1" fontWeight="medium">
                  {files.length.toLocaleString()} unique file{files.length !== 1 ? 's' : ''}
                </Typography>
                {totalCount !== files.length && (
                  <Chip
                    label={`${totalCount - files.length} duplicate${totalCount - files.length !== 1 ? 's' : ''} hidden`}
                    size="small"
                    color="info"
                    variant="outlined"
                    sx={{ fontSize: '0.75rem' }}
                  />
                )}
                <Typography variant="body2" color="text.secondary" sx={{ display: { xs: 'none', sm: 'block' } }}>
                  for capture:
                </Typography>
                <Chip
                  label={selectedFile.name}
                  size="small"
                  sx={{ 
                    fontFamily: 'monospace', 
                    fontSize: { xs: '0.7rem', sm: '0.8rem' },
                    maxWidth: { xs: '200px', sm: '400px' },
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
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <ToggleButtonGroup
              data-learn="View Mode: Switch between table view (all files with details) and gallery view (images only with thumbnails)."
              value={viewMode}
              exclusive
              onChange={handleViewModeChange}
              size="small"
              aria-label="view mode"
            >
              <ToggleButton value="table" aria-label="table view">
                <Tooltip title="Table View">
                  <ViewListIcon />
                </Tooltip>
              </ToggleButton>
              <ToggleButton value="gallery" aria-label="gallery view">
                <Tooltip title="Image Gallery">
                  <ViewModuleIcon />
                </Tooltip>
              </ToggleButton>
            </ToggleButtonGroup>
            <Button 
              data-learn="Refresh Files: Reload the list of extracted files to see newly discovered files from the capture."
              variant="outlined" 
              startIcon={<RefreshIcon />} 
              onClick={handleRefresh}
              size="small"
              sx={{ display: { xs: 'flex', sm: 'inline-flex' } }}
            >
              Refresh
            </Button>
            <Button 
              data-learn="Download All: Download all extracted files as a single archive (ZIP) for offline analysis."
              variant="contained" 
              startIcon={<DownloadForOfflineIcon />} 
              onClick={handleDownloadAll}
              size="small"
              disabled={totalCount === 0}
              sx={{ display: { xs: 'flex', sm: 'inline-flex' } }}
            >
              Download All
            </Button>
          </Box>
        </Box>

        {/* Distribution Pie Charts - only show if there's more than one category */}
        {totalCount > 0 && (mimeTypeDistribution.length > 1 || protocolDistribution.length > 1) && (
          <Box sx={{ display: 'flex', flexDirection: { xs: 'column', lg: 'row' }, gap: 2, mb: 3 }}>
            {/* MIME Type Distribution - only show if more than one MIME type */}
            {mimeTypeDistribution.length > 1 && (
              <Paper 
                data-learn="MIME Type Distribution: Visual breakdown of extracted file types. Click on a slice to filter the table by that MIME type."
                sx={{ flex: 1, p: 2 }}
              >
                <Typography variant="h6" gutterBottom>
                  MIME Type Distribution
                  {mimeTypeFilter && (
                    <Chip 
                      label={`Filtered: ${mimeTypeFilter}`} 
                      size="small" 
                      color="primary"
                      onDelete={() => { setMimeTypeFilter(''); setPage(0); }}
                      sx={{ ml: 1 }}
                    />
                  )}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                  Click a slice to filter
                </Typography>
                <OptimizedPieChart 
                  option={mimeTypePieChartOption} 
                  style={{ height: '250px', width: '100%' }}
                  onItemClick={handleMimeTypeChartClick}
                />
              </Paper>
            )}

            {/* Protocol Distribution - only show if more than one protocol */}
            {protocolDistribution.length > 1 && (
              <Paper 
                data-learn="Protocol Distribution: Visual breakdown of network protocols used to transfer extracted files. Click on a slice to filter the table by that protocol."
                sx={{ flex: 1, p: 2 }}
              >
                <Typography variant="h6" gutterBottom>
                  Protocol Distribution
                  {protocolFilter && (
                    <Chip 
                      label={`Filtered: ${protocolFilter}`} 
                      size="small" 
                      color="primary"
                      onDelete={() => { setProtocolFilter(''); setPage(0); }}
                      sx={{ ml: 1 }}
                    />
                  )}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                  Click a slice to filter
                </Typography>
                <OptimizedPieChart 
                  option={protocolPieChartOption} 
                  style={{ height: '250px', width: '100%' }}
                  onItemClick={handleProtocolChartClick}
                />
              </Paper>
            )}
          </Box>
        )}

        {/* Filters */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <Select
              data-learn="MIME Type Filter: Filter extracted files by their file type (e.g., images, documents, text files) to quickly find specific content."
              value={mimeTypeFilter}
              onChange={(e) => {
                setMimeTypeFilter(e.target.value);
                setPage(0);
              }}
              displayEmpty
            >
              <MenuItem value="">
                <em>All MIME Types</em>
              </MenuItem>
              {mimeTypes.sort().map((mimeType) => (
                <MenuItem key={mimeType} value={mimeType}>
                  {mimeType}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <Select
              data-learn="Protocol Filter: Filter extracted files by the network protocol they were transferred over (HTTP, FTP, SMB, SMTP, IRC)."
              value={protocolFilter}
              onChange={(e) => {
                setProtocolFilter(e.target.value);
                setPage(0);
              }}
              displayEmpty
            >
              <MenuItem value="">
                <em>All Protocols</em>
              </MenuItem>
              {protocols.sort().map((protocol) => (
                <MenuItem key={protocol} value={protocol}>
                  {protocol}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          {(mimeTypeFilter || protocolFilter) && (
            <Typography variant="body2" color="text.secondary">
              {filteredFiles.length} of {files.length} files
            </Typography>
          )}
        </Box>

        {/* Files Table or Gallery */}
        {!extractedFilesData && !error ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : totalCount === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <InsertDriveFileIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Files
            </Typography>
            <Typography variant="body2" color="text.secondary">
              No files have been extracted from this capture yet.
            </Typography>
          </Paper>
        ) : viewMode === 'gallery' ? (
          <>
            {/* Gallery View */}
            {imageFiles.length === 0 ? (
              <Paper sx={{ p: 4, textAlign: 'center' }}>
                <ImageIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  No Images Found
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  No image files have been extracted from this capture.
                </Typography>
              </Paper>
            ) : (
              <>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  {paginatedImageFiles.map((file) => (
                    <Grid item xs={12} sm={6} md={4} lg={3} xl={2} key={file.path}>
                      <Card 
                        data-row-key={file.path}
                        sx={{ 
                          height: '100%', 
                          display: 'flex', 
                          flexDirection: 'column',
                          cursor: 'pointer',
                          border: selectedFileKey === file.path ? 2 : 0,
                          borderColor: selectedFileKey === file.path ? 'primary.main' : 'transparent',
                          '&:hover': {
                            boxShadow: 6,
                            transform: 'translateY(-2px)',
                            transition: 'all 0.2s ease-in-out',
                          },
                        }}
                        onClick={() => handlePreviewFile(file)}
                      >
                        <CardMedia
                          component="img"
                          height="200"
                          image={api.downloadExtractedFile(file.path)}
                          alt={file.originalName || file.name}
                          sx={{ 
                            objectFit: 'contain', 
                            bgcolor: 'grey.100',
                            p: 1,
                          }}
                        />
                        <CardContent sx={{ flexGrow: 1, pb: 1 }}>
                          <Tooltip title={(file.originalName || file.name).length > 50 ? (file.originalName || file.name) : ''}>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                fontFamily: 'monospace',
                                fontSize: '0.75rem',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                mb: 0.5,
                              }}
                            >
                              {truncateFileName(file.originalName || file.name)}
                            </Typography>
                          </Tooltip>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            <Chip
                              label={file.mimeType || 'unknown'}
                              size="small"
                              variant="outlined"
                              sx={{ fontSize: '0.65rem', height: 20 }}
                            />
                            {file.protocol && (
                              <Chip
                                label={file.protocol}
                                size="small"
                                color="primary"
                                variant="outlined"
                                sx={{ fontSize: '0.65rem', height: 20 }}
                              />
                            )}
                            <Chip
                              label={formatBytes(file.size)}
                              size="small"
                              variant="outlined"
                              sx={{ fontSize: '0.65rem', height: 20 }}
                            />
                          </Box>
                        </CardContent>
                        <CardActions sx={{ pt: 0, px: 2, pb: 1, gap: 0.5 }}>
                          <Tooltip title="Preview">
                            <IconButton
                              size="small"
                              color="secondary"
                              onClick={(e) => {
                                e.stopPropagation();
                                handlePreviewFile(file);
                              }}
                            >
                              <VisibilityIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Download">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDownloadFile(file.path);
                              }}
                            >
                              <DownloadIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </CardActions>
                      </Card>
                    </Grid>
                  ))}
                </Grid>

                <TablePagination
                  component="div"
                  count={sortedGalleryImages.length}
                  page={galleryPage}
                  onPageChange={handleGalleryChangePage}
                  rowsPerPage={galleryRowsPerPage}
                  onRowsPerPageChange={handleGalleryChangeRowsPerPage}
                  rowsPerPageOptions={[25, 50, 100, 200]}
                  labelDisplayedRows={({ from, to, count }) => 
                    `${from}-${to} of ${count} image${count !== 1 ? 's' : ''}`
                  }
                />
              </>
            )}
          </>
        ) : (
          <>
            <TableContainer component={Paper} sx={{ overflowX: 'auto', maxWidth: '100%' }}>
              <Table size="small" sx={{ minWidth: { xs: 700, md: 'auto' } }}>
                <TableHead>
                  <TableRow>
                    <TableCell>File Name</TableCell>
                    <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>MIME Type</TableCell>
                    <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>Protocol</TableCell>
                    <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>Path</TableCell>
                    <TableCell align="right">Size</TableCell>
                    <TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}>Modified</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedFiles.map((file) => (
                    <TableRow 
                      key={file.path}
                      data-row-key={file.path}
                      hover 
                      onClick={() => handlePreviewFile(file)}
                      selected={selectedFileKey === file.path}
                      sx={{ cursor: 'pointer' }}
                    >
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {getFileTypeIcon(file.mimeType)}
                          <Tooltip title={(file.originalName || file.name).length > 50 ? (file.originalName || file.name) : ''}>
                            <Typography 
                              sx={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.85rem',
                                maxWidth: 300,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}
                            >
                              {truncateFileName(file.originalName || file.name)}
                            </Typography>
                          </Tooltip>
                        </Box>
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                        <Chip
                          label={file.mimeType || 'unknown'}
                          size="small"
                          variant="outlined"
                          sx={{ fontSize: '0.75rem' }}
                        />
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                        {file.protocol && (
                          <Chip
                            label={file.protocol}
                            size="small"
                            color="primary"
                            variant="outlined"
                            sx={{ fontSize: '0.75rem' }}
                          />
                        )}
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                        <Typography 
                          variant="body2" 
                          sx={{ 
                            fontFamily: 'monospace', 
                            fontSize: '0.75rem',
                            color: 'text.secondary',
                            maxWidth: 300,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}
                        >
                          {file.path}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Typography variant="body2">
                          {formatBytes(file.size)}
                        </Typography>
                      </TableCell>
                      <TableCell align="right" sx={{ display: { xs: 'none', xl: 'table-cell' } }}>
                        <Typography variant="body2">
                          {formatTimestamp(file.modifiedTime)}
                        </Typography>
                      </TableCell>
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                        <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'flex-end' }}>
                          <Tooltip title="Preview file">
                            <IconButton
                              size="small"
                              color="secondary"
                              onClick={(e) => {
                                e.stopPropagation();
                                handlePreviewFile(file);
                              }}
                            >
                              <VisibilityIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Download file">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDownloadFile(file.path);
                              }}
                            >
                              <DownloadIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              component="div"
              count={filteredFiles.length}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
            />
          </>
        )}

        {/* File Preview Dialog */}
        <Dialog
          open={previewFile !== null}
          onClose={handleClosePreview}
          maxWidth="lg"
          fullWidth
          PaperProps={{
            sx: { height: '90vh' }
          }}
        >
          <DialogTitle>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flex: 1 }}>
                {previewFile && getFileTypeIcon(previewFile.mimeType)}
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Tooltip title={(previewFile?.originalName || previewFile?.name || '').length > 50 ? (previewFile?.originalName || previewFile?.name) : ''}>
                    <Typography variant="h6" sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {truncateFileName(previewFile?.originalName || previewFile?.name || '')}
                    </Typography>
                  </Tooltip>
                  <Box sx={{ display: 'flex', gap: 1.5, mt: 0.5, flexWrap: 'wrap' }}>
                    <Chip label={previewFile?.mimeType || 'unknown'} size="small" variant="outlined" />
                    {previewFile?.protocol && (
                      <Chip label={previewFile.protocol} size="small" color="primary" variant="outlined" />
                    )}
                    <Chip label={formatBytes(previewFile?.size || 0)} size="small" variant="outlined" />
                    {(() => {
                      const currentList = getCurrentFileList();
                      const currentIndex = previewFile ? currentList.findIndex(f => f.path === previewFile.path) : -1;
                      if (currentIndex >= 0) {
                        return (
                          <Chip 
                            label={`${currentIndex + 1} / ${currentList.length}`} 
                            size="small" 
                            color="primary"
                            variant="outlined"
                          />
                        );
                      }
                      return null;
                    })()}
                  </Box>
                </Box>
              </Box>
              <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                <Tooltip title="Previous file (↑)">
                  <span>
                    <IconButton 
                      onClick={handlePreviousFile} 
                      size="small"
                      disabled={(() => {
                        const currentList = getCurrentFileList();
                        const currentIndex = previewFile ? currentList.findIndex(f => f.path === previewFile.path) : -1;
                        return currentIndex <= 0;
                      })()}
                    >
                      <KeyboardArrowUpIcon />
                    </IconButton>
                  </span>
                </Tooltip>
                <Tooltip title="Next file (↓)">
                  <span>
                    <IconButton 
                      onClick={handleNextFile} 
                      size="small"
                      disabled={(() => {
                        const currentList = getCurrentFileList();
                        const currentIndex = previewFile ? currentList.findIndex(f => f.path === previewFile.path) : -1;
                        return currentIndex < 0 || currentIndex >= currentList.length - 1;
                      })()}
                    >
                      <KeyboardArrowDownIcon />
                    </IconButton>
                  </span>
                </Tooltip>
                <IconButton onClick={handleClosePreview} size="small">
                  <CloseIcon />
                </IconButton>
              </Box>
            </Box>
          </DialogTitle>
          <DialogContent dividers sx={{ p: 0, display: 'flex', flexDirection: 'column' }}>
            {previewLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                <CircularProgress />
              </Box>
            ) : previewError ? (
              <Box sx={{ p: 3 }}>
                <Alert severity="error">{previewError}</Alert>
              </Box>
            ) : previewFile ? (
              <>
                {/* Tabs for text files to switch between rendered, source (formatted + highlighted), and raw view */}
                {isTextFile(previewFile.mimeType) && previewContent && (
                  <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
                    <Tabs value={previewTab} onChange={(_, v) => setPreviewTab(v)}>
                      <Tab label="Rendered" value="rendered" />
                      <Tab label="Source" value="source" />
                      <Tab label="Raw" value="raw" />
                    </Tabs>
                  </Box>
                )}

                <Box sx={{ flex: 1, overflow: 'auto', p: isTextFile(previewFile.mimeType) && previewTab === 'raw' ? 0 : 2 }}>
                  {/* Text Files */}
                  {isTextFile(previewFile.mimeType) && previewContent && (
                    <>
                      {previewTab === 'rendered' ? (
                        // Rendered view - HTML gets iframe, code files get syntax highlighting with formatted content
                        (previewFile.mimeType === 'text/html' ? (<>
                          <Alert severity="warning" sx={{ m: 2, mb: 1 }}>
                            <strong>Security Warning:</strong> Viewing untrusted HTML in rendered mode. 
                            JavaScript execution is disabled, but CSS and images will be loaded.
                          </Alert>
                          <iframe
                            srcDoc={previewContent}
                            style={{
                              width: '100%',
                              height: '100%',
                              minHeight: '500px',
                              border: 'none',
                              backgroundColor: 'white'
                            }}
                            sandbox=""
                            title={previewFile.originalName || previewFile.name}
                          />
                        </>) : // Code view with syntax highlighting for supported languages
                        shouldUseSyntaxHighlighting(previewFile.mimeType, previewFile.originalName || previewFile.name) ? (
                          <Box
                            sx={{
                              overflow: 'auto',
                              maxHeight: 'calc(90vh - 200px)',
                              '& pre': {
                                margin: '0 !important',
                                borderRadius: '8px !important',
                              },
                              '& code': {
                                fontSize: '0.875rem !important',
                              }
                            }}
                          >
                            <SyntaxHighlighter
                              language={getSyntaxLanguage(previewFile.mimeType, previewFile.originalName || previewFile.name) || 'text'}
                              style={tomorrow}
                              showLineNumbers
                              wrapLines
                              wrapLongLines
                              customStyle={{
                                margin: 0,
                                borderRadius: '8px',
                                fontSize: '0.875rem',
                              }}
                            >
                              {formatContent(previewContent, previewFile.mimeType, previewFile.originalName || previewFile.name)}
                            </SyntaxHighlighter>
                          </Box>
                        ) : (
                          // Plain text view for other text files
                          <Paper
                            sx={{
                              bgcolor: 'grey.900',
                              p: 2,
                              overflow: 'auto',
                              maxHeight: 'calc(90vh - 200px)'
                            }}
                          >
                            <pre
                              style={{
                                margin: 0,
                                fontFamily: 'monospace',
                                fontSize: '0.875rem',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                                color: '#e0e0e0',
                              }}
                            >
                              {previewContent}
                            </pre>
                          </Paper>
                        ))
                      ) : previewTab === 'source' ? (
                        // Source view - pretty printed and syntax highlighted
                        <Box
                          sx={{
                            overflow: 'auto',
                            maxHeight: 'calc(90vh - 200px)',
                            '& pre': {
                              margin: '0 !important',
                              borderRadius: '8px !important',
                            },
                            '& code': {
                              fontSize: '0.875rem !important',
                            }
                          }}
                        >
                          <SyntaxHighlighter
                            language={getSyntaxLanguage(previewFile.mimeType, previewFile.originalName || previewFile.name) || 'text'}
                            style={tomorrow}
                            showLineNumbers
                            wrapLines
                            wrapLongLines
                            customStyle={{
                              margin: 0,
                              borderRadius: '8px',
                              fontSize: '0.875rem',
                            }}
                          >
                            {formatContent(previewContent, previewFile.mimeType, previewFile.originalName || previewFile.name)}
                          </SyntaxHighlighter>
                        </Box>
                      ) : (
                        // Raw view - shows original content without any formatting or highlighting
                        (<Paper
                          sx={{
                            bgcolor: 'grey.900',
                            p: 2,
                            overflow: 'auto',
                            maxHeight: 'calc(90vh - 250px)'
                          }}
                        >
                          <pre
                            style={{
                              margin: 0,
                              fontFamily: 'monospace',
                              fontSize: '0.875rem',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                              color: '#e0e0e0',
                            }}
                          >
                            {previewContent}
                          </pre>
                        </Paper>)
                      )}
                    </>
                  )}

                  {/* Images */}
                  {isImageFile(previewFile.mimeType) && (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
                      <img
                        src={api.downloadExtractedFile(previewFile.path)}
                        alt={previewFile.originalName || previewFile.name}
                        style={{
                          maxWidth: '100%',
                          maxHeight: 'calc(90vh - 250px)',
                          objectFit: 'contain'
                        }}
                      />
                    </Box>
                  )}

                  {/* PDFs */}
                  {isPDFFile(previewFile.mimeType) && (
                    <iframe
                      src={api.downloadExtractedFile(previewFile.path)}
                      style={{
                        width: '100%',
                        height: 'calc(90vh - 200px)',
                        border: 'none'
                      }}
                      title={previewFile.originalName || previewFile.name}
                    />
                  )}

                  {/* Videos */}
                  {isVideoFile(previewFile.mimeType) && (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
                      <video
                        controls
                        style={{
                          maxWidth: '100%',
                          maxHeight: 'calc(90vh - 250px)',
                        }}
                      >
                        <source src={api.downloadExtractedFile(previewFile.path)} type={previewFile.mimeType} />
                        Your browser does not support the video tag.
                      </video>
                    </Box>
                  )}

                  {/* Audio */}
                  {isAudioFile(previewFile.mimeType) && (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 200, flexDirection: 'column', gap: 2 }}>
                      <AudiotrackIcon sx={{ fontSize: 80, color: 'primary.main' }} />
                      <audio
                        controls
                        style={{ width: '100%', maxWidth: 500 }}
                      >
                        <source src={api.downloadExtractedFile(previewFile.path)} type={previewFile.mimeType} />
                        Your browser does not support the audio tag.
                      </audio>
                    </Box>
                  )}

                  {/* Binary file hex dump view */}
                  {isBinaryFile(previewFile.mimeType) && (
                    <Box sx={{ height: '100%', overflow: 'auto' }}>
                      {binaryLoading && <LinearProgress />}
                      
                      {/* Legend and controls */}
                      <Box
                        sx={{
                          position: 'sticky',
                          top: 0,
                          bgcolor: 'background.paper',
                          borderBottom: 1,
                          borderColor: 'divider',
                          p: 1,
                          display: 'flex',
                          gap: 3,
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          zIndex: 1,
                        }}
                      >
                        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                          <Typography variant="caption" color="text.secondary">
                            Binary File • {formatBytes(binaryTotalSize)}
                          </Typography>
                          
                          {/* View Mode Toggle */}
                          <IconButton
                            size="small"
                            onClick={() => setHexViewMode(hexViewMode === 'ascii' ? 'hex' : 'ascii')}
                            title={hexViewMode === 'ascii' ? 'Switch to Hex View' : 'Switch to ASCII View'}
                          >
                            {hexViewMode === 'ascii' ? <GridOnIcon fontSize="small" /> : <ViewHeadlineIcon fontSize="small" />}
                          </IconButton>
                        </Box>
                        
                        {/* Pagination Controls */}
                        {binaryTotalPages > 1 && (
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <IconButton
                              size="small"
                              onClick={handleBinaryPrevious}
                              disabled={binaryOffset === 0 || binaryLoading}
                            >
                              <NavigateBeforeIcon />
                            </IconButton>
                            <Typography variant="caption">
                              {binaryCurrentPage} / {binaryTotalPages}
                            </Typography>
                            <IconButton
                              size="small"
                              onClick={handleBinaryNext}
                              disabled={!binaryHasMore || binaryLoading}
                            >
                              <NavigateNextIcon />
                            </IconButton>
                          </Box>
                        )}
                      </Box>

                      {/* ASCII view */}
                      {hexViewMode === 'ascii' && (
                        <Box
                          sx={{
                            fontFamily: 'Courier New, monospace',
                            fontSize: '13px',
                            lineHeight: 1.6,
                            p: 2,
                            bgcolor: '#1e1e1e',
                            color: '#d4d4d4',
                            whiteSpace: 'pre',
                            overflowX: 'auto',
                            minHeight: 400,
                          }}
                        >
                          {hexRows.map((row) => (
                            <Box key={row.offset} component="span">
                              {row.asciiChars.join('')}
                            </Box>
                          ))}

                          {hexRows.length === 0 && !binaryLoading && (
                            <Typography variant="body2" color="text.secondary" align="center">
                              No data available
                            </Typography>
                          )}
                        </Box>
                      )}

                      {/* Hex dump view */}
                      {hexViewMode === 'hex' && (
                        <Box
                          sx={{
                            fontFamily: 'Courier New, monospace',
                            fontSize: '13px',
                            lineHeight: 1.4,
                            p: 2,
                            bgcolor: '#1e1e1e',
                            color: '#d4d4d4',
                            minHeight: 400,
                          }}
                        >
                          {hexRows.map((row) => (
                            <Box
                              key={row.offset}
                              sx={{
                                display: 'flex',
                                gap: 2,
                                py: 0.25,
                                px: 1,
                                '&:hover': {
                                  bgcolor: 'rgba(255, 255, 255, 0.05)',
                                },
                              }}
                            >
                              {/* Offset */}
                              <Box sx={{ color: '#858585', minWidth: '60px' }}>
                                {row.offset.toString(16).padStart(8, '0')}
                              </Box>

                              {/* Hex bytes (split into two groups of 8) */}
                              <Box sx={{ display: 'flex', gap: 2, minWidth: '400px' }}>
                                <Box sx={{ display: 'flex', gap: 0.5 }}>
                                  {row.hexBytes.slice(0, 8).map((hex, i) => (
                                    <Box key={i} sx={{ minWidth: '20px' }}>
                                      {hex}
                                    </Box>
                                  ))}
                                </Box>
                                <Box sx={{ display: 'flex', gap: 0.5 }}>
                                  {row.hexBytes.slice(8, 16).map((hex, i) => (
                                    <Box key={i} sx={{ minWidth: '20px' }}>
                                      {hex}
                                    </Box>
                                  ))}
                                </Box>
                              </Box>

                              {/* ASCII representation */}
                              <Box sx={{ color: '#82b1ff' }}>
                                {row.asciiChars.join('')}
                              </Box>
                            </Box>
                          ))}

                          {hexRows.length === 0 && !binaryLoading && (
                            <Typography variant="body2" color="text.secondary" align="center">
                              No data available
                            </Typography>
                          )}
                        </Box>
                      )}

                      {/* Page selector at bottom */}
                      {binaryTotalPages > 1 && (
                        <Box sx={{ display: 'flex', justifyContent: 'center', p: 2, borderTop: 1, borderColor: 'divider' }}>
                          <Pagination
                            count={binaryTotalPages}
                            page={binaryCurrentPage}
                            onChange={handleBinaryPageChange}
                            disabled={binaryLoading}
                            size="small"
                            showFirstButton
                            showLastButton
                          />
                        </Box>
                      )}
                    </Box>
                  )}
                </Box>
              </>
            ) : null}
          </DialogContent>
          <DialogActions>
            <Button data-learn="Close Dialog: Close the file preview viewer." onClick={handleClosePreview}>Close</Button>
            {previewFile && (
              <Button
                variant="contained"
                startIcon={<DownloadIcon />}
                onClick={() => handleDownloadFile(previewFile.path)}
              >
                Download
              </Button>
            )}
          </DialogActions>
        </Dialog>
      </Box>
    </Layout>
  );
}
