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

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useIsMobile } from '../hooks';
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Typography,
  Alert,
  CircularProgress,
  IconButton,
  Pagination,
  LinearProgress,
} from '@mui/material';
import {
  Close as CloseIcon,
  NavigateBefore as NavigateBeforeIcon,
  NavigateNext as NavigateNextIcon,
  ViewHeadline as ViewHeadlineIcon,
  GridOn as GridOnIcon,
  KeyboardArrowUp as KeyboardArrowUpIcon,
  KeyboardArrowDown as KeyboardArrowDownIcon,
} from '@mui/icons-material';
import { api, ConversationData } from '../lib/api';

interface ConversationModalProps {
  open: boolean;
  onClose: () => void;
  srcIP: string;
  srcPort: string;
  dstIP: string;
  dstPort: string;
  protocol: string;
  // Navigation callbacks for switching between connections
  onNavigatePrevious?: () => void;
  onNavigateNext?: () => void;
  hasPrevious?: boolean;
  hasNext?: boolean;
}

interface ParsedSegment {
  data: Uint8Array;
  isClient: boolean;
}

// ANSI color codes (mgutz/ansi uses extended format)
const ANSI_RED = '\x1b[0;31m';
const ANSI_BLUE = '\x1b[0;34m';
const ANSI_RESET = '\x1b[0m';

// Chunk size for pagination (16KB for faster initial load and reduced memory usage)
const CHUNK_SIZE = 16 * 1024;

// Parse ANSI-encoded conversation data into segments
function parseConversationData(base64Data: string): ParsedSegment[] {
  // Decode base64 to binary
  const binaryString = atob(base64Data);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  // Convert to string to parse ANSI codes
  const text = new TextDecoder('latin1').decode(bytes);
  
  const segments: ParsedSegment[] = [];
  let currentColor = '';
  let currentData: number[] = [];

  let i = 0;
  while (i < text.length) {
    // Check for ANSI escape sequence
    if (text.substring(i, i + 7) === ANSI_RED) {
      // Save previous segment if any
      if (currentData.length > 0) {
        segments.push({
          data: new Uint8Array(currentData),
          isClient: currentColor === 'red',
        });
        currentData = [];
      }
      currentColor = 'red';
      i += 7;
    } else if (text.substring(i, i + 7) === ANSI_BLUE) {
      // Save previous segment if any
      if (currentData.length > 0) {
        segments.push({
          data: new Uint8Array(currentData),
          isClient: currentColor === 'red',
        });
        currentData = [];
      }
      currentColor = 'blue';
      i += 7;
    } else if (text.substring(i, i + 4) === ANSI_RESET) {
      i += 4;
    } else {
      // Regular character
      currentData.push(text.charCodeAt(i));
      i++;
    }
  }

  // Save final segment
  if (currentData.length > 0) {
    segments.push({
      data: new Uint8Array(currentData),
      isClient: currentColor === 'red',
    });
  }

  return segments;
}

// Convert byte to hex string
function byteToHex(byte: number): string {
  return byte.toString(16).padStart(2, '0');
}

// Convert byte to ASCII character (or dot for non-printable)
// Keep newlines and carriage returns as is
function byteToAscii(byte: number): string {
  if (byte === 10 || byte === 13) return String.fromCharCode(byte); // \n or \r
  return byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
}

// Generate hex dump rows
interface HexRow {
  offset: number;
  hexBytes: string[];
  asciiChars: string[];
  isClient: boolean;
}

function generateHexRows(segments: ParsedSegment[], baseOffset: number): HexRow[] {
  const rows: HexRow[] = [];
  let offset = baseOffset;

  for (const segment of segments) {
    const data = segment.data;
    
    for (let i = 0; i < data.length; i += 16) {
      const hexBytes: string[] = [];
      const asciiChars: string[] = [];

      for (let j = 0; j < 16; j++) {
        if (i + j < data.length) {
          hexBytes.push(byteToHex(data[i + j]));
          asciiChars.push(byteToAscii(data[i + j]));
        } else {
          hexBytes.push('  ');
          asciiChars.push(' ');
        }
      }

      rows.push({
        offset,
        hexBytes,
        asciiChars,
        isClient: segment.isClient,
      });

      offset += 16;
    }
  }

  return rows;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

export default function ConversationModal({
  open,
  onClose,
  srcIP,
  srcPort,
  dstIP,
  dstPort,
  protocol,
  onNavigatePrevious,
  onNavigateNext,
  hasPrevious = false,
  hasNext = false,
}: ConversationModalProps) {
  const isMobile = useIsMobile();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentChunk, setCurrentChunk] = useState<ConversationData | null>(null);
  const [currentOffset, setCurrentOffset] = useState(0);
  const [totalSize, setTotalSize] = useState(0);
  const [viewMode, setViewMode] = useState<'ascii' | 'hex'>('ascii');

  // Calculate total pages
  const totalPages = useMemo(() => {
    if (totalSize === 0) return 1;
    return Math.ceil(totalSize / CHUNK_SIZE);
  }, [totalSize]);

  const currentPage = useMemo(() => {
    return Math.floor(currentOffset / CHUNK_SIZE) + 1;
  }, [currentOffset]);

  // Determine if this is a network-layer-only connection (no transport layer)
  const isNetworkLayer = !srcPort && !dstPort;

  // Load chunk function
  const loadChunk = useCallback(
    async (offset: number) => {
      setLoading(true);
      setError(null);

      try {
        let data;
        
        if (isNetworkLayer) {
          // Network-layer connection (ICMP, IGMP, GRE, etc.)
          // Try common network protocols to find the conversation file
          const protocolsToTry = ['icmpv4', 'icmpv6', 'igmp', 'gre', protocol.toLowerCase()];
          
          for (const proto of protocolsToTry) {
            try {
              data = await api.getNetworkConversation(
                srcIP,
                dstIP,
                proto,
                offset,
                CHUNK_SIZE
              );
              if (data.exists) break;
            } catch {
              // Continue trying other protocols
            }
          }
          
          if (!data) {
            // Fallback: try with the provided protocol
            data = await api.getNetworkConversation(
              srcIP,
              dstIP,
              protocol.toLowerCase(),
              offset,
              CHUNK_SIZE
            );
          }
        } else {
          // Transport-layer connection (TCP/UDP)
          data = await api.getConnectionConversation(
            srcIP,
            srcPort,
            dstIP,
            dstPort,
            protocol,
            offset,
            CHUNK_SIZE
          );
        }

        if (!data.exists) {
          setError(data.errorMessage || 'Conversation data not found');
          setCurrentChunk(null);
        } else {
          setCurrentChunk(data);
          setTotalSize(data.totalSize);
        }
      } catch (err: any) {
        setError(err.message || 'Failed to load conversation data');
        setCurrentChunk(null);
      } finally {
        setLoading(false);
      }
    },
    [srcIP, srcPort, dstIP, dstPort, protocol, isNetworkLayer]
  );

  // Load initial chunk when modal opens
  useEffect(() => {
    if (open) {
      setCurrentOffset(0);
      setTotalSize(0);
      loadChunk(0);
    }
  }, [open, loadChunk]);

  // Navigate to page
  const handlePageChange = (_event: React.ChangeEvent<unknown>, page: number) => {
    const newOffset = (page - 1) * CHUNK_SIZE;
    setCurrentOffset(newOffset);
    loadChunk(newOffset);
  };

  // Navigate to next chunk
  const handleNext = () => {
    if (currentChunk && currentChunk.hasMore) {
      const newOffset = currentOffset + CHUNK_SIZE;
      setCurrentOffset(newOffset);
      loadChunk(newOffset);
    }
  };

  // Navigate to previous chunk
  const handlePrevious = () => {
    if (currentOffset > 0) {
      const newOffset = Math.max(0, currentOffset - CHUNK_SIZE);
      setCurrentOffset(newOffset);
      loadChunk(newOffset);
    }
  };

  // Keyboard navigation
  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowLeft') {
        e.preventDefault();
        handlePrevious();
      } else if (e.key === 'ArrowRight') {
        e.preventDefault();
        handleNext();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (onNavigatePrevious && hasPrevious) {
          onNavigatePrevious();
        }
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (onNavigateNext && hasNext) {
          onNavigateNext();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, currentOffset, currentChunk, onNavigatePrevious, onNavigateNext, hasPrevious, hasNext]);

  // Touch swipe navigation (mobile equivalent of arrow key navigation)
  const touchStartRef = useRef<{ x: number; y: number } | null>(null);

  const handleTouchStart = useCallback((e: React.TouchEvent) => {
    touchStartRef.current = { x: e.touches[0].clientX, y: e.touches[0].clientY };
  }, []);

  const handleTouchEnd = useCallback((e: React.TouchEvent) => {
    if (!touchStartRef.current) return;
    const dx = e.changedTouches[0].clientX - touchStartRef.current.x;
    const dy = e.changedTouches[0].clientY - touchStartRef.current.y;
    const absDx = Math.abs(dx);
    const absDy = Math.abs(dy);
    const minSwipe = 50;

    // Only trigger if swipe is clearly directional (not a tap or diagonal)
    if (absDx > minSwipe && absDx > absDy * 1.5) {
      // Horizontal swipe: chunk (page) navigation
      if (dx > 0 && currentOffset > 0) {
        // Swipe right = previous page
        handlePrevious();
      } else if (dx < 0 && currentChunk?.hasMore) {
        // Swipe left = next page
        handleNext();
      }
    } else if (absDy > minSwipe && absDy > absDx * 1.5) {
      // Vertical swipe: connection navigation
      if (dy > 0 && hasPrevious && onNavigatePrevious) {
        // Swipe down = previous connection
        onNavigatePrevious();
      } else if (dy < 0 && hasNext && onNavigateNext) {
        // Swipe up = next connection
        onNavigateNext();
      }
    }
    touchStartRef.current = null;
  }, [currentOffset, currentChunk, hasPrevious, hasNext, onNavigatePrevious, onNavigateNext]);

  const hexRows = useMemo(() => {
    if (!currentChunk || !currentChunk.exists || !currentChunk.conversationData) {
      return [];
    }
    const segments = parseConversationData(currentChunk.conversationData);
    return generateHexRows(segments, currentOffset);
  }, [currentChunk, currentOffset]);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      fullScreen={isMobile}
      PaperProps={{
        sx: isMobile ? {} : {
          height: '85vh',
          maxHeight: '900px',
        },
      }}
    >
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          {isMobile && (
            <IconButton onClick={onClose} edge="start" sx={{ mr: 1 }}>
              <CloseIcon />
            </IconButton>
          )}
          <Box sx={{ flex: 1 }}>
            <Typography variant="h6">Raw Conversation Data</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
              <Box component="span" sx={{ color: '#f44336', fontWeight: 'bold' }}>
                {srcIP}
              </Box>
              {srcPort && (
                <>
                  <Box component="span" sx={{ color: 'text.secondary' }}>:</Box>
                  <Box component="span" sx={{ color: '#FFB74D', fontWeight: 'medium' }}>
                    {srcPort}
                  </Box>
                </>
              )}
              {' → '}
              <Box component="span" sx={{ color: '#2196f3', fontWeight: 'bold' }}>
                {dstIP}
              </Box>
              {dstPort && (
                <>
                  <Box component="span" sx={{ color: 'text.secondary' }}>:</Box>
                  <Box component="span" sx={{ color: '#FFB74D', fontWeight: 'medium' }}>
                    {dstPort}
                  </Box>
                </>
              )}
              {' '}
              ({protocol || 'Network Layer'})
            </Typography>
            {totalSize > 0 && (
              <Typography variant="caption" color="text.secondary">
                Total size: {formatBytes(totalSize)} • Page {currentPage} of {totalPages}
              </Typography>
            )}
          </Box>
          {/* Connection navigation buttons */}
          {(onNavigatePrevious || onNavigateNext) && (
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', ml: 2 }}>
              <IconButton
                size="small"
                onClick={onNavigatePrevious}
                disabled={!hasPrevious}
                title="Previous connection (↑)"
              >
                <KeyboardArrowUpIcon />
              </IconButton>
              <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
                ↑↓
              </Typography>
              <IconButton
                size="small"
                onClick={onNavigateNext}
                disabled={!hasNext}
                title="Next connection (↓)"
              >
                <KeyboardArrowDownIcon />
              </IconButton>
            </Box>
          )}
        </Box>
      </DialogTitle>

      {loading && <LinearProgress />}

      <DialogContent dividers sx={{ p: 0 }} onTouchStart={handleTouchStart} onTouchEnd={handleTouchEnd}>
        {error && (
          <Box p={3}>
            <Alert severity="warning">{error}</Alert>
          </Box>
        )}

        {!error && currentChunk && currentChunk.exists && (
          <Box sx={{ height: '100%', overflow: 'auto' }}>
            {/* Legend */}
            <Box
              sx={{
                position: 'sticky',
                top: 0,
                bgcolor: 'background.paper',
                borderBottom: 1,
                borderColor: 'divider',
                p: 1,
                display: 'flex',
                flexDirection: { xs: 'column', sm: 'row' },
                gap: { xs: 1, sm: 3 },
                justifyContent: 'space-between',
                alignItems: { xs: 'stretch', sm: 'center' },
                zIndex: 1,
              }}
            >
              <Box sx={{ display: 'flex', gap: { xs: 1.5, sm: 3 }, alignItems: 'center', flexWrap: 'wrap' }}>
                <Typography variant="caption" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      bgcolor: 'rgba(244, 67, 54, 0.2)',
                      border: '1px solid #f44336',
                    }}
                  />
                  Client → Server
                </Typography>
                <Typography variant="caption" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      bgcolor: 'rgba(33, 150, 243, 0.2)',
                      border: '1px solid #2196f3',
                    }}
                  />
                  Server → Client
                </Typography>
                
                {/* View Mode Toggle */}
                <IconButton
                  size="small"
                  onClick={() => setViewMode(viewMode === 'ascii' ? 'hex' : 'ascii')}
                  title={viewMode === 'ascii' ? 'Switch to Hex View' : 'Switch to ASCII View'}
                  sx={{ ml: 2 }}
                >
                  {viewMode === 'ascii' ? <GridOnIcon fontSize="small" /> : <ViewHeadlineIcon fontSize="small" />}
                </IconButton>
              </Box>
              
              {/* Pagination Controls */}
              {totalPages > 1 && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <IconButton
                    size="small"
                    onClick={handlePrevious}
                    disabled={currentOffset === 0 || loading}
                  >
                    <NavigateBeforeIcon />
                  </IconButton>
                  <Typography variant="caption">
                    {currentPage} / {totalPages}
                  </Typography>
                  <IconButton
                    size="small"
                    onClick={handleNext}
                    disabled={!currentChunk?.hasMore || loading}
                  >
                    <NavigateNextIcon />
                  </IconButton>
                </Box>
              )}
            </Box>

            {/* ASCII-only view (default) */}
            {viewMode === 'ascii' && (
              <Box
                sx={{
                  fontFamily: 'Courier New, monospace',
                  fontSize: { xs: '11px', sm: '13px' },
                  lineHeight: 1.6,
                  p: 2,
                  bgcolor: '#1e1e1e',
                  color: '#d4d4d4',
                  whiteSpace: 'pre',
                  overflowX: 'auto',
                }}
              >
                {hexRows.map((row) => {
                  const text = row.asciiChars.join('');
                  
                  return (
                    <Box
                      key={row.offset}
                      component="span"
                      sx={{
                        bgcolor: row.isClient
                          ? 'rgba(244, 67, 54, 0.2)'
                          : 'rgba(33, 150, 243, 0.2)',
                        color: row.isClient ? '#ff8a80' : '#82b1ff',
                        display: 'inline',
                      }}
                    >
                      {text}
                    </Box>
                  );
                })}

                {hexRows.length === 0 && !loading && (
                  <Typography variant="body2" color="text.secondary" align="center">
                    No conversation data available
                  </Typography>
                )}
              </Box>
            )}

            {/* Hex dump display */}
            {viewMode === 'hex' && (
              <Box
                sx={{
                  fontFamily: 'Courier New, monospace',
                  fontSize: { xs: '11px', sm: '13px' },
                  lineHeight: 1.4,
                  p: 2,
                  bgcolor: '#1e1e1e',
                  color: '#d4d4d4',
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
                      bgcolor: row.isClient
                        ? 'rgba(244, 67, 54, 0.15)'
                        : 'rgba(33, 150, 243, 0.15)',
                      borderLeft: row.isClient ? '3px solid #f44336' : '3px solid #2196f3',
                    }}
                  >
                    {/* Offset - hidden on mobile */}
                    <Box sx={{ color: '#858585', minWidth: '60px', display: { xs: 'none', sm: 'block' } }}>
                      {row.offset.toString(16).padStart(8, '0')}
                    </Box>

                    {/* Hex bytes (split into two groups of 8) */}
                    <Box sx={{ display: 'flex', gap: { xs: 1, sm: 2 }, minWidth: { xs: 'auto', sm: '400px' }, flexWrap: { xs: 'wrap', sm: 'nowrap' } }}>
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
                    <Box sx={{ color: row.isClient ? '#ff8a80' : '#82b1ff' }}>
                      {row.asciiChars.join('')}
                    </Box>
                  </Box>
                ))}

                {hexRows.length === 0 && !loading && (
                  <Typography variant="body2" color="text.secondary" align="center">
                    No conversation data available
                  </Typography>
                )}
              </Box>
            )}
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ justifyContent: 'space-between', flexDirection: { xs: 'column', sm: 'row' }, gap: 1 }}>
        {/* Page Selector */}
        {totalPages > 1 && (
          <Pagination
            count={totalPages}
            page={currentPage}
            onChange={handlePageChange}
            disabled={loading}
            size="small"
            showFirstButton
            showLastButton
            siblingCount={isMobile ? 0 : 1}
          />
        )}
        <Box sx={{ flex: 1, display: { xs: 'none', sm: 'block' } }} />
        <Button onClick={onClose} startIcon={<CloseIcon />}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}
