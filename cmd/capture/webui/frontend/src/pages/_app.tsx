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

import * as React from 'react';
import { useState, useEffect, useCallback, useRef } from 'react';
import type { AppProps } from 'next/app';
import { useRouter } from 'next/router';
import Head from 'next/head';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import { NextjsNetcapProvider } from '@dreadl0ck/netcap-ui/adapters/nextjs';
import { api, getBackendUrl } from '@dreadl0ck/netcap-ui/lib';
import { ConnectionOverlay } from '@dreadl0ck/netcap-ui/components';
import { mutate as globalMutate } from 'swr';

// Import self-hosted Roboto fonts (only the weights needed by MUI)
import '@fontsource/roboto/300.css'; // Light
import '@fontsource/roboto/400.css'; // Regular
import '@fontsource/roboto/500.css'; // Medium
import '@fontsource/roboto/700.css'; // Bold
// Import Roboto Mono for code/monospace content
import '@fontsource/roboto-mono/400.css';
import '@fontsource/roboto-mono/700.css';

// Create theme once outside component to prevent recreation on every render
// This is a critical performance optimization that prevents unnecessary re-renders
// of all child components wrapped by ThemeProvider
const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00bcd4',
    },
    secondary: {
      main: '#ff4081',
    },
  },
  typography: {
    // Use self-hosted Roboto font
    fontFamily: [
      'Roboto',
      '-apple-system',
      'BlinkMacSystemFont',
      '"Segoe UI"',
      '"Helvetica Neue"',
      'Arial',
      'sans-serif',
    ].join(','),
    // Slightly smaller font sizes for mobile devices
    fontSize: 14, // Base font size (default is 14)
    // Font rendering optimizations for self-hosted fonts
    fontWeightLight: 300,
    fontWeightRegular: 400,
    fontWeightMedium: 500,
    fontWeightBold: 700,
    h1: {
      fontSize: '2rem',
      '@media (min-width:600px)': {
        fontSize: '2.5rem',
      },
    },
    h2: {
      fontSize: '1.5rem',
      '@media (min-width:600px)': {
        fontSize: '2rem',
      },
    },
    h3: {
      fontSize: '1.25rem',
      '@media (min-width:600px)': {
        fontSize: '1.5rem',
      },
    },
    h4: {
      fontSize: '1.1rem',
      '@media (min-width:600px)': {
        fontSize: '1.25rem',
      },
    },
    h5: {
      fontSize: '1rem',
      '@media (min-width:600px)': {
        fontSize: '1.1rem',
      },
    },
    h6: {
      fontSize: '0.9rem',
      '@media (min-width:600px)': {
        fontSize: '1rem',
      },
    },
    body1: {
      fontSize: '0.875rem',
      '@media (min-width:600px)': {
        fontSize: '1rem',
      },
    },
    body2: {
      fontSize: '0.8125rem',
      '@media (min-width:600px)': {
        fontSize: '0.875rem',
      },
    },
    button: {
      fontSize: '0.8125rem',
      '@media (min-width:600px)': {
        fontSize: '0.875rem',
      },
    },
    caption: {
      fontSize: '0.7rem',
      '@media (min-width:600px)': {
        fontSize: '0.75rem',
      },
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        html: {
          WebkitFontSmoothing: 'antialiased',
          MozOsxFontSmoothing: 'grayscale',
          WebkitTextSizeAdjust: '100%',
          // Prevent iOS Safari overscroll/rubber-banding
          height: '100%',
          width: '100%',
          overflow: 'hidden',
        },
        body: {
          WebkitFontSmoothing: 'antialiased',
          MozOsxFontSmoothing: 'grayscale',
          textRendering: 'optimizeLegibility',
          WebkitTextSizeAdjust: '100%',
          // Prevent iOS Safari overscroll/rubber-banding
          height: '100%',
          width: '100%',
          margin: 0,
          padding: 0,
          overflow: 'hidden',
          position: 'fixed',
          // Prevent pull-to-refresh and bounce
          overscrollBehavior: 'none',
          touchAction: 'pan-x pan-y',
        },
        // Target Next.js root div
        '#__next': {
          height: '100%',
          width: '100%',
          overflow: 'auto',
          position: 'relative',
          WebkitOverflowScrolling: 'touch',
          overscrollBehavior: 'none',
        },
        '@font-face': [
          {
            fontFamily: 'Roboto',
            fontDisplay: 'swap',
          },
        ],
      },
    },
  },
});

// Valid PCAP file extensions
const VALID_PCAP_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

function isPcapFile(filename: string): boolean {
  const lowerName = filename.toLowerCase();
  return VALID_PCAP_EXTENSIONS.some(ext => lowerName.endsWith(ext));
}

function hasFiles(dataTransfer: DataTransfer): boolean {
  // Check if there are any files being dragged
  // Note: During drag events, browsers don't always expose file names for security
  // We show the overlay for any file drag and validate file types on drop
  if (dataTransfer.types && dataTransfer.types.includes('Files')) {
    return true;
  }
  if (dataTransfer.files && dataTransfer.files.length > 0) {
    return true;
  }
  if (dataTransfer.items && dataTransfer.items.length > 0) {
    return Array.from(dataTransfer.items).some(item => item.kind === 'file');
  }
  return false;
}

// Connection status hook - tracks backend connectivity
function useConnectionStatus() {
  const [isConnected, setIsConnected] = useState(false);
  const [isInitializing, setIsInitializing] = useState(true);
  const [connectionMessage, setConnectionMessage] = useState('Connecting to NETCAP...');
  const retryCountRef = useRef(0);
  const maxRetries = 3;
  const retryDelay = 2000;

  useEffect(() => {
    let mounted = true;
    let retryTimeout: ReturnType<typeof setTimeout>;

    const checkConnection = async () => {
      try {
        // Try to fetch version info - this is a lightweight endpoint
        await api.getVersion();
        if (mounted) {
          setIsConnected(true);
          setIsInitializing(false);
          retryCountRef.current = 0;
        }
      } catch {
        if (mounted) {
          retryCountRef.current++;
          
          if (retryCountRef.current <= maxRetries) {
            setConnectionMessage(`Connecting to backend... (attempt ${retryCountRef.current}/${maxRetries})`);
            retryTimeout = setTimeout(checkConnection, retryDelay);
          } else {
            setConnectionMessage('Unable to connect to backend');
            setIsConnected(false);
            setIsInitializing(false);
            // Keep retrying in the background
            retryTimeout = setTimeout(() => {
              retryCountRef.current = 0;
              setIsInitializing(true);
              setConnectionMessage('Retrying connection...');
              checkConnection();
            }, 5000);
          }
        }
      }
    };

    // Start initial connection check
    checkConnection();

    // Set up periodic health check when connected
    const healthCheckInterval = setInterval(() => {
      if (isConnected) {
        api.getVersion().catch(() => {
          if (mounted) {
            setIsConnected(false);
            setConnectionMessage('Connection lost. Reconnecting...');
            retryCountRef.current = 0;
            checkConnection();
          }
        });
      }
    }, 10000); // Check every 10 seconds

    return () => {
      mounted = false;
      clearTimeout(retryTimeout);
      clearInterval(healthCheckInterval);
    };
  }, [isConnected]);

  return {
    isConnected,
    isInitializing,
    showOverlay: !isConnected || isInitializing,
    message: connectionMessage,
    subMessage: !isConnected && !isInitializing 
      ? `Make sure the NETCAP backend is running on ${getBackendUrl()}`
      : undefined,
  };
}

// Global drop zone component that wraps the entire app
function GlobalDropZone({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [isDraggingOver, setIsDraggingOver] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState('');
  const dragCounter = React.useRef(0);

  const handleDragEnter = useCallback((e: DragEvent) => {
    e.preventDefault();
    dragCounter.current++;
    
    // Show overlay for any file drag - we validate file types on drop
    if (e.dataTransfer && hasFiles(e.dataTransfer)) {
      setIsDraggingOver(true);
    }
  }, []);

  const handleDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault();
    dragCounter.current--;
    
    if (dragCounter.current === 0) {
      setIsDraggingOver(false);
    }
  }, []);

  const handleDragOver = useCallback((e: DragEvent) => {
    e.preventDefault();
    
    if (e.dataTransfer) {
      e.dataTransfer.dropEffect = 'copy';
      // Ensure overlay stays visible during drag
      if (hasFiles(e.dataTransfer)) {
        setIsDraggingOver(true);
      }
    }
  }, []);

  const handleDrop = useCallback(async (e: DragEvent) => {
    e.preventDefault();
    dragCounter.current = 0;
    setIsDraggingOver(false);

    if (!e.dataTransfer?.files || e.dataTransfer.files.length === 0) {
      return;
    }

    // Filter for valid PCAP files
    const pcapFiles = Array.from(e.dataTransfer.files).filter(file => isPcapFile(file.name));
    
    if (pcapFiles.length === 0) {
      setUploadMessage('No valid PCAP files found. Supported formats: .pcap, .pcapng, .cap');
      setTimeout(() => setUploadMessage(''), 3000);
      return;
    }

    setIsUploading(true);
    setUploadMessage(`Uploading ${pcapFiles.length} file(s)...`);

    try {
      const uploadedIds: string[] = [];
      
      for (let i = 0; i < pcapFiles.length; i++) {
        const file = pcapFiles[i];
        setUploadMessage(`Uploading ${i + 1}/${pcapFiles.length}: ${file.name}...`);
        
        const response = await api.uploadFile(file);
        
        // Track session/file IDs for progress polling
        if (response.sessionId) {
          uploadedIds.push(response.sessionId);
        } else if (response.id) {
          uploadedIds.push(response.id);
        }
      }

      setUploadMessage(`Successfully uploaded ${pcapFiles.length} file(s)! Redirecting...`);
      
      // Invalidate SWR cache for input files so other pages will refresh
      globalMutate('inputFiles');
      
      // Redirect to PCAPs page after a short delay
      setTimeout(() => {
        setIsUploading(false);
        setUploadMessage('');
        router.push('/pcaps');
      }, 1500);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      setUploadMessage(`Error: ${errorMessage}`);
      setTimeout(() => {
        setIsUploading(false);
        setUploadMessage('');
      }, 3000);
    }
  }, [router]);

  useEffect(() => {
    // Add global event listeners
    document.addEventListener('dragenter', handleDragEnter);
    document.addEventListener('dragleave', handleDragLeave);
    document.addEventListener('dragover', handleDragOver);
    document.addEventListener('drop', handleDrop);

    return () => {
      document.removeEventListener('dragenter', handleDragEnter);
      document.removeEventListener('dragleave', handleDragLeave);
      document.removeEventListener('dragover', handleDragOver);
      document.removeEventListener('drop', handleDrop);
    };
  }, [handleDragEnter, handleDragLeave, handleDragOver, handleDrop]);

  return (
    <>
      {children}
      
      {/* Global drop overlay - active on all pages */}
      {(isDraggingOver || isUploading || uploadMessage) && (
        <Box
          sx={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            zIndex: 9999,
            pointerEvents: isDraggingOver ? 'auto' : 'none',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: isDraggingOver ? 'rgba(0, 188, 212, 0.25)' : 'transparent',
            border: isDraggingOver ? '6px dashed' : 'none',
            borderColor: 'primary.main',
            boxShadow: isDraggingOver ? 'inset 0 0 100px rgba(0, 188, 212, 0.3)' : 'none',
            transition: 'all 0.2s ease-in-out',
          }}
        >
          <Box
            sx={{
              backgroundColor: 'background.paper',
              borderRadius: 2,
              p: 4,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 2,
              boxShadow: 6,
              border: '2px solid',
              borderColor: 'primary.main',
            }}
          >
            <CloudUploadIcon 
              sx={{ 
                fontSize: 64, 
                color: 'primary.main',
                animation: isUploading ? 'pulse 1.5s infinite' : 'none',
                '@keyframes pulse': {
                  '0%': { opacity: 1 },
                  '50%': { opacity: 0.5 },
                  '100%': { opacity: 1 },
                },
              }} 
            />
            <Typography variant="h6" color="primary">
              {isUploading 
                ? uploadMessage 
                : uploadMessage 
                  ? uploadMessage 
                  : 'Drop PCAP files anywhere to upload'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Supported formats: .pcap, .pcapng, .cap
            </Typography>
          </Box>
        </Box>
      )}
    </>
  );
}

// App content wrapper that uses the connection status
function AppContent({ Component, pageProps }: AppProps) {
  const connectionStatus = useConnectionStatus();

  return (
    <>
      <GlobalDropZone>
        <Component {...pageProps} />
      </GlobalDropZone>
      <ConnectionOverlay
        visible={connectionStatus.showOverlay}
        message={connectionStatus.message}
        subMessage={connectionStatus.subMessage}
      />
    </>
  );
}

export default function App(props: AppProps) {
  return (
    <>
      <Head>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover" />
      </Head>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <NextjsNetcapProvider backendUrl={getBackendUrl()}>
          <AppContent {...props} />
        </NextjsNetcapProvider>
      </ThemeProvider>
    </>
  );
}

