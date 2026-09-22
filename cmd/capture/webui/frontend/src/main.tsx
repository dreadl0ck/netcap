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
import { useState, useEffect, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, useNavigate } from 'react-router';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import BoltIcon from '@mui/icons-material/Bolt';
import DataObjectIcon from '@mui/icons-material/DataObject';
import ManageSearchIcon from '@mui/icons-material/ManageSearch';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import SearchIcon from '@mui/icons-material/Search';
import ShieldIcon from '@mui/icons-material/Shield';
import { ReactRouterNetcapProvider } from '@dreadl0ck/netcap-ui/adapters/react-router';
import { api, getBackendUrl } from '@dreadl0ck/netcap-ui/lib';
import { ConnectionOverlay, DatabaseBootstrap } from '@dreadl0ck/netcap-ui/components';
import { mutate as globalMutate } from 'swr';
import { AppRoutes } from './routes';
import { netcapTheme } from './theme';

import '@fontsource/space-grotesk/400.css';
import '@fontsource/space-grotesk/500.css';
import '@fontsource/space-grotesk/600.css';
import '@fontsource/space-grotesk/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/600.css';

const DIRECT_NAVIGATION_ITEMS = [
  {
    path: '/interfaces',
    label: 'Interfaces',
    icon: <NetworkCheckIcon />,
    placement: 'workspace-before-pcaps' as const,
    description: 'View available network interfaces for live packet capture and monitoring.',
  },
  {
    path: '/yara',
    label: 'YARA Rules',
    icon: <ShieldIcon />,
    placement: 'data-before-logs' as const,
    description: 'YARA Rules: Upload and manage YARA rules, scan extracted files for malware signatures.',
  },
  {
    path: '/inject',
    label: 'Inject',
    icon: <BoltIcon />,
    placement: 'detection-end' as const,
    description: 'Configure packet injection and manipulation rules.',
  },
  {
    path: '/dbs',
    label: 'Databases',
    icon: <DataObjectIcon />,
    placement: 'system-start' as const,
    description: 'Manage GeoIP, vulnerability, and MAC vendor databases.',
  },
  {
    path: '/dpi',
    label: 'DPI',
    icon: <ManageSearchIcon />,
    placement: 'system-start' as const,
    description: 'Configure Deep Packet Inspection modules.',
  },
  {
    path: '/probes',
    label: 'Service Probes',
    icon: <SearchIcon />,
    placement: 'system-before-bpf' as const,
    description: 'Manage nmap service probes for service fingerprinting.',
  },
];

// Valid PCAP file extensions
const VALID_PCAP_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

function isPcapFile(filename: string): boolean {
  const lowerName = filename.toLowerCase();
  return VALID_PCAP_EXTENSIONS.some(ext => lowerName.endsWith(ext));
}

function hasFiles(dataTransfer: DataTransfer): boolean {
  if (dataTransfer.types?.includes('Files')) {
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

  useEffect(() => {
    let mounted = true;
    let retryTimeout: ReturnType<typeof setTimeout>;

    const checkConnection = async () => {
      try {
        await api.getStatus();
        if (mounted) {
          setIsConnected(true);
          setIsInitializing(false);
        }
      } catch {
        if (mounted) {
          setConnectionMessage('Connecting to backend...');
          retryTimeout = setTimeout(checkConnection, 1000);
        }
      }
    };

    checkConnection();

    const healthCheckInterval = setInterval(() => {
      if (isConnected) {
        api.getStatus().catch(() => {
          if (mounted) {
            setIsConnected(false);
            setConnectionMessage('Connection lost. Reconnecting...');
            checkConnection();
          }
        });
      }
    }, 10000);

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
      ? ``
      : undefined,
  };
}

// Global drop zone component that wraps the entire app
function GlobalDropZone({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const [isDraggingOver, setIsDraggingOver] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState('');
  const dragCounter = React.useRef(0);

  const handleDragEnter = useCallback((e: DragEvent) => {
    e.preventDefault();
    dragCounter.current++;

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

        if (response.sessionId) {
          uploadedIds.push(response.sessionId);
        } else if (response.id) {
          uploadedIds.push(response.id);
        }
      }

      setUploadMessage(`Successfully uploaded ${pcapFiles.length} file(s)`);

      globalMutate('inputFiles');

      setTimeout(() => {
        setIsUploading(false);
        setUploadMessage('');
        navigate('/pcaps');
      }, 1500);

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      setUploadMessage(`Error: ${errorMessage}`);
      setTimeout(() => {
        setIsUploading(false);
        setUploadMessage('');
      }, 3000);
    }
  }, [navigate]);

  useEffect(() => {
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
function AppContent() {
  const connectionStatus = useConnectionStatus();

  return (
    <>
      <GlobalDropZone>
        <AppRoutes />
      </GlobalDropZone>
      <ConnectionOverlay
        visible={connectionStatus.showOverlay}
        message={connectionStatus.message}
        subMessage={connectionStatus.subMessage}
      />
      {/* Offers the one-time database download when a required DB is absent. */}
      <DatabaseBootstrap />
    </>
  );
}

function App() {
  return (
    <BrowserRouter>
      <ThemeProvider theme={netcapTheme}>
        <CssBaseline />
        <ReactRouterNetcapProvider backendUrl={getBackendUrl()} navigationItems={DIRECT_NAVIGATION_ITEMS}>
          <AppContent />
        </ReactRouterNetcapProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
