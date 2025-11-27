import * as React from 'react';
import { useState, useEffect, useCallback } from 'react';
import type { AppProps } from 'next/app';
import { useRouter } from 'next/router';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import { LearnModeProvider } from '@/contexts/LearnModeContext';
import { api } from '@/lib/api';
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

// Global drop zone component that wraps the entire app
function GlobalDropZone({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [isDraggingOver, setIsDraggingOver] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState('');
  const dragCounter = React.useRef(0);

  // Skip global drop zone on the analyze page (it has its own drop zone)
  const isAnalyzePage = router.pathname === '/analyze';

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
      if (hasFiles(e.dataTransfer) && !isAnalyzePage) {
        setIsDraggingOver(true);
      }
    }
  }, [isAnalyzePage]);

  const handleDrop = useCallback(async (e: DragEvent) => {
    e.preventDefault();
    dragCounter.current = 0;
    setIsDraggingOver(false);

    // Skip if on analyze page (let local handler take over)
    if (router.pathname === '/analyze') {
      return;
    }

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
      
      // Redirect to dashboard after a short delay
      setTimeout(() => {
        setIsUploading(false);
        setUploadMessage('');
        router.push('/');
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
      
      {/* Global drop overlay - hidden on analyze page which has its own drop zone */}
      {!isAnalyzePage && (isDraggingOver || isUploading || uploadMessage) && (
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

export default function App({ Component, pageProps }: AppProps) {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <LearnModeProvider>
        <GlobalDropZone>
          <Component {...pageProps} />
        </GlobalDropZone>
      </LearnModeProvider>
    </ThemeProvider>
  );
}

