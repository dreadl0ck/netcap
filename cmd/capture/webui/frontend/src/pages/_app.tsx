import * as React from 'react';
import type { AppProps } from 'next/app';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { LearnModeProvider } from '@/contexts/LearnModeContext';

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
          touchAction: 'manipulation',
          WebkitTextSizeAdjust: '100%',
        },
        body: {
          WebkitFontSmoothing: 'antialiased',
          MozOsxFontSmoothing: 'grayscale',
          textRendering: 'optimizeLegibility',
          touchAction: 'manipulation',
          WebkitTextSizeAdjust: '100%',
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

export default function App({ Component, pageProps }: AppProps) {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <LearnModeProvider>
        <Component {...pageProps} />
      </LearnModeProvider>
    </ThemeProvider>
  );
}

