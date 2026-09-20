import { alpha, createTheme } from '@mui/material/styles';

const colors = {
  canvas: '#050508',
  surface: '#0b0c14',
  raised: '#11131f',
  blue: '#3b82f6',
  blueBright: '#60a5fa',
  violet: '#8b5cf6',
  border: '#24283a',
  text: '#f4f7fb',
  muted: '#9199ad',
};

export const netcapTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: colors.blueBright, dark: colors.blue, light: '#93c5fd', contrastText: '#050508' },
    secondary: { main: '#a78bfa', dark: colors.violet, contrastText: '#050508' },
    background: { default: colors.canvas, paper: colors.surface },
    text: { primary: colors.text, secondary: colors.muted },
    divider: colors.border,
    success: { main: '#34d399' },
    warning: { main: '#fbbf24' },
    error: { main: '#fb7185' },
    info: { main: '#38bdf8' },
  },
  shape: { borderRadius: 12 },
  typography: {
    fontFamily: '"Space Grotesk", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: 14,
    h1: { fontSize: '2.25rem', fontWeight: 650, letterSpacing: '-0.035em' },
    h2: { fontSize: '1.75rem', fontWeight: 650, letterSpacing: '-0.025em' },
    h3: { fontSize: '1.4rem', fontWeight: 650, letterSpacing: '-0.02em' },
    h4: { fontSize: '1.15rem', fontWeight: 650 },
    h5: { fontSize: '1rem', fontWeight: 650 },
    h6: { fontSize: '0.92rem', fontWeight: 650, letterSpacing: '-0.01em' },
    body1: { fontSize: '0.9rem' },
    body2: { fontSize: '0.82rem' },
    button: { fontSize: '0.8rem', fontWeight: 650, letterSpacing: '0.01em', textTransform: 'none' },
    caption: { fontSize: '0.72rem', letterSpacing: '0.015em' },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        ':root': {
          colorScheme: 'dark',
          '--netcap-canvas': colors.canvas,
          '--netcap-surface': colors.surface,
          '--netcap-raised': colors.raised,
          '--netcap-blue': colors.blue,
          '--netcap-violet': colors.violet,
          '--netcap-border': colors.border,
          '--netcap-text': colors.text,
          '--netcap-muted': colors.muted,
          '--netcap-mono': '"JetBrains Mono", "SFMono-Regular", Consolas, monospace',
        },
        html: { height: '100%', width: '100%', overflow: 'hidden', WebkitFontSmoothing: 'antialiased' },
        body: {
          height: '100%',
          width: '100%',
          margin: 0,
          overflow: 'hidden',
          position: 'fixed',
          color: colors.text,
          backgroundColor: colors.canvas,
          backgroundImage: `radial-gradient(circle at 88% -10%, ${alpha(colors.violet, 0.1)}, transparent 30%), radial-gradient(circle at 35% 0%, ${alpha(colors.blue, 0.08)}, transparent 28%)`,
          textRendering: 'optimizeLegibility',
          overscrollBehavior: 'none',
        },
        '#root': { height: '100%', width: '100%', overflow: 'auto', position: 'relative', WebkitOverflowScrolling: 'touch' },
        '::selection': { backgroundColor: alpha(colors.blue, 0.42), color: '#fff' },
        'code, pre, kbd, samp': { fontFamily: 'var(--netcap-mono)' },
        '*': { scrollbarColor: `${alpha(colors.muted, 0.35)} transparent`, scrollbarWidth: 'thin' },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: `1px solid ${colors.border}`,
          boxShadow: '0 18px 50px rgba(0, 0, 0, 0.2)',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          position: 'relative',
          overflow: 'hidden',
          background: `linear-gradient(145deg, ${alpha(colors.raised, 0.94)}, ${alpha(colors.surface, 0.98)})`,
          border: `1px solid ${colors.border}`,
          boxShadow: '0 14px 40px rgba(0, 0, 0, 0.16)',
          transition: 'border-color 160ms ease, transform 160ms ease, box-shadow 160ms ease',
        },
      },
    },
    MuiCardContent: { styleOverrides: { root: { padding: 20, '&:last-child': { paddingBottom: 20 } } } },
    MuiAppBar: {
      styleOverrides: {
        root: {
          background: alpha(colors.canvas, 0.82),
          border: 0,
          borderBottom: `1px solid ${alpha(colors.border, 0.85)}`,
          boxShadow: 'none',
          backdropFilter: 'blur(18px)',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          background: `linear-gradient(180deg, ${colors.surface}, ${colors.canvas})`,
          border: 0,
          borderRight: `1px solid ${colors.border}`,
        },
      },
    },
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: {
        root: { borderRadius: 9, minHeight: 36, paddingInline: 15 },
        containedPrimary: {
          background: `linear-gradient(135deg, ${colors.blue}, ${colors.violet})`,
          color: '#fff',
          '&:hover': { boxShadow: `0 8px 24px ${alpha(colors.blue, 0.28)}` },
        },
        outlined: { borderColor: colors.border, '&:hover': { borderColor: alpha(colors.blueBright, 0.55), backgroundColor: alpha(colors.blue, 0.07) } },
      },
    },
    MuiIconButton: { styleOverrides: { root: { borderRadius: 9 } } },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          borderRadius: 9,
          backgroundColor: alpha(colors.raised, 0.66),
          '& .MuiOutlinedInput-notchedOutline': { borderColor: colors.border },
          '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: alpha(colors.blueBright, 0.48) },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { borderRadius: 7, fontFamily: 'var(--netcap-mono)', fontSize: '0.69rem', borderColor: colors.border },
      },
    },
    MuiTabs: { styleOverrides: { indicator: { height: 2, borderRadius: 2, background: `linear-gradient(90deg, ${colors.blue}, ${colors.violet})` } } },
    MuiTab: { styleOverrides: { root: { minHeight: 42, textTransform: 'none', fontWeight: 600 } } },
    MuiTableContainer: { styleOverrides: { root: { borderRadius: 12, border: `1px solid ${colors.border}` } } },
    MuiTableCell: {
      styleOverrides: {
        root: { borderColor: alpha(colors.border, 0.78) },
        head: { color: '#bac2d4', backgroundColor: alpha(colors.raised, 0.88), fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.055em', textTransform: 'uppercase' },
      },
    },
    MuiTableRow: { styleOverrides: { root: { '&:hover': { backgroundColor: alpha(colors.blue, 0.045) } } } },
    MuiDialog: { styleOverrides: { paper: { background: `linear-gradient(145deg, ${colors.raised}, ${colors.surface})` } } },
    MuiTooltip: { styleOverrides: { tooltip: { backgroundColor: '#171a29', border: `1px solid ${colors.border}`, fontSize: '0.72rem' } } },
    MuiLinearProgress: { styleOverrides: { root: { backgroundColor: alpha(colors.blue, 0.12) }, bar: { background: `linear-gradient(90deg, ${colors.blue}, ${colors.violet})` } } },
    MuiBottomNavigation: { styleOverrides: { root: { backgroundColor: alpha(colors.surface, 0.97), borderTop: `1px solid ${colors.border}` } } },
  },
});
