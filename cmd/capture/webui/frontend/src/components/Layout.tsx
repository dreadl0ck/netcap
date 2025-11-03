import { useState } from 'react';
import {
  AppBar,
  Badge,
  Box,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import DashboardIcon from '@mui/icons-material/Dashboard';
import StorageIcon from '@mui/icons-material/Storage';
import DescriptionIcon from '@mui/icons-material/Description';
import DataObjectIcon from '@mui/icons-material/DataObject';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import SecurityIcon from '@mui/icons-material/Security';
import SettingsIcon from '@mui/icons-material/Settings';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import BarChartIcon from '@mui/icons-material/BarChart';
import BubbleChartIcon from '@mui/icons-material/BubbleChart';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import GitHubIcon from '@mui/icons-material/GitHub';
import Link from 'next/link';
import { useRouter } from 'next/router';
import useSWR from 'swr';
import { api } from '@/lib/api';

const drawerWidth = 240;

interface LayoutProps {
  children: React.ReactNode;
  title: string;
}

export default function Layout({ children, title }: LayoutProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const router = useRouter();

  // Fetch version information
  const { data: version } = useSWR('version', () => api.getVersion(), {
    refreshInterval: 0, // Only fetch once
  });

  // Fetch status to check if we're in service mode
  const { data: status } = useSWR('status', () => api.getStatus(), {
    refreshInterval: 5000, // Refresh every 5 seconds
  });

  // Fetch input files to get count for badge
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles(), {
    refreshInterval: 10000, // Refresh every 10 seconds
  });

  // Calculate total PCAP count (including preloaded and user files)
  const pcapCount = inputFiles?.length || 0;

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  // Helper function to check if a path is currently active
  const isActive = (path: string) => {
    if (path === '/') {
      return router.pathname === '/';
    }
    return router.pathname.startsWith(path);
  };

  const drawer = (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Toolbar>
        <Link href="/analyze" passHref style={{ textDecoration: 'none', width: '100%' }}>
          <Box>
            <Typography 
              variant="h6" 
              noWrap 
              component="div" 
              sx={{ 
                color: 'primary.main', 
                fontWeight: 'bold',
                cursor: 'pointer',
                lineHeight: 1.2,
                '&:hover': {
                  color: 'primary.dark',
                }
              }}
            >
              NETCAP
            </Typography>
            {status?.isServiceMode && (
              <Typography 
                variant="caption" 
                component="div"
                sx={{ 
                  color: 'text.secondary',
                  fontSize: '0.65rem',
                  fontWeight: 500,
                  letterSpacing: '0.1em',
                  mt: -0.5
                }}
              >
                SERVICE
              </Typography>
            )}
            {status && !status?.isTryService && !status?.isServiceMode && (
              <Typography 
                variant="caption" 
                component="div"
                sx={{ 
                  color: 'text.secondary',
                  fontSize: '0.65rem',
                  fontWeight: 500,
                  letterSpacing: '0.1em',
                  mt: -0.5
                }}
              >
                LOCAL
              </Typography>
            )}
          </Box>
        </Link>
      </Toolbar>
      <List sx={{ flexGrow: 1 }}>
        <Link href="/" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <DashboardIcon />
            </ListItemIcon>
            <ListItemText primary="Dashboard" />
          </ListItemButton>
        </Link>
        <Link href="/analyze" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/analyze')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <CloudUploadIcon />
            </ListItemIcon>
            <ListItemText primary="Analyze" />
          </ListItemButton>
        </Link>
        <Link href="/interfaces" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/interfaces')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <NetworkCheckIcon />
            </ListItemIcon>
            <ListItemText primary="Interfaces" />
          </ListItemButton>
        </Link>
        <Link href="/pcaps" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/pcaps')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <Badge 
                badgeContent={pcapCount} 
                color="primary"
                max={999}
                sx={{
                  '& .MuiBadge-badge': {
                    right: -3,
                    top: 3,
                  },
                }}
              >
                <InsertDriveFileIcon />
              </Badge>
            </ListItemIcon>
            <ListItemText primary="PCAPs" />
          </ListItemButton>
        </Link>
        <Link href="/audit" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/audit')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <StorageIcon />
            </ListItemIcon>
            <ListItemText primary="Audit Records" />
          </ListItemButton>
        </Link>
        <Link href="/explore" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/explore')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <BarChartIcon />
            </ListItemIcon>
            <ListItemText primary="Explore" />
          </ListItemButton>
        </Link>
        <Link href="/visualize" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/visualize')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <BubbleChartIcon />
            </ListItemIcon>
            <ListItemText primary="Visualize" />
          </ListItemButton>
        </Link>
        <Link href="/logs" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/logs')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <DescriptionIcon />
            </ListItemIcon>
            <ListItemText primary="Logs" />
          </ListItemButton>
        </Link>
        <Link href="/dbs" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/dbs')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <DataObjectIcon />
            </ListItemIcon>
            <ListItemText primary="Databases" />
          </ListItemButton>
        </Link>
        <Link href="/dpi" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/dpi')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <SecurityIcon />
            </ListItemIcon>
            <ListItemText primary="DPI" />
          </ListItemButton>
        </Link>
        <Link href="/decoders" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/decoders')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <AccountTreeIcon />
            </ListItemIcon>
            <ListItemText primary="Decoders" />
          </ListItemButton>
        </Link>
        <Link href="/bpf" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/bpf')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <FilterAltIcon />
            </ListItemIcon>
            <ListItemText primary="BPF Filters" />
          </ListItemButton>
        </Link>
        <Link href="/config" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/config')}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon>
              <SettingsIcon />
            </ListItemIcon>
            <ListItemText primary="Config" />
          </ListItemButton>
        </Link>
      </List>
      {version && (
        <Box
          sx={{
            p: 2,
            borderTop: '1px solid',
            borderColor: 'divider',
            mt: 'auto',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography variant="caption" color="text.secondary">
              {version.version}-
              <Link
                href={`https://github.com/dreadl0ck/netcap/commit/${version.commit}`}
                passHref
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  color: 'inherit',
                  textDecoration: 'none',
                }}
              >
                <Box
                  component="span"
                  sx={{
                    '&:hover': {
                      textDecoration: 'underline',
                      color: 'primary.main',
                    }
                  }}
                >
                  {version.commit}
                </Box>
              </Link>
            </Typography>
            <Box sx={{ display: 'flex', gap: 0.5 }}>
              <IconButton
                size="small"
                href="https://docs.netcap.io"
                target="_blank"
                rel="noopener noreferrer"
                sx={{ 
                  color: 'text.secondary',
                  '&:hover': {
                    color: 'primary.main',
                  }
                }}
                title="Documentation"
              >
                <MenuBookIcon fontSize="small" />
              </IconButton>
              <IconButton
                size="small"
                href="https://github.com/dreadl0ck/netcap"
                target="_blank"
                rel="noopener noreferrer"
                sx={{ 
                  color: 'text.secondary',
                  '&:hover': {
                    color: 'primary.main',
                  }
                }}
                title="GitHub Repository"
              >
                <GitHubIcon fontSize="small" />
              </IconButton>
            </Box>
          </Box>
        </Box>
      )}
    </Box>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          ml: { sm: `${drawerWidth}px` },
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { sm: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" noWrap component="div">
            {title}
          </Typography>
        </Toolbar>
      </AppBar>
      <Box
        component="nav"
        sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
        aria-label="navigation"
      >
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true,
          }}
          sx={{
            display: { xs: 'block', sm: 'none' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', sm: 'block' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          mt: 8,
        }}
      >
        {children}
      </Box>
    </Box>
  );
}

