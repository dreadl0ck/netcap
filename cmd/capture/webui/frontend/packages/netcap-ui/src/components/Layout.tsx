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

import { useState, useEffect } from 'react';
import { useIsMobile } from '../hooks/useIsMobile';
import AppBar from '@mui/material/AppBar';
import Badge from '@mui/material/Badge';
import Box from '@mui/material/Box';
import Collapse from '@mui/material/Collapse';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import MenuIcon from '@mui/icons-material/Menu';
import ExpandLess from '@mui/icons-material/ExpandLess';
import ExpandMore from '@mui/icons-material/ExpandMore';
import DashboardIcon from '@mui/icons-material/Dashboard';
import FolderIcon from '@mui/icons-material/Folder';
import StorageIcon from '@mui/icons-material/Storage';
import DescriptionIcon from '@mui/icons-material/Description';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import SettingsIcon from '@mui/icons-material/Settings';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import DevicesIcon from '@mui/icons-material/Devices';
import RouterIcon from '@mui/icons-material/Router';
import SyncAltIcon from '@mui/icons-material/SyncAlt';
import DnsIcon from '@mui/icons-material/Dns';
import LanguageIcon from '@mui/icons-material/Language';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import AppsIcon from '@mui/icons-material/Apps';
import BugReportIcon from '@mui/icons-material/BugReport';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import BarChartIcon from '@mui/icons-material/BarChart';
import BubbleChartIcon from '@mui/icons-material/BubbleChart';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import GitHubIcon from '@mui/icons-material/GitHub';
import RuleIcon from '@mui/icons-material/Rule';
import NotificationsActiveIcon from '@mui/icons-material/NotificationsActive';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import HttpIcon from '@mui/icons-material/Http';
import BadgeIcon from '@mui/icons-material/Badge';
import LibraryBooksIcon from '@mui/icons-material/LibraryBooks';
import CodeIcon from '@mui/icons-material/Code';
import FullscreenIcon from '@mui/icons-material/Fullscreen';
import FullscreenExitIcon from '@mui/icons-material/FullscreenExit';
import { keyframes } from '@mui/material/styles';
import useSWR from 'swr';

import { useNetcapRouter } from '../hooks/useNetcapRouter';
import { useNetcapApi } from '../hooks/useNetcapApi';
import { useNetcapConfig, useNetcapLink, type NavigationItem } from '../providers/NetcapProvider';
import LearnModeToggle from './LearnModeToggle';
import LearnModeOverlay from './LearnModeOverlay';
import CommunityIDFilterBar from './CommunityIDFilterBar';
import MobileBottomNav from './MobileBottomNav';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

const drawerWidth = 264;

const logoGlowPulse = keyframes`
  0%, 100% { opacity: 0.42; transform: scale(0.9); }
  50% { opacity: 0.9; transform: scale(1.08); }
`;

// Extracted sx styles to prevent object recreation on every render
const SELECTED_MENU_ITEM_SX = {
  mx: 1.25,
  mb: 0.25,
  minHeight: 38,
  borderRadius: '9px',
  color: 'text.secondary',
  transition: 'background-color 150ms ease, color 150ms ease',
  '& .MuiListItemIcon-root': {
    color: 'text.secondary',
    minWidth: 34,
    transition: 'color 150ms ease',
  },
  '& .MuiSvgIcon-root': { fontSize: 19 },
  '&:hover': {
    backgroundColor: 'rgba(59, 130, 246, 0.07)',
    color: 'text.primary',
  },
  '&.Mui-selected': {
    backgroundColor: 'rgba(59, 130, 246, 0.13)',
    color: 'primary.light',
    boxShadow: 'inset 2px 0 #3b82f6',
    '&:hover': {
      backgroundColor: 'rgba(59, 130, 246, 0.18)',
    },
    '& .MuiListItemIcon-root': {
      color: 'primary.main',
    },
  },
};

const BADGE_SX = {
  '& .MuiBadge-badge': {
    right: -3,
    top: 3,
  },
};

const LINK_STYLE = { textDecoration: 'none', color: 'inherit' };

const TOOLBAR_LOGO_IMG_STYLE: React.CSSProperties = {
  width: '320px',
  maxWidth: 'none',
  height: 'auto',
  display: 'block',
  position: 'relative',
  zIndex: 2,
  userSelect: 'none',
  WebkitUserDrag: 'none',
  pointerEvents: 'none',
  transformOrigin: 'center',
  transition: 'filter 220ms ease, transform 220ms ease',
  willChange: 'filter, transform',
} as React.CSSProperties;


const VERSION_BOX_SX = {
  px: 2,
  py: 1.5,
  borderTop: '1px solid',
  borderColor: 'divider',
  mt: 'auto',
};

const VERSION_LINK_HOVER_SX = {
  '&:hover': {
    textDecoration: 'underline',
    color: 'primary.main',
  },
};

const ICON_BUTTON_SX = {
  color: 'text.secondary',
  '&:hover': {
    color: 'primary.main',
  },
};

const SECTION_LABEL_SX = {
  display: 'block',
  px: 2.5,
  pt: 2,
  pb: 0.75,
  color: 'text.disabled',
  fontFamily: 'var(--netcap-mono)',
  fontSize: '0.61rem',
  fontWeight: 600,
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
};

export interface LayoutProps {
  children: React.ReactNode;
  title: string;
  headerAction?: React.ReactNode;
  /** Optional custom top padding override */
  topPadding?: string | { xs?: string; sm?: string; md?: string; lg?: string };
}

export function Layout({ children, title, headerAction, topPadding }: LayoutProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const isMobile = useIsMobile();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const Link = useNetcapLink();
  const { navigationItems = [] } = useNetcapConfig();
  
  // Get community ID filter state
  const { selectedCommunityIDs, isFilterActive } = useCommunityIDFilter();
  
  // Initialize dataMenuOpen based on current route
  const [dataMenuOpen, setDataMenuOpen] = useState(() => {
    const dataRoutes = ['/records', '/explore', '/visualize', '/hosts', '/devices', '/connections', '/http', '/certificates', '/secrets',
                        '/services', '/domains', '/fingerprints', '/software', '/vulnerabilities', '/alerts', '/files', '/logs'];
    return dataRoutes.some(route => router.pathname.startsWith(route));
  });

  // Fetch version information
  const { data: version } = useSWR('version', () => api.getVersion(), {
    refreshInterval: 0,
  });

  // Fetch status
  const { data: status } = useSWR('status', () => api.getStatus(), {
    refreshInterval: 5000,
  });

  // Fetch input files count
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles(), {
    refreshInterval: 10000,
  });

  // Convert selectedCommunityIDs Set to array for API call and cache key
  const communityIDsArray = Array.from(selectedCommunityIDs);
  const communityIDsKey = isFilterActive ? communityIDsArray.join(',') : '';

  // Fetch all menu counts in a single efficient request
  // When filter is active, pass community IDs to get filtered counts
  const { data: menuCounts, mutate: mutateMenuCounts } = useSWR(
    ['menuCounts', communityIDsKey],
    () => api.getMenuCounts(isFilterActive ? communityIDsArray : undefined),
    {
      refreshInterval: 0,
      revalidateOnFocus: false,
    }
  );

  // Fetch alert statistics (not filtered by community ID in menu badge)
  const { data: alertStats, mutate: mutateAlertStats } = useSWR('alertStats', () => api.getAlertStats(), {
    refreshInterval: 10000,
  });

  // Extract counts from menuCounts response
  const auditRecordsCount = menuCounts?.auditRecordsCount || 0;
  const hostsCount = menuCounts?.hostsCount || 0;
  const devicesCount = menuCounts?.devicesCount || 0;
  const connectionsCount = menuCounts?.connectionsCount || 0;
  const httpCount = menuCounts?.httpCount || 0;
  const certificatesCount = menuCounts?.certificatesCount || 0;
  const secretCount = menuCounts?.secretCount || 0;
  const domainsCount = menuCounts?.domainsCount || 0;
  const fingerprintsCount = menuCounts?.fingerprintsCount || 0;
  const softwareCount = menuCounts?.softwareCount || 0;
  const vulnerabilitiesCount = menuCounts?.vulnerabilitiesCount || 0;
  const servicesCount = menuCounts?.servicesCount || 0;
  const logsCount = menuCounts?.logsCount || 0;
  const extractedFilesCount = menuCounts?.extractedFilesCount || 0;

  const pcapCount = inputFiles?.length || 0;
  const alertCount = isFilterActive ? (menuCounts?.alertsGroupCount || 0) : (alertStats?.groupCount || 0);

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch((err) => {
        console.error('Failed to enter fullscreen:', err);
      });
    } else {
      document.exitFullscreen().catch((err) => {
        console.error('Failed to exit fullscreen:', err);
      });
    }
  };

  // Auto-expand Data menu when navigating to data routes
  useEffect(() => {
    const dataRoutes = ['/records', '/explore', '/visualize', '/hosts', '/devices', '/connections', '/http', '/certificates', '/secrets',
                        '/services', '/domains', '/fingerprints', '/software', '/vulnerabilities', '/alerts', '/files', '/logs'];
    const isDataRoute = dataRoutes.some(route => router.pathname.startsWith(route));
    
    if (isDataRoute) {
      setDataMenuOpen(true);
    }
  }, [router.pathname]);

  // Listen for directory-changed events
  useEffect(() => {
    const handleDirectoryChanged = () => {
      mutateAlertStats();
      mutateMenuCounts();
    };

    window.addEventListener('directory-changed', handleDirectoryChanged);
    return () => {
      window.removeEventListener('directory-changed', handleDirectoryChanged);
    };
  }, [mutateAlertStats, mutateMenuCounts]);

  // Handle fullscreen changes
  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };

    document.addEventListener('fullscreenchange', handleFullscreenChange);

    return () => {
      document.removeEventListener('fullscreenchange', handleFullscreenChange);
    };
  }, []);

  const defaultTopPadding = topPadding || {
    xs: headerAction ? '112px' : '72px',
    sm: headerAction ? '120px' : '88px',
    md: '88px',
  };

  const renderNavigationItems = (placement: NavigationItem['placement'], nested = false) => navigationItems
    .filter(item => (item.placement ?? 'main') === placement)
    .map(item => (
      <Link key={item.path} href={item.path} passHref style={LINK_STYLE}>
        <ListItemButton
          selected={router.isActive(item.path)}
          data-learn={item.description}
          sx={nested ? { ...SELECTED_MENU_ITEM_SX, pl: 4 } : SELECTED_MENU_ITEM_SX}
        >
          <ListItemIcon>{item.icon}</ListItemIcon>
          <ListItemText primary={item.label} />
        </ListItemButton>
      </Link>
    ));

  const drawer = (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Toolbar
        sx={{
          px: '0 !important',
          minHeight: { xs: 92, sm: 104 },
          justifyContent: 'center',
          position: 'relative',
          overflow: 'hidden',
          borderBottom: '1px solid',
          borderColor: 'divider',
          backgroundImage: 'radial-gradient(circle at 50% 120%, rgba(59,130,246,.22), transparent 52%), linear-gradient(rgba(59,130,246,.045) 1px, transparent 1px), linear-gradient(90deg, rgba(139,92,246,.04) 1px, transparent 1px)',
          backgroundSize: 'auto, 20px 20px, 20px 20px',
        }}
      >
        <Link href="/" passHref style={{ ...LINK_STYLE, width: '100%', height: '100%' }}>
          <Box
            sx={{
              position: 'relative',
              isolation: 'isolate',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '100%',
              height: '100%',
              cursor: 'pointer',
              '&::before': {
                content: '""',
                position: 'absolute',
                zIndex: 0,
                inset: '-24px 16px',
                background: 'radial-gradient(ellipse at center, rgba(59, 130, 246, 0.42) 0%, rgba(59, 130, 246, 0.14) 42%, transparent 72%)',
                filter: 'blur(7px)',
                animation: `${logoGlowPulse} 6s ease-in-out infinite`,
              },
              '&::after': {
                content: '""',
                position: 'absolute',
                zIndex: 1,
                inset: 0,
                opacity: 0,
                background: 'radial-gradient(circle at 50% 55%, rgba(96,165,250,.24), rgba(139,92,246,.09) 34%, transparent 66%)',
                transition: 'opacity 220ms ease',
              },
              '&:hover::after': { opacity: 1 },
              '&:hover img': {
                transform: 'scale(1.08)',
                filter: 'drop-shadow(0 0 10px rgba(59,130,246,.58)) drop-shadow(0 0 22px rgba(139,92,246,.28))',
              },
              '@media (prefers-reduced-motion: reduce)': {
                '&::before': { animation: 'none', opacity: 0.58 },
                '& img': { transition: 'filter 220ms ease' },
                '&:hover img': { transform: 'none' },
              },
            }}
          >
            <img src="/logo.png" alt="Netcap" style={TOOLBAR_LOGO_IMG_STYLE} />
          </Box>
        </Link>
      </Toolbar>
      <List sx={{ flexGrow: 1, pt: 0, pb: 2, overflowY: 'auto', overflowX: 'hidden' }}>
        <Typography component="li" sx={SECTION_LABEL_SX}>Workspace</Typography>
        <Link href="/" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/')}
            data-learn="Dashboard: Overview of system status, processing statistics, and quick access to key metrics."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <DashboardIcon />
            </ListItemIcon>
            <ListItemText primary="Dashboard" />
          </ListItemButton>
        </Link>
        <Link href="/analyze" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/analyze')}
            data-learn="Analyze: Upload and process PCAP files to extract network traffic information and generate audit records."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <CloudUploadIcon />
            </ListItemIcon>
            <ListItemText primary="Analyze" />
          </ListItemButton>
        </Link>
        {renderNavigationItems('workspace-before-pcaps')}
        <Link href="/pcaps" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/pcaps')}
            data-learn="Manage uploaded packet capture files, view processing status, and download results."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <Badge 
                badgeContent={pcapCount} 
                color="primary"
                max={999}
                sx={BADGE_SX}
              >
                <InsertDriveFileIcon />
              </Badge>
            </ListItemIcon>
            <ListItemText primary="PCAPs" />
          </ListItemButton>
        </Link>
        {renderNavigationItems('main')}
        <Typography component="li" sx={SECTION_LABEL_SX}>Investigation</Typography>
        <ListItemButton
          onClick={() => setDataMenuOpen(!dataMenuOpen)}
          data-learn="Data: Access network traffic data including audit records, visualizations, hosts, devices, connections, and more."
          sx={SELECTED_MENU_ITEM_SX}
        >
          <ListItemIcon>
            <FolderIcon />
          </ListItemIcon>
          <ListItemText primary="Data" />
          {dataMenuOpen ? <ExpandLess /> : <ExpandMore />}
        </ListItemButton>
        <Collapse in={dataMenuOpen} timeout="auto" unmountOnExit>
          <List component="div" disablePadding>
            <Link href="/records" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/records')}
                data-learn="Records: Explore detailed network traffic records organized by protocol type with advanced filtering."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={auditRecordsCount} color="primary" max={999} sx={BADGE_SX}>
                    <StorageIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Records" />
              </ListItemButton>
            </Link>
            <Link href="/explore" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/explore')}
                data-learn="Explore: Create custom charts and time-series visualizations of audit record fields."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <BarChartIcon />
                </ListItemIcon>
                <ListItemText primary="Explore" />
              </ListItemButton>
            </Link>
            <Link href="/visualize" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/visualize')}
                data-learn="Visualize: Interactive protocol hierarchy flow diagram showing network traffic relationships."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <BubbleChartIcon />
                </ListItemIcon>
                <ListItemText primary="Visualize" />
              </ListItemButton>
            </Link>

            <Link href="/hosts" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/hosts')}
                data-learn="Hosts: Browse discovered network hosts with geolocation, device profiles, and communication patterns."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={hostsCount} color="primary" max={999} sx={BADGE_SX}>
                    <RouterIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Hosts" />
              </ListItemButton>
            </Link>
            <Link href="/devices" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/devices')}
                data-learn="Devices: View hardware devices identified by MAC addresses, vendors, and network layer information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={devicesCount} color="primary" max={999} sx={BADGE_SX}>
                    <DevicesIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Devices" />
              </ListItemButton>
            </Link>
            <Link href="/connections" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/connections')}
                data-learn="Connections: View network connections with protocol analysis, traffic statistics, and flow information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={connectionsCount} color="primary" max={999} sx={BADGE_SX}>
                    <SyncAltIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Connections" />
              </ListItemButton>
            </Link>
            <Link href="/http" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/http')}
                data-learn="HTTP: View HTTP requests and responses with headers, status codes, URLs, and content information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={httpCount} color="primary" max={999} sx={BADGE_SX}>
                    <HttpIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="HTTP" />
              </ListItemButton>
            </Link>
            <Link href="/certificates" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/certificates')}
                data-learn="Certificates: View TLS/SSL certificates with subject, issuer, expiration status, and security information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={certificatesCount} color="primary" max={999} sx={BADGE_SX}>
                    <BadgeIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Certificates" />
              </ListItemButton>
            </Link>
            <Link href="/secrets" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/secrets')}
                data-learn="Secrets: View captured secrets from network traffic."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={secretCount} color="primary" max={999} sx={BADGE_SX}>
                    <VpnKeyIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Secrets" />
              </ListItemButton>
            </Link>
            <Link href="/services" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/services')}
                data-learn="Services: View discovered network services with protocol detection and version information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={servicesCount} color="primary" max={999} sx={BADGE_SX}>
                    <DnsIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Services" />
              </ListItemButton>
            </Link>
            <Link href="/domains" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/domains')}
                data-learn="Domains: View DNS domains discovered in traffic with query statistics."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={domainsCount} color="primary" max={999} sx={BADGE_SX}>
                    <LanguageIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Domains" />
              </ListItemButton>
            </Link>
            <Link href="/fingerprints" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/fingerprints')}
                data-learn="Fingerprints: View device and application fingerprints including JA3, HASSH, and DHCP."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={fingerprintsCount} color="primary" max={999} sx={BADGE_SX}>
                    <FingerprintIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Fingerprints" />
              </ListItemButton>
            </Link>
            <Link href="/software" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/software')}
                data-learn="Software: Browse detected software products, versions, and operating systems."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={softwareCount} color="primary" max={999} sx={BADGE_SX}>
                    <AppsIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Software" />
              </ListItemButton>
            </Link>
            <Link href="/vulnerabilities" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/vulnerabilities')}
                data-learn="Vulnerabilities: Review discovered vulnerabilities with severity ratings."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={vulnerabilitiesCount} color="primary" max={999} sx={BADGE_SX}>
                    <BugReportIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Vulnerabilities" />
              </ListItemButton>
            </Link>
            <Link href="/alerts" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/alerts')}
                data-learn="Alerts: Review security alerts triggered by detection rules."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={alertCount} color="error" max={999} sx={BADGE_SX}>
                    <NotificationsActiveIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Alerts" />
              </ListItemButton>
            </Link>
            <Link href="/files" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/files')}
                data-learn="Files: Access files extracted from network streams."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={extractedFilesCount} color="primary" max={999} sx={BADGE_SX}>
                    <InsertDriveFileIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Files" />
              </ListItemButton>
            </Link>
            {renderNavigationItems('data-before-logs', true)}
            <Link href="/logs" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/logs')}
                data-learn="Logs: View system logs and processing information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={logsCount} color="primary" max={999} sx={BADGE_SX}>
                    <DescriptionIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Logs" />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>
        <Typography component="li" sx={SECTION_LABEL_SX}>Detection</Typography>
        <Link href="/rules" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/rules')}
            data-learn="Create and manage detection rules using expression-based filtering."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <RuleIcon />
            </ListItemIcon>
            <ListItemText primary="Rules" />
          </ListItemButton>
        </Link>
        <Link href="/rulesets" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/rulesets')}
            data-learn="Organize detection rules into collections for different security scenarios."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <LibraryBooksIcon />
            </ListItemIcon>
            <ListItemText primary="Rule Sets" />
          </ListItemButton>
        </Link>
        {renderNavigationItems('detection-end')}
        <Typography component="li" sx={SECTION_LABEL_SX}>System</Typography>
        {renderNavigationItems('system-start')}
        <Link href="/decoders" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/decoders')}
            data-learn="Enable or disable packet and stream decoders."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <AccountTreeIcon />
            </ListItemIcon>
            <ListItemText primary="Decoders" />
          </ListItemButton>
        </Link>
        <Link href="/protobuf" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/protobuf')}
            data-learn="Protobuf Schemas: Manage .proto schema files for decoding Protocol Buffer traffic."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <CodeIcon />
            </ListItemIcon>
            <ListItemText primary="Protobuf Schemas" />
          </ListItemButton>
        </Link>
        <Link href="/harvesters" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/harvesters')}
            data-learn="View credential harvesters that extract authentication data."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <VpnKeyIcon />
            </ListItemIcon>
            <ListItemText primary="Harvesters" />
          </ListItemButton>
        </Link>
        {renderNavigationItems('system-before-bpf')}
        <Link href="/bpf" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/bpf')}
            data-learn="Apply Berkeley Packet Filter expressions to capture specific traffic."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <FilterAltIcon />
            </ListItemIcon>
            <ListItemText primary="BPF Filters" />
          </ListItemButton>
        </Link>
        <Link href="/errors" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/errors')}
            data-learn="Review processing errors and troubleshooting information."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <ErrorOutlineIcon />
            </ListItemIcon>
            <ListItemText primary="Errors" />
          </ListItemButton>
        </Link>
        <Link href="/config" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/config')}
            data-learn="Adjust system configuration settings."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <SettingsIcon />
            </ListItemIcon>
            <ListItemText primary="Config" />
          </ListItemButton>
        </Link>
        {renderNavigationItems('settings')}
      </List>
      {version && (
        <Box sx={VERSION_BOX_SX}>
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
                <Box component="span" sx={VERSION_LINK_HOVER_SX}>
                  {version.commit}
                </Box>
              </Link>
            </Typography>
            <Box sx={{ display: 'flex', gap: 0.5 }}>
              <LearnModeToggle size="small" />
              <IconButton
                data-learn="Documentation: Open the official Netcap documentation."
                size="small"
                href="https://docs.netcap.io"
                target="_blank"
                rel="noopener noreferrer"
                sx={ICON_BUTTON_SX}
                title="Documentation"
              >
                <MenuBookIcon fontSize="small" />
              </IconButton>
              <IconButton
                data-learn="GitHub Repository: View the Netcap source code."
                size="small"
                href="https://github.com/dreadl0ck/netcap"
                target="_blank"
                rel="noopener noreferrer"
                sx={ICON_BUTTON_SX}
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
          width: { lg: `calc(100% - ${drawerWidth}px)` },
          ml: { lg: `${drawerWidth}px` },
        }}
      >
        <Toolbar
          sx={{
            minHeight: { xs: 'auto', sm: 72 },
            py: { xs: 0.5, sm: 1 },
            display: { xs: 'flex', sm: 'grid' },
            gridTemplateColumns: {
              sm: headerAction
                ? 'auto minmax(0, 1fr) minmax(180px, 300px) auto'
                : 'auto minmax(0, 1fr) auto',
              md: headerAction
                ? 'auto minmax(0, 1fr) minmax(260px, 400px) auto'
                : 'auto minmax(0, 1fr) auto',
              lg: headerAction
                ? 'minmax(180px, 1fr) minmax(300px, 400px) auto'
                : 'minmax(180px, 1fr) auto',
            },
            alignItems: 'center',
            gap: { xs: 0.5, sm: 2 },
          }}
        >
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: { xs: 1, sm: 2 }, display: { lg: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Box sx={{ flexGrow: { xs: 1, sm: 0 }, minWidth: 0 }}>
            <Typography variant="h5" noWrap component="h1" sx={{ fontSize: { xs: '1rem', sm: '1.05rem' } }}>
              {title}
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: { xs: 'none', sm: 'block' }, fontFamily: 'var(--netcap-mono)' }}>
              Network traffic intelligence
            </Typography>
          </Box>
          {headerAction && !isMobile && (
            <Box sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              minWidth: 0,
              width: '100%',
              '& > *': { width: '100%', maxWidth: '400px' },
            }}>
              {headerAction}
            </Box>
          )}
          <IconButton
            onClick={toggleFullscreen}
            aria-label={isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'}
            title={isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'}
            sx={{ color: 'text.secondary', justifySelf: 'end', flexShrink: 0 }}
          >
            {isFullscreen ? <FullscreenExitIcon /> : <FullscreenIcon />}
          </IconButton>
        </Toolbar>
        {headerAction && isMobile && (
          <Box sx={{
            px: 1,
            py: 0.5,
            display: 'flex',
            alignItems: 'center',
            borderTop: '1px solid',
            borderColor: 'divider',
          }}>
            {headerAction}
          </Box>
        )}
      </AppBar>
      <Box
        component="nav"
        sx={{ width: { lg: drawerWidth }, flexShrink: { lg: 0 } }}
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
            display: { xs: 'block', lg: 'none' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', lg: 'block' },
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
          p: { xs: 2, sm: 3, xl: 4 },
          pb: { xs: '72px', sm: '72px', md: 3 },
          width: { lg: `calc(100% - ${drawerWidth}px)` },
          minWidth: 0,
          overflowX: 'hidden',
          pt: defaultTopPadding,
          maxWidth: '1800px',
          mx: 'auto',
        }}
      >
        <CommunityIDFilterBar />
        {children}
      </Box>
      <MobileBottomNav onMoreClick={handleDrawerToggle} />
      <LearnModeOverlay />
    </Box>
  );
}

export default Layout;
