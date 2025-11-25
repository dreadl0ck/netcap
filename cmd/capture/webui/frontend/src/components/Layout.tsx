import { useState, useEffect } from 'react';
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
import DataObjectIcon from '@mui/icons-material/DataObject';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import SettingsIcon from '@mui/icons-material/Settings';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import DevicesIcon from '@mui/icons-material/Devices';
import RouterIcon from '@mui/icons-material/Router';
import CableIcon from '@mui/icons-material/Cable';
import SyncAltIcon from '@mui/icons-material/SyncAlt';
import BuildIcon from '@mui/icons-material/Build';
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
import SearchIcon from '@mui/icons-material/Search';
import HttpIcon from '@mui/icons-material/Http';
import BadgeIcon from '@mui/icons-material/Badge';
import ManageSearchIcon from '@mui/icons-material/ManageSearch';
import LibraryBooksIcon from '@mui/icons-material/LibraryBooks';
import Link from 'next/link';
import { useRouter } from 'next/router';
import useSWR from 'swr';
import { api } from '@/lib/api';
import LearnModeToggle from './LearnModeToggle';
import LearnModeOverlay from './LearnModeOverlay';

const drawerWidth = 240;

// Extracted sx styles to prevent object recreation on every render
// This is a critical performance optimization for the navigation menu
const SELECTED_MENU_ITEM_SX = {
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
};

const BADGE_SX = {
  '& .MuiBadge-badge': {
    right: -3,
    top: 3,
  },
};

const LINK_STYLE = { textDecoration: 'none', color: 'inherit' };

const TOOLBAR_LOGO_SX = {
  color: 'primary.main',
  fontWeight: 'bold',
  cursor: 'pointer',
  lineHeight: 1.2,
  '&:hover': {
    color: 'primary.dark',
  },
};

const SERVICE_MODE_CAPTION_SX = {
  color: 'text.secondary',
  fontSize: '0.65rem',
  fontWeight: 500,
  letterSpacing: '0.1em',
  mt: -0.5,
};

const VERSION_BOX_SX = {
  p: 2,
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

interface LayoutProps {
  children: React.ReactNode;
  title: string;
  headerAction?: React.ReactNode;
  /** Optional custom top padding override. If not provided, uses responsive defaults based on screen size and headerAction. */
  topPadding?: string | { xs?: string; sm?: string; md?: string; lg?: string };
}

export default function Layout({ children, title, headerAction, topPadding }: LayoutProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const router = useRouter();
  
  // Initialize dataMenuOpen based on current route to prevent re-rendering
  const [dataMenuOpen, setDataMenuOpen] = useState(() => {
    const dataRoutes = ['/records', '/explore', '/visualize', '/hosts', '/devices', '/connections', '/http', '/certificates', '/credentials',
                        '/services', '/domains', '/fingerprints', '/software', '/vulnerabilities', '/alerts', '/files', '/logs'];
    return dataRoutes.some(route => router.pathname.startsWith(route));
  });

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

  // Fetch alert statistics for badge
  const { data: alertStats, mutate: mutateAlertStats } = useSWR('alertStats', () => api.getAlertStats(), {
    refreshInterval: 10000, // Refresh every 10 seconds
  });

  // Fetch extracted files for badge
  const { data: extractedFilesData, mutate: mutateExtractedFiles } = useSWR('extractedFiles', () => api.getExtractedFiles(), {
    refreshInterval: 10000, // Refresh every 10 seconds
  });

  // Fetch error logs for badge
  const { data: errorLogs, mutate: mutateErrorLogs } = useSWR('errorLogs', () => api.getErrorLogs(), {
    refreshInterval: 10000, // Refresh every 10 seconds
  });

  // Fetch counts for Data menu items - only load once and cache, no auto-refresh
  // These counts are static once data is processed and only change when a new PCAP is analyzed
  const { data: auditRecordsCount, mutate: mutateAuditRecordsCount } = useSWR('auditRecordsCount', () => api.getAuditRecordsCount(), {
    refreshInterval: 0, // No auto-refresh
    revalidateOnFocus: false, // Don't refetch when window regains focus
    revalidateOnReconnect: false, // Don't refetch on reconnect
  });

  const { data: hostsCount, mutate: mutateHostsCount } = useSWR('hostsCount', () => api.getHostsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: devicesCount, mutate: mutateDevicesCount } = useSWR('devicesCount', () => api.getDevicesCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: connectionsCount, mutate: mutateConnectionsCount } = useSWR('connectionsCount', () => api.getConnectionsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: httpCount, mutate: mutateHTTPCount } = useSWR('httpCount', () => api.getHTTPCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: certificatesCount, mutate: mutateCertificatesCount } = useSWR('certificatesCount', () => api.getCertificatesCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: credentialsCount, mutate: mutateCredentialsCount } = useSWR('credentialsCount', () => api.getCredentialsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: domainsCount, mutate: mutateDomainsCount } = useSWR('domainsCount', () => api.getDomainsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: fingerprintsCount, mutate: mutateFingerprintsCount } = useSWR('fingerprintsCount', () => api.getFingerprintsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: softwareCount, mutate: mutateSoftwareCount } = useSWR('softwareCount', () => api.getSoftwareCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: vulnerabilitiesCount, mutate: mutateVulnerabilitiesCount } = useSWR('vulnerabilitiesCount', () => api.getVulnerabilitiesCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: servicesCount, mutate: mutateServicesCount } = useSWR('servicesCount', () => api.getServicesCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  const { data: logsCount, mutate: mutateLogsCount } = useSWR('logsCount', () => api.getLogsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
  });

  // Calculate total PCAP count (including preloaded and user files)
  const pcapCount = inputFiles?.length || 0;
  
  // Get alert group count for badge (not individual alerts)
  const alertCount = alertStats?.groupCount || 0;

  // Get total extracted files count
  const extractedFilesCount = extractedFilesData?.totalCount || 0;

  // Get total error logs count
  const errorLogsCount = errorLogs?.length || 0;

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      // Enter fullscreen mode
      document.documentElement.requestFullscreen().then(() => {
        setIsFullscreen(true);
      }).catch((err) => {
        console.error('Failed to enter fullscreen:', err);
      });
    } else {
      // Exit fullscreen mode
      document.exitFullscreen().then(() => {
        setIsFullscreen(false);
      }).catch((err) => {
        console.error('Failed to exit fullscreen:', err);
      });
    }
  };

  // Helper function to check if a path is currently active
  const isActive = (path: string) => {
    if (path === '/') {
      return router.pathname === '/';
    }
    // Exact match for /rules to prevent matching /rulesets
    if (path === '/rules') {
      return router.pathname === '/rules';
    }
    return router.pathname.startsWith(path);
  };

  // Auto-expand Data menu when navigating to data routes, but don't auto-collapse when leaving
  useEffect(() => {
    const dataRoutes = ['/records', '/explore', '/visualize', '/hosts', '/devices', '/connections', '/http', '/certificates', '/credentials',
                        '/services', '/domains', '/fingerprints', '/software', '/vulnerabilities', '/alerts', '/files', '/logs'];
    const isDataRoute = dataRoutes.some(route => router.pathname.startsWith(route));
    
    // Only auto-expand when navigating to a data route, never auto-collapse
    if (isDataRoute) {
      setDataMenuOpen(true);
    }
  }, [router.pathname]);

  // Listen for directory-changed events to refresh alert stats, extracted files, and error logs count
  useEffect(() => {
    const handleDirectoryChanged = () => {
      // Refresh alert statistics, extracted files, and error logs count when the capture file changes
      mutateAlertStats();
      mutateExtractedFiles();
      mutateErrorLogs();
      // Also refresh all data menu counts since new data was processed
      mutateAuditRecordsCount();
      mutateHostsCount();
      mutateDevicesCount();
      mutateConnectionsCount();
      mutateHTTPCount();
      mutateCertificatesCount();
      mutateCredentialsCount();
      mutateDomainsCount();
      mutateFingerprintsCount();
      mutateSoftwareCount();
      mutateVulnerabilitiesCount();
      mutateServicesCount();
      mutateLogsCount();
    };

    window.addEventListener('directory-changed', handleDirectoryChanged);
    return () => {
      window.removeEventListener('directory-changed', handleDirectoryChanged);
    };
  }, [mutateAlertStats, mutateExtractedFiles, mutateErrorLogs, mutateAuditRecordsCount, mutateHostsCount, mutateDevicesCount, mutateConnectionsCount, mutateHTTPCount, mutateCertificatesCount, mutateCredentialsCount, mutateServicesCount, mutateDomainsCount, mutateFingerprintsCount, mutateSoftwareCount, mutateVulnerabilitiesCount, mutateLogsCount]);

  // Handle ESC key to exit fullscreen and listen for fullscreen change events
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && document.fullscreenElement) {
        document.exitFullscreen();
      }
    };

    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('fullscreenchange', handleFullscreenChange);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('fullscreenchange', handleFullscreenChange);
    };
  }, []);


  // Calculate default top padding based on whether headerAction exists
  const defaultTopPadding = topPadding || {
    xs: headerAction ? '140px' : '80px',  // Mobile: more space when header has actions
    sm: headerAction ? '120px' : '88px',  // Tablet: moderate space
    md: '88px',                            // Desktop: header doesn't wrap
  };

  const drawer = (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Toolbar sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box 
          onClick={toggleFullscreen}
          sx={{ 
            textDecoration: 'none', 
            flexGrow: 1,
            cursor: 'pointer',
          }}
        >
          <Box>
            <Typography 
              variant="h6" 
              noWrap 
              component="div" 
              sx={TOOLBAR_LOGO_SX}
            >
              NETCAP
            </Typography>
            {status?.isServiceMode && (
              <Typography 
                variant="caption" 
                component="div"
                sx={SERVICE_MODE_CAPTION_SX}
              >
                SERVICE
              </Typography>
            )}
            {status && !status?.isTryService && !status?.isServiceMode && (
              <Typography 
                variant="caption" 
                component="div"
                sx={SERVICE_MODE_CAPTION_SX}
              >
                LOCAL
              </Typography>
            )}
          </Box>
        </Box>
        <LearnModeToggle />
      </Toolbar>
      <List sx={{ flexGrow: 1 }}>
        <Link href="/" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/')}
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
            selected={isActive('/analyze')}
            data-learn="Analyze: Upload and process PCAP files to extract network traffic information and generate audit records."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <CloudUploadIcon />
            </ListItemIcon>
            <ListItemText primary="Analyze" />
          </ListItemButton>
        </Link>
        <Link href="/interfaces" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/interfaces')}
            data-learn="View available network interfaces for live packet capture and monitoring."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <NetworkCheckIcon />
            </ListItemIcon>
            <ListItemText primary="Interfaces" />
          </ListItemButton>
        </Link>
        <Link href="/pcaps" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/pcaps')}
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
                selected={isActive('/records')}
                data-learn="Records: Explore detailed network traffic records organized by protocol type with advanced filtering."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={auditRecordsCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <StorageIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Records" />
              </ListItemButton>
            </Link>
            <Link href="/explore" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/explore')}
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
                selected={isActive('/visualize')}
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
                selected={isActive('/hosts')}
                data-learn="Hosts: Browse discovered network hosts with geolocation, device profiles, and communication patterns."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={hostsCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <RouterIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Hosts" />
              </ListItemButton>
            </Link>
            <Link href="/devices" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/devices')}
                data-learn="Devices: View hardware devices identified by MAC addresses, vendors, and network layer information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={devicesCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <DevicesIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Devices" />
              </ListItemButton>
            </Link>
            <Link href="/connections" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/connections')}
                data-learn="Connections: View network connections with protocol analysis, traffic statistics, and flow information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={connectionsCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <SyncAltIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Connections" />
              </ListItemButton>
            </Link>
            <Link href="/http" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/http')}
                data-learn="HTTP: View HTTP requests and responses with headers, status codes, URLs, and content information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={httpCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <HttpIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="HTTP" />
              </ListItemButton>
            </Link>
            <Link href="/certificates" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/certificates')}
                data-learn="Certificates: View TLS/SSL certificates with subject, issuer, expiration status, and security information."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={certificatesCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <BadgeIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Certificates" />
              </ListItemButton>
            </Link>
            <Link href="/credentials" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/credentials')}
                data-learn="Credentials: View captured credentials from network traffic including usernames, passwords, and authentication attempts."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={credentialsCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <VpnKeyIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Credentials" />
              </ListItemButton>
            </Link>
            <Link href="/services" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/services')}
                data-learn="Services: View discovered network services with protocol detection, version information, and traffic statistics."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={servicesCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <DnsIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Services" />
              </ListItemButton>
            </Link>
            <Link href="/domains" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/domains')}
                data-learn="Domains: View DNS domains discovered in traffic with query statistics, TLD distribution, and resolved IP addresses."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={domainsCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <LanguageIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Domains" />
              </ListItemButton>
            </Link>
            <Link href="/fingerprints" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/fingerprints')}
                data-learn="Fingerprints: View device and application fingerprints including JA3 (TLS), HASSH (SSH), and DHCP fingerprinting results."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={fingerprintsCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <FingerprintIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Fingerprints" />
              </ListItemButton>
            </Link>
            <Link href="/software" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/software')}
                data-learn="Software: Browse detected software products, versions, and operating systems identified in the traffic."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={softwareCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <AppsIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Software" />
              </ListItemButton>
            </Link>
            <Link href="/vulnerabilities" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/vulnerabilities')}
                data-learn="Vulnerabilities: Review discovered vulnerabilities and applicable exploits with severity ratings and affected hosts."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={vulnerabilitiesCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <BugReportIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Vulnerabilities" />
              </ListItemButton>
            </Link>
            <Link href="/alerts" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/alerts')}
                data-learn="Alerts: Review security alerts triggered by detection rules with severity levels and details."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={alertCount} 
                    color="error"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <NotificationsActiveIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Alerts" />
              </ListItemButton>
            </Link>
            <Link href="/files" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/files')}
                data-learn="Files: Access files extracted from network streams (HTTP, FTP, SMTP) with metadata and hashes."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={extractedFilesCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <InsertDriveFileIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Files" />
              </ListItemButton>
            </Link>
            <Link href="/logs" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={isActive('/logs')}
                data-learn="Logs: View system logs, processing information, and debug output from Netcap operations."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge 
                    badgeContent={logsCount} 
                    color="primary"
                    max={999}
                    sx={BADGE_SX}
                  >
                    <DescriptionIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Logs" />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>
        <Link href="/rules" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/rules')}
            data-learn="Create and manage detection rules using expression-based filtering to identify network anomalies."
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
            selected={isActive('/rulesets')}
            data-learn="Organize detection rules into collections for different security scenarios and threat models."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <LibraryBooksIcon />
            </ListItemIcon>
            <ListItemText primary="Rule Sets" />
          </ListItemButton>
        </Link>
        <Link href="/dbs" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/dbs')}
            data-learn="Manage GeoIP, vulnerability, and MAC vendor databases for enriched traffic analysis."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <DataObjectIcon />
            </ListItemIcon>
            <ListItemText primary="Databases" />
          </ListItemButton>
        </Link>
        <Link href="/dpi" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/dpi')}
            data-learn="Configure Deep Packet Inspection modules for advanced protocol detection and analysis."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <ManageSearchIcon />
            </ListItemIcon>
            <ListItemText primary="DPI" />
          </ListItemButton>
        </Link>
        <Link href="/decoders" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/decoders')}
            data-learn="Enable or disable packet and stream decoders for specific protocols and layers."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <AccountTreeIcon />
            </ListItemIcon>
            <ListItemText primary="Decoders" />
          </ListItemButton>
        </Link>
        <Link href="/harvesters" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/harvesters')}
            data-learn="View credential harvesters that extract authentication data from various protocols."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <VpnKeyIcon />
            </ListItemIcon>
            <ListItemText primary="Harvesters" />
          </ListItemButton>
        </Link>
        <Link href="/probes" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/probes')}
            data-learn="Manage nmap service probes for network service fingerprinting and identification."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <SearchIcon />
            </ListItemIcon>
            <ListItemText primary="Service Probes" />
          </ListItemButton>
        </Link>
        <Link href="/bpf" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/bpf')}
            data-learn="BPF Apply Berkeley Packet Filter expressions to capture specific network traffic."
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
            selected={isActive('/errors')}
            data-learn="Review processing errors, failed packets, and troubleshooting information."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <Badge 
                badgeContent={errorLogsCount} 
                color="error"
                max={999}
                sx={BADGE_SX}
              >
                <ErrorOutlineIcon />
              </Badge>
            </ListItemIcon>
            <ListItemText primary="Errors" />
          </ListItemButton>
        </Link>
        <Link href="/config" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={isActive('/config')}
            data-learn="Adjust system configuration settings, debug mode, and processing parameters."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <SettingsIcon />
            </ListItemIcon>
            <ListItemText primary="Config" />
          </ListItemButton>
        </Link>
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
              <IconButton
                data-learn="Documentation: Open the official Netcap documentation to learn about features, usage, configuration, and best practices."
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
                data-learn="GitHub Repository: View the Netcap source code, report issues, contribute to development, and access the latest updates."
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
            minHeight: { xs: 'auto', sm: 64 },
            py: { xs: 1, sm: 0 },
            flexDirection: { xs: 'column', md: 'row' },
            alignItems: { xs: 'flex-start', md: 'center' },
            gap: { xs: 1, md: 0 },
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', width: { xs: '100%', md: 'auto' } }}>
            <IconButton
              color="inherit"
              aria-label="open drawer"
              edge="start"
              onClick={handleDrawerToggle}
              sx={{ mr: 2, display: { lg: 'none' } }}
            >
              <MenuIcon />
            </IconButton>
            <Typography variant="h6" noWrap component="div" sx={{ flexGrow: headerAction ? 0 : 1 }}>
              {title}
            </Typography>
          </Box>
          {headerAction && (
            <Box sx={{ 
              ml: { xs: 0, md: 'auto' },
              width: { xs: '100%', md: 'auto' },
              display: 'flex', 
              alignItems: 'center',
              flexGrow: { xs: 1, md: 0 },
            }}>
              {headerAction}
            </Box>
          )}
        </Toolbar>
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
          p: { xs: 2, sm: 3 },
          width: { lg: `calc(100% - ${drawerWidth}px)` },
          minWidth: 0, // Allow shrinking below content size
          overflowX: 'hidden', // Prevent horizontal scroll
          // Top padding ensures header never overlaps main content
          // Can be customized per-page via topPadding prop
          pt: defaultTopPadding,
        }}
      >
        {children}
      </Box>
      <LearnModeOverlay />
    </Box>
  );
}

