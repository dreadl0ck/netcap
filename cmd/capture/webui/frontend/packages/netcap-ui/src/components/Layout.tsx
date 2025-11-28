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
import SearchIcon from '@mui/icons-material/Search';
import HttpIcon from '@mui/icons-material/Http';
import BadgeIcon from '@mui/icons-material/Badge';
import ManageSearchIcon from '@mui/icons-material/ManageSearch';
import LibraryBooksIcon from '@mui/icons-material/LibraryBooks';
import BoltIcon from '@mui/icons-material/Bolt';
import useSWR from 'swr';

import { useNetcapRouter } from '../hooks/useNetcapRouter';
import { useNetcapApi } from '../hooks/useNetcapApi';
import { useNetcapLink } from '../providers/NetcapProvider';
import LearnModeToggle from './LearnModeToggle';
import LearnModeOverlay from './LearnModeOverlay';

const drawerWidth = 240;

// Extracted sx styles to prevent object recreation on every render
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
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const Link = useNetcapLink();
  
  // Initialize dataMenuOpen based on current route
  const [dataMenuOpen, setDataMenuOpen] = useState(() => {
    const dataRoutes = ['/records', '/explore', '/visualize', '/hosts', '/devices', '/connections', '/http', '/certificates', '/credentials',
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

  // Fetch alert statistics
  const { data: alertStats, mutate: mutateAlertStats } = useSWR('alertStats', () => api.getAlertStats(), {
    refreshInterval: 10000,
  });

  // Fetch extracted files
  const { data: extractedFilesData, mutate: mutateExtractedFiles } = useSWR('extractedFiles', () => api.getExtractedFiles(), {
    refreshInterval: 10000,
  });

  // Fetch counts for badges
  const { data: auditRecordsCount, mutate: mutateAuditRecordsCount } = useSWR('auditRecordsCount', () => api.getAuditRecordsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: hostsCount, mutate: mutateHostsCount } = useSWR('hostsCount', () => api.getHostsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: devicesCount, mutate: mutateDevicesCount } = useSWR('devicesCount', () => api.getDevicesCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: connectionsCount, mutate: mutateConnectionsCount } = useSWR('connectionsCount', () => api.getConnectionsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: httpCount, mutate: mutateHTTPCount } = useSWR('httpCount', () => api.getHTTPCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: certificatesCount, mutate: mutateCertificatesCount } = useSWR('certificatesCount', () => api.getCertificatesCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: credentialsCount, mutate: mutateCredentialsCount } = useSWR('credentialsCount', () => api.getCredentialsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: domainsCount, mutate: mutateDomainsCount } = useSWR('domainsCount', () => api.getDomainsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: fingerprintsCount, mutate: mutateFingerprintsCount } = useSWR('fingerprintsCount', () => api.getFingerprintsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: softwareCount, mutate: mutateSoftwareCount } = useSWR('softwareCount', () => api.getSoftwareCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: vulnerabilitiesCount, mutate: mutateVulnerabilitiesCount } = useSWR('vulnerabilitiesCount', () => api.getVulnerabilitiesCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: servicesCount, mutate: mutateServicesCount } = useSWR('servicesCount', () => api.getServicesCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const { data: logsCount, mutate: mutateLogsCount } = useSWR('logsCount', () => api.getLogsCount(), {
    refreshInterval: 0,
    revalidateOnFocus: false,
  });

  const pcapCount = inputFiles?.length || 0;
  const alertCount = alertStats?.groupCount || 0;
  const extractedFilesCount = extractedFilesData?.totalCount || 0;

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
    const dataRoutes = ['/records', '/explore', '/visualize', '/hosts', '/devices', '/connections', '/http', '/certificates', '/credentials',
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
      mutateExtractedFiles();
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
  }, [mutateAlertStats, mutateExtractedFiles, mutateAuditRecordsCount, mutateHostsCount, mutateDevicesCount, mutateConnectionsCount, mutateHTTPCount, mutateCertificatesCount, mutateCredentialsCount, mutateServicesCount, mutateDomainsCount, mutateFingerprintsCount, mutateSoftwareCount, mutateVulnerabilitiesCount, mutateLogsCount]);

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
    xs: headerAction ? '140px' : '80px',
    sm: headerAction ? '120px' : '88px',
    md: '88px',
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
          <Box sx={status?.logoSubText ? { padding: '7px 0px 0px 50px' } : undefined}>
            <Typography 
              variant="h6" 
              noWrap 
              component="div" 
              sx={TOOLBAR_LOGO_SX}
            >
              NETCAP
            </Typography>
            {status?.logoSubText ? (
              <Typography 
                variant="caption" 
                component="div"
                sx={SERVICE_MODE_CAPTION_SX}
              >
                {status.logoSubText}
              </Typography>
            ) : status?.isServiceMode ? (
              <Typography 
                variant="caption" 
                component="div"
                sx={SERVICE_MODE_CAPTION_SX}
              >
                SERVICE
              </Typography>
            ) : status && !status?.isTryService && (
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
        <Link href="/interfaces" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/interfaces')}
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
            <Link href="/credentials" passHref style={LINK_STYLE}>
              <ListItemButton
                selected={router.isActive('/credentials')}
                data-learn="Credentials: View captured credentials from network traffic."
                sx={{ ...SELECTED_MENU_ITEM_SX, pl: 4 }}
              >
                <ListItemIcon>
                  <Badge badgeContent={credentialsCount} color="primary" max={999} sx={BADGE_SX}>
                    <VpnKeyIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Credentials" />
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
        <Link href="/inject" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/inject')}
            data-learn="Configure packet injection and manipulation rules."
            sx={SELECTED_MENU_ITEM_SX}
          >
            <ListItemIcon>
              <BoltIcon />
            </ListItemIcon>
            <ListItemText primary="Inject" />
          </ListItemButton>
        </Link>
        <Link href="/dbs" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/dbs')}
            data-learn="Manage GeoIP, vulnerability, and MAC vendor databases."
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
            selected={router.isActive('/dpi')}
            data-learn="Configure Deep Packet Inspection modules."
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
        <Link href="/probes" passHref style={LINK_STYLE}>
          <ListItemButton
            selected={router.isActive('/probes')}
            data-learn="Manage nmap service probes for service fingerprinting."
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
          minWidth: 0,
          overflowX: 'hidden',
          pt: defaultTopPadding,
        }}
      >
        {children}
      </Box>
      <LearnModeOverlay />
    </Box>
  );
}

export default Layout;


