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
import SecurityIcon from '@mui/icons-material/Security';
import SettingsIcon from '@mui/icons-material/Settings';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import DevicesIcon from '@mui/icons-material/Devices';
import RouterIcon from '@mui/icons-material/Router';
import CableIcon from '@mui/icons-material/Cable';
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
import Link from 'next/link';
import { useRouter } from 'next/router';
import useSWR from 'swr';
import { api } from '@/lib/api';
import LearnModeToggle from './LearnModeToggle';
import LearnModeOverlay from './LearnModeOverlay';

const drawerWidth = 240;

interface LayoutProps {
  children: React.ReactNode;
  title: string;
  headerAction?: React.ReactNode;
  /** Optional custom top padding override. If not provided, uses responsive defaults based on screen size and headerAction. */
  topPadding?: string | { xs?: string; sm?: string; md?: string; lg?: string };
}

export default function Layout({ children, title, headerAction, topPadding }: LayoutProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const router = useRouter();
  
  // Initialize dataMenuOpen based on current route to prevent re-rendering
  const [dataMenuOpen, setDataMenuOpen] = useState(() => {
    const dataRoutes = ['/audit', '/explore', '/visualize', '/hosts', '/devices', '/connections', 
                        '/domains', '/fingerprints', '/software', '/vulnerabilities', '/alerts', '/files'];
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

  // Keep Data menu open when navigating between data routes, close when leaving
  useEffect(() => {
    const dataRoutes = ['/audit', '/explore', '/visualize', '/hosts', '/devices', '/connections', 
                        '/domains', '/fingerprints', '/software', '/vulnerabilities', '/alerts', '/files'];
    const isDataRoute = dataRoutes.some(route => router.pathname.startsWith(route));
    
    // Only update state if it needs to change to prevent unnecessary re-renders
    setDataMenuOpen(prevState => {
      if (prevState !== isDataRoute) {
        return isDataRoute;
      }
      return prevState;
    });
  }, [router.pathname]);

  // Listen for directory-changed events to refresh alert stats, extracted files, and error logs count
  useEffect(() => {
    const handleDirectoryChanged = () => {
      // Refresh alert statistics, extracted files, and error logs count when the capture file changes
      mutateAlertStats();
      mutateExtractedFiles();
      mutateErrorLogs();
    };

    window.addEventListener('directory-changed', handleDirectoryChanged);
    return () => {
      window.removeEventListener('directory-changed', handleDirectoryChanged);
    };
  }, [mutateAlertStats, mutateExtractedFiles, mutateErrorLogs]);

  // Calculate default top padding based on whether headerAction exists
  const defaultTopPadding = topPadding || {
    xs: headerAction ? '140px' : '80px',  // Mobile: more space when header has actions
    sm: headerAction ? '120px' : '88px',  // Tablet: moderate space
    md: '88px',                            // Desktop: header doesn't wrap
  };

  const drawer = (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Toolbar sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Link href="/analyze" passHref style={{ textDecoration: 'none', flexGrow: 1 }}>
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
        <LearnModeToggle />
      </Toolbar>
      <List sx={{ flexGrow: 1 }}>
        <Link href="/" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/')}
            data-learn="Dashboard: Overview of system status, processing statistics, and quick access to key metrics."
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
            data-learn="Analyze: Upload and process PCAP files to extract network traffic information and generate audit records."
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
            data-learn="View available network interfaces for live packet capture and monitoring."
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
            data-learn="Manage uploaded packet capture files, view processing status, and download results."
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
        <ListItemButton
          onClick={() => setDataMenuOpen(!dataMenuOpen)}
          data-learn="Data: Access network traffic data including audit records, visualizations, hosts, devices, connections, and more."
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
            <FolderIcon />
          </ListItemIcon>
          <ListItemText primary="Data" />
          {dataMenuOpen ? <ExpandLess /> : <ExpandMore />}
        </ListItemButton>
        <Collapse in={dataMenuOpen} timeout="auto" unmountOnExit>
          <List component="div" disablePadding>
            <Link href="/audit" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/audit')}
                data-learn="Audit Records: Explore detailed network traffic records organized by protocol type with advanced filtering."
                sx={{
                  pl: 4,
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
                data-learn="Explore: Create custom charts and time-series visualizations of audit record fields."
                sx={{
                  pl: 4,
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
                data-learn="Visualize: Interactive protocol hierarchy flow diagram showing network traffic relationships."
                sx={{
                  pl: 4,
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
            <Link href="/hosts" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/hosts')}
                data-learn="Hosts: Browse discovered network hosts with geolocation, device profiles, and communication patterns."
                sx={{
                  pl: 4,
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
                  <RouterIcon />
                </ListItemIcon>
                <ListItemText primary="Hosts" />
              </ListItemButton>
            </Link>
            <Link href="/devices" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/devices')}
                data-learn="Devices: View hardware devices identified by MAC addresses, vendors, and network layer information."
                sx={{
                  pl: 4,
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
                  <DevicesIcon />
                </ListItemIcon>
                <ListItemText primary="Devices" />
              </ListItemButton>
            </Link>
            <Link href="/connections" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/connections')}
                data-learn="Connections: View network connections with protocol analysis, traffic statistics, and flow information."
                sx={{
                  pl: 4,
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
                  <CableIcon />
                </ListItemIcon>
                <ListItemText primary="Connections" />
              </ListItemButton>
            </Link>
            <Link href="/domains" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/domains')}
                data-learn="Domains: View DNS domains discovered in traffic with query statistics, TLD distribution, and resolved IP addresses."
                sx={{
                  pl: 4,
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
                  <LanguageIcon />
                </ListItemIcon>
                <ListItemText primary="Domains" />
              </ListItemButton>
            </Link>
            <Link href="/fingerprints" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/fingerprints')}
                data-learn="Fingerprints: View device and application fingerprints including JA3 (TLS), HASSH (SSH), and DHCP fingerprinting results."
                sx={{
                  pl: 4,
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
                  <FingerprintIcon />
                </ListItemIcon>
                <ListItemText primary="Fingerprints" />
              </ListItemButton>
            </Link>
            <Link href="/software" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/software')}
                data-learn="Software: Browse detected software products, versions, and operating systems identified in the traffic."
                sx={{
                  pl: 4,
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
                  <AppsIcon />
                </ListItemIcon>
                <ListItemText primary="Software" />
              </ListItemButton>
            </Link>
            <Link href="/vulnerabilities" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/vulnerabilities')}
                data-learn="Vulnerabilities: Review discovered vulnerabilities and applicable exploits with severity ratings and affected hosts."
                sx={{
                  pl: 4,
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
                  <BugReportIcon />
                </ListItemIcon>
                <ListItemText primary="Vulnerabilities" />
              </ListItemButton>
            </Link>
            <Link href="/alerts" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/alerts')}
                data-learn="Alerts: Review security alerts triggered by detection rules with severity levels and details."
                sx={{
                  pl: 4,
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
                    badgeContent={alertCount} 
                    color="error"
                    max={999}
                    sx={{
                      '& .MuiBadge-badge': {
                        right: -3,
                        top: 3,
                      },
                    }}
                  >
                    <NotificationsActiveIcon />
                  </Badge>
                </ListItemIcon>
                <ListItemText primary="Alerts" />
              </ListItemButton>
            </Link>
            <Link href="/files" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
              <ListItemButton
                selected={isActive('/files')}
                data-learn="Files: Access files extracted from network streams (HTTP, FTP, SMTP) with metadata and hashes."
                sx={{
                  pl: 4,
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
                    badgeContent={extractedFilesCount} 
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
                <ListItemText primary="Files" />
              </ListItemButton>
            </Link>
          </List>
        </Collapse>
        <Link href="/rules" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/rules')}
            data-learn="Create and manage detection rules using expression-based filtering to identify network anomalies."
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
              <RuleIcon />
            </ListItemIcon>
            <ListItemText primary="Rules" />
          </ListItemButton>
        </Link>
        <Link href="/rulesets" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/rulesets')}
            data-learn="Organize detection rules into collections for different security scenarios and threat models."
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
            <ListItemText primary="Rule Sets" />
          </ListItemButton>
        </Link>
        <Link href="/dbs" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/dbs')}
            data-learn="Manage GeoIP, vulnerability, and MAC vendor databases for enriched traffic analysis."
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
            data-learn="Configure Deep Packet Inspection modules for advanced protocol detection and analysis."
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
            data-learn="Enable or disable packet and stream decoders for specific protocols and layers."
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
            data-learn="BPF Apply Berkeley Packet Filter expressions to capture specific network traffic."
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
        <Link href="/logs" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/logs')}
            data-learn="View system logs, processing information, and debug output from Netcap operations."
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
        <Link href="/errors" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/errors')}
            data-learn="Review processing errors, failed packets, and troubleshooting information."
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
                badgeContent={errorLogsCount} 
                color="error"
                max={999}
                sx={{
                  '& .MuiBadge-badge': {
                    right: -3,
                    top: 3,
                  },
                }}
              >
                <ErrorOutlineIcon />
              </Badge>
            </ListItemIcon>
            <ListItemText primary="Errors" />
          </ListItemButton>
        </Link>
        <Link href="/config" passHref style={{ textDecoration: 'none', color: 'inherit' }}>
          <ListItemButton
            selected={isActive('/config')}
            data-learn="Adjust system configuration settings, debug mode, and processing parameters."
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
                data-learn="Documentation: Open the official Netcap documentation to learn about features, usage, configuration, and best practices."
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
                data-learn="GitHub Repository: View the Netcap source code, report issues, contribute to development, and access the latest updates."
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

