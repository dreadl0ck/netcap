import { useState } from 'react';
import {
  Box,
  CircularProgress,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import { CheckCircle as CheckCircleIcon, Share as ShareIcon } from '@mui/icons-material';
import Layout from '@/components/Layout';
import { api } from '@/lib/api';
import useSWR from 'swr';

export default function Interfaces() {
  const { data: networkInterfaces, error } = useSWR('networkInterfaces', () => api.getNetworkInterfaces());
  const { data: status } = useSWR('status', () => api.getStatus());
  const [copiedInterface, setCopiedInterface] = useState<string | null>(null);

  const handleCopyInterfaceCommand = async (interfaceName: string) => {
    const command = `net capture -iface ${interfaceName} -out /path/to/output`;
    try {
      await navigator.clipboard.writeText(command);
      setCopiedInterface(interfaceName);
      setTimeout(() => setCopiedInterface(null), 2000);
    } catch (err) {
      console.error('Failed to copy command:', err);
    }
  };

  if (!networkInterfaces && !error) {
    return (
      <Layout title="Network Interfaces">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Network Interfaces">
        <Box>
          <Typography color="error">Error loading network interfaces</Typography>
        </Box>
      </Layout>
    );
  }

  // Check if we're in local mode (not try service)
  const isServiceMode = status?.isServiceMode === true;

  return (
    <Layout title="Network Interfaces">
      <Box sx={{ minWidth: 0 }}>
        {networkInterfaces && networkInterfaces.length > 0 ? (
          <>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {networkInterfaces.length} interface(s) available
            </Typography>
            <TableContainer component={Paper} sx={{ overflowX: 'auto', maxWidth: '100%' }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Index</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Flags</TableCell>
                    <TableCell>Hardware Address</TableCell>
                    <TableCell>IP Addresses</TableCell>
                    <TableCell align="right">MTU</TableCell>
                    {!isServiceMode && <TableCell align="right">Actions</TableCell>}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {networkInterfaces.map((iface) => (
                    <TableRow 
                      key={iface.index}
                      hover={!isServiceMode}
                      sx={{ 
                        cursor: isServiceMode ? 'default' : 'pointer',
                        opacity: isServiceMode ? 0.7 : 1
                      }}
                      onClick={isServiceMode ? undefined : () => handleCopyInterfaceCommand(iface.name)}
                    >
                      <TableCell>{iface.index}</TableCell>
                      <TableCell>
                        <Typography sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>
                          {iface.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {iface.flags}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                          {iface.hardwareAddr || 'N/A'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {iface.addrs && iface.addrs.length > 0 ? (
                          <Box>
                            {iface.addrs.map((addr) => (
                              <Typography 
                                key={addr} 
                                sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                              >
                                {addr}
                              </Typography>
                            ))}
                          </Box>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            N/A
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell align="right">{iface.mtu}</TableCell>
                      {!isServiceMode && (
                        <TableCell align="right">
                          <Tooltip title={copiedInterface === iface.name ? "Command copied!" : "Click to copy capture command"}>
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleCopyInterfaceCommand(iface.name);
                              }}
                              color={copiedInterface === iface.name ? "success" : "primary"}
                            >
                              {copiedInterface === iface.name ? <CheckCircleIcon /> : <ShareIcon />}
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </>
        ) : (
          <Box mt={3}>
            <Typography color="text.secondary">No network interfaces found</Typography>
          </Box>
        )}
      </Box>
    </Layout>
  );
}

