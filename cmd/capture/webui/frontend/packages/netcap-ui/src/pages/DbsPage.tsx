import {
  Box,
  Card,
  CardContent,
  CircularProgress,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Alert,
  AlertTitle,
  Grid,
  Button,
  Snackbar,
} from '@mui/material';
import { useState } from 'react';
import Layout from '../components/Layout';
import { formatBytes, formatTimestamp, type DBFileInfo } from '../lib/api';
import { useNetcapApi } from '../hooks';
import useSWR from 'swr';
import StorageIcon from '@mui/icons-material/Storage';
import FolderIcon from '@mui/icons-material/Folder';
import InfoIcon from '@mui/icons-material/Info';
import RefreshIcon from '@mui/icons-material/Refresh';

// Map database types to friendly names and colors
const DB_TYPE_INFO: Record<string, { label: string; color: 'primary' | 'secondary' | 'success' | 'warning' | 'info' | 'error' | 'default' }> = {
  maxmind: { label: 'MaxMind GeoIP', color: 'primary' },
  bleve: { label: 'Bleve Index', color: 'secondary' },
  json: { label: 'JSON', color: 'info' },
  csv: { label: 'CSV', color: 'warning' },
  hosts: { label: 'Hosts', color: 'success' },
  services: { label: 'Services', color: 'success' },
  other: { label: 'Other', color: 'default' },
};

// Map database file names to descriptions
const DB_DESCRIPTIONS: Record<string, string> = {
  'GeoLite2-City.mmdb': 'MaxMind GeoLite2 City database - provides city-level geolocation data for IP addresses',
  'GeoLite2-ASN.mmdb': 'MaxMind GeoLite2 ASN database - provides autonomous system number information',
  'exploit-db.bleve': 'Exploit database index - contains indexed exploit information from ExploitDB',
  'nvd.bleve': 'NVD CVE database index - contains indexed vulnerability data from NIST National Vulnerability Database',
  'mitre-cve.bleve': 'MITRE CVE database index - contains indexed CVE data from MITRE',
  'macaddress.io-db.json': 'MAC address vendor database - maps MAC address prefixes to manufacturers',
  'ja3.json': 'JA3 fingerprint database - TLS client fingerprints for service identification',
  'hosts': 'Local DNS hosts file - custom hostname to IP address mappings',
  'services': 'Services database - port number to service name mappings',
};

export default function DatabasesPage() {
  const api = useNetcapApi();
  const { data: dbInfo, error, isLoading, mutate } = useSWR('dbs', () => api.getDatabaseInfo(), {
    refreshInterval: 0, // No need to refresh automatically
  });
  const { data: status } = useSWR('status', () => api.getStatus());
  
  const [updating, setUpdating] = useState(false);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState<'success' | 'error'>('success');

  const handleUpdateDatabases = async () => {
    setUpdating(true);
    try {
      const result = await api.updateDatabases();
      setSnackbarMessage(result.message || 'Database update started successfully');
      setSnackbarSeverity('success');
      setSnackbarOpen(true);
      // Refresh database info after a short delay to allow background process to start
      setTimeout(() => {
        mutate();
      }, 2000);
    } catch (error) {
      setSnackbarMessage((error as Error).message || 'Failed to update databases');
      setSnackbarSeverity('error');
      setSnackbarOpen(true);
    } finally {
      setUpdating(false);
    }
  };

  const handleSnackbarClose = () => {
    setSnackbarOpen(false);
  };

  if (isLoading) {
    return (
      <Layout title="Databases">
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Databases">
        <Alert severity="error">
          <AlertTitle>Error Loading Database Information</AlertTitle>
          <Typography variant="body2">
            Failed to fetch database information: {error.message}
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            Make sure the databases are installed. You can download them using:
          </Typography>
          <Typography variant="body2" component="pre" sx={{ mt: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
            net util -download-dbs
          </Typography>
        </Alert>
      </Layout>
    );
  }

  // Group files by type
  const filesByType: Record<string, DBFileInfo[]> = {};
  dbInfo?.files.forEach((file) => {
    if (!filesByType[file.type]) {
      filesByType[file.type] = [];
    }
    filesByType[file.type].push(file);
  });

  return (
    <Layout 
      title="Databases"
      headerAction={
        <Button
          variant="contained"
          color="primary"
          startIcon={updating ? <CircularProgress size={20} color="inherit" /> : <RefreshIcon />}
          onClick={handleUpdateDatabases}
          disabled={updating || status?.isServiceMode}
        >
          {updating ? 'Updating...' : 'Update Databases'}
        </Button>
      }
    >
      <Box>
        {/* Summary Cards */}
        <Grid container spacing={3} mb={4}>
          <Grid item xs={12} md={4} sx={{ display: 'flex' }}>
            <Card sx={{ width: '100%' }}>
              <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <Box display="flex" alignItems="center" mb={1}>
                  <InfoIcon color="primary" sx={{ mr: 1 }} />
                  <Typography variant="h6">Version</Typography>
                </Box>
                <Typography variant="h4" color="primary">
                  {dbInfo?.version || 'unknown'}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Database release version
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4} sx={{ display: 'flex' }}>
            <Card sx={{ width: '100%' }}>
              <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <Box display="flex" alignItems="center" mb={1}>
                  <StorageIcon color="secondary" sx={{ mr: 1 }} />
                  <Typography variant="h6">Total Size</Typography>
                </Box>
                <Typography variant="h4" color="secondary">
                  {formatBytes(dbInfo?.totalSize || 0)}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  {dbInfo?.fileCount || 0} database files
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4} sx={{ display: 'flex' }}>
            <Card sx={{ width: '100%' }}>
              <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <Box display="flex" alignItems="center" mb={1}>
                  <FolderIcon color="success" sx={{ mr: 1 }} />
                  <Typography variant="h6">Location</Typography>
                </Box>
                <Typography variant="body2" sx={{ mt: 1, wordBreak: 'break-all', fontFamily: 'monospace' }}>
                  {dbInfo?.dbPath || 'N/A'}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                  Config root: {dbInfo?.configRootPath || 'N/A'}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Database Type Summary */}
        <Box mt={4}>
              <Grid container spacing={2}>
                {Object.entries(filesByType).map(([type, files]) => {
                  const typeInfo = DB_TYPE_INFO[type] || DB_TYPE_INFO.other;
                  const totalSize = files.reduce((sum, f) => sum + f.size, 0);
                  
                  return (
                    <Grid item xs={12} sm={6} md={4} key={type}>
                      <Card variant="outlined">
                        <CardContent>
                          <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
                            <Chip label={typeInfo.label} color={typeInfo.color} size="small" />
                            <Typography variant="body2" color="text.secondary">
                              {files.length} file{files.length !== 1 ? 's' : ''}
                            </Typography>
                          </Box>
                          <Typography variant="h6" color="primary">
                            {formatBytes(totalSize)}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  );
                })}
              </Grid>
            </Box>

        {/* Database Files Table */}
        {dbInfo && dbInfo.files.length > 0 ? (
          <>
            <Typography variant="h5" gutterBottom sx={{ mt: 4, mb: 2 }}>
              Database Files
            </Typography>
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell><strong>Name</strong></TableCell>
                    <TableCell><strong>Type</strong></TableCell>
                    <TableCell><strong>Size</strong></TableCell>
                    <TableCell><strong>Modified</strong></TableCell>
                    <TableCell><strong>Description</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dbInfo.files.map((file) => {
                    const typeInfo = DB_TYPE_INFO[file.type] || DB_TYPE_INFO.other;
                    const description = DB_DESCRIPTIONS[file.name] || 'Database file';
                    
                    return (
                      <TableRow key={file.path} hover>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                            {file.name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={typeInfo.label}
                            color={typeInfo.color}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {formatBytes(file.size)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {formatTimestamp(file.modifiedTime)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {description}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          </>
        ) : (
          <Alert severity="warning" sx={{ mt: 4 }}>
            <AlertTitle>No Databases Found</AlertTitle>
            <Typography variant="body2">
              No database files found in {dbInfo?.dbPath || 'the database directory'}.
            </Typography>
            <Typography variant="body2" sx={{ mt: 2 }}>
              To download the latest databases, run:
            </Typography>
            <Typography variant="body2" component="pre" sx={{ mt: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
              net util -download-dbs
            </Typography>
          </Alert>
        )}

      </Box>

      {/* Snackbar for update notifications */}
      <Snackbar
        open={snackbarOpen}
        autoHideDuration={6000}
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert onClose={handleSnackbarClose} severity={snackbarSeverity} sx={{ width: '100%' }}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Layout>
  );
}

