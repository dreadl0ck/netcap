import { useState } from 'react';
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Paper,
  Switch,
  FormControlLabel,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import InfoIcon from '@mui/icons-material/Info';
import useSWR from 'swr';
import Layout from '@/components/Layout';
import { api, type ConfigOption } from '@/lib/api';

export default function Config() {
  const { data: configData, error: configError, mutate } = useSWR('config', () => api.getConfig());
  const [searchTerm, setSearchTerm] = useState('');
  const [updating, setUpdating] = useState<string | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [updateSuccess, setUpdateSuccess] = useState<string | null>(null);

  const handleDebugToggle = async (currentValue: boolean) => {
    setUpdating('debug');
    setUpdateError(null);
    setUpdateSuccess(null);
    
    try {
      const result = await api.setDebugState(!currentValue);
      setUpdateSuccess(result.message);
      // Refresh config data
      mutate();
      // Clear success message after 3 seconds
      setTimeout(() => setUpdateSuccess(null), 3000);
    } catch (err) {
      setUpdateError(err instanceof Error ? err.message : 'Failed to update debug setting');
    } finally {
      setUpdating(null);
    }
  };

  if (configError) {
    return (
      <Layout title="Configuration">
        <Alert severity="error">
          Failed to load configuration: {configError.message}
        </Alert>
      </Layout>
    );
  }

  if (!configData) {
    return (
      <Layout title="Configuration">
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  // Filter options by search term
  const filteredOptions = configData.options.filter((option) => {
    const term = searchTerm.toLowerCase();
    return (
      option.name.toLowerCase().includes(term) ||
      option.description.toLowerCase().includes(term) ||
      option.category.toLowerCase().includes(term)
    );
  });

  // Group options by category
  const groupedOptions = filteredOptions.reduce((acc, option) => {
    if (!acc[option.category]) {
      acc[option.category] = [];
    }
    acc[option.category].push(option);
    return acc;
  }, {} as Record<string, ConfigOption[]>);

  // Format value for display
  const formatValue = (value: unknown, type: string): string => {
    if (value === null || value === undefined || value === '') {
      return '(not set)';
    }
    if (type === 'bool') {
      return value ? 'true' : 'false';
    }
    if (typeof value === 'number') {
      return value.toString();
    }
    return String(value);
  };

  // Get chip color for type
  const getTypeColor = (type: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
    switch (type) {
      case 'bool':
        return 'primary';
      case 'int':
      case 'int64':
        return 'secondary';
      case 'string':
        return 'info';
      case 'duration':
        return 'warning';
      default:
        return 'default';
    }
  };

  return (
    <Layout title="Configuration">
      {updateSuccess && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {updateSuccess}
        </Alert>
      )}
      {updateError && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setUpdateError(null)}>
          {updateError}
        </Alert>
      )}
      
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          Configuration
        </Typography>
        <Typography variant="body1" color="text.secondary" gutterBottom>
          Current Netcap configuration options and their values
        </Typography>

        {configData.readOnly && (
          <Alert severity="info" icon={<InfoIcon />} sx={{ mt: 2 }}>
            Configuration is read-only. 
            {configData.isTryService
              ? ' To change settings for future analysis runs, restart the try service with different flags.'
              : ' To change settings, restart the capture process with different flags.'}
          </Alert>
        )}
      </Box>

      <Box sx={{ mb: 3 }}>
        <TextField
          fullWidth
          placeholder="Search configuration options..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </Box>

      {Object.keys(groupedOptions).length === 0 ? (
        <Alert severity="info">No configuration options found matching your search.</Alert>
      ) : (
        Object.entries(groupedOptions).map(([category, options]) => (
          <Accordion key={category} defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">
                {category} <Chip label={options.length} size="small" sx={{ ml: 1 }} />
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer component={Paper} variant="outlined">
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 'bold' }}>Option</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Type</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Value</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Default</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Description</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {options.map((option) => (
                      <TableRow key={option.name} hover>
                        <TableCell>
                          <Typography
                            component="code"
                            sx={{
                              fontFamily: 'monospace',
                              fontSize: '0.9rem',
                              backgroundColor: 'action.hover',
                              px: 1,
                              py: 0.5,
                              borderRadius: 1,
                            }}
                          >
                            {option.name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={option.type} size="small" color={getTypeColor(option.type)} />
                        </TableCell>
                        <TableCell>
                          {option.isEditable && option.type === 'bool' ? (
                            <FormControlLabel
                              control={
                                <Switch
                                  checked={Boolean(option.value)}
                                  onChange={() => handleDebugToggle(Boolean(option.value))}
                                  disabled={updating === option.name}
                                  color="primary"
                                />
                              }
                              label={option.value ? 'Enabled' : 'Disabled'}
                            />
                          ) : (
                            <Typography
                              component="code"
                              sx={{
                                fontFamily: 'monospace',
                                fontSize: '0.9rem',
                                color: option.value === option.default ? 'text.secondary' : 'primary.main',
                                fontWeight: option.value === option.default ? 'normal' : 'bold',
                              }}
                            >
                              {formatValue(option.value, option.type)}
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Typography
                            component="code"
                            sx={{
                              fontFamily: 'monospace',
                              fontSize: '0.9rem',
                              color: 'text.secondary',
                            }}
                          >
                            {formatValue(option.default, option.type)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {option.description}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        ))
      )}

      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Command Line Reference
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            To modify these settings, restart Netcap with the appropriate flags:
          </Typography>
          <Box
            component="pre"
            sx={{
              backgroundColor: 'action.hover',
              p: 2,
              borderRadius: 1,
              overflow: 'auto',
              fontFamily: 'monospace',
              fontSize: '0.875rem',
            }}
          >
            {configData.isTryService
              ? `net try -http :7070 -dpi -max-file-size 52428800 ...`
              : `net capture -read input.pcap -out output -workers 8 -dpi ...`}
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
            Use <code>net capture -h</code> or <code>net try -h</code> for a complete list of available flags.
          </Typography>
        </CardContent>
      </Card>
    </Layout>
  );
}

