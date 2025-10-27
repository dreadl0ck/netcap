import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Collapse,
  FormControlLabel,
  IconButton,
  Switch,
  TextField,
  Typography,
  Paper,
} from '@mui/material';
import {
  ChevronRight as ChevronRightIcon,
  ExpandMore as ExpandMoreIcon,
  Save as SaveIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
} from '@mui/icons-material';
import useSWR from 'swr';
import Layout from '@/components/Layout';
import type { DecoderInfo, DecoderConfig } from '@/lib/api';
import { api } from '@/lib/api';

interface DecoderCategory {
  name: string;
  key: string;
  decoders: DecoderInfo[];
  color: string;
}

const getCategoryColor = (categoryKey: string): string => {
  const colors: Record<string, string> = {
    packet: '#2196f3',    // Blue
    gopacket: '#9c27b0',  // Purple
    stream: '#ff9800',    // Orange
    abstract: '#4caf50',  // Green
  };
  return colors[categoryKey] || '#757575';
};

export default function Decoders() {
  const { data: decodersData, error: decodersError } = useSWR('decoders', () => api.getDecoders());
  const { data: configData, mutate: mutateConfig } = useSWR('decoderConfig', () => api.getDecoderConfig());
  const [searchTerm, setSearchTerm] = useState('');
  const [enabledDecoders, setEnabledDecoders] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(['packet', 'gopacket', 'stream', 'abstract'])
  );

  // Initialize enabled decoders state from fetched data
  useEffect(() => {
    if (decodersData) {
      const enabled: Record<string, boolean> = {};
      
      [...decodersData.packet, ...decodersData.gopacket, ...decodersData.stream, ...decodersData.abstract].forEach(
        (decoder) => {
          enabled[decoder.name] = decoder.enabled;
        }
      );
      
      setEnabledDecoders(enabled);
    }
  }, [decodersData]);

  const toggleCategory = (categoryKey: string) => {
    setExpandedCategories((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(categoryKey)) {
        newSet.delete(categoryKey);
      } else {
        newSet.add(categoryKey);
      }
      return newSet;
    });
  };

  const handleToggle = (decoderName: string) => {
    setEnabledDecoders((prev) => ({
      ...prev,
      [decoderName]: !prev[decoderName],
    }));
  };

  const handleToggleAll = (category: string, enabled: boolean) => {
    if (!decodersData) return;

    const decoders = category === 'packet' 
      ? decodersData.packet
      : category === 'gopacket'
      ? decodersData.gopacket
      : category === 'stream'
      ? decodersData.stream
      : decodersData.abstract;

    const updates: Record<string, boolean> = {};
    decoders.forEach((decoder) => {
      updates[decoder.name] = enabled;
    });

    setEnabledDecoders((prev) => ({
      ...prev,
      ...updates,
    }));
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveError(null);
    setSaveSuccess(null);

    try {
      // Get list of enabled and disabled decoders
      const enabled = Object.entries(enabledDecoders)
        .filter(([_, isEnabled]) => isEnabled)
        .map(([name]) => name);
      
      const disabled = Object.entries(enabledDecoders)
        .filter(([_, isEnabled]) => !isEnabled)
        .map(([name]) => name);

      // Determine whether to use include or exclude mode
      // If more than half are enabled, use exclude mode; otherwise use include mode
      const totalCount = Object.keys(enabledDecoders).length;
      const enabledCount = enabled.length;
      
      let config: DecoderConfig;
      if (enabledCount > totalCount / 2) {
        // Most decoders enabled, use exclude list
        config = {
          includeDecoders: '',
          excludeDecoders: disabled.join(','),
          enabledDecoders: enabled,
        };
      } else {
        // Fewer decoders enabled, use include list
        config = {
          includeDecoders: enabled.join(','),
          excludeDecoders: '',
          enabledDecoders: enabled,
        };
      }

      const result = await api.saveDecoderConfig(config);
      setSaveSuccess(result.message);
      mutateConfig();

      // Clear success message after 3 seconds
      setTimeout(() => setSaveSuccess(null), 3000);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  if (decodersError) {
    return (
      <Layout title="Decoders">
        <Alert severity="error">
          Failed to load decoders: {decodersError.message}
        </Alert>
      </Layout>
    );
  }

  if (!decodersData || !configData) {
    return (
      <Layout title="Decoders">
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  // Filter decoders by search term
  const filterDecoders = (decoders: DecoderInfo[]) => {
    if (!searchTerm) return decoders;
    const term = searchTerm.toLowerCase();
    return decoders.filter(
      (decoder) =>
        decoder.name.toLowerCase().includes(term) ||
        decoder.description.toLowerCase().includes(term)
    );
  };

  // Build category groups
  const categories: DecoderCategory[] = decodersData ? [
    {
      name: 'Packet Decoders',
      key: 'packet',
      decoders: filterDecoders(decodersData.packet),
      color: getCategoryColor('packet'),
    },
    {
      name: 'GoPacket Layer Decoders',
      key: 'gopacket',
      decoders: filterDecoders(decodersData.gopacket),
      color: getCategoryColor('gopacket'),
    },
    {
      name: 'Stream Decoders',
      key: 'stream',
      decoders: filterDecoders(decodersData.stream),
      color: getCategoryColor('stream'),
    },
    {
      name: 'Abstract Decoders',
      key: 'abstract',
      decoders: filterDecoders(decodersData.abstract),
      color: getCategoryColor('abstract'),
    },
  ].filter(cat => cat.decoders.length > 0) : [];

  const totalDecoders = categories.reduce((sum, cat) => sum + cat.decoders.length, 0);
  const enabledCount = Object.values(enabledDecoders).filter(Boolean).length;

  return (
    <Layout title="Decoders">
      {saveSuccess && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {saveSuccess}
        </Alert>
      )}
      {saveError && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setSaveError(null)}>
          {saveError}
        </Alert>
      )}

      <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={3} gap={2}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Decoder Configuration
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {totalDecoders} decoder(s) available • {enabledCount} enabled • Hierarchical by type
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<SaveIcon />}
          onClick={handleSave}
          disabled={saving}
          sx={{ minWidth: '160px' }}
        >
          {saving ? 'Saving...' : 'Save Configuration'}
        </Button>
      </Box>

      <Alert severity="info" icon={<InfoIcon />} sx={{ mb: 3 }}>
        Changes will be saved to the configuration file and applied to all future capture executions.
        The current capture session will not be affected.
      </Alert>

      <Box sx={{ mb: 3 }}>
        <TextField
          fullWidth
          placeholder="Search decoders by name or description..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          size="small"
        />
      </Box>

      {categories.length > 0 ? (
        <Paper sx={{ p: 2 }}>
          {categories.map((category, catIdx) => {
            const enabledInCategory = category.decoders.filter((d) => enabledDecoders[d.name]).length;
            const totalInCategory = category.decoders.length;
            const allEnabled = enabledInCategory === totalInCategory;
            const noneEnabled = enabledInCategory === 0;

            return (
              <Box key={category.key} sx={{ mb: catIdx < categories.length - 1 ? 2 : 0 }}>
                {/* Category Header */}
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    cursor: 'pointer',
                    p: 1,
                    borderRadius: 1,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                  onClick={() => toggleCategory(category.key)}
                >
                  <IconButton size="small" sx={{ mr: 1 }}>
                    {expandedCategories.has(category.key) ? <ExpandMoreIcon /> : <ChevronRightIcon />}
                  </IconButton>
                  <Box
                    sx={{
                      width: 3,
                      height: 24,
                      bgcolor: category.color,
                      mr: 2,
                      borderRadius: 1,
                    }}
                  />
                  <Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>
                    {category.name}
                  </Typography>
                  <Chip
                    label={`${enabledInCategory}/${totalInCategory} enabled`}
                    size="small"
                    color={allEnabled ? 'success' : noneEnabled ? 'default' : 'warning'}
                    sx={{ mr: 2 }}
                  />
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleAll(category.key, true);
                    }}
                    sx={{ mr: 1 }}
                  >
                    Enable All
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleAll(category.key, false);
                    }}
                  >
                    Disable All
                  </Button>
                </Box>

                {/* Category Content */}
                <Collapse in={expandedCategories.has(category.key)}>
                  <Box sx={{ ml: 6, mt: 1 }}>
                    {category.decoders.map((decoder, decoderIdx) => {
                      const isEnabled = enabledDecoders[decoder.name] || false;
                      return (
                        <Box
                          key={decoder.name}
                          sx={{
                            display: 'flex',
                            alignItems: 'center',
                            p: 1.5,
                            mb: decoderIdx < category.decoders.length - 1 ? 1 : 0,
                            borderLeft: 2,
                            borderColor: 'divider',
                            bgcolor: 'background.default',
                            borderRadius: 1,
                            cursor: 'pointer',
                            transition: 'all 0.2s',
                            '&:hover': {
                              bgcolor: 'action.hover',
                              borderLeftColor: category.color,
                            },
                          }}
                          onClick={() => handleToggle(decoder.name)}
                        >
                          <Box sx={{ mr: 2 }}>
                            {isEnabled ? (
                              <CheckCircleIcon sx={{ color: 'success.main', fontSize: 20 }} />
                            ) : (
                              <CancelIcon sx={{ color: 'text.disabled', fontSize: 20 }} />
                            )}
                          </Box>
                          <Box sx={{ flex: 1 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                              <Typography
                                component="code"
                                sx={{
                                  fontFamily: 'monospace',
                                  fontSize: '0.9rem',
                                  fontWeight: 600,
                                  color: isEnabled ? 'text.primary' : 'text.disabled',
                                }}
                              >
                                {decoder.name}
                              </Typography>
                              {decoder.port && (
                                <Chip
                                  label={`Port ${decoder.port}`}
                                  size="small"
                                  sx={{
                                    height: 20,
                                    fontSize: '0.7rem',
                                    bgcolor: category.color + '20',
                                    color: category.color,
                                  }}
                                />
                              )}
                              {decoder.layer && (
                                <Chip
                                  label={decoder.layer}
                                  size="small"
                                  sx={{
                                    height: 20,
                                    fontSize: '0.7rem',
                                    bgcolor: category.color + '20',
                                    color: category.color,
                                  }}
                                />
                              )}
                            </Box>
                            <Typography
                              variant="body2"
                              color="text.secondary"
                              sx={{ fontSize: '0.85rem' }}
                            >
                              {decoder.description}
                            </Typography>
                          </Box>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={isEnabled}
                                onChange={(e) => {
                                  e.stopPropagation();
                                  handleToggle(decoder.name);
                                }}
                                color="primary"
                              />
                            }
                            label=""
                            onClick={(e) => e.stopPropagation()}
                          />
                        </Box>
                      );
                    })}
                  </Box>
                </Collapse>
              </Box>
            );
          })}
        </Paper>
      ) : (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography color="text.secondary">
            {searchTerm ? 'No decoders match your search.' : 'No decoders available.'}
          </Typography>
        </Paper>
      )}

      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Configuration Summary
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
            {JSON.stringify(
              {
                includeDecoders: configData.includeDecoders || '(none - all enabled by default)',
                excludeDecoders: configData.excludeDecoders || '(none)',
                totalEnabled: enabledCount,
                totalDecoders: Object.keys(enabledDecoders).length,
              },
              null,
              2
            )}
          </Box>
        </CardContent>
      </Card>
    </Layout>
  );
}

