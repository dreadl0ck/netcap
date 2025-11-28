import { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  FormControlLabel,
  Grid,
  Switch,
  Tooltip,
  Typography,
  Alert,
  Snackbar,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import InventoryIcon from '@mui/icons-material/Inventory';
import EditIcon from '@mui/icons-material/Edit';
import { useNetcapRouter, useNetcapApi } from '../hooks';
import Layout from '../components/Layout';
import { RuleSet } from '../lib/api';
import useSWR, { mutate } from 'swr';

export default function RuleSetsPage() {
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Fetch rule sets
  const { data: ruleSetsData, error } = useSWR('ruleSets', () => api.getRuleSets(), {
    refreshInterval: 5000,
  });

  const ruleSets = ruleSetsData?.ruleSets || [];

  const handleToggleRuleSet = async (ruleSetName: string, enabled: boolean, event: React.MouseEvent) => {
    // Stop event propagation to prevent card click
    event.stopPropagation();
    
    console.log(`Toggling rule set: ${ruleSetName} to ${enabled}`);
    
    // Optimistically update the UI
    mutate(
      'ruleSets',
      (currentData: any) => {
        if (!currentData) return currentData;
        return {
          ...currentData,
          ruleSets: currentData.ruleSets.map((rs: any) =>
            rs.name === ruleSetName ? { ...rs, enabled } : rs
          ),
        };
      },
      false // Don't revalidate immediately
    );

    try {
      const result = await api.updateRuleSet(ruleSetName, { enabled });
      console.log('Rule set update result:', result);
      setSnackbar({
        open: true,
        message: result.message || `Rule set ${enabled ? 'enabled' : 'disabled'} successfully`,
        severity: 'success',
      });
      // Refresh data from server
      await mutate('ruleSets');
      await mutate('rules');
    } catch (err) {
      console.error('Failed to update rule set:', err);
      setSnackbar({
        open: true,
        message: `Failed to update rule set: ${err instanceof Error ? err.message : String(err)}`,
        severity: 'error',
      });
      // Revert the optimistic update on error
      await mutate('ruleSets');
    }
  };

  const handleCardClick = (ruleSetName: string) => {
    // Navigate to rules page with ruleset tag filter
    const ruleSetTag = `ruleset:${ruleSetName}`;
    router.push(`/rules?tag=${encodeURIComponent(ruleSetTag)}`);
  };

  return (
    <Layout title="Rule Sets">
      <Box sx={{ minWidth: 0 }}>
        <Box sx={{ mb: 3 }}>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Total: {ruleSets.length} rule set{ruleSets.length !== 1 ? 's' : ''} • 
            Active: {ruleSets.filter(rs => rs.enabled).length} •
            Built-in: {ruleSets.filter(rs => rs.isEmbedded).length}
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            Failed to load rule sets: {error.message}
          </Alert>
        )}

        {ruleSets.length === 0 ? (
          <Card>
            <CardContent>
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <SecurityIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  No Rule Sets Available
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Built-in rule sets should be available automatically. Custom rule sets can be added as YAML files in your rules directory.
                </Typography>
              </Box>
            </CardContent>
          </Card>
        ) : (
          <Grid container spacing={3}>
            {ruleSets.map((ruleSet) => (
              <Grid item xs={12} sm={6} md={4} key={ruleSet.name}>
                <Card 
                  data-learn="Rule Set Card: Click to view all detection rules in this rule set and manage individual rules within the collection."
                  variant="outlined"
                  onClick={() => handleCardClick(ruleSet.name)}
                  sx={{ 
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    transition: 'all 0.2s',
                    cursor: 'pointer',
                    '&:hover': {
                      boxShadow: 4,
                      transform: 'translateY(-2px)',
                    },
                    minHeight: '200px',
                  }}
                >
                  <CardContent sx={{ 
                    flexGrow: 1, 
                    display: 'flex', 
                    flexDirection: 'column',
                    p: 3,
                  }}>
                    <Box sx={{ 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      alignItems: 'flex-start', 
                      mb: 2 
                    }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <SecurityIcon color={ruleSet.enabled ? 'primary' : 'disabled'} />
                        <Typography variant="h6" component="div" sx={{ fontWeight: 600 }}>
                          {ruleSet.name.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
                        </Typography>
                      </Box>
                      <FormControlLabel
                        data-learn="Enable Rule Set: Toggle to enable or disable all rules in this rule set at once, affecting whether these detection rules are applied to network traffic."
                        control={
                          <Switch
                            checked={ruleSet.enabled}
                            onChange={(e) => handleToggleRuleSet(ruleSet.name, e.target.checked, e as any)}
                            onClick={(e) => e.stopPropagation()}
                            size="small"
                            color="primary"
                          />
                        }
                        label=""
                        sx={{ m: 0 }}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </Box>
                    
                    <Typography 
                      variant="body2" 
                      color="text.secondary" 
                      sx={{ 
                        mb: 'auto', 
                        flexGrow: 1,
                        fontSize: '0.9rem',
                        lineHeight: 1.6,
                      }}
                    >
                      {ruleSet.description}
                    </Typography>
                    
                    <Box sx={{ mt: 2, pt: 2, borderTop: '1px solid', borderColor: 'divider', display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                      <Chip
                        label={`${ruleSet.ruleCount} rule${ruleSet.ruleCount !== 1 ? 's' : ''}`}
                        size="medium"
                        color={ruleSet.enabled ? 'primary' : 'default'}
                        sx={{ 
                          fontSize: '0.85rem',
                          fontWeight: 500,
                        }}
                      />
                      {ruleSet.isEmbedded && (
                        <Tooltip title={ruleSet.isOverridden ? "Built-in rule set with local overrides" : "Built-in rule set bundled with the application"}>
                          <Chip
                            icon={ruleSet.isOverridden ? <EditIcon /> : <InventoryIcon />}
                            label={ruleSet.isOverridden ? "Modified" : "Built-in"}
                            size="small"
                            variant="outlined"
                            color={ruleSet.isOverridden ? "warning" : "info"}
                            sx={{ 
                              fontSize: '0.75rem',
                            }}
                          />
                        </Tooltip>
                      )}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}

        {/* Snackbar for notifications */}
        <Snackbar
          open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
        >
          <Alert
            onClose={() => setSnackbar({ ...snackbar, open: false })}
            severity={snackbar.severity}
            sx={{ width: '100%' }}
          >
            {snackbar.message}
          </Alert>
        </Snackbar>
      </Box>
    </Layout>
  );
}

