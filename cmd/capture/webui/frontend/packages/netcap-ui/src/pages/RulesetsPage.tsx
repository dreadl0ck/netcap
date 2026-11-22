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

import { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  FormControlLabel,
  Switch,
  Tooltip,
  Typography,
  Alert,
  Snackbar,
} from '@mui/material';
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
import SecurityIcon from '@mui/icons-material/Security';
import InventoryIcon from '@mui/icons-material/Inventory';
import EditIcon from '@mui/icons-material/Edit';
import { useNetcapRouter, useNetcapApi } from '../hooks';
import Layout from '../components/Layout';
import { RuleSet } from '../lib/api';

import { message as i18nMessage, translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as mutate } from "../lib/i18n";
import { renderError } from "../lib/i18n";
import { metadataMessage, errorText } from "../lib/i18n";
import { message as i18nParameterMessage } from "../lib/i18n";






export default function RuleSetsPage() {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: UIMessageText; severity: 'success' | 'error' }>({
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
      setSnackbar({ open: true, message: metadataMessage(result, 'message') || i18nMessage("ui:m_031e199aeccb2b6d58d8", { arg0: enabled ? i18nParameterMessage("ui:m_e51446f30214e1d15adb") : i18nParameterMessage("ui:m_16cbf16002fe9b16eeed") }), severity: 'success' });
      // Refresh data from server
      await mutate('ruleSets');
      await mutate('rules');
    } catch (err) {
      console.error('Failed to update rule set:', err);
      setSnackbar({ open: true, message: i18nMessage("ui:m_22e8942cae444e6e334d", { arg0: err instanceof Error ? errorText(err) : String(err) }), severity: 'error' });
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
    <Layout title={i18nText("ui:m_8946156de4df831b89d7")}><Box sx={{ minWidth: 0 }}><Box sx={{ mb: 3 }}><Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            {i18nRichText("ui:m_c25f3f8bd5cf186115e4", { arg0: ruleSets.length, arg2: ruleSets.filter(rs => rs.enabled).length, arg3: ruleSets.filter(rs => rs.isEmbedded).length })}
          </Typography></Box>{error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {i18nRichText("ui:m_c5df5dcc359ad6a3efad", { arg0: renderError(error) })}
          </Alert>
        )}{ruleSets.length === 0 ? (
          <Card><CardContent><Box sx={{ textAlign: 'center', py: 4 }}><SecurityIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} /><Typography variant="h6" color="text.secondary" gutterBottom>
                  {i18nText("ui:m_b63d81b2925d3dbe0999")}
                </Typography><Typography variant="body2" color="text.secondary">
                  {i18nText("ui:m_bd6a272dec7f44cd9a1f")}
                </Typography></Box></CardContent></Card>
        ) : (
          <Grid container spacing={3}>{ruleSets.map((ruleSet) => (
              <Grid item xs={12} sm={6} md={4} key={ruleSet.name}><Card data-learn={i18nText("ui:m_b9aed2cf2cd7c46c000e")}
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
                  }}><CardContent sx={{ 
                    flexGrow: 1, 
                    display: 'flex', 
                    flexDirection: 'column',
                    p: 3,
                  }}><Box sx={{ 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      alignItems: 'flex-start', 
                      mb: 2 
                    }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><SecurityIcon color={ruleSet.enabled ? 'primary' : 'disabled'} /><Typography variant="h6" component="div" sx={{ fontWeight: 600 }}>{ruleSet.name.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}</Typography></Box><FormControlLabel data-learn={i18nText("ui:m_442cd41ac652386b11d1")}
                        control={<Switch checked={ruleSet.enabled}
                            onChange={(e) => handleToggleRuleSet(ruleSet.name, e.target.checked, e as any)}
                            onClick={(e) => e.stopPropagation()}
                            size="small"
                            color="primary" />}
                        label={""}
                        sx={{ m: 0 }}
                        onClick={(e) => e.stopPropagation()} /></Box><Typography variant="body2" 
                      color="text.secondary" 
                      sx={{ 
                        mb: 'auto', 
                        flexGrow: 1,
                        fontSize: '0.9rem',
                        lineHeight: 1.6,
                      }}>{ruleSet.description}</Typography><Box sx={{ mt: 2, pt: 2, borderTop: '1px solid', borderColor: 'divider', display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}><Chip label={i18nText("ui:m_19ef433ea1bd95d52e84", { arg0: ruleSet.ruleCount })}
                        size="medium"
                        color={ruleSet.enabled ? 'primary' : 'default'}
                        sx={{ 
                          fontSize: '0.85rem',
                          fontWeight: 500,
                        }} />{ruleSet.isEmbedded && (
                        <Tooltip title={ruleSet.isOverridden ? i18nText("ui:m_1b0dbb6d313921c8cc7b") : i18nText("ui:m_b1f25e08c100f6aa452e")}><Chip icon={ruleSet.isOverridden ? <EditIcon /> : <InventoryIcon />}
                            label={ruleSet.isOverridden ? i18nText("ui:m_b335bad6aaf88c35cb6c") : i18nText("ui:m_a3baf2979227992650af")}
                            size="small"
                            variant="outlined"
                            color={ruleSet.isOverridden ? "warning" : "info"}
                            sx={{ 
                              fontSize: '0.75rem',
                            }} /></Tooltip>
                      )}</Box></CardContent></Card></Grid>
            ))}</Grid>
        )}{/* Snackbar for notifications */}<Snackbar open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({ ...snackbar, open: false })}><Alert onClose={() => setSnackbar({ ...snackbar, open: false })}
            severity={snackbar.severity}
            sx={{ width: '100%' }}>{i18nRenderText(snackbar.message)}</Alert></Snackbar></Box></Layout>
  );
}

