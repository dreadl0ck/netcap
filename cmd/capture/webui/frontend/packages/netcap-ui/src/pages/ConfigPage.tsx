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

import Layout from '../components/Layout';
import FeatureToggles from '../components/FeatureToggles';
import { type ConfigOption } from '../lib/api';
import { useNetcapApi } from '../hooks';
import { message as i18nMessage, translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, metadataText } from "../lib/i18n";
import { renderError, renderUIMessage } from "../lib/i18n";
import { errorText, recordTypeLabel } from "../lib/i18n";
import { metadataMessage } from "../lib/i18n";
import { rawCode } from "../lib/i18n";







const optionLabel = (option: ConfigOption) => option.labelI18n ? renderUIMessage(option.labelI18n) : option.name;

export default function Config() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { data: configData, error: configError, mutate } = useSWR('config', () => api.getConfig());
  const [searchTerm, setSearchTerm] = useState('');
  const [updating, setUpdating] = useState<string | null>(null);
  const [updateError, setUpdateError] = useState<UIMessageText | null>(null);
  const [updateSuccess, setUpdateSuccess] = useState<UIMessageText | null>(null);

  const handleDebugToggle = async (currentValue: boolean) => {
    setUpdating('debug');
    setUpdateError(null);
    setUpdateSuccess(null);
    
    try {
      const result = await api.setDebugState(!currentValue);
      setUpdateSuccess(metadataMessage(result, 'message'));
      // Refresh config data
      mutate();
      // Clear success message after 3 seconds
      setTimeout(() => setUpdateSuccess(null), 3000);
    } catch (err) {
      setUpdateError(err instanceof Error ? errorText(err) : i18nMessage("ui:m_35acfd61c9df2942f511"));
    } finally {
      setUpdating(null);
    }
  };

  const handlePayloadToggle = async (currentValue: boolean) => {
    setUpdating('payload');
    setUpdateError(null);
    setUpdateSuccess(null);
    
    try {
      const result = await api.setPayloadState(!currentValue);
      setUpdateSuccess(metadataMessage(result, 'message'));
      // Refresh config data
      mutate();
      // Clear success message after 3 seconds
      setTimeout(() => setUpdateSuccess(null), 3000);
    } catch (err) {
      setUpdateError(err instanceof Error ? errorText(err) : i18nMessage("ui:m_935a56335d0ca74dbd05"));
    } finally {
      setUpdating(null);
    }
  };

  if (configError) {
    return (
      <Layout title={i18nText("ui:m_b759ee55e0dc37df549e")}><Alert severity="error">
          {i18nRichText("ui:m_c0abf7a909f579ca67fc", { arg0: renderError(configError) })}
        </Alert></Layout>
    );
  }

  if (!configData) {
    return (
      <Layout title={i18nText("ui:m_b759ee55e0dc37df549e")}><Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}><CircularProgress /></Box></Layout>
    );
  }

  // Filter options by search term
  const filteredOptions = configData.options.filter((option) => {
    const term = searchTerm.toLowerCase();
    return (
      [option.name, option.description, option.category, optionLabel(option), metadataText(option, 'description'), metadataText(option, 'category')]
        .some(value => value.toLowerCase().includes(term))
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
      return i18nText("ui:m_15b0e97f8eec056f3739");
    }
    if (type === 'bool') {
      return value ? i18nText("ui:m_f3b6de25b6936558f126") : i18nText("ui:m_f2a9e8b340ba8d251edc");
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
    <Layout title={i18nText("ui:m_b759ee55e0dc37df549e")}>{i18nRenderText(updateSuccess) && (
        <Alert severity="success" sx={{ mb: 2 }}>{i18nRenderText(updateSuccess)}</Alert>
      )}{i18nRenderText(updateError) && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setUpdateError(null)}>{i18nRenderText(updateError)}</Alert>
      )}<FeatureToggles /><Box sx={{ mb: 3 }}><TextField data-learn={i18nText("ui:m_e78c493c81e2a3eb1a8c")}
           fullWidth
           label={i18nText("ui:m_588eb6ab1c7da1684c83")}
           placeholder={i18nText("ui:m_588eb6ab1c7da1684c83")}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)} /></Box>{Object.keys(groupedOptions).length === 0 ? (
        <Alert severity="info">{i18nText("ui:m_0bfdbc24161f21997579")}</Alert>
      ) : (
        Object.entries(groupedOptions).map(([category, options]) => (
          <Accordion key={category} defaultExpanded><AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography variant="h6">{metadataText(options[0], 'category', category)}<Chip label={options.length} size="small" sx={{ ml: 1 }} /></Typography></AccordionSummary><AccordionDetails><TableContainer component={Paper} variant="outlined"><Table><TableHead><TableRow><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_68433d7d3146799c379b")}</TableCell><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_3da346bd3b7d84ce65d6")}</TableCell><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_86ec80687ed80be80da0")}</TableCell><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_5a75b21808225492d936")}</TableCell><TableCell sx={{ fontWeight: 'bold' }}>{i18nText("ui:m_a02602e322c10d1a5449")}</TableCell></TableRow></TableHead><TableBody>{options.map((option) => (
                      <TableRow key={option.name} hover><TableCell><Typography variant="body2">{optionLabel(option)}</Typography><Typography component="code"
                            sx={{
                              fontFamily: 'monospace',
                              fontSize: '0.9rem',
                              backgroundColor: 'action.hover',
                              px: 1,
                              py: 0.5,
                              borderRadius: 1,
                            }}>{option.name}</Typography></TableCell><TableCell><Chip label={recordTypeLabel(option.type)} size="small" color={getTypeColor(option.type)} /></TableCell><TableCell>{option.isEditable && option.type === 'bool' ? (
                            <FormControlLabel control={<Switch checked={Boolean(option.value)}
                                  onChange={() => {
                                    if (option.name === 'debug') {
                                      handleDebugToggle(Boolean(option.value));
                                    } else if (option.name === 'payload') {
                                      handlePayloadToggle(Boolean(option.value));
                                    }
                                  }}
                                   disabled={updating === option.name}
                                   slotProps={{ input: { 'aria-label': optionLabel(option) } }}
                                   color="primary" />}
                              label={option.value ? i18nText("ui:m_23052c4fec9eb3ac70e9") : i18nText("ui:m_5e51003ed903b62900ec")} />
                          ) : (
                            <Typography component="code"
                              sx={{
                                fontFamily: 'monospace',
                                fontSize: '0.9rem',
                                color: option.value === option.default ? 'text.secondary' : 'primary.main',
                                fontWeight: option.value === option.default ? 'normal' : 'bold',
                              }}>{formatValue(option.value, option.type)}</Typography>
                          )}</TableCell><TableCell><Typography component="code"
                            sx={{
                              fontFamily: 'monospace',
                              fontSize: '0.9rem',
                              color: 'text.secondary',
                            }}>{formatValue(option.default, option.type)}</Typography></TableCell><TableCell><Typography variant="body2" color="text.secondary">{metadataText(option, "description")}</Typography></TableCell></TableRow>
                    ))}</TableBody></Table></TableContainer></AccordionDetails></Accordion>
        ))
      )}<Card sx={{ mt: 3 }}><CardContent><Typography variant="h6" gutterBottom>
            {i18nText("ui:m_8ad56babdbfcf13cdda9")}
          </Typography><Typography variant="body2" color="text.secondary" paragraph>
            {i18nText("ui:m_000cf0c25f0d69deb28b")}
          </Typography><Box component="pre"
            sx={{
              backgroundColor: 'action.hover',
              p: 2,
              borderRadius: 1,
              overflow: 'auto',
              fontFamily: 'monospace',
              fontSize: '0.875rem',
            }}>{configData.isServiceMode ? rawCode("net try -http :7070 -dpi -max-file-size 52428800 ...") : rawCode("net capture -read input.pcap -out output -workers 8 -dpi ...")}</Box><Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
            {((__codeValues: Record<string, unknown>) => i18nRichText("ui:m_aee19f9f31d9fb91ed18", { ...__codeValues, code0: rawCode("net capture -h", __codeValues), code1: rawCode("net try -h", __codeValues) }))({ tag0: (chunks: import('react').ReactNode[]) => <code>{chunks}</code>, tag1: (chunks: import('react').ReactNode[]) => <code>{chunks}</code> })}
          </Typography></CardContent></Card></Layout>
  );
}
