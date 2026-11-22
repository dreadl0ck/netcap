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

import { useState, useEffect } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  IconButton,
  Link,
  List,
  ListItem,
  ListItemText,
  TextField,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import InfoIcon from '@mui/icons-material/Info';
import SaveIcon from '@mui/icons-material/Save';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import Layout from '../components/Layout';
import { useNetcapApi } from '../hooks';
import BPFExpressionHighlight, { BPFExpressionBlock } from '../components/BPFExpressionHighlight';
import { SyntaxHighlightedTextArea } from '../components/SyntaxHighlightedInput';
import { translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { renderError, errorText, message } from "../lib/i18n";
import { metadataText } from "../lib/i18n";
import { metadataMessage } from "../lib/i18n";
import { suppliedMetadataText } from "../lib/i18n";







export default function BPF() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { data: bpfData, error: bpfError, mutate: mutateBPF } = useSWR('bpfInfo', () => api.getBPFInfo());
  const [bpfFilter, setBpfFilter] = useState('');
  const [bpfSaving, setBpfSaving] = useState(false);
  const [bpfErrorMsg, setBpfErrorMsg] = useState<UIMessageText | null>(null);
  const [bpfSuccess, setBpfSuccess] = useState<UIMessageText | null>(null);

  // Initialize BPF filter from loaded data
  useEffect(() => {
    if (bpfData) {
      setBpfFilter(bpfData.currentFilter);
    }
  }, [bpfData]);

  const handleBPFSave = async () => {
    setBpfSaving(true);
    setBpfErrorMsg(null);
    setBpfSuccess(null);

    try {
      const result = await api.saveBPFConfig({ filter: bpfFilter });
      setBpfSuccess(metadataMessage(result, 'message'));
      mutateBPF();
      // Clear success message after 3 seconds
      setTimeout(() => setBpfSuccess(null), 3000);
    } catch (err) {
      setBpfErrorMsg(err instanceof Error ? errorText(err) : message('ui:bpf.saveFailed'));
    } finally {
      setBpfSaving(false);
    }
  };

  const handleCopyExample = (filter: string) => {
    setBpfFilter(filter);
    navigator.clipboard.writeText(filter);
  };

  if (bpfError) {
    return (
      <Layout title={i18nText("ui:m_5a7fa520d675449adbdd")}><Alert severity="error">
          {i18nRichText("ui:m_813377d27363ea7c1174", { arg0: renderError(bpfError) })}
        </Alert></Layout>
    );
  }

  if (!bpfData) {
    return (
      <Layout title={i18nText("ui:m_5a7fa520d675449adbdd")}><Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}><CircularProgress /></Box></Layout>
    );
  }

  return (
    <Layout title={i18nText("ui:m_5a7fa520d675449adbdd")}><Box sx={{ minWidth: 0 }}>{i18nRenderText(bpfSuccess) && (
        <Alert severity="success" sx={{ mb: 2 }}>{i18nRenderText(bpfSuccess)}</Alert>
      )}{bpfErrorMsg && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setBpfErrorMsg(null)}>{i18nRenderText(bpfErrorMsg)}</Alert>
      )}<Card sx={{ mb: 3 }}><CardContent><Box sx={{ mb: 3 }}><SyntaxHighlightedTextArea syntaxType="bpf"
              value={bpfFilter}
              onChange={setBpfFilter}
              label={i18nText("ui:m_3057da6e637180a241fd")}
              placeholder={i18nText("ui:m_e01302b584d0febb083b")}
              rows={4}
              fullWidth
              data-learn={i18nText("ui:m_e4a5dbd178398b78b7b1")} /><Box sx={{ mt: 2, display: 'flex', gap: 2, alignItems: 'center' }}><Button data-learn={i18nText("ui:m_a42d319351727a94fa44")}
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={handleBPFSave}
                disabled={bpfSaving}>{bpfSaving ? i18nText("ui:m_84d67cc7cab845a90ab6") : i18nText("ui:m_cceb1f9ea725d00261ba")}</Button><Button data-learn={i18nText("ui:m_51671e4bde916e52b6d7")}
                variant="outlined"
                onClick={() => setBpfFilter('')}
                disabled={!bpfFilter}>
                {i18nText("ui:m_cfdaafce54dddd3e0005")}
              </Button><Box sx={{ flex: 1 }} />
              {i18nRichText("ui:m_7fff1662193e616079a6", { arg0: <OpenInNewIcon fontSize="small" />, tag0: (chunks: import('react').ReactNode[]) => <Link data-learn={i18nText("ui:m_d03c732c8925fb91f54b")}
                href={bpfData.docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>{chunks}</Link> })}
            </Box></Box></CardContent></Card><Card><CardContent><Accordion defaultExpanded><AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography variant="h6" sx={{ fontWeight: 600 }}>
                {i18nText("ui:m_8a7e596223c5ad17cad8")}
              </Typography></AccordionSummary><AccordionDetails><Typography variant="body2" color="text.secondary" paragraph>
                {i18nText("ui:m_2e358ee6e0563a96f066")}
              </Typography><List>{bpfData.examples.map((example) => (
                  <ListItem data-learn={i18nText("ui:m_4a5cf5934e3491903009")}
                    key={`${example.name}-${example.filter}`}
                    sx={{
                      border: 1,
                      borderColor: 'divider',
                      borderRadius: 1,
                      mb: 1,
                      '&:hover': {
                        bgcolor: 'action.hover',
                        cursor: 'pointer',
                      },
                    }}
                    onClick={() => handleCopyExample(example.filter)}><ListItemText primary={<Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{suppliedMetadataText(example, "name")}</Typography><IconButton size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopyExample(example.filter);
                            }}><ContentCopyIcon fontSize="small" /></IconButton></Box>}
                      secondary={<><Box sx={{
                              display: 'block',
                              bgcolor: 'action.hover',
                              p: 1,
                              borderRadius: 1,
                              my: 1,
                            }}><BPFExpressionHighlight expression={example.filter}
                              fontSize="0.9rem"
                              wrap={true} /></Box><Typography variant="body2" color="text.secondary">{metadataText(example, "description")}</Typography></>} /></ListItem>
                ))}</List></AccordionDetails></Accordion></CardContent></Card><Card sx={{ mt: 3 }}><CardContent><Typography variant="h6" gutterBottom>
            {i18nText("ui:m_eacf0211f9346f3ec5d3")}
          </Typography><Typography variant="body2" color="text.secondary" paragraph>
            {i18nText("ui:m_433a4f5a0d5ff619e59b")}
          </Typography><Typography variant="body2" color="text.secondary" paragraph>
            {i18nText("ui:m_1193e8f26b65e56b2c66")}
          </Typography><List sx={{ pl: 2 }}><ListItem sx={{ py: 0.5 }}><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_527ec0c583d2e0e409ff")}
              </Typography></ListItem><ListItem sx={{ py: 0.5 }}><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_ed58f57c38f01949eddc")}
              </Typography></ListItem><ListItem sx={{ py: 0.5 }}><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_9ae110a8a4e148f2bed4")}
              </Typography></ListItem><ListItem sx={{ py: 0.5 }}><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_61ef41a8cc8383247a9c")}
              </Typography></ListItem><ListItem sx={{ py: 0.5 }}><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_8b05ff27c9f506a3063f")}
              </Typography></ListItem><ListItem sx={{ py: 0.5 }}><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_e040ecfb7e8cee100068")}
              </Typography></ListItem></List><Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            {i18nRichText("ui:m_3bf711488cbe36e437fd", { tag0: (chunks: import('react').ReactNode[]) => <Link href={bpfData.docsUrl} target="_blank" rel="noopener noreferrer">{chunks}</Link> })}
          </Typography></CardContent></Card></Box></Layout>
  );
}
