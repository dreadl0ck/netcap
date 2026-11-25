/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useMemo } from 'react';
import Box from '@mui/material/Box';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select, { type SelectChangeEvent } from '@mui/material/Select';
import Typography from '@mui/material/Typography';
import PublicIcon from '@mui/icons-material/Public';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';

import type { FileInfo } from '../lib/api';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { translate } from "../lib/i18n";



export const ALL_PCAPS_SCOPE = 'all';

interface Props {
  value: string;
  onChange: (next: string) => void;
  inputFiles: FileInfo[] | undefined;
  useSessionIds?: boolean;
}

export default function DashboardPcapScopeSelector({ value, onChange, inputFiles, useSessionIds }: Props) {
  const __uiLocale = useUILocale();
  const completed = useMemo(
    () => (inputFiles || []).filter((f) => f.isCompleted && (!useSessionIds || f.sessionId))
      .sort((a, b) => a.name.localeCompare(b.name))
      .map(file => ({ file, value: useSessionIds ? file.sessionId! : file.path })),
    [inputFiles, useSessionIds],
  );

  const handleChange = (e: SelectChangeEvent<string>) => onChange(e.target.value);

  const current = completed.find(option => option.value === value);
  const currentLabel = value === ALL_PCAPS_SCOPE ? translate("ui:m_2e9a446e47941ebe828a") : current?.file.name;

  return (
    <FormControl size="small" fullWidth sx={{ minWidth: { sm: 280 }, maxWidth: { xs: '100%', sm: 420 } }}><InputLabel id="dashboard-pcap-scope-label">{i18nText("ui:m_b0a6d8ea700eac59739c")}</InputLabel><Select labelId="dashboard-pcap-scope-label"
        label={i18nText("ui:m_b0a6d8ea700eac59739c")}
        value={value === ALL_PCAPS_SCOPE || current ? value : ''}
        onChange={handleChange}
        renderValue={() => (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>{value === ALL_PCAPS_SCOPE ? <PublicIcon fontSize="small" /> : <InsertDriveFileIcon fontSize="small" />}<Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{currentLabel}</Typography></Box>
        )}><MenuItem value={ALL_PCAPS_SCOPE}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><PublicIcon fontSize="small" /><Typography variant="body2">{i18nRichText("ui:m_66bbfd80449c7a935e68", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</Typography><Typography variant="caption" color="text.secondary">({completed.length}{completed.length === 1 ? i18nText("ui:m_9a33d83ca5cbc06ccebc") : i18nText("ui:m_2b00d655c21476e5e2d1")})
            </Typography></Box></MenuItem>{completed.length === 0 && (
          <MenuItem value="" disabled><Typography variant="caption" color="text.secondary">{i18nText("ui:m_f0593356bc9adc0eaa51")}</Typography></MenuItem>
        )}{completed.map(({ file, value }) => (
          <MenuItem key={value} value={value}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}><InsertDriveFileIcon fontSize="small" /><Typography variant="body2" sx={{ fontFamily: 'monospace', flex: 1 }} noWrap>{file.name}</Typography></Box></MenuItem>
        ))}</Select></FormControl>
  );
}
