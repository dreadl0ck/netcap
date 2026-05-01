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

export const ALL_PCAPS_SCOPE = 'all';

interface Props {
  value: string;
  onChange: (next: string) => void;
  inputFiles: FileInfo[] | undefined;
}

export default function DashboardPcapScopeSelector({ value, onChange, inputFiles }: Props) {
  const completed = useMemo(
    () => (inputFiles || []).filter((f) => f.isCompleted).sort((a, b) => a.name.localeCompare(b.name)),
    [inputFiles],
  );

  const handleChange = (e: SelectChangeEvent<string>) => onChange(e.target.value);

  // Resolve label for current value (so the renderValue is informative)
  const currentLabel = useMemo(() => {
    if (value === ALL_PCAPS_SCOPE) return 'All PCAPs';
    const match = completed.find((f) => f.path === value || f.id === value || f.name === value);
    return match?.name || value;
  }, [value, completed]);

  return (
    <FormControl size="small" sx={{ minWidth: 240, maxWidth: { xs: '100%', sm: 420 } }}>
      <InputLabel id="dashboard-pcap-scope-label">Scope</InputLabel>
      <Select
        labelId="dashboard-pcap-scope-label"
        label="Scope"
        value={value}
        onChange={handleChange}
        renderValue={() => (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {value === ALL_PCAPS_SCOPE ? <PublicIcon fontSize="small" /> : <InsertDriveFileIcon fontSize="small" />}
            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{currentLabel}</Typography>
          </Box>
        )}
      >
        <MenuItem value={ALL_PCAPS_SCOPE}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <PublicIcon fontSize="small" />
            <Typography variant="body2"><strong>All PCAPs</strong></Typography>
            <Typography variant="caption" color="text.secondary">
              ({completed.length} {completed.length === 1 ? 'capture' : 'captures'})
            </Typography>
          </Box>
        </MenuItem>
        {completed.length === 0 && (
          <MenuItem value="" disabled>
            <Typography variant="caption" color="text.secondary">No completed captures yet</Typography>
          </MenuItem>
        )}
        {completed.map((f) => (
          <MenuItem key={f.id || f.path} value={f.path}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
              <InsertDriveFileIcon fontSize="small" />
              <Typography variant="body2" sx={{ fontFamily: 'monospace', flex: 1 }} noWrap>{f.name}</Typography>
            </Box>
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
}
