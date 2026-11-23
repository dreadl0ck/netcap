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

import { useEffect, useState } from 'react';
import useSWR from 'swr';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Link from '@mui/material/Link';
import Typography from '@mui/material/Typography';
import GitHubIcon from '@mui/icons-material/GitHub';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import { api } from '../lib/api';
import { translate as i18nText, useLocale } from '../lib/i18n';

export const DEMO_NOTICE_STORAGE_KEY = 'netcap.demoNotice.seen';

function alreadySeen(): boolean {
  try {
    return window.localStorage.getItem(DEMO_NOTICE_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function markSeen() {
  try {
    window.localStorage.setItem(DEMO_NOTICE_STORAGE_KEY, '1');
  } catch {
    // Storage may be unavailable (private mode); the notice then reappears per visit.
  }
}

/** First-visit welcome for the hosted service-mode demo. */
export default function DemoNotice() {
  useLocale();
  const { data: status } = useSWR('status', () => api.getStatus());
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (status?.isServiceMode && !alreadySeen()) setOpen(true);
  }, [status?.isServiceMode]);

  const close = () => {
    markSeen();
    setOpen(false);
  };

  return (
    <Dialog open={open} onClose={close} maxWidth="sm" fullWidth aria-labelledby="netcap-demo-notice-title">
      <DialogTitle id="netcap-demo-notice-title">{i18nText('ui:m_2f276e4068f0375699dd')}</DialogTitle>
      <DialogContent>
        <Typography variant="body1" sx={{ mb: 2 }}>
          {i18nText('ui:m_21c4f89ee68f43187561')}
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
          <Link href="https://github.com/dreadl0ck/netcap" target="_blank" rel="noopener noreferrer" sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.75 }}>
            <GitHubIcon fontSize="small" />
            {i18nText('ui:m_f40bbb8a54a9a01da6b4')}
          </Link>
          <Link href="https://docs.netcap.io" target="_blank" rel="noopener noreferrer" sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.75 }}>
            <MenuBookIcon fontSize="small" />
            {i18nText('ui:m_c89ba1325ff2fd81112d')}
          </Link>
        </Box>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button variant="contained" onClick={close} autoFocus>
          {i18nText('ui:m_12d5999e39fac7b14eb6')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
