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
  CircularProgress,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import { CheckCircle as CheckCircleIcon, Share as ShareIcon } from '@mui/icons-material';
import Layout from '../components/Layout';
import { useNetcapApi } from '../hooks';

import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";



export default function Interfaces() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { data: networkInterfaces, error } = useSWR('networkInterfaces', () => api.getNetworkInterfaces());
  const { data: status } = useSWR('status', () => api.getStatus());
  const [copiedInterface, setCopiedInterface] = useState<string | null>(null);

  const handleCopyInterfaceCommand = async (interfaceName: string) => {
    const command = `net capture -iface ${interfaceName} -out /path/to/output`;
    try {
      await navigator.clipboard.writeText(command);
      setCopiedInterface(interfaceName);
      setTimeout(() => setCopiedInterface(null), 2000);
    } catch (err) {
      console.error('Failed to copy command:', err);
    }
  };

  if (!networkInterfaces && !error) {
    return (
      <Layout title={i18nText("removed:m_efb1e81e228656c0080b")}><Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh"><CircularProgress /></Box></Layout>
    );
  }

  if (error) {
    return (
      <Layout title={i18nText("removed:m_efb1e81e228656c0080b")}><Box><Typography color="error">{i18nText("removed:m_f823e82aef1326373386")}</Typography></Box></Layout>
    );
  }

  // Check if we're in local mode (not try service)
  const isServiceMode = status?.isServiceMode === true;

  return (
    <Layout title={i18nText("removed:m_efb1e81e228656c0080b")}><Box sx={{ minWidth: 0 }}>{networkInterfaces && networkInterfaces.length > 0 ? (
          <><Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {i18nRichText("removed:m_5bc5ea1fdce8f3889708", { arg0: networkInterfaces.length })}
            </Typography><TableContainer component={Paper} sx={{ overflowX: 'auto', maxWidth: '100%' }}><Table><TableHead><TableRow><TableCell>{i18nText("removed:m_a0f5d1890ffe278500fe")}</TableCell><TableCell>{i18nText("removed:m_e707e3dfaa88e6753600")}</TableCell><TableCell>{i18nText("removed:m_e2b25ca311c37700235c")}</TableCell><TableCell>{i18nText("removed:m_de240542763469980e50")}</TableCell><TableCell>{i18nText("removed:m_3a41daee658f3bb86e92")}</TableCell><TableCell align="right">{i18nText("removed:m_98ab8bd138ec566bfc67")}</TableCell>{!isServiceMode && <TableCell align="right">{i18nText("removed:m_8b59af6a47204b74041c")}</TableCell>}</TableRow></TableHead><TableBody>{networkInterfaces.map((iface) => (
                    <TableRow key={iface.index}
                      hover={!isServiceMode}
                      sx={{ 
                        cursor: isServiceMode ? 'default' : 'pointer',
                        opacity: isServiceMode ? 0.7 : 1
                      }}
                      onClick={isServiceMode ? undefined : () => handleCopyInterfaceCommand(iface.name)}><TableCell>{iface.index}</TableCell><TableCell><Typography sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>{iface.name}</Typography></TableCell><TableCell><Typography variant="body2" color="text.secondary">{iface.flags}</Typography></TableCell><TableCell><Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{iface.hardwareAddr || i18nText("removed:m_8dc598ebf1e055830140")}</Typography></TableCell><TableCell>{iface.addrs && iface.addrs.length > 0 ? (
                          <Box>{iface.addrs.map((addr) => (
                              <Typography key={addr} 
                                sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{addr}</Typography>
                            ))}</Box>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            {i18nText("removed:m_8dc598ebf1e055830140")}
                          </Typography>
                        )}</TableCell><TableCell align="right">{iface.mtu}</TableCell>{!isServiceMode && (
                        <TableCell align="right"><Tooltip title={copiedInterface === iface.name ? i18nText("removed:m_93599c08ce68f5a49a0a") : i18nText("removed:m_8c680b520c8f2e52f4b0")}><IconButton data-learn={i18nText("removed:m_f9a97d04dff5542865a6")}
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleCopyInterfaceCommand(iface.name);
                              }}
                              color={copiedInterface === iface.name ? "success" : "primary"}>{copiedInterface === iface.name ? <CheckCircleIcon /> : <ShareIcon />}</IconButton></Tooltip></TableCell>
                      )}</TableRow>
                  ))}</TableBody></Table></TableContainer></>
        ) : (
          <Box mt={3}><Typography color="text.secondary">{i18nText("removed:m_26a63c982ec6cacb3fdb")}</Typography></Box>
        )}</Box></Layout>
  );
}

