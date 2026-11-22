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

import {
  Box,
  Card,
  CardContent,
  CircularProgress,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Alert,
  AlertTitle,
  Button,
  Snackbar,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
// MUI 7's Grid ignores item/xs; GridLegacy keeps the v5 API these pages use.
import Grid from '@mui/material/GridLegacy';
import { useState } from 'react';
import Layout from '../components/Layout';
import { formatBytes, formatTimestamp, type DBFileInfo } from '../lib/api';
import { useNetcapApi } from '../hooks';

import StorageIcon from '@mui/icons-material/Storage';
import FolderIcon from '@mui/icons-material/Folder';
import InfoIcon from '@mui/icons-material/Info';
import RefreshIcon from '@mui/icons-material/Refresh';
import { message as i18nMessage, translate as i18nText, richText as i18nRichText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { renderError, translate, errorText } from "../lib/i18n";
import { metadataText } from "../lib/i18n";
import { metadataMessage } from "../lib/i18n";
import { rawCode } from "../lib/i18n";
import { translate as finalCopyText } from "../lib/i18n";








// Map database types to friendly names and colors
const DB_TYPE_INFO: Record<string, { label: string; color: 'primary' | 'secondary' | 'success' | 'warning' | 'info' | 'error' | 'default' }> = {
  maxmind: { label: 'GeoIP (MMDB)', color: 'primary' },
  mmdb: { label: 'GeoIP (MMDB)', color: 'primary' },
  sqlite: { label: 'SQLite', color: 'secondary' },
  bleve: { label: 'Bleve Index (unused since v0.10)', color: 'default' },
  json: { label: 'JSON', color: 'info' },
  csv: { label: 'CSV', color: 'warning' },
  hosts: { label: 'Hosts', color: 'success' },
  services: { label: 'Services', color: 'success' },
  other: { label: 'Other', color: 'default' },
};

// Map database file names to descriptions
const DB_DESCRIPTIONS: Record<string, string> = {
  'dbip-city-lite.mmdb': 'DB-IP Lite City - monthly country and approximate city geolocation',
  'dbip-asn-lite.mmdb': 'DB-IP Lite ASN - monthly autonomous system number and organization',
  'GeoLite2-City.mmdb': 'MaxMind GeoLite2 City database - provides city-level geolocation data for IP addresses',
  'GeoLite2-ASN.mmdb': 'MaxMind GeoLite2 ASN database - provides autonomous system number information',
  'netcap.sqlite': 'Vulnerability and exploit database - NIST NVD CVEs and ExploitDB entries with full-text search, shared by the Go and Rust engines',
  'exploit-db.bleve': 'Legacy exploit index from netcap < v0.10 - no longer read, safe to delete',
  'nvd.bleve': 'Legacy NVD index from netcap < v0.10 - no longer read, safe to delete',
  'mitre-cve.bleve': 'Legacy MITRE CVE index from netcap < v0.10 - no longer read, safe to delete',
  'macaddress.io-db.json': 'MAC address vendor database - maps MAC address prefixes to manufacturers',
  'ja3.json': 'JA3 fingerprint database - TLS client fingerprints for service identification',
  'hosts': 'Local DNS hosts file - custom hostname to IP address mappings',
  'services': 'Services database - port number to service name mappings',
};

export default function DatabasesPage() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { data: dbInfo, error, isLoading, mutate } = useSWR('dbs', () => api.getDatabaseInfo(), {
    refreshInterval: 0, // No need to refresh automatically
  });
  const { data: status } = useSWR('status', () => api.getStatus());
  const { data: geoStatus, mutate: refreshGeoStatus } = useSWR('dbs/status', () => api.getDatabaseStatus(), { refreshInterval: 5000 });
  const [savingGeo, setSavingGeo] = useState(false);
  
  const [updating, setUpdating] = useState(false);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState<UIMessageText>('');
  const [snackbarSeverity, setSnackbarSeverity] = useState<'success' | 'error'>('success');

  const handleUpdateDatabases = async () => {
    setUpdating(true);
    try {
      const result = await api.updateDatabases();
      setSnackbarMessage(metadataMessage(result, 'message') || i18nMessage("removed:m_fbba79352ce27a317c97"));
      setSnackbarSeverity('success');
      setSnackbarOpen(true);
      // Refresh database info after a short delay to allow background process to start
      setTimeout(() => {
        mutate();
      }, 2000);
    } catch (error) {
      setSnackbarMessage(errorText(error) || i18nMessage("removed:m_7be105a1147b6c5fdeac"));
      setSnackbarSeverity('error');
      setSnackbarOpen(true);
    } finally {
      setUpdating(false);
    }
  };

  const handleSnackbarClose = () => {
    setSnackbarOpen(false);
  };

  const setProviders = async (providers: string) => {
    setSavingGeo(true);
    try {
      const result = await api.setGeoProviders(providers);
      await refreshGeoStatus(result, false);
      setSnackbarMessage(i18nMessage("removed:m_f5b64f925defed29909c"));
      setSnackbarSeverity('success');
    } catch (error) {
      setSnackbarMessage(errorText(error));
      setSnackbarSeverity('error');
    } finally {
      setSnackbarOpen(true);
      setSavingGeo(false);
    }
  };

  if (isLoading) {
    return (
      <Layout title={i18nText("removed:m_b9ca438f78bcafc385f9")}><Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh"><CircularProgress /></Box></Layout>
    );
  }

  if (error) {
    return (
      <Layout title={i18nText("removed:m_b9ca438f78bcafc385f9")}><Alert severity="error"><AlertTitle>{i18nText("removed:m_039dde90c868832712c4")}</AlertTitle><Typography variant="body2">
            {i18nRichText("removed:m_3b6cc770fee9e4f86e1b", { arg0: renderError(error) })}
          </Typography><Typography variant="body2" sx={{ mt: 1 }}>
            {i18nText("removed:m_c85a0e0bf2235b10066e")}
          </Typography><Typography variant="body2" component="pre" sx={{ mt: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
            {rawCode("net util -download-dbs")}
          </Typography></Alert></Layout>
    );
  }

  // Group files by type
  const filesByType: Record<string, DBFileInfo[]> = {};
  dbInfo?.files.forEach((file) => {
    if (!filesByType[file.type]) {
      filesByType[file.type] = [];
    }
    filesByType[file.type].push(file);
  });

  return (
    <Layout title={i18nText("removed:m_b9ca438f78bcafc385f9")}
      headerAction={<Button variant="contained"
          color="primary"
          startIcon={updating ? <CircularProgress size={20} color="inherit" /> : <RefreshIcon />}
          onClick={handleUpdateDatabases}
          disabled={updating || status?.isServiceMode}>{updating ? i18nText("removed:m_db2820e49ddc833ebe2b") : i18nText("removed:m_c21804e9d22c9f8e66e0")}</Button>}><Box>{geoStatus && (
          <Card variant="outlined" sx={{ mb: 3 }}><CardContent><Typography variant="h6" sx={{ mb: 2 }}>{i18nText("removed:m_366574f25e159d6e1f43")}</Typography><FormControl fullWidth disabled={savingGeo}><InputLabel id="geo-provider-label">{i18nText("removed:m_379d0528add7f2ab9ee9")}</InputLabel><Select labelId="geo-provider-label" label={i18nText("removed:m_379d0528add7f2ab9ee9")} value={geoStatus.geoProviders || 'dbip,geolite2'} onChange={(event) => setProviders(event.target.value)}><MenuItem value="dbip,geolite2">{i18nText("removed:m_804891ab31ef46353eb2")}</MenuItem><MenuItem value="geolite2,dbip">{i18nText("removed:m_5207506704877f0290dc")}</MenuItem><MenuItem value="dbip">{i18nText("removed:m_aa1eab5d579ed9559a13")}</MenuItem><MenuItem value="geolite2">{i18nText("removed:m_6f361516861f8c6afe27")}</MenuItem></Select></FormControl><Typography variant="body2" sx={{ mt: 2 }}>{i18nText("removed:m_57c6bbe92206ecb70d60")}</Typography>{geoStatus.geoStatus?.map((provider) => (
                <Box key={provider.name} sx={{ mt: 2 }}><Typography variant="subtitle2">{provider.name === 'dbip' ? i18nText("removed:m_1ce972ebad31e5ee1acd") : i18nText("removed:m_134306d49032c6d84c07")}: {provider.selected ? i18nText("removed:m_d0824a4f5cbcded71d39") : i18nText("removed:m_17628e441518c6802c1e")}, {provider.available ? i18nText("removed:m_560b680c17314344f9dc") : i18nText("removed:m_ddddc9fec2c62ce5d4b3")}{provider.loaded ? i18nText("removed:m_a5de519dc164ffd7dd4e") : ''}</Typography>{provider.available && <Typography variant="caption">{i18nRichText("removed:m_1951ea4a8fd319d9692c", { arg0: provider.cityBuild, arg1: provider.asnBuild })}</Typography>}{!provider.available && <Typography variant="body2" color="text.secondary">{provider.error}</Typography>}</Box>
              ))}<Typography variant="body2" sx={{ mt: 2 }}>{((__codeValues: Record<string, unknown>) => i18nRichText("removed:m_a19688b32638a1d72a92", { ...__codeValues, code0: rawCode("net util -download-geolite", __codeValues) }))({ tag0: (chunks: import('react').ReactNode[]) => <code>{chunks}</code> })}</Typography>{geoStatus.geoError && <Alert severity="error" sx={{ mt: 2 }}>{geoStatus.geoError}</Alert>}</CardContent></Card>
        )}{/* Summary Cards */}<Grid container spacing={3} mb={4}><Grid item xs={12} md={4} sx={{ display: 'flex' }}><Card sx={{ width: '100%' }}><CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}><Box display="flex" alignItems="center" mb={1}><InfoIcon color="primary" sx={{ mr: 1 }} /><Typography variant="h6">{i18nText("removed:m_37b931c3ef2914c51753")}</Typography></Box><Typography variant="h4" color="primary">{dbInfo?.version || i18nText("removed:m_b1b6b391498fb13c454c")}</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  {i18nText("removed:m_17e99997cb560c1ab485")}
                </Typography></CardContent></Card></Grid><Grid item xs={12} md={4} sx={{ display: 'flex' }}><Card sx={{ width: '100%' }}><CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}><Box display="flex" alignItems="center" mb={1}><StorageIcon color="secondary" sx={{ mr: 1 }} /><Typography variant="h6">{i18nText("removed:m_163a1f5490a50d7d1c6d")}</Typography></Box><Typography variant="h4" color="secondary">{formatBytes(dbInfo?.totalSize || 0)}</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  {i18nRichText("removed:m_6cfc2db7b4501ed137a8", { arg0: dbInfo?.fileCount || 0 })}
                </Typography></CardContent></Card></Grid><Grid item xs={12} md={4} sx={{ display: 'flex' }}><Card sx={{ width: '100%' }}><CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}><Box display="flex" alignItems="center" mb={1}><FolderIcon color="success" sx={{ mr: 1 }} /><Typography variant="h6">{i18nText("removed:m_6f262c78e6f3816c4c5a")}</Typography></Box><Typography variant="body2" sx={{ mt: 1, wordBreak: 'break-all', fontFamily: 'monospace' }}>{dbInfo?.dbPath || i18nText("removed:m_8dc598ebf1e055830140")}</Typography><Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                  {i18nRichText("removed:m_151fdcc3b0f7262a21b1", { arg0: dbInfo?.configRootPath || i18nText("removed:m_8dc598ebf1e055830140") })}
                </Typography></CardContent></Card></Grid></Grid>{/* Database Type Summary */}<Box mt={4}><Grid container spacing={2}>{Object.entries(filesByType).map(([type, files]) => {
                  const typeInfo = DB_TYPE_INFO[type] || DB_TYPE_INFO.other;
                  const totalSize = files.reduce((sum, f) => sum + f.size, 0);
                  
                  return (
                    <Grid item xs={12} sm={6} md={4} key={type}><Card variant="outlined"><CardContent><Box display="flex" alignItems="center" justifyContent="space-between" mb={1}><Chip label={metadataText(typeInfo, "label")} color={typeInfo.color} size="small" /><Typography variant="body2" color="text.secondary">
                              {i18nRichText("removed:m_4507816c2ef62e991dd9", { arg0: files.length })}
                            </Typography></Box><Typography variant="h6" color="primary">{formatBytes(totalSize)}</Typography></CardContent></Card></Grid>
                  );
                })}</Grid></Box>{/* Database Files Table */}{dbInfo && dbInfo.files.length > 0 ? (
          <><Typography variant="h5" gutterBottom sx={{ mt: 4, mb: 2 }}>
              {i18nText("removed:m_45c62a0d8a3de70d93af")}
            </Typography><TableContainer component={Paper}><Table><TableHead><TableRow><TableCell>{i18nRichText("removed:m_59199fd72f93edc668a9", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell><TableCell>{i18nRichText("removed:m_38ccd876bc0ea0d76303", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell><TableCell>{i18nRichText("removed:m_f8bcb675bdb0fb02957a", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell><TableCell>{i18nRichText("removed:m_3bbafe2c2d010ec8fed7", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell><TableCell>{i18nRichText("removed:m_055b4c5cb3abb7dceac0", { tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}</TableCell></TableRow></TableHead><TableBody>{dbInfo.files.map((file) => {
                    const typeInfo = DB_TYPE_INFO[file.type] || DB_TYPE_INFO.other;
                    const description = finalCopyText(DB_DESCRIPTIONS[file.name]) || translate("removed:m_4112d810e465c87bde04");
                    
                    return (
                      <TableRow key={file.path} hover><TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>{file.name}</Typography></TableCell><TableCell><Chip label={metadataText(typeInfo, "label")}
                            color={typeInfo.color}
                            size="small" /></TableCell><TableCell><Typography variant="body2">{formatBytes(file.size)}</Typography></TableCell><TableCell><Typography variant="body2" color="text.secondary">{formatTimestamp(file.modifiedTime, 'seconds')}</Typography></TableCell><TableCell><Typography variant="body2" color="text.secondary">{description}</Typography></TableCell></TableRow>
                    );
                  })}</TableBody></Table></TableContainer></>
        ) : (
          <Alert severity="warning" sx={{ mt: 4 }}><AlertTitle>{i18nText("removed:m_1003323b27d060f313e2")}</AlertTitle><Typography variant="body2">
              {i18nRichText("removed:m_e36bbd5c15efa946738f", { arg0: dbInfo?.dbPath || i18nText("removed:m_a638aaf6671badb143fe") })}
            </Typography><Typography variant="body2" sx={{ mt: 2 }}>
              {i18nText("removed:m_71bdb160ed830f8ccec6")}
            </Typography><Typography variant="body2" component="pre" sx={{ mt: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
              {rawCode("net util -download-dbs")}
            </Typography></Alert>
        )}</Box>{/* Snackbar for update notifications */}<Snackbar open={snackbarOpen}
        autoHideDuration={6000}
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}><Alert onClose={handleSnackbarClose} severity={snackbarSeverity} sx={{ width: '100%' }}>{i18nRenderText(snackbarMessage)}</Alert></Snackbar></Layout>
  );
}
