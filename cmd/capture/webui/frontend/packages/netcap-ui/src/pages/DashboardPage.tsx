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

import { useEffect, useMemo, useState } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Alert from '@mui/material/Alert';
import Stack from '@mui/material/Stack';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';

import Layout from '../components/Layout';
import OverviewView from '../components/OverviewView';
import CustomDashboardView from '../components/CustomDashboardView';
import DashboardViewTabs, { OVERVIEW_VIEW_ID } from '../components/DashboardViewTabs';
import DashboardPcapScopeSelector, { ALL_PCAPS_SCOPE } from '../components/DashboardPcapScopeSelector';
import { useNetcapApi, useNetcapRouter } from '../hooks';

import { DashboardApiError, type Dashboard } from '../lib/api';
import { setSelectedSession } from '../lib/captureSelection';
import { translate as i18nText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";



const SCOPE_STORAGE_KEY = 'dashboard-pcap-scope';
const VIEW_STORAGE_KEY = 'dashboard-active-view';

function describeError(err: unknown): string {
  if (err instanceof DashboardApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

export default function DashboardPage() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const router = useNetcapRouter();

  const { data: status } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const {
    data: dashboards,
    error: dashboardsError,
    mutate: mutateDashboards,
  } = useSWR('dashboards-list', () => api.listDashboards());

  // Service scope belongs to the URL. A bare landing always aggregates, even
  // in tabs that persisted the old "current" default without a selection.
  const sessionId = typeof router.query.sessionId === 'string' ? router.query.sessionId : undefined;
  const service = status?.isServiceMode ?? Boolean(sessionId);
  const [localScope, setLocalScope] = useState(() => {
    const saved = typeof window === 'undefined' ? null : window.sessionStorage.getItem(SCOPE_STORAGE_KEY);
    return saved && saved !== 'current' ? saved : ALL_PCAPS_SCOPE;
  });
  const localAvailable = inputFiles?.some(file => file.isCompleted && file.path === localScope);
  const scopeChoice = service ? sessionId || ALL_PCAPS_SCOPE : localAvailable ? localScope : ALL_PCAPS_SCOPE;
  const scope = service && sessionId ? 'current' : scopeChoice;
  const changeScope = (value: string) => {
    if (service) setSelectedSession(value === ALL_PCAPS_SCOPE ? null : value);
    else {
      setLocalScope(value);
      window.sessionStorage.setItem(SCOPE_STORAGE_KEY, value);
    }
  };

  // Active tab/view (persisted across reloads).
  const [activeView, setActiveView] = useState<string>(() => {
    if (typeof window === 'undefined') return OVERVIEW_VIEW_ID;
    return window.localStorage.getItem(VIEW_STORAGE_KEY) || OVERVIEW_VIEW_ID;
  });
  useEffect(() => {
    window.localStorage.setItem(VIEW_STORAGE_KEY, activeView);
  }, [activeView]);

  // If the persisted activeView no longer exists (e.g. user deleted it from
  // another tab), fall back to overview.
  useEffect(() => {
    if (!dashboards || activeView === OVERVIEW_VIEW_ID) return;
    if (!dashboards.some((d) => d.id === activeView)) {
      setActiveView(OVERVIEW_VIEW_ID);
    }
  }, [dashboards, activeView]);

  // New / rename dialog state
  const [dialogMode, setDialogMode] = useState<null | 'create' | 'rename'>(null);
  const [dialogTarget, setDialogTarget] = useState<Dashboard | null>(null);
  const [draftName, setDraftName] = useState('');
  const [draftDesc, setDraftDesc] = useState('');
  const [pending, setPending] = useState(false);
  const [actionError, setActionError] = useState<UIMessageText | null>(null);

  const openCreate = () => {
    setDialogTarget(null);
    setDraftName('');
    setDraftDesc('');
    setDialogMode('create');
  };
  const openRename = (d: Dashboard) => {
    setDialogTarget(d);
    setDraftName(d.name);
    setDraftDesc(d.description || '');
    setDialogMode('rename');
  };
  const closeDialog = () => {
    setDialogMode(null);
    setDialogTarget(null);
  };

  const handleDialogSubmit = async () => {
    const name = draftName.trim();
    if (!name) return;
    setPending(true);
    setActionError(null);
    try {
      if (dialogMode === 'create') {
        const created = await api.createDashboard({
          name,
          description: draftDesc.trim() || undefined,
          charts: [],
          gridCols: 12,
          rowHeight: 80,
        });
        await mutateDashboards();
        setActiveView(created.id);
      } else if (dialogMode === 'rename' && dialogTarget) {
        const updated = await api.updateDashboard(dialogTarget.id, {
          ...dialogTarget,
          name,
          description: draftDesc.trim() || undefined,
        });
        await mutateDashboards();
        // Force the per-dashboard SWR cache to refresh too.
        await api.getDashboard(updated.id);
      }
      closeDialog();
    } catch (err) {
      console.error('[Dashboard] dialog action failed', err);
      setActionError(describeError(err));
    } finally {
      setPending(false);
    }
  };

  const handleDuplicate = async (d: Dashboard) => {
    setActionError(null);
    try {
      const copy = await api.createDashboard({
        name: `${d.name} (copy)`,
        description: d.description,
        charts: d.charts.map((c) => ({ ...c, id: '' })),
        gridCols: d.gridCols,
        rowHeight: d.rowHeight,
      });
      await mutateDashboards();
      setActiveView(copy.id);
    } catch (err) {
      console.error('[Dashboard] duplicate failed', err);
      setActionError(describeError(err));
    }
  };

  const handleDelete = async (d: Dashboard) => {
    if (!confirm(i18nText("ui:m_558985f2bd4d42d27727", { arg0: d.name }))) return;
    setActionError(null);
    try {
      await api.deleteDashboard(d.id);
      await mutateDashboards();
      if (activeView === d.id) setActiveView(OVERVIEW_VIEW_ID);
    } catch (err) {
      console.error('[Dashboard] delete failed', err);
      setActionError(describeError(err));
    }
  };

  const noOutDir = dashboardsError instanceof DashboardApiError && dashboardsError.noOutputDir;

  // Build the tab list, filtering out overview placeholder.
  const userDashboards: Dashboard[] = useMemo(() => dashboards || [], [dashboards]);

  return (
    <Layout title={i18nText("ui:m_4030128748ac546a3cc2")}><Stack spacing={2}><Box sx={{
          display: 'flex',
          alignItems: { xs: 'stretch', md: 'center' },
          justifyContent: 'space-between',
          flexDirection: { xs: 'column', md: 'row' },
          gap: 2.5,
          py: { xs: 1, md: 2 },
        }}><Box><Chip label={i18nText("ui:m_36b211425443465c14c7")} color="primary" variant="outlined" size="small" sx={{ mb: 1.5, height: 24 }} /><Typography component="h2" variant="h2">{i18nText("ui:m_b2507e16ae0cc36bfb5e")}</Typography><Typography color="text.secondary" sx={{ mt: 0.75, maxWidth: 620 }}>
              {i18nText("ui:m_2cc7656d50b861f3c12f")}
            </Typography></Box><Box sx={{ minWidth: { md: 300 } }}><DashboardPcapScopeSelector value={scopeChoice} onChange={changeScope} inputFiles={inputFiles} useSessionIds={service} /></Box></Box><DashboardViewTabs dashboards={userDashboards}
          activeId={activeView}
          onSelect={setActiveView}
          onCreate={openCreate}
          onRename={openRename}
          onDuplicate={handleDuplicate}
          onDelete={handleDelete} />{dashboardsError && (
          <Alert severity={noOutDir ? 'info' : 'error'}
            action={<Button color="inherit" size="small" onClick={() => mutateDashboards()}>{i18nText("ui:m_3c4b66117cf7e2a0bf82")}</Button>}>{noOutDir ? i18nText("ui:m_3753827162223ed0ea2b") : i18nText("ui:m_07c32a8c753fc494832c", { arg0: describeError(dashboardsError) })}</Alert>
        )}{i18nRenderText(actionError) && (
          <Alert severity="error" onClose={() => setActionError(null)}>{i18nRenderText(actionError)}</Alert>
        )}{activeView === OVERVIEW_VIEW_ID ? (
          <OverviewView scope={scope} />
        ) : (
          <CustomDashboardView dashboardId={activeView}
            scope={scope}
            onForkComplete={(newId) => setActiveView(newId)} />
        )}</Stack><Dialog open={dialogMode !== null} onClose={closeDialog} maxWidth="sm" fullWidth><DialogTitle>{dialogMode === 'rename' ? i18nText("ui:m_3743eb9e935e9a5b11b3") : i18nText("ui:m_f39f7bc29a249c5ab8cb")}</DialogTitle><DialogContent><TextField label={i18nText("ui:m_e707e3dfaa88e6753600")}
            value={draftName}
            onChange={(e) => setDraftName(e.target.value)}
            fullWidth
            autoFocus
            sx={{ mt: 1, mb: 2 }}
            required /><TextField label={i18nText("ui:m_c4d163cb8523809177be")}
            value={draftDesc}
            onChange={(e) => setDraftDesc(e.target.value)}
            fullWidth
            multiline
            rows={2} /></DialogContent><DialogActions><Button onClick={closeDialog} disabled={pending}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button onClick={handleDialogSubmit} variant="contained" disabled={!draftName.trim() || pending}>{dialogMode === 'rename' ? i18nText("ui:m_72bba814ee286eb80909") : i18nText("ui:m_a09c62c4acf8363f90e2")}</Button></DialogActions></Dialog></Layout>
  );
}
