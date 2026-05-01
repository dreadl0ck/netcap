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

import Layout from '../components/Layout';
import OverviewView from '../components/OverviewView';
import CustomDashboardView from '../components/CustomDashboardView';
import DashboardViewTabs, { OVERVIEW_VIEW_ID } from '../components/DashboardViewTabs';
import DashboardPcapScopeSelector, { ALL_PCAPS_SCOPE } from '../components/DashboardPcapScopeSelector';
import { useNetcapApi } from '../hooks';
import useSWR from 'swr';
import { DashboardApiError, type Dashboard } from '../lib/api';

const SCOPE_STORAGE_KEY = 'dashboard-pcap-scope';
const VIEW_STORAGE_KEY = 'dashboard-active-view';

function describeError(err: unknown): string {
  if (err instanceof DashboardApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

export default function DashboardPage() {
  const api = useNetcapApi();

  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const {
    data: dashboards,
    error: dashboardsError,
    mutate: mutateDashboards,
  } = useSWR('dashboards-list', () => api.listDashboards());

  // Page-level scope (persisted across reloads).
  const [scope, setScope] = useState<string>(() => {
    if (typeof window === 'undefined') return ALL_PCAPS_SCOPE;
    return window.localStorage.getItem(SCOPE_STORAGE_KEY) || ALL_PCAPS_SCOPE;
  });
  useEffect(() => {
    window.localStorage.setItem(SCOPE_STORAGE_KEY, scope);
  }, [scope]);

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
  const [actionError, setActionError] = useState<string | null>(null);

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
    if (!confirm(`Delete dashboard "${d.name}"? This cannot be undone.`)) return;
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
    <Layout title="Dashboard">
      <Stack spacing={2}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <DashboardPcapScopeSelector value={scope} onChange={setScope} inputFiles={inputFiles} />
          <Box sx={{ flex: 1 }} />
        </Box>

        <DashboardViewTabs
          dashboards={userDashboards}
          activeId={activeView}
          onSelect={setActiveView}
          onCreate={openCreate}
          onRename={openRename}
          onDuplicate={handleDuplicate}
          onDelete={handleDelete}
        />

        {dashboardsError && (
          <Alert
            severity={noOutDir ? 'info' : 'error'}
            action={<Button color="inherit" size="small" onClick={() => mutateDashboards()}>Retry</Button>}
          >
            {noOutDir
              ? 'Dashboards storage is unavailable. Check service configuration.'
              : `Failed to load dashboards: ${describeError(dashboardsError)}`}
          </Alert>
        )}
        {actionError && (
          <Alert severity="error" onClose={() => setActionError(null)}>{actionError}</Alert>
        )}

        {activeView === OVERVIEW_VIEW_ID ? (
          <OverviewView scope={scope} />
        ) : (
          <CustomDashboardView
            dashboardId={activeView}
            scope={scope}
            onForkComplete={(newId) => setActiveView(newId)}
          />
        )}
      </Stack>

      <Dialog open={dialogMode !== null} onClose={closeDialog} maxWidth="sm" fullWidth>
        <DialogTitle>{dialogMode === 'rename' ? 'Rename Dashboard' : 'New Dashboard'}</DialogTitle>
        <DialogContent>
          <TextField
            label="Name"
            value={draftName}
            onChange={(e) => setDraftName(e.target.value)}
            fullWidth
            autoFocus
            sx={{ mt: 1, mb: 2 }}
            required
          />
          <TextField
            label="Description (optional)"
            value={draftDesc}
            onChange={(e) => setDraftDesc(e.target.value)}
            fullWidth
            multiline
            rows={2}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={closeDialog} disabled={pending}>Cancel</Button>
          <Button onClick={handleDialogSubmit} variant="contained" disabled={!draftName.trim() || pending}>
            {dialogMode === 'rename' ? 'Save' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </Layout>
  );
}
