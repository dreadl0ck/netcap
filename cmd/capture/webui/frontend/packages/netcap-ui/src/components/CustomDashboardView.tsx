/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useEffect, useMemo, useState, useCallback } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import CircularProgress from '@mui/material/CircularProgress';
import Tooltip from '@mui/material/Tooltip';
import Alert from '@mui/material/Alert';
import Stack from '@mui/material/Stack';
import Chip from '@mui/material/Chip';
import AddIcon from '@mui/icons-material/Add';
import SaveIcon from '@mui/icons-material/Save';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';

import { Responsive, WidthProvider, type Layout, type LayoutItem } from 'react-grid-layout/legacy';
import 'react-grid-layout/css/styles.css';

import DashboardChartTile from './DashboardChartTile';
import ChartConfigDialog from './ChartConfigDialog';
import { useNetcapApi } from '../hooks';
import useSWR, { mutate as globalMutate } from 'swr';
import { DashboardApiError, type Dashboard, type DashboardChart } from '../lib/api';

const ResponsiveGridLayout = WidthProvider(Responsive);

function describeError(err: unknown): string {
  if (err instanceof DashboardApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

function placeNewChart(charts: DashboardChart[], cols: number) {
  const maxY = charts.reduce((m, c) => Math.max(m, c.layout.y + c.layout.h), 0);
  return { x: 0, y: maxY, w: Math.min(6, cols), h: 4 };
}

function newChartId(): string {
  return 'c-' + Math.random().toString(36).slice(2, 10);
}

interface Props {
  dashboardId: string;
  scope: string;
  onForkComplete?: (newId: string) => void;
}

export default function CustomDashboardView({ dashboardId, scope, onForkComplete }: Props) {
  const api = useNetcapApi();

  const { data: loaded, error, isLoading, mutate } = useSWR(
    dashboardId ? ['dashboard', dashboardId] : null,
    () => api.getDashboard(dashboardId),
  );
  const { data: auditFiles } = useSWR(['auditFiles', scope], () => api.getAuditFiles(scope));

  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [editing, setEditing] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingChart, setEditingChart] = useState<DashboardChart | null>(null);

  useEffect(() => {
    if (loaded) {
      setDashboard(loaded);
      setDirty(false);
    }
  }, [loaded]);

  // Browser-level unsaved-changes guard
  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [dirty]);

  const availableTypes = useMemo(() => (auditFiles || []).map((f) => f.type), [auditFiles]);

  const handleLayoutChange = useCallback((layout: Layout) => {
    if (!dashboard || !editing) return;
    setDashboard((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        charts: prev.charts.map((c) => {
          const l = layout.find((x) => x.i === c.id);
          if (!l) return c;
          return { ...c, layout: { x: l.x, y: l.y, w: l.w, h: l.h } };
        }),
      };
    });
    setDirty(true);
  }, [dashboard, editing]);

  const openAddChart = () => { setEditingChart(null); setDialogOpen(true); };
  const openEditChart = (chart: DashboardChart) => { setEditingChart(chart); setDialogOpen(true); };

  const handleChartSubmit = (data: Omit<DashboardChart, 'id' | 'layout'>) => {
    if (!dashboard) return;
    if (editingChart) {
      setDashboard({
        ...dashboard,
        charts: dashboard.charts.map((c) => (c.id === editingChart.id ? { ...c, ...data } : c)),
      });
    } else {
      const layout = placeNewChart(dashboard.charts, dashboard.gridCols || 12);
      setDashboard({
        ...dashboard,
        charts: [...dashboard.charts, { id: newChartId(), layout, ...data }],
      });
    }
    setDirty(true);
    setDialogOpen(false);
    setEditingChart(null);
  };

  const handleDeleteChart = (chartId: string) => {
    if (!dashboard) return;
    if (!confirm('Remove this chart from the dashboard?')) return;
    setDashboard({ ...dashboard, charts: dashboard.charts.filter((c) => c.id !== chartId) });
    setDirty(true);
  };

  const handleSave = async () => {
    if (!dashboard) return;
    setSaving(true);
    setActionError(null);
    try {
      if (dashboard.builtin) {
        const saved = await api.createDashboard({
          name: dashboard.name,
          description: dashboard.description,
          charts: dashboard.charts.map((c) => ({ ...c, id: '' })),
          gridCols: dashboard.gridCols,
          rowHeight: dashboard.rowHeight,
        });
        await globalMutate('dashboards-list');
        setDirty(false);
        onForkComplete?.(saved.id);
        return;
      }
      const saved = await api.updateDashboard(dashboard.id, dashboard);
      setDashboard(saved);
      setDirty(false);
      await mutate(saved, { revalidate: false });
      await globalMutate('dashboards-list');
    } catch (err) {
      console.error('[CustomDashboardView] save failed', err);
      setActionError(describeError(err));
    } finally {
      setSaving(false);
    }
  };

  if (isLoading || !dashboard) {
    if (error) {
      const apiErr = error instanceof DashboardApiError ? error : null;
      return (
        <Stack spacing={2}>
          <Alert
            severity={apiErr?.noOutputDir ? 'info' : apiErr?.notFound ? 'warning' : 'error'}
            action={<Button color="inherit" size="small" onClick={() => mutate()}>Retry</Button>}
          >
            {apiErr?.noOutputDir
              ? 'No output directory selected. Select a session or PCAP first.'
              : apiErr?.notFound
                ? 'Dashboard not found. It may have been deleted.'
                : `Failed to load dashboard: ${describeError(error)}`}
          </Alert>
        </Stack>
      );
    }
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
        <CircularProgress />
      </Box>
    );
  }

  const layoutItems: LayoutItem[] = dashboard.charts.map((c) => ({
    i: c.id,
    x: c.layout.x,
    y: c.layout.y,
    w: c.layout.w,
    h: c.layout.h,
    minW: 2,
    minH: 2,
  }));

  return (
    <Stack spacing={2}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
        {dashboard.builtin && <Chip label="Built-in (read-only — Save to fork)" size="small" color="secondary" />}
        <Box sx={{ flex: 1 }} />
        {editing ? (
          <>
            <Button startIcon={<AddIcon />} onClick={openAddChart} variant="outlined">Add Chart</Button>
            <Button
              startIcon={<SaveIcon />}
              onClick={handleSave}
              variant="contained"
              disabled={saving || (!dirty && !dashboard.builtin)}
            >
              {saving ? 'Saving…' : dashboard.builtin ? 'Save as Copy' : 'Save'}
            </Button>
            <Tooltip title={dirty ? 'Save or discard your changes first' : ''}>
              <span>
                <Button startIcon={<VisibilityIcon />} onClick={() => setEditing(false)} disabled={dirty}>
                  View
                </Button>
              </span>
            </Tooltip>
          </>
        ) : (
          <Button startIcon={<EditIcon />} onClick={() => setEditing(true)} variant="outlined">Edit</Button>
        )}
      </Box>

      {actionError && (
        <Alert severity="error" onClose={() => setActionError(null)}>{actionError}</Alert>
      )}

      {dashboard.charts.length === 0 ? (
        <Alert severity="info">
          This dashboard has no charts. {editing ? 'Click "Add Chart" to add one.' : 'Click "Edit" then "Add Chart".'}
        </Alert>
      ) : (
        <Box sx={{
          '& .react-grid-placeholder': { backgroundColor: 'primary.main', opacity: 0.2, borderRadius: 1 },
        }}>
          <ResponsiveGridLayout
            className="layout"
            layouts={{ lg: layoutItems, md: layoutItems, sm: layoutItems, xs: layoutItems, xxs: layoutItems }}
            breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
            cols={{ lg: dashboard.gridCols || 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
            rowHeight={dashboard.rowHeight || 80}
            margin={[12, 12]}
            isDraggable={editing}
            isResizable={editing}
            draggableHandle=".dashboard-tile-header"
            onLayoutChange={(l: Layout) => handleLayoutChange(l)}
            compactType="vertical"
          >
            {dashboard.charts.map((c) => (
              <div key={c.id}>
                <DashboardChartTile
                  chart={c}
                  editing={editing}
                  scope={scope}
                  available={availableTypes.length === 0 ? true : availableTypes.includes(c.auditType)}
                  onEdit={openEditChart}
                  onDelete={handleDeleteChart}
                />
              </div>
            ))}
          </ResponsiveGridLayout>
        </Box>
      )}

      <ChartConfigDialog
        open={dialogOpen}
        initial={editingChart || undefined}
        availableAuditTypes={availableTypes}
        scope={scope}
        onClose={() => { setDialogOpen(false); setEditingChart(null); }}
        onSubmit={handleChartSubmit}
      />
    </Stack>
  );
}
