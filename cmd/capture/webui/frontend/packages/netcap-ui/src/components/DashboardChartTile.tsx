/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { forwardRef, useEffect, useRef, useState, useMemo, type CSSProperties, type ReactNode } from 'react';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import RefreshIcon from '@mui/icons-material/Refresh';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';

import { getBackendUrl } from '../lib/api';
import type { DashboardChart } from '../lib/api';

import { ChartFrame } from './ChartFrame';
interface Props {
  chart: DashboardChart;
  editing: boolean;
  available: boolean; // false if the audit record type is missing in current scope
  /** Scope passed to the chart endpoint: 'all', 'current', or a pcap id/path. */
  scope?: string;
  onEdit?: (chart: DashboardChart) => void;
  onDelete?: (chartId: string) => void;
  // react-grid-layout passes through these props on the wrapped element
  className?: string;
  style?: CSSProperties;
  children?: ReactNode;
  onMouseDown?: (e: any) => void;
  onMouseUp?: (e: any) => void;
  onTouchEnd?: (e: any) => void;
}

const DashboardChartTile = forwardRef<HTMLDivElement, Props>(function DashboardChartTile(
  { chart, editing, available, scope, onEdit, onDelete, className, style, children, onMouseDown, onMouseUp, onTouchEnd },
  ref,
) {
  const [refreshKey, setRefreshKey] = useState(0);
  const [loadError, setLoadError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Debounced re-mount of iframe when the tile resizes so that go-echarts
  // re-renders at the new dimensions.
  useEffect(() => {
    const node = containerRef.current;
    if (!node) return;
    let timer: number | undefined;
    const ro = new ResizeObserver(() => {
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(() => setRefreshKey((k) => k + 1), 250);
    });
    ro.observe(node);
    return () => {
      ro.disconnect();
      if (timer) window.clearTimeout(timer);
    };
  }, []);

  const iframeSrc = useMemo(() => {
    const params = new URLSearchParams({
      type: chart.auditType,
      field: chart.field,
      chartType: chart.chartType,
      showLegend: chart.showLegend ? 'true' : 'false',
      maxDataPoints: String(chart.maxDataPoints || 1000),
    });
    if (chart.interval) params.set('interval', chart.interval);
    if (scope) params.set('scope', scope);
    return `${getBackendUrl()}/api/chart/data?${params.toString()}`;
  }, [chart.auditType, chart.field, chart.chartType, chart.showLegend, chart.maxDataPoints, chart.interval, scope]);

  // Probe the chart endpoint so we can show a clear error message instead of a
  // blank iframe (browsers don't surface non-2xx responses inside iframes).
  // The iframe still renders in parallel for the success path, avoiding a
  // double-load delay.
  useEffect(() => {
    if (!available) return;
    let cancelled = false;
    setLoadError(null);
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 30000);
    fetch(iframeSrc, { method: 'GET', signal: controller.signal })
      .then(async (res) => {
        if (cancelled) return;
        if (!res.ok) {
          const body = (await res.text()).trim();
          setLoadError(body || `Chart endpoint returned HTTP ${res.status}`);
        }
      })
      .catch((err) => {
        if (cancelled || (err && err.name === 'AbortError')) return;
        console.error('[DashboardChartTile] chart probe failed', err);
        setLoadError((err as Error).message || 'Failed to load chart');
      })
      .finally(() => {
        window.clearTimeout(timeout);
      });
    return () => {
      cancelled = true;
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, [iframeSrc, available, refreshKey]);

  return (
    <Box
      ref={(node: HTMLDivElement | null) => {
        containerRef.current = node;
        if (typeof ref === 'function') ref(node);
        else if (ref) (ref as React.MutableRefObject<HTMLDivElement | null>).current = node;
      }}
      className={className}
      // Tile must fill its react-grid-layout cell entirely; Box defaults
      // collapse to content height otherwise.
      style={{ width: '100%', height: '100%', ...style }}
      onMouseDown={onMouseDown}
      onMouseUp={onMouseUp}
      onTouchEnd={onTouchEnd}
    >
      <Card
        data-learn={chart.description || undefined}
        sx={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
      >
        <Box
          className="dashboard-tile-header"
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            px: 1.5,
            py: 0.5,
            borderBottom: 1,
            borderColor: 'divider',
            cursor: editing ? 'move' : 'default',
            backgroundColor: 'background.paper',
          }}
        >
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography variant="subtitle2" noWrap title={chart.title}>
              {chart.title}
            </Typography>
            <Typography variant="caption" color="text.secondary" noWrap>
              {chart.auditType} · {chart.field} · {chart.chartType}
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', gap: 0.5, ml: 1 }} onMouseDown={(e) => e.stopPropagation()}>
            {chart.description && (
              <Tooltip
                title={
                  <Typography variant="caption" sx={{ whiteSpace: 'pre-wrap' }}>
                    {chart.description}
                  </Typography>
                }
                arrow
                placement="top"
              >
                <IconButton size="small" aria-label="About this chart">
                  <InfoOutlinedIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
            <Tooltip title="Refresh">
              <IconButton size="small" onClick={() => setRefreshKey((k) => k + 1)}>
                <RefreshIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            {editing && (
              <>
                <Tooltip title="Edit chart">
                  <IconButton size="small" onClick={() => onEdit?.(chart)}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Delete chart">
                  <IconButton size="small" color="error" onClick={() => onDelete?.(chart.id)}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              </>
            )}
          </Box>
        </Box>
        <CardContent sx={{ flex: 1, p: 0, '&:last-child': { p: 0 }, position: 'relative', minHeight: 0 }}>
          {!available ? (
            <Box sx={{ p: 2, height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Typography variant="body2" color="text.secondary" align="center">
                Audit record type <strong>{chart.auditType}</strong> not present in the current output directory.
              </Typography>
            </Box>
          ) : loadError ? (
            <Box sx={{ p: 2, height: '100%', overflow: 'auto' }}>
              <Alert severity="error" sx={{ mb: 1 }}>
                Failed to render chart
              </Alert>
              <Typography variant="caption" component="pre" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace', m: 0 }}>
                {loadError}
              </Typography>
            </Box>
          ) : (
            <ChartFrame
              key={refreshKey}
              src={iframeSrc}
              title={chart.title}
              style={{ width: '100%', height: '100%', border: 'none', display: 'block' }}
            />
          )}
        </CardContent>
      </Card>
      {children}
    </Box>
  );
});

export default DashboardChartTile;
