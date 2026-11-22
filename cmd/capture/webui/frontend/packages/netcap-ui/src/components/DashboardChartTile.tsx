/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { forwardRef, useEffect, useState, useMemo, type CSSProperties, type ReactNode } from 'react';
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
import { message as i18nMessage, translate as i18nText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { recordTypeLabel, suppliedMetadataText, errorText } from "../lib/i18n";


interface Props {
  chart: DashboardChart;
  editing: boolean;
  available: boolean; // false if the audit record type is missing in current scope
  /** Scope passed to the chart endpoint: 'all', 'current', or a pcap id/path. */
  scope?: string;
  onEdit?: (chart: DashboardChart) => void;
  onDelete?: (chartId: string) => void;
  /** Reports whether the chart has data in the current scope. */
  onEmptyChange?: (chartId: string, empty: boolean) => void;
  // react-grid-layout passes through these props on the wrapped element
  className?: string;
  style?: CSSProperties;
  children?: ReactNode;
  onMouseDown?: (e: any) => void;
  onMouseUp?: (e: any) => void;
  onTouchEnd?: (e: any) => void;
}

const DashboardChartTile = forwardRef<HTMLDivElement, Props>(function DashboardChartTile(
  { chart, editing, available, scope, onEdit, onDelete, onEmptyChange, className, style, children, onMouseDown, onMouseUp, onTouchEnd },
  ref,
) {
  const __uiLocale = useUILocale();
  const [refreshKey, setRefreshKey] = useState(0);
  const [loadError, setLoadError] = useState<UIMessageText | null>(null);
  const [empty, setEmpty] = useState(false);

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
    if (!available) {
      onEmptyChange?.(chart.id, true);
      return;
    }
    let cancelled = false;
    setLoadError(null);
    setEmpty(false);
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 30000);
    fetch(iframeSrc, { method: 'GET', signal: controller.signal })
      .then(async (res) => {
        if (cancelled) return;
        const noData = res.status === 204;
        setEmpty(noData);
        onEmptyChange?.(chart.id, noData);
        if (!res.ok) {
          const body = (await res.text()).trim();
          setLoadError(body || i18nMessage("ui:m_b9d4156d6812609b290c", { arg0: res.status }));
        }
      })
      .catch((err) => {
        if (cancelled) return;
        if (err && err.name === 'AbortError') {
          setLoadError(i18nMessage("ui:m_c8da3774e7ac2729c228"));
          return;
        }
        console.error('[DashboardChartTile] chart probe failed', err);
        setLoadError(errorText(err) || i18nMessage("ui:m_6fe1f773940b7c09de12"));
      })
      .finally(() => {
        window.clearTimeout(timeout);
      });
    return () => {
      cancelled = true;
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, [iframeSrc, available, refreshKey, chart.id, onEmptyChange]);

  return (
    <Box ref={ref}
      className={className}
      // Tile must fill its react-grid-layout cell entirely; Box defaults
      // collapse to content height otherwise.
      style={{ width: '100%', height: '100%', ...style }}
      onMouseDown={onMouseDown}
      onMouseUp={onMouseUp}
      onTouchEnd={onTouchEnd}><Card data-learn={suppliedMetadataText(chart, 'description') || undefined}
        sx={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}><Box className="dashboard-tile-header"
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            px: 1.75,
            py: 0.85,
            borderBottom: 1,
            borderColor: 'divider',
            cursor: editing ? 'move' : 'default',
            background: 'linear-gradient(90deg, rgba(59,130,246,.07), rgba(139,92,246,.025))',
          }}><Box sx={{ minWidth: 0, flex: 1 }}><Typography variant="subtitle2" noWrap title={suppliedMetadataText(chart, 'title')}>{suppliedMetadataText(chart, 'title')}</Typography><Typography variant="caption" color="text.secondary" noWrap sx={{ fontFamily: 'var(--netcap-mono)', fontSize: '.65rem' }}>{recordTypeLabel(chart.auditType)}· {chart.field}· {chart.chartType}</Typography></Box><Box sx={{ display: 'flex', gap: 0.5, ml: 1 }} onMouseDown={(e) => e.stopPropagation()}>{chart.description && (
              <Tooltip title={<Typography variant="caption" sx={{ whiteSpace: 'pre-wrap' }}>{suppliedMetadataText(chart, 'description')}</Typography>}
                arrow
                placement="top"><IconButton size="small" aria-label={i18nText("ui:m_1cc48346b3e932af8879")}><InfoOutlinedIcon fontSize="small" /></IconButton></Tooltip>
            )}<Tooltip title={i18nText("ui:m_230fc1b63eb3ef4e6a34")}><IconButton size="small" onClick={() => setRefreshKey((k) => k + 1)}><RefreshIcon fontSize="small" /></IconButton></Tooltip>{editing && (
              <><Tooltip title={i18nText("ui:m_91ec71a4ce56c8d61d29")}><IconButton size="small" onClick={() => onEdit?.(chart)}><EditIcon fontSize="small" /></IconButton></Tooltip><Tooltip title={i18nText("ui:m_7d088d9465c7e460a1df")}><IconButton size="small" color="error" onClick={() => onDelete?.(chart.id)}><DeleteIcon fontSize="small" /></IconButton></Tooltip></>
            )}</Box></Box><CardContent sx={{ flex: 1, p: 0, '&:last-child': { p: 0 }, position: 'relative', minHeight: 0 }}>{!available || empty ? (
            <Box sx={{ p: 2, height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Typography variant="body2" color="text.secondary" align="center">
                {i18nText("ui:m_b7d6ef18736c5a923259")}
              </Typography></Box>
          ) : loadError ? (
            <Box sx={{ p: 2, height: '100%', overflow: 'auto' }}><Alert severity="error" sx={{ mb: 1 }}>
                {i18nText("ui:m_81d5222e8d9541adb4f7")}
              </Alert><Typography variant="caption" component="pre" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'var(--netcap-mono)', m: 0 }}>{i18nRenderText(loadError)}</Typography></Box>
          ) : (
            <ChartFrame key={refreshKey}
              src={iframeSrc}
              title={suppliedMetadataText(chart, 'title')}
              style={{ width: '100%', height: '100%', border: 'none', display: 'block' }} />
          )}</CardContent></Card>{children}</Box>
  );
});

export default DashboardChartTile;
