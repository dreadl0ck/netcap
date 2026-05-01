/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { useEffect, useState, useMemo } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { type SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Stack from '@mui/material/Stack';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';

import { CHART_TYPES } from '../lib/chartConfig';
import { useNetcapApi } from '../hooks';
import type { DashboardChart } from '../lib/api';

interface Props {
  open: boolean;
  initial?: Partial<DashboardChart>;
  availableAuditTypes: string[]; // names of audit record types present in the current scope
  /** Scope passed when probing chart fields ('all', 'current', or pcap id). */
  scope?: string;
  onClose: () => void;
  onSubmit: (chart: Omit<DashboardChart, 'id' | 'layout'>) => void;
}

export default function ChartConfigDialog({ open, initial, availableAuditTypes, scope, onClose, onSubmit }: Props) {
  const api = useNetcapApi();
  const [title, setTitle] = useState(initial?.title || '');
  const [description, setDescription] = useState(initial?.description || '');
  const [auditType, setAuditType] = useState(initial?.auditType || '');
  const [field, setField] = useState(initial?.field || '');
  const [chartType, setChartType] = useState(initial?.chartType || 'line');
  const [interval, setIntervalStr] = useState(initial?.interval || '');
  const [showLegend, setShowLegend] = useState(initial?.showLegend ?? true);
  const [maxDataPoints, setMaxDataPoints] = useState<number>(initial?.maxDataPoints || 1000);
  const [fields, setFields] = useState<{ name: string; type: string }[]>([]);
  const [fieldsLoading, setFieldsLoading] = useState(false);
  const [fieldsError, setFieldsError] = useState<string | null>(null);

  // Reset state when dialog opens with new initial values
  useEffect(() => {
    if (!open) return;
    setTitle(initial?.title || '');
    setDescription(initial?.description || '');
    setAuditType(initial?.auditType || '');
    setField(initial?.field || '');
    setChartType(initial?.chartType || 'line');
    setIntervalStr(initial?.interval || '');
    setShowLegend(initial?.showLegend ?? true);
    setMaxDataPoints(initial?.maxDataPoints || 1000);
  }, [open, initial]);

  // Load fields when audit type changes. The cancelled flag guards against
  // out-of-order responses if the user switches type rapidly.
  useEffect(() => {
    if (!auditType) {
      setFields([]);
      setFieldsError(null);
      return;
    }
    let cancelled = false;
    setFieldsLoading(true);
    setFieldsError(null);
    api.getChartFields(auditType, scope)
      .then((res) => {
        if (cancelled) return;
        setFields(res.fields);
        if (res.fields.length === 0) {
          setFieldsError(`No chartable fields available for ${auditType}.`);
        } else if (!res.fields.some((f) => f.name === field)) {
          setField(res.fields[0].name);
        }
      })
      .catch((err: Error) => {
        if (cancelled) return;
        console.error('[ChartConfigDialog] getChartFields failed', err);
        setFieldsError(err.message || `Failed to load fields for ${auditType}`);
        setFields([]);
      })
      .finally(() => {
        if (!cancelled) setFieldsLoading(false);
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auditType, scope]);

  const sortedAuditTypes = useMemo(() => [...availableAuditTypes].sort((a, b) => a.localeCompare(b)), [availableAuditTypes]);

  const canSubmit = title.trim() && auditType && field && chartType;

  const handleSubmit = () => {
    if (!canSubmit) return;
    onSubmit({
      title: title.trim(),
      description: description.trim() || undefined,
      auditType,
      field,
      chartType,
      interval: interval.trim() || undefined,
      showLegend,
      maxDataPoints,
    });
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{initial?.id ? 'Edit Chart' : 'Add Chart'}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField
            label="Title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            fullWidth
            required
          />
          <TextField
            label="Description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Explain what this chart shows and why it matters"
            fullWidth
            multiline
            minRows={2}
            maxRows={4}
          />
          <FormControl fullWidth required>
            <InputLabel>Audit Record Type</InputLabel>
            <Select
              value={auditType}
              label="Audit Record Type"
              onChange={(e: SelectChangeEvent) => setAuditType(e.target.value)}
            >
              {sortedAuditTypes.length === 0 && (
                <MenuItem value="" disabled>
                  No audit records available
                </MenuItem>
              )}
              {sortedAuditTypes.map((t) => (
                <MenuItem key={t} value={t}>{t}</MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl fullWidth required disabled={!auditType || fieldsLoading}>
            <InputLabel>Field</InputLabel>
            <Select
              value={field}
              label="Field"
              onChange={(e: SelectChangeEvent) => setField(e.target.value)}
              endAdornment={fieldsLoading ? <CircularProgress size={18} sx={{ mr: 4 }} /> : undefined}
            >
              {fields.map((f) => (
                <MenuItem key={f.name} value={f.name}>
                  {f.name} <span style={{ marginLeft: 8, opacity: 0.6 }}>({f.type})</span>
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          {fieldsError && <Alert severity="warning">{fieldsError}</Alert>}

          <FormControl fullWidth required>
            <InputLabel>Chart Type</InputLabel>
            <Select
              value={chartType}
              label="Chart Type"
              onChange={(e: SelectChangeEvent) => setChartType(e.target.value)}
            >
              {CHART_TYPES.map((c) => (
                <MenuItem key={c.value} value={c.value}>{c.label}</MenuItem>
              ))}
            </Select>
          </FormControl>

          <TextField
            label="Interval (optional, e.g. 1s, 1m, 1h)"
            value={interval}
            onChange={(e) => setIntervalStr(e.target.value)}
            fullWidth
          />

          <TextField
            label="Max Data Points"
            type="number"
            value={maxDataPoints}
            onChange={(e) => setMaxDataPoints(Math.max(1, parseInt(e.target.value || '1000', 10)))}
            fullWidth
          />

          <FormControlLabel
            control={<Switch checked={showLegend} onChange={(e) => setShowLegend(e.target.checked)} />}
            label="Show legend"
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" disabled={!canSubmit}>
          {initial?.id ? 'Save' : 'Add'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
