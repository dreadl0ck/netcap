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
import Typography from '@mui/material/Typography';

import { CHART_TYPES } from '../lib/chartConfig';
import { useNetcapApi } from '../hooks';
import type { DashboardChart } from '../lib/api';
import { message as i18nMessage, translate as i18nText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { errorText, fieldLabel, recordTypeLabel } from "../lib/i18n";
import { metadataText, translate } from "../lib/i18n";




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
  const __uiLocale = useUILocale();
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
  const [fieldsError, setFieldsError] = useState<UIMessageText | null>(null);

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
          setFieldsError(i18nMessage("ui:m_d47c5225ba937a36fdd2", { arg0: auditType }));
        } else if (!res.fields.some((f) => f.name === field)) {
          setField(res.fields[0].name);
        }
      })
      .catch((err: Error) => {
        if (cancelled) return;
        console.error('[ChartConfigDialog] getChartFields failed', err);
        setFieldsError(errorText(err) || i18nMessage("ui:m_fa2da71362a5e043ae67", { arg0: auditType }));
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
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth><DialogTitle>{initial?.id ? i18nText("ui:m_1a9f13f5ce418d79057a") : i18nText("ui:m_9194f7c4d9b324362224")}</DialogTitle><DialogContent><Stack spacing={2} sx={{ mt: 1 }}><TextField label={i18nText("ui:m_629474760b8835c24f58")}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            fullWidth
            required /><TextField label={i18nText("ui:m_c4d163cb8523809177be")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder={i18nText("ui:m_558522d2f2ef42500af9")}
            fullWidth
            multiline
            minRows={2}
            maxRows={4} /><FormControl fullWidth required><InputLabel>{i18nText("ui:m_8967f6bff900534033ae")}</InputLabel><Select value={auditType}
              label={i18nText("ui:m_8967f6bff900534033ae")}
              onChange={(e: SelectChangeEvent) => setAuditType(e.target.value)}>{sortedAuditTypes.length === 0 && (
                <MenuItem value="" disabled>
                  {i18nText("ui:m_a6b64afbfd016bdbdc6a")}
                </MenuItem>
              )}{sortedAuditTypes.map((t) => (
                <MenuItem key={t} value={t}>{t}</MenuItem>
              ))}</Select></FormControl><FormControl fullWidth required disabled={!auditType || fieldsLoading}><InputLabel>{i18nText("ui:m_3f7b74092bb8729b554f")}</InputLabel><Select value={field}
              label={i18nText("ui:m_3f7b74092bb8729b554f")}
              onChange={(e: SelectChangeEvent) => setField(e.target.value)}
              endAdornment={fieldsLoading ? <CircularProgress size={18} sx={{ mr: 4 }} /> : undefined}>{fields.map((f) => (
                <MenuItem key={f.name} value={f.name}>{fieldLabel(f.name, auditType)}<Typography component="span" sx={{ ml: 1, color: 'text.secondary' }}>({metadataText(f, 'type')})</Typography></MenuItem>
              ))}</Select></FormControl>{i18nRenderText(fieldsError) && <Alert severity="warning">{i18nRenderText(fieldsError)}</Alert>}<FormControl fullWidth required><InputLabel>{i18nText("ui:m_79c0705a0b89e49733cb")}</InputLabel><Select value={chartType}
              label={i18nText("ui:m_79c0705a0b89e49733cb")}
              onChange={(e: SelectChangeEvent) => setChartType(e.target.value)}>{CHART_TYPES.map((c) => (
                <MenuItem key={c.value} value={c.value}>{translate(c.label)}</MenuItem>
              ))}</Select></FormControl><TextField label={i18nText("ui:m_2258d011a9eca19fd546")}
            value={interval}
            onChange={(e) => setIntervalStr(e.target.value)}
            fullWidth /><TextField label={i18nText("ui:m_eaccbfb766ad1bd6626e")}
            type="number"
            value={maxDataPoints}
            onChange={(e) => setMaxDataPoints(Math.max(1, parseInt(e.target.value || '1000', 10)))}
            fullWidth /><FormControlLabel control={<Switch checked={showLegend} onChange={(e) => setShowLegend(e.target.checked)} />}
            label={i18nText("ui:m_4d0acc5f5600d5cd889c")} /></Stack></DialogContent><DialogActions><Button onClick={onClose}>{i18nText("ui:m_0095547326bed510a824")}</Button><Button onClick={handleSubmit} variant="contained" disabled={!canSubmit}>{initial?.id ? i18nText("ui:m_72bba814ee286eb80909") : i18nText("ui:m_44184266e152017ac805")}</Button></DialogActions></Dialog>
  );
}
