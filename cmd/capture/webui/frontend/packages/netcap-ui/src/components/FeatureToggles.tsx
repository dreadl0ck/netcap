import { useState } from 'react';
import { Alert, Box, Card, CardContent, Chip, FormControlLabel, Switch, Typography } from '@mui/material';

import { useNetcapApi } from '../hooks';
import { richText as i18nRichText, translate as i18nText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, metadataText } from "../lib/i18n";
import { renderError, renderUIMessage } from "../lib/i18n";
import { errorText } from "../lib/i18n";





/** Settings card listing optional features with per-feature switches. */
export function FeatureToggles() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const { data, error, mutate } = useSWR('features', () => api.getFeatures());
  const [pending, setPending] = useState<string | null>(null);
  const [failure, setFailure] = useState<UIMessageText | null>(null);
  if (error) return <Alert severity="warning" sx={{ mb: 3 }}>{i18nRichText("ui:m_23f4f600ba10020c926e", { arg0: String(renderError(error) || error) })}</Alert>;
  if (!data || data.features.length === 0) return null;
  const toggle = async (name: string, enabled: boolean) => {
    setPending(name);
    setFailure(null);
    try {
      await mutate(await api.setFeature(name, enabled), { revalidate: false });
    } catch (e: any) {
      setFailure(errorText(e));
    } finally {
      setPending(null);
    }
  };
  return (
    <Card sx={{ mb: 3 }} data-testid="feature-toggles"
      data-learn={i18nText("ui:m_fc66795e138b5c669aa3")}><CardContent><Typography variant="h6" gutterBottom>{i18nText("ui:m_3b03c0feb3985d604a7f")}</Typography>{i18nRenderText(failure) && <Alert severity="error" sx={{ mb: 1 }} onClose={() => setFailure(null)}>{i18nRenderText(failure)}</Alert>}<Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>{data.features.map(feature => (
            <Box key={feature.name}><FormControlLabel control={<Switch checked={feature.enabled} disabled={pending === feature.name}
                  onChange={e => toggle(feature.name, e.target.checked)} slotProps={{ input: { 'aria-label': metadataText(feature, "title") } }} />}
                label={<Box component="span" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>{metadataText(feature, "title")}<Chip size="small" variant="outlined" label={feature.scopeI18n ? renderUIMessage(feature.scopeI18n) : feature.scope === 'query' ? i18nText("ui:m_3ff44d65636ee8541133") : i18nText("ui:m_4fe871ff50c5a96b1f71")} /></Box>} /><Typography variant="body2" color="text.secondary" sx={{ ml: 6 }}>{metadataText(feature, "description")}</Typography><Typography variant="caption" color="text.secondary" sx={{ ml: 6, fontFamily: 'monospace' }}>{feature.flag}· {feature.env}</Typography></Box>
          ))}</Box></CardContent></Card>
  );
}

export default FeatureToggles;
