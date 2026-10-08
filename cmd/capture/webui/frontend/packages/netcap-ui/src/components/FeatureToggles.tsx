import { useState } from 'react';
import { Alert, Box, Card, CardContent, Chip, FormControlLabel, Switch, Typography } from '@mui/material';
import useSWR from 'swr';
import { useNetcapApi } from '../hooks';

/** Settings card listing optional features with per-feature switches. */
export function FeatureToggles() {
  const api = useNetcapApi();
  const { data, error, mutate } = useSWR('features', () => api.getFeatures());
  const [pending, setPending] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  if (error) return <Alert severity="warning" sx={{ mb: 3 }}>Features are unavailable: {String(error.message || error)}</Alert>;
  if (!data || data.features.length === 0) return null;
  const toggle = async (name: string, enabled: boolean) => {
    setPending(name);
    setFailure(null);
    try {
      await mutate(await api.setFeature(name, enabled), { revalidate: false });
    } catch (e: any) {
      setFailure(String(e?.message || e));
    } finally {
      setPending(null);
    }
  };
  return (
    <Card sx={{ mb: 3 }} data-testid="feature-toggles"
      data-learn="Features: optional capabilities that can be switched on or off individually. Query features apply to the next request; capture features apply to the next analysis started here. Each has a capture flag and environment variable for startup state.">
      <CardContent>
        <Typography variant="h6" gutterBottom>Features</Typography>
        {failure && <Alert severity="error" sx={{ mb: 1 }} onClose={() => setFailure(null)}>{failure}</Alert>}
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          {data.features.map(feature => (
            <Box key={feature.name}>
              <FormControlLabel
                control={<Switch checked={feature.enabled} disabled={pending === feature.name}
                  onChange={e => toggle(feature.name, e.target.checked)} slotProps={{ input: { 'aria-label': feature.title } }} />}
                label={<Box component="span" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {feature.title}
                  <Chip size="small" variant="outlined" label={feature.scope === 'query' ? 'applies immediately' : 'applies to next analysis'} />
                </Box>}
              />
              <Typography variant="body2" color="text.secondary" sx={{ ml: 6 }}>{feature.description}</Typography>
              <Typography variant="caption" color="text.secondary" sx={{ ml: 6, fontFamily: 'monospace' }}>{feature.flag} · {feature.env}</Typography>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );
}

export default FeatureToggles;
