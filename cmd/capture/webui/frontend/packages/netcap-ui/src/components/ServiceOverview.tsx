import { Accordion, AccordionDetails, AccordionSummary, Box, Chip, Stack, Typography } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import type { ServiceSummary } from '../pages/ServicesPage';
import { formatTimestamp } from '../lib/api';
import DirectionalTraffic from './DirectionalTraffic';

export default function ServiceOverview({ service: svc }: { service: ServiceSummary }) {
  const fields = [['Product', svc.product], ['Vendor', svc.vendor], ['Version', svc.version], ['OS', svc.os], ['Hostname', svc.hostname], ['Detected protocol', svc.detectedProtocolName]].filter(([, value]) => value);
  const panel = { p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 2, bgcolor: 'background.paper' };
  return <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'minmax(0, 1fr) minmax(0, 1fr)' }, gap: 2 }}>
    <Stack spacing={2} sx={panel}>
      <Stack direction="row" justifyContent="space-between" alignItems="center" gap={1} flexWrap="wrap">
        <Box><Typography variant="caption" color="text.secondary">SERVICE ENDPOINT</Typography><Typography variant="h6" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>{svc.ip}:{svc.port}</Typography></Box>
        <Stack direction="row" gap={0.5}>{svc.name && <Chip size="small" label={svc.name} color="primary" variant="outlined" />}<Chip size="small" label={svc.protocol} /></Stack>
      </Stack>
      <DirectionalTraffic client={svc.bytesClient} server={svc.bytesServer} flows={svc.numFlows} />
      <Typography variant="caption" color="text.secondary">Observed {formatTimestamp(svc.timestamp)}</Typography>
    </Stack>
    {fields.length > 0 && <Box sx={panel}><Typography variant="subtitle2" sx={{ mb: 1 }}>Service identity</Typography><Box component="dl" sx={{ display: 'grid', gridTemplateColumns: 'auto minmax(0, 1fr)', columnGap: 2, rowGap: 0.75, m: 0 }}>
      {fields.map(([label, value]) => <Box key={label} sx={{ display: 'contents' }}><Typography component="dt" variant="body2" color="text.secondary">{label}</Typography><Typography component="dd" variant="body2" sx={{ m: 0, overflowWrap: 'anywhere' }}>{value}</Typography></Box>)}
    </Box></Box>}
    {svc.banner && <Accordion disableGutters variant="outlined" sx={{ gridColumn: '1 / -1', '&:before': { display: 'none' } }}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ '&:hover': { bgcolor: 'action.hover' } }}><Stack spacing={0.25} sx={{ minWidth: 0 }}><Typography variant="subtitle2">Server banner</Typography><Typography variant="caption" color="text.secondary" noWrap sx={{ fontFamily: 'monospace' }}>{svc.banner.split(/\r?\n/)[0]}</Typography></Stack></AccordionSummary>
      <AccordionDetails><Box component="pre" sx={{ m: 0, p: 1.5, borderRadius: 1, bgcolor: 'action.hover', fontSize: '0.8rem', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 280, overflow: 'auto' }}>{svc.banner}</Box></AccordionDetails>
    </Accordion>}
  </Box>;
}
