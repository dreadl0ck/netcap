import { Box, Stack, Typography } from '@mui/material';
import { formatBytes } from '../lib/api';

export default function DirectionalTraffic({ client, server, flows }: { client: number; server: number; flows?: number }) {
  const total = client + server;
  const clientPercent = total > 0 ? client / total * 100 : 0;
  return <Stack spacing={1}>
    <Stack direction="row" justifyContent="space-between" alignItems="baseline">
      <Typography variant="h6" sx={{ fontVariantNumeric: 'tabular-nums' }}>{formatBytes(total)} <Typography component="span" variant="caption" color="text.secondary">total</Typography></Typography>
      {flows !== undefined && <Typography variant="body2" color="text.secondary">{flows.toLocaleString()} {flows === 1 ? 'flow' : 'flows'}</Typography>}
    </Stack>
    <Box role="img" aria-label={`Client to server ${formatBytes(client)}, server to client ${formatBytes(server)}`} sx={{ display: 'flex', height: 8, borderRadius: 1, overflow: 'hidden', bgcolor: 'action.hover' }}>
      <Box sx={{ width: `${clientPercent}%`, bgcolor: 'primary.main' }} />
      <Box sx={{ width: `${total > 0 ? 100 - clientPercent : 0}%`, bgcolor: 'secondary.main' }} />
    </Box>
    <Stack direction="row" justifyContent="space-between" gap={2}>
      <Box><Typography variant="caption" color="text.secondary">Client → Server</Typography><Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>{formatBytes(client)} <Typography component="span" variant="caption" color="text.secondary">({clientPercent.toFixed(1)}%)</Typography></Typography></Box>
      <Box sx={{ textAlign: 'right' }}><Typography variant="caption" color="text.secondary">Server → Client</Typography><Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>{formatBytes(server)} <Typography component="span" variant="caption" color="text.secondary">({total > 0 ? (100 - clientPercent).toFixed(1) : '0.0'}%)</Typography></Typography></Box>
    </Stack>
  </Stack>;
}
