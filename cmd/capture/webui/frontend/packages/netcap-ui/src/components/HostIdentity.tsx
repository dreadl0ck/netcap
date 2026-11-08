import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';

export interface HostIdentityData {
  state: string;
  report?: {
    schema: number; overflow: number; unscopedRecords: number; limitations: string[];
    hosts: { ip: string; scope: string; hostname?: string; hostnameState: string;
      mac?: string; macState: string; evidence: unknown[]; accounts: unknown[]; bindings: unknown[] }[];
  };
}

export default function HostIdentity({ identity, ip }: { identity?: HostIdentityData; ip: string }) {
  const report = identity?.report;
  const hosts = report?.hosts.filter(host => host.ip === ip) || [];
  return <Box sx={{ my: 2 }}>
    <Typography variant="h6">Qualified identity evidence</Typography>
    <Alert severity="info">Names and accounts are scoped observations, not proof of an IP's current owner or signed-in user.</Alert>
    {!report || identity?.state !== 'available' ? <Typography>Identity evidence unavailable for this capture.</Typography> : <>
      <Typography>Omitted observations: {report.overflow}; unscoped records: {report.unscopedRecords}</Typography>
      {report.limitations?.map((limitation, i) => <Typography key={i} variant="body2">{limitation}</Typography>)}
      {hosts.length === 0 && <Typography>No scoped identity observations for this IP.</Typography>}
      {hosts.map((host, i) => <Box key={`${host.scope}:${i}`} sx={{ mt: 1 }}>
        <Typography>Scope: {host.scope || 'unavailable'}</Typography>
        <Typography>Hostname: {host.hostname || 'unavailable'} ({host.hostnameState}); MAC: {host.mac || 'unavailable'} ({host.macState})</Typography>
        <details><summary>Names, account evidence and link bindings (times in Unix ns)</summary>
          <Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify({ evidence: host.evidence, accounts: host.accounts, bindings: host.bindings }, null, 2)}</Box>
        </details>
      </Box>)}
    </>}
  </Box>;
}
