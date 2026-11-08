import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';

export interface SoftwareObservation {
  host: string; role: string; timestampNs: string; vulnerabilityAssessment: string;
}

export default function SoftwareEvidence({ observations, capped }: {
  observations?: SoftwareObservation[]; capped?: boolean;
}) {
  return <Box sx={{ my: 2 }}>
    <Alert severity="info">Risk flags are observations, not proof of a current vulnerability assessment or vendor lifecycle status. Missing host or assessment evidence is unavailable.</Alert>
    {!observations?.length ? <p>Host and assessment evidence unavailable.</p> : <details>
      <summary>Host and assessment observations ({observations.length}{capped ? '+, capped' : ''})</summary>
      <Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(observations.map(item => ({
        host: item.host || 'unavailable', role: item.role || 'unavailable', timestampNs: item.timestampNs,
        vulnerabilityAssessment: item.vulnerabilityAssessment || 'unavailable',
      })), null, 2)}</Box>
    </details>}
  </Box>;
}
