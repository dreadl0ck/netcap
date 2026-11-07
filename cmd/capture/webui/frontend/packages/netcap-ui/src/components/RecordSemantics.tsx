import { Alert } from '@mui/material';

export interface CertificateAssessmentFields {
  assessmentBasis?: string; assessmentTimeNs?: string; validityState?: string;
  selfSignatureState?: string; certificateSender?: string;
}

export function certificateValidityLabel(cert: CertificateAssessmentFields & { daysUntilExpiration: number }): string {
  if (cert.assessmentBasis !== 'capture-time' || !cert.validityState || cert.validityState === 'unavailable') return 'Assessment unavailable / legacy';
  if (cert.validityState === 'expired') return 'Expired at observation';
  if (cert.validityState === 'not-yet-valid') return 'Not yet valid at observation';
  if (cert.validityState !== 'valid') return 'Assessment unavailable';
  return `${cert.daysUntilExpiration} days remaining at observation`;
}

export function CertificateAssessmentNotice({ cert }: { cert: CertificateAssessmentFields }) {
  const known = cert.assessmentBasis === 'capture-time' && cert.validityState && cert.validityState !== 'unavailable';
  return <Alert severity={known ? 'info' : 'warning'}>
    {known ? `Certificate validity: ${cert.validityState} at capture time (${cert.assessmentTimeNs} ns).` : 'Certificate assessment is unavailable or legacy-unqualified; false flags do not establish validity.'}
    {' '}Self-signature: {cert.selfSignatureState || 'legacy-unqualified'}; sender: {cert.certificateSender || 'unknown'}.
    {' '}This does not verify hostname, trust chain or revocation.
  </Alert>;
}

export function RecordSemantics({ data }: { data: Record<string, unknown> }) {
  if ('NegotiationOutcome' in data || 'ConnectionSuccessful' in data) return <Alert severity="info">
    RDP negotiation: {String(data.NegotiationOutcome || 'legacy-unqualified')}; authentication: {String(data.AuthenticationOutcome || 'unknown')}.
    {' '}ConnectionSuccessful is legacy negotiation acceptance, not proof of login. Negotiated security is {data.NegotiatedSecurityKnown ? 'observed' : 'unknown'}.
  </Alert>;
  return null;
}
