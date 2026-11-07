import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { CertificateAssessmentNotice, certificateValidityLabel, RecordSemantics } from '../../packages/netcap-ui/src/components/RecordSemantics';

afterEach(cleanup);
describe('audit evidence semantics', () => {
  it('does not infer validity from legacy false flags', () => {
    expect(certificateValidityLabel({ daysUntilExpiration: 100 })).toContain('unavailable');
    render(<CertificateAssessmentNotice cert={{}} />);
    expect(screen.getByText(/false flags do not establish validity/)).toBeInTheDocument();
  });
  it('preserves capture nanoseconds and assessment limitations', () => {
    const cert = { assessmentBasis: 'capture-time', assessmentTimeNs: '1590969600000000123', validityState: 'valid', selfSignatureState: 'verified', certificateSender: 'client', daysUntilExpiration: 12 };
    expect(certificateValidityLabel(cert)).toBe('12 days remaining at observation');
    render(<CertificateAssessmentNotice cert={cert} />);
    expect(screen.getByText(/1590969600000000123 ns/)).toBeInTheDocument();
    expect(screen.getByText(/does not verify hostname, trust chain or revocation/)).toBeInTheDocument();
  });
  for (const outcome of ['accepted', 'rejected', 'not-observed', 'malformed']) it(`RDP ${outcome} does not establish login`, () => {
    render(<RecordSemantics data={{ NegotiationOutcome: outcome, AuthenticationOutcome: 'unknown', ConnectionSuccessful: outcome === 'accepted' }} />);
    expect(screen.getByText(/authentication: unknown/)).toBeInTheDocument();
    expect(screen.getByText(/not proof of login/)).toBeInTheDocument();
  });
  it('labels legacy RDP data', () => {
    render(<RecordSemantics data={{ ConnectionSuccessful: true }} />);
    expect(screen.getByText(/legacy-unqualified/)).toBeInTheDocument();
  });
});
