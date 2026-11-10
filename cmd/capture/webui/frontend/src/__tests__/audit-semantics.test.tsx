import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { CertificateAssessmentNotice, certificateValidityLabel, HTTPReassemblyNotice, RecordSemantics } from '../../packages/netcap-ui/src/components/RecordSemantics';

afterEach(cleanup);
describe('audit evidence semantics', () => {
  it('preserves actionable HTTP reassembly status without raw timestamp prose', () => {
    render(<HTTPReassemblyNotice status="unpaired_after_capture_loss" timestampNs="1590969600000000123" />);
    expect(screen.getByText(/unpaired_after_capture_loss/)).toBeInTheDocument();
    expect(screen.queryByText(/1590969600000000123 ns/)).not.toBeInTheDocument();
  });
  it('does not label a rounded generic HTTP timestamp as exact', () => {
    render(<RecordSemantics data={{ ReassemblyStatus: '', Timestamp: 1590969600000000123 }} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
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
    render(<RecordSemantics recordType="RDP" data={{ ConnectionSuccessful: true }} />);
    expect(screen.getByText(/legacy-unqualified/)).toBeInTheDocument();
  });
  it('does not interpret SOCKS connection success as RDP evidence', () => {
    render(<RecordSemantics recordType="SOCKS" data={{ ConnectionSuccessful: true }} />);
    expect(screen.queryByText(/RDP negotiation/)).not.toBeInTheDocument();
  });
  it('does not relabel an already formatted timestamp as exact nanoseconds', () => {
    render(<HTTPReassemblyNotice timestampNs="2020-06-01T00:00:00.000Z" />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
