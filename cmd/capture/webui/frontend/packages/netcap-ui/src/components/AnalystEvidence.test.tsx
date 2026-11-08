import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import HostIdentity from './HostIdentity';
import SoftwareEvidence from './SoftwareEvidence';

afterEach(cleanup);
describe('qualified analyst evidence', () => {
  it('keeps competing identities scoped and preserves account evidence and exact times', () => {
    render(<HostIdentity ip="192.0.2.1" identity={{ state: 'available', report: {
      schema: 1, overflow: 2, unscopedRecords: 3, limitations: ['Capture scope only'], hosts: [
        { ip: '192.0.2.1', scope: 'capture-a/vlan-1', hostnameState: 'ambiguous', macState: 'ambiguous',
          accounts: [{ name: 'alice', at: '1700000000000000001', fullNameState: 'unknown' }], evidence: [], bindings: [{ mac: 'aa', source: 'observed-link-source' }] },
        { ip: '192.0.2.1', scope: 'capture-a/vlan-2', hostname: 'printer', hostnameState: 'observed', macState: 'unknown', accounts: [], evidence: [], bindings: [] },
        { ip: '192.0.2.2', scope: 'unrelated', hostname: 'NEVER_JOIN', hostnameState: 'observed', macState: 'unknown', accounts: [], evidence: [], bindings: [] },
      ],
    } }} />);
    expect(screen.getByText('Scope: capture-a/vlan-1')).toBeInTheDocument();
    expect(screen.getByText('Scope: capture-a/vlan-2')).toBeInTheDocument();
    expect(screen.getByText(/Hostname: unavailable \(ambiguous\)/)).toBeInTheDocument();
    expect(screen.getByText(/1700000000000000001/)).toBeInTheDocument();
    expect(screen.queryByText(/NEVER_JOIN/)).not.toBeInTheDocument();
    expect(screen.getByText(/Omitted observations: 2; unscoped records: 3/)).toBeInTheDocument();
  });
  it('does not infer identity from legacy absence', () => {
    render(<HostIdentity ip="192.0.2.1" />);
    expect(screen.getByText('Identity evidence unavailable for this capture.')).toBeInTheDocument();
  });
  it('distinguishes software host/assessment absence and capped observations', () => {
    render(<SoftwareEvidence capped observations={[{ host: '', role: '', timestampNs: '1700000000000000001', vulnerabilityAssessment: '' }]} />);
    expect(screen.getByText(/observations \(1\+, capped\)/)).toBeInTheDocument();
    expect(screen.getByText(/"vulnerabilityAssessment": "unavailable"/)).toBeInTheDocument();
    expect(screen.getByText(/"host": "unavailable"/)).toBeInTheDocument();
  });
});
