import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import NetworkDetectionEvidence, { parseNetworkEvidence } from '../../packages/netcap-ui/src/components/NetworkDetectionEvidence';
import type { Alert } from '../../packages/netcap-ui/src/lib/api';

const evidence = { schema: 1, detector: 'dns.tunnel', classification: 'behavioral-suspicion', scope: { sensor: 'office', interface: 'pcap', vlans: [12] }, firstSeen: 1800000000000000000, lastSeen: 1800000001000000000, observed: 10, threshold: 10, windowNS: 60000000000, samples: ['<script>alert(1)</script>'], limitations: ['DNS payload content is unavailable'] };
const alert = { recordType: 'NetworkDetection', matchedRecord: JSON.stringify(evidence), srcIP: '192.0.2.10', dstIP: '192.0.2.53', srcPort: '40000', dstPort: '53', ruleName: 'dns.tunnel', alertId: 'fixture' } as Alert;

describe('network detection analyst evidence', () => {
  it('renders measurements, scope, uncertainty and hostile samples as text', () => {
    render(<NetworkDetectionEvidence alert={alert} />);
    expect(screen.getByText('Behavioral suspicion')).toBeTruthy();
    expect(screen.getByText('10 / 10')).toBeTruthy();
    expect(screen.getByText(/office \/ pcap \/ VLANs 12/)).toBeTruthy();
    expect(screen.getByText('<script>alert(1)</script>')).toBeTruthy();
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getByText('DNS payload content is unavailable')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Export original evidence JSON' })).toBeTruthy();
  });
  it('preserves legacy alerts and rejects malformed or future evidence', () => {
    expect(parseNetworkEvidence('{')).toBeNull();
    for (const patch of [{ schema: 2 }, { firstSeen: 1e308 }, { scope: { sensor: 'x', interface: 'p', vlans: 'fake' } }, { samples: [1] }]) expect(parseNetworkEvidence(JSON.stringify({ ...evidence, ...patch }))).toBeNull();
    const { container } = render(<NetworkDetectionEvidence alert={{ ...alert, recordType: 'DNS' }} />);
    expect(container.innerHTML).toBe('');
  });
});
