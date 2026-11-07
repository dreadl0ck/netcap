import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { ArtifactAnalysisSummary } from '../../packages/netcap-ui/src/components/ArtifactAnalysisPanel';
import type { ArtifactAnalysisReport } from '../../packages/netcap-ui/src/lib/api';

afterEach(cleanup);
describe('artifact analysis evidence', () => {
  for (const [state, outcome] of [['completed', 'matched'], ['completed', 'no-match'], ['completed', 'classified'], ['failed', ''], ['timed-out', ''], ['cancelled', ''], ['rejected', ''], ['unavailable', '']]) {
    it(`preserves ${state}/${outcome}`, () => {
      const report: ArtifactAnalysisReport = { version: 1, runId: 'owned', configDigest: 'config', state: state === 'completed' ? 'complete' : 'partial', rejected: state === 'rejected' ? 1 : 0,
        results: { sha: { sha256: 'sha', configDigest: 'config', analyzers: [{ engine: 'yara-x', state, outcome, digest: 'rules' }] } } };
      render(<ArtifactAnalysisSummary report={report} sha256="sha" />);
      expect(screen.getByText(`yara-x: ${state}${outcome ? ` · ${outcome}` : ''}`)).toBeInTheDocument();
      if (state !== 'completed') expect(screen.getByText(/not a clean scan/)).toBeInTheDocument();
    });
  }
  it('does not interpret missing evidence as a no-match', () => {
    render(<ArtifactAnalysisSummary report={{ version: 1, runId: 'owned', configDigest: 'config', state: 'complete', rejected: 0, results: {} }} sha256="legacy" />);
    expect(screen.getByText(/Disabled, legacy or rejected analysis is not a no-match/)).toBeInTheDocument();
  });
});
