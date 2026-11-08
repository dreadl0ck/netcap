import json
import os
import pathlib
import tempfile
import unittest

import evidence


class RetentionTests(unittest.TestCase):
    def test_zero_fault_checkpoint_and_bounded_history_total(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            report = dict(load_state='running', qualification_state='incomplete',
                          actual_load_seconds=5, faults=None, fault_count=0,
                          resources_peak={}, soak_24h_pass=False, false_positive_error='',
                          profiles={'h1': dict(counts=dict(Offered=1, Allowed=1, Denied=0,
                              Errors=0, Dropped=0, FalseBlocks=0), p95_upper_ms=1, p99_upper_ms=1,
                              forbidden_origin_bytes=0, forbidden_origin_requests=0)})
            (directory / 'progress.json').write_text(json.dumps(report))
            self.assertEqual(evidence.summarize(directory)['fault_count'], 0)
            report.update(fault_count=300, faults=[dict(recovery_ms=2)])
            (directory / 'progress.json').write_text(json.dumps(report))
            self.assertEqual(evidence.summarize(directory)['fault_count'], 300)
            failure = dict(result='fail', stage='recovery-allow', elapsed_ms=3001,
                           failure=dict(Category='timeout'))
            report.update(load_state='failed', faults=[dict(recovery_ms=2), failure])
            report['profiles']['h1']['first_failures'] = [dict(Category='partial-eof')]
            (directory / 'progress.json').write_text(json.dumps(report))
            summary = evidence.summarize(directory)
            self.assertEqual(summary['load_state'], 'failed')
            self.assertEqual(summary['max_fault_recovery_ms'], 2)
            self.assertEqual(summary['failed_faults'], [failure])
            self.assertEqual(summary['first_failures'], {'h1': [dict(Category='partial-eof')]})

    def test_prune_only_owned_inactive_and_preserve_active(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            unowned = root / 'topic-qual-user'
            unowned.mkdir()
            outputs = [evidence.allocate(root) for _ in range(3)]
            for output in outputs:
                os.utime(output.parent, (1, 1))
            (outputs[0] / 'progress.json').write_text(json.dumps({'load_state': 'running', 'pid': os.getpid()}))
            evidence.prune(root, retention_days=1)
            self.assertTrue(unowned.exists())
            self.assertTrue(outputs[0].exists())
            self.assertFalse(outputs[1].exists())
            self.assertFalse(outputs[2].exists())


if __name__ == '__main__':
    unittest.main()
