import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('recheck_mta', Path(__file__).with_name('recheck-mta.py'))
recheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recheck)


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / 'run'
        self.run.mkdir()

    def summary(self, rows, baseline=None):
        (self.run / 'results.json').write_text(json.dumps({'rows': rows}))
        with contextlib.redirect_stdout(io.StringIO()):
            status = recheck.summarize(self.run, baseline)
        return status, json.loads((self.run / 'summary.json').read_text())

    def corpus(self, directory, capture, hashes):
        target = directory / '2021-06-16' / capture
        target.mkdir(parents=True)
        (target / 'audit.nccorpus.txt').write_text('\n'.join('FILEHASH ' + h for h in hashes))

    def test_nonzero_exit_is_visible_without_parser_errors(self):
        status, report = self.summary([{'pcap': 'test.pcap', 'exit': 137, 'errors': []}])
        self.assertEqual(status, 1)
        self.assertEqual(report['errors'][0]['exit'], 137)
        self.assertEqual(report['successful'], 0)

    def test_empty_run_cannot_pass(self):
        status, _ = self.summary([])
        self.assertEqual(status, 1)

    def test_missing_capture_and_hash_are_not_hidden_by_intersection(self):
        baseline = self.root / 'baseline'
        self.corpus(baseline, 'missing', ['abc'])
        self.corpus(baseline, 'present', ['def'])
        self.corpus(self.run, 'present', ['def'])
        status, report = self.summary([{'pcap': 'present.pcap', 'exit': 0, 'errors': []}], baseline)
        self.assertEqual(status, 1)
        comparison = report['baselineArtifactComparison']
        self.assertEqual(comparison['comparedCaptures'], 1)
        self.assertEqual(comparison['missingCaptures'], [['2021-06-16', 'missing']])
        self.assertEqual(comparison['missingUniqueHashes'], 1)

    def test_matched_capture_with_all_hashes_passes(self):
        baseline = self.root / 'baseline'
        self.corpus(baseline, 'present', ['abc'])
        self.corpus(self.run, 'present', ['abc', 'def'])
        status, report = self.summary([{'pcap': 'present.pcap', 'exit': 0, 'errors': []}], baseline)
        self.assertEqual(status, 0)
        self.assertEqual(report['baselineArtifactComparison']['missingUniqueHashes'], 0)


if __name__ == '__main__':
    unittest.main()
