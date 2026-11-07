import unittest

import protocols


class EvidenceTests(unittest.TestCase):
    def test_skip_and_missing_test_are_not_success(self):
        for events in [[], [{'Action': 'skip', 'Test': 'TestRequired'}],
                       [{'Action': 'pass', 'Test': 'TestUnrelated'}],
                       [{'Action': 'pass', 'Test': 'TestRequired'}]]:
            with self.subTest(events=events):
                self.assertFalse(protocols.summarize(events, ['TestRequired'], 2)['accepted'])

    def test_every_repetition_required(self):
        events = [{'Action': 'pass', 'Test': 'TestRequired'}] * 2
        self.assertTrue(protocols.summarize(events, ['TestRequired'], 2)['accepted'])
        self.assertFalse(protocols.summarize(events + [{'Action': 'fail'}], ['TestRequired'], 2)['accepted'])


if __name__ == '__main__':
    unittest.main()
