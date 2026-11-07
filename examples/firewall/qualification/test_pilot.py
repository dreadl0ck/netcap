import copy
import unittest

import pilot


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.plan = {'version': 1, 'environment': 'owned-local-fake',
                     'endpoints': [{'method': 'GET', 'path': '/health'},
                                   {'method': 'POST', 'path': '/api/invoices'}],
                     'requests_per_endpoint': 2, 'rate': 50, 'timeout_seconds': 1}

    def test_owned_workflow_and_cleanup(self):
        report = pilot.execute(self.plan)
        self.assertEqual(report['requests'], 4)
        self.assertEqual(len(report['ledger']), 4)
        self.assertEqual(report['production_pilot'], 'not-authorized-not-executed')

    def test_reject_unbounded_or_external_inventory(self):
        mutations = [dict(environment='production'), dict(rate=100000),
                     dict(requests_per_endpoint=-1), dict(rate=True),
                     dict(endpoints=[{'method': 'GET', 'path': 'http://example.com'}]),
                     dict(endpoints=[{'method': 'GET', 'path': '//127.0.0.1/health'}]),
                     dict(endpoints=[{'method': 'GET', 'path': '/health?url=external'}]),
                     dict(endpoints=[{'method': 'GET', 'path': '/health', 'host': 'external'}]),
                     dict(endpoints=self.plan['endpoints'] * 2)]
        for mutation in mutations:
            plan = copy.deepcopy(self.plan)
            plan.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                pilot.validate(plan)


if __name__ == '__main__':
    unittest.main()
