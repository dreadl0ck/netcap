"""Helm control-plane singleton, storage and Secret boundary contract."""
import pathlib
import subprocess
import unittest

import yaml

CHART = pathlib.Path(__file__).resolve().parents[1]
ARGS = ['--set', 'enabled=true', '--set', 'configSecretName=bootstrap',
        '--set', 'credentialsSecretName=tokens', '--set', 'tlsSecretName=control-tls']


def render(*args, success=True):
    r = subprocess.run(['helm', 'template', 'lab', str(CHART), '--kube-version', '1.32.2', *args],
                       text=True, capture_output=True)
    if not success:
        assert r.returncode != 0, 'unsafe control values accepted'
        return
    assert r.returncode == 0, r.stderr
    return [d for d in yaml.safe_load_all(r.stdout) if d]


class ControlContract(unittest.TestCase):
    def test_disabled_and_secret_gates(self):
        self.assertEqual(render(), [])
        render('--set', 'enabled=true', success=False)
        for override in ['tlsSecretName=', 'credentialsSecretName=', 'configSecretName=', 'replicaCount=2', 'token=plaintext']:
            render(*ARGS, '--set', override, success=False)

    def test_fenced_singleton_and_existing_claim(self):
        for service in ['fleet-controller', 'sharedstate']:
            docs = render(*ARGS, '--set', 'service=' + service)
            deployment = next(d for d in docs if d['kind'] == 'Deployment')
            self.assertEqual(deployment['spec']['replicas'], 1)
            self.assertEqual(deployment['spec']['strategy'], {'type': 'Recreate'})
            pod = deployment['spec']['template']['spec']
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertTrue(pod['securityContext']['runAsNonRoot'])
            c = pod['containers'][0]
            self.assertEqual(c['args'][0], service)
            self.assertEqual(c['envFrom'], [{'secretRef': {'name': 'tokens'}}])
            self.assertEqual(c['securityContext']['capabilities']['drop'], ['ALL'])
            self.assertEqual(next(d for d in docs if d['kind'] == 'PersistentVolumeClaim')['metadata']['annotations']['helm.sh/resource-policy'], 'keep')
        self.assertNotIn('PersistentVolumeClaim', {d['kind'] for d in render(*ARGS, '--set', 'storage.existingClaim=existing')})

    def test_postgres_active_active_has_no_local_state(self):
        pg = ['--set', 'persistence.backend=postgres', '--set', 'replicaCount=2',
              '--set', 'persistence.postgres.databaseURLEnv=CONTROL_DATABASE_URL',
              '--set', 'persistence.postgres.databaseNamespace=ncf_fleet']
        for service in ['fleet-controller', 'sharedstate']:
            docs = render(*ARGS, *pg, '--set', 'service=' + service)
            self.assertNotIn('PersistentVolumeClaim', {d['kind'] for d in docs})
            deploy = next(d for d in docs if d['kind'] == 'Deployment')
            self.assertEqual(deploy['spec']['replicas'], 2)
            self.assertEqual(deploy['spec']['strategy']['type'], 'RollingUpdate')
            pod = deploy['spec']['template']['spec']
            self.assertNotIn('state', {v['name'] for v in pod['volumes']})
            self.assertNotIn('state', {v['name'] for v in pod['containers'][0]['volumeMounts']})
            self.assertEqual(pod['containers'][0]['envFrom'], [{'secretRef': {'name': 'tokens'}}])
        for override in ['replicaCount=1', 'storage.existingClaim=sqlite-data',
                         'persistence.postgres.databaseURLEnv=', 'persistence.postgres.databaseNamespace=',
                         'persistence.postgres.databaseNamespace=public', 'persistence.postgres.databaseNamespace=pg_temp',
                         'persistence.postgres.databaseURL=postgres://plaintext']:
            render(*ARGS, *pg, '--set', override, success=False)


if __name__ == '__main__':
    unittest.main()
