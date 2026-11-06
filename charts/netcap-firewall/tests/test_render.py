"""Run with python3; requires Helm and PyYAML."""
import pathlib
import subprocess
import unittest

import yaml

CHART = pathlib.Path(__file__).resolve().parents[1]


def render(*args, success=True):
    result = subprocess.run(
        ['helm', 'template', 'test', str(CHART), '--kube-version', '1.25.0', '--set', 'upstream=http://backend:8080', *args],
        capture_output=True, text=True,
    )
    if not success:
        assert result.returncode != 0, 'invalid values unexpectedly accepted'
        assert 'incompatible with Kubernetes' not in result.stderr, result.stderr
        return result.stderr
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


class DeploymentContract(unittest.TestCase):
    def test_isolated_defaults(self):
        docs = render()
        self.assertEqual({d['kind'] for d in docs}, {'Deployment', 'Service', 'ConfigMap'})
        self.assertEqual(next(d for d in docs if d['kind'] == 'Deployment')['spec']['replicas'], 2)
        runtime = yaml.safe_load(next(d for d in docs if d['kind'] == 'ConfigMap')['data']['config.yaml'])
        self.assertTrue(runtime['corazaCRS'])
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(pod['securityContext']['runAsUser'], 10001)
        container = pod['containers'][0]
        self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
        self.assertEqual(container['securityContext']['capabilities']['drop'], ['ALL'])
        self.assertEqual(container['readinessProbe']['httpGet']['port'], 'admin')
        service = next(d for d in docs if d['kind'] == 'Service')
        self.assertEqual([p['targetPort'] for p in service['spec']['ports']], ['http'])

    def test_immutable_rollout_and_digest(self):
        first = next(d for d in render() if d['kind'] == 'ConfigMap')
        changed = render('--set', 'runtime.maxBodyBytes=2048', '--set', 'image.digest=sha256:' + 'a' * 64)
        config = next(d for d in changed if d['kind'] == 'ConfigMap')
        self.assertTrue(config['immutable'])
        self.assertNotEqual(first['metadata']['name'], config['metadata']['name'])
        pod = next(d for d in changed if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertEqual(pod['volumes'][0]['configMap']['name'], config['metadata']['name'])
        self.assertEqual(pod['containers'][0]['image'], 'netcap-firewall@sha256:' + 'a' * 64)

    def test_optional_resources_and_secrets(self):
        docs = render('--set', 'ingress.enabled=true', '--set', 'ingress.host=waf.example.test',
                      '--set', 'autoscaling.enabled=true', '--set', 'pdb.enabled=true',
                      '--set', 'adminTokenSecret.name=admin', '--set', 'tls.secretName=tls',
                      '--set', 'adminTLS.secretName=admin-tls',
                      '--set', 'upstreamTLS.caSecretName=origin-ca', '--set', 'upstream=https://backend:8080')
        self.assertTrue({'Ingress', 'HorizontalPodAutoscaler', 'PodDisruptionBudget'} <= {d['kind'] for d in docs})
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertEqual(pod['containers'][0]['env'][0]['valueFrom']['secretKeyRef']['name'], 'admin')
        self.assertEqual(len(pod['volumes']), 5)

    def test_managed_singleton_and_tls(self):
        args = ['--set', 'mode=managed', '--set', 'replicaCount=1',
                '--set', 'adminTokenSecret.name=token', '--set', 'adminTLS.secretName=admin-tls',
                '--set', 'adminService.enabled=true']
        docs = render(*args)
        deploy = next(d for d in docs if d['kind'] == 'Deployment')
        self.assertEqual(deploy['spec']['strategy'], {'type': 'Recreate'})
        pod = deploy['spec']['template']['spec']
        c = pod['containers'][0]
        self.assertIn('--managed', c['args'])
        self.assertIn('--state-dir', c['args'])
        self.assertIn('--admin-cert', c['args'])
        self.assertEqual(c['readinessProbe']['httpGet']['scheme'], 'HTTPS')
        self.assertEqual(next(d for d in docs if d['kind'] == 'PersistentVolumeClaim')['metadata']['annotations']['helm.sh/resource-policy'], 'keep')
        for overrides in [('--set', 'replicaCount=2'), ('--set', 'autoscaling.enabled=true'),
                          ('--set', 'adminTLS.secretName='), ('--set', 'adminTokenSecret.name=')]:
            render(*args, *overrides, success=False)
        existing = render(*args, '--set', 'managed.existingClaim=existing')
        self.assertNotIn('PersistentVolumeClaim', {d['kind'] for d in existing})

    def test_admin_is_not_exposed_without_tls_and_auth(self):
        render('--set', 'adminService.enabled=true', success=False)

    def test_file_token_requires_tls_in_schema(self):
        error = render('--set', 'mode=file', '--set', 'adminTokenSecret.name=token', success=False)
        self.assertIn("don't meet the specifications of the schema", error)
        self.assertIn('adminTLS.secretName', error)
        docs = render('--set', 'mode=file', '--set', 'adminTokenSecret.name=token',
                      '--set', 'adminTLS.secretName=admin-tls')
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertNotIn('--managed', pod['containers'][0]['args'])
        self.assertIn('--admin-cert', pod['containers'][0]['args'])
        self.assertEqual(pod['containers'][0]['readinessProbe']['httpGet']['scheme'], 'HTTPS')
        self.assertNotIn('PersistentVolumeClaim', {d['kind'] for d in docs})

    def test_body_limits_match_native_projection(self):
        render('--set', 'runtime.maxBodyBytes=1048576', '--set', 'runtime.maxResponseBytes=1048576')
        render('--set', 'runtime.maxBodyBytes=1', '--set', 'runtime.maxResponseBytes=1')
        for field in ('maxBodyBytes', 'maxResponseBytes'):
            for value in (0, 1048577, 67108864):
                with self.subTest(field=field, value=value):
                    error = render('--set', f'runtime.{field}={value}', success=False)
                    self.assertIn("don't meet the specifications of the schema", error)
                    self.assertIn('runtime.' + field, error)

    def test_network_policy_requires_explicit_destinations(self):
        render('--set', 'networkPolicy.enabled=true', success=False)
        docs = render('--set', 'networkPolicy.enabled=true',
                      '--set', 'networkPolicy.dnsPeers[0].namespaceSelector.matchLabels.name=kube-system',
                      '--set', 'networkPolicy.upstreamEgress[0].to[0].podSelector.matchLabels.app=backend',
                      '--set', 'networkPolicy.upstreamEgress[0].ports[0].port=8080')
        policy = next(d for d in docs if d['kind'] == 'NetworkPolicy')['spec']
        self.assertEqual(policy['ingress'], [])
        self.assertEqual(policy['egress'][1]['ports'][0]['port'], 8080)

    def test_invalid_values(self):
        for key, value in [('image.tag', 'latest'), ('image.digest', 'sha256:bad'),
                           ('runtime.maxConcurrent', '0'), ('upstream', 'ftp://backend'),
                           ('policy.mode', 'typo'), ('runtime.unknown', 'true'),
                           ('upstreamTLS.caSecretName', 'ca'), ('ingress.enabled', 'true')]:
            with self.subTest(key=key):
                render('--set', key + '=' + value, success=False)
        render('--set', 'autoscaling.enabled=true', '--set', 'autoscaling.maxReplicas=1', success=False)


if __name__ == '__main__':
    unittest.main()
