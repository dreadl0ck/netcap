"""Run with python3; requires Helm and PyYAML."""
import pathlib
import subprocess
import tempfile
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
    def test_mtls_secrets_are_binding_scoped(self):
        args = ['--set', 'tls.secretName=listener', '--set', 'tls.clientCASecretName=clients',
                '--set', 'upstream=https://backend:8443', '--set', 'upstreamTLS.clientSecretName=identity']
        docs = render(*args)
        runtime = yaml.safe_load(next(d for d in docs if d['kind'] == 'ConfigMap')['data']['config.yaml'])
        self.assertEqual(runtime['clientCA'], '/etc/netcap-firewall/client-ca/ca.crt')
        self.assertEqual(runtime['upstreamCert'], '/etc/netcap-firewall/upstream-client/tls.crt')
        render('--set', 'tls.clientCASecretName=clients', success=False)
        render('--set', 'upstreamTLS.clientSecretName=identity', success=False)
        route = {'id': 'a', 'priority': 1, 'hosts': ['a.example'], 'methods': ['GET'],
                 'pathPrefix': '/', 'upstream': 'https://a:8443',
                 'policy': {'version': 'netcap-policy/v1', 'id': 'a', 'mode': 'enforce', 'default': 'allow', 'rules': []},
                 'maxBodyBytes': 1024, 'maxResponseBytes': 1024, 'maxConcurrent': 8,
                 'upstreamTLS': {'serverName': 'a.example', 'caSecretName': 'a-ca', 'clientSecretName': 'a-client'}}
        with tempfile.TemporaryDirectory() as directory:
            values = pathlib.Path(directory) / 'values.yaml'
            values.write_text(yaml.safe_dump({'routes': [route]}))
            docs = render('-f', str(values))
            pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
            runtime = yaml.safe_load(next(d for d in docs if d['kind'] == 'ConfigMap')['data']['config.yaml'])
            installed = runtime['routes'][0]
            self.assertNotIn('upstreamTLS', installed)
            self.assertEqual(installed['upstreamServerName'], 'a.example')
            self.assertEqual(installed['upstreamCA'], '/etc/netcap-firewall/route-tls/0/ca/ca.crt')
            self.assertEqual(installed['upstreamCert'], '/etc/netcap-firewall/route-tls/0/client/tls.crt')
            volumes = {v['name']: v for v in pod['volumes']}
            self.assertEqual(volumes['route-client-0']['secret']['secretName'], 'a-client')
            self.assertEqual(volumes['route-ca-0']['secret']['secretName'], 'a-ca')
            for mount in pod['containers'][0]['volumeMounts']:
                if mount['name'].startswith('route-'):
                    self.assertTrue(mount['readOnly'])
            del route['upstreamTLS']['serverName']
            values.write_text(yaml.safe_dump({'routes': [route]}))
            render('-f', str(values), success=False)

    def test_negative_profiles(self):
        profile = {'paranoiaLevel': 1, 'inboundThreshold': 5, 'outboundThreshold': 4}
        exclusion = {'ruleID': 942100, 'owner': 'ops', 'reason': 'SQL examples',
                     'expiresAt': '2026-11-08T00:00:00Z', 'parameter': 'q'}
        invalid = []
        for field, value in [('paranoiaLevel', 0), ('paranoiaLevel', 5),
                             ('inboundThreshold', 0), ('inboundThreshold', 101),
                             ('outboundThreshold', 0), ('outboundThreshold', 101),
                             ('rawDirectives', 'SecRuleEngine Off')]:
            invalid.append({**profile, field: value})
        for field, value in [('ruleID', 949110), ('ruleID', 920100), ('owner', ''),
                             ('reason', ''), ('parameter', 'q;ctl:ruleEngine=Off'),
                             ('expiresAt', 'invalid')]:
            invalid.append({**profile, 'exclusions': [{**exclusion, field: value}]})
        invalid.append({**profile, 'exclusions': [exclusion] * 65})
        with tempfile.TemporaryDirectory() as directory:
            values = pathlib.Path(directory) / 'values.yaml'
            for candidate in invalid:
                with self.subTest(profile=candidate):
                    values.write_text(yaml.safe_dump({'runtime': {'crsProfile': candidate}}))
                    render('-f', str(values), success=False)
            values.write_text(yaml.safe_dump({'runtime': {'crsProfile': profile, 'corazaCRS': False}}))
            render('-f', str(values), success=False)

    def test_route_policies_profiles_and_rollout(self):
        policy = {'version': 'netcap-policy/v1', 'id': 'tenant-a', 'mode': 'enforce', 'default': 'allow', 'rules': []}
        route = {'id': 'a', 'priority': 10, 'hosts': ['a.example'], 'methods': ['GET'],
                 'pathPrefix': '/api', 'upstream': 'http://a:8080', 'policy': policy,
                 'maxBodyBytes': 1024, 'maxResponseBytes': 1024, 'maxConcurrent': 8,
                 'crsProfile': {'paranoiaLevel': 2, 'inboundThreshold': 5, 'outboundThreshold': 4,
                                'exclusions': [{'ruleID': 942100, 'parameter': 'password', 'path': '/api/account', 'method': 'POST',
                                                'owner': 'fixture', 'reason': 'qualification password', 'expiresAt': '2026-11-08T00:00:00Z'}]}}
        with tempfile.TemporaryDirectory() as directory:
            values = pathlib.Path(directory) / 'values.yaml'
            values.write_text(yaml.safe_dump({'routes': [route]}))
            docs = render('-f', str(values))
            cm = next(d for d in docs if d['kind'] == 'ConfigMap')
            runtime = yaml.safe_load(cm['data']['config.yaml'])
            installed = runtime['routes'][0]
            self.assertEqual(installed['policyFile'], '/etc/netcap-firewall/route-a.yaml')
            self.assertEqual(installed['policyID'], 'tenant-a')
            self.assertNotIn('policy', installed)
            self.assertEqual(installed['crsProfile']['exclusions'][0]['path'], '/api/account')
            self.assertEqual(yaml.safe_load(cm['data']['route-a.yaml']), policy)
            composed = render('-f', str(values), '--set', 'websocket=true', '--set', 'grpc=true', '--set', 'http3.enabled=true', '--set', 'tls.secretName=listener')
            args = next(d for d in composed if d['kind'] == 'Deployment')['spec']['template']['spec']['containers'][0]['args']
            self.assertIn('--websocket', args)
            self.assertIn('--grpc', args)
            managed = ['--set', 'legacyAdmin=true', '--set', 'mode=managed', '--set', 'replicaCount=1', '--set', 'adminTokenSecret.name=token', '--set', 'adminTLS.secretName=admin']
            render('-f', str(values), *managed, success=False)
            docs = render('-f', str(values), *managed, '--set', 'routeID=a')
            args = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']['containers'][0]['args']
            self.assertIn('--route-id=a', args)
            render('-f', str(values), *managed, '--set', 'routeID=foreign', success=False)
            route['crsProfile']['paranoiaLevel'] = 5
            values.write_text(yaml.safe_dump({'routes': [route]}))
            render('-f', str(values), success=False)
            route['crsProfile']['paranoiaLevel'] = 2
            policy['default'] = 'deny'
            values.write_text(yaml.safe_dump({'routes': [route]}))
            changed = next(d for d in render('-f', str(values)) if d['kind'] == 'ConfigMap')
            self.assertNotEqual(cm['metadata']['name'], changed['metadata']['name'])

    def test_native_policy_state_secret_mount_and_exclusive_guard(self):
        args = ['--set', 'policyState.configSecretName=native-client',
                '--set', 'policyState.credentialsSecretName=native-token']
        docs = render(*args)
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        c = pod['containers'][0]
        self.assertIn('--policy-state-config=/etc/policy-state/config.json', c['args'])
        self.assertEqual(c['envFrom'], [{'secretRef': {'name': 'native-token'}}])
        mount = next(v for v in c['volumeMounts'] if v['name'] == 'policy-state')
        self.assertTrue(mount['readOnly'])
        self.assertEqual(next(v for v in pod['volumes'] if v['name'] == 'policy-state')['secret']['secretName'], 'native-client')
        render('--set', 'policyState.configSecretName=native-client', success=False)
        render('--set', 'policyState.credentialsSecretName=native-token', success=False)
        render(*args, '--set', 'sharedRate.configSecretName=rate', '--set', 'sharedRate.credentialsSecretName=rate-token', success=False)
        render('--set', 'policyState.token=plaintext', success=False)

    def test_committed_advanced_policy_renders_without_losing_state_options(self):
        policy = yaml.safe_load((CHART.parents[1] / 'examples/firewall/advanced-policy.yaml').read_text())
        with tempfile.TemporaryDirectory() as directory:
            values = pathlib.Path(directory) / 'values.yaml'
            values.write_text(yaml.safe_dump({'policy': policy}))
            docs = render('-f', str(values))
        installed = yaml.safe_load(next(d for d in docs if d['kind'] == 'ConfigMap')['data']['policy.yaml'])
        self.assertEqual(installed, policy)
        threshold = installed['rules'][1]['threshold']
        self.assertEqual(threshold['mode'], 'sliding')
        self.assertEqual(threshold['distinct'], 'Path')
        self.assertEqual(threshold['group_by_fields'], ['ClientIP', 'Host'])

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
                      '--set', 'legacyAdmin=true', '--set', 'adminTokenSecret.name=admin', '--set', 'tls.secretName=tls',
                      '--set', 'adminTLS.secretName=admin-tls',
                      '--set', 'upstreamTLS.caSecretName=origin-ca', '--set', 'upstream=https://backend:8080')
        self.assertTrue({'Ingress', 'HorizontalPodAutoscaler', 'PodDisruptionBudget'} <= {d['kind'] for d in docs})
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertEqual(pod['containers'][0]['env'][0]['valueFrom']['secretKeyRef']['name'], 'admin')
        self.assertEqual(len(pod['volumes']), 5)

    def test_managed_singleton_and_tls(self):
        args = ['--set', 'mode=managed', '--set', 'replicaCount=1',
                '--set', 'legacyAdmin=true', '--set', 'adminTokenSecret.name=token', '--set', 'adminTLS.secretName=admin-tls',
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

    def test_grant_bootstrap_and_legacy_optin(self):
        args = ['--set', 'mode=managed', '--set', 'replicaCount=1',
                '--set', 'adminTLS.secretName=tls', '--set', 'authConfigSecret.name=auth',
                '--set', 'tokenEnvironment[0].name=READER_TOKEN',
                '--set', 'tokenEnvironment[0].secretName=roles',
                '--set', 'tokenEnvironment[0].secretKey=reader']
        docs = render(*args)
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        c = pod['containers'][0]
        self.assertIn('--auth-config=/etc/firewall-auth/auth.json', c['args'])
        self.assertNotIn('--legacy-admin', c['args'])
        self.assertTrue(next(v for v in c['volumeMounts'] if v['name'] == 'auth')['readOnly'])
        self.assertEqual(c['env'][0]['valueFrom']['secretKeyRef'], {'name': 'roles', 'key': 'reader'})
        for option in ['legacyAdmin=true', 'adminTokenSecret.name=token', 'adminTLS.secretName=', 'authConfigSecret.name=']:
            render(*args, '--set', option, success=False)
        render('--set', 'adminTLS.secretName=tls', '--set', 'adminTokenSecret.name=token', success=False)

    def test_api_artifacts_are_mounted_and_digest_bound(self):
        contract = {'descriptorPath': 'declaration.json', 'descriptorSHA256': 'a' * 64,
                    'apiValidateResponse': True}
        route = {'id': 'api', 'priority': 1, 'hosts': ['api.example'], 'methods': ['POST'],
                 'pathPrefix': '/', 'upstream': 'http://backend:8080',
                 'policy': {'version': 'netcap-policy/v1', 'id': 'api', 'mode': 'enforce', 'default': 'allow', 'rules': []},
                 'maxBodyBytes': 1024, 'maxResponseBytes': 1024, 'maxConcurrent': 8,
                 'apiContract': contract}
        with tempfile.TemporaryDirectory() as directory:
            values = pathlib.Path(directory) / 'api.yaml'
            for routed in [False, True]:
                data = {'routes': [route]} if routed else {'apiContract': contract}
                values.write_text(yaml.safe_dump(data))
                render('-f', str(values), success=False)
                docs = render('-f', str(values), '--set', 'apiArtifactsConfigMap=reviewed-contracts')
                config = yaml.safe_load(next(d for d in docs if d['kind'] == 'ConfigMap')['data']['config.yaml'])
                self.assertEqual(config['bootstrapDir'], '/etc/api-bootstrap')
                binding = config['routes'][0] if routed else config
                self.assertEqual({k: binding[k] for k in contract}, contract)
                self.assertNotIn('apiContract', binding)
                pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
                self.assertEqual(next(v for v in pod['volumes'] if v['name'] == 'api-artifacts')['configMap']['name'], 'reviewed-contracts')
                self.assertTrue(next(v for v in pod['containers'][0]['volumeMounts'] if v['name'] == 'api-artifacts')['readOnly'])
            for change in [{'descriptorPath': '../escape'}, {'descriptorSHA256': ''}, {'descriptorSHA256': 'sha256:' + 'a' * 64}]:
                values.write_text(yaml.safe_dump({'apiContract': dict(contract, **change)}))
                render('-f', str(values), '--set', 'apiArtifactsConfigMap=reviewed-contracts', success=False)

    def test_file_token_requires_tls_in_schema(self):
        error = render('--set', 'mode=file', '--set', 'adminTokenSecret.name=token', success=False)
        self.assertIn("don't meet the specifications of the schema", error)
        self.assertRegex(error, r'adminTLS[./]secretName')
        docs = render('--set', 'legacyAdmin=true', '--set', 'mode=file', '--set', 'adminTokenSecret.name=token',
                      '--set', 'adminTLS.secretName=admin-tls')
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertNotIn('--managed', pod['containers'][0]['args'])
        self.assertIn('--admin-cert', pod['containers'][0]['args'])
        self.assertEqual(pod['containers'][0]['readinessProbe']['httpGet']['scheme'], 'HTTPS')
        self.assertNotIn('PersistentVolumeClaim', {d['kind'] for d in docs})

    def test_spool_and_budget_bounds(self):
        docs = render('--set', 'runtime.maxBodyBytes=67108864', '--set', 'runtime.maxResponseBytes=67108864')
        runtime = yaml.safe_load(next(d for d in docs if d['kind'] == 'ConfigMap')['data']['config.yaml'])
        self.assertEqual(runtime['maxBufferedBytes'], 67108864)
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertEqual(next(v for v in pod['volumes'] if v['name'] == 'tmp')['emptyDir'], {'sizeLimit': '256Mi'})
        render('--set', 'runtime.maxBodyBytes=1', '--set', 'runtime.maxResponseBytes=1')
        for field in ('maxBodyBytes', 'maxResponseBytes'):
            for value in (0, 67108865):
                with self.subTest(field=field, value=value):
                    error = render('--set', f'runtime.{field}={value}', success=False)
                    self.assertIn("don't meet the specifications of the schema", error)
                    self.assertRegex(error, r'runtime[./]' + field)
        render('--set', 'runtime.maxBufferedBytes=0', success=False)
        render('--set', 'runtime.maxBufferedBytes=1073741825', success=False)

    def test_messages_and_http3_tls_gate(self):
        render('--set', 'http3.enabled=true', success=False)
        docs = render('--set', 'http3.enabled=true', '--set', 'tls.secretName=client-tls',
                      '--set', 'websocket=true', '--set', 'grpc=true')
        c = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']['containers'][0]
        self.assertTrue({'--websocket', '--grpc', '--http3-listen=:8443'} <= set(c['args']))
        self.assertEqual(next(p for p in c['ports'] if p['name'] == 'http3')['protocol'], 'UDP')
        self.assertEqual(next(p for d in docs if d['kind'] == 'Service' for p in d['spec']['ports'] if p['name'] == 'http3')['protocol'], 'UDP')

    def test_control_config_is_secret_only_and_fleet_identity_is_stable(self):
        render('--set', 'sharedRate.configSecretName=rate', success=False)
        render('--set', 'mode=managed', '--set', 'fleet.configSecretName=agent', success=False)
        args = ['--set', 'mode=fleet', '--set', 'fleet.configSecretName=agents',
                '--set', 'fleet.credentialsSecretName=target-tokens',
                '--set', 'sharedRate.configSecretName=rate', '--set', 'sharedRate.credentialsSecretName=rate-token']
        docs = render(*args)
        sts = next(d for d in docs if d['kind'] == 'StatefulSet')
        self.assertNotIn('Deployment', {d['kind'] for d in docs})
        c = sts['spec']['template']['spec']['containers'][0]
        self.assertIn('--fleet-agent-config=/etc/fleet/$(POD_NAME).json', c['args'])
        self.assertIn('--shared-rate-config=/etc/shared-rate/config.json', c['args'])
        self.assertEqual(c['envFrom'], [{'secretRef': {'name': 'rate-token'}}, {'secretRef': {'name': 'target-tokens'}}])
        self.assertEqual(sts['spec']['volumeClaimTemplates'][0]['metadata']['name'], 'agent-state')
        render(*args, '--set', 'autoscaling.enabled=true', success=False)
        render('--set', 'sharedRate.token=plaintext-is-forbidden', success=False)

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
