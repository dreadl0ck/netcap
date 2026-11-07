"""Validate the optional privileged boundary with Helm and PyYAML."""
import pathlib
import subprocess
import unittest

import yaml

CHART = pathlib.Path(__file__).resolve().parents[1]


def render(*args, success=True):
    result = subprocess.run(['helm', 'template', 'lab', str(CHART), '--kube-version', '1.32.2', *args],
                            text=True, capture_output=True)
    if not success:
        assert result.returncode != 0, 'unsafe values accepted'
        return
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


ARGS = ['--set', 'enabled=true', '--set-string', 'nodeSelector.netcap-lab=true',
        '--set', 'scope.namespace=netcap-fw-lab', '--set', 'scope.interface=ingress',
        '--set', 'scope.destination=198.51.100.0/24', '--set', 'tokenSecret.name=lab-token']


class EnforcerBoundary(unittest.TestCase):
    def test_disabled_by_default(self):
        self.assertEqual(render(), [])

    def test_scoped_daemonset(self):
        docs = render(*ARGS)
        self.assertEqual([d['kind'] for d in docs], ['DaemonSet'])
        pod = docs[0]['spec']['template']['spec']
        self.assertTrue(pod['hostNetwork'])
        self.assertFalse(pod['hostPID'])
        self.assertFalse(pod['automountServiceAccountToken'])
        container = pod['containers'][0]
        security = container['securityContext']
        self.assertFalse(security['privileged'])
        self.assertFalse(security['allowPrivilegeEscalation'])
        self.assertTrue(security['readOnlyRootFilesystem'])
        self.assertEqual(security['capabilities'], {'drop': ['ALL'], 'add': ['NET_ADMIN', 'SYS_ADMIN']})
        mounts = {v['mountPath']: v for v in container['volumeMounts']}
        self.assertTrue(mounts['/run/netns']['readOnly'])
        self.assertEqual(mounts['/run/netns']['mountPropagation'], 'HostToContainer')
        self.assertIn('/run/netcap-enforcer', mounts)
        self.assertEqual({v['hostPath']['type'] for v in pod['volumes'] if 'hostPath' in v}, {'Directory'})
        self.assertNotIn('ports', container)
        self.assertNotIn('livenessProbe', container)

    def test_missing_scopes_and_floating_images_rejected(self):
        render('--set', 'enabled=true', success=False)
        for field, value in [('scope.namespace', ''), ('scope.namespace', 'host'), ('scope.namespace', 'default'),
                             ('scope.namespace', '../netns'), ('scope.interface', ''), ('scope.destination', ''),
                             ('tokenSecret.name', ''), ('image.tag', 'latest'), ('scope.port', '0'),
                             ('scope.protocol', 'icmp'), ('scope.hook', 'output')]:
            with self.subTest(field=field, value=value):
                render(*ARGS, '--set', field + '=' + value, success=False)

    def test_network_mode_requires_protected_ranges_and_has_no_bearer_api(self):
        render(*ARGS, '--set', 'mode=network', success=False)
        docs = render(*ARGS, '--set', 'mode=network', '--set', 'scope.protectedCIDRs[0]=198.51.100.0/24')
        pod = next(d for d in docs if d['kind'] == 'DaemonSet')['spec']['template']['spec']
        c = pod['containers'][0]
        self.assertNotIn('NETCAP_FIREWALL_ADMIN_TOKEN', {e['name'] for e in c['env']})
        self.assertIn('--protected-cidr=198.51.100.0/24', c['args'])
        self.assertIn('--bypass-without-listener=false', c['args'])
        self.assertEqual(next(d for d in docs if d['kind'] == 'ConfigMap')['immutable'], True)


if __name__ == '__main__':
    unittest.main()
