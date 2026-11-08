#!/usr/bin/env python3
"""Dedicated kind+Cilium lab: enforced origin boundary, restricted pods, replica-local counters."""
import argparse
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import time

import yaml
from kind_smoke import NODE, ROOT
from control_k8s import qualify as qualify_control

sys.path.insert(0, str(ROOT / 'scripts'))
from firewall_download import verified_read

CILIUM = '1.17.2'
FIXTURE = 'nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284'
METRICS_VERSION = '3.12.2'
METRICS_URL = f'https://github.com/kubernetes-sigs/metrics-server/releases/download/metrics-server-helm-chart-{METRICS_VERSION}/metrics-server-{METRICS_VERSION}.tgz'
# Official https://kubernetes-sigs.github.io/metrics-server/index.yaml, version 3.12.2.
METRICS_SHA256 = 'e904ffa2fe33c429e12cac8aa013ba38f42d944e315d060e94230a53b98985cf'


def metrics_chart(directory):
    data = verified_read(METRICS_URL, METRICS_SHA256)
    path = directory / f'metrics-server-{METRICS_VERSION}.tgz'
    path.write_bytes(data)
    return path


def install_metrics(run, chart, cluster):
    run('helm', 'install', 'metrics-server', str(chart),
        '--namespace', 'kube-system', '--kube-context', 'kind-' + cluster,
        '--set', 'args[0]=--kubelet-insecure-tls', '--wait', '--timeout', '180s')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--image', default='netcap-firewall:0.1.0-local')
    parser.add_argument('--enforcer-image', default='netcap-enforcer:0.1.0-local')
    args = parser.parse_args()
    cluster = 'fw-cni-' + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix='netcap-fw-cni-') as directory:
        temp = pathlib.Path(directory)
        env = dict(os.environ, KUBECONFIG=str(temp / 'kubeconfig'))
        metrics = metrics_chart(temp)

        def run(*command, **kwargs):
            return subprocess.run(command, env=env, text=True, check=True, timeout=600, **kwargs)

        def k(*command, **kwargs):
            return run('kubectl', '--context', 'kind-' + cluster, '-n', 'firewall', *command, **kwargs)

        def apply(objects):
            k('apply', '-f', '-', input=yaml.safe_dump_all(objects))

        def probe(pod, url, allowed=True, status=200):
            result = subprocess.run(['kubectl', '--context', 'kind-' + cluster, '-n', 'firewall',
                                     'exec', pod, '--', 'wget', '-T', '3', '-t', '1', '-S', '-O-', url],
                                    env=env, text=True, capture_output=True, timeout=15)
            if allowed:
                assert f'HTTP/1.1 {status}' in result.stderr, (url, result.stderr)
            else:
                assert result.returncode != 0 and 'timed out' in result.stderr, (url, result.stderr)

        config = temp / 'kind.yaml'
        config.write_text(yaml.safe_dump({'kind': 'Cluster', 'apiVersion': 'kind.x-k8s.io/v1alpha4',
                                         'networking': {'disableDefaultCNI': True},
                                         'nodes': [{'role': 'control-plane'}]}))
        try:
            run('kind', 'create', 'cluster', '--name', cluster, '--image', NODE,
                '--config', str(config), '--kubeconfig', env['KUBECONFIG'], '--wait', '0s')
            run('helm', 'install', 'cilium', 'cilium', '--repo', 'https://helm.cilium.io/',
                '--version', CILIUM, '--namespace', 'kube-system', '--kube-context', 'kind-' + cluster,
                '--set', 'ipam.mode=kubernetes', '--set', 'operator.replicas=1',
                '--set', 'kubeProxyReplacement=false', '--wait', '--timeout', '300s')
            k('wait', 'nodes', '--all', '--for=condition=Ready', '--timeout=180s')
            run('kind', 'load', 'docker-image', args.image, '--name', cluster)
            k('create', 'namespace', 'firewall')
            k('label', 'namespace', 'firewall', 'pod-security.kubernetes.io/enforce=restricted',
              'pod-security.kubernetes.io/enforce-version=v1.32')
            k('apply', '-f', str(ROOT / 'examples/firewall/kind-backend.yaml'))
            for role in ['client', 'attacker']:
                apply([{'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': role, 'labels': {'role': role}},
                        'spec': {'automountServiceAccountToken': False,
                                 'securityContext': {'runAsNonRoot': True, 'runAsUser': 101,
                                                     'seccompProfile': {'type': 'RuntimeDefault'}},
                                 'containers': [{'name': 'probe', 'image': FIXTURE,
                                                 'command': ['/bin/sh', '-c', 'sleep 3600'],
                                                 'securityContext': {'allowPrivilegeEscalation': False,
                                                                     'readOnlyRootFilesystem': True,
                                                                     'capabilities': {'drop': ['ALL']}}}]}}])
            k('wait', 'pod/client', 'pod/attacker', '--for=condition=Ready', '--timeout=180s')
            k('rollout', 'status', 'deployment/backend', '--timeout=180s')
            probe('client', 'http://backend:8080/')
            probe('attacker', 'http://backend:8080/')
            policy = {'version': 'netcap-policy/v1', 'id': 'cni-local-counters', 'mode': 'enforce',
                      'default': 'allow', 'rules': [
                          {'id': 'counter', 'phase': 'request', 'expression': 'Path == "/counter"',
                           'action': 'deny', 'status': 403, 'threshold': {'count': 2, 'window': '1h'}}]}
            values = temp / 'values.yaml'
            values.write_text(yaml.safe_dump({
                'replicaCount': 2, 'image': {'repository': args.image.rsplit(':', 1)[0],
                                            'tag': args.image.rsplit(':', 1)[1], 'pullPolicy': 'Never'},
                'upstream': 'http://backend:8080', 'policy': policy,
                'networkPolicy': {'enabled': True, 'ingressPeers': [{'podSelector': {'matchLabels': {'role': 'client'}}}],
                                  'dnsPeers': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                                                'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
                                  'upstreamEgress': [{'to': [{'podSelector': {'matchLabels': {'app': 'backend'}}}],
                                                      'ports': [{'protocol': 'TCP', 'port': 8080}]}]}}))
            run('helm', 'install', 'cni', str(ROOT / 'charts/netcap-firewall'), '-f', str(values),
                '-n', 'firewall', '--kube-context', 'kind-' + cluster, '--wait', '--timeout', '180s')
            apply([{'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                    'metadata': {'name': 'origin-only-firewall'},
                    'spec': {'podSelector': {'matchLabels': {'app': 'backend'}}, 'policyTypes': ['Ingress'],
                             'ingress': [{'from': [{'podSelector': {'matchLabels': {'app.kubernetes.io/instance': 'cni',
                                                                                   'app.kubernetes.io/name': 'netcap-firewall'}}}],
                                          'ports': [{'protocol': 'TCP', 'port': 8080}]}]}}])
            # Wait for policy realization by proving a formerly working path is blocked.
            for attempt in range(30):
                try:
                    probe('client', 'http://backend:8080/', allowed=False)
                    break
                except AssertionError:
                    if attempt == 29:
                        raise
                    time.sleep(1)
            probe('client', 'http://cni-netcap-firewall:8080/')
            probe('attacker', 'http://cni-netcap-firewall:8080/', allowed=False)
            probe('attacker', 'http://backend:8080/', allowed=False)
            k('scale', 'deployment/cni-netcap-firewall', '--replicas=3')
            k('rollout', 'status', 'deployment/cni-netcap-firewall', '--timeout=180s')
            pods = json.loads(k('get', 'pods', '-l', 'app.kubernetes.io/instance=cni', '-o', 'json', capture_output=True).stdout)['items']
            assert len(pods) == 3
            for pod in pods:
                address = pod['status']['podIP']
                probe('client', f'http://{address}:8080/counter', status=200)
                probe('client', f'http://{address}:8080/counter', status=403)
                probe('client', f'http://{address}:9090/readyz', allowed=False)
            # Actual HPA resource is checked independently of metric availability.
            run('helm', 'upgrade', 'cni', str(ROOT / 'charts/netcap-firewall'), '--reuse-values',
                '--set', 'autoscaling.enabled=true', '--set', 'autoscaling.minReplicas=3',
                '--set', 'autoscaling.maxReplicas=4', '-n', 'firewall', '--kube-context', 'kind-' + cluster,
                '--wait', '--timeout', '180s')
            hpa = json.loads(k('get', 'hpa', '-o', 'json', capture_output=True).stdout)['items'][0]
            assert hpa['spec']['minReplicas'] == 3 and hpa['spec']['maxReplicas'] == 4
            install_metrics(run, metrics, cluster)
            run('helm', 'upgrade', 'cni', str(ROOT / 'charts/netcap-firewall'), '--reuse-values',
                '--set', 'autoscaling.targetCPUUtilizationPercentage=1',
                '-n', 'firewall', '--kube-context', 'kind-' + cluster, '--wait', '--timeout', '180s')
            # CPU target is deliberately tiny for this bounded lab, not a production recommendation.
            load = subprocess.Popen(['kubectl', '--context', 'kind-' + cluster, '-n', 'firewall',
                                     'exec', 'client', '--', 'sh', '-c',
                                     'i=0; while [ "$i" -lt 6000 ]; do '
                                     'wget -qO /dev/null http://cni-netcap-firewall:8080/; '
                                     'i=$((i+1)); done'], env=env, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            try:
                for _ in range(90):
                    status = json.loads(k('get', 'hpa', '-o', 'json', capture_output=True).stdout)['items'][0]['status']
                    if status.get('desiredReplicas') == 4:
                        break
                    time.sleep(2)
                else:
                    raise AssertionError(('HPA did not request four replicas from real metrics', status))
                k('rollout', 'status', 'deployment/cni-netcap-firewall', '--timeout=180s')
                scaled = json.loads(k('get', 'deployment/cni-netcap-firewall', '-o', 'json', capture_output=True).stdout)
                assert scaled['spec']['replicas'] == 4 and scaled['status']['availableReplicas'] == 4
            finally:
                load.terminate()
                load.wait(timeout=10)
            node = json.loads(k('get', 'nodes', '-o', 'json', capture_output=True).stdout)['items'][0]
            node_name = node['metadata']['name']
            # All node filesystem/netns preparation is inside this script's disposable kind container.
            run('kind', 'load', 'docker-image', args.enforcer_image, '--name', cluster)
            run('docker', 'exec', node_name, 'sh', '-ec',
                'mkdir -p /run/netcap-enforcer /var/lib/netcap-enforcer; '
                'chmod 700 /run/netcap-enforcer /var/lib/netcap-enforcer; '
                'ip netns add netcap-fw-lab; ip -n netcap-fw-lab link add lab0 type dummy; '
                'ip -n netcap-fw-lab addr add 198.51.100.1/32 dev lab0; '
                'ip -n netcap-fw-lab link set lab0 up')
            k('create', 'namespace', 'enforcer-lab')
            token = secrets.token_hex(32)
            role_tokens = {'OPERATOR_TOKEN': token, 'READER_TOKEN': secrets.token_hex(32), 'FOREIGN_TOKEN': secrets.token_hex(32)}
            auth_scope = {'tenant': 'lab', 'app': 'enforcer', 'environment': 'test', 'target': 'edge'}
            auth = {'scope': auth_scope, 'static': [
                {'tokenEnv': role, 'principal': {'id': role.lower(), 'grants': [
                    {'scope': dict(auth_scope, tenant='foreign') if role == 'FOREIGN_TOKEN' else auth_scope,
                     'actions': ['read'] if role == 'READER_TOKEN' else ['read', 'lease']}]}}
                for role in role_tokens]}
            run('kubectl', '--context', 'kind-' + cluster, '-n', 'enforcer-lab', 'apply', '-f', '-',
                input=yaml.safe_dump({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'lab-token'},
                                      'stringData': role_tokens}))
            run('kubectl', '--context', 'kind-' + cluster, '-n', 'enforcer-lab', 'apply', '-f', '-',
                input=yaml.safe_dump({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'lab-auth'},
                                      'stringData': {'auth.json': json.dumps(auth)}}))
            enforcer_values = temp / 'enforcer.yaml'
            enforcer_values.write_text(yaml.safe_dump({
                'enabled': True, 'nodeSelector': {'kubernetes.io/hostname': node_name},
                'image': {'repository': args.enforcer_image.rsplit(':', 1)[0],
                          'tag': args.enforcer_image.rsplit(':', 1)[1], 'pullPolicy': 'Never'},
                'scope': {'namespace': 'netcap-fw-lab', 'interface': 'lab0',
                          'destination': '198.51.100.1/32', 'hook': 'input'},
                'authConfigSecret': {'name': 'lab-auth'},
                'tokenEnvironment': [{'name': role, 'secretName': 'lab-token', 'secretKey': role} for role in role_tokens]}))
            run('helm', 'install', 'lab', str(ROOT / 'charts/netcap-enforcer'), '-f', str(enforcer_values),
                '-n', 'enforcer-lab', '--kube-context', 'kind-' + cluster, '--wait', '--timeout', '180s')
            run('kubectl', '--context', 'kind-' + cluster, '-n', 'enforcer-lab', 'wait', 'pods',
                '-l', 'app.kubernetes.io/name=netcap-enforcer', '--for=condition=Ready', '--timeout=180s')
            # Helm cannot use an unauthenticated HTTP probe for this bearer-only API.
            run('docker', 'exec', node_name, 'curl', '--fail', '--silent', '--max-time', '5',
                '--retry', '5', '--retry-connrefused',
                '-H', 'Authorization: Bearer ' + token, 'http://127.0.0.1:9091/v1/leases')
            for role in ['READER_TOKEN', 'FOREIGN_TOKEN', 'OPERATOR_TOKEN']:
                result = run('docker', 'exec', node_name, 'curl', '--silent', '--max-time', '5',
                             '-o', '/dev/null', '-w', '%{http_code}', '-H', 'Content-Type: application/json',
                             '-H', 'Authorization: Bearer ' + role_tokens[role],
                             '-d', json.dumps({'id': 'role-check', 'source': '192.0.2.1', 'ttl_seconds': 2}),
                             'http://127.0.0.1:9091/v1/leases', capture_output=True)
                assert result.stdout in (['200', '201'] if role == 'OPERATOR_TOKEN' else ['403']), (role, result.stdout)
            # Use the shipped pinned nft, including for rules containing timed leases.
            run('kubectl', '--context', 'kind-' + cluster, '-n', 'enforcer-lab', 'exec',
                'ds/lab-netcap-enforcer', '--', 'ip', 'netns', 'exec', 'netcap-fw-lab',
                'nft', 'list', 'table', 'inet', 'netcap_firewall_lab')
            default_table = subprocess.run(['docker', 'exec', node_name, 'nft', 'list', 'table',
                                            'inet', 'netcap_firewall_lab'], text=True, capture_output=True)
            assert default_table.returncode != 0, 'enforcer table appeared in node default namespace'
            run('helm', 'upgrade', 'lab', str(ROOT / 'charts/netcap-enforcer'), '--reuse-values',
                '--set', 'mode=network', '--set', 'scope.protectedCIDRs[0]=198.51.100.0/24',
                '-n', 'enforcer-lab', '--kube-context', 'kind-' + cluster)
            run('kubectl', '--context', 'kind-' + cluster, '-n', 'enforcer-lab', 'delete', 'pods',
                '-l', 'app.kubernetes.io/name=netcap-enforcer', '--wait=true')
            run('kubectl', '--context', 'kind-' + cluster, '-n', 'enforcer-lab', 'wait', 'pods',
                '-l', 'app.kubernetes.io/name=netcap-enforcer', '--for=condition=Ready', '--timeout=180s')
            for _ in range(30):
                network_table = subprocess.run(['docker', 'exec', node_name, 'ip', 'netns', 'exec', 'netcap-fw-lab',
                                                'nft', 'list', 'table', 'inet', 'netcap_networkfirewall'], capture_output=True, text=True)
                if network_table.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError(network_table.stderr)
            controls = qualify_control(env, 'kind-' + cluster, temp, args.image)
            report = {'result': 'pass', 'kind_node': NODE, 'cilium_chart': CILIUM,
                      'metrics_chart': {'version': METRICS_VERSION, 'url': METRICS_URL, 'sha256': METRICS_SHA256},
                      'control_plane': controls,
                      'architecture': node['status']['nodeInfo']['architecture'],
                      'checks': ['restricted admission install', 'client through WAF allowed',
                                 'direct origin bypass blocked after successful baseline',
                                 'unselected client blocked', 'admin port blocked', 'scale to 3 replicas',
                                 'each replica independently allows first and denies second counter request',
                                 'HPA resource min/max 3/4', 'Metrics Server 3.12.2 and actual CPU-driven scale to 4',
                                 'optional capability-scoped root DaemonSet starts against existing named lab netns',
                                  'enforcer reader and foreign grants cannot create leases; operator can',
                                  'enforcer API authenticated and table absent from node default netns'],
                      'network_daemonset': 'network CLI NFQUEUE table started in existing named namespace after explicit OnDelete replacement',
                      'unsupported': ['distributed/global thresholds: file-mode counters remain process-local'],
                      'images': [p['status']['containerStatuses'][0]['imageID'] for p in pods]}
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))
        except BaseException:
            subprocess.run(['kubectl', '--context', 'kind-' + cluster, '-n', 'firewall',
                            'get', 'pods,events', '-o', 'wide'], env=env, check=False)
            subprocess.run(['kubectl', '--context', 'kind-' + cluster, '-n', 'enforcer-lab',
                            'logs', '-l', 'app.kubernetes.io/name=netcap-enforcer', '--tail=50'], env=env, check=False)
            raise
        finally:
            run('kind', 'delete', 'cluster', '--name', cluster)


if __name__ == '__main__':
    main()
