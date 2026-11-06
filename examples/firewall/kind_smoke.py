#!/usr/bin/env python3
"""Disposable kind install/traffic/upgrade/rollback and managed persistence test."""
import contextlib
import json
import os
import pathlib
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = 'kindest/node:v1.32.2@sha256:f226345927d7e348497136874b6d207e0b32cc52154ad8323129352923a3142f'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    cluster = 'firewall-' + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix='netcap-firewall-kind-') as directory:
        temp = pathlib.Path(directory)
        env = dict(os.environ, KUBECONFIG=str(temp / 'kubeconfig'))
        k = ['kubectl', '--context', 'kind-' + cluster, '-n', 'firewall']

        def kubectl(*args, **kwargs):
            return run(*k, *args, env=env, **kwargs)

        def helm(*args):
            return run('helm', *args, '--kube-context', 'kind-' + cluster, '-n', 'firewall', env=env)

        def rollout(name):
            kubectl('rollout', 'status', 'deployment/' + name, '--timeout=180s')

        def traffic(name, path, status):
            # A pod connects through ClusterIP/DNS, not a pod port-forward.
            result = subprocess.run([*k, 'exec', 'deploy/backend', '--', 'wget', '-S', '-O-',
                                     'http://' + name + ':8080' + path], env=env,
                                    text=True, capture_output=True, timeout=30)
            assert ('HTTP/1.1 ' + str(status)) in result.stderr, result.stderr
            if status == 200:
                assert 'origin-ok' in result.stdout, result.stdout

        @contextlib.contextmanager
        def management():
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            with (temp / 'port-forward.log').open('w+') as log:
                process = subprocess.Popen([*k, 'port-forward', '--address=127.0.0.1',
                                            'svc/managed-netcap-firewall-admin', f'{port}:9090'],
                                           env=env, stdout=log, stderr=log)
                try:
                    context = ssl.create_default_context(cafile=str(temp / 'tls.crt'))

                    def api(op, data=None):
                        req = urllib.request.Request(
                            f'https://localhost:{port}/api/v1/policy/{op}',
                            data=None if data is None else json.dumps(data).encode(),
                            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
                        with urllib.request.urlopen(req, context=context, timeout=10) as response:
                            return json.load(response)

                    for _ in range(60):
                        if process.poll() is not None:
                            log.seek(0)
                            raise RuntimeError(log.read())
                        try:
                            capabilities = api('capabilities')
                            assert capabilities['managed'] and not capabilities['read_only'], capabilities
                            break
                        except (OSError, urllib.error.URLError):
                            time.sleep(0.5)
                    else:
                        raise RuntimeError('administrative TLS endpoint never became ready')
                    yield api
                finally:
                    process.terminate()
                    process.wait(timeout=10)

        try:
            run('kind', 'create', 'cluster', '--name', cluster, '--image', NODE,
                '--kubeconfig', env['KUBECONFIG'], '--wait', '180s', env=env)
            run('kind', 'load', 'docker-image', 'netcap-firewall:0.1.0-local', '--name', cluster)
            kubectl('create', 'namespace', 'firewall')
            kubectl('apply', '-f', str(ROOT / 'examples/firewall/kind-backend.yaml'))
            rollout('backend')
            helm('install', 'file', str(ROOT / 'charts/netcap-firewall'),
                 '--set', 'upstream=http://backend:8080', '--set', 'image.pullPolicy=Never',
                 '--wait', '--timeout', '180s')
            traffic('file-netcap-firewall', '/blocked', 200)
            original = kubectl('get', 'deploy/file-netcap-firewall', '-o', 'json', capture_output=True)
            original_config = json.loads(original.stdout)['spec']['template']['spec']['volumes'][0]['configMap']['name']
            policy = {'version': 'netcap-policy/v1', 'id': 'kind-deny', 'mode': 'enforce',
                      'default': 'allow', 'rules': [{'id': 'deny-blocked', 'phase': 'request',
                      'expression': 'Path == "/blocked"', 'action': 'deny', 'status': 403, 'priority': 100}]}
            values = temp / 'upgrade.yaml'
            values.write_text(yaml.safe_dump({'policy': policy}))
            helm('upgrade', 'file', str(ROOT / 'charts/netcap-firewall'), '--reuse-values',
                 '-f', str(values), '--wait', '--timeout', '180s')
            rollout('file-netcap-firewall')
            updated = kubectl('get', 'deploy/file-netcap-firewall', '-o', 'json', capture_output=True)
            assert original_config != json.loads(updated.stdout)['spec']['template']['spec']['volumes'][0]['configMap']['name']
            for _ in range(4):
                traffic('file-netcap-firewall', '/blocked', 403)
            traffic('file-netcap-firewall', '/allowed', 200)
            helm('rollback', 'file', '1', '--wait', '--timeout', '180s')
            rollout('file-netcap-firewall')
            traffic('file-netcap-firewall', '/blocked', 200)
            print('PASS: file-mode install, Service traffic, immutable policy upgrade, and Helm rollback', flush=True)

            token = secrets.token_hex(32)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-keyout', str(temp / 'tls.key'), '-out', str(temp / 'tls.crt'),
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            kubectl('create', 'secret', 'tls', 'firewall-admin-tls', '--cert=' + str(temp / 'tls.crt'),
                    '--key=' + str(temp / 'tls.key'))
            kubectl('apply', '-f', '-', input=yaml.safe_dump({'apiVersion': 'v1', 'kind': 'Secret',
                    'metadata': {'name': 'firewall-admin-token'}, 'type': 'Opaque', 'stringData': {'token': token}}))
            helm('install', 'managed', str(ROOT / 'charts/netcap-firewall'),
                 '-f', str(ROOT / 'examples/firewall/managed-values.yaml'),
                 '--set', 'image.pullPolicy=Never', '--wait', '--timeout', '180s')
            traffic('managed-netcap-firewall', '/blocked', 200)
            with management() as api:
                before = api('revision')['revision']
                staged = api('stage', {'bundle': yaml.safe_dump(policy), 'idempotency_key': 'kind-stage'})
                revision = staged['revision']
                api('activate', {'revision': revision, 'expected_revision': before, 'idempotency_key': 'kind-activate'})
                assert api('revision')['revision'] == revision
            traffic('managed-netcap-firewall', '/blocked', 403)
            kubectl('rollout', 'restart', 'deployment/managed-netcap-firewall')
            rollout('managed-netcap-firewall')
            with management() as api:
                assert api('revision')['revision'] == revision, 'active revision did not survive restart'
                api('rollback', {'revision': before, 'expected_revision': revision, 'idempotency_key': 'kind-rollback'})
                assert api('revision')['revision'] == before
            traffic('managed-netcap-firewall', '/blocked', 200)
            print('PASS: embedded managed bootstrap, TLS API activation, PVC restart recovery, and policy rollback', flush=True)
        except BaseException:
            for args in [('get', 'pods,pvc,events', '-o', 'wide'),
                         ('logs', '-l', 'app.kubernetes.io/name=netcap-firewall', '--all-containers', '--tail=100')]:
                subprocess.run([*k, *args], env=env, check=False)
            raise
        finally:
            run('kind', 'delete', 'cluster', '--name', cluster, env=env)


if __name__ == '__main__':
    main()
