"""Called by the disposable CNI lab: actual control charts and fixed-identity StatefulSet."""
import datetime
import json
import pathlib
import secrets
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


def qualify(env, context, temp, image):
    namespace = 'control-lab'

    def run(*args, **kwargs):
        return subprocess.run(args, env=env, check=True, text=True, timeout=240, **kwargs)

    def k(*args, **kwargs):
        return run('kubectl', '--context', context, '-n', namespace, *args, **kwargs)

    def helm(release, chart, values, wait=True):
        path = temp / f'{release}-values.json'
        path.write_text(json.dumps(values))
        command = ['helm', 'install', release, str(ROOT / 'charts' / chart), '-f', str(path),
                   '-n', namespace, '--kube-context', context]
        if wait:
            command += ['--wait', '--timeout', '180s']
        run(*command)

    def secret(name, data):
        k('apply', '-f', '-', input=yaml.safe_dump({'apiVersion': 'v1', 'kind': 'Secret',
                                                   'metadata': {'name': name}, 'stringData': data}))

    def wait(check):
        for _ in range(120):
            try:
                result = check()
                if result:
                    return result
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise AssertionError('Kubernetes fleet convergence timed out')

    k('create', 'namespace', namespace)
    k('label', 'namespace', namespace, 'pod-security.kubernetes.io/enforce=restricted',
      'pod-security.kubernetes.io/enforce-version=v1.32')
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-keyout', str(temp / 'control.key'), '-out', str(temp / 'control.crt'),
        '-subj', '/CN=fc-control', '-addext', 'subjectAltName=DNS:fc-control,DNS:sc-control,DNS:localhost',
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ca = (temp / 'control.crt').read_text()
    secret('control-tls', {'tls.crt': ca, 'tls.key': (temp / 'control.key').read_text()})
    scope = {'tenant': 'lab', 'app': 'kubernetes'}
    tokens = {key: secrets.token_hex(32) for key in ['OPERATOR_TOKEN', 'VIEWER_TOKEN', 'FOREIGN_TOKEN', 'TARGET0_TOKEN', 'TARGET1_TOKEN', 'STATE_TOKEN']}
    secret('fleet-tokens', {key: value for key, value in tokens.items() if key != 'STATE_TOKEN'})
    secret('target-tokens', {key: value for key, value in tokens.items() if key.startswith('TARGET')})
    secret('state-tokens', {'STATE_TOKEN': tokens['STATE_TOKEN']})
    auth_scope = dict(scope, environment='lab', target='*')
    identities = []
    for key, actor, grant, actions in [
            ('OPERATOR_TOKEN', 'operator', auth_scope, ['read', 'author', 'deploy']),
            ('VIEWER_TOKEN', 'viewer', auth_scope, ['read']),
            ('FOREIGN_TOKEN', 'foreign', dict(auth_scope, tenant='foreign', app='other'), ['read', 'author', 'deploy']),
            *[(f'TARGET{i}_TOKEN', f'fixed-{i}', dict(auth_scope, target=f'fixed-{i}'), ['lease']) for i in [0, 1]]]:
        identities.append({'tokenEnv': key, 'principal': {'id': actor, 'grants': [{'scope': grant, 'actions': actions}]}})
    secret('fleet-auth', {'auth.json': json.dumps({'scope': dict(scope, environment='lab', target=''), 'static': identities})})
    secret('fleet-bootstrap', {'config.json': json.dumps({'stateDir': '/var/lib/control/state',
            'authConfig': '/etc/firewall-auth/auth.json',
            'targets': [{'id': f'fixed-{i}', 'scope': scope} for i in [0, 1]]})})
    secret('state-bootstrap', {'config.json': json.dumps({'stateDir': '/var/lib/control/state',
            'maxKeys': 1000, 'principals': [{'id': 'wafs', 'tokenEnv': 'STATE_TOKEN', 'scope': scope}]})})
    image_values = {'repository': image.rsplit(':', 1)[0], 'tag': image.rsplit(':', 1)[1], 'pullPolicy': 'Never'}
    for release, service in [('fc', 'fleet-controller'), ('sc', 'sharedstate')]:
        helm(release, 'netcap-firewall-control', {'enabled': True, 'service': service, 'image': image_values,
             'authConfigSecret': {'name': 'fleet-auth' if release == 'fc' else ''},
             'configSecretName': 'fleet-bootstrap' if release == 'fc' else 'state-bootstrap',
             'credentialsSecretName': 'fleet-tokens' if release == 'fc' else 'state-tokens', 'tlsSecretName': 'control-tls'})
    agent_configs = {'ca.crt': ca}
    for i in [0, 1]:
        agent_configs[f'targets-netcap-firewall-{i}.json'] = json.dumps({
            'url': 'https://fc-control:9092', 'tokenEnv': f'TARGET{i}_TOKEN', 'targetID': f'fixed-{i}',
            'scope': scope, 'stateDir': '/var/lib/netcap-firewall/agent', 'ca': '/etc/fleet/ca.crt',
            'pollInterval': 100000000, 'maxStale': 30000000000})
    secret('agent-configs', agent_configs)
    secret('rate-config', {'ca.crt': ca, 'config.json': json.dumps({
        'url': 'https://sc-control:9092', 'tokenEnv': 'STATE_TOKEN', 'ca': '/etc/shared-rate/ca.crt',
        'window': 3600000000000, 'limit': 3, 'group_by': 'Path', 'id': 'kubernetes-global', 'unit': 'request'})})
    k('apply', '-f', str(ROOT / 'examples/firewall/kind-backend.yaml'))
    k('rollout', 'status', 'deployment/backend', '--timeout=180s')
    helm('targets', 'netcap-firewall', {'mode': 'fleet', 'replicaCount': 2, 'image': image_values,
         'upstream': 'http://backend:8080', 'fleet': {'configSecretName': 'agent-configs', 'credentialsSecretName': 'target-tokens'},
         'sharedRate': {'configSecretName': 'rate-config', 'credentialsSecretName': 'state-tokens'}}, wait=False)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    log = (temp / 'control-forward.log').open('w+')
    forwarding = subprocess.Popen(['kubectl', '--context', context, '-n', namespace, 'port-forward',
                                    '--address=127.0.0.1', 'svc/fc-control', f'{port}:9092'],
                                   env=env, stdout=log, stderr=log)
    try:
        tls = ssl.create_default_context(cafile=str(temp / 'control.crt'))

        def api(op, data=None, token='OPERATOR_TOKEN', expected=200):
            if data is None and '?' not in op:
                op += '?tenant=lab&app=kubernetes'
            elif data is not None:
                data = dict({'scope': scope}, **data)
            req = urllib.request.Request(f'https://localhost:{port}/api/v1/fleet/{op}',
                                         data=None if data is None else json.dumps(data).encode(),
                                         headers={'Authorization': 'Bearer ' + tokens[token], 'Content-Type': 'application/json'})
            try:
                response = urllib.request.urlopen(req, context=tls, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read()
                assert response.status == expected, (op, token, response.status, body)
                return json.loads(body) if expected == 200 else None

        wait(lambda: api('status'))
        policy = {'version': 'netcap-policy/v1', 'id': 'kubernetes-fleet', 'mode': 'enforce', 'default': 'allow',
                  'rules': [{'id': 'block', 'phase': 'request', 'expression': 'Path == "/blocked"', 'action': 'deny', 'status': 403}]}
        revision = api('stage', {'bundle': json.dumps(policy)})['revision']
        api('status', token='VIEWER_TOKEN')
        api('stage', {'bundle': json.dumps(policy)}, token='VIEWER_TOKEN', expected=403)
        api('status?tenant=lab&app=kubernetes', token='FOREIGN_TOKEN', expected=403)
        for token in ['VIEWER_TOKEN', 'FOREIGN_TOKEN']:
            api('rollout', {'id': 'forbidden', 'scope': scope,
                           'revision': revision, 'targets': ['fixed-0'], 'expected': {'fixed-0': 0},
                           'deadline': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat()},
                token=token, expected=403)
        api('rollout', {'id': 'kubernetes-bootstrap', 'revision': revision, 'targets': ['fixed-0', 'fixed-1'],
                        'expected': {'fixed-0': 0, 'fixed-1': 0},
                        'deadline': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat()})
        api('activate', {'id': 'kubernetes-bootstrap', 'expected_phase': 'staged'})
        wait(lambda: all(t['observed_revision'] == revision and t['generation'] == t['observed_generation']
                         for t in api('status')['targets'].values()))
        k('rollout', 'status', 'statefulset/targets-netcap-firewall', '--timeout=180s')
        pods = json.loads(k('get', 'pods', '-l', 'app.kubernetes.io/instance=targets', '-o', 'json', capture_output=True).stdout)['items']
        pods.sort(key=lambda p: p['metadata']['name'])

        def traffic(pod, path, status):
            result = subprocess.run(['kubectl', '--context', context, '-n', namespace, 'exec', 'deploy/backend',
                                     '--', 'wget', '-T', '5', '-S', '-O-', 'http://' + pod['status']['podIP'] + ':8080' + path],
                                    env=env, text=True, capture_output=True, timeout=15)
            assert f'HTTP/1.1 {status}' in result.stderr, result.stderr

        for pod in pods:
            traffic(pod, '/blocked', 403)
        for index, status in [(0, 200), (1, 200), (0, 200), (1, 429)]:
            traffic(pods[index], '/global', status)
        before = {p['metadata']['name']: p['metadata']['uid'] for p in pods}
        k('delete', 'pod', pods[0]['metadata']['name'], '--wait=true')
        k('rollout', 'status', 'statefulset/targets-netcap-firewall', '--timeout=180s')
        replacement = json.loads(k('get', 'pod', pods[0]['metadata']['name'], '-o', 'json', capture_output=True).stdout)
        assert replacement['metadata']['uid'] != before[replacement['metadata']['name']]
        traffic(replacement, '/blocked', 403)
        assert set(api('status')['targets']) == {'fixed-0', 'fixed-1'}
        return {'result': 'pass', 'checks': ['two single-owner TLS control charts', 'restricted admission',
                'viewer cannot stage/rollout; foreign tenant cannot read/rollout lab targets',
                'fixed-identity StatefulSet plus per-pod cache PVC', 'fleet acknowledgments and deny traffic',
                'shared global count across pods', 'same enrolled identity and policy after pod replacement']}
    finally:
        forwarding.terminate()
        forwarding.wait(timeout=10)
        log.close()
