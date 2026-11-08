#!/usr/bin/env python3
"""Exercise scoped grants through the shipping image and local Compose API."""
import json
import os
import pathlib
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    project = 'firewall-roles-' + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix=project) as directory:
        lab = pathlib.Path(directory)
        lab.chmod(0o755)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-keyout', str(lab / 'tls.key'),
                        '-out', str(lab / 'tls.crt')], check=True, capture_output=True)
        scope = dict(tenant='example', app='web', environment='lab', target='edge')
        tokens = {role: secrets.token_hex(32) for role in ['reader', 'operator', 'foreign']}
        auth = {'scope': scope, 'origin': 'https://firewall.example.test', 'static': []}
        for role, actions in [('reader', ['read', 'metrics']),
                              ('operator', ['read', 'author', 'evaluate', 'deploy', 'rollback']),
                              ('foreign', ['read', 'author', 'deploy'])]:
            grant = dict(scope, tenant='foreign') if role == 'foreign' else scope
            auth['static'].append({'tokenEnv': role.upper() + '_TOKEN', 'principal': {
                'id': role, 'grants': [{'scope': grant, 'actions': actions}]}})
        (lab / 'auth.json').write_text(json.dumps(auth))
        for path in lab.iterdir():
            path.chmod(0o644)
        override = {'services': {'firewall': {
            'command': ['serve', '--config', '/etc/netcap-firewall/config.yaml', '--managed',
                        '--state-dir', '/tmp/managed', '--auth-config', '/lab/auth.json',
                        '--admin-cert', '/lab/tls.crt', '--admin-key', '/lab/tls.key'],
            'environment': {role.upper() + '_TOKEN': token for role, token in tokens.items()},
            'healthcheck': {'disable': True},
            'ports': ['127.0.0.1::9090'], 'volumes': [str(lab) + ':/lab:ro']}}}
        (lab / 'compose.yaml').write_text(yaml.safe_dump(override))
        env = dict(os.environ, FIREWALL_PORT='0')
        compose = ['docker', 'compose', '-p', project, '-f', str(ROOT / 'examples/firewall/compose.yaml'),
                   '-f', str(lab / 'compose.yaml')]

        def run(*args):
            return subprocess.check_output([*compose, *args], env=env, text=True).strip()

        try:
            run('up', '-d', '--no-build')
            address = run('port', 'firewall', '9090')
            base = 'https://' + address

            def api(operation, role='reader', data=None, expected=200):
                headers = {'Authorization': 'Bearer ' + tokens[role],
                           'Origin': auth['origin'], 'Host': 'firewall.example.test',
                           'Content-Type': 'application/json'}
                req = urllib.request.Request(base + '/api/v1/policy/' + operation, headers=headers,
                                             data=None if data is None else json.dumps(data).encode())
                try:
                    response = urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=3)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    body = response.read()
                    assert response.status == expected, (operation, role, response.status, body)
                    return json.loads(body) if expected == 200 else None

            for attempt in range(60):
                try:
                    api('capabilities')
                    break
                except (OSError, AssertionError):
                    if attempt == 59:
                        raise
                    time.sleep(1)
            initial = api('revision')['revision']
            bundle = json.dumps({'version': '1', 'id': 'role-smoke', 'mode': 'enforce',
                                 'default': 'allow', 'rules': []})
            request = {'bundle': bundle, 'idempotency_key': 'roles-stage'}
            api('stage', data=request, expected=403)
            api('stage', role='foreign', data=request, expected=403)
            revision = api('stage', role='operator', data=request)['revision']
            activation = {'revision': revision, 'expected_revision': initial, 'idempotency_key': 'roles-activate'}
            api('activate', data=activation, expected=403)
            api('activate', role='foreign', data=activation, expected=403)
            assert api('revision')['revision'] == initial
            api('activate', role='operator', data=activation)
            assert api('revision')['revision'] == revision
            api('capabilities', role='foreign', expected=403)
            page = urllib.request.urlopen(base + '/console/', context=ssl._create_unverified_context()).read()
            assert b'<html' in page.lower(), 'embedded console missing from shipping image'
            print('PASS: shipping Compose image embeds console; reader and foreign grants cannot stage/deploy; scoped operator CAS activation works')
        except Exception:
            subprocess.run([*compose, 'logs', '--tail', '80'], env=env, check=False)
            raise
        finally:
            run('down', '--volumes', '--remove-orphans')


if __name__ == '__main__':
    main()
