#!/usr/bin/env python3
"""Real TLS controller + scoped fixed targets + global counters + offline CLI recovery."""
import argparse
import datetime
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

ROOT = pathlib.Path(__file__).resolve().parents[2]


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    scope = {'tenant': 'lab', 'app': 'example'}
    with tempfile.TemporaryDirectory(prefix='fw-control-') as directory:
        temp = pathlib.Path(directory)
        config = temp / 'config'
        config.mkdir(mode=0o755)
        env = dict(os.environ, COMPOSE_PROJECT_NAME='fw-control-' + secrets.token_hex(4),
                   LAB_CONFIG_DIR=str(config), LAB_ENV_DIR=str(temp),
                   FLEET_PORT=str(free_port()), WAF1_PORT=str(free_port()), WAF2_PORT=str(free_port()))
        tokens = {key: secrets.token_hex(32) for key in ['OPERATOR_TOKEN', 'OTHER_TOKEN', 'TARGET1_TOKEN', 'TARGET2_TOKEN', 'STATE_TOKEN']}
        for name, keys in {'fleet': ['OPERATOR_TOKEN', 'OTHER_TOKEN', 'TARGET1_TOKEN', 'TARGET2_TOKEN'],
                           'state': ['STATE_TOKEN'], 'waf1': ['TARGET1_TOKEN', 'STATE_TOKEN'],
                           'waf2': ['TARGET2_TOKEN', 'STATE_TOKEN']}.items():
            path = temp / f'{name}.env'
            path.write_text(''.join(f'{key}={tokens[key]}\n' for key in keys))
            path.chmod(0o600)
        for service in ['FLEET', 'COUNTER', 'WAF1', 'WAF2']:
            path = temp / service.lower()
            path.mkdir(mode=0o777)
            path.chmod(0o777)  # Private host temp parent; runtime creates its own UID-10001/0700 child.
            env['LAB_' + service + '_STATE'] = str(path)

        def write(name, value):
            (config / name).write_text(json.dumps(value))

        write('fleet.json', {'stateDir': '/state/service',
                             'identities': [{'id': 'operator', 'tokenEnv': 'OPERATOR_TOKEN', 'scope': scope},
                                            {'id': 'other', 'tokenEnv': 'OTHER_TOKEN', 'scope': {'tenant': 'other', 'app': 'other'}}],
                             'targets': [{'id': f'waf{i}', 'tokenEnv': f'TARGET{i}_TOKEN', 'scope': scope} for i in [1, 2]]})
        write('state.json', {'stateDir': '/state/service', 'maxKeys': 1000,
                             'principals': [{'id': 'wafs', 'tokenEnv': 'STATE_TOKEN', 'scope': scope}]})
        write('rate.json', {'url': 'https://state:9092', 'tokenEnv': 'STATE_TOKEN', 'ca': '/lab/tls.crt',
                            'window': 3600000000000, 'limit': 3, 'group_by': 'Path', 'id': 'lab-global', 'unit': 'request'})
        baseline = {'version': 'netcap-policy/v1', 'id': 'lab-bootstrap', 'mode': 'enforce', 'default': 'allow', 'rules': []}
        write('policy.json', baseline)
        write('waf.json', {'version': 'netcap-firewall/v1', 'listen': ':8080', 'adminListen': ':9090',
                           'upstream': 'http://backend:8080', 'policyFile': '/lab/policy.json',
                           'maxBodyBytes': 67108864, 'maxResponseBytes': 67108864,
                           'maxBufferedBytes': 67108864, 'maxConcurrent': 32, 'bodyTimeout': '15s', 'corazaCRS': True})
        for i in [1, 2]:
            write(f'waf{i}.json', {'url': 'https://fleet:9092', 'tokenEnv': f'TARGET{i}_TOKEN',
                                   'targetID': f'waf{i}', 'scope': scope, 'stateDir': '/state/agent',
                                   'ca': '/lab/tls.crt', 'pollInterval': 100000000, 'maxStale': 30000000000})
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(config / 'tls.key'), '-out', str(config / 'tls.crt'),
                        '-subj', '/CN=fleet', '-addext', 'subjectAltName=DNS:fleet,DNS:state,DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (config / 'tls.key').chmod(0o644)  # Container UID reads it beneath host-private parent.
        context = ssl.create_default_context(cafile=str(config / 'tls.crt'))
        compose = ['docker', 'compose', '-f', str(ROOT / 'examples/firewall/control-compose.yaml')]

        def run(*parts):
            return subprocess.run([*compose, *parts], env=env, text=True, check=True, capture_output=True, timeout=120)

        def api(op, data=None, token='OPERATOR_TOKEN', expected=200):
            request = urllib.request.Request(f'https://localhost:{env["FLEET_PORT"]}/api/v1/fleet/{op}',
                                             data=None if data is None else json.dumps(data).encode(),
                                             headers={'Authorization': 'Bearer ' + tokens[token], 'Content-Type': 'application/json'})
            try:
                with urllib.request.urlopen(request, context=context, timeout=5) as response:
                    assert response.status == expected
                    return json.load(response)
            except urllib.error.HTTPError as error:
                assert error.code == expected, (error.code, error.read())

        def wait(check):
            for _ in range(100):
                try:
                    value = check()
                    if value:
                        return value
                except (OSError, urllib.error.URLError, subprocess.CalledProcessError):
                    pass
                time.sleep(0.2)
            raise AssertionError('control lab convergence timeout')

        def traffic(node, path, expected):
            try:
                with urllib.request.urlopen(f'http://localhost:{env[f"WAF{node}_PORT"]}{path}', timeout=5) as response:
                    assert response.status == expected
                    assert response.read() == b'origin-ok\n'
            except urllib.error.HTTPError as error:
                assert error.code == expected, (node, path, error.code)

        def rollout(bundle, job):
            rev = api('stage', {'bundle': json.dumps(bundle)})['revision']
            states = api('status')['targets']
            api('rollout', {'id': job, 'revision': rev, 'targets': ['waf1', 'waf2'],
                            'expected': {name: states[name]['generation'] for name in ['waf1', 'waf2']},
                            'deadline': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat()})
            api('activate', {'id': job, 'expected_phase': 'staged'})
            wait(lambda: all(s['observed_revision'] == rev and s['observed_generation'] == s['generation']
                             for s in api('status')['targets'].values()))
            return rev

        try:
            run('config', '--quiet')
            run('up', '-d')
            wait(lambda: api('status'))
            rollout(baseline, 'bootstrap')
            for i in [1, 2]:
                wait(lambda i=i: run('exec', '-T', f'waf{i}', '/netcap-firewall', 'healthcheck').returncode == 0)
            api('status?tenant=lab&app=example', token='OTHER_TOKEN', expected=403)
            for node, expected in [(1, 200), (2, 200), (1, 200), (2, 429)]:
                traffic(node, '/global', expected)
            candidate = dict(baseline, id='lab-deny', rules=[{'id': 'blocked', 'phase': 'request',
                                                             'expression': 'Path == "/blocked"', 'action': 'deny', 'status': 403}])
            revision = rollout(candidate, 'deny-policy')
            for i in [1, 2]:
                traffic(i, '/blocked', 403)
            traffic(1, '/persist', 200)
            traffic(2, '/persist', 200)
            generations = {name: value['generation'] for name, value in api('status')['targets'].items()}
            for service, name in [('fleet', 'fleet'), ('state', 'sharedstate')]:
                run('stop', service)
                run('run', '--rm', '--no-deps', service, 'backup', '--service', name, '--config', f'/lab/{service}.json',
                    '--output', '/state/service/backups/snapshot.sqlite')
                run('run', '--rm', '--no-deps', service, 'restore', '--service', name,
                    '--input', '/state/service/backups/snapshot.sqlite', '--state-dir', '/state/restored')
                path = config / f'{service}.json'
                settings = json.loads(path.read_text())
                settings['stateDir'] = '/state/restored'
                write(path.name, settings)
                run('up', '-d', service)
            wait(lambda: api('status'))
            assert {name: value['generation'] for name, value in api('status')['targets'].items()} == generations
            for i in [1, 2]:
                wait(lambda i=i: run('exec', '-T', f'waf{i}', '/netcap-firewall', 'healthcheck').returncode == 0)
            traffic(1, '/persist', 200)
            traffic(2, '/persist', 429)
            report = {'result': 'pass', 'revision': revision,
                      'checks': ['TLS fleet/sharedstate CLI services', 'two explicit target identities',
                                 'scoped operator cross-tenant read refused', 'global count shared across two WAFs',
                                 'fleet policy push acknowledged and enforced on both WAFs',
                                 'offline CLI backup/restore of fleet and sharedstate',
                                 'fleet generations and shared counters survive restore'],
                      'recovery': 'fenced/stopped lab owners; new restored directories; no active/active HA'}
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))
        except BaseException:
            # Avoid printing env/config; daemon logs contain only runtime diagnostics.
            subprocess.run([*compose, 'logs', '--no-color', '--tail=30'], env=env, check=False)
            raise
        finally:
            run('down', '--volumes', '--remove-orphans')
            # Linux bind mounts retain UID 10001; remove only this lab's state children.
            for service in ['FLEET', 'COUNTER', 'WAF1', 'WAF2']:
                subprocess.run(['docker', 'run', '--rm', '--network=none', '--cap-drop=ALL', '--cap-add=DAC_OVERRIDE',
                                '--mount', f'type=bind,src={env["LAB_" + service + "_STATE"]},dst=/state',
                                'alpine:3.23.2@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62',
                                'sh', '-ec', 'rm -rf /state/service /state/restored /state/agent'], check=True, timeout=30)


if __name__ == '__main__':
    main()
