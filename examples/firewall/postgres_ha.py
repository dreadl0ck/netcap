#!/usr/bin/env python3
"""Disposable Postgres 17.11 active-active fleet/counter CLI qualification."""
import argparse
import datetime
import hashlib
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
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
POSTGRES = 'postgres:17.11@sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f'


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--package-tests', action='store_true', help='also run real Postgres package race/crash tests')
    parser.add_argument('--backup-restore', action='store_true', help='qualify chart dump/Restic scripts against an encrypted local repository')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='fw-postgres-ha-') as directory:
        temp = pathlib.Path(directory)
        config = temp / 'config'
        config.mkdir(mode=0o755)
        nonce = secrets.token_hex(4)
        env = dict(os.environ, COMPOSE_PROJECT_NAME='ncf-ha-' + nonce, PG_TEST_CONTAINER='ncf-ha-' + nonce,
                   LAB_CONFIG_DIR=str(config))
        for name in ['PG_TEST', 'FLEET', 'FLEET1', 'FLEET2', 'STATE1', 'STATE2', 'WAF1', 'WAF2']:
            env[name + '_PORT'] = str(free_port())
        tokens = {key: secrets.token_hex(32) for key in ['OPERATOR_TOKEN', 'OTHER_TOKEN', 'TARGET1_TOKEN', 'TARGET2_TOKEN', 'STATE_TOKEN']}
        password = secrets.token_hex(32)
        db_url = f'postgres://firewall:{password}@postgres:5432/firewall?sslmode=verify-full&sslrootcert=/lab/tls.crt'
        env.update(tokens, POSTGRES_PASSWORD=password, CONTROL_DATABASE_URL=db_url)
        scope = {'tenant': 'lab', 'app': 'postgres-ha'}

        def write(name, data):
            (config / name).write_text(json.dumps(data))

        write('fleet.json', {'databaseURLEnv': 'CONTROL_DATABASE_URL', 'databaseNamespace': 'ncf_lab_fleet',
            'identities': [{'id': 'operator', 'tokenEnv': 'OPERATOR_TOKEN', 'scope': scope},
                           {'id': 'other', 'tokenEnv': 'OTHER_TOKEN', 'scope': {'tenant': 'other', 'app': 'other'}}],
            'targets': [{'id': f'waf{i}', 'tokenEnv': f'TARGET{i}_TOKEN', 'scope': scope} for i in [1, 2]]})
        write('state.json', {'databaseURLEnv': 'CONTROL_DATABASE_URL', 'databaseNamespace': 'ncf_lab_state',
            'maxKeys': 1000, 'principals': [{'id': 'wafs', 'tokenEnv': 'STATE_TOKEN', 'scope': scope}]})
        write('rate.json', {'url': 'https://state:9093', 'tokenEnv': 'STATE_TOKEN', 'ca': '/lab/tls.crt',
            'requestTimeout': 1000000000, 'window': 3600000000000, 'limit': 3,
            'group_by': 'Path', 'id': 'postgres-global', 'unit': 'request'})
        baseline = {'version': 'netcap-policy/v1', 'id': 'ha-bootstrap', 'mode': 'enforce', 'default': 'allow', 'rules': []}
        write('policy.json', baseline)
        write('waf.json', {'version': 'netcap-firewall/v1', 'listen': ':8080', 'adminListen': ':9090',
            'upstream': 'http://backend:8080', 'policyFile': '/lab/policy.json', 'maxBodyBytes': 67108864,
            'maxResponseBytes': 67108864, 'maxBufferedBytes': 67108864, 'maxConcurrent': 32, 'bodyTimeout': '15s', 'corazaCRS': True})
        for i in [1, 2]:
            write(f'waf{i}.json', {'url': 'https://fleet:9092', 'tokenEnv': f'TARGET{i}_TOKEN', 'targetID': f'waf{i}',
                'scope': scope, 'stateDir': '/state/agent', 'ca': '/lab/tls.crt',
                'pollInterval': 100000000, 'requestTimeout': 1000000000, 'maxStale': 2000000000})
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(config / 'tls.key'), '-out', str(config / 'tls.crt'), '-subj', '/CN=postgres',
                        '-addext', 'subjectAltName=DNS:postgres,DNS:fleet,DNS:state,DNS:localhost,IP:127.0.0.1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (config / 'tls.key').chmod(0o644)  # Host-private parent; Postgres copies its key to owned 0600 storage.
        tls = ssl.create_default_context(cafile=str(config / 'tls.crt'))
        compose = ['docker', 'compose', '-f', str(ROOT / 'examples/firewall/control-postgres-compose.yaml')]

        def run(*parts, check=True):
            return subprocess.run([*compose, *parts], env=env, text=True, capture_output=True, check=check, timeout=180)

        def api(port, path, token, data=None, expected=200):
            req = urllib.request.Request(f'https://127.0.0.1:{env[port + "_PORT"]}{path}',
                data=None if data is None else json.dumps(data).encode(),
                headers={'Authorization': 'Bearer ' + tokens[token], 'Content-Type': 'application/json'})
            try:
                with urllib.request.urlopen(req, context=tls, timeout=5) as response:
                    assert response.status == expected
                    return json.load(response)
            except urllib.error.HTTPError as error:
                if error.code != expected:
                    raise

        def fleet(op, data=None, replica='FLEET', token='OPERATOR_TOKEN', expected=200):
            return api(replica, '/api/v1/fleet/' + op, token, data, expected)

        def wait(check):
            for _ in range(150):
                try:
                    value = check()
                    if value:
                        return value
                except (OSError, urllib.error.URLError, subprocess.CalledProcessError):
                    pass
                time.sleep(0.2)
            raise AssertionError('Postgres HA lab convergence timeout')

        def ready(node, wanted=True):
            result = run('exec', '-T', f'waf{node}', '/netcap-firewall', 'healthcheck', check=False)
            return (result.returncode == 0) == wanted

        def traffic(node, path, expected):
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{env[f"WAF{node}_PORT"]}{path}', timeout=5) as response:
                    assert response.status == expected and response.read() == b'origin-ok\n'
            except urllib.error.HTTPError as error:
                assert error.code == expected, (node, path, error.code)

        def rollout(bundle, job, direct=False):
            rev = fleet('stage', {'bundle': json.dumps(bundle)}, replica='FLEET1' if direct else 'FLEET')['revision']
            targets = fleet('status', replica='FLEET2' if direct else 'FLEET')['targets']
            fleet('rollout', {'id': job, 'revision': rev, 'targets': ['waf1', 'waf2'],
                'expected': {name: targets[name]['generation'] for name in ['waf1', 'waf2']},
                'deadline': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat()},
                replica='FLEET2' if direct else 'FLEET')
            fleet('activate', {'id': job, 'expected_phase': 'staged'}, replica='FLEET1' if direct else 'FLEET')
            wait(lambda: all(s['observed_revision'] == rev and s['observed_generation'] == s['generation']
                             for s in fleet('status', replica='FLEET2' if direct else 'FLEET')['targets'].values()))
            return rev

        key = {'revision': hashlib.sha256(b'ha-revision').hexdigest(), 'group': hashlib.sha256(b'ha-group').hexdigest()}
        count_request = {'key': key, 'window': {'mode': 'fixed', 'duration': 3600000000000}}

        def count(replica, expected):
            assert api(replica, '/api/v1/state/count', 'STATE_TOKEN', count_request)['count'] == expected

        try:
            run('config', '--quiet')
            run('up', '-d')
            wait(lambda: fleet('status', replica='FLEET1'))
            wait(lambda: fleet('status', replica='FLEET2'))
            version = run('exec', '-T', 'postgres', 'psql', '-U', 'firewall', '-d', 'firewall', '-Atc', 'SHOW server_version').stdout.strip()
            assert version.startswith('17.11'), version
            rollout(baseline, 'bootstrap', direct=True)
            for i in [1, 2]:
                wait(lambda i=i: ready(i))
            fleet('status?tenant=lab&app=postgres-ha', replica='FLEET2', token='OTHER_TOKEN', expected=403)
            count('STATE1', 1)
            count('STATE2', 2)
            for node, expected in [(1, 200), (2, 200), (1, 200), (2, 429)]:
                traffic(node, '/global', expected)
            run('kill', 'fleet1', 'state1')  # Application replicas only; database stays running.
            wait(lambda: fleet('status'))
            for i in [1, 2]:
                wait(lambda i=i: ready(i))
            count('STATE2', 3)
            candidate = dict(baseline, id='ha-survivor', rules=[{'id': 'block', 'phase': 'request',
                'expression': 'Path == "/blocked"', 'action': 'deny', 'status': 403}])
            revision = rollout(candidate, 'survivor-policy')
            for i in [1, 2]:
                traffic(i, '/blocked', 403)
            traffic(1, '/persist', 200)
            traffic(2, '/persist', 200)
            generations = {name: target['generation'] for name, target in fleet('status')['targets'].items()}
            run('kill', 'postgres')
            fleet('status', expected=503)
            api('STATE2', '/api/v1/state/count', 'STATE_TOKEN', count_request, expected=503)
            for i in [1, 2]:
                wait(lambda i=i: ready(i, wanted=False))
            run('start', 'postgres')
            wait(lambda: fleet('status'))
            for i in [1, 2]:
                wait(lambda i=i: ready(i))
            assert {name: target['generation'] for name, target in fleet('status')['targets'].items()} == generations
            count('STATE2', 4)
            traffic(1, '/persist', 200)
            traffic(2, '/persist', 429)
            package_checks = []
            if args.package_tests:
                test_url = f'postgres://firewall:{password}@127.0.0.1:{env["PG_TEST_PORT"]}/firewall?' + urllib.parse.urlencode({
                    'sslmode': 'verify-full', 'sslrootcert': str(config / 'tls.crt')})
                test_env = dict(env, GOWORK='off', CGO_ENABLED='1', NETCAP_POSTGRES_TEST_URL=test_url,
                                NETCAP_POSTGRES_TEST_CONTAINER=env['PG_TEST_CONTAINER'])
                result = subprocess.run(['go', 'test', '-race', '-json', '-count=1', '-p', '1', '-run', '^TestPostgres',
                                         './internal/firewallstate', './internal/firewallfleet'],
                                        cwd=ROOT, env=test_env, capture_output=True, text=True, timeout=180)
                if result.returncode:
                    print(result.stdout)
                    print(result.stderr)
                    raise AssertionError('Postgres package tests failed')
                events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
                package_checks = [e['Test'] for e in events if e.get('Action') == 'pass' and e.get('Test')]
                required = {'TestPostgresCountersActiveActive', 'TestPostgresCounterMultiProcess',
                            'TestPostgresFleetActiveActive', 'TestPostgresMCPAndAgentAcrossReplicas',
                            'TestPostgresDatabaseCrashRecovery'}
                assert required <= set(package_checks), 'required HA tests skipped or missing'
            backup = None
            if args.backup_restore:
                from backup_lab import qualify
                backup = qualify(env, temp, config, password)
            for path in temp.rglob('*'):
                if path.is_file():
                    contents = path.read_bytes()
                    assert all(secret.encode() not in contents for secret in [password, db_url, *tokens.values()]), \
                        'generated credential persisted in a host fixture file'
            report = {'result': 'pass', 'postgres_image': POSTGRES, 'postgres_version': version,
                'checks': ['TLS verified database and service connections', 'two fleet and two counter CLI replicas',
                           'stage/rollout/activate cross replicas', 'two enrolled target agents', 'scope isolation',
                           'global counts across direct counter replicas and WAFs', 'service availability after killing one replica of each service',
                           'database outage fails closed', 'database WAL restart preserves generations and committed counters'],
                'host_generated_password_or_token_files': False,
                'package_tests': package_checks,
                'backup_restore': backup,
                'boundary': 'one disposable Postgres primary; primary election/fencing and production DB HA are external operator responsibilities'}
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))
        except BaseException:
            result = run('logs', '--no-color', '--tail=25', 'fleet1', 'fleet2', 'state1', 'state2', 'postgres', check=False)
            print(result.stdout)
            raise
        finally:
            run('down', '--volumes', '--remove-orphans')


if __name__ == '__main__':
    main()
