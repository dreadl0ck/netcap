#!/usr/bin/env python3
"""Two real WAFs and PostgreSQL native-rule authorities; scoped state and fail-closed faults."""
import argparse
import copy
import json
import os
import pathlib
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml
from postgres_ha import POSTGRES, ROOT, free_port

CURL = 'curlimages/curl:8.19.0@sha256:c03110c736db81bbe1be0296f1f1608c81b954b01626bdfb0a8f84e5bd00ff3c'
HEALTH = '/api/v1/policy-state/health'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--package-tests', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='native-policy-state-') as directory:
        temp = pathlib.Path(directory)
        config = temp / 'config'
        config.mkdir(mode=0o755)
        nonce = secrets.token_hex(4)
        password = secrets.token_hex(32)
        tokens = {f'NATIVE{i}_TOKEN': secrets.token_hex(32) for i in [1, 2]}
        env = dict(os.environ, COMPOSE_PROJECT_NAME='ncf-policy-' + nonce, PG_TEST_CONTAINER='ncf-policy-' + nonce,
                   LAB_CONFIG_DIR=str(config), POSTGRES_PASSWORD=password, **tokens)
        ports = set()
        for name in ['PG_TEST', 'AUTHORITY1', 'AUTHORITY2', 'WAF1', 'WAF2']:
            port = free_port()
            while port in ports:
                port = free_port()
            ports.add(port)
            env[name + '_PORT'] = str(port)
        env['CONTROL_DATABASE_URL'] = f'postgres://firewall:{password}@postgres:5432/firewall?sslmode=verify-full&sslrootcert=/lab/tls.crt'
        scope = {'tenant': 'lab', 'app': 'native-policy-state'}

        def write(name, data):
            (config / name).write_text(json.dumps(data))

        write('authority.json', {'databaseURLEnv': 'CONTROL_DATABASE_URL', 'databaseNamespace': 'ncf_policy_authority',
            'allowEffects': False, 'maxRevisions': 64, 'maxStateBytes': 67108864,
            'principals': [{'id': f'waf{i}', 'tokenEnv': f'NATIVE{i}_TOKEN', 'scope': scope} for i in [1, 2]]})
        policy = yaml.safe_load((ROOT / 'examples/firewall/policy-state-policy.yaml').read_text())
        for i in [1, 2]:
            write(f'policy{i}.json', policy)
            write(f'client{i}.json', {'url': 'https://authority:9092', 'tokenEnv': f'NATIVE{i}_TOKEN',
                                     'ca': '/lab/tls.crt', 'requestTimeout': 1000000000})
            write(f'waf{i}.json', {'version': 'netcap-firewall/v1', 'listen': ':8080', 'adminListen': ':9090',
                'upstream': 'http://backend:8080', 'policyFile': f'/lab/policy{i}.json', 'maxBodyBytes': 1048576,
                'maxResponseBytes': 1048576, 'maxBufferedBytes': 67108864, 'maxConcurrent': 8, 'bodyTimeout': '5s', 'corazaCRS': False})
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-keyout', str(config / 'tls.key'), '-out', str(config / 'tls.crt'), '-subj', '/CN=authority',
            '-addext', 'subjectAltName=DNS:postgres,DNS:authority,DNS:authority1,DNS:authority2,DNS:localhost,IP:127.0.0.1'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (config / 'tls.key').chmod(0o644)
        tls = ssl.create_default_context(cafile=str(config / 'tls.crt'))
        compose = ['docker', 'compose', '-f', str(ROOT / 'examples/firewall/policy-state-compose.yaml')]

        def run(*parts, check=True):
            return subprocess.run([*compose, *parts], env=env, check=check, text=True, capture_output=True, timeout=180)

        def health(node, expected=200, authorized=True):
            headers = {'Authorization': 'Bearer ' + tokens['NATIVE1_TOKEN']} if authorized else {}
            req = urllib.request.Request(f'https://127.0.0.1:{env[f"AUTHORITY{node}_PORT"]}{HEALTH}', headers=headers)
            try:
                with urllib.request.urlopen(req, context=tls, timeout=3) as response:
                    data = json.load(response)
                    assert response.status == expected and data == {'version': 1, 'ready': True}
                    return True
            except urllib.error.HTTPError as error:
                if error.code != expected:
                    raise
                return True

        def wait(check):
            for _ in range(150):
                try:
                    if check():
                        return
                except (OSError, urllib.error.URLError, subprocess.CalledProcessError):
                    pass
                time.sleep(0.2)
            raise AssertionError('native policy-state fixture convergence timeout')

        def ready(node, expected=True):
            result = run('exec', '-T', f'waf{node}', '/netcap-firewall', 'healthcheck', check=False)
            return (result.returncode == 0) == expected

        latencies = []

        def traffic(node, path, expected, body=None):
            req = urllib.request.Request(f'http://127.0.0.1:{env[f"WAF{node}_PORT"]}{path}', data=body,
                                         headers={'Host': 'native-policy-state.lab', 'Content-Type': 'application/octet-stream'})
            start = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    assert response.status == expected and response.read() == b'origin-ok\n'
            except urllib.error.HTTPError as error:
                assert error.code == expected, (node, path, error.code)
            latencies.append((time.monotonic() - start) * 1000)

        def curl_probe(authorized=True):
            node = run('ps', '-q', 'authority2').stdout.strip()
            probe = ROOT / 'charts/netcap-firewall-control/files/policy-state-health.sh'
            header = 'Authorization: Bearer ' + (tokens['NATIVE2_TOKEN'] if authorized else 'invalid-probe-token')
            return subprocess.run(['docker', 'run', '--rm', '--interactive', '--network=container:' + node,
                '--user', '10001:10001', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--tmpfs', '/probe-auth:rw,noexec,nosuid,nodev,size=64k,mode=0700,uid=10001,gid=10001',
                '-v', str(probe) + ':/health/probe.sh:ro', '-v', str(config / 'tls.crt') + ':/probe-ca/ca.crt:ro',
                '-e', 'PROBE_SERVER=authority', '--entrypoint', '/bin/sh', CURL, '-ec',
                'umask 077; IFS= read -r header; printf "%s" "$header" > /probe-auth/authorization; '
                'unset header; exec /bin/sh /health/probe.sh'], input=header + '\n', text=True,
                capture_output=True, timeout=30)

        try:
            run('config', '--quiet')
            run('up', '-d')
            wait(lambda: health(1))
            wait(lambda: health(2))
            health(1, expected=401, authorized=False)
            assert curl_probe().returncode == 0
            assert curl_probe(authorized=False).returncode != 0
            for i in [1, 2]:
                wait(lambda i=i: ready(i))
            traffic(1, '/sliding', 200)
            traffic(2, '/sliding', 200)
            run('kill', 'authority1')
            wait(lambda: health(2))
            time.sleep(1.2)  # Health probes evict dead persistent connections without evaluating another event.
            traffic(2, '/sliding', 429)
            run('start', 'authority1')
            wait(lambda: health(1))
            traffic(1, '/sliding', 429)
            marker = 'native-privacy-' + secrets.token_hex(16)
            for node, path, expected in [(1, '/distinct/a-' + marker, 200), (2, '/distinct/a-' + marker, 200),
                                         (2, '/distinct/b-' + marker, 200), (1, '/distinct/c-' + marker, 429)]:
                traffic(node, path, expected)
            traffic(1, '/sequence/login', 200)
            traffic(2, '/sequence/export', 403)
            traffic(1, '/body-check', 403, body=marker.encode())
            private_rows = run('exec', '-T', 'postgres', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'firewall',
                '-d', 'firewall', '-Atc', "SELECT count(*) FROM ncf_policy_authority.policy_states WHERE "
                f"position(convert_to('{marker}','UTF8') in bundle)>0 OR position(convert_to('{marker}','UTF8') in snapshot)>0").stdout.strip()
            assert private_rows == '0', 'raw request data persisted by authority'
            revised = copy.deepcopy(policy)
            revised['id'] = 'native-authority-v2'
            write('policy1.json', revised)
            run('restart', 'waf1')
            wait(lambda: ready(1))
            traffic(1, '/sliding', 200)  # New revision starts independent state.
            traffic(2, '/sliding', 429)  # Previous revision is not reset or erased.
            traffic(1, '/sliding', 200)
            traffic(1, '/sliding', 429)
            write('policy2.json', revised)
            run('restart', 'waf2')
            wait(lambda: ready(2))
            traffic(2, '/sliding', 429)  # Joining the revision does not reset its shared state.
            run('kill', 'postgres')
            health(2, expected=503)
            assert curl_probe().returncode != 0
            traffic(1, '/db-outage', 503)
            for i in [1, 2]:
                wait(lambda i=i: ready(i, expected=False))
            run('start', 'postgres')
            wait(lambda: health(1))
            wait(lambda: health(2))
            for i in [1, 2]:
                wait(lambda i=i: ready(i))
            traffic(2, '/sliding', 429)
            package_tests, skipped = [], []
            if args.package_tests:
                query = urllib.parse.urlencode({'sslmode': 'verify-full', 'sslrootcert': str(config / 'tls.crt')})
                test_env = dict(env, GOWORK='off', CGO_ENABLED='1',
                    NETCAP_POSTGRES_TEST_URL=f'postgres://firewall:{password}@127.0.0.1:{env["PG_TEST_PORT"]}/firewall?{query}',
                    NETCAP_POSTGRES_TEST_CONTAINER=env['PG_TEST_CONTAINER'])
                result = subprocess.run(['go', 'test', '-race', '-json', '-count=1', './internal/policystate'],
                    env=test_env, cwd=ROOT, text=True, capture_output=True, timeout=180)
                if result.returncode:
                    print(result.stdout)
                    print(result.stderr)
                    raise AssertionError('native policy-state package tests failed')
                events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
                package_tests = [e['Test'] for e in events if e.get('Action') == 'pass' and e.get('Test')]
                skipped = [e['Test'] for e in events if e.get('Action') == 'skip' and e.get('Test')]
                assert 'TestPostgresNativeStateAcrossProcesses' in package_tests
            run('kill', 'authority1', 'authority2')
            traffic(2, '/authority-outage', 503)
            logs = run('logs', '--no-color', 'backend').stdout
            assert '/db-outage' not in logs and '/authority-outage' not in logs and '/body-check' not in logs
            for path in temp.rglob('*'):
                if path.is_file():
                    contents = path.read_bytes()
                    assert all(value.encode() not in contents for value in [password, env['CONTROL_DATABASE_URL'], *tokens.values()]), 'generated credential persisted'
            report = {'result': 'pass', 'postgres_image': POSTGRES,
                'checks': ['two rootless WAFs and two PG authority processes', 'TLS and authenticated health including exact optional chart probe',
                           'native sliding count survives authority process loss/restart', 'distinct duplicate handling across WAFs',
                           'named sequence crosses WAFs', 'new revision isolates state without erasing old revision',
                           'joining revision preserves shared counts', 'DB restart retains state',
                           'DB/authority outages fail closed without local fallback or origin traffic',
                           'unique body/path marker absent from persisted artifact/snapshot', 'generated credentials remain in runtime environment'],
                'request_timeout_ns': 1000000000, 'observed_request_latencies_ms': latencies,
                'package_tests': package_tests, 'skipped_package_tests': skipped,
                'boundary': 'local functional qualification, not capacity; remote evaluation adds TLS/DB latency per event/message; ambiguous outcomes are not retried'}
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))
        except BaseException:
            print(run('logs', '--no-color', '--tail=25', 'authority1', 'authority2', 'waf1', 'waf2', check=False).stdout)
            raise
        finally:
            run('down', '--volumes', '--remove-orphans')


if __name__ == '__main__':
    main()
