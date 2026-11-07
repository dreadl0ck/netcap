#!/usr/bin/env python3
"""Managed-process backup/restore drill with traffic, audit and receipt assertions."""
import argparse
import contextlib
import http.server
import json
import os
import pathlib
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
OPERATOR = ROOT / 'examples/firewall/managed_snapshot.py'


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, default=ROOT / 'netcap-firewall')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    token = secrets.token_hex(32)

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'origin-ok\n')

        def log_message(self, *_):
            pass

    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='fw-restore-drill-') as directory:
            temp = pathlib.Path(directory)
            app, admin = port(), port()
            config = temp / 'config.json'
            baseline = {'version': 'netcap-policy/v1', 'id': 'restore-baseline', 'mode': 'enforce',
                        'default': 'allow', 'rules': []}
            (temp / 'policy.json').write_text(json.dumps(baseline))
            config.write_text(json.dumps({'version': 'netcap-firewall/v1', 'listen': f'127.0.0.1:{app}',
                                           'adminListen': f'127.0.0.1:{admin}',
                                           'upstream': f'http://127.0.0.1:{origin.server_port}',
                                           'policyFile': str(temp / 'policy.json'),
                                           'maxBodyBytes': 1048576, 'maxResponseBytes': 1048576,
                                           'maxConcurrent': 8, 'bodyTimeout': '5s'}))
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', str(temp / 'tls.key'), '-out', str(temp / 'tls.crt'),
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tls = ssl.create_default_context(cafile=str(temp / 'tls.crt'))

            def api(op, data=None):
                request = urllib.request.Request(f'https://localhost:{admin}/api/v1/policy/{op}',
                                                 data=None if data is None else json.dumps(data).encode(),
                                                 headers={'Authorization': 'Bearer ' + token,
                                                          'Content-Type': 'application/json'})
                with urllib.request.urlopen(request, context=tls, timeout=5) as response:
                    return json.load(response)

            def traffic(expected):
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{app}/blocked', timeout=5) as response:
                        assert response.status == expected
                except urllib.error.HTTPError as error:
                    assert error.code == expected, error.code

            @contextlib.contextmanager
            def serve(state):
                with (temp / 'process.log').open('w+') as log:
                    process = subprocess.Popen([str(args.binary.resolve()), 'serve', '--config', str(config),
                                                '--managed', '--state-dir', str(state), '--admin-cert',
                                                str(temp / 'tls.crt'), '--admin-key', str(temp / 'tls.key')],
                                               env=dict(os.environ, NETCAP_FIREWALL_ADMIN_TOKEN=token),
                                               stdout=log, stderr=log)
                    try:
                        for _ in range(100):
                            if process.poll() is not None:
                                log.seek(0)
                                raise RuntimeError(log.read())
                            try:
                                api('revision')
                                break
                            except (OSError, urllib.error.URLError):
                                time.sleep(0.1)
                        else:
                            raise RuntimeError('managed process never ready')
                        yield
                    finally:
                        if process.poll() is None:
                            process.terminate()
                        process.wait(timeout=60)

            def operator(operation, state, snapshot, success=True):
                result = subprocess.run([sys.executable, str(OPERATOR), operation,
                                         '--state-dir', str(state), '--snapshot', str(snapshot)],
                                        text=True, capture_output=True, timeout=10)
                assert (result.returncode == 0) == success, result.stderr
                return result

            source, restored, backup = temp / 'source', temp / 'restored', temp / 'snapshot.sqlite'
            with serve(source):
                original = api('revision')['revision']
                traffic(200)
                candidate = dict(baseline, id='restore-deny', rules=[{
                    'id': 'deny', 'phase': 'request', 'expression': 'Path == "/blocked"',
                    'action': 'deny', 'status': 403}])
                stage = {'bundle': json.dumps(candidate), 'idempotency_key': 'drill-stage'}
                staged = api('stage', stage)
                activation = {'revision': staged['revision'], 'expected_revision': original,
                              'idempotency_key': 'drill-activate'}
                receipt = api('activate', activation)
                audit = api('audit')
                traffic(403)
                operator('backup', source, backup, success=False)
                assert not backup.exists(), 'live-owner refusal left an artifact'
            operator('backup', source, backup)
            operator('backup', source, backup, success=False)
            corrupt = temp / 'corrupt.sqlite'
            corrupt.write_bytes(b'not a SQLite backup')
            corrupt.chmod(0o600)
            operator('restore', temp / 'corrupt-restore', corrupt, success=False)
            assert not (temp / 'corrupt-restore/policycontrol.sqlite').exists()
            operator('restore', restored, backup)
            operator('restore', restored, backup, success=False)
            with serve(restored):
                assert api('revision')['revision'] == staged['revision']
                assert api('audit') == audit, 'audit did not survive restore'
                assert api('stage', stage) == staged, 'stage receipt did not survive restore'
                assert api('activate', activation) == receipt, 'CAS/idempotency receipt did not survive restore'
                traffic(403)
                api('rollback', {'revision': original, 'expected_revision': staged['revision'],
                                 'idempotency_key': 'drill-rollback'})
                traffic(200)
            report = {'result': 'pass', 'sqlite_version': __import__('sqlite3').sqlite_version,
                      'checks': ['live owner backup refused', 'offline transactional snapshot integrity',
                                 'existing backup/restore refused', 'corrupt backup refused', 'restored live revision',
                                 'audit retained', 'stage and activation receipts retained',
                                 'restored deny traffic', 'rollback restores allowed traffic'],
                      'boundary': 'offline process-owner operator; no online backup API/CLI assumed'}
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))
    finally:
        origin.shutdown()
        origin.server_close()


if __name__ == '__main__':
    main()
