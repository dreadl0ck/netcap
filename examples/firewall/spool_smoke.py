#!/usr/bin/env python3
"""Container-level large-body, late-body and aggregate-quota checks, with and without CRS."""
import argparse
import http.client
import json
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    reports = []
    with tempfile.TemporaryDirectory(prefix='fw-spool-') as directory:
        temp = pathlib.Path(directory)
        temp.chmod(0o755)
        port = free_port()
        env = dict(os.environ, COMPOSE_PROJECT_NAME='fw-spool-' + secrets.token_hex(4), FIREWALL_PORT=str(port))
        override = temp / 'compose.json'
        (temp / 'nginx.conf').write_text((ROOT / 'examples/firewall/buffered-nginx.conf').read_text())
        override.write_text(json.dumps({'services': {'firewall': {
            'command': ['serve', '--config', '/lab/config.json'],
            'volumes': [str(temp) + ':/lab:ro']}, 'backend': {
                'volumes': [str(temp / 'nginx.conf') + ':/etc/nginx/nginx.conf:ro']}}}))
        compose = ['docker', 'compose', '-f', str(ROOT / 'examples/firewall/compose.yaml'), '-f', str(override)]

        def run(*parts):
            return subprocess.check_output([*compose, *parts], env=env, text=True, timeout=60)

        def request(path, chunks=None, content_type='application/octet-stream'):
            c = http.client.HTTPConnection('127.0.0.1', port, timeout=90)
            try:
                if chunks is None:
                    c.request('GET', path)
                else:
                    c.putrequest('POST', path)
                    c.putheader('Content-Type', content_type)
                    c.putheader('Transfer-Encoding', 'chunked')
                    c.endheaders()
                    for chunk in chunks:
                        c.send(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                    c.send(b'0\r\n\r\n')
                r = c.getresponse()
                r.read()
                if r.status == 200 and path.startswith('/large-'):
                    assert int(r.getheader('X-Origin-Request-Bytes', '0')) >= 8388608
                return r.status
            finally:
                c.close()

        def configure(crs, body_policy=False, budget=67108864):
            run('stop', 'firewall')
            policy = {'version': 'netcap-policy/v1', 'id': 'spool-lab', 'mode': 'enforce', 'default': 'allow', 'rules': []}
            if body_policy:
                policy['rules'] = [{'id': 'late-body', 'phase': 'request', 'expression': 'Body contains "netcap-smoke-deny"', 'action': 'deny', 'status': 403}]
            (temp / 'policy.json').write_text(json.dumps(policy))
            (temp / 'config.json').write_text(json.dumps({
                'version': 'netcap-firewall/v1', 'listen': ':8080', 'adminListen': ':9090',
                'upstream': 'http://backend:8080', 'policyFile': '/lab/policy.json',
                'maxBodyBytes': 67108864, 'maxResponseBytes': 67108864, 'maxBufferedBytes': budget,
                'maxConcurrent': 32, 'bodyTimeout': '90s', 'corazaCRS': crs}))
            run('up', '-d', '--no-build')
            for _ in range(60):
                try:
                    if request('/') == 200:
                        return
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.2)
            raise AssertionError('spool fixture never ready')

        try:
            for crs in [False, True]:
                configure(crs)
                durations = []
                body_bytes = 8388608
                for i in range(3):
                    start = time.monotonic()
                    chunks = [b'--netcap-boundary\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\nContent-Type: application/octet-stream\r\n\r\n']
                    chunks += [b'x' * 65536] * (body_bytes // 65536)
                    chunks += [b'\r\n--netcap-boundary--\r\n']
                    status = request(f'/large-{crs}-{i}', chunks, 'multipart/form-data; boundary=netcap-boundary')
                    assert status == 200, ('large body status', crs, status)
                    durations.append((time.monotonic() - start) * 1000)
                container = run('ps', '-q', 'firewall').strip()
                stats = json.loads(subprocess.check_output(['docker', 'stats', '--no-stream', '--format', '{{json .}}', container], text=True))
                configure(crs, body_policy=True)
                marker = 'late-' + secrets.token_hex(6)
                assert request('/?' + marker, [b'x' * 32768, b'netcap-smoke-deny']) == 403
                assert marker not in run('logs', '--no-color', 'backend')
                configure(crs, budget=1572864)
                held = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                try:
                    held.putrequest('POST', '/held')
                    held.putheader('Transfer-Encoding', 'chunked')
                    held.endheaders()
                    for _ in range(32):
                        held.send(b'8000\r\n' + b'x' * 32768 + b'\r\n')
                    time.sleep(0.2)
                    assert request('/quota', [b'x' * 32768] * 32) == 503
                finally:
                    held.close()
                time.sleep(0.2)
                assert request('/recovered') == 200
                reports.append({'coraza': crs, 'file_bytes': body_bytes, 'payload': 'multipart file; not opaque-body or file-content inspection qualification', 'allowed_requests': 3,
                                'latencies_ms': durations, 'docker_stats': stats,
                                'late_body': '403; absent at origin', 'aggregate_quota': '503 under retained body; released after close'})
            args.output.write_text(json.dumps({'result': 'pass', 'profiles': reports, 'scope': 'bounded fixture qualification, not capacity'}, indent=2) + '\n')
            print(json.dumps({'result': 'pass', 'profiles': reports}, indent=2))
        except BaseException:
            print(run('logs', '--no-color', '--tail=30', 'firewall', 'backend'))
            raise
        finally:
            run('down', '--volumes', '--remove-orphans')


if __name__ == '__main__':
    main()
