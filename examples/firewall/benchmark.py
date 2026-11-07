#!/usr/bin/env python3
"""Bounded open-loop load against an isolated pinned Compose fixture; standard library only."""
import argparse
import collections
import concurrent.futures
import hashlib
import http.client
import json
import math
import os
import pathlib
import secrets
import socket
import subprocess
import threading
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = 'nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rate', type=float, default=50)
    parser.add_argument('--duration', type=float, default=10)
    parser.add_argument('--workers', type=int, default=32)
    parser.add_argument('--image', default='netcap-firewall:0.1.0-local')
    parser.add_argument('--coraza', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--body-bytes', type=int, default=0, help='multipart file bytes per offered request, 0=GET')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not (0 < args.rate <= 10000 and 0 < args.duration <= 300 and 1 <= args.workers <= 256):
        parser.error('rate <=10000, duration <=300s, workers <=256 required')
    if not 1 <= int(args.rate * args.duration) <= 100000:
        parser.error('1..100000 offered requests required')
    if not 0 <= args.body_bytes <= 64 * 1024 * 1024 - 4096:
        parser.error('body bytes must leave multipart framing room inside 64 MiB')
    project = 'fw-bench-' + secrets.token_hex(4)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, COMPOSE_PROJECT_NAME=project, FIREWALL_PORT=str(port),
               FIREWALL_IMAGE=args.image, BACKEND_IMAGE=FIXTURE)
    compose = ['docker', 'compose', '-f', str(ROOT / 'examples/firewall/compose.yaml')]
    scratch = tempfile.TemporaryDirectory(prefix='fw-benchmark-profile-')
    profile = pathlib.Path(scratch.name)
    profile.chmod(0o755)
    baseline = {'version': 'netcap-policy/v1', 'id': 'benchmark', 'mode': 'enforce', 'default': 'allow',
                'rules': [{'id': 'late', 'phase': 'request', 'expression': 'Body contains "netcap-smoke-deny"', 'action': 'deny', 'status': 403}]}
    if args.body_bytes or not args.coraza:
        (profile / 'policy.json').write_text(json.dumps(dict(baseline, rules=[]) if args.body_bytes else baseline))
        (profile / 'config.json').write_text(json.dumps({'version': 'netcap-firewall/v1', 'listen': ':8080',
            'adminListen': ':9090', 'upstream': 'http://backend:8080', 'policyFile': '/bench/policy.json',
            'maxBodyBytes': 67108864, 'maxResponseBytes': 67108864, 'maxBufferedBytes': 67108864,
            'maxConcurrent': 32, 'bodyTimeout': '15s', 'corazaCRS': args.coraza}))
        (profile / 'nginx.conf').write_text((ROOT / 'examples/firewall/buffered-nginx.conf').read_text())
        (profile / 'compose.json').write_text(json.dumps({'services': {
            'firewall': {'command': ['serve', '--config', '/bench/config.json'], 'volumes': [str(profile) + ':/bench:ro']},
            'backend': {'volumes': [str(profile / 'nginx.conf') + ':/etc/nginx/nginx.conf:ro']}}}))
        compose += ['-f', str(profile / 'compose.json')]

    def command(*parts):
        return subprocess.check_output([*parts], env=env, text=True)

    def request(path='/', chunks=None, load=False):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
        try:
            multipart = load and args.body_bytes > 0
            if multipart:
                def body():
                    yield b'--netcap-boundary\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'
                    remaining = args.body_bytes
                    while remaining:
                        size = min(remaining, 65536)
                        yield b'x' * size
                        remaining -= size
                    yield b'\r\n--netcap-boundary--\r\n'
                chunks = body()
            if chunks is None:
                connection.request('GET', path)
            else:
                connection.putrequest('POST', path)
                connection.putheader('Transfer-Encoding', 'chunked')
                if multipart:
                    connection.putheader('Content-Type', 'multipart/form-data; boundary=netcap-boundary')
                connection.endheaders()
                for chunk in chunks:
                    connection.send(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                    if not load:
                        time.sleep(0.01)
                connection.send(b'0\r\n\r\n')
            response = connection.getresponse()
            body = response.read()
            if response.status == 200:
                assert body == b'origin-ok\n'
                if multipart:
                    assert int(response.getheader('X-Origin-Request-Bytes', '0')) >= args.body_bytes
            return response.status
        finally:
            connection.close()

    # Docker's stats API supplies raw cgroup CPU throttling and memory counters,
    # even though the scratch WAF image has no shell or cgroup reader.
    context = json.loads(command('docker', 'context', 'inspect'))[0]
    endpoint = context['Endpoints']['docker']['Host']
    if not endpoint.startswith('unix://'):
        parser.error('local Unix-socket Docker context required')

    class Engine(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(15)
            self.sock.connect(endpoint.removeprefix('unix://'))

    def cgroup(container):
        connection = Engine('localhost', timeout=15)
        try:
            connection.request('GET', f'/containers/{container}/stats?stream=false&one-shot=true')
            response = connection.getresponse()
            assert response.status == 200, response.status
            stats = json.load(response)
            return {key: stats.get(key) for key in ['read', 'cpu_stats', 'memory_stats', 'pids_stats', 'blkio_stats']}
        finally:
            connection.close()

    try:
        command(*compose, 'up', '-d', '--no-build')
        for _ in range(60):
            try:
                if request() == 200:
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(1)
        else:
            raise RuntimeError('WAF never ready')
        container = command(*compose, 'ps', '-q', 'firewall').strip()
        identity = json.loads(command('docker', 'inspect', container))[0]
        backend = command(*compose, 'ps', '-q', 'backend').strip()
        backend_identity = json.loads(command('docker', 'inspect', backend))[0]
        before = cgroup(container)
        profile_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in profile.iterdir() if p.is_file()}
        slots = threading.BoundedSemaphore(args.workers)
        results = []
        dropped = 0
        count = int(args.rate * args.duration)

        def worker(planned):
            started = time.monotonic()
            try:
                try:
                    status = str(request(load=True))
                except (OSError, http.client.HTTPException) as error:
                    status = type(error).__name__
                finished = time.monotonic()
                return status, (finished - planned) * 1000, (started - planned) * 1000
            finally:
                slots.release()

        start = time.monotonic() + 0.1
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            for index in range(count):
                planned = start + index / args.rate
                time.sleep(max(0, planned - time.monotonic()))
                if slots.acquire(blocking=False):
                    results.append(pool.submit(worker, planned))
                else:
                    dropped += 1
        time.sleep(max(0, start + args.duration - time.monotonic()))
        elapsed = time.monotonic() - start
        observations = [future.result() for future in results]
        after = cgroup(container)
        if args.body_bytes:
            command(*compose, 'stop', 'firewall')
            (profile / 'policy.json').write_text(json.dumps(baseline))
            command(*compose, 'up', '-d', '--no-build', 'firewall')
            for _ in range(60):
                try:
                    if request() == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.2)
            else:
                raise RuntimeError('late-body profile never became ready')
        marker = 'late-' + secrets.token_hex(8)
        assert request('/?' + marker, [b'x' * 32768, b'netcap-smoke-deny']) == 403
        time.sleep(0.2)
        assert marker not in command(*compose, 'logs', '--no-color', 'backend'), 'late attack reached origin'

        def percentiles(values):
            ordered = sorted(values)
            return {f'p{p}': ordered[math.ceil(len(ordered) * p / 100) - 1]
                    for p in [50, 95, 99]} if ordered else {}

        report = {'fixture': {'image_id': identity['Image'], 'configured_image': identity['Config']['Image'],
                               'backend_image': FIXTURE, 'backend_image_id': backend_identity['Image'],
                               'backend_memory_limit': backend_identity['HostConfig']['Memory'],
                               'cpu_quota': identity['HostConfig']['NanoCpus'],
                               'memory_limit': identity['HostConfig']['Memory'],
                               'file_sha256': {name: hashlib.sha256((ROOT / 'examples/firewall' / name).read_bytes()).hexdigest()
                                               for name in ['compose.yaml', 'config.yaml', 'policy.yaml', 'nginx.conf']}},
                  'docker_arch': command('docker', 'info', '--format', '{{.Architecture}}').strip(),
                  'offered_rps': args.rate, 'offered_requests': count, 'duration_s': args.duration,
                  'coraza': args.coraza, 'multipart_file_bytes': args.body_bytes,
                  'measured_profile_sha256': profile_hashes,
                  'elapsed_with_drain_s': elapsed, 'workers': args.workers,
                  'generator_dropped': dropped, 'completed_rps': len(observations) / elapsed,
                  'statuses': dict(collections.Counter(row[0] for row in observations)),
                  'schedule_to_completion_ms': percentiles([row[1] for row in observations]),
                  'generator_lag_ms': percentiles([row[2] for row in observations]),
                  'quantile_method': 'nearest-rank', 'latency_samples': len(observations),
                  'cgroup_before': before, 'cgroup_after': after,
                  'late_body_attack': '403 and absent from origin logs',
                  'scope': 'local fixture over Docker published loopback; no production capacity claim'}
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({key: value for key, value in report.items() if not key.startswith('cgroup_')}, indent=2))
        assert dropped == 0 and report['statuses'] == {'200': count}, 'offered load not sustained; see JSON'
    finally:
        command(*compose, 'down', '--volumes', '--remove-orphans')
        scratch.cleanup()


if __name__ == '__main__':
    main()
