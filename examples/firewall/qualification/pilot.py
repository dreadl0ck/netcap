#!/usr/bin/env python3
"""Validate a finite pilot inventory and execute only an owned loopback fake."""
import argparse
import hashlib
import http.client
import http.server
import json
import pathlib
import threading
import time

MAX_ENDPOINTS = 16
ALLOWED = {('GET', '/health'), ('POST', '/api/invoices'),
           ('POST', '/api/orders'), ('POST', '/api/comments')}


def validate(plan):
    if set(plan) != {'version', 'environment', 'endpoints', 'requests_per_endpoint',
                     'rate', 'timeout_seconds'} or plan['version'] != 1:
        raise ValueError('strict version 1 pilot plan required')
    if plan['environment'] != 'owned-local-fake':
        raise ValueError('exact production environment authorization is absent; local fake only')
    for key, low, high in [('requests_per_endpoint', 1, 100), ('rate', 1, 50),
                           ('timeout_seconds', 1, 5)]:
        if type(plan[key]) is not int or not low <= plan[key] <= high:
            raise ValueError(f'{key} must be an integer in {low}..{high}')
    endpoints = plan['endpoints']
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= MAX_ENDPOINTS:
        raise ValueError('1..16 finite endpoint records required')
    seen = set()
    for endpoint in endpoints:
        if set(endpoint) != {'method', 'path'}:
            raise ValueError('only method/path endpoint descriptors accepted; no target URLs')
        pair = (endpoint['method'], endpoint['path'])
        if pair not in ALLOWED or pair in seen:
            raise ValueError('endpoint must be unique and exactly allowlisted')
        seen.add(pair)
    return plan


def execute(plan):
    validate(plan)
    ledger = []

    class Fake(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.handle_request()

        def do_POST(self):
            self.handle_request()

        def handle_request(self):
            pair = (self.command, self.path)
            size = int(self.headers.get('Content-Length', '0'))
            if pair not in ALLOWED or not 0 <= size <= 1024:
                self.send_error(403)
                return
            payload = self.rfile.read(size)
            ledger.append({'method': self.command, 'path': self.path, 'bytes': len(payload),
                           'body_sha256': hashlib.sha256(payload).hexdigest()})
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fake)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    statuses = []
    started = time.monotonic()
    try:
        for index in range(plan['requests_per_endpoint']):
            for endpoint in plan['endpoints']:
                planned = started + len(statuses) / plan['rate']
                time.sleep(max(0, planned - time.monotonic()))
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port,
                                                         timeout=plan['timeout_seconds'])
                try:
                    body = None if endpoint['method'] == 'GET' else b'{"fixture":"synthetic-only"}'
                    connection.request(endpoint['method'], endpoint['path'], body,
                                       {'Content-Type': 'application/json'})
                    response = connection.getresponse()
                    if response.read(1025) != b'OK' or response.status != 200:
                        raise AssertionError('fake workflow failed')
                    statuses.append(response.status)
                finally:
                    connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    if thread.is_alive() or len(ledger) != len(statuses):
        raise AssertionError('fixture cleanup or independent request count failed')
    return {'result': 'local-fake-pass', 'production_pilot': 'not-authorized-not-executed',
            'requests': len(statuses), 'elapsed_seconds': time.monotonic() - started,
            'ledger': ledger, 'cleanup': 'listener closed and serving thread joined',
            'scope': 'workflow plan rehearsal, no firewall capacity or deployment evidence'}


def evidence_directory(path):
    path = path.resolve()
    if not path.is_dir() or any((parent / '.git').exists() for parent in [path, *path.parents]):
        raise ValueError('existing evidence directory outside git required')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--execute-local-fake', action='store_true')
    args = parser.parse_args()
    plan = validate(json.loads(args.plan.read_text()))
    directory = evidence_directory(args.output)
    path = directory / 'pilot.json'
    if path.exists():
        parser.error('pilot.json already exists; use a fresh evidence directory')
    result = execute(plan) if args.execute_local_fake else {
        'result': 'validated-only', 'production_pilot': 'not-authorized-not-executed', 'plan': plan}
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'ledger'}))


if __name__ == '__main__':
    main()
