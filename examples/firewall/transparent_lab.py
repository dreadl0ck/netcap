#!/usr/bin/env python3
"""Build and qualify shipping gateway/redirect CLIs in disposable Docker namespaces."""
import argparse
import json
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='netcap-transparentfirewall:qualification')
    parser.add_argument('--skip-build', action='store_true',
                        help='run an already-built qualification image')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if not args.skip_build:
        subprocess.run(['docker', 'build', '-f',
                        'internal/transparentfirewall/Dockerfile.lab',
                        '-t', args.image, '.'], cwd=root, check=True, timeout=900)
    name = 'netcap-transparent-lab-' + uuid.uuid4().hex[:12]
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', '--name', name, '--privileged',
             '--network=none', args.image],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=150)
    finally:
        subprocess.run(['docker', 'rm', '-f', name], check=False,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    print(result.stdout, end='')
    result.check_returncode()
    expected = ['--- PASS: TestTransparentLab ',
                '--- PASS: TestTransparentShippingCLI ']
    expected += [f'--- PASS: TestTransparentShippingCLI/{protocol}/{family} '
                 for protocol in ('redis', 'dnp3') for family in ('ipv4', 'ipv6')]
    if '--- SKIP:' in result.stdout or any(s not in result.stdout for s in expected):
        raise SystemExit('qualification incomplete: required checks missing or skipped')
    print(json.dumps({
        'result': 'pass', 'host_mounts': False, 'network': 'none',
        'checks': ['shipping gateway and redirect processes',
                   'Redis/DNP3 IPv4/IPv6 message withholding and source ACL',
                   'missing-listener refusal', 'SIGTERM restores direct traffic',
                   'unrelated tables, addresses, ports and UDP preserved',
                   'default namespace ruleset and interfaces unchanged'],
        'boundary': 'explicit TCP services and new conntrack sessions; fixed upstream',
        'tls': 'opaque TLS rejected; terminated label does not verify certificates; caller owns termination',
    }))


if __name__ == '__main__':
    main()
