#!/usr/bin/env python3
"""Validate shipped examples and reuse existing real-CLI TLS dry-run lease evidence."""
import argparse
import json
import os
import pathlib
import secrets
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / 'examples/firewall'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--validate-only', action='store_true', help='skip Go integration tests; no traffic evidence')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    env = dict(os.environ, GOWORK='off', CGO_ENABLED='1', LAB_ENFORCER_TOKEN=secrets.token_hex(32))
    with tempfile.TemporaryDirectory(prefix='fw-example-validation-') as directory:
        temp = pathlib.Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(temp / 'lab-enforcer.key'), '-out', str(temp / 'lab-enforcer.crt'),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        effects = json.loads((EXAMPLES / 'effects-config.json').read_text())
        effects['ca'] = str(temp / 'lab-enforcer.crt')
        effect_path = temp / 'effects.json'
        effect_path.write_text(json.dumps(effects))
        version = json.loads(subprocess.check_output([binary, 'version'], text=True, env=env))
        assert {'mysql', 'dnp3', 'network'} <= set(version['protocols']), version
        validated = []
        for name in ['advanced-policy.yaml', 'effects-policy.yaml', 'audit-smb-policy.yaml', 'capture-policy.yaml']:
            config = temp / 'config.json'
            config.write_text(json.dumps({'version': 'netcap-firewall/v1', 'listen': '127.0.0.1:18080',
                'adminListen': '127.0.0.1:19090', 'upstream': 'http://127.0.0.1:18081',
                'policyFile': str(EXAMPLES / name), 'maxBodyBytes': 1048576, 'maxResponseBytes': 1048576,
                'maxBufferedBytes': 67108864, 'maxConcurrent': 8, 'bodyTimeout': '5s'}))
            options = [binary, 'validate', '--config', str(config)]
            admitted = name in ['effects-policy.yaml', 'audit-smb-policy.yaml']
            if admitted:
                rejected = subprocess.run(options, env=env, capture_output=True, text=True, timeout=15)
                assert rejected.returncode != 0, 'effect policy accepted without explicit broker admission'
                options += ['--effects-config', str(effect_path)]
            subprocess.run(options, env=env, check=True, timeout=15)
            validated.append(name)
        subprocess.run([binary, 'network', '--validate-only', '--policy', str(EXAMPLES / 'network-policy.yaml'),
                        '--namespace', 'netcap-fw-lab', '--interface', 'lab0', '--protected-cidr', '10.81.0.2/32',
                        '--hook', 'forward', '--failure-verdict', 'deny', '--inspect-tls'],
                       check=True, env=env, timeout=15)
        validated.append('network-policy.yaml')
        passed = []
        if not args.validate_only:
            selected = {'TestEffectsBrokerShippingDryRunLease', 'TestLiveBrokerAndReplayAreSeparated',
                        'TestCaptureMultiFileReplayNeverContactsEnforcer'}
            result = subprocess.run(['go', 'test', '-race', '-json', '-count=1', '-tags', 'coraza,http3,nodpi,noyara',
                                     '-run', '^(' + '|'.join(sorted(selected)) + ')$',
                                     './cmd/netcap-firewall', './internal/firewallaudit'],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
            if result.returncode:
                print(result.stdout)
                print(result.stderr)
                raise AssertionError('selected full-stack integration evidence failed')
            events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
            passed = [event['Test'] for event in events if event.get('Action') == 'pass' and event.get('Test')]
            assert selected <= set(passed), 'required integration tests missing or skipped'
        report = {'result': 'pass', 'version': version, 'validated_examples': validated, 'integration_tests': passed,
                  'verification': 'validation-only' if args.validate_only else 'examples-and-existing-integration',
                  'evidence': 'committed examples compile; no traffic tests requested' if args.validate_only else
                              'committed examples compile; selected existing tests prove actual CLI TLS dry-run leases, trusted attribution and audit/replay separation',
                  'boundary': 'no live kernel lease or host routing change; SMTP example is compiled only'}
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
