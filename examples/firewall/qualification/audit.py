#!/usr/bin/env python3
"""Join local qualification receipts without upgrading unrun deployment gates."""
import argparse
import json
import pathlib
import subprocess
import sys
import time

from pilot import evidence_directory
from protocols import PROFILES
from runner import digest, write, OWNER
from evidence import summarize


def audit(run, ftw, protocols, pilot, output):
    output = evidence_directory(output)
    if any(output.iterdir()):
        raise ValueError('fresh empty audit directory required')
    sources = {'manifest': run / 'manifest.json', 'load': run / 'http' / 'progress.json',
               'corpus': run / 'http' / 'falsepositives.json', 'ftw': ftw / 'ftw.json',
               'protocols': protocols / 'protocols.json', 'pilot': pilot / 'pilot.json'}
    receipts = {name: json.loads(path.read_text()) for name, path in sources.items()}
    manifest, load, corpus = (receipts[name] for name in ('manifest', 'load', 'corpus'))
    if manifest.get('owner') != OWNER or manifest['state'] != 'pass':
        raise ValueError('owned completed load manifest required')
    binary = pathlib.Path(manifest['binary'])
    if digest(binary) != manifest['binary_sha256']:
        raise ValueError('runner binary changed since measured run')
    for name in ('load', 'corpus'):
        relative = str(sources[name].relative_to(run))
        if digest(sources[name]) != manifest['receipt_sha256'].get(relative):
            raise ValueError('completed receipt changed: ' + name)
    negative = output / 'negative'
    negative.mkdir(mode=0o700)
    command = [str(binary), '-rules', '0', '-inject-leak', '-output', str(negative)]
    started = time.monotonic()
    process = subprocess.run(command, capture_output=True, timeout=120, check=False)
    negative_receipt = json.loads((negative / 'negative-control.json').read_text())
    negative_result = dict(command=command, exit_code=process.returncode,
                           elapsed_seconds=time.monotonic() - started,
                           receipt=negative_receipt)
    write(output / 'negative.json', negative_result)
    sources['negative'] = output / 'negative.json'
    zero = ('Errors', 'Dropped', 'FalseBlocks')
    wire_zero = ('forbidden_origin_requests', 'forbidden_origin_bytes', 'forbidden_side_effects')
    profile_checks = {name: (p['counts']['Allowed'] > 0 and p['counts']['Denied'] > 0
                            and p['counts']['Offered'] == p['counts']['Allowed'] + p['counts']['Denied']
                            and all(p['counts'][key] == 0 for key in zero)
                            and all(p.get(key, 0) == 0 for key in wire_zero))
                      for name, p in load['profiles'].items()}
    expected_wire = {'dns-udp-scripted-v1', 'h1-native-stateful',
                     *(name + '-scripted-v1' for name in ('redis', 'postgres', 'mysql', 'smtp',
                                                          'modbus', 'dnp3', 'websocket', 'grpc'))}
    expected_http = {f'h{proto}-{engine}-{rules}-filler' for proto in (1, 2, 3)
                     for engine in ('native', 'crs') for rules in (0, 10, 100, 1000)}
    protocol_receipt = receipts['protocols']
    ftw_receipt = receipts['ftw']
    ftw_rows = ftw_receipt['results']
    checks = {
        'mixed_load': load['load_state'] == 'pass' and load['mixed_wire_enabled']
                      and expected_wire | expected_http == set(profile_checks) and all(profile_checks.values()),
        'completed_requested_duration': load['actual_load_seconds'] >= load['requested_seconds'] >= 1800,
        'evaluator_state_exercised_and_recovered': load['profiles']['h1-native-stateful']['evaluator_state_peak']['entries'] > 0
            and load['profiles']['h1-native-stateful']['evaluator_state_current']['entries'] == 0
            and load['profiles']['h1-native-stateful']['evaluator_state_current']['groups'] == 0,
        'critical_false_blocks_zero': corpus['result'] == 'pass' and corpus['critical_false_blocks'] == 0,
        'route_corpus_origin_evidence': all(row['status'] == (403 if row['split'] == 'attack-control' else 200)
            and row['origin_request_delta'] == (0 if row['split'] == 'attack-control' else 1)
            for row in corpus['owned_synthetic_cases']),
        'ftw_reviewed_subset': ftw_receipt['passed'] and bool(ftw_receipt.get('license_sha256'))
            and len(ftw_rows) == 6 and all(row['accepted'] for row in ftw_rows)
            and {(row['protocol'], row['test_id']) for row in ftw_rows} == {(p, case) for p in (1, 2, 3) for case in (2, 4)},
        'bounded_protocol_regressions': protocol_receipt['result'] == 'pass'
            and set(protocol_receipt['profiles']) == set(PROFILES)
            and all(p['accepted'] and not p['skipped'] and not p['failed'] and not p['missing_or_wrong_count']
                    for p in protocol_receipt['profiles'].values()),
        'independent_leak_negative_exits_nonzero': process.returncode == 1
            and negative_receipt['result'] == 'detected' and negative_receipt['forbidden_bytes'] > 0,
        'pilot_local_rehearsal': receipts['pilot']['result'] == 'local-fake-pass'
            and receipts['pilot']['production_pilot'] == 'not-authorized-not-executed',
    }
    result = dict(result='pass' if all(checks.values()) else 'fail', checks=checks,
                  scope='owned local scripted wire qualification; no vendor-server or production admission claim',
                  load=summarize(run / 'http'), corpus_rows=len(corpus['owned_synthetic_cases']),
                  critical_false_blocks=corpus['critical_false_blocks'],
                  ftw_cases=len(ftw_rows), protocol_skips=sum(len(p['skipped']) for p in protocol_receipt['profiles'].values()),
                  binary_sha256=manifest['binary_sha256'],
                  evidence={name: dict(path=str(path.resolve()), sha256=digest(path)) for name, path in sources.items()},
                  unrun_gates=['24h run' if not load['soak_24h_pass'] else None,
                               'authorized production pilot', 'vendor-server version matrix',
                               'external UDP ingress/LB/NAT/CNI path',
                               'OS process and external state dependency disruptions during sustained load'],
                  production_authorization='absent; local-only plan passed, production not executed')
    result['unrun_gates'] = [gate for gate in result['unrun_gates'] if gate]
    write(output / 'qualification.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run', 'ftw', 'protocols', 'pilot', 'output'):
        parser.add_argument('--' + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = audit(**vars(args))
    print(json.dumps({key: value for key, value in result.items() if key != 'evidence'}, indent=2))
    return 0 if result['result'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
