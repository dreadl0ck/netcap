#!/usr/bin/env python3
"""Collect bounded real-wire regression evidence, separately from soak evidence."""
import argparse
import collections
import json
import os
import pathlib
import signal
import subprocess
import threading
import time

from pilot import evidence_directory

ROOT = pathlib.Path(__file__).resolve().parents[3]
PROFILES = {
    'websocket': ('./internal/waf', ['TestMessageEvaluatorWebSocketSnapshotAndBothDirections']),
    'grpc': ('./internal/waf', ['TestMessageHandlerNativePolicyBeforeGRPCForwarding',
                              'TestMessageEvaluatorCoversGRPCHeadersMessagesTrailersAndGuardCounts']),
    'dns': ('./internal/gateway', ['TestDNSOriginEnforcementAndCompressedResponse',
                                 'TestDNSMalformedAndSourceDeniedNeverReachOrigin',
                                 'TestDNSCancellationDuringUpstreamWait']),
    'redis': ('./internal/gateway', ['TestRedisPipelineBinaryAndPreOriginDenial',
                                   'TestRedisUnsupportedModesAndMalformedNeverDial']),
    'postgres': ('./internal/gateway', ['TestPostgresExtendedPipelineGateAndOpaqueAuth',
                                      'TestPostgresParseDenialAndMalformedBind']),
    'mysql': ('./internal/gateway', ['TestMySQLPreparedStatementIDQueryGate',
                                   'TestMySQLOriginTLSVerificationPrecedesCredentials',
                                   'TestMySQLPreparedStateBoundAndClose']),
    'modbus': ('./internal/gateway', ['TestModbusOriginEnforcementSplitAndCoalesced',
                                    'TestModbusRejectsMalformedBeforeOrigin']),
    'dnp3': ('./internal/gateway', ['TestDNP3TransportApplicationGateNoForbiddenEffects',
                                  'TestDNP3ApplicationReplayClosesWithoutSecondEffect']),
    'smtp': ('./internal/gateway', ['TestSMTPWholeDataBeforeOriginAndResetRecovery',
                                  'TestSMTPAuthOpaqueNegotiation']),
    'state-recovery': ('./internal/waf', ['TestSharedGuardReadinessStartupFailureRecoveryAndNoProbeIO',
                                        'TestEvaluatorPreservesDenyWhenBrokerUnavailable']),
}


def summarize(events, expected, repetitions):
    passed = collections.Counter(event['Test'] for event in events
                                 if event.get('Action') == 'pass' and event.get('Test'))
    skipped = [event.get('Test') for event in events if event.get('Action') == 'skip']
    failed = [event.get('Test', event.get('Package')) for event in events if event.get('Action') == 'fail']
    missing = {name: repetitions - passed[name] for name in expected if passed[name] != repetitions}
    return {'passed': dict(passed), 'skipped': skipped, 'failed': failed, 'missing_or_wrong_count': missing,
            'accepted': not skipped and not failed and not missing}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--repetitions', type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 10:
        parser.error('repetitions must be 1..10')
    directory = evidence_directory(args.output)
    target = directory / 'protocols.json'
    if target.exists():
        parser.error('protocols.json exists; use a fresh directory')
    report = {'kind': 'bounded-wire-integration-not-soak', 'profiles': {}, 'result': 'running'}
    for name, (package, expected) in PROFILES.items():
        started = time.monotonic()
        command = ['go', 'test', '-race', '-json', '-count', str(args.repetitions),
                   '-timeout', '120s', '-tags', 'coraza,http3,nodpi,noyara',
                   '-run', '^(' + '|'.join(expected) + ')$', package]
        process = subprocess.Popen(command, cwd=ROOT, env=dict(os.environ, GOWORK='off'),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                   start_new_session=True)
        events = []
        size = 0
        def terminate():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = threading.Timer(180, terminate)
        deadline.start()
        try:
            # go test's internal timeout bounds execution; cap evidence in memory.
            for line in process.stdout:
                size += len(line)
                if size > 8 * 1024 * 1024:
                    raise RuntimeError('bounded protocol evidence exceeded 8 MiB')
                if line.startswith('{'):
                    events.append(json.loads(line))
            code = process.wait(timeout=10)
        finally:
            deadline.cancel()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            process.stdout.close()
        result = summarize(events, expected, args.repetitions)
        result.update(exit_code=code, elapsed_seconds=time.monotonic() - started,
                      command=command, evidence_bytes=size)
        if code:
            result['accepted'] = False
        report['profiles'][name] = result
        report['result'] = 'running'
        temporary = target.with_suffix('.tmp')
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(target)
    report['result'] = 'pass' if all(p['accepted'] for p in report['profiles'].values()) else 'fail'
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['result'] == 'pass' else 1


if __name__ == '__main__':
    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
