#!/usr/bin/env python3
"""Fail-closed Npcap gate, with an operator-created loopback capture as evidence."""
import argparse
import base64
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def live_records(directory):
    spec = importlib.util.spec_from_file_location('packaged_client', Path(__file__).with_name('qualify-packaged-client.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    records = module.rows(directory)
    positive = [r for r in records if r.get('DstPort') == 19999 and r.get('SrcIP') == '127.0.0.1'
                and r.get('DstIP') == '127.0.0.1'
                and base64.b64decode(r.get('Payload', ''), validate=True) == b'NETCAP_NPCAP_POSITIVE']
    if not positive or any(r.get('DstPort') == 19998 for r in records):
        raise ValueError('live audit lacks the loopback marker or retained the BPF negative control')
    return len(positive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--live-audit', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = dict(schema='netcap-windows-npcap/v1', host=platform.platform(), state='blocked',
                  sourceRevision=args.source_revision, liveCapture='not-executed')
    code = 3
    try:
        if sys.platform != 'win32':
            raise RuntimeError('native Windows host required; cross-compilation is not Npcap qualification')
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError('run this gate from an elevated Windows console')
        dll = Path(os.environ['SystemRoot']) / 'System32/Npcap/wpcap.dll'
        if not dll.is_file():
            raise RuntimeError('Npcap wpcap.dll is absent; install the licensed driver manually')
        service = subprocess.run(['sc.exe', 'query', 'npcap'], capture_output=True, text=True)
        (args.output / 'npcap-service.log').write_text(service.stdout + service.stderr)
        if service.returncode or 'RUNNING' not in service.stdout:
            raise RuntimeError('Npcap driver service is not running')
        report['npcapDLLSHA256'] = hashlib.sha256(dll.read_bytes()).hexdigest()
        binary = args.binary.resolve(strict=True)
        report['binarySHA256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        enumeration = subprocess.run([str(binary), 'util', '-interfaces'], capture_output=True, text=True)
        (args.output / 'interfaces.log').write_text(enumeration.stdout + enumeration.stderr)
        if enumeration.returncode or 'NPF_Loopback' not in enumeration.stdout + enumeration.stderr:
            raise RuntimeError('Npcap loopback interface enumeration failed')
        subprocess.run([sys.executable, str(Path(__file__).with_name('qualify-packaged-client.py')), str(binary),
                        '--output', str(args.output / 'offline'), '--source-revision', args.source_revision,
                        '--require-bpf'], check=True)
        report['offlineCaptureAndBPF'] = 'passed'
        if args.live_audit is None:
            raise RuntimeError('manual loopback capture required; pass --live-audit after the documented marker/BPF control')
        report['livePositivePackets'] = live_records(args.live_audit)
        report['liveAuditHashes'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.live_audit.glob('*UDP*')}
        report.update(state='passed', liveCapture='passed')
        code = 0
    except Exception as error:
        report['blocker'] = str(error)
    (args.output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(args.output / 'qualification.json')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
