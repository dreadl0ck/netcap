#!/usr/bin/env python3
"""Allocate bounded retained evidence and summarize qualification JSON."""
import argparse
import json
import os
import pathlib
import shutil
import tempfile
import time

from pilot import evidence_directory

OWNER = 'netcap-topic-qualification/v1'


def prune(root, retention_days=7, max_runs=32):
    root = evidence_directory(root)
    if not 1 <= retention_days <= 30 or not 1 <= max_runs <= 100:
        raise ValueError('retention must be 1..30 days and max_runs 1..100')
    owned = []
    for directory in root.glob('topic-qual-*'):
        if directory.is_symlink() or not directory.is_dir():
            continue
        marker = directory / 'owner.json'
        try:
            metadata = json.loads(marker.read_text())
        except (OSError, ValueError):
            continue
        if metadata.get('owner') != OWNER:
            continue
        progress = directory / 'run' / 'progress.json'
        try:
            state = json.loads(progress.read_text())
            if state.get('load_state') == 'running':
                # A live PID is protected even if a report is temporarily stale.
                try:
                    os.kill(state['pid'], 0)
                    continue
                except ProcessLookupError:
                    pass
                except (PermissionError, KeyError, TypeError):
                    continue
        except (OSError, ValueError):
            pass
        owned.append((directory.stat().st_mtime, directory))
    owned.sort(reverse=True)
    removed = []
    cutoff = time.time() - retention_days * 86400
    for index, (modified, directory) in enumerate(owned):
        if modified < cutoff or index >= max_runs:
            shutil.rmtree(directory)
            removed.append(str(directory))
    return removed


def allocate(root):
    root = evidence_directory(root)
    prune(root, max_runs=31)
    directory = pathlib.Path(tempfile.mkdtemp(prefix='topic-qual-', dir=root))
    (directory / 'owner.json').write_text(json.dumps({'owner': OWNER, 'created': time.time()}))
    # Runners require empty output directories, keeping their own reports separate.
    output = directory / 'run'
    output.mkdir(mode=0o700)
    return output


def summarize(directory):
    report = json.loads((directory / 'progress.json').read_text())
    profiles = report['profiles']
    counts = {key: sum(p['counts'][key] for p in profiles.values())
              for key in ['Offered', 'Allowed', 'Denied', 'Errors', 'Dropped', 'FalseBlocks']}
    return {'load_state': report['load_state'], 'qualification_state': report['qualification_state'],
            'actual_load_seconds': report['actual_load_seconds'], 'profiles': len(profiles),
            'counts': counts, 'max_profile_p95_upper_ms': max(p['p95_upper_ms'] for p in profiles.values()),
            'max_profile_p99_upper_ms': max(p['p99_upper_ms'] for p in profiles.values()),
            'forbidden_origin_bytes': sum(p['forbidden_origin_bytes'] for p in profiles.values()),
            'forbidden_origin_requests': sum(p['forbidden_origin_requests'] for p in profiles.values()),
            'forbidden_side_effects': sum(p.get('forbidden_side_effects', 0) for p in profiles.values()),
            'fault_count': report.get('fault_count', len(report.get('faults') or [])),
            'max_fault_recovery_ms': max((f['recovery_ms'] for f in (report.get('faults') or []) if 'recovery_ms' in f), default=0),
            'failed_faults': [f for f in (report.get('faults') or []) if f.get('result') == 'fail'],
            'first_failures': {name: p['first_failures'] for name, p in profiles.items() if p.get('first_failures')},
            'resources_peak': report['resources_peak'], 'resources_recovery': report.get('resources_recovery'), 'soak_24h_pass': report['soak_24h_pass'],
            'false_positive_error': report['false_positive_error']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['allocate', 'prune', 'summarize'])
    parser.add_argument('directory', type=pathlib.Path)
    args = parser.parse_args()
    if args.action == 'allocate':
        print(allocate(args.directory))
    elif args.action == 'prune':
        print(json.dumps({'removed': prune(args.directory), 'retention_days': 7, 'max_inactive_runs': 32}))
    else:
        print(json.dumps(summarize(args.directory), indent=2))


if __name__ == '__main__':
    main()
