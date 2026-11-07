#!/usr/bin/env python3
"""Owned local soak launcher. Resume observes a checkpoint; it never invents elapsed time."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import secrets
import signal
import subprocess
import sys
import time

from pilot import evidence_directory

OWNER = 'netcap-topic-qualification/v2'
ROOT = pathlib.Path(__file__).resolve().parents[3]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write(path, data):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, indent=2) + '\n')
    temporary.replace(path)


def identity(pid):
    result = subprocess.run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'lstart=', '-o', 'command='],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def owned(manifest):
    pid = manifest.get('supervisor_pid')
    token = manifest.get('token')
    if not isinstance(token, str) or len(token) != 32 or any(c not in '0123456789abcdef' for c in token):
        return False
    actual = identity(pid) if type(pid) is int and pid > 1 else None
    return (manifest.get('owner') == OWNER and actual is not None
            and actual == manifest.get('supervisor_identity')
            and token in actual)


def inspect(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest.get('owner') != OWNER:
        raise ValueError('unrecognized run ownership; refusing adoption')
    result = dict(manifest, supervisor_owned_live=owned(manifest))
    progress = directory / 'http' / 'progress.json'
    if progress.exists():
        from evidence import summarize
        try:
            result['http'] = summarize(progress.parent)
        except (OSError, ValueError, TypeError, KeyError) as error:
            result['report_error'] = str(error)
    return result


def wait(directory, timeout):
    if not 1 <= timeout <= 604980:
        raise ValueError('wait timeout must be 1..604980 seconds')
    deadline = time.monotonic() + timeout
    while True:
        result = inspect(directory)
        if result['state'] in ('pass', 'fail', 'stopped'):
            return result
        if not result['supervisor_owned_live']:
            raise ValueError('supervisor ownership lost; checkpoint preserved, no restart')
        if time.monotonic() >= deadline:
            raise TimeoutError('wait expired; owned background run remains untouched')
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def worker(directory, token):
    path = directory / 'manifest.json'
    manifest = json.loads(path.read_text())
    if manifest['owner'] != OWNER or manifest['token'] != token or manifest['state'] != 'allocated':
        raise ValueError('manifest ownership/state mismatch')
    manifest.update(supervisor_pid=os.getpid(), supervisor_identity=identity(os.getpid()), state='running')
    write(path, manifest)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    command = [manifest['binary'], '-duration', f"{manifest['duration_seconds']}s",
               '-rate', str(manifest['rate']), '-workers', str(manifest.get('workers', 32)),
               '-fault-every', '10s', '-output', str(directory / 'http')]
    if manifest.get('mixed'):
        command.append('-mixed')
    started = time.monotonic()
    with (directory / 'http.log').open('xb') as log:
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        child_identity = identity(process.pid)
        manifest.update(child_pid=process.pid, child_identity=child_identity, command=command)
        write(path, manifest)
        deadline = started + manifest['duration_seconds'] + 180
        while process.poll() is None:
            if stopping or time.monotonic() > deadline:
                if identity(process.pid) != child_identity:
                    raise RuntimeError('child ownership changed; refusing signal')
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    if identity(process.pid) != child_identity:
                        raise RuntimeError('child ownership changed; refusing kill')
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
                break
            manifest.update(checkpoint_unix=time.time(), supervisor_elapsed_seconds=time.monotonic() - started)
            write(path, manifest)
            time.sleep(1)
    manifest.update(state='stopped' if stopping else ('pass' if process.returncode == 0 else 'fail'),
                    child_exit_code=process.returncode, elapsed_seconds=time.monotonic() - started,
                    finished_unix=time.time(), qualification='incomplete; see corpus and protocol receipts')
    manifest['receipt_sha256'] = {str(p.relative_to(directory)): digest(p)
                                  for p in directory.rglob('*') if p.is_file() and p != path}
    write(path, manifest)


def start(directory, binary, duration, rate, mixed=True, workers=128):
    if not 1 <= duration <= 604800 or not 1 <= rate <= 1000 or not 1 <= workers <= 128:
        raise ValueError('duration 1..604800 seconds; rate 1..1000; workers 1..128')
    directory = evidence_directory(directory)
    if any(directory.iterdir()):
        raise ValueError('fresh empty evidence directory required')
    binary = binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError('executable runner binary required')
    changed = subprocess.check_output(['git', 'diff', '--name-only', '--diff-filter=ACMRT', '-z'], cwd=ROOT).decode().split('\0')
    files = {*pathlib.Path(__file__).parent.glob('*.go'), *pathlib.Path(__file__).parent.glob('*.py'), ROOT / 'go.mod', ROOT / 'go.sum', *(ROOT / p for p in changed if p)}
    hardware = {}
    if platform.system() == 'Darwin':
        for key in ('hw.model', 'hw.memsize', 'machdep.cpu.brand_string'):
            result = subprocess.run(['/usr/sbin/sysctl', '-n', key], capture_output=True, text=True, check=False)
            hardware[key] = result.stdout.strip() if result.returncode == 0 else 'unavailable'
    manifest = {'owner': OWNER, 'token': secrets.token_hex(16), 'state': 'allocated',
                'created_unix': time.time(), 'binary': str(binary), 'binary_sha256': digest(binary),
                'duration_seconds': duration, 'rate': rate, 'platform': platform.system(),
                'workers': workers,
                'mixed': mixed,
                'machine': platform.machine(), 'cpu_count': os.cpu_count(), 'python': platform.python_version(),
                'hardware': hardware,
                'source_sha256': {str(p.relative_to(ROOT)): digest(p) for p in files},
                'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'go_build': subprocess.check_output(['go', 'version', '-m', str(binary)], cwd=ROOT, text=True),
                'coverage': 'HTTP/1.1,H2,H3' + (' and owned scripted WS,gRPC,DNS,Redis,Postgres,MySQL,Modbus,DNP3,SMTP wire profiles' if mixed else ''),
                'resume': 'monitor validates PID birth/command/token; interrupted duration is never credited',
                'fail_budget': 'zero forbidden origin bytes/requests, drops, errors, false blocks; p99 <=2s; heap <=1GiB'}
    (directory / 'http').mkdir(mode=0o700)
    write(directory / 'manifest.json', manifest)
    with (directory / 'supervisor.log').open('xb') as log:
        child = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).resolve()), '_worker',
                                  str(directory), '--token', manifest['token']],
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(100):
        result = json.loads((directory / 'manifest.json').read_text())
        if result['state'] != 'allocated':
            return result
        if child.poll() is not None:
            raise RuntimeError('supervisor failed; inspect supervisor.log')
        time.sleep(.05)
    raise RuntimeError('supervisor startup timeout; inspect manifest before retrying')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'monitor', 'resume', 'stop', 'wait', '_worker'])
    parser.add_argument('directory', type=pathlib.Path)
    parser.add_argument('--binary', type=pathlib.Path)
    parser.add_argument('--duration', type=int, default=86400)
    parser.add_argument('--rate', type=int, default=50)
    parser.add_argument('--workers', type=int, default=128)
    parser.add_argument('--token')
    parser.add_argument('--http-only', action='store_true')
    parser.add_argument('--wait-timeout', type=int, default=2100)
    args = parser.parse_args()
    directory = evidence_directory(args.directory)
    if args.action == '_worker':
        worker(directory, args.token)
        return
    if args.action == 'start':
        if args.binary is None:
            parser.error('--binary is required')
        result = start(directory, args.binary, args.duration, args.rate, not args.http_only, args.workers)
    elif args.action == 'wait':
        result = wait(directory, args.wait_timeout)
    else:
        result = inspect(directory)
        if args.action == 'stop':
            if not result['supervisor_owned_live']:
                raise ValueError('no verified owned supervisor; refusing signal')
            os.kill(result['supervisor_pid'], signal.SIGTERM)
            result['stop_requested'] = True
    print(json.dumps({k: v for k, v in result.items() if k not in ('source_sha256', 'go_build')}, indent=2))
    if args.action == 'wait' and result['state'] != 'pass':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
