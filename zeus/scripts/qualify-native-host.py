#!/usr/bin/env python3
"""Transfer new candidates to an existing x86 Docker host and retain receipts."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=lambda p: Path(p).resolve())
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=lambda p: Path(p).resolve(), required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+', args.host):
        raise ValueError('--host must be an SSH hostname or user@hostname')
    candidate = json.loads(args.manifest.read_text())
    if candidate.get('state') != 'built-not-native-qualified' or candidate.get('platform') != 'linux/amd64':
        raise ValueError('manifest does not describe newly built linux/amd64 candidates')
    images = [item['image'] for item in candidate['images']]
    if not images or any(not re.fullmatch(r'netcap-native-candidate:[a-z0-9-]+', name) for name in images):
        raise ValueError('only isolated candidate image names may be transferred')
    archives = [args.manifest.parent / item['archive'] for item in candidate['images']]
    if any(path.parent != args.manifest.parent or not path.is_file() for path in archives):
        raise ValueError('candidate archive missing or outside manifest directory')
    args.output.mkdir(parents=True, exist_ok=False)
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.host]
    remote = subprocess.check_output([*ssh, 'mktemp -d /tmp/netcap-final-native.XXXXXXXX'], text=True).strip()
    if not re.fullmatch(r'/tmp/netcap-final-native\.[A-Za-z0-9]+', remote):
        raise ValueError('unexpected remote temporary directory')
    scripts = Path(__file__).resolve().parent
    inputs = [args.manifest, *archives, *(scripts / name for name in ('native-host-worker.py', 'run-candidate-runtime.py', 'qualify-packaged-client.py'))]
    try:
        subprocess.run([*ssh, 'printf %s netcap-native-qualification/v1 > ' + shlex.quote(remote + '/.owner')], check=True)
        subprocess.run(['scp', '-q', *map(str, inputs), args.host + ':' + remote + '/'], check=True)
        # The worker uses a stable filename independently of the caller's manifest name.
        if args.manifest.name != 'candidate.json':
            raise ValueError('candidate manifest must be named candidate.json')
        with (args.output / 'transfer.log').open('wb') as log:
            export = subprocess.Popen(['docker', 'save', *images], stdout=subprocess.PIPE, stderr=log)
            try:
                loaded = subprocess.run([*ssh, 'docker load'], stdin=export.stdout, stdout=log, stderr=log)
            finally:
                export.stdout.close()
                saved = export.wait()
            if saved or loaded.returncode:
                raise RuntimeError('image transfer failed; inspect transfer.log')
        subprocess.run([*ssh, 'chmod 700 ' + shlex.quote(remote + '/run-candidate-runtime.py')], check=True)
        with (args.output / 'native-host.log').open('wb') as log:
            result = subprocess.run([*ssh, 'python3 ' + shlex.quote(remote + '/native-host-worker.py')], stdout=log, stderr=log)
        with (args.output / 'native-host-evidence.tar.gz').open('wb') as archive:
            subprocess.run([*ssh, 'tar -czf - -C ' + shlex.quote(remote) + ' native-host.json qualifications'], stdout=archive, check=True)
        if result.returncode:
            raise RuntimeError('native qualification failed; retained native-host log/archive contain the failure')
        print(args.output / 'native-host-evidence.tar.gz')
    finally:
        # Remove only this invocation's owned scratch directory, never Docker caches/images.
        subprocess.run([*ssh, 'test "$(cat ' + shlex.quote(remote + '/.owner') + ')" = netcap-native-qualification/v1 && rm -rf -- ' + shlex.quote(remote)], check=True)


if __name__ == '__main__':
    main()
