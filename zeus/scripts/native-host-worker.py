#!/usr/bin/env python3
"""Run only in the disposable directory prepared by qualify-native-host.py."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile


def main():
    root = Path(__file__).resolve().parent
    if (root / '.owner').read_text() != 'netcap-native-qualification/v1':
        raise ValueError('unowned native qualification directory')
    candidate = json.loads((root / 'candidate.json').read_text())
    output = root / 'qualifications'
    output.mkdir()
    report = dict(schema='netcap-native-host/v1', sourceRevision=candidate['sourceRevision'], cpuLimit=2,
                  machine=platform.machine(), system=platform.system(), state='started', variants=[])
    try:
        if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
            raise ValueError('native Linux x86_64 host required')
        for item in candidate['images']:
            metadata = json.loads(subprocess.check_output(['docker', 'image', 'inspect', item['image']], text=True))[0]
            if (metadata['Os'], metadata['Architecture']) != ('linux', 'amd64'):
                raise ValueError('image architecture mismatch')
            if metadata['Config'] != item['config'] or metadata['RootFS'] != item['rootFS']:
                raise ValueError('transferred image config or filesystem layers changed')
            archive = root / item['archive']
            if archive.parent != root or hashlib.sha256(archive.read_bytes()).hexdigest() != item['archiveSHA256']:
                raise ValueError('candidate archive digest/path mismatch')
            runtime = root / ('runtime-' + item['variant'])
            runtime.mkdir()
            with tarfile.open(archive) as tar:
                tar.extractall(runtime, filter='data')
            env = dict(os.environ, NETCAP_QUAL_ROOT=str(root), NETCAP_QUAL_RUNTIME=str(runtime), NETCAP_QUAL_IMAGE=item['image'])
            subprocess.run(['python3', str(root / 'qualify-packaged-client.py'), str(root / 'run-candidate-runtime.py'),
                            '--output', str(output / item['variant']), '--source-revision', candidate['sourceRevision'],
                            '--require-bpf', '--require-yara'], env=env, check=True)
            report['variants'].append(dict(variant=item['variant'], image=item['image'], archiveSHA256=item['archiveSHA256'], state='passed'))
        report['state'] = 'passed'
    except Exception as error:
        report.update(state='failed', error=str(error))
        raise
    finally:
        (root / 'native-host.json').write_text(json.dumps(report, indent=2) + '\n')
        for cidfile in root.glob('container-*.cid'):
            cid = cidfile.read_text().strip()
            if not re.fullmatch('[0-9a-f]{64}', cid):
                continue
            inspected = subprocess.run(['docker', 'inspect', '--format', '{{index .Config.Labels "netcap.qualification.owner"}}', cid], capture_output=True, text=True)
            if inspected.returncode == 0 and inspected.stdout.strip() == root.name:
                subprocess.run(['docker', 'rm', '-f', cid], check=True)


if __name__ == '__main__':
    main()
