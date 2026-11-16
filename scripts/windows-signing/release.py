#!/usr/bin/env python3
"""Finalize or verify a product's Windows packages from a checked portable ZIP."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile
from windows_sign import SERIAL, TOOL_SHA256, sha, sign, verify


def extract(archive, destination, prefix, patterns):
    seen = set()
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            path = Path(entry.filename)
            if (path.is_absolute() or '..' in path.parts or ':' in entry.filename or '\\' in entry.filename
                    or not path.parts or path.parts[0] != prefix or entry.filename.lower() in seen
                    or ((entry.external_attr >> 16) & 0o170000) == 0o120000):
                raise ValueError('unsafe ZIP entry: ' + entry.filename)
            seen.add(entry.filename.lower())
        bundle.extractall(destination)
    payload = destination / prefix
    binaries = {p for p in payload.rglob('*') if p.is_file() and p.suffix.lower() in ('.exe', '.dll')}
    allowed = set()
    for pattern in patterns:
        matches = {p for p in payload.glob(pattern) if p.is_file()}
        if not matches:
            raise ValueError('missing signing payload: ' + pattern)
        allowed.update(matches)
    if binaries != allowed:
        raise ValueError('unreviewed executable/DLL inventory')
    return payload, sorted(binaries)


def finalize(root, config, candidate, output, version, source, bootstrapper=None):
    setup_name = config['setup'].format(version=version)
    zip_name = config['portable'].format(version=version)
    prefix = config['prefix'].format(version=version)
    inputs = {p.name: sha(p) for p in (candidate / setup_name, candidate / zip_name)}
    sums = config.get('checksums')
    manifests = config.get('candidateManifests', [])
    if manifests:
        expected = {}
        for name in manifests:
            record = json.loads((candidate / name.format(version=version)).read_text())
            if record['version'] != version or record['source_sha'] != source:
                raise ValueError('candidate manifest source identity mismatch')
            expected[record['artifact']] = record['sha256']
        if expected != inputs:
            raise ValueError('candidate manifest checksum mismatch')
    elif sums:
        expected = {}
        for name in sums:
            for line in (candidate / name.format(version=version)).read_text().splitlines():
                digest, filename = line.split(None, 1)
                expected[filename.strip().lstrip('*')] = digest.lower()
        if any(expected.get(name) != digest for name, digest in inputs.items()):
            raise ValueError('candidate checksum mismatch')
    if not sums:
        raise ValueError('candidate checksum provenance is required')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='estate-windows-') as scratch:
        work = Path(scratch)
        portable = output / zip_name
        state_path = output / 'windows-payload.json'
        if portable.exists():
            state = json.loads(state_path.read_text())
            if (state['version'], state['sourceRevision'], state['inputs'], state['portableSHA256']) != (version, source, inputs, sha(portable)):
                raise ValueError('cached payload identity mismatch')
            payload, binaries = extract(portable, work, prefix, config['binaries'])
            before = state['unsigned']
            for path in binaries:
                verify(path)
        else:
            payload, binaries = extract(candidate / zip_name, work, prefix, config['binaries'])
            before = {p.relative_to(payload).as_posix(): sha(p) for p in binaries}
            if config.get('nativeReceipt'):
                native = json.loads((payload / config['nativeReceipt']).read_text())
                if any(before.get(name) != digest for name, digest in native['libraries'].items()):
                    raise ValueError('native runtime source receipt differs from candidate libraries')
            sign(binaries)
            after = {p.relative_to(payload).as_posix(): sha(p) for p in binaries}
            (payload / 'windows-signing.json').write_text(json.dumps({
                'schema': 1, 'certificateSerial': SERIAL, 'sourceRevision': source,
                'payload': {name: {'unsignedSHA256': digest, 'signedSHA256': after[name]} for name, digest in before.items()},
            }, indent=2) + '\n')
            with zipfile.ZipFile(portable, 'w', zipfile.ZIP_DEFLATED) as bundle:
                for path in sorted(payload.rglob('*')):
                    if path.is_file():
                        bundle.write(path, path.relative_to(payload.parent).as_posix())
            state_path.write_text(json.dumps(dict(version=version, sourceRevision=source, inputs=inputs,
                                                 portableSHA256=sha(portable), unsigned=before), indent=2) + '\n')
        packaging = work / 'packaging'
        for name in config['resources']:
            destination = packaging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, destination)
        script = packaging / config['nsis']
        if config.get('bootstrapper'):
            shutil.copyfile(bootstrapper or root / config['bootstrapper'], packaging / config['bootstrapper'])
        setup = output / setup_name
        uninstaller = work / 'uninstall.exe'
        values = dict(payload=str(payload), version=version, setup=str(setup), python=sys.executable,
                      signer=str(Path(__file__).with_name('windows_sign.py')))
        flags = {key: value.format(**values) for key, value in config['defines'].items()}
        flags.update(SIGN_PYTHON=sys.executable, SIGN_SCRIPT=values['signer'])
        env = dict(os.environ, WINDOWS_UNINSTALLER_COPY=str(uninstaller))
        subprocess.run(['makensis', '-V2', *[f'-D{k}={v}' for k, v in flags.items()], script.name],
                       cwd=script.parent, env=env, check=True, timeout=600)
        verify(uninstaller)
        sign([setup])
        receipt = dict(schema=1, version=version, sourceRevision=source, certificateSerial=SERIAL,
                       toolSHA256=TOOL_SHA256, inputs=inputs, uninstallerSHA256=sha(uninstaller),
                       payload={p.relative_to(payload).as_posix(): {'unsignedSHA256': before[p.relative_to(payload).as_posix()],
                                'signedSHA256': sha(p)} for p in binaries},
                       artifacts={p.name: sha(p) for p in (setup, portable)})
        (output / 'windows-signing.json').write_text(json.dumps(receipt, indent=2) + '\n')
        for name in manifests:
            record = json.loads((candidate / name.format(version=version)).read_text())
            record['unsigned_sha256'] = record['sha256']
            record['sha256'] = receipt['artifacts'][record['artifact']]
            record['signing'] = 'authenticode-timestamped'
            (output / name.format(version=version)).write_text(json.dumps(record, indent=2) + '\n')
        for name in config['checksums']:
            path = output / name.format(version=version)
            entries = [p for p in (setup, portable) if len(config['checksums']) == 1 or path.name == p.name + '.sha256']
            path.write_text(''.join(f'{sha(p)}  {p.name}\n' for p in entries))


def check(directory, config, version, source, installed=None):
    record = json.loads((directory / 'windows-signing.json').read_text())
    if (record['schema'], record['version'], record['sourceRevision'], record['certificateSerial']) != (1, version, source, SERIAL):
        raise ValueError('signed release identity mismatch')
    for name in ('setup', 'portable'):
        artifact = directory / config[name].format(version=version)
        if record['artifacts'].get(artifact.name) != sha(artifact):
            raise ValueError('signed package hash mismatch')
    verify(directory / config['setup'].format(version=version))
    with tempfile.TemporaryDirectory() as work:
        payload, binaries = extract(directory / config['portable'].format(version=version), Path(work),
                                    config['prefix'].format(version=version), config['binaries'])
        if set(record['payload']) != {p.relative_to(payload).as_posix() for p in binaries}:
            raise ValueError('signed inventory mismatch')
        for path in binaries:
            if record['payload'][path.relative_to(payload).as_posix()]['signedSHA256'] != sha(path):
                raise ValueError('signed executable hash mismatch')
            verify(path)
        if config.get('nativeReceipt'):
            native = json.loads((payload / config['nativeReceipt']).read_text())
            if any(record['payload'].get(name, {}).get('unsignedSHA256') != digest for name, digest in native['libraries'].items()):
                raise ValueError('native runtime source receipt lost its original library binding')
        if installed:
            for path in payload.rglob('*'):
                relative = path.relative_to(payload).as_posix()
                destination = config.get('installedPaths', {}).get(relative, relative)
                if path.is_file() and sha(installed / destination) != sha(path):
                    raise ValueError('installed payload differs: ' + path.name)
            verify(installed / config.get('uninstaller', 'uninstall.exe'))
            if sha(installed / config.get('uninstaller', 'uninstall.exe')) != record['uninstallerSHA256']:
                raise ValueError('installed uninstaller differs')
    print('Verified complete signed Windows packages: ' + version)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('finalize', 'verify'))
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--bootstrapper', type=Path)
    parser.add_argument('--installed', type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    root = args.config.resolve().parent.parent
    if args.command == 'finalize':
        finalize(root, config, args.candidate.resolve(), args.out.resolve(), args.version, args.source, args.bootstrapper)
    else:
        check(args.out.resolve(), config, args.version, args.source, args.installed)
