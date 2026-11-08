#!/usr/bin/env python3
"""Validate, Developer-ID sign and optionally notarize a local CLI candidate."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tarfile


def run(args, **kwargs):
    return subprocess.check_output([str(a) for a in args], text=True, stderr=subprocess.STDOUT, **kwargs)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def version(text):
    return tuple((list(map(int, text.split('.'))) + [0, 0])[:3])


def inspect(bundle, minimum, arch='arm64', team=None):
    bundle = Path(bundle).resolve()
    binary = bundle / 'net'
    libraries = sorted((bundle / 'lib').iterdir()) if (bundle / 'lib').is_dir() else []
    paths = [binary, *libraries]
    records = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError('runtime members must be regular files: ' + str(path))
        if run(['lipo', '-archs', path]).strip() != arch:
            raise ValueError('unexpected Mach-O architecture: ' + str(path))
        match = re.search(r'\bminos\s+(\d+(?:\.\d+)+)', run(['vtool', '-show-build', path]))
        if not match:
            raise ValueError('missing deployment target: ' + str(path))
        actual = match[1]
        if version(actual) > version(minimum) or (path == binary and version(actual) != version(minimum)):
            raise ValueError('Mach-O minimum OS conflicts with artifact target: ' + str(path))
        dependencies = []
        for line in run(['otool', '-L', path]).splitlines()[1:]:
            dependency = line.strip().split(' (', 1)[0]
            if not dependency:
                continue
            dependencies.append(dependency)
            if dependency.startswith(('/usr/lib/', '/System/Library/')):
                continue
            prefix = '@executable_path/lib/' if path == binary else '@loader_path/'
            if not dependency.startswith(prefix):
                raise ValueError('unrelocated native dependency: ' + dependency)
            name = dependency.removeprefix(prefix)
            if name != Path(name).name or not name or not (bundle / 'lib' / name).is_file():
                raise ValueError('missing or escaping native dependency: ' + dependency)
        if team:
            run(['codesign', '--verify', '--strict', path])
            signature = run(['codesign', '-d', '--verbose=4', path])
            if 'TeamIdentifier=' + team + '\n' not in signature:
                raise ValueError('unexpected signing team: ' + str(path))
            if 'Timestamp=' not in signature:
                raise ValueError('missing secure signing timestamp: ' + str(path))
            if path == binary and 'runtime' not in signature:
                raise ValueError('executable lacks hardened runtime')
        records.append(dict(file=str(path.relative_to(bundle)), sha256=sha(path), minimumOS=actual, dependencies=dependencies))
    inventory = bundle / 'native-runtime-inventory.json'
    if not inventory.is_file():
        raise ValueError('native runtime inventory is required')
    if inventory.exists():
        inventory = json.loads(inventory.read_text())
        if version(inventory['minimumOS']) != version(minimum):
            raise ValueError('inventory minimum OS conflicts with artifact target')
        expected = {r['file']: r['sha256'] for r in inventory['files']}
        actual = {r['file']: r['sha256'] for r in records if r['file'] != 'net'}
        if expected != actual:
            raise ValueError('native runtime inventory does not match packaged library bytes')
    return records


def notary(arguments, team, profile=None):
    auth = ['--keychain-profile', profile] if profile else ['--apple-id', os.environ['AC_USERNAME'], '--team-id', team]
    password = None if profile else os.environ['AC_PASSWORD'] + '\n'
    result = subprocess.run(['xcrun', 'notarytool', *arguments, *auth], input=password,
                            text=True, capture_output=True, timeout=1500)
    text = result.stdout
    # With stdin authentication, a password prompt can precede JSON on stdout.
    for index, char in enumerate(text):
        if char == '{':
            try:
                value, _ = json.JSONDecoder().raw_decode(text[index:])
                return value, result.returncode
            except json.JSONDecodeError:
                pass
    raise RuntimeError('notarytool returned no JSON (exit ' + str(result.returncode) + '); credentials/output were not logged')


def sign(args):
    if not re.fullmatch('[0-9a-f]{40}', args.source_revision):
        raise ValueError('--source-revision must be a full commit hash')
    archive = args.archive.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    bundle = args.output / 'bundle'
    bundle.mkdir()
    receipt = dict(schema='netcap-macos-signing/v1', inputSHA256=sha(archive), minimumOS=args.min_os,
                   architecture=args.arch, team=args.team_id, state='started', sourceRevision=args.source_revision)
    receipt_path = args.output / 'signing-receipt.json'
    try:
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if not (member.isfile() or member.isdir()):
                    raise ValueError('candidate archive contains a non-regular member')
            tar.extractall(bundle, filter='data')
        receipt['before'] = inspect(bundle, args.min_os, args.arch)
        entitlements = args.output / 'cli-entitlements.plist'
        # Wasmtime's generated executable pages need more than allow-jit alone.
        entitlements.write_bytes(plistlib.dumps({'com.apple.security.cs.allow-jit': True,
                                               'com.apple.security.cs.allow-unsigned-executable-memory': True}))
        for library in sorted((bundle / 'lib').iterdir()):
            run(['codesign', '--force', '--sign', args.identity, '--timestamp', library])
        run(['codesign', '--force', '--sign', args.identity, '--timestamp', '--options', 'runtime',
             '--entitlements', entitlements, bundle / 'net'])
        inventory_path = bundle / 'native-runtime-inventory.json'
        if inventory_path.exists():
            inventory = json.loads(inventory_path.read_text())
            for member in inventory['files']:
                member['sha256'] = sha(bundle / member['file'])
            inventory_path.write_text(json.dumps(inventory, indent=2) + '\n')
        receipt['signed'] = inspect(bundle, args.min_os, args.arch, args.team_id)
        # This launches the signed executable, not an unsigned pre-signing copy.
        receipt['versionOutput'] = run([bundle / 'net', '--version'], env={
            k: v for k, v in os.environ.items() if not k.startswith(('DYLD_', 'PKG_CONFIG'))
        })
        if '> NETCAP build commit: ' + args.source_revision + '\n' not in receipt['versionOutput']:
            raise ValueError('artifact does not report the expected source revision')
        smoke = Path(__file__).with_name('qualify-packaged-client.py')
        run(['python3', smoke, bundle / 'net', '--output', args.output / 'signed-smoke',
             '--source-revision', args.source_revision, '--require-bpf', '--require-yara'])
        receipt['signedRuntimeQualification'] = json.loads((args.output / 'signed-smoke/qualification.json').read_text())
        zip_path = args.output / 'signed-candidate.zip'
        run(['ditto', '-c', '-k', '--sequesterRsrc', bundle, zip_path])
        receipt.update(state='signed', archive=str(zip_path), archiveSHA256=sha(zip_path))
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
        if args.notarize:
            submission, code = notary(['submit', str(zip_path), '--wait', '--timeout', '20m', '--output-format', 'json'], args.team_id, args.keychain_profile)
            receipt['submission'] = submission
            receipt['state'] = 'notarization-' + submission.get('status', 'unknown').lower().replace(' ', '-')
            receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
            if submission.get('id') and submission.get('status') in ('Accepted', 'Invalid', 'Rejected'):
                log, _ = notary(['log', submission['id']], args.team_id, args.keychain_profile)
                (args.output / 'notarization-log.json').write_text(json.dumps(log, indent=2) + '\n')
            if code or submission.get('status') != 'Accepted':
                raise RuntimeError('candidate notarization did not reach Accepted; inspect receipt and notarization log')
            receipt['afterNotarization'] = inspect(bundle, args.min_os, args.arch, args.team_id)
            receipt['stapling'] = 'CLI ZIP/Mach-O does not support stapler; retain Accepted submission and per-Mach-O ticket log. Gatekeeper lookup requires network.'
    except Exception as error:
        receipt['error'] = str(error)
        raise
    finally:
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(receipt_path)


def build(args):
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('native_candidate', Path(__file__).with_name('native-candidate.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.check_source(args.revision)
    minimum = '15.0' if args.variant == 'nodpi' else '26.0'
    env = dict(os.environ, GOWORK='off', GOMAXPROCS='2', GOFLAGS='-mod=readonly -p=2', RAYON_NUM_THREADS='2',
               MACOSX_DEPLOYMENT_TARGET=minimum, YARA_X_PREFIX=str(args.yara_prefix.resolve(strict=True)))
    if run(['uname', '-s']).strip() != 'Darwin' or run(['uname', '-m']).strip() != 'arm64':
        raise ValueError('native macOS arm64 build host required')
    frontend = root / 'cmd/capture/webui/frontend/dist'
    if not (frontend / 'index.html').is_file() or '/assets/' not in (frontend / 'index.html').read_text():
        raise ValueError('build the approved revision frontend before packaging')
    args.output.mkdir(parents=True, exist_ok=False)
    bundle = args.output / 'bundle'
    bundle.mkdir()
    fork = run(['go', 'list', '-m', '-f', '{{.Version}}{{with .Replace}}+{{.Version}}{{end}}', 'github.com/gopacket/gopacket'], cwd=root, env=env).strip()
    flags = '-X github.com/dreadl0ck/netcap.Version=native-' + args.revision[:12]
    flags += ' -X github.com/dreadl0ck/netcap.Commit=' + args.revision + ' -X github.com/dreadl0ck/netcap.GopacketVersion=' + fork
    if args.variant == 'dpi':
        for package, field in [('libndpi', 'NDPIVersion'), ('libprotoident', 'LibprotoidentVersion')]:
            try:
                native_version = run(['pkg-config', '--modversion', package], env=env).strip()
            except subprocess.CalledProcessError:
                if package != 'libprotoident':
                    raise
                # The installed libprotoident formula supplies no pkg-config file.
                installed = run(['brew', 'list', '--versions', 'libprotoident'], env=env).split()
                if len(installed) != 2 or installed[0] != 'libprotoident':
                    raise ValueError('one installed libprotoident version is required')
                native_version = installed[1]
            flags += ' -X github.com/dreadl0ck/netcap/internal/dpi.' + field + '=' + native_version
        flags += ' -X github.com/dreadl0ck/netcap/internal/dpi.GoDPIVersion=' + run(['go', 'list', '-m', '-f', '{{.Version}}', 'github.com/dreadl0ck/go-dpi'], cwd=root, env=env).strip()
    command = ['sh', 'scripts/with-yara-x.sh', 'env', 'GOMAXPROCS=2', 'GOFLAGS=-mod=readonly -p=2', 'go', 'build', '-trimpath', '-ldflags', flags, '-o', str(bundle / 'net')]
    if args.variant == 'nodpi':
        command += ['-tags=nodpi']
    command += ['./cmd/net']
    with (args.output / 'build.log').open('w') as log:
        subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    run(['python3', 'zeus/scripts/bundle-macos-runtime.py', bundle / 'net', '--variant', args.variant], cwd=root, env=env)
    shutil.copyfile(root / 'LICENSE', bundle / 'LICENSE')
    shutil.copytree(root / 'legal', bundle / 'legal')
    shutil.copyfile(root / 'dist-macos-runtime' / args.variant / 'inventory.json', bundle / 'native-runtime-inventory.json')
    shutil.copyfile(root / 'dist-macos-runtime' / args.variant / 'NOTICES.txt', bundle / 'legal/native-runtime-notices.txt')
    records = inspect(bundle, minimum)
    run(['python3', Path(__file__).with_name('qualify-packaged-client.py'), bundle / 'net', '--output', args.output / 'smoke',
         '--source-revision', args.revision, '--require-bpf', '--require-yara'])
    archive = args.output / 'candidate.tar.gz'
    with archive.open('wb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', mtime=0, filename='') as gz, tarfile.open(fileobj=gz, mode='w') as tar:
        for path in sorted(bundle.rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            data = path.read_bytes()
            member = tarfile.TarInfo(str(path.relative_to(bundle)))
            member.size, member.mode, member.mtime = len(data), (0o755 if path.name == 'net' else 0o644), 0
            tar.addfile(member, io.BytesIO(data))
    receipt = dict(schema='netcap-macos-build/v1', sourceRevision=args.revision, minimumOS=minimum, cpuLimit=2,
                   variant=args.variant, state='built-and-local-smoke-passed', archiveSHA256=sha(archive), members=records,
                   frontendSHA256={str(p.relative_to(frontend)): sha(p) for p in sorted(frontend.rglob('*')) if p.is_file()})
    (args.output / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    building = commands.add_parser('build')
    building.add_argument('--revision', required=True)
    building.add_argument('--variant', choices=('dpi', 'nodpi'), required=True)
    building.add_argument('--yara-prefix', type=Path, required=True)
    building.add_argument('--output', type=lambda p: Path(p).resolve(), required=True)
    validate = commands.add_parser('validate')
    validate.add_argument('bundle', type=Path)
    signing = commands.add_parser('sign')
    signing.add_argument('archive', type=Path)
    signing.add_argument('--output', type=lambda p: Path(p).resolve(), required=True)
    signing.add_argument('--identity', required=True)
    signing.add_argument('--source-revision', required=True)
    signing.add_argument('--notarize', action='store_true')
    signing.add_argument('--keychain-profile', default=os.environ.get('NOTARY_KEYCHAIN_PROFILE'))
    for command in (validate, signing):
        command.add_argument('--min-os', choices=('15.0', '26.0'), required=True)
        command.add_argument('--arch', choices=('arm64',), default='arm64')
        command.add_argument('--team-id', required=command is signing)
    args = parser.parse_args()
    if args.command == 'validate':
        print(json.dumps(inspect(args.bundle, args.min_os, args.arch, args.team_id), indent=2))
    elif args.command == 'sign':
        sign(args)
    else:
        build(args)


if __name__ == '__main__':
    main()
