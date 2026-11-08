#!/usr/bin/env python3
"""Build local Linux candidates from an exact clean revision; never publish."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
VARIANTS = {'alpine': 'alpine-nodpi', 'alpine-dpi': 'alpine', 'ubuntu': 'ubuntu-nodpi', 'ubuntu-dpi': 'ubuntu'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_source(revision):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('--revision must be the coordinator-approved full commit hash')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if actual != revision:
        raise ValueError('checkout HEAD differs from requested candidate revision')
    status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).splitlines()
    # Vite clears this tracked bootstrap marker when generating the real bundle.
    dirty = [line for line in status if line != ' D cmd/capture/webui/frontend/dist/MODULE_PLACEHOLDER.txt']
    if dirty:
        raise ValueError('candidate source checkout must be clean')


def plan(revision, platform, variants, builder, nonce, release_version=None):
    if platform != 'linux/amd64':
        raise ValueError('qualified native builders support linux/amd64 only')
    if release_version is not None and not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', release_version):
        raise ValueError('invalid release version')
    spec = importlib.util.spec_from_file_location('builder_image', Path(__file__).with_name('builder-image.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    commands = []
    for variant in variants:
        image = 'netcap-native-candidate:' + revision[:12] + '-' + variant + '-' + nonce
        reference = module.resolve(variant, platform)
        command = ['docker', 'buildx', 'build', '--builder', builder, '--platform', platform,
                   '--build-arg', 'NETCAP_BUILDER_IMAGE=' + reference,
                   '--build-arg', 'NETCAP_BUILD_VERSION=' + (release_version or 'native-' + revision[:12]),
                   '--build-arg', 'NETCAP_BUILD_COMMIT=' + revision,
                   '--build-arg', 'TAGS=' + ('' if variant.endswith('-dpi') else '-tags=nodpi'),
                   '--build-context', 'netcap-webui=./cmd/capture/webui/frontend/dist',
                   '--load', '-t', image, '-f', 'docker/' + VARIANTS[variant] + '/Dockerfile', '.']
        commands.append(dict(variant=variant, image=image, builder=reference, command=command))
    return commands


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--release-version', help='SemVer without v; omit for a native qualification candidate')
    parser.add_argument('--platform', default='linux/amd64')
    parser.add_argument('--variant', choices=('all', *VARIANTS), default='all')
    parser.add_argument('--output', type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    check_source(args.revision)
    nonce = uuid.uuid4().hex[:10]
    builder = 'netcap-candidate-' + nonce
    variants = list(VARIANTS) if args.variant == 'all' else [args.variant]
    commands = plan(args.revision, args.platform, variants, builder, nonce, args.release_version)
    if args.plan:
        print(json.dumps(commands, indent=2))
        return
    frontend = ROOT / 'cmd/capture/webui/frontend/dist'
    if not (frontend / 'index.html').is_file() or '/assets/' not in (frontend / 'index.html').read_text():
        raise ValueError('build the real frontend from the approved revision before packaging')
    args.output.mkdir(parents=True, exist_ok=False)
    report = dict(schema='netcap-linux-candidate/v1', sourceRevision=args.revision, platform=args.platform,
                  releaseVersion=args.release_version,
                  cpuLimit=2, state='building', images=[], frontendSHA256={
                      str(p.relative_to(frontend)): sha(p) for p in sorted(frontend.rglob('*')) if p.is_file()})
    created = False
    def run(command):
        with (args.output / 'build.log').open('a') as log:
            subprocess.run(command, cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
    try:
        run(['docker', 'buildx', 'create', '--name', builder, '--driver', 'docker-container',
             '--driver-opt', 'cpu-period=100000,cpu-quota=200000,memory=4g'])
        created = True
        for item in commands:
            run(item['command'])
            metadata = json.loads(subprocess.check_output(['docker', 'image', 'inspect', item['image']], text=True))[0]
            if (metadata['Os'], metadata['Architecture']) != ('linux', 'amd64'):
                raise ValueError('runtime image has an incompatible architecture')
            stage = args.output / item['variant']
            stage.mkdir()
            run(['python3', 'zeus/scripts/bundle-linux-runtime.py', item['image'], str(stage)])
            shutil.copyfile(ROOT / 'LICENSE', stage / 'LICENSE')
            shutil.copytree(ROOT / 'legal', stage / 'legal')
            archive = args.output / (item['variant'] + '.tar.gz')
            def normalize(member):
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ''
                return member
            with archive.open('wb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', mtime=0, filename='') as gz, tarfile.open(fileobj=gz, mode='w') as tar:
                tar.add(stage, arcname='.', filter=normalize)
            report['images'].append(dict(variant=item['variant'], image=item['image'], builder=item['builder'],
                                         archive=archive.name, archiveSHA256=sha(archive),
                                         config=metadata['Config'], rootFS=metadata['RootFS'], imageID=metadata['Id']))
        report['state'] = 'built-not-native-qualified'
    except Exception as error:
        report.update(state='failed', error=str(error))
        raise
    finally:
        (args.output / 'candidate.json').write_text(json.dumps(report, indent=2) + '\n')
        if created:
            run(['docker', 'buildx', 'rm', builder])
    print(args.output / 'candidate.json')


if __name__ == '__main__':
    main()
