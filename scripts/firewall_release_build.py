#!/usr/bin/env python3
"""Build once, qualify locally, export immutable OCI archives. Never logs into a registry."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile

from firewall_release import ROOT, ARCHES, KINDS, TESTS, POLICY, CHARTS, require, run, version, write, record, sha, loopback, qualification, checked_file


def export_oci(ref, archive):
    layout = archive.with_suffix('.layout')
    run('crane', 'pull', ref, layout, '--format=oci')
    require(layout.is_dir(), 'crane must export an OCI layout directory')
    with tarfile.open(archive, 'w') as tf:
        tf.add(layout, arcname='.')
    shutil.rmtree(layout)


def import_oci(archive, ref):
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(archive) as tf:
            tf.extractall(tmp, filter='data')
        run('crane', 'push', tmp, ref)


def evidence(root, out, name, command, env=None):
    path = out / (name + '.log')
    with path.open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, env=env)
    return record(root, path)


def source_export(out):
    source = out / 'source'
    source.mkdir()
    subprocess.run(['git', 'archive', '--format=tar.gz', '-o', str(source / 'netcap.tar.gz'), 'HEAD'], check=True)
    # Vendor is an offline rebuild tree, including license texts and modules.txt.
    run('go', 'mod', 'vendor', '-o', source / 'vendor')
    goroot = Path(run('go', 'env', 'GOROOT'))
    with tarfile.open(source / 'go-toolchain-source.tar.gz', 'w:gz') as tf:
        for name in ('src', 'LICENSE', 'PATENTS', 'VERSION'):
            tf.add(goroot / name, arcname='go/' + name)
    with tarfile.open(out / 'corresponding-source.tar.gz', 'w:gz') as tf:
        tf.add(source, arcname='source')
    shutil.rmtree(source)


def binaries(args, single=False):
    import yaml
    version(args.version)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ.update(GOWORK='off', FIREWALL_VERSION=args.version)
    config = yaml.safe_load((ROOT / '.goreleaser-firewall.yml').read_text())
    config['dist'] = str(out / 'goreleaser')
    config_path = out / 'goreleaser.yml'
    config_path.write_text(yaml.safe_dump(config))
    run('goreleaser', 'build', '--config', config_path, '--snapshot', '--clean', *(['--single-target'] if single else []))
    return json.loads((out / 'goreleaser/artifacts.json').read_text())


def inventories(out, kind, digest, supplements, supplements_root=None):
    sbom_path = out / (kind + '.spdx.json')
    sbom = json.loads(sbom_path.read_text())
    entries = []
    unresolved = []
    for p in sbom['packages']:
        name = p['name'] + '@' + p.get('versionInfo', '')
        supplied = supplements.get(name)
        if supplied:
            entry = dict(supplied)
            for key in ('source', 'licenseFile'):
                base = (supplements_root or ROOT).resolve()
                src = (base / entry[key]).resolve()
                require(src.is_relative_to(base) and src.is_file() and not (base / entry[key]).is_symlink(), 'unsafe/missing supplemental export: ' + str(src))
                dest = out / ('supplement-' + sha(src))
                if not dest.exists():
                    shutil.copyfile(src, dest)
                entry[key] = record(out.parent, dest)
        elif any('pkg:golang/' in r.get('referenceLocator', '') for r in p.get('externalRefs', [])) or p['name'] in ('go', 'stdlib', 'github.com/dreadl0ck/netcap') or p['SPDXID'].startswith('SPDXRef-DocumentRoot-Image-'):
            license_id = p.get('licenseConcluded', 'NOASSERTION')
            if license_id in ('NOASSERTION', 'NONE'):
                license_id = p.get('licenseDeclared', 'NOASSERTION')
            if p['name'] == 'github.com/dreadl0ck/netcap' or p['SPDXID'].startswith('SPDXRef-DocumentRoot-Image-'):
                license_id = 'GPL-3.0-only'
            entry = {'license': license_id, 'source': record(out.parent, out / 'corresponding-source.tar.gz'), 'licenseFile': record(out.parent, out / 'licenses.tar.gz')}
        else:
            unresolved.append(name)
            continue
        if entry['license'] in ('NOASSERTION', 'NONE', 'UNKNOWN', ''):
            unresolved.append(name + ': unresolved license')
        entry['id'] = p['SPDXID']
        entries.append(entry)
    write(out / (kind + '.inventory.json'), {'schema': 'netcap-source-inventory/v1', 'imageDigest': digest, 'packages': entries, 'unresolved': unresolved})
    return unresolved


def native(args):
    version(args.version)
    require(not run('git', 'status', '--porcelain'), 'release build requires a clean committed worktree')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    arch = args.arch
    machine = {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch]
    require(platform.system() == 'Linux' and platform.machine() == machine, 'native Linux runner required; emulation cannot qualify release')
    require(run('docker', 'info', '--format', '{{.Architecture}}') == machine, 'Docker architecture mismatch')
    artifacts = binaries(args, single=True)
    context = out / 'context'
    context.mkdir()
    shutil.copy(ROOT / 'LICENSE', context)
    shutil.copytree(ROOT / 'legal', context / 'legal')
    modules = run('go', 'list', '-m', '-f', '{{if .Dir}}{{.Path}} {{.Dir}}{{end}}', 'all')
    for line in modules.splitlines():
        module, directory = line.split(' ', 1)
        for pattern in ('LICENSE*', 'NOTICE*', 'COPYING*'):
            for path in Path(directory).glob(pattern):
                if path.is_file():
                    target = context / 'legal/licenses' / module
                    target.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target / path.name)
    shutil.copy(ROOT / 'docker/enforcer/entrypoint.sh', context)
    commit = run('git', 'rev-parse', 'HEAD')
    for kind in KINDS:
        paths = [Path(a['path']) for a in artifacts if a.get('type') == 'Binary' and a.get('extra', {}).get('ID') == kind]
        require(len(paths) == 1, 'GoReleaser did not produce exactly one ' + kind + ' binary')
        shutil.copy(paths[0], context / ('netcap-firewall-' + kind))
        (context / ('legal/BUILD_MODULES-' + kind + '.txt')).write_text(run('go', 'version', '-m', paths[0]) + '\n')
        run('docker', 'build', '--provenance=false', '--sbom=false', '--platform', 'linux/' + arch, '--build-arg', 'VERSION=' + args.version, '--build-arg', 'REVISION=' + commit, '-f', ROOT / ('docker/' + ('firewall' if kind == 'waf' else kind) + '/Dockerfile.release'), '-t', 'netcap-release-' + kind + ':' + args.version, context)
    logs = out / 'evidence'
    logs.mkdir()
    env = dict(os.environ, CGO_ENABLED='1')
    packages = ['./cmd/netcap-firewall', './cmd/firewall', './internal/firewallui', './internal/waf', './internal/policy', './internal/policystate', './internal/policycontrol', './internal/gateway', './internal/enforcer', './internal/networkfirewall', './internal/transparentfirewall', './internal/firewallstate', './internal/firewallfleet', './internal/firewalltransport', './internal/responseactions']
    proofs = {}
    versions = {}
    for kind in KINDS:
        data = json.loads(run('docker', 'run', '--rm', '--network=none', '--entrypoint', '/netcap-firewall', 'netcap-release-' + kind + ':' + args.version, 'version'))
        require(data['releaseVersion'] == args.version and data['commit'] == commit, 'binary release version/commit not embedded')
        require(data['version'] == POLICY['configSchema'] and data['policy'] == POLICY['policySchema'], 'binary schema mismatch')
        require(data['http3'] is (kind == 'waf'), 'binary feature mismatch')
        versions[kind] = data
    write(logs / 'version-smoke.log', versions)
    proofs['version-smoke'] = record(out.parent, logs / 'version-smoke.log')
    for chart in CHARTS:
        name = 'chart-' + chart
        proofs[name] = evidence(out.parent, logs, name, ['python3', str(ROOT / 'charts' / chart / 'tests/test_render.py')])
    for name, tags in [('race', ''), ('race-coraza', 'coraza'), ('race-http3', 'coraza,http3')]:
        extra = ['./examples/firewall/qualification'] if tags == 'coraza,http3' else []
        proofs[name] = evidence(out.parent, logs, name, ['go', 'test', '-race', '-count=1'] + (['-tags', tags] if tags else []) + packages + extra, env)
    proofs['gateway'] = evidence(out.parent, logs, 'gateway', ['python3', 'examples/firewall/gateway_smoke.py', str(context / 'netcap-firewall-waf')])
    proofs['image-smoke'] = evidence(out.parent, logs, 'image-smoke', ['bash', 'examples/firewall/smoke.sh'], dict(os.environ, SKIP_BUILD='1', FIREWALL_IMAGE='netcap-release-waf:' + args.version))
    run('docker', 'tag', 'netcap-release-enforcer:' + args.version, 'netcap-enforcer:0.1.0-local')
    # The test overlay is separate; the runtime image is never rebuilt after qualification.
    run('docker', 'build', '-f', 'docker/enforcer/Dockerfile', '--target', 'qualification', '-t', 'netcap-enforcer-test-base', '.')
    run('docker', 'build', '-f', 'internal/transparentfirewall/Dockerfile.lab', '-t', 'netcap-transparent-test-base', '.')
    for name, base, binary in [('enforcer', 'netcap-enforcer-test-base', 'enforcer'), ('transparent', 'netcap-transparent-test-base', 'waf')]:
        dockerfile = context / (name + '.Dockerfile')
        dockerfile.write_text('FROM ' + base + '\nCOPY netcap-firewall-' + binary + ' /netcap-firewall\n')
        run('docker', 'build', '-f', dockerfile, '-t', 'netcap-' + name + '-release-test', context)
    for name in ('enforcer', 'network', 'transparent'):
        command = ['python3', 'examples/firewall/' + name + '_lab.py']
        command += ['--image', 'netcap-' + ('enforcer' if name == 'network' else name) + '-release-test']
        if name != 'network':
            command.append('--skip-build')
        proofs[name] = evidence(out.parent, logs, name, command)
    source_export(out)
    with tarfile.open(out / 'licenses.tar.gz', 'w:gz') as tf:
        tf.add(context / 'legal', arcname='legal')
        tf.add(context / 'LICENSE', arcname='LICENSE')
    supplements = json.loads(args.supplements.read_text()) if args.supplements else {}
    images = {}
    blockers = []
    for kind in KINDS:
        ref = args.registry + '/netcap-firewall-' + kind + ':' + args.version + '-' + arch
        run('docker', 'tag', 'netcap-release-' + kind + ':' + args.version, ref)
        run('docker', 'push', ref)
        digest = run('crane', 'digest', ref)
        # Force digest preservation on import; the archive's tag is never used as evidence.
        archive = out / (kind + '.oci.tar')
        export_oci(ref + '@' + digest, archive)
        sbom = run('syft', 'registry:' + ref + '@' + digest, '-o', 'spdx-json')
        (out / (kind + '.spdx.json')).write_text(sbom + '\n')
        blockers += inventories(out, kind, digest, supplements, args.supplements.parent if args.supplements else None)
        binary = out / ('netcap-firewall-' + kind)
        shutil.copy(context / binary.name, binary)
        images[kind] = {'digest': digest, 'archive': record(out.parent, archive), 'binary': record(out.parent, binary), 'sbom': record(out.parent, out / (kind + '.spdx.json')), 'inventory': record(out.parent, out / (kind + '.inventory.json'))}
    write(out / 'native.json', {'commit': commit, 'version': args.version, 'os': 'linux', 'native': True, 'architecture': arch, 'tests': {t: 'passed' for t in TESTS}, 'digests': {k: i['digest'] for k, i in images.items()}, 'evidence': proofs})
    write(out / 'images.json', images)
    write(out / 'blockers.json', {'unresolvedSourcesOrLicenses': blockers})
    shutil.rmtree(context)
    shutil.rmtree(out / 'goreleaser')


def native_inputs(root, commit, release_version, native=True):
    qualifications, images = {}, {}
    checked = set()

    def check(item):
        key = (item['path'], item['sha256'])
        if key not in checked:
            checked_file(root, item)
            checked.add(key)

    for arch in ARCHES:
        q = json.loads((root / arch / 'native.json').read_text())
        require(q['commit'] == commit and q['version'] == release_version, 'qualification commit/version mismatch')
        require(q['architecture'] == arch and q['os'] == 'linux' and q['native'] is native, 'native platform mismatch')
        require(set(q['tests']) == set(TESTS) and all(v == 'passed' for v in q['tests'].values()), 'missing/failed qualification')
        require(set(q['evidence']) == set(TESTS), 'missing named test evidence')
        for name, item in q['evidence'].items():
            # Receipts before the root fix used architecture-local log paths.
            if item['path'] == 'evidence/' + name + '.log':
                item['path'] = arch + '/' + item['path']
            check(item)
        images[arch] = json.loads((root / arch / 'images.json').read_text())
        require(set(images[arch]) == set(KINDS), 'missing native image')
        for kind, image in images[arch].items():
            require(image['digest'] == q['digests'][kind], 'tested digest mismatch')
            for key in ('archive', 'binary', 'sbom', 'inventory'):
                check(image[key])
            inventory = json.loads((root / image['inventory']['path']).read_text())
            for package in inventory['packages']:
                check(package['source'])
                check(package['licenseFile'])
        qualifications[arch] = q
    return qualifications, images


def assemble(args):
    import yaml
    root = args.output.resolve()
    version(args.version)
    m = {'schema': 'netcap-firewall-release/v1', 'qualificationMode': 'native', 'version': args.version, 'tag': 'firewall-v' + args.version, 'commit': getattr(args, 'commit', None) or run('git', 'rev-parse', 'HEAD'), 'schemas': {'config': POLICY['configSchema'], 'policy': POLICY['policySchema']}, 'native': {}, 'images': {}, 'charts': [], 'reviews': {k: {'decision': 'pending', 'reviewer': '', 'uri': '', 'evidence': None} for k in POLICY['externalReviews']}}
    if getattr(args, 'rehearsal', False):
        m['qualificationMode'] = 'rehearsal'
    m['native'], native_images = native_inputs(root, m['commit'], args.version, m['qualificationMode'] == 'native')
    for kind in KINDS:
        refs = []
        platforms = {}
        for arch in ARCHES:
            image = native_images[arch][kind]
            ref = args.registry + '/netcap-firewall-' + kind + ':' + args.version + '-' + arch
            import_oci(root / image['archive']['path'], ref)
            require(run('crane', 'digest', ref) == image['digest'], 'OCI import changed tested digest')
            platforms[arch] = image
            refs.append(ref + '@' + image['digest'])
        index_ref = args.registry + '/netcap-firewall-' + kind + ':' + args.version
        run('crane', 'index', 'append', '-m', refs[0], '-m', refs[1], '-t', index_ref)
        # Preserve exact manifest bytes, including any trailing whitespace.
        data = subprocess.check_output(['crane', 'manifest', index_ref])
        digest = run('crane', 'digest', index_ref)
        path = root / (kind + '-index.json')
        path.write_bytes(data)
        if 'sha256:' + sha(path) != digest and data.endswith(b'\n'):
            path.write_bytes(data[:-1])
        require('sha256:' + sha(path) == digest, 'index bytes do not match registry digest')
        m['images'][kind] = {'repository': POLICY['registry'] + '/netcap-firewall-' + kind, 'digest': digest, 'index': record(root, path), 'platforms': platforms}
    m['source'] = record(root, root / 'amd64/corresponding-source.tar.gz')
    for name in CHARTS:
        chart = root / name
        shutil.copytree(ROOT / 'charts' / name, chart)
        metadata = yaml.safe_load((chart / 'Chart.yaml').read_text())
        metadata.update(version=args.version, appVersion=args.version)
        (chart / 'Chart.yaml').write_text(yaml.safe_dump(metadata))
        values = yaml.safe_load((chart / 'values.yaml').read_text())
        kind = 'enforcer' if name == 'netcap-enforcer' else 'waf'
        values['image'].update(repository=m['images'][kind]['repository'], digest=m['images'][kind]['digest'], tag=args.version)
        (chart / 'values.yaml').write_text(yaml.safe_dump(values))
        options = ['--set', 'upstream=http://backend:8080'] if name == 'netcap-firewall' else []
        run('helm', 'lint', chart, '--strict', *options)
        run('helm', 'template', 'release', chart, *options)
        run('helm', 'package', chart, '--destination', root)
        path = root / (name + '-' + args.version + '.tgz')
        m['charts'].append({'name': name, 'archive': record(root, path)})
        shutil.rmtree(chart)
    if args.reviews:
        m['reviews'] = json.loads(args.reviews.read_text())
    if getattr(args, 'qualification_run', None):
        manifest = qualification(args.qualification_run, m['commit'])
        dest = root / 'soak'
        dest.mkdir(mode=0o700)
        for path, digest in manifest['receipt_sha256'].items():
            src = checked_file(args.qualification_run, {'path': path, 'sha256': digest})
            target = dest / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
        shutil.copyfile(args.qualification_run / 'manifest.json', dest / 'manifest.json')
        write(root / 'soak-binding.json', {'commit': m['commit'], 'digests': {k: i['digest'] for k, i in m['images'].items()}, 'manifest': record(root, dest / 'manifest.json')})
        m['soak'] = record(root, root / 'soak-binding.json')
    write(root / 'candidate.json', m)
    blockers = {arch: {kind: json.loads((root / image['inventory']['path']).read_text())['unresolved'] for kind, image in native_images[arch].items()} for arch in ARCHES}
    write(root / 'candidate-checklist.json', {'schema': 'netcap-release-checklist/v1', 'candidateSHA256': sha(root / 'candidate.json'), 'externalReviews': m['reviews'], 'sourceAndLicenseBlockers': blockers, 'operatorSignoffRequired': True, 'requirements': ['both native Linux qualifications', 'exact tested digests and index children', 'per-architecture pinned Syft SPDX', 'every component license and corresponding source export', 'three Helm3 charts appVersion/image digest coherence', 'cosign OIDC signature and SLSA v1 attestations', 'offline verification with pinned trust root', 'protected release environment and immutable tag'], 'publicationApproved': False})


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['binaries', 'native', 'assemble'])
    p.add_argument('--version', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--registry', default='localhost:5000/candidate')
    p.add_argument('--arch', choices=ARCHES)
    p.add_argument('--supplements', type=Path)
    p.add_argument('--reviews', type=Path)
    p.add_argument('--commit', help='expected tested source commit for assembly; defaults to HEAD, never relabels native receipts')
    p.add_argument('--qualification-run', type=Path, help='completed exact-candidate owned 24h run; required for publication')
    p.add_argument('--rehearsal', action='store_true', help='assemble fixture receipts only; never authorizes publication')
    args = p.parse_args()
    loopback(args.registry)
    {'binaries': binaries, 'native': native, 'assemble': assemble}[args.command](args)
