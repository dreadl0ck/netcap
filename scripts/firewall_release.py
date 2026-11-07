#!/usr/bin/env python3
"""Digest-bound release validation and offline upgrade planning; no deployment shell."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'scripts/firewall-release-policy.json').read_text())
SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
KINDS = ('waf', 'enforcer')
ARCHES = ('amd64', 'arm64')
CHARTS = ('netcap-firewall', 'netcap-enforcer', 'netcap-firewall-control')
TESTS = tuple(POLICY['qualifications'])


def run(*args, **kwargs):
    return subprocess.check_output([str(x) for x in args], text=True, **kwargs).strip()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version(value):
    require(bool(SEMVER.fullmatch(value)), 'release version must be SemVer without v/build metadata')
    require(value != '0.1.0-local', 'local fixture version is not releasable')
    return value


def older(left, right):
    def key(v):
        m = SEMVER.fullmatch(version(v))
        pre = m[4]
        return tuple(map(int, m.group(1, 2, 3))), pre
    a, ap = key(left)
    b, bp = key(right)
    if a != b:
        return a < b
    if ap is None or bp is None:
        return ap is not None and bp is None
    aa, bb = ap.split('.'), bp.split('.')
    for x, y in zip(aa, bb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return int(x) < int(y)
        if x.isdigit() != y.isdigit():
            return x.isdigit()
        return x < y
    return len(aa) < len(bb)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def checked_file(root, item):
    root = root.resolve()
    require(isinstance(item, dict) and set(item) == {'path', 'sha256'}, 'invalid artifact record')
    require(not Path(item['path']).is_absolute() and '..' not in Path(item['path']).parts, 'unsafe artifact path')
    path = (root / item['path']).resolve()
    require(path.is_relative_to(root) and path.is_file() and not any(p.is_symlink() for p in [root / item['path'], *(root / item['path']).parents] if p.is_relative_to(root)), 'unsafe/missing artifact path')
    require(sha(path) == item['sha256'], 'artifact checksum mismatch: ' + item['path'])
    return path


def record(root, path):
    return {'path': str(Path(path).relative_to(root)), 'sha256': sha(path)}


def loopback(value):
    require(re.fullmatch(r'(localhost|127\.0\.0\.1):[0-9]{1,5}/[a-z0-9][a-z0-9/_-]*', value) is not None, 'registry must be loopback with explicit port and repository')
    return value


def qualification(directory, commit):
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text())
    require(manifest.get('head') == commit, 'soak qualification commit mismatch; old topic binaries cannot qualify a future candidate')
    require(manifest.get('owner') == 'netcap-topic-qualification/v2', 'owned qualification manifest required')
    before = manifest.get('provenance_before', {})
    after = manifest.get('provenance_after', {})
    require(before and before == after and manifest.get('inputs_unchanged') is True, 'soak inputs changed or before/after provenance absent')
    require(before.get('commit') == commit and before.get('clean') is True, 'soak requires clean candidate commit')
    require(before.get('binary_sha256') == manifest.get('binary_sha256'), 'soak binary provenance mismatch')
    settings = {line.strip().removeprefix('build\t') for line in before.get('go_build', '').splitlines()}
    require('vcs.revision=' + commit in settings and 'vcs.modified=false' in settings, 'soak binary must embed exact clean candidate revision')
    require(manifest.get('state') == 'pass' and manifest.get('child_exit_code') == 0, 'soak runner did not pass')
    receipts = manifest.get('receipt_sha256', {})
    require('http/progress.json' in receipts, 'missing final soak receipt')
    for path, digest in receipts.items():
        checked_file(directory, {'path': path, 'sha256': digest})
    report = json.loads((directory / 'http/progress.json').read_text())
    require(report.get('load_state') == 'pass' and report.get('soak_24h_pass') is True and report.get('actual_load_seconds', 0) >= 86400, '24h mixed soak is incomplete')
    require(report.get('mixed_wire_enabled') is True and len(report.get('profiles', {})) == 34, 'missing mixed protocol profiles')
    for profile in report['profiles'].values():
        counts = profile['counts']
        require(counts['Allowed'] > 0 and counts['Denied'] > 0 and counts['Offered'] == counts['Allowed'] + counts['Denied'], 'incomplete profile load')
        require(all(counts[k] == 0 for k in ('Errors', 'Dropped', 'FalseBlocks')) and all(profile.get(k, 0) == 0 for k in ('forbidden_origin_requests', 'forbidden_origin_bytes', 'forbidden_side_effects')), 'soak safety budget failed')
    return manifest


def check_oci(path, digest, arch, m, binary):
    with tarfile.open(path) as tf:
        members = {p.name.removeprefix('./'): p for p in tf.getmembers() if p.isfile()}

        def blob(d):
            require(DIGEST.fullmatch(d) is not None, 'invalid blob digest')
            data = tf.extractfile(members['blobs/sha256/' + d[7:]]).read()
            require('sha256:' + hashlib.sha256(data).hexdigest() == d, 'OCI blob digest mismatch')
            return data

        manifest = json.loads(blob(digest))
        config = json.loads(blob(manifest['config']['digest']))
        require(config['architecture'] == arch and config['os'] == 'linux', 'OCI platform mismatch')
        labels = config['config'].get('Labels', {})
        require(labels.get('org.opencontainers.image.version') == m['version'] and labels.get('org.opencontainers.image.revision') == m['commit'], 'OCI version/commit mismatch')
        import io
        found = None
        for layer in manifest['layers']:
            with tarfile.open(fileobj=io.BytesIO(blob(layer['digest']))) as lt:
                for entry in lt:
                    if entry.name.removeprefix('./') in ('.wh.netcap-firewall', '.wh..wh..opq'):
                        found = None
                    if entry.name.removeprefix('./') == 'netcap-firewall':
                        require(entry.isfile(), 'binary layer must be a file')
                        found = hashlib.sha256(lt.extractfile(entry).read()).hexdigest()
        require(found == binary['sha256'], 'offline binary differs from tested image')


def validate(root, publication=False, rehearsal=False):
    root = Path(root)
    m = json.loads((root / 'candidate.json').read_text())
    require(m['schema'] == 'netcap-firewall-release/v1', 'unknown release schema')
    version(m['version'])
    require(re.fullmatch('[0-9a-f]{40}', m['commit']) is not None, 'invalid commit')
    require(m['schemas'] == {'config': POLICY['configSchema'], 'policy': POLICY['policySchema']}, 'unsupported config/policy schema')
    require(m['tag'] == 'firewall-v' + m['version'], 'tag/version mismatch')
    require(set(m['images']) == set(KINDS), 'missing image')
    require(set(m['native']) == set(ARCHES), 'both native qualifications required')
    require(m.get('qualificationMode') == 'native' or (rehearsal and not publication and m.get('qualificationMode') == 'rehearsal'), 'native qualification required; rehearsal is not a release')
    for arch in ARCHES:
        q = m['native'][arch]
        require(q['commit'] == m['commit'] and q['version'] == m['version'], 'qualification commit/version mismatch')
        require(q['native'] is (m['qualificationMode'] == 'native') and q['architecture'] == arch and q['os'] == 'linux', 'native Linux qualification required')
        require(set(q['tests']) == set(TESTS) and all(v == 'passed' for v in q['tests'].values()), 'missing/failed qualification')
        require(set(q['evidence']) == set(TESTS), 'missing named test evidence')
        for evidence in q['evidence'].values():
            checked_file(root, evidence)
        for kind in KINDS:
            image = m['images'][kind]['platforms'][arch]
            require(DIGEST.fullmatch(image['digest']) is not None, 'invalid OCI digest')
            require(q['digests'][kind] == image['digest'], 'tested digest mismatch')
            archive = checked_file(root, image['archive'])
            checked_file(root, image['binary'])
            check_oci(archive, image['digest'], arch, m, image['binary'])
            sbom = json.loads(checked_file(root, image['sbom']).read_text())
            require(sbom['spdxVersion'].startswith('SPDX-2.') and sbom['packages'], 'empty/non-SPDX SBOM')
            require('Tool: syft-' + POLICY['tools']['syft'].lstrip('v') in sbom['creationInfo']['creators'], 'unpinned SBOM generator')
            inventory = json.loads(checked_file(root, image['inventory']).read_text())
            require(inventory['imageDigest'] == image['digest'], 'inventory digest mismatch')
            require(inventory['schema'] == 'netcap-source-inventory/v1', 'unknown inventory schema')
            require(not inventory.get('unresolved'), 'unresolved source/license inventory')
            packages = {p['SPDXID'] for p in sbom['packages']}
            entries = inventory['packages']
            require(len(entries) == len(packages) and {p['id'] for p in entries} == packages, 'missing non-GPL license/source inventory')
            for entry in entries:
                require(entry['license'] and entry['license'] not in ('NOASSERTION', 'NONE', 'UNKNOWN'), 'unresolved component license')
                require(checked_file(root, entry['licenseFile']).stat().st_size > 0, 'empty license text')
                require(checked_file(root, entry['source']).stat().st_size > 0, 'empty corresponding source')
    for kind in KINDS:
        image = m['images'][kind]
        require(image['repository'] == POLICY['registry'] + '/netcap-firewall-' + kind, 'untrusted image repository')
        require(set(image['platforms']) == set(ARCHES), 'missing platform')
        require(DIGEST.fullmatch(image['digest']) is not None, 'missing index digest')
        index = json.loads(checked_file(root, image['index']).read_text())
        require('sha256:' + sha(root / image['index']['path']) == image['digest'], 'index digest mismatch')
        require(len(index['manifests']) == 2, 'index must have exactly two platforms')
        require({(p['platform']['os'], p['platform']['architecture'], p['digest']) for p in index['manifests']} == {('linux', a, image['platforms'][a]['digest']) for a in ARCHES}, 'index contains untested platform/digest')
    checked_file(root, m['source'])
    require(len(m['charts']) == 3 and {c['name'] for c in m['charts']} == set(CHARTS), 'all three charts required')
    import yaml
    for chart in m['charts']:
        path = checked_file(root, chart['archive'])
        with tarfile.open(path) as tf:
            metadata = yaml.safe_load(tf.extractfile(chart['name'] + '/Chart.yaml'))
            values = yaml.safe_load(tf.extractfile(chart['name'] + '/values.yaml'))
        require(metadata['name'] == chart['name'] and metadata['version'] == m['version'] and metadata['appVersion'] == m['version'], 'chart SemVer/appVersion mismatch')
        kind = 'enforcer' if chart['name'] == 'netcap-enforcer' else 'waf'
        require(values['image']['digest'] == m['images'][kind]['digest'] and values['image']['repository'] == m['images'][kind]['repository'] and values['image']['tag'] == m['version'], 'chart imageDigest/version mismatch')
    require(m['reviews'].keys() == set(POLICY['externalReviews']), 'missing external review slots')
    if publication:
        soak = m.get('soak')
        require(soak is not None, 'final candidate soak qualification required')
        receipt = json.loads(checked_file(root, soak).read_text())
        require(receipt['commit'] == m['commit'] and receipt['digests'] == {k: i['digest'] for k, i in m['images'].items()}, 'soak candidate digest mismatch')
        qualification(checked_file(root, receipt['manifest']).parent, m['commit'])
        for review in m['reviews'].values():
            require(review['decision'] == 'approved' and review['reviewer'] and review['uri'].startswith('https://'), 'operator/external signoff required')
            require(review['commit'] == m['commit'] and review['version'] == m['version'] and review['digests'] == {k: i['digest'] for k, i in m['images'].items()}, 'review not bound to this candidate')
            checked_file(root, review['evidence'])
    return m


def verify(root, key=None, offline=False, trust_root=None, rehearsal=False):
    root = Path(root)
    m = json.loads((root / 'candidate.json').read_text())
    version(m['version'])
    args = ['cosign', 'verify-blob']
    if key:
        args += ['--key', key, '--insecure-ignore-tlog=true']
    else:
        args += ['--certificate-oidc-issuer', POLICY['issuer'], '--certificate-identity', POLICY['subjectPrefix'] + m['version']]
        if offline:
            require(trust_root is not None, 'offline keyless verification requires operator-pinned trusted-root.json')
            args += ['--trusted-root', trust_root]
    for name in ('candidate.json', 'SHA256SUMS'):
        run(*args, '--bundle', root / (name + '.sigstore.json'), root / name)
    listed = set()
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        digest, path = line.split('  ', 1)
        require(path not in listed, 'duplicate checksum path')
        listed.add(path)
        checked_file(root, {'path': path, 'sha256': digest})
    expected = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p.name not in ('SHA256SUMS', 'SHA256SUMS.sigstore.json')}
    require(listed == expected, 'unsigned/missing files in offline bundle')
    m = validate(root, rehearsal=rehearsal)
    verify_provenance(root, m, args)
    return m


def verify_provenance(root, m, args):
    result = json.loads((root / 'promotion-result.json').read_text())
    require(result['candidateSHA256'] == sha(root / 'candidate.json'), 'promotion receipt candidate mismatch')
    expected_subjects = {k + '-' + a: p['digest'] for k, i in m['images'].items() for a, p in i['platforms'].items()}
    expected_subjects.update({k + '-index': i['digest'] for k, i in m['images'].items()})
    for chart in m['charts']:
        path = root / (chart['name'] + '.oci.json')
        descriptor = json.loads(path.read_text())
        require(descriptor['layers'][0]['digest'] == 'sha256:' + chart['archive']['sha256'], 'chart OCI layer differs from signed archive')
        expected_subjects[chart['name']] = 'sha256:' + sha(path)
    require(len(result['subjects']) == len(expected_subjects) and {s['name']: s['digest'] for s in result['subjects']} == expected_subjects, 'incomplete promotion subjects')
    for name, digest in expected_subjects.items():
        path = root / (name + '.provenance.json')
        statement = json.loads(path.read_text())
        require(statement['_type'] == 'https://in-toto.io/Statement/v1' and statement['predicateType'] == 'https://slsa.dev/provenance/v1', 'unsupported provenance')
        require(len(statement['subject']) == 1 and statement['subject'][0]['digest'] == {'sha256': digest[7:]}, 'provenance subject mismatch')
        require(statement['predicate']['buildDefinition']['externalParameters'] == {'version': m['version'], 'commit': m['commit']}, 'provenance commit/version mismatch')
        run(*args, '--bundle', str(path) + '.sigstore.json', path)


def checksums(root):
    root = Path(root)
    paths = sorted(p for p in root.rglob('*') if p.is_file() and p.name not in ('SHA256SUMS', 'SHA256SUMS.sigstore.json'))
    (root / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.relative_to(root)}\n' for p in paths))


def apply_reviews(root, path):
    root = Path(root).resolve()
    path = Path(path).resolve()
    m = validate(root)
    reviews = json.loads(path.read_text())
    require(set(reviews) == set(POLICY['externalReviews']), 'missing external review slots')
    for name, review in reviews.items():
        require(review['decision'] == 'approved' and review['reviewer'] and review['uri'].startswith('https://'), 'operator/external signoff required')
        require(review['commit'] == m['commit'] and review['version'] == m['version'] and review['digests'] == {k: i['digest'] for k, i in m['images'].items()}, 'review not bound to this candidate')
        checked_file(path.parent, review['evidence'])
    dest = root / 'external-reviews'
    require(not dest.exists(), 'external reviews already attached')
    dest.mkdir(mode=0o700)
    for name, review in reviews.items():
        target = dest / name
        shutil.copyfile(checked_file(path.parent, review['evidence']), target)
        review['evidence'] = record(root, target)
    m['reviews'] = reviews
    write(root / 'candidate.json', m)
    checklist = root / 'candidate-checklist.json'
    if checklist.exists():
        data = json.loads(checklist.read_text())
        data.update(candidateSHA256=sha(root / 'candidate.json'), externalReviews=reviews)
        write(checklist, data)
    validate(root, publication=True)


def check_run(run_id, commit):
    require(re.fullmatch('[0-9]+', run_id) is not None, 'invalid candidate run id')
    data = json.loads(run('gh', 'api', 'repos/dreadl0ck/netcap/actions/runs/' + run_id))
    require(data['repository']['full_name'] == 'dreadl0ck/netcap' and data['path'] == '.github/workflows/firewall-release.yml', 'untrusted candidate workflow')
    require(data['head_sha'] == commit and data['conclusion'] == 'success' and data['event'] in ('workflow_dispatch', 'push'), 'candidate must be a successful same-commit manual/tag run')


def plan(args):
    m = verify(args.candidate, args.key, args.offline, args.trust_root)
    current = verify(args.current, args.key, args.offline, args.trust_root)
    require(m['schemas'] == current['schemas'], 'schema migration requires a separately reviewed migration tool')
    require(not older(m['version'], current['version']) or args.allow_downgrade, 'downgrade refused: explicit --allow-downgrade required')
    state = Path(args.state).resolve()
    require(not Path(args.state).is_symlink(), 'state symlink refused')
    require(state.is_dir() and not any(p.is_symlink() for p in state.rglob('*')), 'state must be a real directory without symlinks')
    import yaml
    documents = {}
    for name in ('config', 'policy'):
        path = Path(getattr(args, name)).resolve()
        require(path.is_relative_to(state) and path.is_file(), 'config/policy must be included in state backup')
        document = yaml.safe_load(path.read_text())
        require(document.get('version') == m['schemas'][name], 'live config/policy schema mismatch')
        documents[name] = {'path': str(path.relative_to(state)), 'sha256': sha(path)}
    backup = Path(args.backup).resolve()
    output = Path(args.output).resolve()
    require(not output.exists() and not output.is_relative_to(state) and output != backup, 'plan output must be new and outside state')
    require(not backup.exists() and not backup.is_relative_to(state), 'backup must be new and outside state')
    backup.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out, tarfile.open(fileobj=out, mode='w:gz') as tf:
            tf.add(state, arcname='state')
        with tarfile.open(backup) as tf:
            require(bool(tf.getmembers()), 'empty backup')
        with open(backup, 'rb') as f:
            os.fsync(f.fileno())
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    write(args.output, {'schema': 'netcap-upgrade-plan/v1', 'from': current['version'], 'to': m['version'], 'currentManifestSHA256': sha(Path(args.current) / 'candidate.json'), 'targetManifestSHA256': sha(Path(args.candidate) / 'candidate.json'), 'schemas': m['schemas'], 'documents': documents, 'backup': str(backup), 'backupSHA256': sha(backup), 'images': {k: v['repository'] + '@' + v['digest'] for k, v in m['images'].items()}, 'operatorActionRequired': 'Keep writers quiesced; verify application-native encrypted backup/restore and Helm diff before manual upgrade. This plan never mutates live state.', 'downgradeExplicit': args.allow_downgrade})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('validate', 'checksums', 'verify'):
        p = sub.add_parser(command)
        p.add_argument('candidate', type=Path)
        if command == 'validate':
            p.add_argument('--publication', action='store_true')
            p.add_argument('--rehearsal', action='store_true')
        if command == 'verify':
            p.add_argument('--key')
            p.add_argument('--offline', action='store_true')
            p.add_argument('--trust-root')
            p.add_argument('--rehearsal', action='store_true')
    p = sub.add_parser('apply-reviews')
    p.add_argument('candidate', type=Path)
    p.add_argument('--reviews', type=Path, required=True)
    p = sub.add_parser('check-run')
    p.add_argument('run_id')
    p.add_argument('--commit', required=True)
    p = sub.add_parser('check-qualification')
    p.add_argument('directory', type=Path)
    p.add_argument('--commit', required=True)
    p = sub.add_parser('plan-upgrade')
    for name in ('candidate', 'current', 'state', 'config', 'policy', 'backup', 'output'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--allow-downgrade', action='store_true')
    p.add_argument('--quiesced', action='store_true', required=True)
    p.add_argument('--key')
    p.add_argument('--offline', action='store_true')
    p.add_argument('--trust-root')
    args = parser.parse_args()
    if args.command == 'validate':
        validate(args.candidate, args.publication, args.rehearsal)
    elif args.command == 'checksums':
        checksums(args.candidate)
    elif args.command == 'verify':
        verify(args.candidate, args.key, args.offline, args.trust_root, args.rehearsal)
    elif args.command == 'apply-reviews':
        apply_reviews(args.candidate, args.reviews)
    elif args.command == 'check-run':
        check_run(args.run_id, args.commit)
    elif args.command == 'check-qualification':
        qualification(args.directory, args.commit)
    else:
        plan(args)


if __name__ == '__main__':
    main()
