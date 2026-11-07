#!/usr/bin/env python3
"""Release contracts; FIREWALL_RELEASE_INTEGRATION=1 adds real local OCI/cosign tests."""
import argparse
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml
import firewall_release as release
import firewall_release_build as build
import firewall_release_promote as promotion


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name == 'netcap-firewall' else 0o644
            tf.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def encoded(obj):
    return json.dumps(obj, separators=(',', ':'), sort_keys=True).encode()


def artifact(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return release.record(root, path)


def fixture(root):
    """Synthetic, non-executable images. No product qualification or review is claimed."""
    m = {'schema': 'netcap-firewall-release/v1', 'qualificationMode': 'rehearsal',
         'version': '1.2.3-rc.1', 'tag': 'firewall-v1.2.3-rc.1', 'commit': 'a' * 40,
         'schemas': {'config': release.POLICY['configSchema'], 'policy': release.POLICY['policySchema']},
         'native': {}, 'images': {}, 'charts': [],
         'reviews': {k: {'decision': 'pending', 'reviewer': '', 'uri': '', 'evidence': None}
                     for k in release.POLICY['externalReviews']}}
    source = tar_bytes({'fixture/package.json': encoded({'name': 'release-fixture', 'version': '1.0.0', 'license': 'MIT'}),
                        'fixture/LICENSE': b'MIT test fixture; not a distributed product\n'})
    m['source'] = artifact(root, 'fixture-source.tar', source)
    license_file = artifact(root, 'fixture-LICENSE', b'MIT test fixture; not a distributed product\n')
    for arch in release.ARCHES:
        m['native'][arch] = {'commit': m['commit'], 'version': m['version'], 'native': False,
                             'architecture': arch, 'os': 'linux', 'tests': {t: 'passed' for t in release.TESTS},
                             'digests': {}, 'evidence': {t: artifact(root, arch + '/' + t + '.log', b'PLUMBING FIXTURE ONLY; NOT NATIVE PRODUCT QUALIFICATION\n') for t in release.TESTS}}
    for kind in release.KINDS:
        platforms = {}
        descriptors = []
        for arch in release.ARCHES:
            blobs = {}

            def blob(data, media):
                digest = hashlib.sha256(data).hexdigest()
                blobs['blobs/sha256/' + digest] = data
                return {'digest': 'sha256:' + digest, 'size': len(data), 'mediaType': media}

            binary = (kind + '-' + arch + '-NONEXECUTABLE TEST FIXTURE\n').encode()
            layer = tar_bytes({'netcap-firewall': binary, 'usr/lib/node_modules/release-fixture/package.json': encoded({'name': 'release-fixture', 'version': '1.0.0', 'license': 'MIT'})})
            layer_desc = blob(layer, 'application/vnd.oci.image.layer.v1.tar')
            config = {'architecture': arch, 'os': 'linux', 'config': {'Labels': {'org.opencontainers.image.version': m['version'], 'org.opencontainers.image.revision': m['commit']}},
                      'rootfs': {'type': 'layers', 'diff_ids': [layer_desc['digest']]}}
            config_desc = blob(encoded(config), 'application/vnd.oci.image.config.v1+json')
            manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'config': config_desc, 'layers': [layer_desc]}
            descriptor = blob(encoded(manifest), manifest['mediaType'])
            descriptor['platform'] = {'os': 'linux', 'architecture': arch}
            descriptors.append(descriptor)
            archive = tar_bytes({**blobs, 'oci-layout': b'{"imageLayoutVersion":"1.0.0"}', 'index.json': encoded({'schemaVersion': 2, 'manifests': [descriptor]})})
            prefix = arch + '/' + kind
            sbom = {'spdxVersion': 'SPDX-2.3', 'creationInfo': {'creators': ['Tool: syft-' + release.POLICY['tools']['syft'][1:]]},
                    'packages': [{'SPDXID': 'SPDXRef-fixture', 'name': 'release-fixture', 'versionInfo': '1.0.0', 'licenseDeclared': 'MIT'}]}
            inventory = {'schema': 'netcap-source-inventory/v1', 'imageDigest': descriptor['digest'], 'unresolved': [],
                         'packages': [{'id': 'SPDXRef-fixture', 'license': 'MIT', 'licenseFile': license_file, 'source': m['source']}]}
            platforms[arch] = {'digest': descriptor['digest'], 'archive': artifact(root, prefix + '.oci.tar', archive),
                               'binary': artifact(root, prefix + '.bin', binary), 'sbom': artifact(root, prefix + '.spdx.json', encoded(sbom)),
                               'inventory': artifact(root, prefix + '.inventory.json', encoded(inventory))}
            m['native'][arch]['digests'][kind] = descriptor['digest']
        index = encoded({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': descriptors})
        m['images'][kind] = {'repository': release.POLICY['registry'] + '/netcap-firewall-' + kind,
                             'digest': 'sha256:' + hashlib.sha256(index).hexdigest(),
                             'index': artifact(root, kind + '-index.json', index), 'platforms': platforms}
    charts(root, m)
    release.write(root / 'candidate.json', m)
    return m


def charts(root, m):
    m['charts'] = []
    for name in release.CHARTS:
        kind = 'enforcer' if name == 'netcap-enforcer' else 'waf'
        data = tar_bytes({name + '/Chart.yaml': yaml.safe_dump({'apiVersion': 'v2', 'name': name, 'version': m['version'], 'appVersion': m['version']}).encode(),
                          name + '/values.yaml': yaml.safe_dump({'image': {'repository': m['images'][kind]['repository'], 'digest': m['images'][kind]['digest'], 'tag': m['version']}}).encode()})
        m['charts'].append({'name': name, 'archive': artifact(root, name + '-' + m['version'] + '.tgz', gzip.compress(data, mtime=0))})


def registry(test, name):
    container = 'firewall-release-test-' + name
    image = 'registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e'
    release.run('docker', 'run', '-d', '--name', container, '-p', '127.0.0.1::5000', image)
    test.addCleanup(lambda: release.run('docker', 'rm', '-f', container))
    port = release.run('docker', 'port', container, '5000/tcp').rsplit(':', 1)[1]
    host = 'localhost:' + port
    for _ in range(50):
        try:
            release.run('crane', 'catalog', host, stderr=subprocess.DEVNULL)
            return host
        except subprocess.CalledProcessError:
            time.sleep(.2)
    raise AssertionError('local registry did not become ready')


class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.m = fixture(self.root)

    def save(self):
        release.write(self.root / 'candidate.json', self.m)

    def validate(self):
        self.save()
        return release.validate(self.root, rehearsal=True)

    def test_valid_fixture_cannot_claim_native_or_publication(self):
        self.validate()
        with self.assertRaisesRegex(ValueError, 'native qualification'):
            release.validate(self.root)
        with self.assertRaisesRegex(ValueError, 'native qualification'):
            release.validate(self.root, publication=True, rehearsal=True)
        self.m['qualificationMode'] = 'native'
        with self.assertRaisesRegex(ValueError, 'native Linux'):
            self.validate()

    def test_tamper_missing_sbom_source_binary_and_digest(self):
        original = copy.deepcopy(self.m)
        for key in ('sbom', 'binary', 'archive', 'inventory'):
            with self.subTest(key=key):
                self.m = copy.deepcopy(original)
                self.m['images']['waf']['platforms']['arm64'][key]['sha256'] = '0' * 64
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    self.validate()
        self.m = copy.deepcopy(original)
        self.m['source']['path'] = 'absent.tar'
        with self.assertRaisesRegex(ValueError, 'missing artifact'):
            self.validate()
        self.m = copy.deepcopy(original)
        self.m['native']['amd64']['digests']['waf'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(ValueError, 'tested digest'):
            self.validate()

    def test_binary_and_platform_are_bound_inside_archive(self):
        image = self.m['images']['waf']['platforms']['amd64']
        image['binary'] = artifact(self.root, 'substitute', b'not the tested binary')
        with self.assertRaisesRegex(ValueError, 'offline binary differs'):
            self.validate()

    def test_missing_tests_duplicate_charts_and_schema(self):
        original = copy.deepcopy(self.m)
        self.m['native']['arm64']['evidence'].pop('transparent')
        with self.assertRaisesRegex(ValueError, 'named test evidence'):
            self.validate()
        self.m = copy.deepcopy(original)
        self.m['charts'][2] = self.m['charts'][0]
        with self.assertRaisesRegex(ValueError, 'three charts'):
            self.validate()
        self.m = copy.deepcopy(original)
        self.m['schemas']['config'] = 'netcap-firewall/v999'
        with self.assertRaisesRegex(ValueError, 'unsupported config/policy'):
            self.validate()

    def test_unsafe_paths_and_loopback(self):
        for path in ('../escape', '/etc/passwd'):
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                release.checked_file(self.root, {'path': path, 'sha256': '0' * 64})
        (self.root / 'link').symlink_to(self.root / 'fixture-LICENSE')
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            release.checked_file(self.root, {'path': 'link', 'sha256': release.sha(self.root / 'fixture-LICENSE')})
        for host in ('localhost:5000.evil.org/repo', 'localhost:5000@evil.org/repo', 'ghcr.io/dreadl0ck', '127.0.0.1:5000/repo;touch'):
            with self.assertRaisesRegex(ValueError, 'loopback'):
                release.loopback(host)

    def test_semver_order(self):
        self.assertTrue(release.older('1.0.0-rc.9', '1.0.0-rc.10'))
        self.assertTrue(release.older('1.0.0-rc.10', '1.0.0'))
        for v in ('v1.0.0', '1.0.0+build', '1.0.0-01', '$(touch bad)', '0.1.0-local'):
            with self.assertRaises(ValueError):
                release.version(v)

    def test_no_state_change_before_verification_and_downgrade_gate(self):
        state = self.root / 'state'
        state.mkdir()
        (state / 'db').write_bytes(b'pre-upgrade state')
        for name, schema in self.m['schemas'].items():
            (state / (name + '.yaml')).write_text(yaml.safe_dump({'version': schema}))
        args = argparse.Namespace(candidate=self.root, current=self.root, state=state,
                                  config=state / 'config.yaml', policy=state / 'policy.yaml',
                                  backup=self.root / 'backup.tar.gz', output=self.root / 'plan.json',
                                  key=None, offline=True, trust_root='pinned-root', allow_downgrade=False)
        with patch.object(release, 'verify', side_effect=ValueError('bad signature')):
            with self.assertRaisesRegex(ValueError, 'bad signature'):
                release.plan(args)
        self.assertFalse(args.backup.exists())
        self.assertEqual((state / 'db').read_bytes(), b'pre-upgrade state')
        current = copy.deepcopy(self.m)
        current['version'] = '2.0.0'
        with patch.object(release, 'verify', side_effect=[self.m, current]):
            with self.assertRaisesRegex(ValueError, 'downgrade refused'):
                release.plan(args)
        args.allow_downgrade = True
        with patch.object(release, 'verify', side_effect=[self.m, current]):
            release.plan(args)
        self.assertEqual((state / 'db').read_bytes(), b'pre-upgrade state')
        with tarfile.open(args.backup) as tf:
            self.assertEqual(tf.extractfile('state/db').read(), b'pre-upgrade state')
        self.assertEqual(args.backup.stat().st_mode & 0o777, 0o600)

    def test_keyless_verification_pins_issuer_identity_and_root(self):
        calls = []
        with patch.object(release, 'run', side_effect=lambda *args: calls.append(args)), patch.object(release, 'validate', return_value=self.m), patch.object(release, 'verify_provenance'):
            release.checksums(self.root)
            release.verify(self.root, offline=True, trust_root='operator-root.json', rehearsal=True)
        for call in calls:
            self.assertIn(release.POLICY['issuer'], call)
            self.assertIn(release.POLICY['subjectPrefix'] + self.m['version'], call)
            self.assertIn('operator-root.json', call)
            self.assertNotIn('--insecure-ignore-tlog=true', call)
        with self.assertRaisesRegex(ValueError, 'operator-pinned'):
            release.verify(self.root, offline=True)

    def test_review_slots_remain_pending_without_external_evidence(self):
        path = self.root / 'reviews.json'
        release.write(path, self.m['reviews'])
        before = release.sha(self.root / 'candidate.json')
        with patch.object(release, 'validate', return_value=self.m):
            with self.assertRaisesRegex(ValueError, 'external signoff'):
                release.apply_reviews(self.root, path)
        self.assertEqual(release.sha(self.root / 'candidate.json'), before)
        self.assertFalse((self.root / 'external-reviews').exists())

    def test_candidate_run_authentication_rejects_pr_wrong_commit_or_workflow(self):
        data = {'repository': {'full_name': 'dreadl0ck/netcap'}, 'path': '.github/workflows/firewall-release.yml',
                'event': 'workflow_dispatch', 'head_sha': self.m['commit'], 'conclusion': 'success'}
        with patch.object(release, 'run', return_value=json.dumps(data)):
            release.check_run('123', self.m['commit'])
        for key, value in [('event', 'pull_request'), ('head_sha', 'b' * 40), ('conclusion', 'failure'), ('path', '.github/workflows/other.yml')]:
            bad = dict(data, **{key: value})
            with patch.object(release, 'run', return_value=json.dumps(bad)):
                with self.assertRaises(ValueError):
                    release.check_run('123', self.m['commit'])

    def test_unresolved_licenses_and_missing_component_sources(self):
        image = self.m['images']['waf']['platforms']['arm64']
        path = self.root / image['inventory']['path']
        inv = json.loads(path.read_text())
        inv['packages'][0]['source']['path'] = 'missing-component-source'
        release.write(path, inv)
        image['inventory'] = release.record(self.root, path)
        with self.assertRaisesRegex(ValueError, 'missing artifact'):
            self.validate()
        inv['packages'][0]['license'] = 'NOASSERTION'
        release.write(path, inv)
        image['inventory'] = release.record(self.root, path)
        with self.assertRaisesRegex(ValueError, 'unresolved component license'):
            self.validate()

    def test_supplement_exports_are_scoped_and_hashed(self):
        out = self.root / 'amd64'
        item = {'license': 'MIT', 'source': 'fixture-source.tar', 'licenseFile': 'fixture-LICENSE'}
        unresolved = build.inventories(out, 'waf', self.m['images']['waf']['platforms']['amd64']['digest'],
                                      {'release-fixture@1.0.0': item}, self.root)
        self.assertEqual(unresolved, [])
        inv = json.loads((out / 'waf.inventory.json').read_text())
        for key in ('source', 'licenseFile'):
            release.checked_file(self.root, inv['packages'][0][key])
        item['source'] = '../outside'
        with self.assertRaisesRegex(ValueError, 'supplemental export'):
            build.inventories(out, 'waf', 'sha256:' + 'a' * 64, {'release-fixture@1.0.0': item}, self.root)

    def test_workflow_least_privilege_and_no_release_mutations(self):
        wf = yaml.load((release.ROOT / '.github/workflows/firewall-release.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertIn('pull_request', wf['on'])
        self.assertEqual(wf['permissions'], {'contents': 'read'})
        pub = wf['jobs']['publish']
        self.assertEqual(pub['environment'], release.POLICY['environment'])
        self.assertIn("github.event_name == 'workflow_dispatch'", pub['if'])
        self.assertIn('inputs.dryRun == false', pub['if'])
        self.assertEqual(pub['permissions'], {'contents': 'read', 'actions': 'read', 'packages': 'write', 'id-token': 'write'})
        self.assertIn("inputs.candidateRun != ''", pub['if'])
        self.assertIn("needs.contract.result == 'success'", pub['if'])
        self.assertEqual(wf['jobs']['native']['if'], "inputs.candidateRun == ''")
        downloads = [s['with']['path'] for s in wf['jobs']['native']['steps'] if s.get('uses', '').startswith('actions/download-artifact@')]
        self.assertEqual(downloads, ['${{ runner.temp }}/release-inputs'])
        for name, job in wf['jobs'].items():
            if name != 'publish':
                self.assertNotIn('write', job.get('permissions', {}).values())
            for step in job['steps']:
                if 'uses' in step:
                    self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')
        text = (release.ROOT / '.github/workflows/firewall-release.yml').read_text()
        for banned in ('git push', 'gh release', 'goreleaser release', 'contents: write'):
            self.assertNotIn(banned, text)
        for name in ('crane', 'cosign'):
            self.assertIn('@' + release.POLICY['tools'][name], text)
        config = yaml.safe_load((release.ROOT / '.goreleaser-firewall.yml').read_text())
        self.assertEqual(config['version'], 2)
        self.assertTrue(config['release']['disable'])
        self.assertEqual({b['id'] for b in config['builds']}, set(release.KINDS))


@unittest.skipUnless(os.environ.get('FIREWALL_RELEASE_INTEGRATION') == '1', 'explicit loopback integration opt-in')
class LocalPromotion(unittest.TestCase):
    def test_corresponding_source_export_contains_offline_tree_and_licenses(self):
        parent = os.environ.get('FIREWALL_RELEASE_TEST_OUTPUT')
        tmp = tempfile.TemporaryDirectory(prefix='firewall-source-', dir=parent)
        root = Path(tmp.name)
        if parent:
            tmp._finalizer.detach()
        else:
            self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {'GOWORK': 'off'}):
            build.source_export(root)
        archive = root / 'corresponding-source.tar.gz'
        with tarfile.open(archive) as tf:
            names = set(tf.getnames())
            self.assertIn('source/vendor/modules.txt', names)
            self.assertTrue(any('/LICENSE' in name for name in names))
            with tarfile.open(fileobj=tf.extractfile('source/netcap.tar.gz')) as source:
                self.assertIn('LICENSE', source.getnames())
                self.assertIn('go.mod', source.getnames())
            with tarfile.open(fileobj=tf.extractfile('source/go-toolchain-source.tar.gz')) as toolchain:
                self.assertIn('go/LICENSE', toolchain.getnames())
                self.assertIn('go/src/runtime/runtime2.go', toolchain.getnames())
        release.write(root / 'test-result.json', {'qualificationMode': 'rehearsal', 'nativeProductQualification': False,
                      'sourceCommit': release.run('git', 'rev-parse', 'HEAD'), 'archive': release.record(root, archive)})
        print('Corresponding-source packaging artifacts:', root)

    def test_forged_certificate_identity_and_issuer_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix='firewall-identity-') as tmp:
            root = Path(tmp)
            identity = 'https://example.test/fixture-attacker'
            issuer = 'https://example.test/fixture-issuer'
            release.run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=LOCAL-TEST-CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-keyout', root / 'ca.key', '-out', root / 'ca.pem', stderr=subprocess.DEVNULL)
            release.run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', root / 'leaf.key')
            release.run('openssl', 'req', '-new', '-key', root / 'leaf.key', '-subj', '/CN=LOCAL-TEST-ONLY', '-out', root / 'leaf.csr')
            (root / 'extensions.cnf').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\nsubjectAltName=URI:' + identity + '\n1.3.6.1.4.1.57264.1.1=DER:' + issuer.encode().hex(':') + '\n')
            release.run('openssl', 'x509', '-req', '-in', root / 'leaf.csr', '-CA', root / 'ca.pem',
                        '-CAkey', root / 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', root / 'extensions.cnf', '-out', root / 'leaf.pem')
            (root / 'payload').write_bytes(b'local identity-policy test only\n')
            release.run('cosign', 'signing-config', 'create', '--out', root / 'no-services.json')
            release.run('cosign', 'trusted-root', 'create', '--fulcio', 'url=https://example.test,certificate-chain=' + str(root / 'ca.pem'), '--out', root / 'trusted-root.json')
            env = dict(os.environ, COSIGN_PASSWORD='local-fixture-only')
            release.run('cosign', 'import-key-pair', '--key', root / 'leaf.key', '--output-key-prefix', root / 'imported', env=env)
            release.run('cosign', 'sign-blob', '--yes', '--key', root / 'imported.key', '--certificate', root / 'leaf.pem',
                        '--certificate-chain', root / 'ca.pem', '--signing-config', root / 'no-services.json',
                        '--bundle', root / 'payload.sigstore.json', root / 'payload', env=env)
            # These two bypasses apply only to this private fixture CA, which has no SCT/tlog.
            command = ['cosign', 'verify-blob', '--insecure-ignore-tlog=true', '--insecure-ignore-sct=true',
                       '--allow-certificate-chain', '--trusted-root', root / 'trusted-root.json', '--bundle', root / 'payload.sigstore.json']
            release.run(*command, '--certificate-identity', identity, '--certificate-oidc-issuer', issuer, root / 'payload')
            for expected_identity, expected_issuer in [(release.POLICY['subjectPrefix'] + '1.2.3', issuer), (identity, release.POLICY['issuer'])]:
                result = subprocess.run([str(p) for p in [*command, '--certificate-identity', expected_identity,
                                        '--certificate-oidc-issuer', expected_issuer, root / 'payload']], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(result.stderr.lower(), 'identity|issuer|subject')

    def test_crossbuilt_runtime_images_report_embedded_version(self):
        parent = os.environ.get('FIREWALL_RELEASE_TEST_OUTPUT')
        tmp = tempfile.TemporaryDirectory(prefix='firewall-runtime-', dir=parent)
        root = Path(tmp.name)
        if parent:
            tmp._finalizer.detach()
        else:
            self.addCleanup(tmp.cleanup)
        args = argparse.Namespace(version='0.1.0-rc.local', output=root)
        artifacts = build.binaries(args)
        commit = release.run('git', 'rev-parse', 'HEAD')
        host = registry(self, root.name)
        results = []
        for item in artifacts:
            if item.get('type') != 'Binary':
                continue
            kind, arch = item['extra']['ID'], item['goarch']
            context = root / (kind + '-' + arch)
            context.mkdir()
            shutil.copyfile(item['path'], context / ('netcap-firewall-' + kind))
            (context / ('netcap-firewall-' + kind)).chmod(0o755)
            shutil.copy(release.ROOT / 'LICENSE', context)
            shutil.copytree(release.ROOT / 'legal', context / 'legal')
            shutil.copy(release.ROOT / 'docker/enforcer/entrypoint.sh', context)
            tag = 'netcap-release-fixture-' + root.name + '-' + kind + '-' + arch
            dockerfile = release.ROOT / ('docker/' + ('firewall' if kind == 'waf' else 'enforcer') + '/Dockerfile.release')
            release.run('docker', 'build', '--provenance=false', '--sbom=false', '--platform', 'linux/' + arch, '--build-arg', 'VERSION=' + args.version,
                        '--build-arg', 'REVISION=' + commit, '-f', dockerfile, '-t', tag, context)
            self.addCleanup(lambda ref=tag: release.run('docker', 'image', 'rm', ref))
            raw = release.run('docker', 'run', '--rm', '--platform', 'linux/' + arch, '--network=none',
                              '--entrypoint', '/netcap-firewall', tag, 'version')
            metadata = json.loads(raw)
            self.assertEqual(metadata['releaseVersion'], args.version)
            self.assertEqual(metadata['commit'], commit)
            self.assertEqual(metadata['version'], release.POLICY['configSchema'])
            self.assertEqual(metadata['policy'], release.POLICY['policySchema'])
            self.assertEqual(metadata['http3'], kind == 'waf')
            ref = host + '/runtime/' + kind + ':' + arch
            saved = root / 'runtime.docker.tar'
            release.run('docker', 'save', '--output', saved, tag)
            release.run('crane', 'push', saved, ref)
            saved.unlink()
            digest = release.run('crane', 'digest', ref)
            archive = root / (kind + '-' + arch + '.oci.tar')
            build.export_oci(ref + '@' + digest, archive)
            release.check_oci(archive, digest, arch, {'version': args.version, 'commit': commit}, {'sha256': release.sha(item['path'])})
            (root / (kind + '-' + arch + '.spdx.json')).write_text(release.run('syft', 'registry:' + ref + '@' + digest, '-o', 'spdx-json') + '\n')
            results.append({'kind': kind, 'arch': arch, 'version': metadata, 'binarySHA256': release.sha(item['path']),
                            'digest': digest, 'archive': release.record(root, archive)})
        self.assertEqual(len(results), 4)
        release.write(root / 'test-result.json', {'qualificationMode': 'rehearsal', 'nativeProductQualification': False,
                      'sourceTreeDirty': bool(release.run('git', 'status', '--porcelain')), 'images': results})
        print('Cross-built runtime artifacts (not native qualification):', root)

    def test_real_registry_copy_cosign_offline_and_negative_artifacts(self):
        parent = os.environ.get('FIREWALL_RELEASE_TEST_OUTPUT')
        tmp = tempfile.TemporaryDirectory(prefix='firewall-release-', dir=parent)
        root = Path(tmp.name)
        if parent:
            tmp._finalizer.detach()
        else:
            self.addCleanup(tmp.cleanup)
        candidate = root / 'candidate'
        candidate.mkdir()
        m = fixture(candidate)
        host = registry(self, root.name)
        staging = host + '/candidate'
        destination = host + '/promoted'
        for kind in release.KINDS:
            refs = []
            for arch in release.ARCHES:
                image = m['images'][kind]['platforms'][arch]
                ref = staging + '/netcap-firewall-' + kind + ':' + m['version'] + '-' + arch
                build.import_oci(candidate / image['archive']['path'], ref)
                self.assertEqual(release.run('crane', 'digest', ref), image['digest'])
                sbom_path = candidate / image['sbom']['path']
                sbom_path.write_text(release.run('syft', 'registry:' + ref + '@' + image['digest'], '-o', 'spdx-json') + '\n')
                image['sbom'] = release.record(candidate, sbom_path)
                sbom = json.loads(sbom_path.read_text())
                self.assertTrue(sbom['packages'])
                inventory_path = candidate / image['inventory']['path']
                inv = json.loads(inventory_path.read_text())
                inv['packages'] = [{'id': p['SPDXID'], 'license': 'MIT', 'source': m['source'],
                                    'licenseFile': release.record(candidate, candidate / 'fixture-LICENSE')} for p in sbom['packages']]
                self.assertEqual({p['name'] for p in sbom['packages']}, {'release-fixture', staging + '/netcap-firewall-' + kind})
                release.write(inventory_path, inv)
                image['inventory'] = release.record(candidate, inventory_path)
                refs.append(ref + '@' + image['digest'])
            ref = staging + '/netcap-firewall-' + kind + ':' + m['version']
            release.run('crane', 'index', 'append', '-m', refs[0], '-m', refs[1], '-t', ref)
            data = subprocess.check_output(['crane', 'manifest', ref])
            digest = release.run('crane', 'digest', ref)
            if 'sha256:' + hashlib.sha256(data).hexdigest() != digest:
                data = data.removesuffix(b'\n')
            self.assertEqual('sha256:' + hashlib.sha256(data).hexdigest(), digest)
            m['images'][kind]['digest'] = digest
            m['images'][kind]['index'] = artifact(candidate, kind + '-index.json', data)
        charts(candidate, m)
        release.write(candidate / 'candidate.json', m)
        release.validate(candidate, rehearsal=True)
        env = dict(os.environ, COSIGN_PASSWORD='temporary-fixture-only')
        with patch.dict(os.environ, env, clear=True):
            release.run('cosign', 'generate-key-pair', '--output-key-prefix', root / 'fixture')
            release.run('cosign', 'signing-config', 'create', '--out', root / 'no-services.json')
            args = argparse.Namespace(candidate=candidate, staging=staging, destination=destination, publish=False,
                                      key=str(root / 'fixture.key'), public_key=str(root / 'fixture.pub'), signing_config=str(root / 'no-services.json'))
            # Block any accidental compiler/build invocation in the promotion implementation.
            real_run = promotion.run

            def only_promote(*cmd, **kwargs):
                self.assertIn(cmd[0], ('crane', 'helm', 'cosign'))
                return real_run(*cmd, **kwargs)

            with patch.object(promotion, 'run', side_effect=only_promote):
                promotion.promote(args)
            release.verify(candidate, root / 'fixture.pub', offline=True, rehearsal=True)
            for kind in release.KINDS:
                ref = destination + '/netcap-firewall-' + kind + ':' + m['version']
                self.assertEqual(release.run('crane', 'digest', ref), m['images'][kind]['digest'])
            for chart in release.CHARTS:
                release.run('crane', 'digest', destination + '/charts/' + chart + ':' + m['version'])
            # Scratch-key signatures can never impersonate the pinned keyless issuer/identity.
            release.run('cosign', 'trusted-root', 'create', '--out', root / 'trusted-root.json')
            with self.assertRaises(subprocess.CalledProcessError):
                release.verify(candidate, offline=True, trust_root=root / 'trusted-root.json', rehearsal=True)
            sbom_path = candidate / m['images']['waf']['platforms']['arm64']['sbom']['path']
            original = sbom_path.read_bytes()
            sbom_path.write_bytes(b'forged artifact')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                release.verify(candidate, root / 'fixture.pub', offline=True, rehearsal=True)
            sbom_path.write_bytes(original)
            sbom_path.unlink()
            with self.assertRaisesRegex(ValueError, 'missing artifact'):
                release.validate(candidate, rehearsal=True)
            sbom_path.write_bytes(original)
            args.publish = True
            with self.assertRaisesRegex(ValueError, 'native qualification'):
                promotion.promote(args)
        release.write(root / 'test-result.json', {'qualificationMode': 'rehearsal', 'nativeProductQualification': False,
                      'promotedImages': {k: i['digest'] for k, i in m['images'].items()}, 'charts': list(release.CHARTS),
                      'offlineScratchKeyVerification': 'passed', 'externalPublication': False})
        print('Local promotion artifacts:', root)


if __name__ == '__main__':
    unittest.main()
