#!/usr/bin/env python3
"""Loopback rehearsal by default; external promotion requires protected OIDC context."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from firewall_release import POLICY, KINDS, ARCHES, require, run, validate, write, sha, checksums, loopback
from firewall_release_build import import_oci


def hydrate(root, staging):
    loopback(staging)
    m = validate(root)
    for kind in KINDS:
        image = m['images'][kind]
        refs = []
        for arch in ARCHES:
            p = image['platforms'][arch]
            ref = staging + '/netcap-firewall-' + kind + ':' + m['version'] + '-' + arch
            import_oci(root / p['archive']['path'], ref)
            require(run('crane', 'digest', ref) == p['digest'], 'archive is not the tested OCI image')
            refs.append(ref + '@' + p['digest'])
        ref = staging + '/netcap-firewall-' + kind + ':' + m['version']
        run('crane', 'index', 'append', '-m', refs[0], '-m', refs[1], '-t', ref)
        require(run('crane', 'digest', ref) == image['digest'], 'restored index differs from tested index')


def promote(args):
    root = args.candidate.resolve()
    m = validate(root, publication=args.publish, rehearsal=not args.publish)
    loopback(args.staging)
    if not args.publish:
        loopback(args.destination)
        require(args.destination != args.staging, 'rehearsal destination must differ from staging')
    if args.publish:
        require(not args.key, 'scratch keys cannot authorize publication')
        require(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'publication is manual only')
        require(os.environ.get('GITHUB_REPOSITORY') == 'dreadl0ck/netcap', 'untrusted repository')
        require(os.environ.get('GITHUB_REF') == 'refs/tags/' + m['tag'], 'publish from matching immutable tag only')
        require(os.environ.get('GITHUB_SHA') == m['commit'], 'release commit mismatch')
        require(os.environ.get('FIREWALL_RELEASE_ENVIRONMENT') == POLICY['environment'], 'protected release environment required')
        require(os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL'), 'OIDC permission required')
    else:
        require(args.key and args.public_key and args.signing_config, 'dry-run requires an explicit disposable key pair and no-services signing config')
        require(json.loads(Path(args.signing_config).read_text()) == {'mediaType': 'application/vnd.dev.sigstore.signingconfig.v0.2+json', 'rekorTlogConfig': {}, 'tsaConfig': {}}, 'rehearsal signing config must have no external services')
    signing = ['--key', args.key, '--signing-config', args.signing_config] if args.key else []
    verification = ['--key', args.public_key, '--insecure-ignore-tlog=true'] if args.key else ['--certificate-oidc-issuer', POLICY['issuer'], '--certificate-identity', POLICY['subjectPrefix'] + m['version']]

    def sign_blob(path):
        run('cosign', 'sign-blob', '--yes', *signing, '--bundle', str(path) + '.sigstore.json', path)
        run('cosign', 'verify-blob', *verification, '--bundle', str(path) + '.sigstore.json', path)

    # Everything in candidate.json is hashed, validated and signed before an external registry write.
    sign_blob(root / 'candidate.json')
    subjects = []
    for kind in KINDS:
        image = m['images'][kind]
        staging_repo = args.staging + '/netcap-firewall-' + kind
        for arch in (*ARCHES, 'index'):
            digest = image['digest'] if arch == 'index' else image['platforms'][arch]['digest']
            ref = staging_repo + '@' + digest
            require(run('crane', 'digest', ref) == digest, 'staged digest mismatch')
            subjects.append((kind + '-' + arch, ref, image['repository'], digest))
    for chart in m['charts']:
        run('helm', 'push', root / chart['archive']['path'], 'oci://' + args.staging + '/charts', '--plain-http')
        repo = args.staging + '/charts/' + chart['name']
        digest = run('crane', 'digest', repo + ':' + m['version'])
        manifest = subprocess.check_output(['crane', 'manifest', repo + '@' + digest])
        if 'sha256:' + hashlib.sha256(manifest).hexdigest() != digest:
            manifest = manifest.removesuffix(b'\n')
        path = root / (chart['name'] + '.oci.json')
        path.write_bytes(manifest)
        require('sha256:' + sha(path) == digest, 'chart manifest digest mismatch')
        require(json.loads(manifest)['layers'][0]['digest'] == 'sha256:' + chart['archive']['sha256'], 'chart OCI layer differs from reviewed archive')
        subjects.append((chart['name'], repo + '@' + digest, POLICY['registry'] + '/charts/' + chart['name'], digest))
    for name, ref, destination, digest in subjects:
        predicate = {'buildDefinition': {'buildType': 'https://github.com/dreadl0ck/netcap/firewall-release/v1', 'externalParameters': {'version': m['version'], 'commit': m['commit']}, 'internalParameters': {}, 'resolvedDependencies': [{'uri': 'git+https://github.com/dreadl0ck/netcap', 'digest': {'gitCommit': m['commit']}}]}, 'runDetails': {'builder': {'id': 'https://github.com/dreadl0ck/netcap/.github/workflows/firewall-release.yml'}, 'metadata': {'invocationId': os.environ.get('GITHUB_RUN_ID', 'local-rehearsal')}, 'byproducts': [{'name': 'candidate.json', 'digest': {'sha256': sha(root / 'candidate.json')}}]}}
        path = root / (name + '.provenance.json')
        write(path, {'_type': 'https://in-toto.io/Statement/v1', 'subject': [{'name': destination, 'digest': {'sha256': digest.split(':')[1]}}], 'predicateType': 'https://slsa.dev/provenance/v1', 'predicate': predicate})
        sign_blob(path)
        pred = root / (name + '.predicate.json')
        write(pred, predicate)
        run('cosign', 'sign', '--yes', *signing, '--bundle', root / (name + '.image.sigstore.json'), ref)
        run('cosign', 'verify', *verification, ref)
        run('cosign', 'attest', '--yes', *signing, '--type', 'https://slsa.dev/provenance/v1', '--predicate', pred, ref)
        run('cosign', 'verify-attestation', *verification, '--type', 'https://slsa.dev/provenance/v1', ref)
    # Only after every signature and SLSA attestation has verified may promotion begin.
    for name, ref, destination, digest in subjects:
        if not args.publish:
            destination = args.destination + ('/charts/' + name if name.startswith('netcap-') else '/netcap-firewall-' + name.rsplit('-', 1)[0])
        pred = root / (name + '.predicate.json')
        # crane copy preserves descriptors; no Dockerfile or compiler is invoked here.
        target = destination + ':' + m['version'] + ('-' + name.rsplit('-', 1)[1] if name.rsplit('-', 1)[-1] in ARCHES else '')
        run('crane', 'copy', ref, target)
        require(run('crane', 'digest', target) == digest, 'promotion changed qualified digest')
        target = destination + '@' + digest
        run('cosign', 'sign', '--yes', *signing, '--bundle', root / (name + '.published.sigstore.json'), target)
        run('cosign', 'attest', '--yes', *signing, '--type', 'https://slsa.dev/provenance/v1', '--predicate', pred, target)
        if name.rsplit('-', 1)[-1] in ARCHES:
            kind, arch = name.rsplit('-', 1)
            run('cosign', 'attest', '--yes', *signing, '--type', 'spdxjson', '--predicate', root / m['images'][kind]['platforms'][arch]['sbom']['path'], target)
            run('cosign', 'verify-attestation', *verification, '--type', 'spdxjson', target)
        run('cosign', 'verify', *verification, target)
        run('cosign', 'verify-attestation', *verification, '--type', 'https://slsa.dev/provenance/v1', target)
    write(root / 'promotion-result.json', {'dryRun': not args.publish, 'candidateSHA256': sha(root / 'candidate.json'), 'subjects': [{'name': n, 'digest': d} for n, _, _, d in subjects], 'operatorSignoffRequired': not args.publish})
    checksums(root)
    sign_blob(root / 'SHA256SUMS')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('candidate', type=Path)
    p.add_argument('--staging', default='localhost:5000/candidate')
    p.add_argument('--destination', default='localhost:5000/promoted')
    p.add_argument('--publish', action='store_true')
    p.add_argument('--key')
    p.add_argument('--public-key')
    p.add_argument('--signing-config')
    p.add_argument('--hydrate-only', action='store_true')
    args = p.parse_args()
    if args.hydrate_only:
        hydrate(args.candidate.resolve(), args.staging)
    else:
        promote(args)
