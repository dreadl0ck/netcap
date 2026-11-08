#!/usr/bin/env python3
"""Verify the shipped image metadata and runtime license payload without a shell."""
import json
import subprocess
import sys
import tarfile

image = sys.argv[1] if len(sys.argv) > 1 else 'netcap-firewall:0.1.0-local'
metadata = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image]))[0]
assert metadata['Config']['User'] == '10001:10001'
assert metadata['Config']['Entrypoint'] == ['/netcap-firewall']
version = json.loads(subprocess.check_output(['docker', 'run', '--rm', image, 'version']))
assert version['http3'] is True, version
container = subprocess.check_output(['docker', 'create', image], text=True).strip()
try:
    required = {'LICENSE', 'legal/THIRD_PARTY_NOTICES.txt', 'legal/THIRD_PARTY_LICENSES.txt',
                'legal/FIREWALL_NOTICES.txt', 'legal/BUILD_MODULES.txt',
                'legal/licenses/github.com/corazawaf/coraza/v3/LICENSE',
                'legal/licenses/github.com/lib/pq/LICENSE',
                'legal/licenses/github.com/corazawaf/coraza-coreruleset/v4/LICENSE'}
    with subprocess.Popen(['docker', 'export', container], stdout=subprocess.PIPE) as export:
        with tarfile.open(fileobj=export.stdout, mode='r|') as archive:
            for member in archive:
                name = member.name.removeprefix('./')
                required.discard(name)
                if name == 'legal/BUILD_MODULES.txt':
                    modules = archive.extractfile(member).read().decode()
                    assert 'github.com/corazawaf/coraza/v3\tv3.8.1' in modules
                    assert '-tags=coraza,http3' in modules
                    assert 'github.com/quic-go/quic-go' in modules
                    assert 'github.com/lib/pq\tv1.12.3' in modules
                    assert 'google.golang.org/protobuf\tv1.36.11' in modules
                    assert 'CGO_ENABLED=0' in modules
        assert export.wait() == 0
    assert not required, 'missing distribution files: ' + str(required)
    print('PASS: nonroot Coraza+HTTP/3 image, linked QUIC metadata, LICENSE and third-party notices')
finally:
    subprocess.run(['docker', 'rm', container], check=True, stdout=subprocess.DEVNULL)
