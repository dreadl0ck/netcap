#!/usr/bin/env python3
"""Verify the signed Windows archive and its sole executable."""
import json
from pathlib import Path
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent / 'windows-signing'))
from windows_sign import SERIAL, sha, verify

directory, version, source = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
record = json.loads((directory / 'windows-signing.json').read_text())
name = f'netcap-nodpi-v{version}-windows-amd64.tar.gz'
if (record['version'], record['sourceRevision'], record['certificateSerial']) != (version, source, SERIAL):
    raise ValueError('CLI signing receipt identity mismatch')
if record['artifacts'].get(name) != sha(directory / name):
    raise ValueError('CLI archive checksum mismatch')
with tarfile.open(directory / name) as archive, tempfile.TemporaryDirectory() as work:
    binaries = [m for m in archive.getmembers() if m.name.endswith(('.exe', '.dll'))]
    if len(binaries) != 1 or binaries[0].name != 'net.exe' or not binaries[0].isfile():
        raise ValueError('unexpected CLI executable inventory')
    binary = Path(work) / 'net.exe'
    binary.write_bytes(archive.extractfile(binaries[0]).read())
    if sha(binary) != record['payload']['net.exe']['signedSHA256']:
        raise ValueError('CLI executable checksum mismatch')
    verify(binary)
print('Verified signed Netcap CLI archive: ' + version)
