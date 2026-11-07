#!/usr/bin/env python3
"""Download pinned upstream release binaries with upstream SHA256 verification."""
import argparse
import hashlib
import io
from pathlib import Path
import platform
import tarfile
import urllib.request
from firewall_release import POLICY, require


def install(destination):
    destination.mkdir(parents=True, exist_ok=True)
    system = platform.system().lower()
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
    for tool, repo, asset, checksum in [
        ('syft', 'anchore/syft', f'syft_{{v}}_{system}_{arch}.tar.gz', 'syft_{v}_checksums.txt'),
        ('goreleaser', 'goreleaser/goreleaser', f'goreleaser_{system.title()}_{arch}.tar.gz', 'checksums.txt'),
        ('helm', None, f'helm-{{tag}}-{system}-{arch}.tar.gz', None),
    ]:
        tag = POLICY['tools'][tool]
        name = asset.format(v=tag[1:], tag=tag)
        base = f'https://github.com/{repo}/releases/download/{tag}/' if repo else 'https://get.helm.sh/'
        checksum_name = checksum.format(v=tag[1:]) if checksum else name + '.sha256sum'
        sums = urllib.request.urlopen(base + checksum_name, timeout=60).read().decode()
        expected = [line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip('*') == name]
        require(len(expected) == 1, 'missing upstream checksum: ' + name)
        data = urllib.request.urlopen(base + name, timeout=120).read()
        require(hashlib.sha256(data).hexdigest() == expected[0], 'upstream checksum mismatch: ' + name)
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            members = [m for m in tf.getmembers() if Path(m.name).name == tool and m.isfile()]
            require(len(members) == 1, 'unexpected release archive layout')
            path = destination / tool
            path.write_bytes(tf.extractfile(members[0]).read())
            path.chmod(0o755)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('destination', type=Path)
    install(p.parse_args().destination)
