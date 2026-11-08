"""Authenticate a bundled YARA-X library against the selected builder inputs."""
import hashlib
from pathlib import Path
import subprocess


def yara_evidence(image, library, root=None):
    root = Path(root) if root else Path(__file__).resolve().parents[2]
    command = 'sha256sum /usr/local/lib/libyara_x_capi.so; pkg-config --modversion yara_x_capi; cat /opt/netcap-native/yara-x.env; sha256sum /opt/netcap-native/build-yara-x.sh /opt/netcap-native/install-yara-rust.sh'
    output = subprocess.check_output(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--cpus=2', '--network=none', '--entrypoint', 'sh', image, '-ec', command], text=True)
    lines = output.splitlines()
    expected = dict(line.split('=', 1) for line in (root / 'scripts/yara-x.env').read_text().splitlines() if '=' in line)
    actual = dict(line.split('=', 1) for line in lines[2:] if '=' in line)
    if actual != expected or lines[1] != expected['YARA_X_VERSION']:
        raise ValueError('supplier YARA-X version/source pins differ from this release')
    library_hash = hashlib.sha256(Path(library).read_bytes()).hexdigest()
    if lines[0].split()[0] != library_hash:
        raise ValueError('bundled YARA-X bytes differ from the selected supplier')
    recipes = {}
    for recipe in ('build-yara-x.sh', 'install-yara-rust.sh'):
        digest = hashlib.sha256((root / 'scripts' / recipe).read_bytes()).hexdigest()
        if not any(line.split() == [digest, '/opt/netcap-native/' + recipe] for line in lines[2:] if '=' not in line):
            raise ValueError('supplier YARA-X recipe differs from this release: ' + recipe)
        recipes[recipe] = digest
    return dict(requiresSupplierEvidence=False, license='BSD-3-Clause',
                correspondingSource='https://github.com/VirusTotal/yara-x/archive/refs/tags/v' + expected['YARA_X_VERSION'] + '.tar.gz',
                sourceSHA256=expected['YARA_X_SHA256'], supplierLibrarySHA256=library_hash,
                supplierRecipes=recipes, supplierVersion=lines[1])
