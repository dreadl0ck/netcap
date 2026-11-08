"""Authenticate a bundled YARA-X library against the selected builder inputs."""
import hashlib
from pathlib import Path
import subprocess


UBUNTU_LIBRARIES = {
    'libprotoident.so.2': ('LibtraceTeam/libprotoident', 'PROTOIDENT_VERSION', '2.0.15-2', '2b43a492fe1d7ada2e7b7b164c8e35220b35bf816bd971c7f77decc74b69801e'),
    'libtrace.so.7': ('LibtraceTeam/libtrace', 'LIBTRACE_VERSION', '4.0.34-1', 'b3e73b9ca6757094047295937ab4d834155a0c64674f499132b56e8f81f8fcc9'),
    'libwandio.so.6': ('LibtraceTeam/wandio', 'WANDIO_VERSION', '4.2.7-1', '45021795b5c4d1609ba509358e730ea605c4c9621704d75214abb003f37602ab'),
}


def libtrace_evidence(image, library, history):
    library = Path(library)
    repo, argument, version, source_hash = UBUNTU_LIBRARIES[library.name]
    if argument + '=' + version not in history or source_hash not in history or 'https://github.com/' + repo + '/archive/refs/tags/' not in history:
        raise ValueError('supplier build history does not confirm source/version/hash for ' + library.name)
    output = subprocess.check_output(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--cpus=2', '--network=none', '--entrypoint', 'sha256sum', image, '/usr/local/lib/' + library.name], text=True)
    digest = hashlib.sha256(library.read_bytes()).hexdigest()
    if output.split()[0] != digest:
        raise ValueError('bundled native library bytes differ from the selected supplier')
    return dict(requiresSupplierEvidence=False, license='LGPL-3.0-or-later',
                correspondingSource='https://github.com/' + repo + '/archive/refs/tags/' + version + '.tar.gz',
                sourceSHA256=source_hash, supplierLibrarySHA256=digest, supplierVersion=version,
                supplierBuildArgument=argument + '=' + version)


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
