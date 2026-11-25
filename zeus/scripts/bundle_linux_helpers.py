import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def package(image, supplier, version, commit, mode, suffix):
    def run(*args):
        subprocess.run(args, check=True)

    for ref in (image, supplier):
        run('docker', 'pull', '--platform', 'linux/amd64', ref)
    prefix = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none']
    stamp = subprocess.check_output(prefix + ['--entrypoint', '/usr/bin/net', image, '--version'], text=True)
    if not re.search(r'\bv?' + re.escape(version) + r'\b', stamp) or commit[:7] not in stamp:
        raise ValueError(f'candidate identity differs from v{version} / {commit[:7]}')

    name = f"netcap-{'nodpi-' if mode == 'nodpi' else ''}v{version}-linux-amd64-{suffix}"
    base = Path('dist-linux').resolve()
    dest = base / name
    dest.mkdir(parents=True, exist_ok=False)
    run(sys.executable, 'zeus/scripts/bundle-linux-runtime.py', image, str(dest))
    shutil.copy2('LICENSE', dest)
    shutil.copy2('README.md', dest)
    shutil.copytree('legal', dest / 'legal')
    run(sys.executable, 'scripts/stage-release-docs.py', 'docs', str(dest / 'docs'))
    run(sys.executable, 'zeus/scripts/audit-linux-runtime.py', image, str(dest), '--supplier-image', supplier)
    run(sys.executable, 'scripts/strip-linux-runtime.py', '--objcopy', os.environ.get('ELF_OBJCOPY', 'llvm-objcopy'),
        '--strip', os.environ.get('ELF_STRIP', 'llvm-strip'), '--debug-dir', f'dist-linux-symbols/{name}',
        '--inventory', str(dest / 'runtime-inventory.json'), str(dest / 'lib'))
    run(sys.executable, 'scripts/check-binary-hygiene.py', str(dest / 'lib'))
    run(*prefix, '-v', str(dest) + ':/release:ro', '--entrypoint', '/release/net', image, '--version')
    archive = base / (name + '.tar.gz')
    subprocess.run(['tar', '--no-xattrs', '-czf', archive, '-C', base, name], check=True,
                   env=dict(os.environ, COPYFILE_DISABLE='1'))
    run(sys.executable, 'scripts/check-release-archive.py', str(archive))
    with archive.open('rb') as payload, (base / 'checksums.txt').open('a') as checksums:
        checksums.write(f"{hashlib.file_digest(payload, 'sha256').hexdigest()}  {archive.name}\n")
    shutil.rmtree(dest)
