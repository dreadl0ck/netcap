#!/usr/bin/env python3
"""Docker CLI adapter used only by the native candidate qualification worker."""
import os
from pathlib import Path
import sys

root = Path(os.environ['NETCAP_QUAL_ROOT']).resolve(strict=True)
if (root / '.owner').read_text() != 'netcap-native-qualification/v1':
    raise ValueError('unowned qualification directory')
runtime = Path(os.environ['NETCAP_QUAL_RUNTIME']).resolve(strict=True)
runtime.relative_to(root)
arguments = sys.argv[1:]
command = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--cpus=2', '--memory=2g', '--pids-limit=256',
           '--cidfile', str(root / ('container-' + str(os.getpid()) + '.cid')),
           '--cap-drop=ALL', '--security-opt=no-new-privileges', '--label', 'netcap.qualification=final-native',
           '--label', 'netcap.qualification.owner=' + root.name,
           '-v', f'{root}:{root}', '-v', f'{runtime}:{runtime}:ro', '-e', 'HOME', '-e', 'NC_CONFIG_ROOT', '-e', 'GOMAXPROCS=2', '-e', 'RAYON_NUM_THREADS=2']
if '-service' in arguments:
    index = arguments.index('-http') + 1
    port = arguments[index].rsplit(':', 1)[1]
    arguments[index] = '0.0.0.0:7070'
    command += ['-p', f'127.0.0.1:{port}:7070']
else:
    command += ['--network=none']
command += ['--entrypoint', str(runtime / 'net'), os.environ['NETCAP_QUAL_IMAGE'], *arguments]
os.execvp(command[0], command)
