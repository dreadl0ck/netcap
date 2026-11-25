#!/usr/bin/env python3
"""Package digest-pinned Linux candidates built in Dokploy at the release tag."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from bundle_linux_helpers import package


def main():
    version, mode = sys.argv[1:]
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or mode not in ('dpi', 'nodpi'):
        raise ValueError('expected release version and dpi/nodpi mode')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    tag = subprocess.check_output(['git', 'rev-parse', f'v{version}^{{commit}}'], text=True).strip()
    if head != tag:
        raise ValueError(f'checkout is not the release tag v{version}')
    receipt = json.loads(Path(os.environ['NETCAP_RELEASE_IMAGES']).read_text())
    if receipt['commit'] != head:
        raise ValueError('Linux receipt refers to a different source commit')
    for distro, suffix in [('alpine', 'musl'), ('ubuntu', 'libc')]:
        image = receipt['images'][distro + ('-nodpi' if mode == 'nodpi' else '')]
        supplier = receipt['builders'][distro]
        for reference in (image, supplier):
            if not re.fullmatch(r'[\w./:-]+@sha256:[0-9a-f]{64}', reference):
                raise ValueError('Linux inputs must be digest-pinned')
        package(image, supplier, version, head, mode, suffix)


if __name__ == '__main__':
    main()
