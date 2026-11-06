#!/usr/bin/env python3
"""Prune owned acquisition directories after seven days; retain signed release objects."""
import argparse
from pathlib import Path
import shutil
import time

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('root',type=Path)
p.add_argument('--apply',action='store_true')
a=p.parse_args()
root=a.root.resolve(strict=True)
if root==Path('/') or not (root/'v3/signed-latest.json').is_file():p.error('validated publication root required')
for build in sorted(root.glob('build-*')):
    if build.is_symlink() or not build.is_dir() or not (build/'acquisition.log').is_file():continue
    if time.time()-build.stat().st_mtime<7*86400:continue
    print(('remove ' if a.apply else 'would remove ')+str(build))
    if a.apply:shutil.rmtree(build)
