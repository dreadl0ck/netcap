#!/usr/bin/env python3
"""Package the verified sources selected by the macOS runtime bundler."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('version')
a=p.parse_args()
root=Path(__file__).resolve().parents[2]
sources=root/'dist-macos-sources'
files=set()
for variant in ['dpi','nodpi']:
    inventory=sources/('inventory-'+variant+'.json')
    files.add(inventory)
    for record in json.loads(inventory.read_text()):
        archive=sources/record['archive']
        if archive.parent!=sources or hashlib.sha256(archive.read_bytes()).hexdigest()!=record['sha256']:raise ValueError('changed source archive')
        files.add(archive)
        if record['package']=='yara-x':
            for recipe in ('yara-x.env','build-yara-x.sh','install-yara-rust.sh'):
                files.add(sources/recipe)
        else:
            files.add(sources/(record['package']+'-'+record['version']+'.rb'))
name='netcap-macos-runtime-source-v'+a.version
destination=sources/(name+'.tar.gz')
with destination.open('wb') as output,gzip.GzipFile(fileobj=output,mode='wb',mtime=0,filename='') as gz,tarfile.open(fileobj=gz,mode='w',format=tarfile.PAX_FORMAT) as tar:
    for file in sorted(files):
        if file.is_symlink() or not file.is_file():raise ValueError('non-regular source member')
        data=file.read_bytes()
        member=tarfile.TarInfo(name+'/'+file.name)
        member.size=len(data);member.mode=0o644;member.mtime=0
        tar.addfile(member,io.BytesIO(data))
print(destination)
