#!/usr/bin/env python3
"""Relocate the actual Homebrew dependency closure and retain exact supplier source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('binary',type=Path)
p.add_argument('--variant',required=True,choices=['dpi','nodpi'])
a=p.parse_args()
binary=a.binary.resolve(strict=True)
root=Path(__file__).resolve().parents[2]
export=root/'dist-macos-runtime'/a.variant
if export.exists():
    if (export/'.generated-by').read_text()!='bundle-macos-runtime/v1':p.error('unowned runtime staging directory')
    shutil.rmtree(export)
(export/'lib').mkdir(parents=True)
(export/'.generated-by').write_text('bundle-macos-runtime/v1')
lib=binary.parent/'lib'
lib.mkdir(exist_ok=True)
sources=root/'dist-macos-sources'
sources.mkdir(exist_ok=True)

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def deps(path):
    out=subprocess.check_output(['otool','-L',str(path)],text=True)
    return [line.strip().split(' (',1)[0] for line in out.splitlines()[1:] if line.strip()]

def minimum_os(path):
    out=subprocess.check_output(['vtool','-show-build',str(path)],text=True)
    value=re.search(r'\bminos\s+(\d+(?:\.\d+)+)',out)
    if not value:raise ValueError('missing Mach-O minimum OS '+str(path))
    return value.group(1)

def fetch(url,digest,destination):
    if destination.exists():
        if sha(destination)!=digest:raise ValueError('changed cached source '+str(destination))
        return
    if url.startswith('http://'):url='https://'+url[7:]
    if not url.startswith('https://'):raise ValueError('non-HTTPS source URL')
    h=hashlib.sha256();size=0
    with tempfile.NamedTemporaryFile(dir=sources,delete=False) as out:
        temporary=Path(out.name)
        with urllib.request.urlopen(url,timeout=120) as response:
            while block:=response.read(1024*1024):
                size+=len(block)
                if size>4<<30:raise ValueError('source archive exceeds bound')
                h.update(block);out.write(block)
    if h.hexdigest()!=digest:raise ValueError('supplier source digest mismatch '+url)
    os.replace(temporary,destination)

pending=[binary];copied={};records=[];source_records={}
while pending:
    path=pending.pop()
    for dependency in deps(path):
        if dependency.startswith(('/usr/lib/','/System/')):continue
        if not dependency.startswith('/opt/homebrew/'):raise ValueError('unresolved native dependency '+dependency)
        if dependency in copied:continue
        original=Path(dependency).resolve(strict=True)
        destination=lib/original.name
        if destination.exists() and sha(destination)!=sha(original):raise ValueError('dependency basename collision')
        shutil.copyfile(original,destination)
        copied[dependency]=destination
        pending.append(original)
        parts=original.parts
        index=parts.index('Cellar')
        package,version=parts[index+1:index+3]
        keg=Path(*parts[:index+3])
        formula=keg/'.brew'/(package+'.rb')
        text=formula.read_text()
        source_url=re.search(r'^\s*url "([^"\n]+)"',text,re.M)
        if not source_url:raise ValueError('missing exact supplier source '+package)
        source_hash=re.search(r'^\s*sha256 "([0-9a-f]{64})"',text[source_url.end():],re.M)
        if not source_hash:raise ValueError('missing supplier source hash '+package)
        url=source_url.group(1)
        if '#{' in url:raise ValueError('unresolved supplier URL expression '+package)
        suffix='.tar.xz' if '.tar.xz' in url else '.tar.gz' if ('.tar.gz' in url or '/archive/' in url) else '.source'
        archive=sources/(package+'-'+version+suffix)
        fetch(url,source_hash.group(1),archive)
        shutil.copyfile(formula,sources/(package+'-'+version+'.rb'))
        source_records[package]={'package':package,'version':version,'url':url,'sha256':source_hash.group(1),'archive':archive.name}
        records.append({'file':'lib/'+destination.name,'originalPath':dependency,'originalSHA256':sha(original),'package':package,'version':version,'source':source_records[package],'minimumOS':minimum_os(original)})

for path in [binary,*set(copied.values())]:
    changes=[]
    for dependency in deps(path):
        if dependency.startswith(('/usr/lib/','/System/')):continue
        destination=copied[dependency]
        replacement=('@executable_path/lib/' if path==binary else '@loader_path/')+destination.name
        changes.extend(['-change',dependency,replacement])
    if changes:subprocess.run(['install_name_tool',*changes,str(path)],check=True)
    if path!=binary:subprocess.run(['install_name_tool','-id','@loader_path/'+path.name,str(path)],check=True)
    subprocess.run(['codesign','--force','--sign','-',str(path)],check=True)
    subprocess.run(['codesign','--verify',str(path)],check=True)
for record in records:
    file=lib/Path(record['file']).name
    record['sha256']=sha(file)
    shutil.copyfile(file,export/record['file'])
minimum=minimum_os(binary)
if any(tuple(map(int,r['minimumOS'].split('.')))>tuple(map(int,minimum.split('.'))) for r in records):raise ValueError('native library exceeds advertised binary minimum OS')
(export/'inventory.json').write_text(json.dumps({'format':'netcap-macos-runtime/v1','minimumOS':minimum,'files':records},indent=2)+'\n')
notice=['NETCAP MACOS NATIVE RUNTIME','Libraries are dynamically linked and replaceable with compatible modified versions.','Full corresponding supplier sources and Homebrew build recipes are in the macOS runtime source archive.','Native library install names were relocated by Netcap to @loader_path; no library code was modified.','']
for source in sorted(source_records.values(),key=lambda s:s['package']):
    notice.append(json.dumps(source,sort_keys=True))
    archive=sources/source['archive']
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if member.isfile() and len(Path(member.name).parts)<=3 and Path(member.name).name.upper().startswith(('LICENSE','LICENCE','COPYING','COPYRIGHT','NOTICE')) and member.size<=1<<20:
                notice.extend([member.name,tar.extractfile(member).read().decode(errors='replace'),''])
(export/'NOTICES.txt').write_text('\n'.join(notice)+'\n')
(sources/('inventory-'+a.variant+'.json')).write_text(json.dumps(list(source_records.values()),indent=2)+'\n')
print('Relocated',len(records),'native libraries for',a.variant)
