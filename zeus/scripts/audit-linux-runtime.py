#!/usr/bin/env python3
"""Record exact image/library identities and package copyright notices."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('image')
p.add_argument('destination',type=Path)
p.add_argument('--supplier-image',help='builder image for libraries copied into the runtime')
a=p.parse_args()
dest=a.destination.resolve()
lib=dest/'lib'
if not lib.is_dir():p.error('bundled lib directory is required')
inspect=json.loads(subprocess.check_output(['docker','image','inspect',a.image]))[0]
history=subprocess.check_output(['docker','history','--no-trunc','--format','{{.CreatedBy}}',a.supplier_image or a.image],text=True)
notices=dest/'legal/runtime'
notices.mkdir(parents=True,exist_ok=True)
inventory=[]
for file in sorted(lib.iterdir()):
    if not file.is_file() or file.name=='net.bin':continue
    query='''set -eu
name="$1"
if command -v dpkg-query >/dev/null 2>&1; then
  package=$(dpkg-query -S "*/$name" 2>/dev/null | grep -v '^diversion ' | cut -d: -f1 | sort -u | head -n1)
  test -n "$package"
  dpkg-query -W -f='${Package}\n${Version}\n${source:Package}\n${source:Version}\n' "$package"
  test -f "/usr/share/doc/$package/copyright"
  cat "/usr/share/doc/$package/copyright"
elif command -v apk >/dev/null 2>&1; then
  path=$(find /lib /usr/lib -name "$name" -print -quit)
  test -n "$path"
  apk info --who-owns "$path"
  package=$(apk info --who-owns "$path" | sed 's/.* owned by //')
  apk info --all "${package%-[0-9]*}"
else exit 3; fi
'''
    result=subprocess.run(['docker','run','--rm','--entrypoint','sh',a.image,'-c',query,'sh',file.name],text=True,capture_output=True)
    evidence_image=a.image
    if result.returncode and a.supplier_image:
        result=subprocess.run(['docker','run','--rm','--entrypoint','sh',a.supplier_image,'-c',query,'sh',file.name],text=True,capture_output=True)
        evidence_image=a.supplier_image
    owned=result.returncode==0
    record={'file':'lib/'+file.name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'size':file.stat().st_size,'packageEvidence':result.stdout.strip(),'evidenceImage':evidence_image,'requiresSupplierEvidence':not owned}
    if not owned and file.name=='libndpi.so.4':
        record.update(requiresSupplierEvidence=False,correspondingSource='https://github.com/ntop/nDPI/archive/refs/tags/4.14.tar.gz',sourceSHA256='954135ee14ad6bd74a78a10db560b534b8f2083ad0615f5c1a2c376fff0301e0',license='LGPL-3.0-or-later')
        owned=True
    native={
        'libprotoident.so.2':('LibtraceTeam/libprotoident','2.0.15-1','cfa7c2d8db8e701db9f991e4f58fd9a284db65e866194ad54e413202163b7289'),
        'libtrace.so.7':('LibtraceTeam/libtrace','4.0.17-1','e3238661e5bf9133dd9f864c6d2f7a40c91ef07eada6d60f6defccea1d4536bd'),
        'libwandio.so.6':('LibtraceTeam/wandio','4.2.3-1','0b7499dd73fd167dfb35abe80b25b36fe757e51f7cbd8bf5810d24951ca41735'),
    }
    if not owned and 'alpine' in evidence_image and file.name in native:
        repo,version,source_hash=native[file.name]
        if ('/'+version+'.tar.gz') not in history:raise SystemExit('Supplier build history does not confirm '+file.name)
        record.update(requiresSupplierEvidence=False,correspondingSource=f'https://github.com/{repo}/archive/refs/tags/{version}.tar.gz',sourceSHA256=source_hash,license='LGPL-3.0-or-later')
        owned=True
    if owned and 'ubuntu' in evidence_image:
        fields=result.stdout.splitlines()
        if len(fields)>=4:record['correspondingSource']='https://launchpad.net/ubuntu/+source/'+fields[2]+'/'+fields[3]
    if owned:(notices/(file.name+'.txt')).write_text(result.stdout)
    inventory.append(record)
result={'image':a.image,'imageID':inspect['Id'],'repoDigests':inspect.get('RepoDigests',[]),'files':inventory}
(dest/'runtime-inventory.json').write_text(json.dumps(result,indent=2)+'\n')
for image in filter(None,[a.image,a.supplier_image]):
    for license_name in ['GPL-2','GPL-3','LGPL-2','LGPL-2.1','LGPL-3']:
        result=subprocess.run(['docker','run','--rm','--entrypoint','cat',image,'/usr/share/common-licenses/'+license_name],text=True,capture_output=True)
        if result.returncode==0:(notices/(license_name+'.txt')).write_text(result.stdout)
unresolved=[r['file'] for r in inventory if r['requiresSupplierEvidence']]
print(json.dumps({'libraries':len(inventory),'supplierEvidenceRequired':unresolved}))
if unresolved:raise SystemExit('Unidentified runtime libraries prevent release')
for name,url in {
    'musl-COPYRIGHT':'https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT?h=v1.2.5',
    'GCC-RUNTIME-EXCEPTION':'https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-15.2.0/COPYING.RUNTIME',
    'GPL-3.0':'https://raw.githubusercontent.com/spdx/license-list-data/v3.27.0/text/GPL-3.0-or-later.txt',
    'LGPL-2.1':'https://raw.githubusercontent.com/spdx/license-list-data/v3.27.0/text/LGPL-2.1-or-later.txt',
    'LGPL-3.0':'https://raw.githubusercontent.com/spdx/license-list-data/v3.27.0/text/LGPL-3.0-or-later.txt',
}.items():
    with urllib.request.urlopen(url,timeout=60) as response:body=response.read()
    (notices/(name+'.txt')).write_bytes(body)
