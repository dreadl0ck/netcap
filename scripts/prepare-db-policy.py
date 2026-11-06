#!/usr/bin/env python3
"""Prepare an operator-reviewable source policy from an existing reviewed registry."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request

p=argparse.ArgumentParser(description=__doc__)
p.add_argument("registry",type=Path)
p.add_argument("output",type=Path)
args=p.parse_args()
reviews=json.loads(args.registry.read_text())
rules=[]
for review in reviews:
    evidence=review['evidence']
    if evidence['id']=='nvd':
        evidence['transformation']='netcap-nvd-v3.6: frozen complete nonempty NVD 2.0 yearly gzip inputs with per-year counts, NVD-only SQLite schema 2 with structured CPE applicability, nvd_rowid_alias_version=1 valid foreign keys and nvd_references_version=1 HTTP(S) link metadata, sorted metadata without wall-clock fields'
    # This permission is deliberately limited to the exact acquisition and transformation.
    rule={'evidence':evidence,'files':[f['path'] for f in review['outputs']]}
    if evidence['id']=='ua-parser':rule['pinned_revision']=evidence['revision']
    rules.append(rule)
revision='b9324b2bfa2ad8bd9671b49dd2d58ea193591e60'
origin=f'https://raw.githubusercontent.com/0x4D31/hassh-utils/{revision}/hasshdb'
grant_origin=f'https://raw.githubusercontent.com/0x4D31/hassh-utils/{revision}/LICENSE'
with urllib.request.urlopen(origin,timeout=60) as r: source=r.read()
with urllib.request.urlopen(grant_origin,timeout=60) as r: grant=r.read().decode()
assert 'Adel' in grant and 'Redistribution and use' in grant and 'Neither the name' in grant
sha=lambda b:hashlib.sha256(b).hexdigest()
rules.append({'evidence':{'id':'hassh','origin':origin,'revision':sha(source),'sha256':sha(source),'transformation':'netcap-hassh-v1: parse pinned upstream hash/banner/percentage lines, sort hashes, preserve banner and likelihood strings as legacy JSON','grant_origin':grant_origin,'grant_revision':revision,'grant_text':grant,'grant_sha256':sha(grant.encode()),'notice_text':"Copyright (c) 2018, Adel '0x4d31' Karimi. BSD-3-Clause. Netcap transforms the pinned HASSH database text to JSON; original banners and likelihoods are retained."},'files':['hasshdb.json'],'pinned_revision':sha(source)})
expiry=int((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=60)).timestamp())
policy={'format':'netcap-source-policy/v1','expires_at':expiry,'rules':rules,'minimum_nvd_count':400000}
args.output.write_text(json.dumps(policy,indent=2)+'\n')
print(sha(args.output.read_bytes()))
