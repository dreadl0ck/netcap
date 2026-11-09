#!/usr/bin/env python3
"""Replay checksum-pinned MTA receipts; retain logs and counts, never secret values."""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import time
from collections import Counter


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def receipts(args):
    if args.inputs:
        paths=sorted(p for p in args.inputs.rglob('*') if p.is_file() and p.suffix.lower() in {'.pcap','.pcapng','.cap','.gz'})
        if len({p.stem for p in paths})!=len(paths):
            raise ValueError('input basenames must be unique within a group')
        return [dict(date=args.group,pcap=p.name,sourcePath=str(p.resolve()),sha256=sha(p)) for p in paths]
    return [r for path in sorted(args.root.glob('*/receipts.json')) for r in json.loads(path.read_text()) if not args.dates or r['date'] in args.dates.split(',')]


def capture_path(root, receipt):
    return Path(receipt['sourcePath']) if 'sourcePath' in receipt else root / receipt['date'] / Path(receipt['pcap']).name


def completed_rows(output, inputs, binary_hash, root):
    previous=json.loads((output/'results.json').read_text())
    if previous['binarySHA256']!=binary_hash:
        raise ValueError('cannot resume with a different binary')
    expected={(r['date'],Path(r['pcap']).name):r for r in inputs}
    rows=[]
    for row in previous['rows']:
        if row.get('exit')!=0 or row['errors']: continue
        key=(row['date'],row['pcap'])
        receipt=expected.get(key)
        if receipt is None or receipt['sha256']!=row['sha256']:
            raise ValueError('cannot resume changed capture receipts: '+row['pcap'])
        if sha(capture_path(root,receipt))!=row['sha256']:
            raise ValueError('cannot resume changed capture bytes: '+row['pcap'])
        rows.append(row)
    return rows


def store_results(output, binary_hash, rows):
    temporary=output/'results.json.pending'
    temporary.write_text(json.dumps(dict(binarySHA256=binary_hash,rows=rows),indent=2)+'\n')
    temporary.replace(output/'results.json')


def replay(binary, root, output, receipt):
    source = capture_path(root, receipt)
    if sha(source) != receipt['sha256']:
        raise ValueError('capture checksum mismatch: ' + str(source))
    destination = output / receipt['date'] / source.stem
    destination.mkdir(parents=True, mode=0o700)
    started = time.monotonic()
    with (destination / 'run.log').open('w') as log:
        result = subprocess.run([str(binary), 'capture', '--read', str(source), '--out', str(destination / 'audit'), '--workers', '4', '--quiet', '--http', '', '--fileStorage', 'files'], stdout=log, stderr=log, timeout=900)
    row = dict(date=receipt['date'], pcap=source.name, sha256=receipt['sha256'], exit=result.returncode, seconds=time.monotonic()-started, counts={}, errors=[])
    audit = destination / 'audit'
    corpus = []
    if 'PANIC' in (destination / 'run.log').read_text():
        row['errors'].append('panic')
    for path in sorted(audit.glob('*.ncap*')):
        result = subprocess.run([str(binary), 'dump', '--read', str(path), '--json'], capture_output=True, text=True, timeout=180)
        kind = path.name.split('.')[0]
        if kind not in {'Ethernet','IPv4','IPv6','TCP','UDP','TLSRecord','ICMPv4','ICMPv6','ARP','IGMP','LinkFlow','NetworkFlow','TransportFlow','Payload','SCTP','LLC','Dot1Q'}:
            corpus.append(result.stdout)
        records = [json.loads(line) for line in result.stdout.split('\n') if line.startswith('{')]
        row['counts'][kind] = len(records)
        if result.returncode or 'invalid netcap header' in result.stderr or 'unexpected EOF' in result.stderr:
            row['errors'].append(kind + ': unreadable')
        if kind == 'Secret':
            row['redisSMTP'] = sum(r.get('Service') == 'Redis' and any(p in r.get('Flow', '') for p in (':25->', ':587->', ':25', ':587')) for r in records)
        if kind == 'TLSClientHello':
            row['protonmailHellos'] = sum(r.get('SNI') == 'mail.protonmail.com' for r in records)
    row['hosts'] = (audit / 'Hosts.json').exists()
    if not row['hosts']:
        row['errors'].append('missing Hosts.json')
    else:
        corpus.append((audit / 'Hosts.json').read_text())
    for path in audit.glob('files/**/*'):
        if path.is_file():
            with path.open('rb') as stream:
                md5 = hashlib.file_digest(stream, 'md5').hexdigest()
            corpus.append('FILEHASH ' + sha(path) + ' ' + md5 + ' ' + path.name)
    (destination / 'audit.nccorpus.txt').write_text('\n'.join(corpus))
    (destination / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
    return row


def summarize(root, baseline=None, binary=None):
    rows=json.loads((root/'results.json').read_text())['rows']
    totals=Counter()
    for row in rows: totals.update(row.get('counts',{}))
    report=dict(captures=len(rows),successful=sum(r.get('exit')==0 and not r['errors'] for r in rows),errors=[dict(pcap=r['pcap'],exit=r.get('exit'),errors=r['errors']) for r in rows if r.get('exit')!=0 or r['errors']],captureSeconds=sum(r.get('seconds',0) for r in rows),counts=dict(totals),redisSMTP=sum(r.get('redisSMTP',0) for r in rows))
    if baseline:
        def files(directory):
            by_capture={}
            for path in directory.glob('*/*/audit.nccorpus.txt'):
                hashes={line.split()[1] for line in path.read_text().split('\n') if line.startswith('FILEHASH ')}
                by_capture[(path.parent.parent.name,path.parent.name)]=hashes
            return by_capture
        old,new=files(baseline),files(root)
        missing={key:hashes-new.get(key,set()) for key,hashes in old.items() if hashes-new.get(key,set())}
        report['baselineArtifactComparison']=dict(comparedCaptures=len(old.keys()&new.keys()),missingCaptures=[list(key) for key in sorted(old.keys()-new.keys())],capturesWithMissingFiles=len(missing),missingUniqueHashes=len(set().union(*missing.values())) if missing else 0,missingByCapture={str(key):len(hashes) for key,hashes in missing.items()})
        if binary:
            details=[]
            for (date,name),hashes in missing.items():
                path=baseline/date/name/'audit/File.ncap.gz'
                result=subprocess.run([str(binary.resolve()),'dump','--read',str(path),'--json'],capture_output=True,text=True,timeout=180)
                for line in result.stdout.split('\n'):
                    if line.startswith('{'):
                        record=json.loads(line)
                        if record.get('Hashes',{}).get('SHA256') in hashes:
                            details.append(dict(date=date,pcap=name,**record))
            (root/'missing-files.json').write_text(json.dumps(details,indent=2)+'\n')
    (root/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    comparison=report.get('baselineArtifactComparison',{})
    return int(not rows or report['successful']!=len(rows) or bool(comparison.get('missingCaptures')) or bool(comparison.get('missingUniqueHashes')))


def reference(args):
    scorer=args.scoring_repo/'scripts/httpcmp.py'
    source=scorer.read_text().replace('capture_output=True','check=True,capture_output=True')
    source,count=re.subn(r'^o=(subprocess\.run\(.*\)\.stdout)$',r"o=(\1 if os.path.exists(os.path.join(D,'HTTP.ncap.gz')) else '')",source,flags=re.M)
    if count!=1: raise ValueError('HTTP scorer audit adapter no longer matches')
    adapted=args.output/'scoring-httpcmp.py'
    adapted.write_text(source)
    inputs=receipts(args)
    def run(r):
        source=capture_path(args.root,r)
        audit=args.output/r['date']/source.stem/'audit'
        if sha(source)!=r['sha256']: raise ValueError('capture checksum changed')
        env=dict(os.environ,NETBIN=str(args.binary.resolve()))
        result=subprocess.run(['python3',str(adapted),str(source),str(audit)],env=env,capture_output=True,text=True,timeout=300,check=True)
        data=json.loads(result.stdout)
        (audit.parent/'http-reference.json').write_text(json.dumps(data,indent=2)+'\n')
        return dict(pcap=source.name,**data)
    rows=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for row in pool.map(run,inputs): rows.append(row)
    report=dict(scorerSHA256=sha(scorer),captures=len(rows),totals={key:sum(r[key] for r in rows) for key in ('ts','nc','missing','extra','comma')},missing=[dict(pcap=r['pcap'],count=r['missing']) for r in rows if r['missing']])
    (args.output/'reference-summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return int(not rows or report['totals']['missing']!=0)


def questions(args):
    path=args.scoring_repo/'scripts/qcheck16.py'
    source=path.read_text()
    source=source.replace("rows=json.load(open('notes/r13-allrows.json'))","rows=json.load(open(os.environ['MTA_QUESTION_ROWS']))")
    source,count=re.subn(r'def dirs\(date\):.*?(?=def hosts\(d\):)',"def dirs(date):\n    return sorted(glob.glob(os.path.join(os.environ['MTA_RUN_ROOT'],date,'*','audit','')))\n",source,flags=re.S)
    if count!=1: raise ValueError('question scorer directory adapter no longer matches')
    source=source.replace("'notes/v162-qcheck.json'","os.environ['MTA_QUESTION_OUTPUT']")
    source,count=re.subn(r'def cnt\(d,t\):\n',"def cnt(d,t):\n    if not os.path.exists(d+t+'.ncap.gz'): return []\n",source)
    if count!=1: raise ValueError('question scorer audit adapter no longer matches')
    source=source.replace('capture_output=True','check=True,capture_output=True')
    adapted=args.output/'scoring-qcheck.py'
    adapted.write_text(source)
    env=dict(os.environ,NETBIN=str(args.binary.resolve()),MTA_RUN_ROOT=str(args.output.resolve()),MTA_QUESTION_ROWS=str((args.scoring_repo/'data/r13-allrows.json').resolve()),MTA_QUESTION_OUTPUT=str((args.output/'questions.json').resolve()))
    with (args.output/'questions.log').open('w') as log:
        subprocess.run(['python3',str(adapted)],env=env,stdout=log,stderr=log,check=True,timeout=300)
    rows=json.loads((args.output/'questions.json').read_text())
    report=dict(scorerSHA256=sha(path),checks=len(rows),evaluated=sum(r['new']!='?' for r in rows),outcomes=dict(Counter(r['new'] for r in rows)),nonLiteralExpectations=[dict(date=r['date'],question=r['q'],expected=r['exp']) for r in rows if re.fullmatch(r'all\s+\d+',r['exp'],re.I)])
    if args.baseline:
        previous={(r['date'],r['q']):r['new'] for r in json.loads((args.baseline/'questions.json').read_text())}
        report['regressions']=[dict(date=r['date'],question=r['q'],before=previous[(r['date'],r['q'])],after=r['new']) for r in rows if previous.get((r['date'],r['q']))=='ok' and r['new']!='ok']
    (args.output/'questions-summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(checks=report['checks'],outcomes=report['outcomes'],regressions=len(report.get('regressions',[]))),indent=2))
    return int(bool(report.get('regressions')))


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path)
    p.add_argument('--root', type=Path)
    p.add_argument('--inputs', type=Path, help='replay a directory of external captures and record their checksums')
    p.add_argument('--group', default='external')
    p.add_argument('--output', type=Path)
    p.add_argument('--summary', type=Path)
    p.add_argument('--baseline', type=Path)
    p.add_argument('--inventory-report', type=Path)
    p.add_argument('--reference', action='store_true')
    p.add_argument('--questions', action='store_true')
    p.add_argument('--scoring-repo', type=Path)
    p.add_argument('--dates', default='')
    p.add_argument('--jobs', type=int, default=2)
    p.add_argument('--resume', action='store_true', help='resume the same binary and receipts after an interrupted replay')
    args = p.parse_args()
    if args.inputs:
        args.root=args.inputs
        if not args.group or Path(args.group).name!=args.group or args.group in {'.','..'}: p.error('--group must be one directory name')
    if args.summary: return summarize(args.summary,args.baseline,args.binary)
    if args.questions:
        if not all((args.binary,args.output,args.scoring_repo)): p.error('--questions requires --binary, --output and --scoring-repo')
        return questions(args)
    if args.reference:
        if not all((args.binary,args.root,args.output,args.scoring_repo)): p.error('--reference requires --binary, --root, --output and --scoring-repo')
        return reference(args)
    if args.inventory_report:
        if not args.root: p.error('--root is required')
        expected={date:int(n) for date,n in re.findall(r'^\|\s*\d+\s*\|\s*(20\d\d-\d\d-\d\d)\s*\|\s*\d+\s*\|[^|\n]*\|\s*(\d+)\s*\|',args.inventory_report.read_text(),re.M)}
        actual={path.parent.name:len(json.loads(path.read_text())) for path in args.root.glob('*/receipts.json')}
        print(json.dumps(dict(expected=sum(expected.values()),actual=sum(actual.values()),differences={date:dict(expected=n,actual=actual.get(date,0)) for date,n in expected.items() if actual.get(date,0)!=n}),indent=2))
        return 0
    if not args.binary or not args.root or not args.output: p.error('--binary, --root and --output are required for replay')
    inputs = receipts(args)
    if not inputs: p.error('no capture receipts found')
    binary_hash=sha(args.binary)
    rows=completed_rows(args.output,inputs,binary_hash,args.root) if args.resume else []
    done={(r['date'],r['pcap']) for r in rows}
    args.output.mkdir(parents=True, mode=0o700, exist_ok=args.resume)
    (args.output/'receipts.json').write_text(json.dumps(inputs,indent=2)+'\n')
    pending=[r for r in inputs if (r['date'],Path(r['pcap']).name) not in done]
    if args.resume:
        for r in pending:
            destination=args.output/r['date']/Path(r['pcap']).stem
            if destination.exists():
                archived=args.output/'.interrupted'/r['date']/(destination.name+'-'+str(time.time_ns()))
                archived.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
                destination.rename(archived)
    store_results(args.output,binary_hash,rows)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(replay, args.binary.resolve(), args.root, args.output, r): r for r in pending}
        for future in concurrent.futures.as_completed(futures):
            try:
                row = future.result()
            except Exception as error:
                receipt=futures[future]
                row = dict(date=receipt['date'],pcap=Path(receipt['pcap']).name,sha256=receipt['sha256'],errors=[str(error)])
            rows.append(row)
            print(json.dumps(row), flush=True)
            store_results(args.output,binary_hash,rows)
    return int(any(r.get('exit') != 0 or r['errors'] for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())
