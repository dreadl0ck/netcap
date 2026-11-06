#!/usr/bin/env python3
"""Fetch only exercise PCAP archives and replay a report's corpus without executing artifacts."""
import argparse
import concurrent.futures
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import sys
import time
import urllib.parse
import urllib.request
import zipfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def report_dates(text):
    numbered = re.findall(r"^\|\s*\d+\s*\|\s*(20\d\d-\d\d-\d\d)\s*\|", text, re.M)
    return sorted(set(numbered or re.findall(r"^\|\s*(20\d\d-\d\d-\d\d)\s*\|", text, re.M)))


def report_counts(text):
    return {date: int(count) for date, count in re.findall(r"^\|\s*\d+\s*\|\s*(20\d\d-\d\d-\d\d)\s*\|\s*\d+\s*\|[^|\n]*\|\s*(\d+)\s*\|", text, re.M)}


def fetch(root, date, page=None):
    year, month, day = date.split("-")
    page = page or f"https://www.malware-traffic-analysis.net/{year}/{month}/{day}/index.html"
    with urllib.request.urlopen(page, timeout=60) as response:
        html = response.read(2 << 20).decode("utf-8", "replace")
    urls = set()
    for href in re.findall(r'href=[\"\x27]([^\"\x27]+)', html, re.I):
        url = urllib.parse.urljoin(page, href)
        parsed = urllib.parse.urlparse(url)
        name = parsed.path.rsplit("/", 1)[-1].lower()
        contains_pcap = "pcap" in name or name.endswith("-exercise-files.zip") and ".pcap" in html
        if parsed.netloc == "www.malware-traffic-analysis.net" and name.endswith(".zip") and contains_pcap and not any(x in name for x in ("malware", "email", "artifact")):
            urls.add(url)
    if not urls:
        raise RuntimeError("no PCAP archive links found")
    folder = root / date
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipts = []
    for url in sorted(urls):
        archive = folder / Path(urllib.parse.urlparse(url).path).name
        valid = False
        if archive.exists():
            try:
                with zipfile.ZipFile(archive) as z:
                    valid = bool(z.infolist())
            except zipfile.BadZipFile:
                pass
        if not valid:
            subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error", "--max-time", "240", "--retry", "2", "--continue-at", "-", "--output", str(archive), url], check=True, timeout=750)
        with zipfile.ZipFile(archive) as z:
            members = [m for m in z.infolist() if Path(m.filename).suffix.lower() in (".pcap", ".pcapng")]
            if not members or sum(m.file_size for m in members) > 2 << 30:
                raise RuntimeError("invalid bounded PCAP archive")
            for member in members:
                target = folder / Path(member.filename).name
                if not target.exists() or target.stat().st_size != member.file_size:
                    failure = None
                    for password in (f"infected_{year}{month}{day}".encode(), b"infected"):
                        try:
                            with z.open(member, pwd=password) as source, target.open("wb") as destination:
                                while block := source.read(1 << 20):
                                    destination.write(block)
                            failure = None
                            break
                        except (RuntimeError, zipfile.BadZipFile) as error:
                            failure = error
                    if failure:
                        target.unlink(missing_ok=True)
                        raise failure
                    target.chmod(0o600)
                with target.open("rb") as stream:
                    magic = stream.read(4)
                if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                    raise RuntimeError("extracted member is not a PCAP")
                receipts.append({"date": date, "page": page, "archive": url, "archiveSHA256": digest(archive), "pcap": str(target), "sha256": digest(target), "size": target.stat().st_size})
    (folder / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
    (folder / "receipts.json").chmod(0o600)
    return receipts


def records(binary, output, name):
    candidates = [output / (name + suffix) for suffix in (".ncap.gz", ".ncap")]
    path = next((p for p in candidates if p.exists()), None)
    if path is None:
        return []
    data = subprocess.check_output([str(binary), "dump", "--read", str(path), "--json"], text=True, timeout=120)
    return [json.loads(line) for line in data.splitlines()]


def replay(binary, root, receipt):
    source = Path(receipt["pcap"])
    if digest(source) != receipt["sha256"]:
        raise RuntimeError(f"capture checksum changed: {source.name}")
    output = Path(tempfile.mkdtemp(prefix=source.stem + ".netcap-", dir=source.parent))
    command = [str(binary), "capture", "--quiet", "--read", str(source), "--out", str(output), "--network-detection", "--fileStorage", "artifacts"]
    started = time.monotonic()
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    elapsed = time.monotonic() - started
    (source.parent / (source.stem + ".run.log")).write_text(result.stdout)
    (source.parent / (source.stem + ".run.log")).chmod(0o600)
    if result.returncode:
        raise RuntimeError(f"capture failed: {source.name}: exit {result.returncode}")
    metrics = {"pcap": str(source), "output": str(output), "sha256": receipt["sha256"], "exit": result.returncode, "captureSeconds": elapsed, "counts": {}}
    for kind in ("HTTP", "Connection", "DeviceProfile", "Kerberos", "LDAP", "SMB", "DCERPC", "TLSClientHello", "QUICClientHello", "SMTP", "POP3", "IMAP", "File", "Mail", "Alert", "Software", "Vulnerability", "Exploit", "Secret", "FTP", "IEC62351", "BACnetIP"):
        data = records(binary, output, kind)
        metrics["counts"][kind] = len(data)
        if kind == "HTTP":
            metrics["httpRequests"] = sum(bool(r.get("Method")) for r in data)
        if kind == "Kerberos":
            metrics["kerberosWithPrincipal"] = sum(bool(r.get("ClientName")) for r in data)
        if kind == "Alert":
            metrics["alertsByName"] = {name: sum(r.get("Name") == name for r in data) for name in sorted({r.get("Name", "") for r in data})}
        if kind == "Secret":
            metrics["smtpAuthExchanges"] = sum(r.get("Service", "").startswith("SMTP Auth") for r in data)
    metrics["hosts"] = json.loads((output / "Hosts.json").read_text())
    logs = list(output.glob("*.log"))
    metrics["logs"] = {"files": len(logs), "empty": sum(path.stat().st_size == 0 for path in logs)}
    return metrics


def compare(tshark, binary, metric):
    result = {"pcap": metric["pcap"], "sha256": metric["sha256"]}
    for kind, display, fields in (
        ("HTTP", "http.request && tcp", ["http.request.method", "http.request.uri"]),
        ("TLSClientHello", "tls.handshake.type==1 && tcp", ["tls.handshake.extensions_server_name"]),
    ):
        endpoint_fields = ["ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport"]
        command = [str(tshark), "-r", metric["pcap"], "-Y", display, "-T", "fields"]
        for field in endpoint_fields + fields:
            command.extend(["-e", field])
        text = subprocess.check_output(command, text=True, timeout=180)
        expected = Counter()
        for line in text.splitlines():
            values = line.split("\t")
            expected[tuple([values[0] or values[1], values[2], values[3] or values[4], values[5]] + values[6:])] += 1
        observed = Counter()
        for record in records(binary, Path(metric["output"]), kind):
            if kind == "HTTP" and not record.get("Method"):
                continue
            values = [record.get("SrcIP", ""), str(record.get("SrcPort", 0)), record.get("DstIP", ""), str(record.get("DstPort", 0))]
            values += [record.get("Method", ""), record.get("URL", "")] if kind == "HTTP" else [record.get("SNI", "")]
            observed[tuple(values)] += 1
        result[kind] = {"reference": sum(expected.values()), "observed": sum(observed.values()), "missing": [{"tuple": key, "count": count} for key, count in sorted((expected - observed).items())], "additional": sum((observed - expected).values())}
    return result


def audit_user_misses(args):
    replayed = json.loads((args.root / "replay.json").read_text())
    if digest(args.binary) != replayed["binarySHA256"]:
        raise RuntimeError("binary differs from completed replay")
    misses = {}
    for line in args.report.read_text().splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) > 3 and cells[1].isdigit() and re.fullmatch(r"20\d\d-\d\d-\d\d", cells[2]):
            users = re.findall(r"user:([^,\s|]+)", line)
            if users:
                misses[cells[2]] = users
    found = {}
    for metric in replayed["metrics"]:
        date = Path(metric["pcap"]).parent.name
        if date not in misses:
            continue
        names = found.setdefault(date, set())
        for host in metric["hosts"]["hosts"]:
            names.update(account["name"].lower() for account in host["accounts"] or [])
        names.update(record.get("ClientName", "").lower() for record in records(args.binary.resolve(), Path(metric["output"]), "Kerberos"))
    results = [{"date": date, "user": user, "recovered": user.lower() in found.get(date, set())} for date, users in sorted(misses.items()) for user in users]
    target = args.root / "user-misses.json"
    target.write_text(json.dumps({"binarySHA256": replayed["binarySHA256"], "results": results}, indent=2) + "\n")
    target.chmod(0o600)
    print(json.dumps({"checked": len(results), "recovered": sum(row["recovered"] for row in results), "missing": [row for row in results if not row["recovered"]]}))
    return bool(not results or any(not row["recovered"] for row in results))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--offline", action="store_true", help="replay existing checksum-verified receipts without network access")
    parser.add_argument("--compare-only", action="store_true", help="compare a completed replay against tshark HTTP/TCP TLS tuples")
    parser.add_argument("--tshark", type=Path)
    parser.add_argument("--expected-exercises", type=int)
    parser.add_argument("--expected-pcaps", type=int)
    parser.add_argument("--quiet", action="store_true", help="print only the final verification summary")
    parser.add_argument("--count-override", action="append", default=[], metavar="DATE=COUNT", help="explicit correction to a report inventory row")
    parser.add_argument("--dates", default="")
    parser.add_argument("--audit-misses", action="store_true", help="check previously missed user facts against structured identities")
    args = parser.parse_args()
    if args.audit_misses:
        if not args.binary:
            parser.error("--audit-misses requires --binary")
        return audit_user_misses(args)
    if args.compare_only:
        if not args.tshark or not args.binary:
            parser.error("--compare-only requires --tshark and --binary")
        replayed = json.loads((args.root / "replay.json").read_text())
        if digest(args.binary) != replayed["binarySHA256"]:
            parser.error("binary differs from the completed replay")
        comparisons = []
        for metric in replayed["metrics"]:
            if args.dates and Path(metric["pcap"]).parent.name not in args.dates.split(","):
                continue
            compared = compare(args.tshark, args.binary.resolve(), metric)
            comparisons.append(compared)
            if not args.quiet:
                print(json.dumps({"pcap": Path(metric["pcap"]).name, **{kind: {"reference": compared[kind]["reference"], "observed": compared[kind]["observed"], "missing": sum(item["count"] for item in compared[kind]["missing"]), "additional": compared[kind]["additional"]} for kind in ("HTTP", "TLSClientHello")}}), flush=True)
        target = args.root / "reference.json"
        target.write_text(json.dumps({"binarySHA256": replayed["binarySHA256"], "comparisons": comparisons}, indent=2) + "\n")
        target.chmod(0o600)
        print(json.dumps({"compared": len(comparisons), **{kind: {"reference": sum(result[kind]["reference"] for result in comparisons), "missing": sum(item["count"] for result in comparisons for item in result[kind]["missing"]), "additional": sum(result[kind]["additional"] for result in comparisons)} for kind in ("HTTP", "TLSClientHello")}}), flush=True)
        return bool(replayed["failures"] or len(replayed["metrics"]) != len(replayed["receipts"]) or any(result[kind]["missing"] for result in comparisons for kind in ("HTTP", "TLSClientHello")))
    report_text = args.report.read_text()
    dates = report_dates(report_text)
    expected_counts = report_counts(report_text)
    overrides = {}
    for value in args.count_override:
        date, separator, count = value.partition("=")
        if not separator or date not in expected_counts or not count.isdigit() or not 0 < int(count) <= 512:
            parser.error(f"invalid inventory count correction: {value}")
        overrides[date] = int(count)
    expected_counts.update(overrides)
    if not dates or args.expected_exercises is not None and len(dates) != args.expected_exercises:
        parser.error(f"report inventory contains {len(dates)} exercises; expected {args.expected_exercises}")
    if args.dates:
        dates = [d for d in dates if d in args.dates.split(",")]
    args.root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.offline:
        index = ""
    else:
        with urllib.request.urlopen("https://www.malware-traffic-analysis.net/training-exercises.html", timeout=60) as response:
            index = response.read(2 << 20).decode("utf-8", "replace")
    pages = {}
    for href, date in re.findall(r'<a[^>]+href=[\"\x27]([^\"\x27]+)[\"\x27][^>]*>\s*(20\d\d-\d\d-\d\d)\s*</a>', index, re.I):
        url = urllib.parse.urljoin("https://www.malware-traffic-analysis.net/", href)
        if urllib.parse.urlparse(url).netloc == "www.malware-traffic-analysis.net":
            pages[date] = url
    receipts, failures = [], []
    def load(date):
        if args.offline:
            return json.loads((args.root / date / "receipts.json").read_text())
        return fetch(args.root.resolve(), date, pages.get(date))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {pool.submit(load, date): date for date in dates}
        for job in concurrent.futures.as_completed(jobs):
            date = jobs[job]
            try:
                fetched = job.result()
                receipts.extend(fetched)
                if date in expected_counts and len(fetched) != expected_counts[date]:
                    failures.append({"date": date, "error": f"found {len(fetched)} captures; report inventory specifies {expected_counts[date]}"})
                if not args.quiet:
                    print(json.dumps({"date": date, "pcaps": len(fetched), "status": "fetched"}), flush=True)
            except Exception as error:
                failures.append({"date": date, "error": str(error)})
                print(json.dumps(failures[-1]), flush=True)
    if args.expected_pcaps is not None and len(receipts) != args.expected_pcaps:
        failures.append({"error": f"inventory contains {len(receipts)} PCAPs; expected {args.expected_pcaps}"})
    metrics = []
    if not args.fetch_only and not failures:
        if args.binary is None:
            parser.error("--binary is required for replay")
        for receipt in sorted(receipts, key=lambda r: r["pcap"]):
            try:
                result = replay(args.binary.resolve(), args.root, receipt)
                metrics.append(result)
                if not args.quiet:
                    print(json.dumps({"pcap": Path(receipt["pcap"]).name, "status": "replayed", "counts": result["counts"]}), flush=True)
            except Exception as error:
                failures.append({"pcap": receipt["pcap"], "error": str(error)})
    summary = args.root / ("fetch.json" if args.fetch_only else "replay.json")
    summary.write_text(json.dumps({"reportSHA256": digest(args.report), "inventoryOverrides": overrides, "binarySHA256": digest(args.binary) if args.binary else None, "receipts": receipts, "metrics": metrics, "failures": failures}, indent=2) + "\n")
    summary.chmod(0o600)
    print(json.dumps({"exercises": len(dates), "pcaps": len(receipts), "replayed": len(metrics), "failures": failures}), flush=True)
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
