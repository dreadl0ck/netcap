#!/usr/bin/env python3
"""Score the v0.16.14 review's pinned present-IOC set against a service run."""

import argparse
import ipaddress
import json
import re
import subprocess
from pathlib import Path


# A name or address appearing in inventory, header hygiene, a generic port
# alert, or an incidental suspicious-TLD match is not meaningful detection.
FINDINGS = frozenset({
    "Credential Stealer Gate POST", "Dynamic DNS Or Tunnel Service Domain",
    "Public IP Lookup Service", "Tor Network Traffic Detected", "Tor-Like Relay Certificate",
    "Exploit Kit Plugin Content", "http.flash-referral", "Executable Downloaded From Internet",
    "Archive Download With Generic Content-Type", "Failed Connection Fan-Out",
    "Outbound Alt-Port C2 List Walk", "Onion Destination In DNS", "Onion Destination In Cleartext HTTP",
    "Repeated Opaque HTTP Check-In", "Repeated DNS Name Lookup Failure",
    "Indy Library HTTP Client", "Host Identity In HTTP Check-in", "HTTP GET To Raw Public IP",
    "Repeated Failed TCP Contact On RAT-Associated Port",
    "HTTP Check-In On IRC Port", "Scripted HTTP Ad Interaction",
    "c2.beacon", "dns.tunnel", "udp.fanout", "Known Malware Detected", "File Hash In IOC List",
    "DNS Query For IOC Domain", "Connection To IOC Address", "HTTP Host Or URL In IOC List",
    "TLS Server Name In IOC List",
})


def matching_iocs(alert, indicators):
    addresses = {alert.get("SrcIP", ""), alert.get("DstIP", "")}
    blob = (str(alert.get("Domain", "")) + " " + str(alert.get("MatchedRecord", ""))).lower()
    for ioc in indicators:
        try:
            ipaddress.ip_address(ioc)
        except ValueError:
            if re.search(r"(?<![a-z0-9-])" + re.escape(ioc) + r"(?![a-z0-9.-])", blob):
                yield ioc
        else:
            if ioc in addresses:
                yield ioc


def read_alerts(binary, output):
    audit = output / "Alert.ncap.gz"
    if not audit.is_file():
        return
    cmd = [binary, "dump", "--read", audit, "--json", "--select", "RuleName,Severity,SrcIP,DstIP,MatchedRecord"]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
        for line in proc.stdout:
            if line.startswith("{"):
                yield json.loads(line)
        if proc.wait() != 0:
            raise SystemExit(f"could not read alerts for {output.name}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", type=Path)
    ap.add_argument("run", type=Path, help="workdir printed by check-service-pcaps.py")
    ap.add_argument("reference", type=Path, help="netcap-eval-scoring/showcase/v0.16.14")
    ap.add_argument("--floor", type=int, default=23)
    args = ap.parse_args()
    sessions = {}
    for meta in (args.run / "data/results").glob("*/session.json"):
        row = json.loads(meta.read_bytes())
        if not row.get("isPreloaded") or row.get("status") != "completed":
            continue
        name = row["inputFilename"]
        if name in sessions:
            ap.error(f"duplicate completed session: {name}")
        sessions[name] = meta.parent
    total = meaningful = actionable = 0
    for path in sorted(args.reference.glob("*.json")):
        ref = json.loads(path.read_bytes())
        iocs = set(ref.get("blog_ioc_coverage", {}).get("v14", {}).get("present", []))
        if not iocs:
            continue
        output = sessions.get(ref["name"])
        if output is None:
            ap.error(f"missing completed replay of {ref['name']}")
        manifest = json.loads((output / "capture-manifest.json").read_bytes())
        if manifest.get("inputSHA256") != ref["sha256"]:
            ap.error(f"wrong input hash for {ref['name']}")
        all_matches, specific = set(), set()
        for alert in read_alerts(args.binary.resolve(), output):
            if alert.get("Severity") not in {"medium", "high", "critical"}:
                continue
            hits = set(matching_iocs(alert, iocs))
            all_matches.update(hits)
            if alert.get("RuleName") in FINDINGS:
                specific.update(hits)
        print(json.dumps({"capture": ref["name"], "present": len(iocs), "actionable": len(all_matches), "specific": len(specific)}))
        total += len(iocs)
        actionable += len(all_matches)
        meaningful += len(specific)
    print(json.dumps({"present": total, "actionable": actionable, "specific": meaningful, "specificFloor": args.floor}))
    return total != 72 or meaningful < args.floor


if __name__ == "__main__":
    raise SystemExit(main())
