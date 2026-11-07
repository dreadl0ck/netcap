#!/usr/bin/env python3
"""Acquire source evidence and deterministically build optional device catalogues."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import shutil

ROOT = Path(__file__).parent
PF = "de2f9678434a6f922fc7ce66e9fd3191606ed80f"
FB = "f062a677245fcebd338a6839357a65ff53c3b6d8"
SOURCES = {
    "dhcp_fingerprints.conf": f"https://raw.githubusercontent.com/inverse-inc/packetfence/{PF}/conf/dhcp_fingerprints.conf",
    "LICENSE.odbl-10.txt": f"https://raw.githubusercontent.com/karottc/fingerbank/{FB}/LICENSE.odbl-10.txt",
    "LICENSE.dbcl-10.txt": f"https://raw.githubusercontent.com/karottc/fingerbank/{FB}/LICENSE.dbcl-10.txt",
    "debian-ieee-copyright.txt": "https://metadata.ftp-master.debian.org/changelogs/main/i/ieee-data/ieee-data_20260625_copyright",
    "oui.csv": "https://standards-oui.ieee.org/oui/oui.csv",
    "mam.csv": "https://standards-oui.ieee.org/oui28/mam.csv",
    "oui36.csv": "https://standards-oui.ieee.org/oui36/oui36.csv",
    "iab.csv": "https://standards-oui.ieee.org/iab/iab.csv",
    "gopacket-valid-mac-prefixes.go.txt": "https://raw.githubusercontent.com/gopacket/gopacket/v1.7.2/macs/valid_mac_prefixes.go",
    "gopacket-LICENSE.txt": "https://raw.githubusercontent.com/gopacket/gopacket/v1.7.2/LICENSE",
}


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def build(fetch=False, export=None, fetch_missing=False, refresh_ieee=False):
    source_dir = ROOT / "sources"
    data_dir = ROOT / "data"
    source_dir.mkdir(exist_ok=True)
    data_dir.mkdir(exist_ok=True)
    evidence = []
    for name, url in SOURCES.items():
        path = source_dir / name
        if fetch or (fetch_missing and not path.exists()) or (refresh_ieee and name in {"oui.csv", "mam.csv", "oui36.csv", "iab.csv"}):
            response = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "120", "--max-filesize", str(16 << 20), "--dump-header", "-", url], check=True, capture_output=True).stdout
            header, body = response.split(b"\r\n\r\n", 1)
            while body.startswith(b"HTTP/"):
                header, body = body.split(b"\r\n\r\n", 1)
            headers = dict(line.split(":", 1) for line in header.decode().splitlines() if ":" in line)
            metadata = {"url": url, "last_modified": headers.get("Last-Modified"), "etag": headers.get("ETag")}
            path.write_bytes(body)
            path.with_suffix(path.suffix + ".http.json").write_bytes(encode(metadata))
        body = path.read_bytes()
        expected = {
            "dhcp_fingerprints.conf": "a68d73be27467df464769c7c6bd15906c2a5bc36e3ea4f101b1d1a6ecdb1372d",
            "LICENSE.odbl-10.txt": "d9685b90fa7d223f5cb0e7f57d00d5b63de69638c9de0340be2e7cf4dc6ecab3",
            "LICENSE.dbcl-10.txt": "4ba29303b8f63348bd6488219ebf3c7684f5ce16cd2616f3935c94e3c5853380",
            "debian-ieee-copyright.txt": "f1a22c2737d856d90a676a553501431b6a77b9e0bb094cf325827ff6a733381c",
            "gopacket-valid-mac-prefixes.go.txt": "eb562e4e44e343da1ca929f2e2548dccc815eb83341dcb054aeab112775f27f4",
            "gopacket-LICENSE.txt": "8025b28cd71e0a486b173d4a29a05478c003d197a907f99b61a05e181e90b92d",
        }.get(name)
        if expected and hashlib.sha256(body).hexdigest() != expected:
            raise ValueError(f"pinned source hash changed: {name}")
        evidence.append({"file": name, "url": url, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)})
    text = (source_dir / "dhcp_fingerprints.conf").read_text()
    assert "Open Database License" in text and "Database Contents License" in text
    rows = {}
    occurrences = 0
    sections = re.findall(r"(?ms)^\[os (\d+)\][ \t]*\n(.*?)(?=^\[|\Z)", text)
    for ident, section in sections:
        label = re.search(r"(?m)^description=(.*)$", section).group(1).strip()
        block = re.search(r"(?ms)^fingerprints=<<EOT\n(.*?)^EOT", section)
        if block:
            for line in block.group(1).splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                params = [int(x) for x in line.split(",")]
                assert all(0 <= x <= 255 for x in params)
                key = ",".join(map(str, params))
                rows.setdefault(key, []).append({"id": "fingerbank.os." + ident, "label": label})
                occurrences += 1
    blocks = sum("fingerprints=<<EOT" in section for _, section in sections)
    assert (len(sections), blocks, occurrences, len(rows)) == (238, 236, 536, 535)
    dhcp = {"format": "netcap-dhcp-catalogue", "schema": 1, "version": "fingerbank-6.8.2-pf-" + PF[:12], "license": "ODbL-1.0 AND DbCL-1.0", "source_sha256": evidence[0]["sha256"], "entries": [{"key": k, "candidates": sorted(v, key=lambda c: c["id"])} for k, v in sorted(rows.items())]}
    (data_dir / "dhcp-catalogue-v1.json").write_bytes(encode(dhcp))
    vendors = {}
    for name, bits in [("oui.csv", 24), ("mam.csv", 28), ("oui36.csv", 36), ("iab.csv", 36)]:
        for row in csv.DictReader(io.StringIO((source_dir / name).read_text(encoding="utf-8-sig"))):
            prefix = row["Assignment"].strip().upper()
            vendor = row["Organization Name"].strip()
            assert len(prefix) == bits // 4 and re.fullmatch("[0-9A-F]+", prefix) and vendor
            key = (prefix, bits)
            vendors.setdefault(key, set()).add(vendor)
    mac = {"format": "netcap-mac-catalogue", "schema": 1, "version": "ieee-" + hashlib.sha256(encode(evidence[4:8])).hexdigest()[:16], "license": "IEEE-secondary-nonassertion", "entries": [{"prefix": p, "bits": b, "organization": " | ".join(sorted(v))} for (p, b), v in sorted(vendors.items())]}
    (data_dir / "mac-catalogue-v1.json").write_bytes(encode(mac))
    review = {"schema": 1, "reviewer": "OpenCode automated source/evidence review (not human counsel)", "authorization": "User explicitly authorized historical ODbL restoration and accepted derivative-download/SaaS attribution obligations; accepted bounded IEEE fallback and secondary nonassertion evidence.", "sources": evidence, "dhcp": {"sections": len(sections), "occurrences": occurrences, "unique_keys": len(rows), "ambiguous_keys": sum(len(v) > 1 for v in rows.values()), "transformation": "Only active fingerprints blocks and description/id from pinned source; no legacy JSON, API additions or vendor-id inference; ordered request list; preserve all candidates.", "obligations": "Attribute FingerBank / Inverse inc. (2008-2013), retain ODbL/DbCL notices, offer this complete derivative database and transformation/source evidence under ODbL including for public SaaS use."}, "mac": {"prefixes": len(vendors), "transformation": "IEEE MA-L/MA-M/MA-S/IAB Assignment and Organization Name only; exclude Organization Address; deterministic prefix sort.", "basis": "Debian ieee-data 20260625 copyright record quotes: IEEE does not assert any copyright in the OUI Public Listing or attempt to restrict distribution of the listing in any way.", "remaining_evidence_gap": "Secondary Debian record, not a newly obtained direct IEEE grant or legal opinion; no invented grant. Daily source refresh is a builder capability, not a running scheduled deployment.", "fallback": "gopacket v1.7.2 bounded embedded table retained; BSD code license does not independently establish IEEE data rights."}, "outputs": []}
    for name in ["dhcp-catalogue-v1.json", "mac-catalogue-v1.json"]:
        body = (data_dir / name).read_bytes()
        review["outputs"].append({"file": name, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)})
    (ROOT / "provenance.json").write_bytes(encode(review))
    notice = ("Optional Netcap device catalogues, schema 1\n\n"
        "DHCP: FingerBank database, Copyright (C) 2008-2013 Inverse inc.\n"
        f"Source: {SOURCES['dhcp_fingerprints.conf']}\n"
        "Derivative: dhcp-catalogue-v1.json; ordered option-55 keys and all candidate labels.\n"
        "Made available under ODbL 1.0; individual contents under DbCL 1.0.\n"
        "Public services using this catalogue must visibly attribute FingerBank / Inverse inc.,\n"
        "link the ODbL, and offer the complete derivative database, notices and source evidence.\n"
        "The optional delivery channel must expose these complete files for download.\n"
        "No Fingerbank API additions or legacy Netcap JSON are included.\n\n"
        "MAC: IEEE MA-L/MA-M/MA-S/IAB public listings, normalized to prefixes and registered\n"
        "organization names only. Names are not device identity. Updated from IEEE directly.\n"
        "Acceptance basis: secondary Debian ieee-data 20260625 nonassertion record below.\n"
        "No new IEEE grant or human legal review is asserted. gopacket v1.7.2 remains the\n"
        "bounded built-in fallback; its BSD code license does not establish IEEE data rights.\n\n")
    for name in ["LICENSE.odbl-10.txt", "LICENSE.dbcl-10.txt", "debian-ieee-copyright.txt", "gopacket-LICENSE.txt"]:
        notice += f"\n--- {name} ---\n" + (source_dir / name).read_text() + "\n"
    review["dhcp"]["fingerprint_blocks"] = blocks
    review["mac"]["multiple_organization_prefixes"] = sum(len(v) > 1 for v in vendors.values())
    review["mac"]["duplicate_policy"] = "Retain distinct names for a prefix in sorted order, joined by ' | '; do not choose one registration silently."
    (ROOT / "provenance.json").write_bytes(encode(review))
    (ROOT / "NOTICE.txt").write_text(notice)
    (ROOT.parents[1] / "legal/DEVICE_CATALOGUE_NOTICES.txt").write_text(notice)
    channel = ROOT / "channel"
    channel.mkdir(exist_ok=True)
    channel_sources = []
    for source_id, original, name in [("fingerbank-odbl", "dhcp-catalogue-v1.json", "dhcp-fingerprints-odbl.json"), ("mac-organizations", "mac-catalogue-v1.json", "mac-organizations.json")]:
        body = (data_dir / original).read_bytes()
        (channel / name).write_bytes(body)
        if source_id == "fingerbank-odbl":
            origin, revision, input_hash = SOURCES["dhcp_fingerprints.conf"], PF, evidence[0]["sha256"]
            grant_origin = SOURCES["LICENSE.odbl-10.txt"] + "\n" + SOURCES["LICENSE.dbcl-10.txt"]
            grant_revision = FB
            grant = "\n--- LICENSE.odbl-10.txt ---\n" + (source_dir / "LICENSE.odbl-10.txt").read_text() + "\n\n--- LICENSE.dbcl-10.txt ---\n" + (source_dir / "LICENSE.dbcl-10.txt").read_text()
            transformation = review["dhcp"]["transformation"]
        else:
            origin = "\n".join(s["url"] for s in evidence[4:8])
            revision = "sha256-of-canonical-IEEE-source-manifest:" + hashlib.sha256(encode(evidence[4:8])).hexdigest()
            input_hash = hashlib.sha256(encode(evidence[4:8])).hexdigest()
            grant_origin = SOURCES["debian-ieee-copyright.txt"]
            grant_revision = "Debian ieee-data 20260625; secondary evidence accepted explicitly by user"
            grant = (source_dir / "debian-ieee-copyright.txt").read_text()
            transformation = review["mac"]["transformation"] + " " + review["mac"]["duplicate_policy"] + " Input hash is the canonical four-source metadata manifest in provenance.json, not an invented single-file digest. Source SHA-256: " + "; ".join(s["file"] + "=" + s["sha256"] for s in evidence[4:8])
        assert grant in notice
        channel_sources.append({"id": source_id, "origin": origin, "revision": revision, "input_sha256": input_hash, "grant_origin": grant_origin, "grant_revision": grant_revision, "grant_text": grant, "grant_sha256": hashlib.sha256(grant.encode()).hexdigest(), "transformation": transformation + " Automated evidence review; no human counsel sign-off.", "outputs": [{"path": name, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}]})
    (channel / "source-evidence.json").write_bytes(encode(channel_sources))
    (channel / "ENRICHMENT_NOTICES.txt").write_text(notice)
    coverage = {
        "format": "netcap-device-release-coverage/v1",
        "scope": ["DHCPv4 historical option-55 candidates", "MAC registered organization enrichment"],
        "outputs": review["outputs"],
        "dhcp": {"source_os_sections": len(sections), "fingerprint_blocks": blocks, "occurrences": occurrences, "unique_keys": len(rows), "ambiguous_keys": sum(len(v) > 1 for v in rows.values()), "modern_first_party_rules_added": 0, "legacy_json_compared": False, "api_additions_included": False},
        "mac": {"normalized_prefixes": len(vendors), "prefix_lengths": [24, 28, 36], "organization_addresses_in_output": False, "device_identity_claim": False},
        "field_changes": [
            {"field": "DHCPv4.Fingerprint", "change": "Unchanged raw outer-option code sequence; not used as the catalogue key."},
            {"field": "DHCP candidate key", "change": "Ordered option-55 contents, RFC 3396 fragments, file then sname overload; invalid lengths, BOOTP replies and DHCPv6 yield no v4 claim."},
            {"field": "DHCP device label", "change": "Historical source label only for a unique exact key; ambiguous keys retain all candidates but emit no single-label claim; no inferred device version or confidence score."},
            {"field": "MAC organization", "change": "24/28/36-bit longest prefix; complete 48-bit input required; local/group/malformed addresses unknown; registered organization is not device identity."},
        ],
        "qualification": {"shared_functional_vectors": {name: len(values) for name, values in json.loads((ROOT / "vectors.json").read_text()).items() if name in {"mac", "dhcp"}}, "deterministic_random_mac_inputs_per_language": 4096, "classification_accuracy_measured": False, "representative_capture_accuracy_corpus": None, "coverage_parity_claim": False, "nmap_parity_claim": False, "note": "Counts describe data and functional test cases, not detection accuracy. Signed runtime admission is tested with synthetic test-only signing keys over the real candidate."},
    }
    sizing = json.loads((ROOT / "snapshot-sizing-evidence.json").read_text()) if (ROOT / "snapshot-sizing-evidence.json").exists() else None
    if sizing is not None:
        coverage["snapshot_sizing"]={"receipt":"snapshot-sizing-evidence.json","envelope_sha256":sizing["envelope_sha256"],"signed_sequence":sizing["sequence"],"sqlite_bytes":sizing["sqlite"]["size"],"max_file_bytes":2 << 30,"max_total_bytes":4 << 30,"qualification":sizing["qualification"]}
    (ROOT / "release-coverage.json").write_bytes(encode(coverage))
    if export:
        export = Path(export)
        export.mkdir(parents=True, exist_ok=True)
        shutil.copytree(data_dir, export / "data", dirs_exist_ok=True)
        shutil.copytree(channel, export / "channel", dirs_exist_ok=True)
        for name in ["NOTICE.txt", "provenance.json", "vectors.json", "release-coverage.json"]:
            shutil.copyfile(ROOT / name, export / name)
        # The downloadable source/transform bundle remains canonical in Go.
        for file in [export.parent / "THIRD-PARTY-NOTICES", export.parent / "about.hbs"]:
            marker = "\n--- Optional device catalogue notices ---\n"
            base = file.read_text().split(marker)[0]
            file.write_text(base + marker + notice)
    print(json.dumps({"outputs": review["outputs"], "mac_prefixes": len(vendors), "dhcp_keys": len(rows)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--export", type=Path)
    parser.add_argument("--fetch-missing", action="store_true")
    parser.add_argument("--refresh-ieee", action="store_true", help="refresh only the four direct IEEE daily listings")
    args = parser.parse_args()
    build(args.fetch, args.export, args.fetch_missing, args.refresh_ieee)
