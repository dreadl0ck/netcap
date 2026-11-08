#!/usr/bin/env python3
"""Verify complete public bytes, signatures, source offering and two clean client installs."""
import argparse
import base64
import collections
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import time
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = bytes.fromhex("8a6d1aaec22ae69f41430d4109b3293b10f98113df87a0989fa609ffb623d7db")
CAP = ["netcap-enrichment/v1"]
FAMILIES = {"kev.json": "cisa-kev", "dhcp-fingerprints-odbl.json": "fingerbank-odbl", "mac-organizations.json": "mac-organizations", "webtech-descriptors.json": "webtech-descriptors", "service-signatures.json": "netcap-service-signatures"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fetch(url, maximum):
    with urllib.request.urlopen(url, timeout=90) as response:
        assert response.status == 200
        data = response.read(maximum + 1)
    assert len(data) <= maximum
    return data


def verify(server, roots):
    latest = fetch(server + "/enrichment/signed/v1/latest", 2 << 20)
    envelope = json.loads(latest)
    cert = envelope["certificate"]
    cert_bytes = base64.b64decode(cert["payload"], validate=True)
    Ed25519PublicKey.from_public_bytes(ROOT).verify(base64.b64decode(cert["signature"], validate=True), cert_bytes)
    key = json.loads(cert_bytes)
    payload_bytes = base64.b64decode(envelope["payload"], validate=True)
    Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key"], validate=True)).verify(base64.b64decode(envelope["signature"], validate=True), payload_bytes)
    payload = json.loads(payload_bytes)
    now = int(time.time())
    assert key["format"] == "netcap-enrichment-signing-key/v1"
    assert payload["format"] == "netcap-enrichment-release/v1"
    assert key["channel"] == payload["channel"] == "community-enrichment"
    assert key["minimum_format"] == payload["minimum_format"] == 1
    assert key["capabilities"] == payload["capabilities"] == CAP
    assert key["not_before"] <= payload["issued_at"] <= now + 300
    assert now < payload["expires_at"] <= key["not_after"]
    assert 0 < key["not_after"] - key["not_before"] <= 90 * 86400
    assert 0 < payload["expires_at"] - payload["issued_at"] <= 7 * 86400
    archive_url = server + "/enrichment/signed/v1/" + payload["archive_sha256"] + ".tar.gz"
    archive = fetch(archive_url, payload["archive_size"])
    assert len(archive) == payload["archive_size"] and sha(archive) == payload["archive_sha256"]
    with gzip.GzipFile(fileobj=io.BytesIO(archive)) as stream:
        raw = stream.read((256 << 20) + 1)
    assert len(raw) <= 256 << 20
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        entries = tar.getmembers()
        assert len(entries) == 8 and len({m.name for m in entries}) == 8
        assert all(m.isfile() and Path(m.name).name == m.name and 0 < m.size <= 64 << 20 for m in entries)
        members = {m.name: tar.extractfile(m).read() for m in entries}
    manifest = json.loads(members["ENRICHMENT_MANIFEST.json"])
    assert sha(members["ENRICHMENT_MANIFEST.json"]) == payload["manifest_sha256"]
    assert manifest["format"] == "netcap-enrichment/v1"
    inventory = {f["path"]: f for f in manifest["files"]}
    assert set(inventory) == set(FAMILIES) | {"source-evidence.json", "ENRICHMENT_NOTICES.txt"}
    for name, value in inventory.items():
        assert len(members[name]) == value["size"] and sha(members[name]) == value["sha256"]
        offered = fetch(server + "/enrichment/signed/v1/" + payload["archive_sha256"] + "/" + name, value["size"])
        assert offered == members[name]
    sources = json.loads(members["source-evidence.json"])
    assert len(sources) == 5 and {s["id"] for s in sources} == set(FAMILIES.values())
    for source in sources:
        assert sha(source["grant_text"].encode()) == source["grant_sha256"]
        assert source["grant_text"].encode() in members["ENRICHMENT_NOTICES.txt"]
        review = source["review"]
        assert review["decision"] == "approved-for-publication" and "automated" in review["reviewer"].lower()
        assert "not a human legal-review sign-off" in review["authorization"]
        assert sha(source["evidence"].encode()) == review["evidence_sha256"]
        json.loads(source["evidence"])
        for output in source["outputs"]:
            assert FAMILIES[output["path"]] == source["id"] and output == inventory[output["path"]]
    for root in roots:
        root = Path(root)
        version = (root / "active").read_text().strip()
        assert version == sha(payload_bytes)
        installed = root / "versions" / version
        installed_envelope = json.loads((installed / "signed-release.json").read_bytes())
        assert installed_envelope == envelope
        for name, b in members.items():
            assert (installed / name).read_bytes() == b
    kev = json.loads(members["kev.json"])
    assert kev["count"] == len(kev["entries"]) == len({r["cve"] for r in kev["entries"]})
    cisa = next(s for s in sources if s["id"] == "cisa-kev")
    assert cisa["grant_sha256"] == "8dfcf2d0cba33bede386eb470daf2ac08caf6540fc2516baab10dd546f90938a"
    core = json.loads(fetch(server + "/dbs/signed/v1/latest", 16 << 20))
    assert json.loads(base64.b64decode(core["payload"]))["channel"] == "community-schema2"
    fetch(server + "/ready", 1 << 20)
    fetch(server + "/freshness", 1 << 20)
    return {"format": "netcap-enrichment-production-verification/v1", "verified_at": now, "channel": payload["channel"], "minimum_format": 1, "capabilities": CAP, "key_epoch": key["epoch"], "key_not_after": key["not_after"], "sequence": payload["sequence"], "expires_at": payload["expires_at"], "archive_url": archive_url, "archive_sha256": payload["archive_sha256"], "archive_size": len(archive), "manifest_sha256": payload["manifest_sha256"], "files": manifest["files"], "kev_revision": cisa["revision"], "kev_input_sha256": cisa["input_sha256"], "kev_count": kev["count"], "ransomware_labels": dict(collections.Counter(r["ransomware"] for r in kev["entries"])), "client_roots": [str(r) for r in roots], "direct_source_offering_verified": True, "core_channel_responding": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="https://dbs.netcap.io")
    parser.add_argument("--go-root", required=True)
    parser.add_argument("--rust-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--historical-receipt")
    args = parser.parse_args()
    result = verify(args.server.rstrip("/"), [args.go_root, args.rust_root])
    if args.historical_receipt:
        old = json.loads(Path(args.historical_receipt).read_bytes())
        archive = fetch(old["archive_url"], old["archive_size"])
        assert len(archive) == old["archive_size"] and sha(archive) == old["archive_sha256"]
        for item in old["files"]:
            body = fetch(args.server.rstrip("/") + "/enrichment/signed/v1/" + old["archive_sha256"] + "/" + item["path"], item["size"])
            assert len(body) == item["size"] and sha(body) == item["sha256"]
        result["historical_source_offering_verified"] = old["archive_sha256"]
    with Path(args.output).open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({k: result[k] for k in ["sequence", "archive_sha256", "archive_size", "kev_revision", "kev_count", "ransomware_labels"]}, sort_keys=True))
