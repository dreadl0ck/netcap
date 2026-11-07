#!/usr/bin/env python3
"""Recover the count from authenticated publication bytes, never a count cache."""
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tarfile
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = "8a6d1aaec22ae69f41430d4109b3293b10f98113df87a0989fa609ffb623d7db"


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique)


def un64(value):
    return base64.b64decode(value, validate=True)


def recover(root, bootstrap=None, public_root=ROOT):
    root = Path(root)
    pointer = root / "v3/signed-latest.json"
    if not pointer.exists() and not pointer.is_symlink():
        if (bootstrap != "0" or (root / "last-count.json").exists()
                or any(p.name != "refresh-status.json" for p in (root / "v3").iterdir())):
            raise ValueError("no signed publication; explicit empty-channel bootstrap required")
        return {"count": 0, "bootstrap": True}
    with pointer.open("rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode) or pointer.is_symlink():
            raise ValueError("signed pointer must be regular")
        raw = f.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("oversized signed pointer")
    envelope = decode(raw)
    cert = envelope["certificate"]
    cert_bytes = un64(cert["payload"])
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_root)).verify(
        un64(cert["signature"]), cert_bytes)
    key = decode(cert_bytes)
    payload_bytes = un64(envelope["payload"])
    Ed25519PublicKey.from_public_bytes(un64(key["public_key"])).verify(
        un64(envelope["signature"]), payload_bytes)
    p = decode(payload_bytes)
    # Expired publications still provide the authenticated historical baseline.
    if not (key["format"] == "netcap-db-signing-key/v1" and key["epoch"] > 0
            and 0 < key["not_after"] - key["not_before"] <= 90 * 86400
            and p["format"] == "netcap-db-release/v1"
            and p["channel"] == "community-schema2" and p["sequence"] > 0
            and key["not_before"] <= p["issued_at"] <= time.time() + 300
            and p["expires_at"] <= key["not_after"]
            and 0 < p["expires_at"] - p["issued_at"] <= 7 * 86400
            and (not p.get("policy_expires_at") or p["expires_at"] <= p["policy_expires_at"])):
        raise ValueError("invalid signed scope or validity")
    m = p["metadata"]
    digest = m["sha256"]
    if not (re.fullmatch("[0-9a-f]{64}", digest)
            and m["version"] == digest and m["tarball"] == digest + ".tar.gz"
            and m["layout"] == 3 and m["vulndb_schema"] == 2):
        raise ValueError("invalid archive identity")
    registry = un64(p["registry"])
    if hashlib.sha256(registry).hexdigest() != m["approval_registry_sha256"]:
        raise ValueError("registry identity mismatch")
    outputs = [o for r in decode(registry) if r["decision"] == "approved-for-publication"
               for o in r["outputs"] if o["path"] == "netcap.sqlite" and o["source"] == "nvd"]
    if len(outputs) != 1:
        raise ValueError("ambiguous reviewed SQLite identity")
    expected = outputs[0]
    archive = root / "v3" / m["tarball"]
    with archive.open("rb") as f:
        if archive.is_symlink() or not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("archive must be regular")
        if os.fstat(f.fileno()).st_size != m["size"] or hashlib.file_digest(f, "sha256").hexdigest() != digest:
            raise ValueError("archive identity mismatch")
        f.seek(0)
        with tempfile.TemporaryDirectory(prefix="previous-count-") as temp:
            db = Path(temp) / "netcap.sqlite"
            found = False
            with tarfile.open(fileobj=f, mode="r|gz") as tar:
                for member in tar:
                    if member.name != "netcap.sqlite":
                        continue
                    if found or not member.isfile() or member.size != expected["size"] or member.size > 1 << 30:
                        raise ValueError("invalid SQLite archive member")
                    found = True
                    h = hashlib.sha256()
                    with tar.extractfile(member) as src, db.open("xb") as dst:
                        while chunk := src.read(1024 * 1024):
                            h.update(chunk)
                            dst.write(chunk)
                    if h.hexdigest() != expected["sha256"]:
                        raise ValueError("SQLite identity mismatch")
            if not found:
                raise ValueError("missing SQLite archive member")
            with closing(sqlite3.connect(db.as_uri() + "?mode=ro&immutable=1", uri=True)) as conn:
                count = conn.execute("select count(*) from nvd").fetchone()[0]
            if count <= 0:
                raise ValueError("empty published NVD database")
    if pointer.read_bytes() != raw:
        raise ValueError("signed publication changed during recovery")
    receipt = {"count": count, "sequence": p["sequence"], "epoch": key["epoch"],
               "signed_pointer_sha256": hashlib.sha256(raw).hexdigest(),
               "archive_sha256": digest, "sqlite_sha256": expected["sha256"]}
    fd, name = tempfile.mkstemp(prefix=".last-count-", dir=root)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(receipt, out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, root / "last-count.json")
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return receipt


if __name__ == "__main__":
    try:
        print(recover(sys.argv[1], os.environ.get("NC_DBS_BOOTSTRAP_PREVIOUS_COUNT"))["count"])
    except Exception as exc:
        sys.exit("previous publication recovery refused: " + type(exc).__name__)
