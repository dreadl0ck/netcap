import base64
from contextlib import closing
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location("previous", Path(__file__).with_name("db-previous-count.py"))
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)


def encoded(value):
    return base64.b64encode(value).decode()


def signed(value, key):
    payload = json.dumps(value).encode()
    return {"payload": encoded(payload), "signature": encoded(key.sign(payload))}


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "v3").mkdir()
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def publish(self, count=21, sequence=10, expired=False):
        db = self.root / "fixture.sqlite"
        db.unlink(missing_ok=True)
        with closing(sqlite3.connect(db)) as c, c:
            c.execute("create table nvd (id integer)")
            c.executemany("insert into nvd values (?)", ((i,) for i in range(count)))
        data = db.read_bytes()
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode="w:gz") as tar:
            info = tarfile.TarInfo("netcap.sqlite")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        archive = body.getvalue()
        digest = hashlib.sha256(archive).hexdigest()
        (self.root / "v3" / (digest + ".tar.gz")).write_bytes(archive)
        registry = json.dumps([{"decision": "approved-for-publication", "outputs": [{
            "path": "netcap.sqlite", "source": "nvd", "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}]}]).encode()
        now = int(time.time())
        issued = now - 1000 if expired else now
        payload = {"format": "netcap-db-release/v1", "channel": "community-schema2",
                   "sequence": sequence, "issued_at": issued,
                   "expires_at": issued + (100 if expired else 1000),
                   "metadata": {"sha256": digest, "version": digest, "tarball": digest + ".tar.gz",
                                "size": len(archive), "layout": 3, "vulndb_schema": 2,
                                "approval_registry_sha256": hashlib.sha256(registry).hexdigest()},
                   "registry": encoded(registry)}
        envelope = signed(payload, self.key)
        envelope["certificate"] = signed({"format": "netcap-db-signing-key/v1", "epoch": 2,
            "public_key": encoded(bytes.fromhex(self.pub)), "not_before": now - 2000,
            "not_after": now + 10000}, self.key)
        (self.root / "v3/signed-latest.json").write_text(json.dumps(envelope))
        return digest

    def recover(self, bootstrap=None):
        return previous.recover(self.root, bootstrap, self.pub)

    def test_first_boot_requires_explicit_empty_channel(self):
        with self.assertRaises(ValueError):
            self.recover()
        self.assertEqual(self.recover("0"), {"count": 0, "bootstrap": True})
        (self.root / "last-count.json").write_text('{"count":400000}')
        with self.assertRaises(ValueError):
            self.recover("0")
        (self.root / "last-count.json").unlink()
        (self.root / "v3/signed-1.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.recover("0")

    def test_missing_cache_recovers_authenticated_expired_publication(self):
        digest = self.publish(expired=True)
        result = self.recover()
        self.assertEqual(result["count"], 21)
        self.assertEqual(result["archive_sha256"], digest)
        self.assertEqual(json.loads((self.root / "last-count.json").read_text()), result)

    def test_stale_or_corrupt_cache_cannot_lower_previous_count(self):
        self.publish()
        self.recover()
        self.publish(count=31, sequence=11)
        for value in ('{"count":1}', 'invalid', '{"count":400000}'):
            (self.root / "last-count.json").write_text(value)
            result = self.recover()
            self.assertEqual((result["count"], result["sequence"]), (31, 11))

    def test_corrupt_archive_refused_even_with_cache(self):
        digest = self.publish()
        self.recover()
        p = self.root / "v3" / (digest + ".tar.gz")
        p.write_bytes(p.read_bytes()[:-1] + b"x")
        with self.assertRaises(ValueError):
            self.recover()

    def test_forged_signature_refused_even_with_cache(self):
        self.publish()
        self.recover()
        p = self.root / "v3/signed-latest.json"
        envelope = json.loads(p.read_text())
        envelope["signature"] = encoded(bytes(64))
        p.write_text(json.dumps(envelope))
        with self.assertRaises(Exception):
            self.recover()

    def test_root_matches_released_go_pin(self):
        source = Path(__file__).resolve().parents[1] / "internal/dbs/signing_root.go"
        self.assertIn('"' + previous.ROOT + '"', source.read_text())

    def test_refresh_status_accepts_recovery_stages(self):
        writer = Path(__file__).with_name("db-refresh-status.py")
        for stage in ("previous-publication", "publication-recovery"):
            subprocess.run([sys.executable, str(writer), str(self.root / "v3"), "running", stage], check=True)
            state = json.loads((self.root / "v3/refresh-status.json").read_text())
            self.assertEqual((state["status"], state["stage"]), ("running", stage))


if __name__ == "__main__":
    unittest.main()
