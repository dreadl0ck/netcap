import base64
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("refresh_enrichment", Path(__file__).with_name("refresh-enrichment.py"))
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 11, 6, tzinfo=dt.timezone.utc)
        self.grant = b"SYNTHETIC TEST GRANT; NEVER PRODUCTION"
        self.catalog = {"count": 1600, "dateReleased": "2026-11-04T00:00:00Z", "vulnerabilities": [{"cveID": f"CVE-2099-{n:04d}"} for n in range(1600)]}

    def validate(self, previous=1600):
        with patch.object(refresh, "GRANT", refresh.sha(self.grant)):
            return refresh.validate_kev(json.dumps(self.catalog).encode(), self.grant, previous, self.now)

    def test_count_and_labels_are_not_assumed(self):
        self.assertEqual(self.validate(), 1600)

    def test_declared_count_and_duplicates(self):
        self.catalog["count"] = 1601
        with self.assertRaises(ValueError):
            self.validate()
        self.catalog["count"] = 1600
        self.catalog["vulnerabilities"][1] = self.catalog["vulnerabilities"][0]
        with self.assertRaises(ValueError):
            self.validate()

    def test_stale_future_and_decrease(self):
        for released in ["2026-10-01T00:00:00Z", "2026-11-07T00:00:00Z"]:
            self.catalog["dateReleased"] = released
            with self.assertRaises(ValueError):
                self.validate()
        self.catalog["dateReleased"] = "2026-11-04T00:00:00Z"
        with self.assertRaises(ValueError):
            self.validate(1800)

    def test_changed_grant(self):
        with self.assertRaises(ValueError):
            refresh.validate_kev(json.dumps(self.catalog).encode(), self.grant, 0, self.now)

    def test_acquisition_failure_preserves_signed_pointer(self):
        with tempfile.TemporaryDirectory() as temp:
            public = Path(temp) / "public"
            public.mkdir()
            pointer = json.dumps({"payload": base64.b64encode(b'{"sequence":1}').decode()}).encode()
            (public / "signed-latest.json").write_bytes(pointer)
            args = types.SimpleNamespace(root=temp, binary="synthetic-verifier", repo="synthetic-source", key="synthetic-existing-key", certificate="synthetic-certificate")
            with patch.object(refresh.subprocess, "run", return_value=types.SimpleNamespace(stdout="1768")), patch.object(refresh, "fetch", side_effect=TimeoutError):
                with self.assertRaises(TimeoutError):
                    refresh.refresh(args)
            self.assertEqual((public / "signed-latest.json").read_bytes(), pointer)
            self.assertEqual(json.loads((public / "refresh-status.json").read_bytes())["state"], "failed")


if __name__ == "__main__":
    unittest.main()
