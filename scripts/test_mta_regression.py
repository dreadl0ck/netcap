import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("mta_regression", Path(__file__).with_name("mta-regression.py"))
mta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mta)


class ReferenceComparisonTests(unittest.TestCase):
    def test_numbered_inventory_excludes_answer_corrections(self):
        text = "| 1 | 2018-10-01 | 4 |\n| 2 | 2015-02-24 | 7 |\n| 2026-10-01 | typo | correction |\n"
        self.assertEqual(mta.report_dates(text), ["2015-02-24", "2018-10-01"])
        self.assertEqual(mta.report_dates("| 2020-01-30 | 3 |\n"), ["2020-01-30"])
        self.assertEqual(mta.report_counts("| 1 | 2016-07-07 | 6 | Email roulette | 6 | - |\n"), {"2016-07-07": 6})

    def test_raw_targets_and_empty_sni_are_compared_without_rewriting(self):
        metric = {"pcap": "capture.pcap", "sha256": "fixture", "output": "output"}
        responses = ["10.0.0.1\t\t1234\t10.0.0.2\t\t80\tGET\t//raw%2fpath?a,b\n", "10.0.0.1\t\t1235\t10.0.0.2\t\t443\t\n"]
        http = {"SrcIP": "10.0.0.1", "DstIP": "10.0.0.2", "SrcPort": 1234, "DstPort": 80, "Method": "GET", "URL": "//raw%2fpath?a,b"}
        tls = {"SrcIP": "10.0.0.1", "DstIP": "10.0.0.2", "SrcPort": 1235, "DstPort": 443}
        with patch.object(mta.subprocess, "check_output", side_effect=responses), patch.object(mta, "records", side_effect=[[http, {"StatusCode": 200}], [tls]]):
            result = mta.compare(Path("tshark"), Path("net"), metric)
        self.assertEqual(result["HTTP"]["missing"], [])
        self.assertEqual(result["TLSClientHello"]["missing"], [])
        self.assertEqual(result["HTTP"]["observed"], 1)

    def test_missing_reference_tuple_fails_the_command(self):
        for missing in ([], [{"tuple": ["lost"], "count": 1}]):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                binary = root / "net"
                binary.write_bytes(b"fixture")
                (root / "replay.json").write_text(json.dumps({"binarySHA256": mta.digest(binary), "receipts": [{}], "metrics": [{"pcap": "capture.pcap"}], "failures": []}))
                compared = {"HTTP": {"reference": 1, "observed": 1, "missing": missing, "additional": 0}, "TLSClientHello": {"reference": 0, "observed": 0, "missing": [], "additional": 0}}
                args = ["mta-regression.py", "--report", "report.md", "--root", str(root), "--binary", str(binary), "--tshark", "tshark", "--compare-only"]
                with patch.object(mta.sys, "argv", args), patch.object(mta, "compare", return_value=compared), contextlib.redirect_stdout(io.StringIO()):
                    status = mta.main()
                self.assertEqual(bool(status), bool(missing))
                self.assertEqual((root / "reference.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
