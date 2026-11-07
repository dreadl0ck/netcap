#!/usr/bin/env python3
"""Validate published Markdown and execute its marked, offline lab commands."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
from urllib.parse import unquote, urlsplit
from urllib.request import urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
FENCES = re.compile(r"^```[^\n]*\n.*?^```[ \t]*$", re.M | re.S)
LINKS = re.compile(r"!?\[[^\]]*\]\((<[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)|(?:src|page|url)=[\"']([^\"']+)[\"']")
MARKED = re.compile(r"<!-- docs:(run|serve) ([\w-]+) -->\s*```sh\n(.*?)```", re.S)


def targets(text):
    for match in LINKS.finditer(FENCES.sub("", text)):
        yield (match.group(1) or match.group(2)).strip("<>").replace(r"\(", "(").replace(r"\)", ")")


def anchors(text):
    headings = re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", FENCES.sub("", text), re.M)
    return {re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-") for h in headings}


def static_checks():
    pages = [DOCS / unquote(urlsplit(t).path) for t in targets((DOCS / "SUMMARY.md").read_text())]
    marked = {}
    for page in pages:
        text = page.read_text()
        assert "\0" not in text, f"NUL bytes: {page}"
        for target in targets(text):
            url = urlsplit(target)
            if url.scheme or url.netloc or target.startswith("/"):
                continue
            resolved = (page.parent / unquote(url.path)).resolve() if url.path else page.resolve()
            assert resolved.exists(), f"Missing {target} in {page.name}"
            if resolved.suffix == ".md" and url.fragment:
                assert unquote(url.fragment) in anchors(resolved.read_text()), f"Missing anchor {target} in {page.name}"
        for block in re.findall(r"^```(?:sh|bash)\n(.*?)^```", text, re.M | re.S):
            subprocess.run(["bash", "-n"], input=block, text=True, check=True, capture_output=True)
        for mode, name, block in MARKED.findall(text):
            assert name not in marked, f"Duplicate runnable block {name}"
            marked[name] = mode, block
    print(f"PASS: {len(pages)} navigation pages, local links/anchors and shell syntax", flush=True)
    return marked


def ndjson(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def qualify(binary, marked, workspace, require_yara=False):
    for name in ("scripts", "docs"):
        os.symlink(ROOT / name, workspace / name, target_is_directory=True)
    env = dict(os.environ, NETCAP_BIN=str(binary), NC_CONFIG_ROOT=str(workspace / "config"), TZ="UTC")
    prefix = 'set -euo pipefail\nnet() { "$NETCAP_BIN" "$@"; }\n'

    def run(name):
        mode, block = marked[name]
        assert mode == "run", name
        result = subprocess.run(["bash", "-c", prefix + block], cwd=workspace, env=env,
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(f"Documentation block {name} failed ({result.returncode})\n{result.stdout}\n{result.stderr}")
        print(f"PASS: published block {name}", flush=True)

    def dump(path):
        if not path.exists():
            return []
        result = subprocess.run([str(binary), "dump", "-read", str(path), "-json"], cwd=workspace,
                                env=env, check=True, capture_output=True, text=True, timeout=30)
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

    run("fixtures")
    run("investigation")
    fixtures = workspace / "doc-fixtures"
    assert len(ndjson(fixtures / "dns.ndjson")) == 2
    http = ndjson(fixtures / "http.ndjson")
    assert len(http) == 1 and "/fixture.txt" in http[0]["URL"], http
    files = ndjson(fixtures / "files.ndjson")
    expected = b"Netcap synthetic evidence.\n"
    expected_hash = hashlib.sha256(expected).hexdigest()
    assert len(files) == 1 and files[0]["Hashes"]["SHA256"] == expected_hash, files
    location = Path(files[0]["Location"])
    if not location.is_absolute():
        location = workspace / location
    assert location.read_bytes() == expected and files[0]["IsComplete"], files
    assert any(a["RuleName"] == "Documentation HTTP Transfer" for a in ndjson(fixtures / "alerts.ndjson"))
    secrets = dump(fixtures / "audit/Secret.ncap.gz")
    assert any("lab-user" in json.dumps(s) and "lab-password" in json.dumps(s) for s in secrets), secrets
    run("related")
    related = json.loads((fixtures / "related.json").read_text())
    assert related, related
    run("control")
    assert not any(a.get("RuleName") == "Documentation HTTP Transfer" for a in dump(fixtures / "control/Alert.ncap.gz"))
    assert not dump(fixtures / "control/Secret.ncap.gz")
    run("packet-export")
    with zipfile.ZipFile(fixtures / "http-evidence.zip") as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["sourcePackets"] == 10 and manifest["selectedPackets"] == 8, manifest
        assert hashlib.sha256(bundle.read("packets.pcapng")).hexdigest() == manifest["outputSHA256"]
    run("network-policy")
    run("grammar")
    grammar = json.loads((fixtures / "grammar-comparison.json").read_text())
    assert any(d["field"] == "text" and d["before"] == "hello" and d["after"] == "world" for d in grammar["differences"]), grammar
    run("sensor-seal")
    run("sensor-import")
    run("sensor-prune")

    # Refuse a preexisting listener; the guide's explicit URL must hit our process.
    import socket
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 8080))
    mode, serve = marked["baseline"]
    assert mode == "serve"
    with (workspace / "baseline-server.log").open("w") as log:
        process = subprocess.Popen(["bash", "-c", prefix + serve], cwd=workspace, env=env,
                                   stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, "Baseline server exited; inspect baseline-server.log"
                try:
                    with urlopen("http://127.0.0.1:8080/api/behavior", timeout=1) as response:
                        state = json.load(response)
                    if state.get("samples", 0) >= 4 and state["watermark"] - state["learningStarted"] >= 1_000_000_000:
                        break
                except (OSError, ValueError):
                    pass
                assert time.monotonic() < deadline, "Baseline did not become ready"
                time.sleep(0.2)
            run("approve-baseline")
        finally:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    approved = json.loads((fixtures / "approved.json").read_text())
    run("monitor-baseline")
    unchanged = dump(fixtures / "unchanged-audit/Alert.ncap.gz")
    assert not unchanged, unchanged
    changed = ndjson(fixtures / "behavior-alerts.ndjson")
    assert changed, "Changed MAC generated no behavioral observation"
    after = json.loads((fixtures / "baseline-audit/Behavior.json").read_text())
    assert after["baselineId"] == approved["baselineId"] and after["approved"] == approved["approved"]
    print("PASS: expected records/bytes, positive and benign rules, packet counts, grammar, signed bundles and baseline lifecycle", flush=True)

    mode, serve = marked["yara"]
    assert mode == "serve"
    with (workspace / "yara-server.log").open("w") as log:
        process = subprocess.Popen(["bash", "-c", prefix + serve], cwd=workspace, env=env,
                                   stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, "YARA lab server exited"
                try:
                    with urlopen("http://127.0.0.1:8080/api/yara/status", timeout=1) as response:
                        status = json.load(response)
                    if (fixtures / "yara-audit/File.ncap.gz").exists():
                        # Wait for shutdown/finalization of the offline processing,
                        # not merely creation of an open gzip file.
                        dump(fixtures / "yara-audit/File.ncap.gz")
                        break
                except (OSError, ValueError, subprocess.CalledProcessError):
                    pass
                assert time.monotonic() < deadline, "YARA lab did not finalize"
                time.sleep(0.2)
            if not status["available"]:
                assert not require_yara, "YARA is required for this qualification"
                print("SKIP: YARA positive/negative scans (not compiled in this binary)", flush=True)
            else:
                run("yara-scan")
                positive = json.loads((fixtures / "yara-positive.json").read_text())
                negative = json.loads((fixtures / "yara-negative.json").read_text())
                assert "Netcap_Documentation_Fixture" in positive["matches"], positive
                assert negative["matches"] == [], negative
                print("PASS: native YARA positive and negative scanner controls", flush=True)
        finally:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--net", type=Path)
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--require-yara", action="store_true")
    parser.add_argument("--work-dir", type=Path, help="new directory to retain diagnostics")
    args = parser.parse_args()
    marked = static_checks()
    if args.static_only:
        return
    if not args.net:
        parser.error("--net is required unless --static-only is used")
    binary = args.net.resolve(strict=True)
    if args.work_dir:
        args.work_dir.mkdir()
        qualify(binary, marked, args.work_dir.resolve(), args.require_yara)
    else:
        with tempfile.TemporaryDirectory(prefix="netcap-docs-") as directory:
            qualify(binary, marked, Path(directory), args.require_yara)


if __name__ == "__main__":
    main()
