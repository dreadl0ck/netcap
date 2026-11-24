#!/usr/bin/env python3
"""Replay captures through `net capture --service` exactly as try.netcap.io runs.

Stages each capture under its try name in a fresh data directory, starts the
service with docker/service/entrypoint.sh's flags, waits until every preloaded
session is finished and fails unless all complete. `net mcp --pcap` is not a
substitute: it runs local mode with different analysis settings.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# docker/service/entrypoint.sh defaults.
TRY_ARGS = ["-dpi=true", "-service-max-file-size", "104857600", "-service-max-per-hour", "10",
            "-service-expiry", "60", "-service-cleanup", "10"]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.load(response)


def stage(captures, pcaps):
    pcaps.mkdir(parents=True)
    for capture in captures:
        target = pcaps / capture["name"]
        try:
            os.link(capture["source"], target)
        except OSError:
            shutil.copy2(capture["source"], target)


def showcase_report(base, captures, rows, data, dpi, strict):
    stories = json.loads((REPO / "cmd/capture/webui/showcase_stories.json").read_text())
    floors = {
        "WannaCry-ransomware-using-EnternalBlue-exploit.pcap": ["DoublePulsar Backdoor Response", "MS17-010 Probe Response"],
        "snort.log.1426118407.pcap": ["Webshell Command Parameter", "Reverse Shell Indicator In HTTP Request"],
        "traffic-from-malspam-pushing-Dreambot.pcap": ["Onion Destination In DNS", "Onion Destination In Cleartext HTTP"],
        "Blank-Slate-campaign-pushes-Sage-2.2-ransomware.pcap": ["udp.fanout"],
        "botnet-capture-20110810-neris.pcap": ["smtp.fanout", "Host Identity In HTTP Check-in"],
        "mail.pcap": ["Cleartext Password Captured"],
    }
    for name in ("Brazil-malspam-pushes-Banload", "Brazil-malspam-traffic-example",
                 "Brazil-malspam-Solicitacao-de-Orcamento-traffic-example",
                 "Portuguese-invoice-malspam-traffic", "whatsapp-malspam-traffic"):
        floors[name + ".pcap"] = ["Indy Library HTTP Client"]
    failed = False
    sources = set()
    for capture in captures:
        name = capture["name"]
        row = rows.get(name, {})
        if not row.get("isCompleted"):
            continue
        query = urllib.parse.urlencode({"sessionId": row["sessionId"]})
        def endpoint(path):
            return get(f"{base}{path}?{query}")
        errors = []
        try:
            counts = endpoint("/api/alerts/stats")
            alerts = counts.get("byRule") or {}
            audit = endpoint("/api/audit-stats")
            config = endpoint("/api/config")
            story = endpoint("/api/showcase-story")
            pack = config.get("detectionRulePack", {})
            sources.add(pack.get("sha256"))
            if strict and (config.get("admittedSettings", {}).get("dpi") is not dpi or pack.get("source") != "embedded" or not pack.get("sha256")):
                errors.append("missing or mismatched DPI/rule-pack provenance")
            if strict and not story:
                errors.append("missing capture story")
            for rule in floors.get(name, []):
                if strict and alerts.get(rule, 0) == 0:
                    errors.append(f"missing {rule}")
            if strict and any(alerts.get(rule, 0) for rule in ("Potential C2 Beaconing", "SOCKS Proxy Detection", "SOCKS Proxy Detected")):
                errors.append("retired/duplicate rule fired")
            if strict and name in {"snort.log.1426118407.pcap", "traffic-from-malspam-pushing-Dreambot.pcap", "ultimate-PCAP-v20250325.pcapng"} and alerts.get("Non-TLS Traffic on Port 443", 0):
                errors.append("unexpected non-TLS finding on 443")
            if strict and name == "mail.pcap" and alerts.get("Cleartext Password Captured", 0) > 20:
                errors.append("credential findings exceeded the noise budget")
            if strict and name == "smb.pcap" and any(alerts.get(rule) for rule in floors["WannaCry-ransomware-using-EnternalBlue-exploit.pcap"]):
                errors.append("ordinary SMB triggered a backdoor/probe finding")
            pages = {}
            if name.startswith("arp-dns"):
                files = endpoint("/api/extracted-files")
                pages["files"] = files.get("totalCount", 0)
                if not pages["files"] or not row.get("coverage"):
                    errors.append("missing extracted files or partial packet coverage")
            if name.startswith("botnet-capture-20110810"):
                page = endpoint("/api/fingerprints")
                pages["fingerprints"] = page.get("totalCount", 0)
                if not pages["fingerprints"]:
                    errors.append("missing fingerprint inventory")
                next_page = get(f"{base}/api/fingerprints?{query}&offset=1&limit=1&sortField=count")
                if pages["fingerprints"] > 1 and len(next_page.get("fingerprints", [])) != 1:
                    errors.append("fingerprint pagination failed")
            out = data / "results" / row["sessionId"]
            sizes = [p.stat().st_size for p in out.rglob("*") if p.is_file()]
            if strict and name.startswith("Blank-Slate") and (len(sizes) > 30_000 or sum(sizes) > 300 << 20):
                errors.append("Sage output exceeded the file or byte budget")
            print(json.dumps({"capture": name, "alertCounts": alerts, "auditCount": audit.get("totalRecords"),
                              "rulePack": pack, "outputBytes": sum(sizes), "outputFiles": len(sizes),
                              "findings": [x["rule"] for x in (story or {}).get("findings") or []],
                              "pages": pages, "failures": errors}), flush=True)
        except (OSError, ValueError) as err:
            errors.append(str(err))
            print(json.dumps({"capture": name, "failures": errors}), flush=True)
        failed |= strict and bool(errors)
    if strict and (len(sources) != 1 or set(stories) != {c["sha256"] for c in captures}):
        print("Expected a single rule-pack digest and exactly one story per input hash", file=sys.stderr)
        failed = True
    return failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("captures", type=Path, nargs="*", help="captures to stage; default: scripts/try-pcaps.json")
    parser.add_argument("--timeout", type=float, default=3600)
    parser.add_argument("--dpi", default="true", help="try runs a DPI build; use false for nodpi binaries")
    parser.add_argument("--config", type=Path, help="netcap config root with dbs/ (default: empty)")
    parser.add_argument("--compare", help="base URL of a running service to compare names and sizes, e.g. https://try.netcap.io")
    parser.add_argument("--showcase", action="store_true", help="assert findings, coverage, and budgets for the pinned showcase")
    parser.add_argument("--report", action="store_true", help="collect the showcase metrics without applying the acceptance gate")
    args = parser.parse_args()

    if args.captures:
        captures = [{"name": p.name, "source": p.resolve(), "bytes": p.stat().st_size} for p in args.captures]
    else:
        pinned = json.loads((REPO / "scripts/try-pcaps.json").read_text())["captures"]
        captures = []
        for item in pinned:
            source = REPO / item["path"]
            if not source.is_file():
                sys.exit(f"missing {source}; fetch the try captures into pcaps/")
            with source.open("rb") as f:
                if hashlib.file_digest(f, "sha256").hexdigest() != item["sha256"]:
                    sys.exit(f"{source} does not match its pinned SHA-256")
            captures.append({"name": item["name"], "source": source, "bytes": item["bytes"], "sha256": item["sha256"]})
    if args.showcase and (args.captures or args.dpi != "true"):
        parser.error("--showcase requires the full pinned corpus and a DPI build")

    if args.compare:
        remote = {row["name"]: row["size"] for row in get(args.compare.rstrip("/") + "/api/files/input")}
        for capture in captures:
            if remote.get(capture["name"]) != capture["bytes"]:
                print(json.dumps({"compare": capture["name"], "local": capture["bytes"], "remote": remote.get(capture["name"])}))

    root = Path(tempfile.mkdtemp(prefix="netcap-try-parity-"))
    data, config = root / "data", root / "config"
    stage(captures, data / "pcaps")
    if args.config:
        shutil.copytree(args.config, config)
    else:
        config.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("NC_")}
    env.update(HOME=str(root), XDG_CONFIG_HOME=str(root), XDG_DATA_HOME=str(root), NC_CONFIG_ROOT=str(config))
    port = free_port()
    flags = [f if f != "-dpi=true" else f"-dpi={args.dpi}" for f in TRY_ARGS]
    command = [str(args.binary.resolve()), "capture", "--service", "-http", f"127.0.0.1:{port}",
               "-service-data-dir", str(data), *flags, "-service-preload-largest-n", str(max(20, len(captures)))]
    log = (root / "service.log").open("w")
    service = subprocess.Popen(command, env=env, stdout=log, stderr=log)
    base = f"http://127.0.0.1:{port}"
    names = {c["name"] for c in captures}
    deadline = time.monotonic() + args.timeout
    rows = {}
    failed = False
    try:
        while time.monotonic() < deadline and service.poll() is None:
            try:
                rows = {row["name"]: row for row in get(base + "/api/files/input") if row["name"] in names}
            except OSError:
                pass
            if len(rows) == len(names) and all(r.get("isCompleted") or r.get("error") for r in rows.values()):
                break
            time.sleep(2)
        if args.showcase or args.report:
            failed = showcase_report(base, captures, rows, data, args.dpi == "true", args.showcase)
    finally:
        service.send_signal(signal.SIGTERM)
        try:
            service.wait(40)
        except subprocess.TimeoutExpired:
            service.kill()
            service.wait()
        log.close()

    for name in sorted(names, key=lambda n: next(c["bytes"] for c in captures if c["name"] == n)):
        row = rows.get(name, {})
        out = data / "results" / row.get("sessionId", "-")
        runtime = {}
        try:
            runtime = json.loads((out / "analysis-runtime.json").read_text()).get("runtime", {})
        except (OSError, ValueError):
            pass
        status = "completed" if row.get("isCompleted") else "error" if row.get("error") else "unfinished"
        failed |= status != "completed"
        print(json.dumps({"capture": name, "status": status, "seconds": row.get("processingTime"),
                          "coverage": row.get("coverage") or None, "error": row.get("error") or None,
                          "captureEvidence": runtime.get("CaptureEvidence"),
                          "manifest": (out / "capture-manifest.json").exists()}), flush=True)
    print(json.dumps({"workdir": str(root), "log": str(root / "service.log")}))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
