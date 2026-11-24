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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("captures", type=Path, nargs="*", help="captures to stage; default: scripts/try-pcaps.json")
    parser.add_argument("--timeout", type=float, default=3600)
    parser.add_argument("--dpi", default="true", help="try runs a DPI build; use false for nodpi binaries")
    parser.add_argument("--config", type=Path, help="netcap config root with dbs/ (default: empty)")
    parser.add_argument("--compare", help="base URL of a running service to compare names and sizes, e.g. https://try.netcap.io")
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
            captures.append({"name": item["name"], "source": source, "bytes": item["bytes"]})

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
    try:
        while time.monotonic() < deadline and service.poll() is None:
            try:
                rows = {row["name"]: row for row in get(base + "/api/files/input") if row["name"] in names}
            except OSError:
                pass
            if len(rows) == len(names) and all(r.get("isCompleted") or r.get("error") for r in rows.values()):
                break
            time.sleep(2)
    finally:
        service.send_signal(signal.SIGTERM)
        try:
            service.wait(40)
        except subprocess.TimeoutExpired:
            service.kill()

    failed = False
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
