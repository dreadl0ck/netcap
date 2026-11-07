#!/usr/bin/env python3
"""Independent optional-channel acquisition, exact-artifact review and signed publication."""
import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request

GRANT = "8dfcf2d0cba33bede386eb470daf2ac08caf6540fc2516baab10dd546f90938a"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fetch(url, maximum):
    req = urllib.request.Request(url, headers={"User-Agent": "netcap-enrichment-publisher/1"})
    with urllib.request.urlopen(req, timeout=90) as response:
        if response.status != 200:
            raise ValueError("upstream HTTP status")
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("oversized upstream response")
    return data


def validate_kev(data, license_data, previous, now):
    if sha(license_data) != GRANT:
        raise ValueError("changed CISA CC0 grant")
    value = json.loads(data)
    rows = value["vulnerabilities"]
    count = value["count"]
    if count != len(rows) or not 1600 <= count <= 100000:
        raise ValueError("KEV count floor or declared count mismatch")
    if len({v["cveID"] for v in rows}) != count:
        raise ValueError("duplicate KEV CVE")
    if previous and count * 100 < previous * 95:
        raise ValueError("KEV count decreased more than five percent")
    released = dt.datetime.fromisoformat(value["dateReleased"].replace("Z", "+00:00"))
    age = (now - released).total_seconds()
    if age < -300 or age > 14 * 86400:
        raise ValueError("stale or future KEV source")
    return count


def atomic(path, data, mode=0o644):
    fd, tmp = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def run(args):
    subprocess.run(args, check=True, capture_output=True)


def refresh(args):
    root = Path(args.root)
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    public = root / "public"
    public.mkdir(mode=0o755, exist_ok=True)
    builds = root / "builds"
    builds.mkdir(mode=0o700, exist_ok=True)
    with (root / "refresh.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        work = Path(tempfile.mkdtemp(prefix="build-", dir=builds))
        stage = "previous-publication"
        status = lambda state: atomic(public / "refresh-status.json", json.dumps({
            "format": "netcap-enrichment-refresh/v1", "state": state, "stage": stage,
            "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }, sort_keys=True).encode())
        try:
            status("running")
            previous = 0
            sequence = int(dt.datetime.now(dt.timezone.utc).timestamp())
            if (public / "signed-latest.json").exists():
                result = subprocess.run([args.binary, "-mode", "baseline", "-root", str(public)], check=True, capture_output=True, text=True)
                previous = int(result.stdout)
                old = json.loads(base64.b64decode(json.loads((public / "signed-latest.json").read_bytes())["payload"]))
                sequence = max(sequence, old["sequence"] + 1)
            stage = "acquisition"
            status("running")
            repo = json.loads(fetch("https://api.github.com/repos/cisagov/kev-data", 1 << 20))
            if repo["default_branch"] != "develop":
                raise ValueError("changed KEV default branch")
            commit = json.loads(fetch("https://api.github.com/repos/cisagov/kev-data/commits/develop", 4 << 20))
            revision = commit["sha"]
            if not re.fullmatch("[0-9a-f]{40}", revision):
                raise ValueError("invalid immutable KEV revision")
            prefix = f"https://raw.githubusercontent.com/cisagov/kev-data/{revision}/"
            data = fetch(prefix + "known_exploited_vulnerabilities.json", 64 << 20)
            license_data = fetch(prefix + "LICENSE", 64 << 10)
            count = validate_kev(data, license_data, previous, dt.datetime.now(dt.timezone.utc))
            (work / "kev-input.json").write_bytes(data)
            (work / "LICENSE").write_bytes(license_data)
            (work / "acquisition.json").write_text(json.dumps({"revision": revision, "default_branch": "develop", "input_sha256": sha(data), "input_size": len(data), "grant_sha256": sha(license_data), "count": count}, sort_keys=True))
            stage = "build-and-review"
            status("running")
            kev = work / "kev"
            run([args.binary, "-mode", "kev", "-input", str(work / "kev-input.json"), "-grant", str(work / "LICENSE"), "-revision", revision, "-input-sha256", sha(data), "-output", str(kev)])
            candidate = work / "candidate"
            run([args.binary, "-mode", "combine", "-repo", args.repo, "-kev", str(kev), "-output", str(candidate)])
            payload = (candidate / "unsigned-payload.json").read_bytes()
            meta = json.loads(payload)
            archive = candidate / (meta["archive_sha256"] + ".tar.gz")
            target = public / archive.name
            if target.exists():
                if sha(target.read_bytes()) != meta["archive_sha256"]:
                    raise ValueError("immutable publication conflict")
            else:
                with target.open("xb") as stream:
                    stream.write(archive.read_bytes())
                    stream.flush()
                    os.fsync(stream.fileno())
                target.chmod(0o644)
            atomic(public / "unsigned-payload.json", payload)
            stage = "sign"
            status("running")
            run([args.binary, "-mode", "sign", "-root", str(public), "-key", args.key, "-certificate", args.certificate, "-sequence", str(sequence)])
            for name in ["signed-latest.json", f"signed-{sequence}.json"]:
                (public / name).chmod(0o644)
            run([args.binary, "-mode", "verify", "-root", str(public)])
            stage = "complete"
            status("success")
            print(json.dumps({"sequence": sequence, "archive_sha256": meta["archive_sha256"], "archive_size": meta["archive_size"], "kev_revision": revision, "kev_count": count}, sort_keys=True))
        except Exception:
            status("failed")
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ["binary", "repo", "root", "key", "certificate"]:
        parser.add_argument("--" + name, required=True)
    refresh(parser.parse_args())
