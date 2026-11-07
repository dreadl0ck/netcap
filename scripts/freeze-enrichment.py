#!/usr/bin/env python3
"""Retain an exact credential-free build/source snapshot before an uncommitted deployment."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile


def freeze(repo, binary, output):
    repo = Path(repo).resolve()
    output = Path(output)
    output.mkdir(mode=0o700)
    selected = set()
    env = {**os.environ, "GOWORK": "off", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
    listing = subprocess.check_output(["go", "list", "-deps", "-json", "./cmd/enrichment-server"], cwd=repo, env=env)
    decoder = json.JSONDecoder()
    text = listing.decode()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        text = text.lstrip()[end:]
        directory = Path(value.get("Dir", "/"))
        if directory.is_relative_to(repo):
            for field in ["GoFiles", "CgoFiles", "EmbedFiles", "SFiles", "HFiles", "CFiles", "SysoFiles"]:
                for name in value.get(field, []):
                    selected.add((directory / name).relative_to(repo))
    for directory in ["internal/devicecatalog/channel", "internal/webtech", "internal/servicesignatures"]:
        for path in (repo / directory).iterdir():
            if path.is_file() and path.suffix in [".json", ".txt"]:
                selected.add(path.relative_to(repo))
    for name in ["go.mod", "go.sum", "LICENSE", "internal/devicecatalog/provenance.json", "scripts/freeze-enrichment.py", "scripts/refresh-enrichment.py", "scripts/netcap-enrichment-refresh.service", "scripts/netcap-enrichment-refresh.timer", "docker/enrichment-server/Dockerfile", "docker/enrichment-server/compose.yml"]:
        selected.add(Path(name))
    records = {}
    frozen = output / "source"
    frozen.mkdir()
    bundle = output / "source.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        for name in sorted(selected):
            path = repo / name
            if not path.is_file() or path.is_symlink():
                raise ValueError("nonregular source input")
            data = path.read_bytes()
            records[str(name)] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            target = frozen / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            info = tarfile.TarInfo(str(name))
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(Path(binary).resolve()), "./cmd/enrichment-server"], cwd=frozen, env=env, check=True)
    data = Path(binary).read_bytes()
    receipt = {"format": "netcap-enrichment-source-snapshot/v1", "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(), "working_tree_snapshot": True, "commit_or_release_claim": False, "binary_sha256": hashlib.sha256(data).hexdigest(), "binary_size": len(data), "source_archive_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(), "source_files": records, "build": "GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false ./cmd/enrichment-server", "toolchain": subprocess.check_output(["go", "version"], text=True).strip()}
    (output / "source-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: receipt[k] for k in ["binary_sha256", "source_archive_sha256", "git_head"]}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ["repo", "binary", "output"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    freeze(args.repo, args.binary, args.output)
