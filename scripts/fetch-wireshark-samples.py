#!/usr/bin/env python3
"""Fetch the checksum-pinned, NETCAP-compatible Wireshark sample corpus."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "internal/collector/testdata/wireshark/manifest.json"
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_CAPTURE = 64 * 1024 * 1024
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def download(url):
    for attempt in range(5):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "NETCAP sample corpus/1.0"})
            with urllib.request.urlopen(request, timeout=90) as response:
                data = response.read(MAX_ARCHIVE + 1)
                if len(data) > MAX_ARCHIVE:
                    raise ValueError(f"archive exceeds {MAX_ARCHIVE} bytes: {url}")
                return data
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == 4:
                raise
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("download retries exhausted")


def capture_bytes(data, name):
    if name.endswith(".gz"):
        # read() is capped to avoid decompressing an untrusted gzip bomb.
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            data = stream.read(MAX_CAPTURE + 1)
    if len(data) > MAX_CAPTURE:
        raise ValueError(f"capture exceeds {MAX_CAPTURE} bytes: {name}")
    if data[:4] not in PCAP_MAGIC | {PCAPNG_MAGIC}:
        raise ValueError(f"unsupported capture container: {name}")
    return data


def sample_packets(data):
    endian = "<" if data[:4] in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
    packets = []
    position = 24
    while position < len(data):
        if position + 16 > len(data):
            raise ValueError("truncated packet header in PROTOS capture")
        size = struct.unpack_from(endian + "I", data, position + 8)[0]
        end = position + 16 + size
        if end > len(data):
            raise ValueError("truncated packet in PROTOS capture")
        packets.append(data[position:end])
        position = end
    if not packets:
        raise ValueError("empty PROTOS capture")
    stride = max(1, len(packets) // 48)
    selected = [packet for index, packet in enumerate(packets)
                if index < 16 or index >= len(packets) - 16 or index % stride == 0]
    return data[:24] + b"".join(selected)


def convert_netmon(data):
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "source.cap"
        target = Path(directory) / "converted.pcap"
        source.write_bytes(data)
        subprocess.run(["editcap", "-F", "pcap", str(source), str(target)],
                       check=True, timeout=120)
        return target.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="only the committed fast fixtures")
    parser.add_argument("--source-dir", type=Path, help="read pre-downloaded original attachments")
    parser.add_argument("--output", type=Path, default=ROOT / "tests/wireshark-corpus")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    count = 0
    for sample in manifest["samples"]:
        if args.quick and not sample.get("quick"):
            continue
        name = sample["name"]
        sampled = args.quick and sample.get("sampled")
        destination = args.output / (name.removesuffix(".gz") + (".quick.bin" if sampled else ".bin"))
        expected = sample.get("quick_sha256") if sampled else sample["capture_sha256"]
        if destination.is_file():
            with destination.open("rb") as stored:
                data = stored.read(MAX_CAPTURE + 1)
            if expected and hashlib.sha256(data).hexdigest() == expected:
                capture_bytes(data, name.removesuffix(".gz"))
                print(f"cached {name}")
                count += 1
                continue
        if args.source_dir:
            data = (args.source_dir / name).read_bytes()
        else:
            data = download(manifest["base_url"] + name + "?inline=false")
        digest = hashlib.sha256(data).hexdigest()
        if digest != sample["sha256"]:
            raise ValueError(f"{name}: sha256 {digest}, expected {sample['sha256']}")
        capture = convert_netmon(data) if sample.get("convert") == "netmon" else capture_bytes(data, name)
        if hashlib.sha256(capture).hexdigest() != sample["capture_sha256"]:
            raise ValueError(f"{name}: decompressed capture checksum mismatch")
        if sampled:
            capture = sample_packets(capture)
        digest = hashlib.sha256(capture).hexdigest()
        if expected and digest != expected:
            raise ValueError(f"{name}: sampled capture checksum {digest}, expected {expected}")
        temporary = destination.with_suffix(".bin.tmp")
        try:
            temporary.write_bytes(capture)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        print(f"verified {name}: {len(capture)} bytes, capture sha256 {digest}")
        count += 1
    print(f"ready: {count} compatible captures in {args.output}")


if __name__ == "__main__":
    main()
