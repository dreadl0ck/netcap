import argparse
import hashlib
import json
import os
import subprocess
import zipfile
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory


def capture_rows(binary, capture, out, env, flags):
    subprocess.run([str(binary), "capture", "--read", str(capture), "--out", str(out), "--quiet", "--geoDB=false", *flags],
                   env=env, check=True, timeout=60)
    files = sorted(out.glob("Protobuf.ncap*"))
    if len(files) > 1:
        raise ValueError(f"{out.name}: multiple Protobuf audits")
    if not files:
        return []
    result = subprocess.run([str(binary), "dump", "--read", str(files[0]), "--json"],
                            env=env, check=True, timeout=30, capture_output=True, text=True)
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def check(binary, archive, root):
    capture = root / "pb_multifield_udp.pcap"
    addressbook = root / "pb_addressbook_udp_tcp.pcap"
    schema = root / "schema"
    schema.mkdir()
    prefix = "netcap-v0.16.11-synthetic-repros/repro/v1611/protobuf/"
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != "6d5c914a95b343096f86e454ee67a122a1da47b1172dcc82d8dc39f70312133e":
            raise ValueError("unexpected v0.16.11 synthetic archive digest")
        with zipfile.ZipFile(source) as bundle:
            capture.write_bytes(bundle.read(prefix + capture.name))
            addressbook.write_bytes(bundle.read(prefix + addressbook.name))
            (schema / "flat.proto").write_bytes(bundle.read(prefix + "proto/flat.proto"))

    env = {k: v for k, v in os.environ.items() if not k.startswith("NC_")}
    env.update(HOME=str(root), XDG_CONFIG_HOME=str(root), XDG_DATA_HOME=str(root))
    for name, flags in (
        ("default", []),
        ("schema-only", ["--proto-paths", str(schema)]),
        ("wire", ["--include", "UDP,Protobuf"]),
        ("mapped", ["--proto-paths", str(schema), "--proto-message-types", "9001:t.Flat"]),
    ):
        rows = capture_rows(binary, capture, root / name, env, flags)
        methods = sorted({row.get("DetectionMethod", "") for row in rows})
        print(json.dumps({"mode": name, "rows": len(rows), "methods": methods}), flush=True)
        if name in {"default", "schema-only"} and rows:
            raise ValueError(f"{name}: generic Protobuf emitted without opt-in")
        if name == "wire" and (len(rows) != 9 or methods != ["configured"]
                               or any(row.get("SchemaResolved") or not row.get("Fields") for row in rows)):
            raise ValueError("wire opt-in did not preserve nine generic field records")
        if name == "mapped" and (len(rows) != 3 or methods != ["configured"]
                                 or any(row.get("DstPort") != 9001 or row.get("FullMessageName") != "t.Flat"
                                        or not row.get("SchemaResolved") or not row.get("SchemaFields") for row in rows)):
            raise ValueError("schema mapping did not decode only the mapped t.Flat datagrams")

    if capture_rows(binary, addressbook, root / "addressbook-default", env, []):
        raise ValueError("AddressBook fixture emitted Protobuf without opt-in")
    rows = capture_rows(binary, addressbook, root / "addressbook-wire", env, ["--include", "TCP,UDP,Protobuf"])
    ports = Counter(row.get("DstPort") for row in rows)
    if ports != {8124: 1, 9999: 3} or any(row.get("DetectionMethod") != "configured"
                                        or row.get("SchemaResolved") or not row.get("Fields") for row in rows):
        raise ValueError(f"AddressBook wire opt-in lost TCP or UDP field records: {ports}")
    print(json.dumps({"fixture": addressbook.name, "default_rows": 0, "wire_records_by_dst_port": ports}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check V1611-2 Protobuf selection modes on the pinned archive.")
    parser.add_argument("binary", type=Path)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="netcap-protobuf-recheck-") as directory:
        check(args.binary.resolve(), args.archive, Path(directory))
