#!/usr/bin/env python3
"""Qualify actual installed optional data through the CLI and parent HTTP API."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

binary = str(Path(sys.argv[1]).resolve())
config = Path(sys.argv[2]).resolve()
work = Path(sys.argv[3]).resolve()
work.mkdir(parents=True)
env = {key: value for key, value in os.environ.items() if not key.startswith("NC_")}
env.update(NC_CONFIG_ROOT=str(config), NC_ENRICHMENT_ROOT=str(config / "enrichment"))

def execute(*args):
    result = subprocess.run([binary, *map(str, args)], env=env, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout

bootp = bytearray(240)
bootp[0:4] = bytes([1, 1, 6, 0])
bootp[4:8] = struct.pack("!I", 1)
bootp[28:34] = bytes.fromhex("001122334455")
bootp[236:240] = bytes.fromhex("63825363")
dhcp = bytes(bootp) + bytes.fromhex("3501013703010306ff")
udp = struct.pack("!HHHH", 68, 67, 8 + len(dhcp), 0)
ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(dhcp), 1, 0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([255] * 4)))
checksum = sum(struct.unpack("!10H", ip))
while checksum >> 16:
    checksum = (checksum & 65535) + (checksum >> 16)
ip[10:12] = struct.pack("!H", (~checksum) & 65535)
frame = bytes.fromhex("ffffffffffff0011223344550800") + ip + udp + dhcp
pcap = work / "owned-option55.pcap"
pcap.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame)
audits = work / "audits"
execute("capture", "-http", "", "-read", pcap, "-out", audits, "-quiet", "-dpi=false", "-geoDB=false")
hosts = [json.loads(line) for line in execute("dump", "-read", audits / "Host.ncap.gz", "-json").splitlines() if line.lstrip().startswith("{")]
assert any(host.get("Addr") == "192.0.2.1" and "Xbox 360" in host.get("Devices", []) for host in hosts), hosts
captured = json.loads((audits / "service-signatures-status.json").read_text())
assert captured["source"] == "external" and not captured["degraded"], captured

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
url = f"http://127.0.0.1:{port}"
log = (work / "parent.log").open("w")
parent = subprocess.Popen([binary, "capture", "-http", f"127.0.0.1:{port}", "-out", str(audits), "-quiet", "-dpi=false", "-geoDB=false"], env=env, stdout=log, stderr=subprocess.STDOUT)

def request(path):
    with urllib.request.urlopen(url + path, timeout=10) as response:
        assert response.status == 200
        return json.load(response)

try:
    for attempt in range(100):
        assert parent.poll() is None, "owned parent exited"
        try:
            version = request("/api/version")
            break
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    else:
        raise AssertionError("parent readiness timed out")
    catalogue = request("/api/service-signatures")
    assert catalogue["source"] == "external" and catalogue["degraded"] is False, catalogue
    assert catalogue["inventory"]["source_sha256"] == captured["source_sha256"]
    recorded = request("/api/service-signatures/status")
    assert recorded["source_sha256"] == captured["source_sha256"] and recorded["scope"] == "capture", recorded
    devices = request("/api/dbs/status")["deviceCatalogues"]
    assert len(devices) == 2 and all(item["scope"] == "installation" and item["state"] == "verified-installed" and item["version"] for item in devices), devices
    (work / "receipt.json").write_text(json.dumps({"version": version, "dhcp_host_label": "Xbox 360", "catalogue": catalogue["inventory"], "recorded_capture": recorded, "installed_devices": devices, "trust_overrides": False}, indent=2) + "\n")
finally:
    parent.terminate()
    try:
        parent.wait(timeout=10)
    except subprocess.TimeoutExpired:
        parent.kill()
        parent.wait(timeout=10)
    log.close()
print("PASS: real optional DHCP CLI label, installed catalogue API, recorded capture identity and read-only installation inventory")
