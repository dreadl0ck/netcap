#!/usr/bin/env python3
"""Exercise a freshly built CLI or container with synthetic capture data."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary")
    parser.add_argument("--image")
    args = parser.parse_args()
    if bool(args.binary) == bool(args.image):
        parser.error("choose --binary or --image")
    with tempfile.TemporaryDirectory(prefix="netcap-native-smoke-") as directory:
        root = Path(directory).resolve()
        root.chmod(0o777)
        env = {k: v for k, v in os.environ.items() if not k.startswith("NC_")}
        env.update(HOME=str(root), NC_CONFIG_ROOT=str(root / "config"), GOMAXPROCS="2")

        def command(options, port=None):
            if args.binary:
                return [str(Path(args.binary).resolve()), *options]
            base = ["docker", "run", "--rm", "--cpus=2", "--memory=2g", "--pids-limit=256",
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", "-v", f"{root}:{root}",
                    "-e", "HOME", "-e", "NC_CONFIG_ROOT", "-e", "GOMAXPROCS=2"]
            base += ["-p", f"127.0.0.1:{port}:{port}"] if port else ["--network=none"]
            return [*base, "--entrypoint", "/usr/bin/net", args.image, *options]

        pcap = root / "input.pcap"
        with pcap.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for port in (9999, 8888):
                udp = struct.pack("!HHHH", 12345, port, 21, 0) + b"qualification"
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                                 socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2"))
                total = sum(struct.unpack("!10H", ip))
                total = (total & 65535) + (total >> 16)
                ip = ip[:10] + struct.pack("!H", (~total) & 65535) + ip[12:]
                packet = bytes.fromhex("00112233445566778899aabb0800") + ip + udp
                output.write(struct.pack("<IIII", 1700000000, 0, len(packet), len(packet)) + packet)
        for name, bpf, wanted in (("all", "udp", 2), ("filtered", "udp dst port 9999", 1)):
            dest = root / name
            subprocess.run(command(["capture", "-read", str(pcap), "-out", str(dest), "-workers", "2",
                                    "-include", "UDP", "-bpf", bpf, "-dpi=false", "-geoDB=false",
                                    "-network-detection=false", "-quiet", "-http", "", "-compress=false", "-json"]),
                           env=env, check=True, timeout=120)
            files = list(dest.glob("*UDP*"))
            assert len(files) == 1, files
            rows = [json.loads(line) for line in files[0].read_text().splitlines() if line.strip()]
            assert rows.pop(0)["Type"] == 37
            assert len(rows) == wanted, rows
            print(name, "UDP records:", len(rows), flush=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        host = "0.0.0.0" if args.image else "127.0.0.1"
        proc = subprocess.Popen(command(["capture", "-service", "-service-data-dir", str(root / "service"),
                                         "-http", f"{host}:{port}", "-workers", "2", "-dpi=false", "-geoDB=false"], port), env=env)
        try:
            url = f"http://127.0.0.1:{port}"
            for _ in range(150):
                if proc.poll() is not None:
                    raise RuntimeError("service exited before readiness")
                try:
                    with urllib.request.urlopen(url, timeout=1) as response:
                        html = response.read().decode()
                    break
                except OSError:
                    time.sleep(.2)
            else:
                raise RuntimeError("service startup timeout")
            assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
            assert assets, html
            for asset in assets:
                with urllib.request.urlopen(url + asset, timeout=5) as response:
                    assert response.status == 200 and response.read()
            with urllib.request.urlopen(url + "/api/yara/status", timeout=5) as response:
                assert json.load(response)["available"] is True
            for source, wanted in (("rule qualification { condition: true }", 200), ("rule broken { condition: }", 400)):
                body = ('--qualification\r\nContent-Disposition: form-data; name="file"; filename="qualification.yar"\r\n'
                        'Content-Type: text/plain\r\n\r\n' + source + '\r\n--qualification--\r\n').encode()
                request = urllib.request.Request(url + "/api/yara/rules/upload", data=body,
                                                 headers={"Content-Type": "multipart/form-data; boundary=qualification"})
                try:
                    with urllib.request.urlopen(request, timeout=10) as response:
                        code = response.status
                except urllib.error.HTTPError as error:
                    code = error.code
                assert code == wanted, (code, wanted)
            print("PASS: native BPF positive/negative, service assets, YARA availability and valid/invalid compile", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
