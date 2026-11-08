#!/usr/bin/env python3
"""Create synthetic, offline-only documentation fixtures in a new directory."""

import argparse
import socket
import struct
from pathlib import Path

CLIENT = "192.0.2.10"
SERVER = "192.0.2.20"
CLIENT_MAC = bytes.fromhex("020000000010")
SERVER_MAC = bytes.fromhex("020000000020")
BODY = b"Netcap synthetic evidence.\n"


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ipv4(payload, protocol, reverse=False):
    src, dst = (SERVER, CLIENT) if reverse else (CLIENT, SERVER)
    source, target = socket.inet_aton(src), socket.inet_aton(dst)
    pseudo = source + target + struct.pack("!BBH", 0, protocol, len(payload))
    offset = 16 if protocol == 6 else 6
    payload = payload[:offset] + struct.pack("!H", checksum(pseudo + payload) or 65535) + payload[offset + 2:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0, source, target)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    macs = CLIENT_MAC + SERVER_MAC if reverse else SERVER_MAC + CLIENT_MAC
    return macs + b"\x08\x00" + header + payload


def tcp(seq, ack, flags, payload=b"", reverse=False):
    src, dst = (8080, 40000) if reverse else (40000, 8080)
    segment = struct.pack("!HHIIBBHHH", src, dst, seq, ack, 0x50, flags, 65535, 0, 0) + payload
    return ipv4(segment, 6, reverse)


def pcap(path, frames, start=1700000000, spacing=1):
    with path.open("xb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            output.write(struct.pack("<IIII", start + index * spacing, 0, len(frame), len(frame)))
            output.write(frame)


def arp(mac):
    header = b"\xff" * 6 + mac + b"\x08\x06"
    return header + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac + socket.inet_aton(CLIENT) + SERVER_MAC + socket.inet_aton(SERVER)


def generate(root):
    root.mkdir()
    question = b"\x04docs\x07example\x04test\0" + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0) + question
    answer = struct.pack("!HHHHHH", 1234, 0x8180, 1, 1, 0, 0) + question
    answer += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(SERVER)
    udp_query = struct.pack("!HHHH", 53000, 53, 8 + len(query), 0) + query
    udp_answer = struct.pack("!HHHH", 53, 53000, 8 + len(answer), 0) + answer
    request = b"GET /fixture.txt HTTP/1.1\r\nHost: docs.example.test\r\nAuthorization: Basic bGFiLXVzZXI6bGFiLXBhc3N3b3Jk\r\nConnection: close\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=fixture.txt\r\nContent-Length: " + str(len(BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + BODY
    client_end, server_end = 1001 + len(request), 5001 + len(response)
    http = [tcp(1000, 0, 2), tcp(5000, 1001, 18, reverse=True), tcp(1001, 5001, 16),
            tcp(1001, 5001, 24, request), tcp(5001, client_end, 24, response, True),
            tcp(client_end, server_end, 17), tcp(server_end, client_end + 1, 17, reverse=True),
            tcp(client_end + 1, server_end + 1, 16)]
    pcap(root / "investigation.pcap", [ipv4(udp_query, 17), ipv4(udp_answer, 17, True), *http])
    pcap(root / "benign.pcap", [ipv4(udp_query, 17), ipv4(udp_answer, 17, True)])
    pcap(root / "baseline.pcap", [arp(CLIENT_MAC)] * 4, spacing=2)
    pcap(root / "unchanged.pcap", [arp(CLIENT_MAC)] * 2, start=1700000010)
    pcap(root / "changed.pcap", [arp(bytes.fromhex("020000000099"))] * 2, start=1700000020)
    (root / "client.bin").write_bytes(bytes.fromhex("010568656c6c6f"))
    (root / "other-client.bin").write_bytes(bytes.fromhex("0105776f726c64"))
    (root / "sensor.key").write_bytes(bytes(range(32)))
    print(f"Created {root}: synthetic PCAPs, directional bytes and a public lab-only sensor key; no packets sent")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("doc-fixtures"))
    generate(parser.parse_args().out)
