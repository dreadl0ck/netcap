#!/usr/bin/env python3
"""Exercise an extracted CLI artifact without downloads or external traffic."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import struct
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def packet(port):
    payload = b'netcap-candidate-qualification'
    udp = struct.pack('!HHHH', 12345, port, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2'))
    total = sum(struct.unpack('!10H', ip))
    total = (total & 65535) + (total >> 16)
    ip = ip[:10] + struct.pack('!H', (~total) & 65535) + ip[12:]
    return bytes.fromhex('00112233445566778899aabb0800') + ip + udp


def rows(directory):
    paths = list(Path(directory).glob('*UDP*'))
    if len(paths) != 1:
        raise ValueError('expected one UDP output, got ' + str(paths))
    records = [json.loads(line) for line in paths[0].read_text().splitlines() if line.strip()]
    if not records or records.pop(0).get('Type') != 37:
        raise ValueError('missing UDP audit header')
    return records


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def http_fixture(path, body):
    request = b'GET /candidate.bin HTTP/1.1\r\nHost: fixture.test\r\n\r\n'
    response = b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
    packets = [(False, 2, 100, 0, b''), (True, 18, 500, 101, b''), (False, 16, 101, 501, b''),
               (False, 24, 101, 501, request), (True, 24, 501, 101 + len(request), response),
               (False, 17, 101 + len(request), 501 + len(response), b''),
               (True, 17, 501 + len(response), 102 + len(request), b''),
               (False, 16, 102 + len(request), 502 + len(response), b'')]
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, (server, flags, sequence, ack, data) in enumerate(packets):
            source, destination = socket.inet_aton('192.0.2.1'), socket.inet_aton('198.51.100.1')
            sport, dport = 12345, 80
            if server:
                source, destination, sport, dport = destination, source, dport, sport
            tcp = struct.pack('!HHIIBBHHH', sport, dport, sequence, ack, 80, flags, 4096, 0, 0)
            pseudo = source + destination + struct.pack('!BBH', 0, 6, len(tcp) + len(data))
            tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp + data)) + tcp[18:]
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + len(data), index, 0, 64, 6, 0, source, destination)
            ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
            frame = bytes.fromhex('0200000000020200000000010800') + ip + tcp + data
            stream.write(struct.pack('<IIII', 1700000000, index * 1000, len(frame), len(frame)) + frame)


def qualify(args):
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('NC_', 'DYLD_', 'PKG_CONFIG'))}
    env.update(HOME=str(output), NC_CONFIG_ROOT=str(output / 'config'), GOMAXPROCS='2', RAYON_NUM_THREADS='2')
    report = dict(schema='netcap-packaged-client/v1', host=platform.platform(), machine=platform.machine(),
                  binary=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  state='started', bpf='not-requested', yara='not-requested')

    def run(arguments, name):
        result = subprocess.run([str(binary), *arguments], env=env, text=True, capture_output=True, timeout=90)
        (output / (name + '.log')).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(name + ' failed (exit ' + str(result.returncode) + '); inspect its retained log')
        return result.stdout

    try:
        report['version'] = run(['--version'], 'version')
        if args.source_revision and '> NETCAP build commit: ' + args.source_revision + '\n' not in report['version']:
            raise ValueError('artifact does not report the expected source revision')
        pcap = output / 'input.pcap'
        with pcap.open('wb') as stream:
            stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for port in (9999, 8888):
                data = packet(port)
                stream.write(struct.pack('<IIII', 1700000000, 0, len(data), len(data)) + data)
        for name, bpf, expected in [('all', '', 2)] + ([('filtered', 'udp dst port 9999', 1)] if args.require_bpf else []):
            destination = output / name
            command = ['capture', '-read', str(pcap), '-out', str(destination), '-workers', '2', '-include', 'UDP',
                       '-dpi=false', '-geoDB=false', '-network-detection=false', '-quiet', '-http', '', '-compress=false', '-json']
            if bpf:
                command += ['-bpf', bpf]
            run(command, name)
            if len(rows(destination)) != expected:
                raise ValueError('wrong UDP count for ' + name)
            report[name + 'UDPRecords'] = expected
        if args.require_bpf:
            report['bpf'] = 'passed'
        if args.require_yara:
            rules = output / 'rules'
            rules.mkdir()
            (rules / 'candidate.yar').write_text('rule candidate { strings: $a="NETCAP_SIGNED_YARA_MARKER" condition: $a }')
            config = output / 'file.yaml'
            config.write_text('file_extraction:\n  advanced:\n    enable_yara_scanning: true\n    yara_rules_path: ' + json.dumps(str(rules)) + '\n')
            for name, body, matches in [('positive', b'NETCAP_SIGNED_YARA_MARKER', ['candidate']), ('negative', b'negative-control', [])]:
                fixture = output / (name + '.pcap')
                http_fixture(fixture, body)
                destination = output / ('yara-' + name)
                run(['capture', '-read', str(fixture), '-out', str(destination), '-include', 'HTTP,File', '-workers', '2',
                     '-file-config', str(config), '-fileStorage', 'files', '-context=true', '-compress=false', '-json',
                     '-dpi=false', '-geoDB=false', '-network-detection=false', '-http', '', '-quiet', '-y'], 'yara-' + name)
                analysis = json.loads((destination / 'artifact-analysis.json').read_text())
                if analysis['state'] != 'complete' or len(analysis['results']) != 1:
                    raise ValueError('native YARA artifact analysis incomplete')
                analyzers = next(iter(analysis['results'].values()))['analyzers']
                yara = [result for result in analyzers if result['engine'] == 'yara-x']
                if len(yara) != 1 or yara[0].get('matches', []) != matches or yara[0].get('error'):
                    raise ValueError('native YARA match/nonmatch failed: ' + str(yara))
            report['yaraScanControls'] = 'HTTP PCAP -> extracted file -> native positive/negative scans passed'
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            base = 'http://127.0.0.1:' + str(port)
            with (output / 'service.log').open('w') as log:
                process = subprocess.Popen([str(binary), 'capture', '-service', '-service-data-dir', str(output / 'service'),
                                            '-http', '127.0.0.1:' + str(port), '-workers', '2', '-dpi=false', '-geoDB=false'],
                                           env=env, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError('service exited; inspect service.log')
                        try:
                            with urlopen(base + '/', timeout=1) as response:
                                html = response.read().decode()
                            break
                        except OSError:
                            if time.monotonic() > deadline:
                                raise RuntimeError('service startup timed out')
                            time.sleep(.2)
                    assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
                    if not assets:
                        raise ValueError('packaged frontend has no assets')
                    for asset in assets:
                        with urlopen(base + asset, timeout=5) as response:
                            if response.status != 200 or not response.read():
                                raise ValueError('missing frontend asset')
                    with urlopen(base + '/api/yara/status', timeout=5) as response:
                        if json.load(response)['available'] is not True:
                            raise ValueError('packaged native YARA unavailable')
                    for source, expected in [('rule candidate { condition: true }', 200), ('rule broken { condition: }', 400)]:
                        body = ('--candidate\r\nContent-Disposition: form-data; name="file"; filename="candidate.yar"\r\nContent-Type: text/plain\r\n\r\n' + source + '\r\n--candidate--\r\n').encode()
                        request = Request(base + '/api/yara/rules/upload', data=body, headers={'Content-Type': 'multipart/form-data; boundary=candidate'})
                        try:
                            with urlopen(request, timeout=15) as response:
                                status = response.status
                        except HTTPError as error:
                            status = error.code
                        if status != expected:
                            raise ValueError('YARA compiler HTTP result mismatch')
                    report.update(yara='passed', frontendAssets=len(assets))
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        report['state'] = 'passed'
    except Exception as error:
        report.update(state='failed', error=str(error))
        raise
    finally:
        (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(output / 'qualification.json')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-revision')
    parser.add_argument('--require-bpf', action='store_true')
    parser.add_argument('--require-yara', action='store_true')
    qualify(parser.parse_args())
