#!/usr/bin/env python3
"""Exercise the example gateway policies against counted loopback-only origins."""
import contextlib
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time

EXAMPLES = pathlib.Path(__file__).resolve().parent
BINARY = str(pathlib.Path(sys.argv[1]).resolve())


def port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def gateway(protocol, upstream):
    listen = port(socket.SOCK_DGRAM if protocol == 'dns' else socket.SOCK_STREAM)
    process = subprocess.Popen([BINARY, 'gateway', '--protocol', protocol,
                                '--listen', f'127.0.0.1:{listen}', '--upstream', upstream,
                                '--policy', str(EXAMPLES / (protocol + '-policy.yaml')),
                                '--allow-client', '127.0.0.0/8'])
    try:
        yield listen, process
    finally:
        process.terminate()
        process.wait(timeout=10)


def exact(sock, length):
    data = b''
    while len(data) < length:
        part = sock.recv(length - len(data))
        assert part, 'unexpected EOF'
        data += part
    return data


def test_dns():
    calls = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
        origin.bind(('127.0.0.1', 0))
        origin.settimeout(10)

        def answer():
            query, address = origin.recvfrom(512)
            calls.append(query)
            reply = query[:2] + struct.pack('!H', 0x8180) + query[4:]
            origin.sendto(reply, address)

        thread = threading.Thread(target=answer, daemon=True)
        thread.start()
        with gateway('dns', f'127.0.0.1:{origin.getsockname()[1]}') as (listen, process):
            def query(name):
                wire = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
                packet = struct.pack('!HHHHHH', 42, 0x0100, 1, 0, 0, 0) + wire + struct.pack('!HH', 1, 1)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(0.5)
                    client.sendto(packet, ('127.0.0.1', listen))
                    response = client.recv(512)
                    assert response[:2] == packet[:2]
                    return response[3] & 15

            for _ in range(40):
                assert process.poll() is None, 'DNS gateway exited'
                try:
                    assert query('badexample.test') == 5
                    break
                except TimeoutError:
                    time.sleep(0.05)
            else:
                raise AssertionError('DNS gateway not ready')
            assert not calls, 'denied DNS query reached origin'
            assert query('EXAMPLE.test') == 0, 'allowed DNS example failed'
            thread.join(timeout=5)
            assert len(calls) == 1, 'expected exactly one allowed DNS origin query'


def test_modbus():
    calls = []
    with socket.socket() as origin:
        origin.bind(('127.0.0.1', 0))
        origin.listen()
        origin.settimeout(10)

        def answer():
            connection, _ = origin.accept()
            with connection:
                connection.settimeout(5)
                query = exact(connection, 12)
                calls.append(query)
                connection.sendall(query[:4] + struct.pack('!H', 7) + query[6:8] + b'\x04\x00\x01\x00\x02')

        thread = threading.Thread(target=answer, daemon=True)
        thread.start()
        with gateway('modbus', f'127.0.0.1:{origin.getsockname()[1]}') as (listen, process):
            for _ in range(100):
                assert process.poll() is None, 'Modbus gateway exited'
                try:
                    client = socket.create_connection(('127.0.0.1', listen), timeout=1)
                    break
                except ConnectionRefusedError:
                    time.sleep(0.05)
            else:
                raise AssertionError('Modbus gateway not ready')
            with client:
                client.sendall(struct.pack('!HHHBBHH', 1, 0, 6, 1, 6, 0, 1))
                assert exact(client, 9)[7:] == b'\x86\x01', 'write must return illegal-function exception'
                assert not calls, 'denied Modbus write reached origin'
                client.sendall(struct.pack('!HHHBBHH', 2, 0, 6, 1, 3, 0, 2))
                assert exact(client, 13)[7:] == b'\x03\x04\x00\x01\x00\x02'
            thread.join(timeout=5)
            assert len(calls) == 1, 'expected exactly one allowed Modbus origin request'


test_dns()
test_modbus()
print('PASS: DNS and Modbus example policies allow valid reads and prevent denied origin traffic')
