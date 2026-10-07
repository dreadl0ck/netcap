"""Local fixtures for an egress-disabled FlightSim namespace; no external targets."""
import hashlib
import json
import socket
import ssl
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import paramiko


def address(name):
    if name == "api.open.wisdom.alphasoc.net":
        return "127.0.0.2"
    if name == "api.telegram.org":
        return "127.0.0.4"
    if name.startswith("mx."):
        return "127.0.0.%d" % (10 + int(hashlib.sha256(name.encode()).hexdigest()[:4], 16) % 150)
    return "127.0.0.3"


def dns_name(name):
    return b"".join(bytes([len(part)]) + part.encode() for part in name.rstrip(".").split(".")) + b"\0"


def dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 53))
    while True:
        request, peer = sock.recvfrom(65535)
        cursor, labels = 12, []
        while request[cursor]:
            size = request[cursor]
            labels.append(request[cursor + 1:cursor + size + 1].decode())
            cursor += size + 1
        cursor += 1
        kind, _ = struct.unpack("!HH", request[cursor:cursor + 4])
        name = ".".join(labels)
        question = request[12:cursor + 4]
        if kind == 1:
            body = socket.inet_aton(address(name))
        elif kind == 15:
            body = b"\0\x0a" + dns_name("mx." + name)
        elif kind == 16:
            body = b"\x02ok"
        else:
            body = None
        answer = b"" if body is None else b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(body)) + body
        response = request[:2] + struct.pack("!HHHHH", 0x8180, 1, int(body is not None), 0, 0) + question + answer
        sock.sendto(response, peer)


class API(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        query = parse_qs(urlparse(self.path).query)
        category = query.get("category", [""])[0]
        domain = {"sinkholed": "sink.example", "c2": "c2.example", "imposter": "imposter.example", "irc": "irc.example"}.get(category, "miner.example")
        ip = {"c2": "127.0.0.5", "sinkholed": "127.0.0.6", "cryptomining": "127.0.0.7", "irc": "127.0.0.8"}.get(category, "127.0.0.3")
        port = {"cryptomining": 3333, "irc": 6667}.get(category, 8080)
        body = json.dumps({"Items": [{"Domain": domain, "IP": ip, "Port": port, "Protocol": "tcp"} for _ in range(20)]}).encode()
        if self.server.server_address[0] == "127.0.0.4":
            self.send_response(401)
            body = b'{"ok":false}'
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def https(ip):
    server = HTTPServer((ip, 443), API)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/lab/cert.pem", "/lab/key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


class SSHServer(paramiko.ServerInterface):
    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, channel):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class DiscardHandle(paramiko.SFTPHandle):
    def write(self, offset, data):
        return paramiko.SFTP_OK


class SFTPServer(paramiko.SFTPServerInterface):
    def open(self, path, flags, attr):
        return DiscardHandle(flags)


def ssh_connection(conn):
    try:
        transport = paramiko.Transport(conn)
        transport.add_server_key(paramiko.RSAKey.from_private_key_file("/lab/ssh-key.pem"))
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, SFTPServer)
        transport.start_server(server=SSHServer())
        while transport.is_active():
            threading.Event().wait(0.05)
    except (EOFError, paramiko.SSHException, OSError):
        pass
    finally:
        conn.close()


def connection(conn, port):
    try:
        conn.settimeout(10)
        if port == 3333:
            conn.recv(4096)
            conn.sendall(b'{"id":1,"result":[],"error":null}\n')
        elif port == 6667:
            received = b""
            while b"USER " not in received:
                received += conn.recv(4096)
            nick = next(line.split()[1] for line in received.splitlines() if line.startswith(b"NICK "))
            conn.sendall(b":lab 001 " + nick + b" :Welcome\r\n")
        elif port not in (25, 8080):
            conn.recv(4096)
    except (OSError, StopIteration):
        pass
    finally:
        conn.close()


def listener(ip, port, ssh=False):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    sock.listen(20)
    while True:
        conn, _ = sock.accept()
        target = ssh_connection if ssh else lambda conn: connection(conn, port)
        threading.Thread(target=target, args=(conn,), daemon=True).start()


threading.Thread(target=dns, daemon=True).start()
for ip in ("127.0.0.2", "127.0.0.4"):
    threading.Thread(target=https, args=(ip,), daemon=True).start()
for port in (22, 443, 465, 993, 995):
    threading.Thread(target=listener, args=("127.0.0.3", port, True), daemon=True).start()
for port in (21, 23, 25, 110, 143, 873, 3333, 6667, 8080):
    threading.Thread(target=listener, args=("0.0.0.0", port), daemon=True).start()
threading.Event().wait()
