"""A multi-port local lab for running the whole extscan pipeline end to end.

The unit tests hand the probes a pre-built Service. This lab is for the other
half: real nmap discovery, real nuclei, real report. Every listener sits on its
own loopback address (127.0.0.2 by default) so a scan of that /32 sees the lab
and nothing else running on the workstation.

    uv run python -m tests.lab              # foreground, Ctrl-C to stop

See docs/LAB.md for the walkthrough and what each port should produce.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

from . import targetapp
from .test_new_tools import IISHandler
from .test_snmp import FakeAgent

DEFAULT_HOST = "127.0.0.2"

PORTS = {
    "ssh": 2222,
    "docker": 2375,
    "mysql": 3306,
    "redis": 6379,
    "http": 8080,
    "iis": 8081,
    "https": 8443,
    "elasticsearch": 9200,
    "snmp": 10161,
}


# Per-read timeout for every HTTP handler. Without one, nmap's
# http-slowloris-check (categorised "safe", so in the default script set) holds
# each connection open for minutes and the TCP stage takes ten times longer.
HTTP_TIMEOUT = 5


class _LabHTTP:
    timeout = HTTP_TIMEOUT
    server_version = ""

    def version_string(self):
        # The stdlib appends sys_version after a space even when it is empty,
        # and the trailing space defeats nmap's `Server: Microsoft-IIS/` match.
        return self.server_version


class TargetAppHandler(_LabHTTP, targetapp.Handler):
    server_version = targetapp.Handler.server_version


class LabIISHandler(_LabHTTP, IISHandler):
    server_version = IISHandler.server_version


class _Quiet:
    """Scanners hang up mid-request constantly; that is not worth a traceback."""

    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError, ssl.SSLError)):
            super().handle_error(request, client_address)


class _TCPServer(_Quiet, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _HTTPServer(_Quiet, ThreadingHTTPServer):
    pass


class SSHBanner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
        with contextlib.suppress(OSError):
            self.request.settimeout(5)
            self.request.recv(256)


class MySQLGreeting(socketserver.BaseRequestHandler):
    """Protocol-10 handshake packet; enough for nmap to name the version."""

    def handle(self):
        body = (b"\x0a" + b"5.7.33-log\x00" + (42).to_bytes(4, "little")
                + b"abcdefgh\x00" + b"\xff\xf7" + b"\x21" + b"\x02\x00" + b"\xff\x81"
                + b"\x15" + b"\x00" * 10 + b"ijklmnopqrst\x00"
                + b"mysql_native_password\x00")
        self.request.sendall(len(body).to_bytes(3, "little") + b"\x00" + body)
        with contextlib.suppress(OSError):
            self.request.settimeout(5)
            self.request.recv(256)


class RedisNoAuth(socketserver.BaseRequestHandler):
    """Answers PING and INFO without asking for a password, like a default install."""

    INFO = b"# Server\r\nredis_version:5.0.7\r\nredis_mode:standalone\r\nos:Linux\r\n"

    def handle(self):
        self.request.settimeout(10)
        while True:
            try:
                data = self.request.recv(4096)
            except OSError:
                return
            if not data:
                return
            upper = data.upper()
            if b"PING" in upper:
                reply = b"+PONG\r\n"
            elif b"INFO" in upper:
                reply = b"$%d\r\n%s\r\n" % (len(self.INFO), self.INFO)
            else:
                reply = b"-ERR unknown command\r\n"
            with contextlib.suppress(OSError):
                self.request.sendall(reply)


class _JSONHandler(BaseHTTPRequestHandler):
    """JSON API that answers byte-for-byte like the real product.

    nmap's signatures for these match exact header order and JSON layout, so
    the stdlib's default Server header and error page would leave the port
    unidentified (or named as Python's BaseHTTPServer).
    """

    protocol_version = "HTTP/1.0"
    timeout = HTTP_TIMEOUT
    error_content_type = "application/json"
    error_message_format = '{"message":"%(message)s"}'
    routes: ClassVar[dict[str, object]] = {}

    def log_message(self, *a):
        pass

    def send_response(self, code, message=None):
        self.send_response_only(code, message)

    def response_headers(self) -> list[tuple[str, str]]:
        return [("Content-Type", "application/json")]

    def render(self, doc: object) -> bytes:
        return json.dumps(doc, separators=(",", ":")).encode() + b"\n"

    def do_GET(self):
        doc = self.routes.get(self.path.split("?")[0])
        body = self.render(doc if doc is not None else {"message": "page not found"})
        self.send_response(200 if doc is not None else 404)
        for k, v in self.response_headers():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ElasticsearchHandler(_JSONHandler):
    routes: ClassVar[dict[str, object]] = {"/": {
        "name": "es-node-1", "cluster_name": "billing-logs",
        "cluster_uuid": "lab-cluster-uuid",
        "version": {"number": "6.8.0", "build_flavor": "default",
                    "lucene_version": "7.7.0"},
        "tagline": "You Know, for Search",
    }}

    def response_headers(self) -> list[tuple[str, str]]:
        return [("content-type", "application/json; charset=UTF-8")]

    def render(self, doc: object) -> bytes:
        return json.dumps(doc, indent=2, separators=(",", " : ")).encode() + b"\n"


class DockerAPIHandler(_JSONHandler):
    routes: ClassVar[dict[str, object]] = {
        "/version": {"Version": "19.03.12", "ApiVersion": "1.40", "Os": "linux",
                     "Arch": "amd64", "KernelVersion": "5.4.0-42-generic"},
    }

    def response_headers(self) -> list[tuple[str, str]]:
        return [("Content-Type", "application/json"), ("Date", self.date_time_string())]


class _TLSHTTPServer(_HTTPServer):
    """Handshakes in the per-connection thread, not in accept().

    Wrapping the listening socket instead would handshake inside the accept
    loop, so one client that connects and sends nothing (nmap's NULL probe
    does exactly that) stalls every other connection to the port.
    """

    def __init__(self, addr, handler, ctx: ssl.SSLContext):
        super().__init__(addr, handler)
        self.ctx = ctx

    def finish_request(self, request, client_address):
        request.settimeout(10)
        try:
            request = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        super().finish_request(request, client_address)


class SNMPAgent(FakeAgent):
    """FakeAgent rebound to the lab address, answering any OID in the walk."""

    def __init__(self, host: str, port: int, accept: dict[str, str]):
        super().__init__(accept)
        self.sock.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.port = port


def _self_signed_cert(host: str) -> tuple[str, str]:
    d = Path(tempfile.mkdtemp(prefix="extscan-lab-"))
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
         "-subj", "/CN=billing.lab.invalid/O=extscan lab",
         "-addext", f"subjectAltName=IP:{host},DNS:billing.lab.invalid",
         "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True)
    return str(cert), str(key)


def start(host: str = DEFAULT_HOST) -> list:
    """Start every listener in background threads; returns them for shutdown."""
    targetapp.SPEC["servers"][0]["url"] = f"http://{host}:{PORTS['http']}/api"

    servers: list = [
        _TCPServer((host, PORTS["ssh"]), SSHBanner),
        _TCPServer((host, PORTS["mysql"]), MySQLGreeting),
        _TCPServer((host, PORTS["redis"]), RedisNoAuth),
        _HTTPServer((host, PORTS["docker"]), DockerAPIHandler),
        _HTTPServer((host, PORTS["http"]), TargetAppHandler),
        _HTTPServer((host, PORTS["iis"]), LabIISHandler),
        _HTTPServer((host, PORTS["elasticsearch"]), ElasticsearchHandler),
    ]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*_self_signed_cert(host))
    servers.append(_TLSHTTPServer((host, PORTS["https"]), TargetAppHandler, ctx))

    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    agent = SNMPAgent(host, PORTS["snmp"], {"public": "Linux lab-router 4.19.0 #1 SMP x86_64"})
    agent.__enter__()
    servers.append(agent)
    return servers


def stop(servers: list) -> None:
    for srv in servers:
        if isinstance(srv, FakeAgent):
            srv.__exit__(None, None, None)
        else:
            srv.shutdown()
            srv.server_close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help=f"loopback address to bind (default {DEFAULT_HOST})")
    args = ap.parse_args()

    servers = start(args.host)
    print(f"extscan lab listening on {args.host}:")
    for name, port in PORTS.items():
        proto = "udp" if name == "snmp" else "tcp"
        print(f"  {port:>5}/{proto}  {name}")
    print("Ctrl-C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        stop(servers)


if __name__ == "__main__":
    main()
