"""Web coverage: unnamed web ports, virtual hosts, edge products, being blocked.

Each class plants one case on loopback and would fail if the behaviour quietly
stopped working:

* a web application on a port nmap labelled `unknown` is identified and gets
  the normal checks in the same probe run, once;
* a site served only for one `Host` header is reported, a wildcard server is
  not, and the connection only ever goes to the in-scope address;
* a service behind an edge product says so;
* a service that throttles or blocks the path checks ends as a coverage gap,
  keeps what was found, and is retried.
"""

import contextlib
import io
import json
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

from evals import local

from extscan import pipeline
from extscan.models import WEB_IDENTIFY_KEY, Finding, Host, Service
from extscan.policy import Policy
from extscan.probes import ProbeContext, probes_for
from extscan.runner import Runner
from extscan.scope import Scope
from extscan.tools import net, vhost, waf, webid

ENV = "APP_ENV=production\nDB_PASSWORD=not-a-real-password\n"


class _Handler(BaseHTTPRequestHandler):
    """Root page, a readable /.env, 404 for the rest. Subclasses bend it."""

    server_version = "web"
    sys_version = ""
    extra_headers: ClassVar[dict[str, str]] = {}

    def log_message(self, *a):
        pass

    def reply(self, code: int, body: str = "", ctype: str = "text/html") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in self.extra_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def page(self, path: str) -> None:
        if path == "/":
            return self.reply(200, "<html><title>Portal</title></html>")
        if path == "/.env":
            return self.reply(200, ENV, "text/plain")
        return self.reply(404)

    def do_GET(self):
        self.page(self.path.split("?")[0])


class _Site:
    """A loopback HTTP server that records every request it parses."""

    def __init__(self, handler: type[BaseHTTPRequestHandler] = _Handler,
                 tls: ssl.SSLContext | None = None, port: int = 0):
        self.requests: list[tuple[str, str]] = []      # (Host header, path)
        seen = self.requests

        class Recording(handler):
            def parse_request(self):
                ok = super().parse_request()
                seen.append(((self.headers.get("Host") or "") if ok else "",
                             getattr(self, "path", "")))
                return ok

        ThreadingHTTPServer.allow_reuse_address = True
        self.server = ThreadingHTTPServer(("127.0.0.1", port), Recording)
        self.server.daemon_threads = True
        if tls is not None:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _Case(unittest.TestCase):
    """A scope of 127.0.0.1 only, a temp run directory, and quiet stages."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="extscan-webcov-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        scope_path = self.tmp / "scope.json"
        scope_path.write_text(json.dumps({
            "engagement": "web coverage", "client": "self-test",
            "authorization": {"reference": "LOCAL-TEST",
                              "authorized_by": "test harness (loopback only)"},
            "targets": ["127.0.0.1/32"], "allow_private": True, "max_hosts": 2,
        }))
        self.scope = Scope.load(scope_path)
        self.policy = Policy()
        self.policy.http.timeout_sec = 3
        self.policy.max_workers = 4
        self.store = pipeline.init_run(str(self.tmp / "runs"), self.scope, self.policy,
                                       run_id="r")
        self.runner = Runner(self.store)

    def site(self, *args, **kwargs) -> _Site:
        s = _Site(*args, **kwargs)
        self.addCleanup(s.close)
        return s

    def seed(self, port: int, name: str = "http", **fields) -> Service:
        svc = Service(host="127.0.0.1", port=port, proto="tcp", name=name, **fields)
        self.store.save_services([svc])
        return svc

    def probe(self, runner: Runner | None = None, **kwargs) -> tuple[dict, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = pipeline.probe(self.store, self.scope, self.policy,
                                    runner or self.runner, skip_nuclei=True, **kwargs)
        return result, out.getvalue()

    def service(self, port: int) -> Service:
        return next(s for s in self.store.services() if s.port == port)

    def gaps(self, stage: str) -> list:
        return [d for d in self.store.degradations() if d.stage == stage]

    def own_gaps(self) -> list:
        """Everything but the nuclei gap that `skip_nuclei` always records."""
        return [d for d in self.store.degradations() if d.stage != "probe:nuclei"]

    def titles(self, source: str = "") -> list[str]:
        return [f.title for f in self.store.findings() if f.source.startswith(source)]


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _tls_context(tmp: Path, sans: str) -> ssl.SSLContext:
    cert, key = tmp / "cert.pem", tmp / "key.pem"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/CN=default.corp.example", "-addext", f"subjectAltName={sans}",
             "-keyout", str(key), "-out", str(cert)],
            check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise unittest.SkipTest(f"openssl cannot make a test certificate: {exc}") from exc
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


# --------------------------------------------------------------------------
# net.request_at and hostname validation
# --------------------------------------------------------------------------

class TestRequestAt(_Case):
    def test_connects_to_the_ip_and_carries_the_name_in_the_host_header(self):
        site = self.site()
        resp = net.request_at("127.0.0.1", site.port, self.scope, self.policy.http,
                              tls=False, host="app.corp.example")
        self.assertEqual(resp.status, 200)
        self.assertEqual(site.requests, [("app.corp.example", "/")])

    def test_out_of_scope_ip_is_refused_before_any_connection(self):
        site = self.site()
        # 127.0.0.2 reaches the same listener on Linux only if bound to it; the
        # point is that nothing is sent, which the recorded requests show.
        resp = net.request_at("127.0.0.2", site.port, self.scope, self.policy.http, tls=False)
        self.assertEqual((resp.status, resp.failed_at), (0, "scope"))
        self.assertIn("scope refusal", resp.error)
        self.assertEqual(site.requests, [])

    def test_a_hostname_is_never_a_connection_target(self):
        resp = net.request_at("localhost", 80, self.scope, self.policy.http, tls=False)
        self.assertEqual((resp.status, resp.failed_at), (0, "scope"))

    def test_hostile_host_values_are_not_sent(self):
        site = self.site()
        for bad in ("a.example\r\nX-Injected: 1", "a.example\nGET /admin", "*.corp.example",
                    "corp example.com", "10.0.0.1", "évil.example", "a..example",
                    "-a.example", "x" * 64 + ".example", "a.example/path", "a.example:80"):
            resp = net.request_at("127.0.0.1", site.port, self.scope, self.policy.http,
                                  tls=False, host=bad)
            self.assertEqual((resp.status, resp.failed_at), (0, "scope"), bad)
        self.assertEqual(site.requests, [])

    def test_valid_hostname_normalises_and_rejects(self):
        self.assertEqual(net.valid_hostname("App.Corp.Example."), "app.corp.example")
        self.assertEqual(net.valid_hostname("xn--bcher-kva.example"), "xn--bcher-kva.example")
        for bad in ("", "localhost", "*.example.com", "127.0.0.1", "::1", "a_b.example",
                    "a.example\r\n", " ", "a." * 130 + "example", None):
            if bad == "a.example\r\n":
                # Surrounding whitespace is stripped; what comes back is clean.
                self.assertEqual(net.valid_hostname(bad), "a.example")
                continue
            self.assertEqual(net.valid_hostname(bad), "", repr(bad))

    def test_redirects_are_recorded_not_followed(self):
        class Redirect(_Handler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.send_header("Content-Length", "0")
                self.end_headers()

        site = self.site(Redirect)
        resp = net.request_at("127.0.0.1", site.port, self.scope, self.policy.http, tls=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("169.254.169.254", resp.headers["location"])
        self.assertEqual(len(site.requests), 1)

    def test_a_non_http_banner_is_not_a_response(self):
        port = _banner_server(self, b"SSH-2.0-OpenSSH_9.6\r\n")
        resp = net.request_at("127.0.0.1", port, self.scope, self.policy.http, tls=False)
        self.assertEqual((resp.status, resp.failed_at), (0, "http"))

    def test_refused_connection_is_reported_as_such(self):
        resp = net.request_at("127.0.0.1", _closed_port(), self.scope, self.policy.http,
                              tls=False)
        self.assertEqual((resp.status, resp.failed_at), (0, "connect"))


def _banner_server(case: unittest.TestCase, banner: bytes) -> int:
    class Banner(socketserver.BaseRequestHandler):
        def handle(self):
            with contextlib.suppress(OSError):
                self.request.sendall(banner)
                self.request.recv(1024)

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Banner)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05},
                     daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return srv.server_address[1]


# --------------------------------------------------------------------------
# 1. Web services nmap could not name
# --------------------------------------------------------------------------

class TestIdentifyUnnamedWebServices(_Case):
    def test_only_unnamed_open_tcp_services_are_asked(self):
        def svc(name, **kw):
            return Service(host="127.0.0.1", port=kw.pop("port", 7777),
                           proto=kw.pop("proto", "tcp"), name=name, **kw)

        for name in ("", "unknown", "tcpwrapped", "afs3-fileserver?", "UNKNOWN"):
            self.assertTrue(webid.needs_identifying(svc(name)), name)
        for name in ("ssh", "mysql", "postgresql", "smtp", "redis", "ms-wbt-server"):
            self.assertFalse(webid.needs_identifying(svc(name)), name)
        self.assertFalse(webid.needs_identifying(svc("http")))
        self.assertFalse(webid.needs_identifying(svc("unknown", port=8080)))   # already web
        self.assertFalse(webid.needs_identifying(svc("unknown", proto="udp")))
        self.assertFalse(webid.needs_identifying(svc("unknown", state="open|filtered")))

    def test_unknown_port_is_identified_and_checked_in_the_same_run(self):
        site = self.site()
        self.seed(site.port, name="unknown")
        self.assertEqual([p.name for p in probes_for(self.service(site.port))], [])

        self.probe()

        svc = self.service(site.port)
        self.assertTrue(svc.is_http)
        self.assertFalse(svc.is_tls)
        self.assertEqual((svc.name, svc.tunnel), ("http", ""))
        self.assertEqual(svc.scripts[WEB_IDENTIFY_KEY], "http")
        self.assertIn("identified by extscan (nmap reported unknown)", svc.extrainfo)
        self.assertEqual(svc.product, "web")
        self.assertIn(webid.MARK, svc.probed_by)
        self.assertIn("http_fingerprint", svc.probed_by)
        self.assertEqual(svc.base_url(), f"http://127.0.0.1:{site.port}")
        self.assertTrue(any(t.startswith("HTTP service: Portal") for t in self.titles()))
        self.assertTrue(any(t.startswith("Exposed /.env ") for t in self.titles()))
        self.assertEqual(self.gaps(webid.STAGE), [])

    def test_nuclei_is_handed_the_identified_service(self):
        """The step runs before nuclei picks targets, so the gap names this host."""
        site = self.site()
        self.seed(site.port, name="tcpwrapped")
        self.probe()
        nuclei_gaps = self.gaps("probe:nuclei")
        self.assertEqual(len(nuclei_gaps), 1)
        self.assertIn("1 web service(s)", nuclei_gaps[0].impact)

    def test_second_run_does_not_ask_again(self):
        site = self.site()
        other = _banner_server(self, b"220 mail ready\r\n")
        self.seed(site.port, name="unknown")
        self.seed(other, name="unknown")
        self.probe()
        first = len(site.requests)
        self.assertGreater(first, 0)

        _, out = self.probe()
        self.assertEqual(len(site.requests), first)
        self.assertNotIn("identifying", out)

    def test_dry_run_sends_nothing_and_marks_nothing(self):
        site = self.site()
        self.seed(site.port, name="unknown")
        result, out = self.probe(Runner(self.store, dry_run=True))
        self.assertEqual(site.requests, [])
        self.assertIn(f"[dry-run] would try TLS then GET / on 127.0.0.1/tcp/{site.port}", out)
        svc = self.service(site.port)
        self.assertEqual((svc.name, svc.probed_by, svc.scripts), ("unknown", [], {}))
        self.assertTrue(result["dry_run"])
        self.assertEqual(self.own_gaps(), [])

    def test_identified_services_are_not_sent_a_get(self):
        site = self.site()
        self.seed(site.port, name="ssh", product="OpenSSH")
        self.seed(_closed_port(), name="mysql")
        self.probe()
        self.assertEqual(site.requests, [])
        self.assertEqual(self.service(site.port).name, "ssh")
        self.assertEqual(self.gaps(webid.STAGE), [])

    def test_non_http_service_is_left_alone_and_marked(self):
        port = _banner_server(self, b"220 mail.corp.example ESMTP\r\n")
        self.seed(port, name="unknown")
        self.probe()
        svc = self.service(port)
        self.assertFalse(svc.is_http)
        self.assertEqual((svc.name, svc.extrainfo, svc.scripts), ("unknown", "", {}))
        self.assertEqual(svc.probed_by, [webid.MARK])
        self.assertEqual(self.own_gaps(), [])

    def test_unreachable_port_is_a_gap_then_cleared_by_a_clean_run(self):
        port = _closed_port()
        self.seed(port, name="unknown")
        self.probe()                               # must not raise
        gaps = self.gaps(webid.STAGE)
        self.assertEqual(len(gaps), 1)
        self.assertTrue(gaps[0].reason.startswith(f"127.0.0.1/tcp/{port}: "))
        self.assertIn("--only web_identify", gaps[0].remedy)
        self.assertEqual(self.service(port).probed_by, [])

        self.site(port=port)                       # the service comes back
        self.probe()
        self.assertEqual(self.gaps(webid.STAGE), [])
        self.assertTrue(self.service(port).is_http)

    def test_out_of_scope_service_is_a_gap_and_gets_no_request(self):
        site = self.site()
        self.store.save_services([Service(host="127.0.0.9", port=site.port, proto="tcp",
                                          name="unknown")])
        self.probe()
        self.assertEqual(site.requests, [])
        gaps = self.gaps(webid.STAGE)
        self.assertEqual(len(gaps), 1)
        self.assertIn("scope refusal", gaps[0].reason)

    def test_identification_survives_rediscovery(self):
        """Discovery replaces the record with nmap's view but keeps `scripts`."""
        site = self.site()
        self.seed(site.port, name="unknown")
        self.probe()
        self.seed(site.port, name="unknown")       # nmap runs again, still baffled
        svc = self.service(site.port)
        self.assertEqual(svc.name, "unknown")
        self.assertTrue(svc.is_http)
        self.assertFalse(webid.needs_identifying(svc))

    def test_tls_web_service_is_identified_as_https(self):
        site = self.site(tls=_tls_context(self.tmp, "DNS:default.corp.example"))
        self.seed(site.port, name="unknown")
        self.policy.http.max_vhosts = 0
        self.probe(only=[webid.MARK])
        svc = self.service(site.port)
        self.assertEqual((svc.name, svc.tunnel), ("http", "ssl"))
        self.assertTrue(svc.is_http and svc.is_tls)
        self.assertEqual(svc.base_url(), f"https://127.0.0.1:{site.port}")
        self.assertEqual(len(site.requests), 1)    # handshake and GET on one connection


# --------------------------------------------------------------------------
# 2. Virtual hosts
# --------------------------------------------------------------------------

class TestVirtualHosts(_Case):
    def names(self, *names: str) -> None:
        self.store.save_hosts([Host(ip="127.0.0.1", hostnames=list(names), state="up")])

    def test_one_distinct_name_gives_exactly_one_finding(self):
        site = self.site(local.VhostHandler)
        self.seed(site.port)
        self.names(local.VHOST_NAME, local.SAME_SITE_NAME)
        self.probe(only=["vhosts"])

        findings = [f for f in self.store.findings() if f.source == "extscan:vhost"]
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.title, f"Virtual host {local.VHOST_NAME} on 127.0.0.1:{site.port} "
                                  "serves a different site")
        self.assertEqual(f.severity, "info")
        self.assertTrue(f.review_required)
        self.assertIn("none of the other checks", f.description)
        self.assertIn("200 OK, title 'Billing back office'", f.evidence)
        self.assertIn("by address (127.0.0.1) -> 200 OK, title 'Portal'", f.evidence)
        self.assertIn("recorded hostname", f.evidence)
        # One request by address, one random name for the shared parent, one per name.
        hosts = [h for h, _ in site.requests]
        self.assertEqual(len(hosts), 4)
        self.assertEqual(hosts[0], f"127.0.0.1:{site.port}")
        self.assertTrue(hosts[1].endswith(".corp.example"))
        self.assertEqual(sorted(hosts[2:]), sorted([local.VHOST_NAME, local.SAME_SITE_NAME]))
        self.assertEqual({p for _, p in site.requests}, {"/"})
        # Reported, not adopted: no new scope, no leads, no extra service.
        self.assertFalse(self.scope.contains(local.VHOST_NAME))
        self.assertEqual(self.store.leads(), [])
        self.assertEqual(len(self.store.services()), 1)
        self.assertIn("vhosts", self.service(site.port).probed_by)

    def test_wildcard_server_gives_nothing(self):
        site = self.site(local.WildcardHandler)
        self.seed(site.port)
        self.names(local.VHOST_NAME, local.SAME_SITE_NAME, "mail.other.example")
        self.probe(only=["vhosts"])
        self.assertEqual(self.titles("extscan:vhost"), [])
        self.assertEqual(self.own_gaps(), [])
        self.assertEqual(len(site.requests), 6)    # by address, 2 random parents, 3 names

    def test_no_candidate_names_means_no_requests(self):
        site = self.site()
        self.seed(site.port)
        self.probe(only=["vhosts"])
        self.assertEqual(site.requests, [])
        self.assertIn("vhosts", self.service(site.port).probed_by)

    def test_candidates_drop_wildcards_addresses_and_junk(self):
        svc = Service(host="127.0.0.1", port=443, proto="tcp", name="https")
        names, left = vhost.candidates(
            svc, ["b.corp.example", "B.corp.example."],
            ["*.corp.example", "127.0.0.1", "a.corp.example", "b.corp.example",
             "x.example\r\nHost: evil", "2001:db8::1", "intranet"], limit=25)
        self.assertEqual(names, [("b.corp.example", "recorded hostname"),
                                 ("a.corp.example", "certificate SAN")])
        self.assertEqual(left, 0)

    def test_max_vhosts_bounds_requests_and_the_rest_is_a_gap(self):
        site = self.site(local.WildcardHandler)
        self.seed(site.port)
        self.names(*[f"n{i}.corp.example" for i in range(10)])
        self.policy.http.max_vhosts = 3
        self.probe(only=["vhosts"])
        self.assertEqual(len(site.requests), 5)    # by address, one random, three names
        gaps = self.gaps("probe:vhosts")
        self.assertEqual(len(gaps), 1)
        self.assertIn("7 candidate name(s) not tried (http.max_vhosts=3)", gaps[0].reason)
        self.assertNotIn("vhosts", self.service(site.port).probed_by)

        self.policy.http.max_vhosts = 25           # operator raises the cap
        self.probe(only=["vhosts"])
        self.assertEqual(self.gaps("probe:vhosts"), [])
        self.assertIn("vhosts", self.service(site.port).probed_by)

    def test_max_vhosts_zero_turns_the_check_off(self):
        site = self.site(local.VhostHandler)
        self.seed(site.port)
        self.names(local.VHOST_NAME)
        self.policy.http.max_vhosts = 0
        self.probe(only=["vhosts"])
        self.assertEqual(site.requests, [])
        self.assertEqual(self.titles("extscan:vhost"), [])

    def test_inter_request_delay_is_honoured(self):
        site = self.site(local.WildcardHandler)
        self.seed(site.port)
        self.names("a.corp.example", "b.corp.example")
        self.policy.http.inter_request_delay = 0.1
        started = time.perf_counter()
        self.probe(only=["vhosts"])
        self.assertGreaterEqual(time.perf_counter() - started, 0.3)   # 3 delayed requests

    def test_out_of_scope_address_is_refused(self):
        site = self.site(local.VhostHandler)
        svc = Service(host="127.0.0.9", port=site.port, proto="tcp", name="http")
        with self.assertRaises(RuntimeError) as caught:
            vhost.check(svc, self.scope, self.policy.http,
                        [(local.VHOST_NAME, "recorded hostname")])
        self.assertIn("scope refusal", str(caught.exception))
        self.assertEqual(site.requests, [])

    def test_throttled_while_enumerating_is_a_gap_not_a_finding(self):
        """A name asked just after a 429 starts would differ from both baselines."""
        class Limited(local.WildcardHandler):
            served: ClassVar[list[int]] = [0]

            def do_GET(self):
                self.served[0] += 1
                if self.served[0] > 3:
                    return self._send(429, "slow down")
                return super().do_GET()

        site = self.site(Limited)
        self.seed(site.port)
        self.names(*[f"n{i}.corp.example" for i in range(6)])
        self.probe(only=["vhosts"])
        self.assertEqual(self.titles("extscan:vhost"), [])
        self.assertEqual(len(site.requests), 4)    # stops at the first 429
        gaps = self.gaps("probe:vhosts")
        self.assertEqual(len(gaps), 1)
        self.assertIn("429", gaps[0].reason)
        self.assertNotIn("vhosts", self.service(site.port).probed_by)

    def test_tls_names_come_from_the_certificate_and_travel_as_sni(self):
        ctx = _tls_context(self.tmp, "DNS:shop.corp.example,DNS:*.corp.example,IP:127.0.0.1")
        sni: list[str | None] = []
        ctx.sni_callback = lambda sock, name, c: sni.append(name)

        class ByName(_Handler):
            def do_GET(self):
                host = (self.headers.get("Host") or "").split(":")[0]
                if host == "shop.corp.example":
                    return self.reply(200, "<html><title>Shop admin</title></html>")
                return self.reply(200, "<html><title>Default</title></html>")

        site = self.site(ByName, tls=ctx)
        self.seed(site.port, name="http", tunnel="ssl")
        self.probe(only=["vhosts"])

        titles = self.titles("extscan:vhost")
        self.assertEqual(titles, [f"Virtual host shop.corp.example on 127.0.0.1:{site.port} "
                                  "serves a different site"])
        finding = next(f for f in self.store.findings() if f.source == "extscan:vhost")
        self.assertIn("certificate SAN", finding.evidence)
        self.assertIn("TLS SNI", finding.description)
        self.assertIn("shop.corp.example", sni)
        # The wildcard and the IP SAN were never sent as a name.
        sent = {h for h, _ in site.requests}
        self.assertFalse(any("*" in h for h in sent))
        self.assertEqual(sum(1 for n in sni if n and n.endswith(".corp.example")), 2)


# --------------------------------------------------------------------------
# 3. Edge products and being blocked
# --------------------------------------------------------------------------

class TestEdgeFingerprint(_Case):
    def test_table_matches_documented_headers_and_cookies(self):
        cases = {
            "Cloudflare": {"cf-ray": "8a1b2c3d4e5f-LHR", "server": "cloudflare"},
            "Akamai": {"server": "AkamaiGHost"},
            "Imperva (Incapsula)": {"set-cookie": "visid_incap_12345=abc; path=/, "
                                                  "incap_ses_1_12345=def; path=/"},
            "Sucuri": {"x-sucuri-id": "14013"},
            "AWS CloudFront": {"x-amz-cf-id": "abc==", "via": "1.1 x.cloudfront.net"},
            "AWS Application Load Balancer": {
                "set-cookie": "AWSALB=xyz; Expires=Thu, 19 Nov 2026 10:00:00 GMT; Path=/"},
            "AWS WAF": {"x-amzn-waf-action": "challenge"},
            "Fastly": {"x-served-by": "cache-lhr7325-LHR"},
            "F5 BIG-IP": {"set-cookie": "session=1; path=/, BIGipServerpool_web=167837.20480.0000"},
            "Azure Front Door": {"x-azure-ref": "0abc"},
        }
        for product, headers in cases.items():
            self.assertEqual([name for name, _ in waf.fingerprint(headers)], [product])

    def test_ordinary_headers_name_no_product(self):
        self.assertEqual(waf.fingerprint({
            "server": "nginx/1.24.0", "set-cookie": "sessionid=abc; Path=/; HttpOnly",
            "via": "1.1 varnish", "x-served-by": "web-03", "content-type": "text/html"}), [])
        # Body text is never consulted: a page may mention any vendor.
        self.assertEqual(waf.fingerprint({"content-type": "text/html"}), [])

    def test_service_behind_an_edge_gets_one_info_finding(self):
        class Edge(_Handler):
            extra_headers: ClassVar[dict[str, str]] = {"CF-RAY": "8a1b2c3d4e5f-LHR", "Server": "cloudflare",
                             "Set-Cookie": "BIGipServerpool=1.2.3; path=/"}

        site = self.site(Edge)
        self.seed(site.port)
        self.probe(only=["http_fingerprint"])
        found = [f for f in self.store.findings() if f.source == "extscan:edge"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].title,
                         f"127.0.0.1:{site.port} is behind Cloudflare, F5 BIG-IP")
        self.assertEqual(found[0].severity, "info")
        self.assertIn("cf-ray: 8a1b2c3d4e5f-LHR", found[0].evidence)
        self.assertEqual(self.own_gaps(), [])

    def test_plain_service_gets_no_edge_finding(self):
        site = self.site()
        self.seed(site.port)
        self.probe(only=["http_fingerprint"])
        self.assertEqual(self.titles("extscan:edge"), [])


class TestBlockedPathChecks(_Case):
    STAGE = "probe:http_fingerprint"

    def run_against(self, handler) -> _Site:
        site = self.site(handler)
        self.seed(site.port)
        self.probe(only=["http_fingerprint"])
        return site

    def assert_gap(self, site: _Site, needle: str) -> None:
        gaps = self.gaps(self.STAGE)
        self.assertEqual(len(gaps), 1, [g.reason for g in self.store.degradations()])
        self.assertTrue(gaps[0].reason.startswith(f"127.0.0.1/tcp/{site.port}: "))
        self.assertIn(needle, gaps[0].reason)
        self.assertIn("inter_request_delay", gaps[0].remedy)
        self.assertIn("allow-list", gaps[0].remedy)
        self.assertNotIn("http_fingerprint", self.service(site.port).probed_by)

    def test_429_partway_is_a_gap_that_keeps_findings_and_stops_asking(self):
        class Limited(_Handler):
            served: ClassVar[list[int]] = [0]
            limit = 5

            def do_GET(self):
                self.served[0] += 1
                if self.served[0] > self.limit:
                    self.extra_headers = {"Retry-After": "30"}
                    self.reply(429, "slow down")
                else:
                    super().do_GET()

        # /.env is checked before the throttle starts (root, random path, then paths).
        self.policy.http.paths = ["/.env"] + [p for p in self.policy.http.paths if p != "/.env"]
        site = self.run_against(Limited)

        self.assert_gap(site, "429 Too Many Requests (Retry-After: 30)")
        self.assertEqual(len(site.requests), Limited.limit + 1)
        self.assertTrue(any(t.startswith("Exposed /.env ") for t in self.titles()))
        self.assertTrue(any(t.startswith("HTTP service: Portal") for t in self.titles()))

        # The client allow-lists the scanner: the next run covers it and says so.
        Limited.limit = 10_000
        self.probe(only=["http_fingerprint"])
        self.assertEqual(self.gaps(self.STAGE), [])
        self.assertIn("http_fingerprint", self.service(site.port).probed_by)

    def test_429_on_the_root_page_is_a_gap_and_no_paths_are_requested(self):
        class Always(_Handler):
            def do_GET(self):
                self.reply(429, "slow down")

        site = self.run_against(Always)
        self.assert_gap(site, "the root page answered 429")
        self.assertEqual(len(site.requests), 1)

    def test_connections_dropped_after_the_root_page_is_a_gap(self):
        class Drops(_Handler):
            def do_GET(self):
                if self.path == "/":
                    super().do_GET()
                else:
                    self.close_connection = True   # no response at all

        site = self.run_against(Drops)
        self.assert_gap(site, "3 requests in a row got no answer")
        self.assertEqual(len(site.requests), 4)    # root, then three unanswered

    def test_same_block_page_for_every_path_is_a_gap_without_noise(self):
        class BlockPage(_Handler):
            def do_GET(self):
                if self.path == "/":
                    super().do_GET()
                else:
                    self.reply(403, "<html><title>Access denied</title><body>"
                                    + "<p>Your request was blocked by the security policy "
                                      "of this site. Contact the site owner.</p>" * 6
                                    + f"Incident {time.time_ns()}</body></html>")

        site = self.run_against(BlockPage)
        self.assert_gap(site, "same 403 page as a path that cannot exist")
        self.assertEqual(self.titles("extscan:paths"), [])     # no "present but protected"

    def test_challenge_header_on_a_200_is_a_gap(self):
        class Challenge(_Handler):
            def do_GET(self):
                if self.path != "/":
                    self.extra_headers = {"cf-mitigated": "challenge"}
                    self.reply(200, "<html><title>Just a moment...</title></html>")
                else:
                    super().do_GET()

        site = self.run_against(Challenge)
        self.assert_gap(site, "Cloudflare challenge")
        self.assertEqual(len(site.requests), 2)

    def test_slow_but_honest_server_is_not_a_gap(self):
        class Slow(_Handler):
            def do_GET(self):
                time.sleep(0.15)
                super().do_GET()

        self.policy.http.timeout_sec = 5
        site = self.run_against(Slow)
        self.assertEqual(self.own_gaps(), [])
        self.assertIn("http_fingerprint", self.service(site.port).probed_by)
        self.assertTrue(any(t.startswith("Exposed /.env ") for t in self.titles()))

    def test_honest_403s_on_real_paths_are_not_a_gap(self):
        class Protected(_Handler):
            def do_GET(self):
                if self.path in ("/server-status", "/actuator", "/metrics"):
                    self.reply(403, "Forbidden")
                else:
                    super().do_GET()

        site = self.run_against(Protected)
        self.assertEqual(self.own_gaps(), [])
        self.assertIn("http_fingerprint", self.service(site.port).probed_by)
        protected = [t for t in self.titles("extscan:paths") if "access-controlled" in t]
        self.assertEqual(len(protected), 3)

    def test_site_that_is_403_everywhere_including_root_is_not_a_gap(self):
        class Closed(_Handler):
            def do_GET(self):
                self.reply(403, "Forbidden")

        site = self.run_against(Closed)
        self.assertEqual(self.own_gaps(), [])
        self.assertIn("http_fingerprint", self.service(site.port).probed_by)

    def test_one_lost_request_is_reported_but_does_not_stop_the_checks(self):
        class Flaky(_Handler):
            def do_GET(self):
                if self.path == "/swagger.json":
                    self.close_connection = True
                else:
                    super().do_GET()

        site = self.run_against(Flaky)
        self.assert_gap(site, "1 path(s) got no answer: /swagger.json")
        self.assertEqual(len(site.requests), 2 + len(self.policy.http.paths))
        self.assertTrue(any(t.startswith("Exposed /.env ") for t in self.titles()))

    def test_probe_gap_keeps_findings_from_the_same_probe(self):
        """The mechanism itself: report_gap is collected, an exception is not needed."""
        site = self.site()
        svc = self.seed(site.port)
        ctx = ProbeContext(scope=self.scope, policy=self.policy, runner=self.runner)
        ctx.report_gap("http_fingerprint", svc, reason="cut short", impact="not covered",
                       remedy="retry")
        probe = next(p for p in probes_for(svc) if p.name == "http_fingerprint")
        found = Finding(title="kept", host=svc.host, port=svc.port, source="extscan:paths")
        with contextlib.redirect_stdout(io.StringIO()):
            counts = pipeline._store_probe_result(self.store, ctx, self.policy, probe, svc,
                                                  [found], [])
        self.assertEqual(counts, (1, 0))
        self.assertIn("kept", self.titles())
        gap = self.gaps(self.STAGE)[0]
        self.assertEqual((gap.reason, gap.hosts), (f"{svc.id}: cut short", ["127.0.0.1"]))
        # Not marked, so the next run tries again.
        self.assertNotIn("http_fingerprint", self.service(site.port).probed_by)


class TestLocalEvalPlantedCases(unittest.TestCase):
    """The eval's own planted cases, so a regression fails here by name."""

    @classmethod
    def setUpClass(cls):
        cls.result = local.run()

    def test_unnamed_port_vhost_and_throttle_cases_are_found(self):
        for wanted in ("unnamed-port-identified", "unnamed-port-env", "vhost-by-name",
                       "throttled-is-a-gap"):
            self.assertIn(wanted, self.result["found"])
        self.assertEqual(self.result["missed"], [])

    def test_wildcard_and_other_targets_give_no_vhost_finding(self):
        self.assertEqual(self.result["false_positives"], [])

    def test_throttled_target_stops_receiving_requests(self):
        self.assertLessEqual(self.result["requests"]["throttled"], local.THROTTLE_AFTER + 2)
        self.assertEqual(self.result["over_budget"], [])


if __name__ == "__main__":
    unittest.main()
