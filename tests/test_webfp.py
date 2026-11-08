"""Website fingerprinting: favicon hashes, technology detection, page grouping.

The favicon hash is only useful if it is exactly Shodan's, so the hash
implementation is pinned to published MurmurHash3 vectors and to values the
third-party `mmh3` package computed for the fixture icon. Signatures are
checked against hand-written fixture pages and headers. Nothing here touches
the network beyond a throwaway HTTP server on 127.0.0.1.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import shutil
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

from extscan import pipeline, probes, vault
from extscan.models import Finding, Service
from extscan.policy import Policy
from extscan.scope import Authorization, Scope
from extscan.store import Store
from extscan.tools import webfp, webtech
from extscan.tools.net import Response

ROOT = Path(__file__).parent.parent
FIX = ROOT / "tests" / "fixtures" / "webfp"
ICON = (FIX / "favicon.ico").read_bytes()

# Computed with the third-party `mmh3` package (5.3.1) in a throwaway venv as
# mmh3.hash(base64.encodebytes(ICON)) -- Shodan's documented convention.
ICON_MMH3 = 951313297
ICON_MD5 = "3864e20ae9e00dd40fe2b3a78bda39e0"
ICON_SHA256 = "61fa0901ee8004f2242e2466d0d446b2c8d0224c061219f8d3174667d5363e8a"


def page(name: str) -> str:
    return (FIX / name).read_text()


class TestMurmur3(unittest.TestCase):
    """Published MurmurHash3 x86_32 vectors (unsigned), plus mmh3's signed form."""

    VECTORS: ClassVar[list[tuple[bytes, int, int]]] = [
        (b"", 0, 0x00000000),
        (b"", 1, 0x514E28B7),
        (b"", 0xFFFFFFFF, 0x81F16F39),
        (b"\x00\x00\x00\x00", 0, 0x2362F9DE),
        (b"aaaa", 0x9747B28C, 0x5A97808A),
        (b"Hello, world!", 0x9747B28C, 0x24884CBA),
        (b"The quick brown fox jumps over the lazy dog", 0x9747B28C, 0x2FA826CD),
    ]

    def test_reference_vectors(self):
        for data, seed, want in self.VECTORS:
            with self.subTest(data=data, seed=seed):
                self.assertEqual(webfp.murmur3_32(data, seed, signed=False), want)

    def test_tail_lengths_match_mmh3(self):
        # 1-, 2- and 3-byte tails, values from mmh3.hash(data, seed).
        self.assertEqual(webfp.murmur3_32(b"a", 0x9747B28C), 2141232806)
        self.assertEqual(webfp.murmur3_32(b"ab", 0x9747B28C), 1955026322)
        self.assertEqual(webfp.murmur3_32(b"abc", 0x9747B28C), -934649123)

    def test_signed_like_mmh3(self):
        self.assertEqual(webfp.murmur3_32(b"foo"), -156908512)
        self.assertEqual(webfp.murmur3_32(b"", 0xFFFFFFFF), -2114883783)

    def test_str_is_hashed_as_utf8(self):
        self.assertEqual(webfp.murmur3_32("foo"), webfp.murmur3_32(b"foo"))
        self.assertEqual(webfp.murmur3_32("π", 0x9747B28C), 1146496757)


class TestFaviconHash(unittest.TestCase):
    def test_fixture_icon_matches_mmh3_package(self):
        self.assertEqual(webfp.favicon_hash(ICON), ICON_MMH3)

    def test_md5_and_sha256_recorded(self):
        fav = webfp.hash_icon("http://h/favicon.ico", ICON, "image/x-icon")
        self.assertEqual((fav.mmh3, fav.md5, fav.sha256), (ICON_MMH3, ICON_MD5, ICON_SHA256))
        self.assertIn(f"mmh3={ICON_MMH3}", fav.line())

    def test_hash_is_over_mime_base64_with_newlines(self):
        """The 76-column newlines are part of Shodan's input; dropping them breaks pivots."""
        encoded = base64.encodebytes(ICON)
        self.assertGreater(encoded.count(b"\n"), 1)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertNotEqual(webfp.murmur3_32(base64.b64encode(ICON)), ICON_MMH3)

    def test_soft_404_html_is_not_an_icon(self):
        shell = Response(url="u", status=200, headers={"content-type": "text/html"},
                         body=b"<!DOCTYPE html><html>app</html>")
        self.assertIn("HTML", webfp._is_icon(shell))
        self.assertEqual(webfp._is_icon(Response(url="u", status=404)), "HTTP 404")
        trunc = Response(url="u", status=200, body=b"\x00\x00\x01\x00", truncated=True)
        self.assertIn("max_body_bytes", webfp._is_icon(trunc))

    def test_svg_and_ico_are_icons(self):
        svg = Response(url="u", status=200, headers={"content-type": "image/svg+xml"},
                       body=b"<svg xmlns='http://www.w3.org/2000/svg'/>")
        self.assertEqual(webfp._is_icon(svg), "")
        ico = Response(url="u", status=200, headers={"content-type": "image/x-icon"}, body=ICON)
        self.assertEqual(webfp._is_icon(ico), "")


def names(dets) -> dict[str, webtech.Detection]:
    return {d.name: d for d in dets}


class TestSignatures(unittest.TestCase):
    def test_server_headers_with_versions(self):
        got = names(webtech.detect({"server": "nginx/1.25.3"}, ""))
        self.assertEqual(got["nginx"].version, "1.25.3")
        got = names(webtech.detect({"server": "Apache/2.4.58 (Debian)"}, ""))
        self.assertEqual(got["Apache HTTP Server"].version, "2.4.58")

    def test_apache_coyote_is_tomcat_not_apache_httpd(self):
        got = names(webtech.detect({"server": "Apache-Coyote/1.1"},
                                   "<h3>Apache Tomcat/9.0.85</h3>"))
        self.assertIn("Apache Tomcat", got)
        self.assertEqual(got["Apache Tomcat"].version, "9.0.85")
        self.assertNotIn("Apache HTTP Server", got)

    def test_iis_and_aspnet(self):
        got = names(webtech.detect(
            {"server": "Microsoft-IIS/10.0", "x-powered-by": "ASP.NET",
             "x-aspnet-version": "4.0.30319",
             "set-cookie": "ASP.NET_SessionId=abc; path=/; HttpOnly"},
            '<input type="hidden" name="__VIEWSTATE" value="x" />'))
        self.assertEqual(got["Microsoft IIS"].version, "10.0")
        self.assertEqual(got["ASP.NET"].version, "4.0.30319")
        self.assertEqual(got["ASP.NET"].confidence, "firm")

    def test_wordpress_meta_generator_and_implied_php(self):
        got = names(webtech.detect({}, page("wordpress.html")))
        self.assertEqual(got["WordPress"].version, "6.4.3")
        self.assertIn("PHP", got)
        self.assertEqual(got["PHP"].evidence, ["implied by WordPress"])

    def test_php_version_from_x_powered_by(self):
        got = names(webtech.detect({"x-powered-by": "PHP/8.2.12"}, ""))
        self.assertEqual(got["PHP"].version, "8.2.12")

    def test_drupal_from_x_generator(self):
        got = names(webtech.detect({"x-generator": "Drupal 10 (https://www.drupal.org)"}, ""))
        self.assertEqual(got["Drupal"].version, "10")

    def test_jenkins_and_kibana_header_versions(self):
        got = names(webtech.detect({"x-jenkins": "2.426.3", "x-hudson": "1.395"}, ""))
        self.assertEqual(got["Jenkins"].version, "2.426.3")
        got = names(webtech.detect({"kbn-name": "kibana", "kbn-version": "8.11.1"}, ""))
        self.assertEqual(got["Kibana"].version, "8.11.1")

    def test_grafana_version_from_boot_data(self):
        got = names(webtech.detect({}, page("grafana-login.html")))
        self.assertEqual(got["Grafana"].version, "10.2.3")
        self.assertFalse(got["Grafana"].edge)

    def test_spring_boot_whitelabel(self):
        body = "<html><body><h1>Whitelabel Error Page</h1><p>This application has no " \
               "explicit mapping for /error, so you are seeing this as a fallback.</p>"
        self.assertIn("Spring Boot", names(webtech.detect({}, body)))

    def test_version_only_patterns_never_detect_on_their_own(self):
        """`ajs-version-number` is shared by Jira and Confluence: it dates, it does not name."""
        body = '<meta name="ajs-version-number" content="8.5.4">'
        got = names(webtech.detect({}, body))
        self.assertNotIn("Atlassian Confluence", got)
        self.assertNotIn("Atlassian Jira", got)
        got = names(webtech.detect({"x-confluence-request-time": "1700000000"}, body))
        self.assertEqual(got["Atlassian Confluence"].version, "8.5.4")

    def test_fortigate_login_is_an_edge_appliance(self):
        got = names(webtech.detect(
            {"server": "xxxxxxxx-xxxxx"}, page("fortigate-login.html"),
            ["https://vpn.example.test/", "https://vpn.example.test/remote/login?lang=en"]))
        fgt = got["Fortinet FortiGate"]
        self.assertTrue(fgt.edge)
        self.assertEqual(fgt.confidence, "firm")
        self.assertTrue(any(e.startswith("url: ") for e in fgt.evidence))

    def test_other_edge_products(self):
        cases = [
            ({}, "", ["https://h/global-protect/login.esp"], "Palo Alto GlobalProtect"),
            ({}, "", ["https://h/dana-na/auth/url_default/welcome.cgi"],
             "Ivanti Connect Secure (Pulse Secure)"),
            ({"set-cookie": "NSC_TMAS=xyz; path=/"}, "", [], "Citrix NetScaler ADC / Gateway"),
            ({}, "", ["https://h/logon/LogonPoint/tmindex.html"],
             "Citrix NetScaler ADC / Gateway"),
            ({"set-cookie": "BIGipServerpool_web=1677787402.20480.0000; path=/"}, "", [],
             "F5 BIG-IP"),
            ({}, "<link href='/tmui/tmui/login/images/logo.png'>", [],
             "F5 BIG-IP Configuration Utility"),
            ({"x-owa-version": "15.2.1258.12"}, "", ["https://h/owa/auth/logon.aspx"],
             "Microsoft Exchange (OWA)"),
            ({}, "", ["https://h/+CSCOE+/logon.html"], "Cisco ASA / AnyConnect"),
            ({"server": "SonicWALL SSL-VPN Web Server"}, "", [], "SonicWall"),
        ]
        for headers, body, urls, want in cases:
            with self.subTest(want=want):
                got = names(webtech.detect(headers, body, urls))
                self.assertIn(want, got)
                self.assertTrue(got[want].edge)
        owa = names(webtech.detect({"x-owa-version": "15.2.1258.12"}, ""))
        self.assertEqual(owa["Microsoft Exchange (OWA)"].version, "15.2.1258.12")

    def test_plain_page_matches_nothing(self):
        body = "<html><head><title>Acme</title></head><body>Hello, Apache fans</body></html>"
        self.assertEqual(webtech.detect({"content-type": "text/html"}, body), [])

    def test_cookie_names(self):
        self.assertEqual(webtech.cookie_names("a=1; Path=/, b=2; Expires=Wed, 21 Oct 2026"),
                         ["a", "b"])
        self.assertEqual(webtech.cookie_names(""), [])

    def test_every_set_cookie_is_seen_not_just_the_last(self):
        # The headers dict holds only the last Set-Cookie; set_cookies holds all.
        headers = {"set-cookie": "tracking=1; path=/"}
        every = ["BIGipServerpool_web=1677787402.20480.0000; path=/", "tracking=1; path=/"]
        self.assertEqual(webtech.detect(headers, ""), [])
        names = [d.name for d in webtech.detect(headers, "", set_cookies=every)]
        self.assertTrue(any("BIG-IP" in n for n in names), names)

    def test_page_parts(self):
        parts = webtech.parse_page(page("wordpress.html"))
        self.assertIn("Just another WordPress site", parts.title)
        self.assertEqual(parts.generators, ["WordPress 6.4.3"])
        self.assertEqual(parts.icons, ["/wp-content/uploads/2024/01/cropped-icon-32x32.png"])
        self.assertTrue(parts.scripts[0].startswith("/wp-includes/js/jquery"))

    def test_hostile_html_does_not_raise(self):
        for body in ["<", "<meta name=generator content=", "<![CDATA[", "\x00" * 50,
                     "<title>" + "x" * 100_000]:
            webtech.detect({}, body)


class TestPageFingerprint(unittest.TestCase):
    def test_tokens_timestamps_and_hosts_do_not_change_the_digest(self):
        a = webfp.page_fingerprint(page("default-page-a.html"), "203.0.113.10")
        b = webfp.page_fingerprint(page("default-page-b.html"), "203.0.113.11")
        self.assertEqual(a.digest, b.digest)
        self.assertEqual(a.simhash, b.simhash)

    def test_different_pages_differ(self):
        a = webfp.page_fingerprint(page("default-page-a.html"))
        c = webfp.page_fingerprint(page("wordpress.html"))
        self.assertNotEqual(a.digest, c.digest)
        self.assertGreater(webfp.hamming(a.simhash, c.simhash), webfp.SIMHASH_DISTANCE)

    def test_small_edit_is_near_identical(self):
        base = page("wordpress.html") + "<p>" + " ".join(
            f"para word{chr(97 + i % 26)} text" for i in range(400)) + "</p>"
        edited = base.replace("Hello world!", "Hello there world!")
        a, b = webfp.page_fingerprint(base), webfp.page_fingerprint(edited)
        self.assertNotEqual(a.digest, b.digest)
        self.assertLessEqual(webfp.hamming(a.simhash, b.simhash), webfp.SIMHASH_DISTANCE)

    def test_empty_page_has_no_fingerprint(self):
        self.assertTrue(webfp.page_fingerprint("").empty)
        self.assertTrue(webfp.page_fingerprint("12345 \n\t 2026-01-01").empty)


def fp_finding(host: str, port: int, body: str, title: str = "") -> Finding:
    fp = webfp.page_fingerprint(body, host)
    return Finding(title=f"Web fingerprint of {host}:{port}", host=host, port=port,
                   source="extscan:webfp",
                   evidence=f"GET x -> 200\npage title: {title}" if title else "GET x -> 200",
                   tags=["http", "fingerprint", webfp.TAG, f"page-hash:{fp.digest}",
                         f"page-simhash:{fp.simhash}"])


class TestGrouping(unittest.TestCase):
    def test_identical_default_pages_group_and_singletons_do_not(self):
        findings = [fp_finding(f"203.0.113.{i}", 80, page("default-page-a.html"),
                               "Welcome to nginx!") for i in range(1, 15)]
        findings.append(fp_finding("203.0.113.99", 443, page("wordpress.html"), "Blog"))
        findings.append(Finding(title="unrelated", host="203.0.113.1", port=80,
                                tags=["page-hash:ffff"]))
        groups = webfp.page_groups(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].services), 14)
        self.assertEqual(groups[0].titles, ["Welcome to nginx!"])
        self.assertTrue(groups[0].exact)

    def test_near_identical_pages_group_as_near(self):
        base = page("wordpress.html") + "<p>" + " ".join(
            f"para word{chr(97 + i % 26)} text" for i in range(400)) + "</p>"
        findings = [fp_finding("203.0.113.1", 80, base),
                    fp_finding("203.0.113.2", 80, base.replace("Hello world!", "Hi world!"))]
        groups = webfp.page_groups(findings)
        self.assertEqual(len(groups), 1)
        self.assertFalse(groups[0].exact)

    def test_findings_without_a_page_fingerprint_are_ignored(self):
        f = Finding(title="Web fingerprint of h:80", host="h", port=80,
                    tags=["http", webfp.TAG])
        self.assertEqual(webfp.page_groups([f, f]), [])


class _Site(BaseHTTPRequestHandler):
    routes: ClassVar[dict[str, tuple[int, dict, bytes]]] = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        status, headers, body = self.routes.get(self.path, (404, {}, b"not found"))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestProbe(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(engagement="webfp test", client="self-test",
                           authorization=Authorization(reference="LOCAL-TEST",
                                                       authorized_by="test harness"),
                           targets=["127.0.0.1/32"], allow_private=True)
        self.policy = Policy().http

    def serve(self, routes):
        handler = type("Site", (_Site,), {"routes": routes})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return Service(host="127.0.0.1", port=server.server_address[1], proto="tcp",
                       name="http")

    def test_registered_for_http_services(self):
        self.assertIn("web_fingerprint", probes.all_probe_names())
        names_for = [p.name for p in probes.probes_for(
            Service(host="h", port=8080, proto="tcp", name="http"))]
        self.assertIn("web_fingerprint", names_for)

    def test_fortigate_like_site_with_favicon(self):
        html = page("fortigate-login.html").encode()
        svc = self.serve({
            "/": (302, {"Location": "/remote/login?lang=en"}, b""),
            "/remote/login?lang=en": (200, {"Content-Type": "text/html",
                                            "Server": "xxxxxxxx-xxxxx"}, html),
            "/favicon.ico": (200, {"Content-Type": "image/x-icon"}, ICON),
        })
        findings, leads = webfp.probe_web_fingerprint(svc, self.scope, self.policy)
        self.assertEqual(leads, [])
        fp = findings[0]
        self.assertIn(f"favicon-mmh3:{ICON_MMH3}", fp.tags)
        self.assertIn("tech:fortinet-fortigate", fp.tags)
        self.assertTrue(any(t.startswith("page-hash:") for t in fp.tags))
        self.assertIn(ICON_SHA256, fp.evidence)
        self.assertIn(f"http.favicon.hash:{ICON_MMH3}", fp.description)
        edge = [f for f in findings if "edge-appliance" in f.tags]
        self.assertEqual(len(edge), 1)
        self.assertTrue(edge[0].review_required)
        self.assertEqual(edge[0].severity, "info")

    def test_same_origin_icon_link_is_hashed_and_duplicates_collapse(self):
        other = ICON[:-1] + b"\x01"
        body = b'<html><head><link rel="shortcut icon" href="/static/i.ico">' \
               b'<link rel="icon" href="http://203.0.113.9/x.ico"></head></html>'
        svc = self.serve({
            "/": (200, {"Content-Type": "text/html"}, body),
            "/favicon.ico": (200, {"Content-Type": "image/x-icon"}, ICON),
            "/static/i.ico": (200, {"Content-Type": "image/x-icon"}, other),
        })
        findings, _ = webfp.probe_web_fingerprint(svc, self.scope, self.policy)
        hashes = [t for t in findings[0].tags if t.startswith("favicon-mmh3:")]
        self.assertEqual(hashes, [f"favicon-mmh3:{ICON_MMH3}",
                                  f"favicon-mmh3:{webfp.favicon_hash(other)}"])

    def test_cross_origin_icon_link_is_not_fetched(self):
        body = b'<html><head><link rel="icon" href="http://203.0.113.9/x.ico"></head></html>'
        svc = self.serve({"/": (200, {"Content-Type": "text/html"}, body)})
        findings, _ = webfp.probe_web_fingerprint(svc, self.scope, self.policy)
        self.assertIn("cross-origin; not fetched", findings[0].evidence)

    def test_data_uri_icon_is_hashed_without_a_request(self):
        uri = "data:image/x-icon;base64," + base64.b64encode(ICON).decode()
        body = f'<html><head><link rel="icon" href="{uri}"></head></html>'.encode()
        svc = self.serve({"/": (200, {"Content-Type": "text/html"}, body)})
        findings, _ = webfp.probe_web_fingerprint(svc, self.scope, self.policy)
        self.assertIn(f"favicon-mmh3:{ICON_MMH3}", findings[0].tags)

    def test_missing_favicon_is_not_a_gap(self):
        svc = self.serve({"/": (200, {"Content-Type": "text/html"}, b"<html>hi</html>")})
        findings, _ = webfp.probe_web_fingerprint(svc, self.scope, self.policy)
        self.assertIn("not hashed (HTTP 404)", findings[0].evidence)
        self.assertFalse(any(t.startswith("favicon-mmh3:") for t in findings[0].tags))

    def test_unreachable_service_raises_so_the_pipeline_records_a_gap(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        svc = Service(host="127.0.0.1", port=port, proto="tcp", name="http")
        with self.assertRaises(RuntimeError):
            webfp.probe_web_fingerprint(svc, self.scope, self.policy)

    def test_out_of_scope_redirect_is_reported_not_followed(self):
        svc = self.serve({"/": (302, {"Location": "http://169.254.169.254/"}, b"")})
        findings, _ = webfp.probe_web_fingerprint(svc, self.scope, self.policy)
        self.assertEqual(len(findings), 1)
        self.assertIn("out-of-scope-redirect", findings[0].tags)


class TestReportAndVault(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        shutil.copytree(ROOT / "tests" / "fixtures" / "lab-run", self.tmp / "run")
        self.store = Store(self.tmp / "run")
        self.scope = Scope.load(ROOT / "examples" / "lab" / "scope.json")

    def test_report_and_vault_list_services_serving_the_same_page(self):
        body = page("default-page-a.html")
        self.store.add_findings([fp_finding("127.0.0.2", p, body, "Welcome to nginx!")
                                 for p in (8080, 8081, 8443)])
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(self.store, self.scope)
        report = (self.store.path / "report.md").read_text()
        self.assertIn("### Services serving the same page", report)
        self.assertIn("| 3 | Welcome to nginx! | identical |", report)
        summary = (self.store.path / vault.VAULT_DIR / f"{vault.SUMMARY}.md").read_text()
        self.assertIn("Services serving the same page", summary)
        self.assertIn("3 services serve the same page", summary)

    def test_no_section_without_groups(self):
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(self.store, self.scope)
        report = (self.store.path / "report.md").read_text()
        self.assertNotIn("Services serving the same page", report)


class TestRequestsGoThroughNetFetch(unittest.TestCase):
    """Scope checks live in net.fetch; a direct urllib call would bypass them."""

    def test_no_direct_network_calls(self):
        for name in ("webfp.py", "webtech.py"):
            source = (ROOT / "extscan" / "tools" / name).read_text()
            with self.subTest(name=name):
                self.assertNotIn("urllib.request", source)
                self.assertNotIn("import socket", source)
                self.assertNotIn("http.client", source)


class TestFixtureIntegrity(unittest.TestCase):
    def test_icon_fixture_is_unchanged(self):
        self.assertEqual(hashlib.sha256(ICON).hexdigest(), ICON_SHA256)


if __name__ == "__main__":
    unittest.main()
