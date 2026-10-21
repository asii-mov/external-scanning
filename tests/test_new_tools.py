"""sslscan parsing, IIS/ASP.NET enumeration, and subdomain scope splitting."""

import json
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from extscan.models import Service
from extscan.policy import HttpPolicy, Policy
from extscan.scope import Scope
from extscan.tools import iis, sslscan, subdomains

FIXTURES = Path(__file__).parent / "fixtures"


def scope_for(targets, **extra) -> Scope:
    data = {
        "engagement": "t", "client": "c",
        "authorization": {"reference": "T-1", "authorized_by": "x@test"},
        "targets": targets, **extra,
    }
    path = Path(tempfile.mkdtemp()) / "scope.json"
    path.write_text(json.dumps(data))
    return Scope.load(path)


# ---------------------------------------------------------------------------
# sslscan
# ---------------------------------------------------------------------------

class TestSslscanParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = scope_for(["203.0.113.0/24"])
        cls.findings = sslscan.parse_xml(
            (FIXTURES / "sslscan.xml").read_text(), scope=cls.scope)

    def titled(self, needle):
        return [f for f in self.findings if needle.lower() in f.title.lower()]

    def test_deprecated_protocols_reported_together(self):
        hits = self.titled("deprecated tls/ssl protocols")
        self.assertEqual(len(hits), 1)
        for proto in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            self.assertIn(proto, hits[0].title)
        self.assertEqual(hits[0].severity, "high")      # worst of the set

    def test_disabled_protocols_not_reported(self):
        hits = self.titled("deprecated tls/ssl protocols")
        self.assertNotIn("SSLv2", hits[0].title)        # enabled="0"
        self.assertNotIn("TLSv1.3", hits[0].title)

    def test_export_cipher_is_critical(self):
        hits = [f for f in self.findings if "export-grade" in f.title]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "critical")

    def test_rc4_is_high(self):
        hits = [f for f in self.findings if "RC4" in f.title]
        self.assertEqual(hits[0].severity, "high")

    def test_3des_is_medium(self):
        hits = [f for f in self.findings if "3DES" in f.title]
        self.assertEqual(hits[0].severity, "medium")

    def test_strong_ciphers_not_flagged(self):
        joined = " ".join(f.evidence for f in self.findings)
        self.assertNotIn("ECDHE-RSA-AES256-GCM-SHA384", joined)

    def test_compression_reported_as_crime(self):
        hits = self.titled("compression")
        self.assertEqual(len(hits), 1)
        self.assertIn("CRIME", hits[0].title)

    def test_insecure_renegotiation_reported(self):
        self.assertEqual(len(self.titled("insecure tls renegotiation")), 1)

    def test_heartbleed_not_reported_when_not_vulnerable(self):
        self.assertEqual(self.titled("heartbleed"), [])

    def test_certificate_problems(self):
        self.assertEqual(len(self.titled("expired certificate")), 1)
        self.assertEqual(len(self.titled("self-signed certificate")), 1)
        self.assertEqual(len(self.titled("below 2048 bits")), 1)

    def test_sha1_signature_is_flagged(self):
        """Regression: a \\b after sha1 never matched sha1WithRSAEncryption."""
        hits = self.titled("broken hash")
        self.assertEqual(len(hits), 1)
        self.assertIn("sha1WithRSAEncryption", hits[0].title)

    def test_out_of_scope_ssltest_is_dropped(self):
        self.assertNotIn("198.51.100.200", {f.host for f in self.findings})

    def test_every_finding_carries_host_and_port(self):
        for f in self.findings:
            self.assertEqual(f.host, "203.0.113.10")
            self.assertEqual(f.port, 443)
            self.assertEqual(f.source, "sslscan")

    def test_empty_and_malformed_input(self):
        self.assertEqual(sslscan.parse_xml(""), [])
        with self.assertRaises(ValueError):
            sslscan.parse_xml("<document><ssltest")

    def test_argv_requests_xml_output(self):
        argv = sslscan.argv("203.0.113.10", 443, "/out.xml")
        self.assertEqual(argv[0], "sslscan")
        self.assertIn("--xml=/out.xml", argv)
        self.assertIn("203.0.113.10:443", argv)


class TestSha1Pattern(unittest.TestCase):
    """The specific regex that was wrong, pinned."""

    def test_algorithm_names(self):
        import re

        pattern = re.compile(r"\b(?:sha-?1|md5)(?!\d)", re.I)
        for sig, expect in (("sha1WithRSAEncryption", True),
                            ("md5WithRSAEncryption", True),
                            ("ecdsa-with-SHA1", True),
                            ("sha256WithRSAEncryption", False),
                            ("sha512WithRSAEncryption", False),
                            ("ecdsa-with-SHA384", False)):
            self.assertEqual(bool(pattern.search(sig)), expect, sig)


# ---------------------------------------------------------------------------
# IIS
# ---------------------------------------------------------------------------

TRACE_BODY = ("<html><head><title>Application Trace</title></head><body>"
              "<h1>Application Trace</h1><p>Requests to this Application</p>"
              "<table><tr><td>/Account/Login</td>"
              "<td>ASP.NET_SessionId=abc123</td></tr></table></body></html>")

ERROR_BODY = ("<html><head><title>Server Error in '/' Application</title></head>"
              "<body><h2>Runtime Error</h2><p>[HttpException (0x80004005)]</p>"
              "<pre>Stack Trace:\n   at System.Web.HttpRequest.ValidateInput()</pre>"
              "Microsoft .NET Framework Version:4.0.30319</body></html>")


class IISHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Microsoft-IIS/8.5"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body="", ctype="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-AspNet-Version", "4.0.30319")
        self.send_header("X-AspNetMvc-Version", "5.2")
        self.send_header("X-Powered-By", "ASP.NET")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, "", extra={
            "Allow": "OPTIONS, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, "
                     "PROPPATCH, MKCOL, LOCK, UNLOCK, PUT",
            "DAV": "1, 2"})

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/trace.axd":
            return self._send(200, TRACE_BODY)
        if path.lower() == "/elmah.axd":
            return self._send(200, "<html><title>Error Log</title>ELMAH error log</html>")
        if path == "/iisstart.htm":
            return self._send(200, "<html>IIS Windows Server</html>")
        if "~1" in path:
            # The 8.3 oracle: matching wildcard 404, non-matching 400.
            return self._send(404 if path.startswith("/*") else 400, "")
        if "extscan_nonexistent" in path:
            return self._send(500, ERROR_BODY)
        if path == "/":
            return self._send(200, "<html><title>Intranet</title></html>")
        return self._send(404, "<html>404 - File or directory not found.</html>")


class HardenedHandler(IISHandler):
    """A correctly configured IIS: no handlers, no WebDAV, no verbose errors."""

    server_version = "Microsoft-IIS/10.0"

    def _send(self, code, body="", ctype="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, "", extra={"Allow": "GET, HEAD, POST, OPTIONS"})

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._send(200, "<html><title>Portal</title></html>")
        return self._send(404, "<html>Not found</html>")


class _Server:
    def __init__(self, handler):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TestIISDetection(unittest.TestCase):
    def test_detected_from_nmap_banner(self):
        svc = Service(host="h", port=80, proto="tcp", name="http",
                      product="Microsoft IIS httpd", version="8.5")
        self.assertTrue(iis.looks_like_iis(svc))

    def test_detected_from_cpe(self):
        svc = Service(host="h", port=80, proto="tcp", name="http",
                      cpe=["cpe:/a:microsoft:iis:10.0"])
        self.assertTrue(iis.looks_like_iis(svc))

    def test_detected_from_headers_behind_a_proxy(self):
        """nginx in front, ASP.NET behind: only a header gives it away."""
        svc = Service(host="h", port=80, proto="tcp", name="http", product="nginx")
        self.assertFalse(iis.looks_like_iis(svc))
        self.assertTrue(iis.looks_like_iis(
            svc, {"Server": "nginx", "X-AspNet-Version": "4.0.30319"}))

    def test_not_detected_for_plain_nginx(self):
        svc = Service(host="h", port=80, proto="tcp", name="http",
                      product="nginx", version="1.24")
        self.assertFalse(iis.looks_like_iis(svc, {"Server": "nginx/1.24"}))


class TestIISProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _Server(IISHandler)
        cls.scope = scope_for(["127.0.0.1/32"], allow_private=True, max_hosts=2)
        cls.policy = HttpPolicy(timeout_sec=5)
        svc = Service(host="127.0.0.1", port=cls.server.port, proto="tcp",
                      name="http", product="Microsoft IIS httpd", version="8.5")
        cls.findings, cls.leads = iis.probe_iis(svc, cls.scope, cls.policy)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def titled(self, needle):
        return [f for f in self.findings if needle.lower() in f.title.lower()]

    def test_trace_axd_found_and_high(self):
        hits = self.titled("/trace.axd")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")
        self.assertTrue(hits[0].review_required)
        self.assertIn("session", hits[0].review_reason.lower())

    def test_elmah_reported_once_despite_case_variants(self):
        """IIS paths are case-insensitive; one handler is one finding."""
        hits = [f for f in self.findings if "elmah" in f.title.lower()]
        self.assertEqual(len(hits), 1)

    def test_webdav_write_verbs_raise_severity(self):
        hits = self.titled("webdav")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")
        for verb in ("PUT", "DELETE", "MKCOL"):
            self.assertIn(verb, hits[0].title)

    def test_webdav_review_notes_no_write_was_attempted(self):
        hits = self.titled("webdav")
        self.assertIn("did not attempt PUT", hits[0].review_reason)

    def test_shortname_enumeration_detected(self):
        hits = self.titled("short-name enumeration")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")
        self.assertIn("404", hits[0].evidence)
        self.assertIn("400", hits[0].evidence)

    def test_shortname_review_notes_no_enumeration_was_run(self):
        hits = self.titled("short-name enumeration")
        self.assertIn("did not enumerate", hits[0].review_reason)

    def test_verbose_error_page_detected(self):
        hits = self.titled("verbose asp.net error")
        self.assertEqual(len(hits), 1)
        self.assertIn("4.0.30319", hits[0].description)

    def test_version_disclosure_lists_every_header(self):
        hits = self.titled("version disclosure")
        self.assertEqual(len(hits), 1)
        for header in ("server", "x-aspnet-version", "x-aspnetmvc-version"):
            self.assertIn(header, hits[0].evidence.lower())

    def test_default_content_detected(self):
        self.assertEqual(len(self.titled("default iis content")), 1)

    def test_leads_raised_for_exposed_handlers(self):
        self.assertTrue(any(ld.kind == "web_paths" for ld in self.leads))

    def test_no_write_verb_was_ever_requested(self):
        """The probe must be read-only: OPTIONS and GET only."""
        for finding in self.findings:
            for verb in ("PUT /", "DELETE /", "MKCOL /", "PROPPATCH /"):
                self.assertNotIn(verb, finding.evidence)


class TestIISProbeOnHardenedServer(unittest.TestCase):
    """A correctly configured server must produce (almost) nothing."""

    @classmethod
    def setUpClass(cls):
        cls.server = _Server(HardenedHandler)
        scope = scope_for(["127.0.0.1/32"], allow_private=True, max_hosts=2)
        svc = Service(host="127.0.0.1", port=cls.server.port, proto="tcp",
                      name="http", product="Microsoft IIS httpd", version="10.0")
        cls.findings, cls.leads = iis.probe_iis(svc, scope, HttpPolicy(timeout_sec=5))

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def test_no_handler_findings(self):
        self.assertEqual([f for f in self.findings if "handler" in f.title.lower()], [])

    def test_no_webdav_finding(self):
        self.assertEqual([f for f in self.findings if "webdav" in f.title.lower()], [])

    def test_no_shortname_finding(self):
        self.assertEqual([f for f in self.findings if "short-name" in f.title.lower()], [])

    def test_no_verbose_error_finding(self):
        self.assertEqual([f for f in self.findings if "verbose" in f.title.lower()], [])

    def test_at_most_version_disclosure_remains(self):
        titles = [f.title for f in self.findings]
        self.assertLessEqual(len(self.findings), 1, f"unexpected findings: {titles}")


# ---------------------------------------------------------------------------
# Subdomains
# ---------------------------------------------------------------------------

class TestHostnameValidation(unittest.TestCase):
    def test_accepts_normal_names(self):
        for name in ("api.example.com", "a-b.example.com", "x.y.z.example.com"):
            self.assertTrue(subdomains._valid_hostname(name), name)

    def test_rejects_wildcards_and_junk(self):
        for name in ("*.example.com", "", "   ", "-bad.example.com",
                     "bad-.example.com", "a" * 300):
            self.assertFalse(subdomains._valid_hostname(name), repr(name))

    def test_domain_membership(self):
        self.assertTrue(subdomains._under_domain("api.example.com", "example.com"))
        self.assertTrue(subdomains._under_domain("example.com", "example.com"))
        self.assertFalse(subdomains._under_domain("api.notexample.com", "example.com"))
        self.assertFalse(subdomains._under_domain("example.com.evil.test",
                                                  "example.com"))


class TestScopeSplitting(unittest.TestCase):
    """The part that matters: discovered names outside scope are never scanned."""

    def setUp(self):
        self.scope = scope_for(["203.0.113.0/24"])

    def results(self):
        return [
            subdomains.Enumerated(name="in.example.com",
                                  addresses=["203.0.113.10"],
                                  sources=["crt.sh"], in_scope=True),
            subdomains.Enumerated(name="cloud.example.com",
                                  addresses=["198.51.100.7"],
                                  sources=["crt.sh"], in_scope=False),
            subdomains.Enumerated(name="gone.example.com", addresses=[],
                                  sources=["crt.sh"],
                                  resolve_error="gaierror: NXDOMAIN"),
        ]

    def test_in_scope_names_become_host_records(self):
        _findings, hosts = subdomains.to_findings(self.results(), "example.com")
        self.assertEqual([h.ip for h in hosts], ["203.0.113.10"])
        self.assertIn("in.example.com", hosts[0].hostnames)

    def test_out_of_scope_names_produce_no_host_records(self):
        _findings, hosts = subdomains.to_findings(self.results(), "example.com")
        self.assertNotIn("198.51.100.7", [h.ip for h in hosts])

    def test_out_of_scope_gets_its_own_asset_discovery_finding(self):
        findings, _ = subdomains.to_findings(self.results(), "example.com")
        hits = [f for f in findings if "outside the engagement scope" in f.title]
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].review_required)
        self.assertIn("NOT scanned", hits[0].description)
        self.assertIn("written authorisation", hits[0].review_reason)
        self.assertIn("asset-discovery", hits[0].tags)

    def test_unresolved_names_flagged_as_takeover_candidates(self):
        findings, _ = subdomains.to_findings(self.results(), "example.com")
        hits = [f for f in findings if "do not resolve" in f.title]
        self.assertEqual(len(hits), 1)
        self.assertIn("takeover-candidate", hits[0].tags)

    def test_summary_finding_counts_correctly(self):
        findings, _ = subdomains.to_findings(self.results(), "example.com")
        summary = next(f for f in findings if "Subdomain enumeration for" in f.title)
        self.assertIn("3 name(s)", summary.title)
        self.assertIn("1 resolving into the authorised ranges", summary.description)

    def test_name_resolving_to_mixed_scope_is_not_in_scope(self):
        """One address outside scope means the name is not safely scannable."""
        entry = subdomains.Enumerated(
            name="mixed.example.com",
            addresses=["203.0.113.10", "198.51.100.7"])
        entry.in_scope = all(self.scope.contains(a) for a in entry.addresses)
        self.assertFalse(entry.in_scope)

    def test_no_results_produces_no_findings(self):
        findings, hosts = subdomains.to_findings([], "example.com")
        self.assertEqual((findings, hosts), ([], []))


class TestReconPolicyDefaults(unittest.TestCase):
    def test_bruteforce_is_off_by_default(self):
        self.assertFalse(Policy.for_profile("standard").recon.allow_bruteforce)

    def test_sources_are_passive(self):
        sources = Policy.for_profile("standard").recon.sources
        self.assertIn("crt.sh", sources)
        for source in sources:
            self.assertIn(source, ("crt.sh", "subfinder", "amass"))

    def test_name_cap_is_set(self):
        self.assertGreater(Policy.for_profile("standard").recon.max_names, 0)


class TestScopeDomains(unittest.TestCase):
    def test_domains_parsed_and_normalised(self):
        scope = scope_for(["203.0.113.0/24"],
                          domains=["Example.COM", "api.example.com."])
        self.assertEqual(scope.domains, ["example.com", "api.example.com"])

    def test_domains_absent_by_default(self):
        self.assertEqual(scope_for(["203.0.113.0/24"]).domains, [])

    def test_listing_a_domain_does_not_widen_ip_scope(self):
        """Authorising enumeration is not authorising scanning the results."""
        scope = scope_for(["203.0.113.0/24"], domains=["example.com"])
        self.assertFalse(scope.contains("198.51.100.7"))
        self.assertFalse(scope.contains("example.com"))   # not in allow_hostnames

    def test_domains_appear_in_summary(self):
        scope = scope_for(["203.0.113.0/24"], domains=["example.com"])
        self.assertEqual(scope.summary()["domains"], ["example.com"])


class TestResolution(unittest.TestCase):
    def test_localhost_resolves(self):
        addresses, error = subdomains.resolve("localhost", timeout=5)
        self.assertEqual(error, "")
        self.assertTrue(any(a in ("127.0.0.1", "::1") for a in addresses))

    def test_nonexistent_name_returns_an_error_not_an_exception(self):
        addresses, error = subdomains.resolve(
            "extscan-nonexistent-zzq9x.invalid", timeout=5)
        self.assertEqual(addresses, [])
        self.assertTrue(error)


class TestCrtshParsing(unittest.TestCase):
    """The crt.sh reader, exercised against a local stand-in for the API."""

    def setUp(self):
        payload = json.dumps([
            {"name_value": "api.example.com\nwww.example.com"},
            {"name_value": "*.example.com", "common_name": "example.com"},
            {"name_value": "notours.other.test"},
            {"common_name": "MAIL.EXAMPLE.COM"},
            "not a dict",
        ]).encode()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = _Server(Handler)
        self.original = subdomains.CRTSH_URL
        subdomains.CRTSH_URL = (f"http://127.0.0.1:{self.server.port}/"
                                "?q={query}&output=json")

    def tearDown(self):
        subdomains.CRTSH_URL = self.original
        self.server.close()

    def test_extracts_and_normalises_names(self):
        names, error = from_crtsh_local("example.com")
        self.assertEqual(error, "")
        self.assertIn("api.example.com", names)
        self.assertIn("www.example.com", names)
        self.assertIn("mail.example.com", names)        # lowercased
        self.assertIn("example.com", names)             # wildcard stripped to apex

    def test_drops_names_outside_the_queried_domain(self):
        names, _ = from_crtsh_local("example.com")
        self.assertNotIn("notours.other.test", names)

    def test_malformed_records_are_skipped(self):
        names, error = from_crtsh_local("example.com")
        self.assertEqual(error, "")
        self.assertTrue(all(subdomains._valid_hostname(n) for n in names))


def from_crtsh_local(domain):
    return subdomains.from_crtsh(domain, timeout=10, use_system_proxy=False)


class TestCrtshFailureHandling(unittest.TestCase):
    def test_unreachable_source_returns_an_error_not_an_exception(self):
        original = subdomains.CRTSH_URL
        subdomains.CRTSH_URL = "http://127.0.0.1:1/?q={query}"
        try:
            names, error = subdomains.from_crtsh("example.com", timeout=2)
        finally:
            subdomains.CRTSH_URL = original
        self.assertEqual(names, set())
        self.assertTrue(error)


class TestSubfinderAbsent(unittest.TestCase):
    def test_missing_tool_is_reported_not_raised(self):
        from extscan.runner import Runner

        tmp = Path(tempfile.mkdtemp())
        try:
            from extscan.store import Store

            store = Store.create(tmp, "t", run_id="r")
            store.write_meta({"run_id": "r"})
            names, error = subdomains.from_subfinder(Runner(store), "example.com")
            self.assertEqual(names, set())
            self.assertIn("not installed", error)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
