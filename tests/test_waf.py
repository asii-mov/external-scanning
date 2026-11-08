"""CDN/WAF identification and block detection, recorded as coverage gaps.

The fixture responses in tests/fixtures/waf-responses.json say, for each
vendor, what extscan should conclude. The pipeline tests drive real probes
and chase against a local server that impersonates an edge, and check the
two things the report depends on: being blocked is a serious gap that leaves
the work unmarked for a retry, and a slow but honest server is not a WAF.
"""

import contextlib
import io
import json
import shutil
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from extscan import pipeline
from extscan.models import Lead, Service
from extscan.policy import Policy
from extscan.report import render_markdown
from extscan.runner import Runner
from extscan.scope import Scope
from extscan.store import Store
from extscan.tools import net, waf
from extscan.tools.net import Response
from extscan.triage import triage

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "waf-responses.json").read_text())
RESPONSES = FIXTURES["responses"]


def response(name: str, url: str = "https://203.0.113.10/") -> Response:
    r = RESPONSES[name]
    return Response(url=url, status=r["status"], headers=dict(r["headers"]),
                    body=r["body"].encode(), set_cookies=list(r["set_cookies"]))


class TestFixtureResponses(unittest.TestCase):
    def test_identification_matches_each_fixture(self):
        for name, r in RESPONSES.items():
            with self.subTest(name):
                found = {m.name for m in waf.identify_response(response(name))}
                self.assertEqual(found, set(r["edge"]))

    def test_block_classification_matches_each_fixture(self):
        for name, r in RESPONSES.items():
            with self.subTest(name):
                block = waf.classify_block(response(name))
                if r["block"] is None:
                    self.assertIsNone(block)
                else:
                    self.assertIsNotNone(block)
                    self.assertEqual([block.vendor, block.kind], r["block"])

    def test_every_signature_has_a_fixture(self):
        covered = {n for r in RESPONSES.values() for n in r["edge"]}
        missing = [s.name for s in waf.SIGNATURES if s.name not in covered]
        self.assertEqual(missing, [])

    def test_every_vendor_block_page_has_a_fixture(self):
        vendors = {r["block"][0] for r in RESPONSES.values() if r["block"]}
        for vendor in ("Cloudflare", "Akamai", "Imperva Incapsula", "AWS WAF", "Sucuri",
                       "F5 BIG-IP ASM", "ModSecurity", "Azure Front Door"):
            self.assertIn(vendor, vendors)

    def test_retry_after_is_kept(self):
        block = waf.classify_block(response("cloudflare_rate_limit"))
        self.assertEqual(block.retry_after, "60")
        self.assertIn("Retry-After 60", block.describe())

    def test_akamai_reference_number_is_the_evidence(self):
        block = waf.classify_block(response("akamai_access_denied"))
        self.assertIn("reference #18.2d351ab8", block.evidence)

    def test_generic_429_takes_the_vendor_from_the_headers(self):
        r = response("cloudfront_ok")
        r.status, r.headers["retry-after"] = 429, "5"
        block = waf.classify_block(r)
        self.assertEqual((block.vendor, block.kind), ("Amazon CloudFront", "rate-limit"))


class TestNotAWaf(unittest.TestCase):
    """The roadmap's catch: a slow or failing server must not read as a WAF."""

    def test_timeouts_and_resets_are_never_blocks(self):
        for error in ("TimeoutError: timed out", "URLError: <urlopen error [Errno 111] "
                      "Connection refused>", "ConnectionResetError: [Errno 104] reset"):
            with self.subTest(error):
                self.assertIsNone(waf.classify_block(
                    Response(url="http://203.0.113.1/", status=0, error=error)))

    def test_plain_403_and_503_are_ordinary(self):
        for name in ("honest_forbidden", "honest_overloaded", "honest_apache_forbidden",
                     "honest_not_found"):
            with self.subTest(name):
                self.assertIsNone(waf.classify_block(response(name)))
                self.assertEqual(waf.identify_response(response(name)), [])

    def test_cloudflare_scripts_on_a_normal_page_are_not_a_challenge(self):
        self.assertIsNone(waf.classify_block(response("cloudflare_ok")))
        self.assertIsNone(waf.classify_block(response("imperva_ok")))


class TestIdentifySources(unittest.TestCase):
    def test_published_ranges(self):
        cases = {"104.16.1.1": "Cloudflare", "2606:4700::6810:1": "Cloudflare",
                 "151.101.65.1": "Fastly", "45.60.12.1": "Imperva Incapsula",
                 "13.32.1.1": "Amazon CloudFront", "2600:9000:2000::1": "Amazon CloudFront"}
        for ip, name in cases.items():
            with self.subTest(ip):
                match = waf.ip_provider(ip)
                self.assertEqual(match.name, name)
                self.assertIn(waf.IP_RANGES_DATE, match.evidence)

    def test_addresses_outside_the_ranges(self):
        for ip in ("127.0.0.2", "203.0.113.5", "10.0.0.1", "::1", "not-an-ip", ""):
            with self.subTest(ip):
                self.assertIsNone(waf.ip_provider(ip))

    def test_ip_alone_identifies(self):
        self.assertEqual([m.name for m in waf.identify(ip="172.64.1.1")], ["Cloudflare"])

    def test_certificate_text_from_nmap(self):
        cert = ("Subject: commonName=sni.cloudflaressl.com/organizationName=Cloudflare, Inc.\n"
                "Issuer: commonName=Cloudflare Inc ECC CA-3/organizationName=Cloudflare, Inc.")
        self.assertEqual([m.name for m in waf.identify(cert_text=cert)], ["Cloudflare"])
        self.assertEqual(waf.identify(cert_text="Issuer: commonName=R11/organizationName="
                                                "Let's Encrypt"), [])

    def test_one_match_per_provider_and_a_readable_label(self):
        r = response("aws_waf_cloudfront_block")
        r.set_cookies.append("aws-waf-token=x; Path=/")
        matches = waf.identify_response(r)
        self.assertEqual(waf.edge_label(matches),
                         "Amazon CloudFront (CDN) + AWS WAF (WAF)")

    def test_hostile_x_cdn_value_is_sanitised(self):
        [m] = waf.identify({"x-cdn": "Evil|CDN\n# heading <script>"})
        self.assertNotIn("|", m.name)
        self.assertNotIn("<", m.name)
        self.assertLessEqual(len(m.name), 40)


class TestWatch(unittest.TestCase):
    def test_observe_outside_a_watch_records_nothing(self):
        self.assertIsNone(waf.observe(response("cloudflare_block")))

    def test_watch_collects_blocks_only(self):
        with waf.watch() as seen:
            waf.observe(response("cloudflare_ok"))
            waf.observe(response("honest_forbidden"))
            waf.observe(response("sucuri_block"))
        self.assertEqual([b.vendor for b in seen.blocks], ["Sucuri"])
        self.assertIsNone(waf.observe(response("sucuri_block")))

    def test_watches_are_per_thread(self):
        other: list = []

        def worker():
            with waf.watch() as log:
                waf.observe(response("akamai_access_denied"))
            other.append(log)

        with waf.watch() as mine:
            t = threading.Thread(target=worker)
            t.start()
            t.join()
        self.assertFalse(mine)
        self.assertEqual(len(other[0].blocks), 1)

    def test_summary_names_vendor_status_and_wait(self):
        blocks = [waf.classify_block(response("cloudflare_rate_limit")),
                  waf.classify_block(response("cloudflare_block"))]
        text = waf.summarise(blocks)
        self.assertIn("2 request(s)", text)
        self.assertIn("Cloudflare", text)
        self.assertIn("403, 429", text)
        self.assertIn("Retry-After 60", text)


# ---------------------------------------------------------------------------
# A local server that behaves like an edge
# ---------------------------------------------------------------------------

class EdgeServer:
    """Serves one fixture response for every request, switchable mid-test.

    `mode` is a fixture name, "plain" (an ordinary origin), or "root-ok"
    (an ordinary root page and a 429 for everything else). `delay` makes it
    slow.
    """

    def __init__(self):
        self.mode = "plain"
        self.delay = 0.0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if outer.delay:
                    time.sleep(outer.delay)
                mode = outer.mode
                if mode == "root-ok":
                    mode = "plain" if self.path == "/" else "generic_rate_limit"
                if mode == "plain":
                    status, headers, cookies = 200, {"content-type": "text/html"}, []
                    body = "<html><head><title>origin</title></head><body>hi</body></html>"
                else:
                    r = RESPONSES[mode]
                    status, headers, cookies = r["status"], r["headers"], r["set_cookies"]
                    body = r["body"]
                data = body.encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                for c in cookies:
                    self.send_header("Set-Cookie", c)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(data)

            do_OPTIONS = do_GET

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _EdgeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="extscan-waf-"))
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "waf", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["127.0.0.1/32"], "allow_private": True,
        }))
        self.scope = Scope.load(sp)
        self.store = Store.create(self.tmp / "runs", "waf", run_id="r")
        self.store.write_meta({"run_id": "r"})
        self.runner = Runner(self.store)
        self.policy = Policy()
        self.policy.http.timeout_sec = 3
        self.edge = EdgeServer()
        self.addCleanup(self.edge.close)
        self.svc = Service(host="127.0.0.1", port=self.edge.port, proto="tcp", name="http")
        self.store.save_services([self.svc])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def probe(self, only=("http_fingerprint", "waf_detect"), force=False) -> Service:
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.probe(self.store, self.scope, self.policy, self.runner,
                           only=list(only), force=force)
        return self.store.services()[0]

    def gaps(self, stage_prefix="probe:"):
        return [d for d in self.store.degradations() if d.stage.startswith(stage_prefix)]

    def report(self) -> str:
        return render_markdown(self.scope, triage(self.store.findings(), self.store.services()),
                               self.store.hosts(), self.store.services(), self.store.meta(),
                               [], self.store.degradations())


class TestBlockedService(_EdgeCase):
    def test_blocked_probes_are_serious_gaps_and_stay_unprobed(self):
        self.edge.mode = "cloudflare_block"
        svc = self.probe()
        gaps = {d.stage: d for d in self.gaps()}
        self.assertEqual(set(gaps), {"probe:http_fingerprint", "probe:waf_detect"})
        for d in gaps.values():
            self.assertEqual(d.severity, "serious")
            self.assertIn("Cloudflare", d.reason)
            self.assertIn(svc.id, d.reason)
            self.assertIn("unreliable", d.impact)
            self.assertEqual(d.hosts, ["127.0.0.1"])
        self.assertNotIn("http_fingerprint", svc.probed_by)
        self.assertNotIn("waf_detect", svc.probed_by)
        self.assertEqual(svc.edge, "Cloudflare (CDN/WAF)")

    def test_block_pages_are_not_reported_as_access_controlled_paths(self):
        self.edge.mode = "cloudflare_block"
        self.probe()
        tags = [t for f in self.store.findings() for t in f.tags]
        self.assertNotIn("protected", tags)
        # The root finding is kept: it is the evidence of what was served.
        self.assertTrue(any("fingerprint" in f.tags for f in self.store.findings()))

    def test_gap_reaches_the_report_coverage_section(self):
        self.edge.mode = "akamai_access_denied"
        self.probe()
        report = self.report()
        gaps_section = report.split("## Coverage gaps", 1)[1]
        self.assertIn("blocked or challenged by Akamai", gaps_section)
        self.assertIn("behind Akamai (CDN/WAF)", report)

    def test_unblocking_clears_the_block_gaps(self):
        self.edge.mode = "cloudflare_challenge"
        self.probe()
        self.edge.mode = "cloudflare_ok"
        svc = self.probe()
        self.assertIn("http_fingerprint", svc.probed_by)
        self.assertIn("waf_detect", svc.probed_by)
        [note] = self.gaps()
        self.assertEqual((note.stage, note.severity), ("probe:waf_detect", "warning"))

    def test_rate_limited_partway_keeps_root_findings(self):
        self.edge.mode = "root-ok"
        svc = self.probe(only=["http_fingerprint"])
        [gap] = self.gaps()
        self.assertIn("rate-limited", gap.reason)
        self.assertIn("inter_request_delay", gap.remedy)
        self.assertIn("30s", gap.remedy)
        self.assertNotIn("http_fingerprint", svc.probed_by)
        self.assertTrue(any(f.title.startswith("HTTP service: origin")
                            for f in self.store.findings()))


class TestEdgeWithoutBlocking(_EdgeCase):
    def test_cdn_in_front_is_a_warning_note_and_named_in_the_inventory(self):
        self.edge.mode = "cloudflare_ok"
        svc = self.probe(only=["waf_detect"])
        [note] = self.gaps()
        self.assertEqual(note.severity, "warning")
        self.assertIn("edge rather than the origin", note.impact)
        self.assertIn("cf-ray", note.reason)
        self.assertEqual(svc.probed_by, ["waf_detect"])
        self.assertEqual(svc.edge, "Cloudflare (CDN/WAF)")
        self.assertIn("| behind Cloudflare (CDN/WAF) |", self.report())
        [finding] = [f for f in self.store.findings() if f.source == "extscan:waf"]
        self.assertEqual(finding.severity, "info")

    def test_rediscovery_keeps_the_edge(self):
        self.edge.mode = "fastly_ok"
        self.probe(only=["waf_detect"])
        self.store.save_services([Service(host="127.0.0.1", port=self.edge.port,
                                          proto="tcp", name="http")])
        self.assertEqual(self.store.services()[0].edge, "Fastly (CDN)")

    def test_forced_rerun_without_an_edge_clears_note_and_name(self):
        self.edge.mode = "sucuri_ok"
        self.probe(only=["waf_detect"])
        self.edge.mode = "plain"
        svc = self.probe(only=["waf_detect"], force=True)
        self.assertEqual(self.gaps(), [])
        self.assertEqual(svc.edge, "")

    def test_plain_origin_has_no_note(self):
        svc = self.probe()
        self.assertEqual(self.gaps(), [])
        self.assertEqual(svc.edge, "")
        self.assertEqual(sorted(svc.probed_by), ["http_fingerprint", "waf_detect"])


class TestSlowButHonest(_EdgeCase):
    def test_slow_server_is_not_a_waf(self):
        self.edge.delay = 0.3
        self.policy.http.path_checks = False
        svc = self.probe()
        self.assertEqual(self.gaps(), [])
        self.assertEqual(svc.edge, "")

    def test_timeouts_are_not_a_waf(self):
        self.edge.delay = 2.0
        self.policy.http.timeout_sec = 1
        self.policy.http.path_checks = False
        svc = self.probe()
        self.assertEqual(self.gaps(), [])
        self.assertEqual(svc.edge, "")

    def test_overloaded_503_is_not_a_waf(self):
        self.edge.mode = "honest_overloaded"
        self.policy.http.path_checks = False
        self.assertEqual((self.probe().edge, self.gaps()), ("", []))


class TestBlockedChase(_EdgeCase):
    def chase(self):
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.chase_leads(self.store, self.scope, self.policy, self.runner, rounds=1)
        return self.store.leads()[0]

    def test_blocked_lead_stays_open_with_a_gap_then_clears(self):
        url = f"http://127.0.0.1:{self.edge.port}/admin/"
        self.store.add_leads([Lead(kind="web_paths", host="127.0.0.1", port=self.edge.port,
                                   url=url, reason="check it")])
        self.edge.mode = "imperva_block"
        lead = self.chase()
        self.assertEqual(lead.status, "open")
        self.assertEqual(lead.attempts, 1)
        [gap] = self.gaps("chase")
        self.assertEqual((gap.component, gap.severity), ("waf", "serious"))
        self.assertIn("Imperva", gap.reason)
        self.assertEqual(self.store.findings(), [])

        self.edge.mode = "plain"
        lead = self.chase()
        self.assertEqual(lead.status, "done")
        self.assertEqual(self.gaps("chase"), [])


class TestNetFetch(_EdgeCase):
    def test_every_set_cookie_is_kept(self):
        self.edge.mode = "imperva_ok"
        resp = net.fetch(self.svc.base_url(), self.scope, self.policy.http)
        self.assertEqual(waf.cookie_names(resp.set_cookies),
                         ["visid_incap_123456", "incap_ses_1234_123456"])

    def test_fetch_reports_blocks_to_the_active_watch(self):
        self.edge.mode = "f5_asm_block"
        with waf.watch() as seen:
            net.fetch(self.svc.base_url(), self.scope, self.policy.http)
        self.assertEqual([(b.vendor, b.status) for b in seen.blocks], [("F5 BIG-IP ASM", 200)])


if __name__ == "__main__":
    unittest.main()
