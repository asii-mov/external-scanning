"""KEV / EPSS ranking and CDN tagging, against local feed files only.

Every feed here is a file:// URL in a temp directory. Nothing in this file
may reach the network.
"""

import contextlib
import gzip
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from extscan import cli, enrich, pipeline, vault
from extscan.models import Finding, Host
from extscan.policy import Policy
from extscan.runner import Runner
from extscan.scope import Scope
from extscan.store import Store
from extscan.tools import nuclei
from extscan.triage import triage

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "lab-run"

KEV_CVE = "CVE-2021-44228"       # planted in the KEV file
EPSS_ONLY_CVE = "CVE-2019-0001"  # scored, not in KEV
VULNERS_CVE = "CVE-2021-23017"   # KEV-listed, reached only by a version match

KEV = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.10", "dateReleased": "2026-11-10T15:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {"cveID": KEV_CVE, "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": VULNERS_CVE, "vendorProject": "F5", "product": "nginx",
         "vulnerabilityName": "nginx resolver off-by-one", "dateAdded": "2022-01-01",
         "dueDate": "2022-02-01", "knownRansomwareCampaignUse": "Unknown"},
    ],
}
EPSS = ("#model_version:v2025.03.14,score_date:2026-11-11T12:55:00Z\n"
        "cve,epss,percentile\n"
        + "".join(f"CVE-2010-{n:04d},0.00042,0.11000\n" for n in range(1000, 4000))
        + f"{KEV_CVE},0.94358,0.99990\n{EPSS_ONLY_CVE},0.61000,0.97500\n"
          f"{VULNERS_CVE},0.20000,0.90000\n")
AWS = {"prefixes": [
    {"ip_prefix": "127.0.0.9/32", "service": "EC2"},          # not an edge: must not tag
    {"ip_prefix": "127.0.0.3/32", "service": "CLOUDFRONT"}],
    "ipv6_prefixes": [{"ipv6_prefix": "2600:9000::/28", "service": "CLOUDFRONT"}]}


def cve_finding(title, severity, source, port=8080, **kw):
    return Finding(title=title, severity=severity, host="127.0.0.2", port=port,
                   source=source, **kw)


class _Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(enrich.OFFLINE_ENV, None)

        shutil.copytree(FIXTURE, self.tmp / "runs" / "run")
        self.store = Store(self.tmp / "runs" / "run")
        self.feeds = self.tmp / "feeds"
        self.feeds.mkdir()
        (self.feeds / "kev.json").write_text(json.dumps(KEV))
        (self.feeds / "epss.csv.gz").write_bytes(gzip.compress(EPSS.encode()))
        (self.feeds / "cloudflare.txt").write_text("127.0.0.2/32\n2400:cb00::/32\n")
        (self.feeds / "aws.json").write_text(json.dumps(AWS))

        scope = json.loads((ROOT / "examples" / "lab" / "scope.json").read_text())
        scope["targets"] = ["127.0.0.2/32", "127.0.0.9/32"]
        scope["max_hosts"] = 2
        self.scope_path = self.tmp / "scope.json"
        self.scope_path.write_text(json.dumps(scope))
        self.scope = Scope.load(self.scope_path)
        self.store.save_hosts([Host(ip="127.0.0.9", state="up")])

        self.policy = Policy()
        self.policy.enrich.kev_url = self.url("kev.json")
        self.policy.enrich.epss_url = self.url("epss.csv.gz")
        self.policy.enrich.range_urls = {"cloudflare": [self.url("cloudflare.txt")],
                                         "cloudfront": [self.url("aws.json")]}
        self.fetched: list[str] = []

    def url(self, name: str) -> str:
        return (self.feeds / name).as_uri()

    def fetcher(self, url, dest, timeout):
        """The real downloader on file:// URLs, with every call recorded."""
        self.fetched.append(url)
        enrich.url_fetcher()(url, dest, timeout)

    def plant(self):
        """Three findings with CVE ids, each stated a different way."""
        self.store.add_findings([
            cve_finding("Apache Log4j2 remote code execution", "medium",
                        f"nuclei:{KEV_CVE}"),
            cve_finding("Some scored issue", "medium", "nuclei:scored-template",
                        references=[f"https://nvd.nist.gov/vuln/detail/{EPSS_ONLY_CVE}"],
                        review_required=True, review_reason="r"),
            cve_finding("Known-vulnerability candidates on http nginx 1.18.0", "medium",
                        "nmap-tcp:vulners", confidence="tentative", review_required=True,
                        review_reason="r", tags=["cve", "version-match"],
                        evidence=f"  cpe:/a:igor_sysoev:nginx:1.18.0:\n    {VULNERS_CVE}\t7.7\t"
                                 f"https://vulners.com/cve/{VULNERS_CVE}\n"
                                 "    CVE-2021-3618\t7.4\thttps://vulners.com/cve/CVE-2021-3618"),
        ])

    def run_enrich(self, dry_run=False, policy=None):
        runner = Runner(self.store, dry_run=dry_run)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = pipeline.enrich(self.store, self.scope, policy or self.policy, runner,
                                     fetcher=self.fetcher)
        return result, out.getvalue()

    def by_title(self, start: str) -> Finding:
        return next(f for f in self.store.findings() if f.title.startswith(start))

    def gaps(self) -> list:
        return [d for d in self.store.degradations() if d.stage == "enrich"]


class TestCveExtraction(unittest.TestCase):
    def test_reliable_places_only(self):
        f = Finding(title="Heartbleed (CVE-2014-0160) reported on 203.0.113.5:443",
                    source="nuclei:CVE-2021-41773", tags=["cve", "cve2021", "CVE-2020-1938"],
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
                                "https://blog.example/why-CVE-2018-0001-matters"],
                    evidence="--- response ---\nchangelog: fixes CVE-2017-5638")
        self.assertEqual(enrich.extract_cves(f), [
            "CVE-2021-41773", "CVE-2020-1938", "CVE-2019-11043", "CVE-2014-0160"])

    def test_response_bodies_are_not_searched(self):
        f = Finding(title="Exposed /CHANGELOG on 203.0.113.5:80", source="extscan:paths",
                    evidence="HTTP/1.1 200\n\nFixed CVE-2021-44228 in 2.15")
        self.assertEqual(enrich.extract_cves(f), [])

    def test_nmap_script_that_only_ran_names_no_cve(self):
        ran = Finding(title="x", source="nmap-tcp:smb-vuln-ms17-010",
                      evidence="State: NOT VULNERABLE\n IDs:  CVE:CVE-2017-0143")
        hit = Finding(title="x", source="nmap-tcp:smb-vuln-ms17-010",
                      evidence="State: VULNERABLE\n IDs:  CVE:CVE-2017-0143\n"
                               " see also CVE-2000-0001")
        self.assertEqual(enrich.extract_cves(ran), [])
        self.assertEqual(enrich.extract_cves(hit), ["CVE-2017-0143"])

    def test_nuclei_classification_is_read(self):
        line = json.dumps({
            "template-id": "apache-log4j-rce", "ip": "203.0.113.5", "port": "8080",
            "matched-at": "http://203.0.113.5:8080/",
            "info": {"name": "Log4j RCE", "severity": "critical",
                     "classification": {"cve-id": ["cve-2021-44228"], "cwe-id": ["cwe-502"]}}})
        (f,), _ = nuclei.parse_jsonl(line)
        self.assertEqual(f.cves, ["CVE-2021-44228"])
        none = json.dumps({"template-id": "t", "ip": "203.0.113.5",
                           "info": {"name": "n", "classification": {"cve-id": None}}})
        self.assertEqual(nuclei.parse_jsonl(none)[0][0].cves, [])


class TestOldRunsStillLoad(_Case):
    def test_old_records_load_and_round_trip(self):
        old = json.loads((FIXTURE / "findings.json").read_text())[0]
        self.assertNotIn("cves", old)
        f = Finding.from_dict(old)
        self.assertEqual((f.cves, f.kev, f.epss, f.id), ([], False, None, old["id"]))
        self.assertEqual(Finding.from_dict(f.to_dict()), f)
        host = Host.from_dict(json.loads((FIXTURE / "hosts.json").read_text())[0])
        self.assertEqual(host.network, "")
        self.assertEqual(Host.from_dict(host.to_dict()), host)

    def test_fixture_rerenders_without_the_new_fields(self):
        scope = Scope.load(ROOT / "examples" / "lab" / "scope.json")
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(self.store, scope)
        report = (self.store.path / "report.md").read_text()
        self.assertIn("the `enrich` stage did not run", report)
        self.assertNotIn("**KEV**", report)
        note = next((self.store.path / vault.VAULT_DIR / "findings").glob("*.md")).read_text()
        self.assertNotIn("kev:", note)


class TestRanking(_Case):
    def test_kev_finding_is_flagged_scored_and_keeps_its_id_and_severity(self):
        self.plant()
        before = {f.title: (f.id, f.severity) for f in self.store.findings()}
        result, _ = self.run_enrich()
        f = self.by_title("Apache Log4j2")
        self.assertEqual(f.cves, [KEV_CVE])
        self.assertTrue(f.kev)
        self.assertEqual(f.kev_detail[0]["date_added"], "2021-12-10")
        self.assertTrue(f.kev_detail[0]["ransomware"])
        self.assertAlmostEqual(f.epss, 0.94358)
        self.assertAlmostEqual(f.epss_percentile, 0.9999)
        self.assertTrue(f.review_required)      # a known-exploited CVE reaches the queue
        self.assertEqual(result["kev_findings"], 2)
        self.assertEqual({f.title: (f.id, f.severity) for f in self.store.findings()
                          if f.title in before}, before)

    def test_epss_attaches_without_kev(self):
        self.plant()
        self.run_enrich()
        f = self.by_title("Some scored issue")
        self.assertEqual((f.cves, f.kev), ([EPSS_ONLY_CVE], False))
        self.assertAlmostEqual(f.epss, 0.61)

    def test_vulners_candidates_are_captured_and_stay_tentative(self):
        self.plant()
        self.run_enrich()
        f = self.by_title("Known-vulnerability candidates")
        self.assertEqual(f.cves, [VULNERS_CVE, "CVE-2021-3618"])
        self.assertTrue(f.kev)
        self.assertEqual((f.confidence, f.severity), ("tentative", "medium"))
        self.assertTrue(any("version string" in line for line in enrich.cve_lines(f)))

    def test_kev_medium_outranks_non_kev_high_but_not_critical(self):
        self.plant()
        self.run_enrich()
        queue = triage(self.store.findings(), self.store.services()).review_queue
        kev = next(i for i in queue if i.title.startswith("Apache Log4j2"))
        self.assertEqual(kev.severity, "medium")
        highs = [i.priority for i in queue if i.severity == "high" and not i.kev]
        criticals = [i.priority for i in queue if i.severity == "critical" and not i.kev]
        self.assertTrue(highs and criticals)
        self.assertLess(kev.priority, min(highs))
        self.assertGreater(kev.priority, max(criticals))
        # A version-matched KEV candidate leads its own severity and no more.
        candidate = next(i for i in queue if i.title.startswith("Known-vulnerability"))
        self.assertTrue(candidate.kev and candidate.version_match)
        self.assertGreater(candidate.priority, max(highs))
        mediums = [i.priority for i in queue if i.severity == "medium" and not i.kev]
        self.assertLess(candidate.priority, min(mediums))
        # Among the rest of a severity, the higher EPSS comes first.
        scored = next(i for i in queue if i.title == "Some scored issue")
        self.assertLess(scored.priority, min(m for m in mediums if m != scored.priority))

    def test_feed_versions_are_recorded_in_run_metadata(self):
        self.plant()
        self.run_enrich()
        stage = self.store.meta()["stages"]["enrich"]
        self.assertEqual(stage["kev"]["catalog_version"], "2026.11.10")
        self.assertEqual(stage["kev"]["count"], 2)
        self.assertEqual(stage["epss"]["score_date"], "2026-11-11T12:55:00Z")
        self.assertEqual(stage["epss"]["model_version"], "v2025.03.14")
        self.assertEqual(stage["epss"]["rows"], 3003)

    def test_no_cves_means_no_scoring_download(self):
        self.run_enrich()
        self.assertNotIn(self.policy.enrich.kev_url, self.fetched)
        self.assertNotIn(self.policy.enrich.epss_url, self.fetched)
        self.assertIn("skipped", self.store.meta()["stages"]["enrich"])

    def test_epss_loader_keeps_only_the_wanted_rows(self):
        info, scores = enrich.load_epss(self.feeds / "epss.csv.gz", {KEV_CVE})
        self.assertEqual(scores, {KEV_CVE: (0.94358, 0.9999)})
        self.assertEqual(info["rows"], 3003)


class TestQueueRule(unittest.TestCase):
    """The ranking rule on its own, with no feeds involved."""

    def item(self, title, severity, **kw):
        return Finding(title=title, severity=severity, host="203.0.113.5", port=443,
                       source=f"t:{title}", review_required=True, review_reason="r", **kw)

    def order(self, *findings):
        return [i.title for i in triage(list(findings)).review_queue]

    def test_bands(self):
        self.assertEqual(self.order(
            self.item("high", "high", tags=["secrets"]),
            self.item("kev-low", "low", kev=True),
            self.item("kev-medium", "medium", kev=True),
            self.item("critical", "critical"),
            self.item("medium", "medium"),
            self.item("kev-high", "high", kev=True),
            self.item("kev-critical", "critical", kev=True),
            self.item("kev-high-tentative", "high", kev=True, confidence="tentative"),
        ), ["kev-critical", "kev-high", "critical", "kev-high-tentative", "kev-medium",
            "high", "kev-low", "medium"])

    def test_epss_orders_within_a_severity_and_never_across(self):
        self.assertEqual(self.order(
            self.item("m-low-epss", "medium", epss=0.02),
            self.item("m-none", "medium", tags=["secrets"]),
            self.item("m-high-epss", "medium", epss=0.9),
            self.item("high-none", "high"),
        ), ["high-none", "m-high-epss", "m-low-epss", "m-none"])


class TestFeedFailure(_Case):
    def test_unreachable_feed_is_a_gap_that_a_later_enrich_clears(self):
        self.plant()
        kev = self.feeds / "kev.json"
        kev.rename(self.feeds / "kev.away")
        result, out = self.run_enrich()
        gaps = self.gaps()
        self.assertEqual([d.component for d in gaps], ["kev"])
        self.assertIn("not ranked by exploitation", gaps[0].impact)
        self.assertIn("not ranked by exploitation", out)
        self.assertIsNone(result["kev"])
        f = self.by_title("Apache Log4j2")
        self.assertFalse(f.kev)
        self.assertAlmostEqual(f.epss, 0.94358)     # the other feed still applied

        (self.feeds / "kev.away").rename(kev)
        self.run_enrich()
        self.assertEqual(self.gaps(), [])
        self.assertTrue(self.by_title("Apache Log4j2").kev)

    def test_unparseable_feed_is_a_gap_and_is_not_kept_in_the_cache(self):
        self.plant()
        (self.feeds / "epss.csv.gz").write_text("<html>blocked by proxy</html>")
        self.run_enrich()
        self.assertEqual([d.component for d in self.gaps()], ["epss"])
        self.assertIsNone(self.by_title("Apache Log4j2").epss)
        (self.feeds / "epss.csv.gz").write_bytes(gzip.compress(EPSS.encode()))
        self.run_enrich()                      # inside the max age: must fetch again
        self.assertEqual(self.gaps(), [])
        self.assertAlmostEqual(self.by_title("Apache Log4j2").epss, 0.94358)

    def test_stale_copy_is_used_and_said_to_be_stale(self):
        self.plant()
        self.run_enrich()
        self.policy.enrich.cache_max_age_hours = 0      # everything is now too old
        (self.feeds / "kev.json").unlink()
        self.run_enrich()
        (gap,) = self.gaps()
        self.assertIn("could not be refreshed", gap.reason)
        self.assertTrue(self.by_title("Apache Log4j2").kev)

    def test_dry_run_fetches_nothing_and_marks_nothing(self):
        self.plant()
        before = [f.to_dict() for f in self.store.findings()]
        result, out = self.run_enrich(dry_run=True)
        self.assertEqual(self.fetched, [])
        self.assertTrue(result["dry_run"])
        self.assertIn(f"[dry-run] would fetch {self.policy.enrich.kev_url}", out)
        self.assertIn(f"[dry-run] would fetch {self.url('cloudflare.txt')}", out)
        self.assertNotIn("enrich", self.store.meta()["stages"])
        self.assertEqual([f.to_dict() for f in self.store.findings()], before)
        self.assertFalse((self.tmp / "runs" / ".feed-cache").exists())
        self.assertEqual(self.gaps(), [])

    def test_cache_is_reused_within_its_max_age(self):
        self.plant()
        self.run_enrich()
        first = list(self.fetched)
        self.assertEqual(len(first), 4)             # KEV, EPSS, two range lists
        self.run_enrich()
        self.assertEqual(self.fetched, first)       # second run: no downloads
        self.assertTrue(self.store.meta()["stages"]["enrich"]["kev"]["from_cache"])
        # Another run of the same engagement shares the cache.
        shutil.copytree(self.store.path, self.tmp / "runs" / "second")
        self.store = Store(self.tmp / "runs" / "second")
        self.run_enrich()
        self.assertEqual(self.fetched, first)

    def test_cache_expires(self):
        clock = [1000.0]
        cache = enrich.FeedCache(self.tmp / "cache", max_age=3600, fetcher=self.fetcher,
                                 now=lambda: clock[0])
        url = self.url("kev.json")
        self.assertFalse(cache.get(url).from_cache)
        clock[0] += 3599
        self.assertTrue(cache.get(url).from_cache)
        clock[0] += 2
        self.assertFalse(cache.get(url).from_cache)
        self.assertEqual(self.fetched, [url, url])

    def test_disabled_by_policy_or_environment_fetches_nothing(self):
        self.plant()
        self.policy.enrich.enabled = False
        result, _ = self.run_enrich()
        self.assertTrue(result["disabled"])
        os.environ[enrich.OFFLINE_ENV] = "1"
        self.policy.enrich.enabled = True
        result, _ = self.run_enrich()
        self.assertTrue(result["disabled"])
        self.assertEqual(self.fetched, [])
        self.assertTrue(self.store.meta()["stages"]["enrich"]["disabled"])

    def test_system_proxy_is_ignored_unless_the_policy_allows_it(self):
        seen = []

        def build(*handlers):
            seen.append(handlers)
            raise OSError("stop here")

        with mock.patch.object(enrich.urllib.request, "build_opener", build):
            for allow in (False, True):
                with self.assertRaises(OSError):
                    enrich.url_fetcher(allow)("https://feeds.invalid/x", self.tmp / "x", 1)
        self.assertEqual(len(seen[0]), 1)
        self.assertEqual(seen[0][0].proxies, {})    # no proxy, whatever the environment
        self.assertEqual(seen[1], ())


class TestNetworkTags(_Case):
    def test_address_in_a_planted_range_is_tagged_and_reported(self):
        result, _ = self.run_enrich()
        hosts = {h.ip: h.network for h in self.store.hosts()}
        # 127.0.0.9 is in the AWS file, but as EC2 and not as CloudFront.
        self.assertEqual(hosts, {"127.0.0.2": "cloudflare", "127.0.0.9": ""})
        self.assertEqual(result["networks"]["by_network"], {"cloudflare": 1})
        (f,) = [f for f in self.store.findings() if f.source == enrich.EDGE_SOURCE]
        self.assertEqual((f.severity, f.review_required), ("info", True))
        self.assertIn("127.0.0.2", f.evidence)
        self.assertNotIn("127.0.0.9", f.evidence)
        self.assertIn("provider's edge, not the client's origin server", f.description)
        self.assertIn("other tenants share the address", f.description)

    def test_tag_shows_in_the_host_inventory_of_both_reports(self):
        self.run_enrich()
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(self.store, self.scope)
        report = (self.store.path / "report.md").read_text()
        self.assertRegex(report, r"\| `127\.0\.0\.2` \|[^\n]*\| Cloudflare \|")
        self.assertIn("CDN and cloud address ranges published by: cloudflare", report)
        note = (self.store.path / vault.VAULT_DIR / "hosts" / "127.0.0.2.md").read_text()
        self.assertIn('network: "cloudflare"', note)
        self.assertIn("Address in Cloudflare ranges", note)

    def test_tagging_changes_nothing_about_what_is_scanned(self):
        before = [s.to_dict() for s in self.store.services()]
        self.run_enrich()
        self.assertEqual([s.to_dict() for s in self.store.services()], before)

    def test_one_failed_list_is_a_gap_for_that_provider_only(self):
        (self.feeds / "aws.json").write_text("not a range list")
        self.run_enrich()
        self.assertEqual([d.component for d in self.gaps()], ["ranges:cloudfront"])
        self.assertEqual({h.ip: h.network for h in self.store.hosts()}["127.0.0.2"],
                         "cloudflare")
        (self.feeds / "aws.json").write_text(json.dumps(AWS))
        self.run_enrich()
        self.assertEqual(self.gaps(), [])

    def test_rerun_does_not_duplicate_and_drops_a_stale_tag(self):
        self.run_enrich()
        (self.feeds / "cloudflare.txt").write_text("198.51.100.0/24\n")
        self.policy.enrich.cache_max_age_hours = 0
        self.run_enrich()
        self.assertEqual({h.network for h in self.store.hosts()}, {""})
        self.assertEqual([f for f in self.store.findings()
                          if f.source == enrich.EDGE_SOURCE], [])

    def test_range_formats(self):
        nets = enrich.parse_ranges("cloudfront", json.dumps(AWS))
        self.assertEqual(sorted(map(str, nets)), ["127.0.0.3/32", "2600:9000::/28"])
        fastly = json.dumps({"addresses": ["23.235.32.0/20"], "ipv6_addresses": ["2a04:4e40::/32"]})
        self.assertEqual(len(enrich.parse_ranges("fastly", fastly)), 2)
        google = json.dumps({"syncToken": "1", "prefixes": [
            {"ipv4Prefix": "8.8.4.0/24"}, {"ipv6Prefix": "2001:4860::/32"}]})
        self.assertEqual(len(enrich.parse_ranges("google", google)), 2)
        # A list that would swallow the whole internet is refused.
        with self.assertRaises(enrich.FeedError):
            enrich.parse_ranges("cloudflare", "0.0.0.0/0\n")

    def test_most_specific_range_wins(self):
        index = enrich.RangeIndex()
        index.add("google", enrich.parse_ranges("google", "34.64.0.0/10\n"))
        index.add("google-cloud", enrich.parse_ranges("google-cloud", "34.80.0.0/15\n"))
        self.assertEqual(index.lookup("34.80.1.1"), ("google-cloud", "34.80.0.0/15"))
        self.assertEqual(index.lookup("34.100.1.1"), ("google", "34.64.0.0/10"))
        self.assertIsNone(index.lookup("203.0.113.1"))


class TestRendering(_Case):
    def setUp(self):
        super().setUp()
        self.plant()
        self.run_enrich()
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(self.store, self.scope)

    def test_report_shows_kev_epss_and_feed_versions(self):
        report = (self.store.path / "report.md").read_text()
        self.assertRegex(report, r"\| \d+ \| Medium \| \*\*KEV\*\*, EPSS 0\.94 \| Apache Log4j2")
        self.assertIn("**KEV** (version match)", report)
        self.assertIn(f"- **CISA KEV:** {KEV_CVE} is known to be exploited", report)
        self.assertIn("used in ransomware campaigns", report)
        self.assertIn("catalogue, version 2026.11.10", report)
        self.assertIn(enrich.EPSS_ATTRIBUTION, report)
        data = json.loads((self.store.path / "report.json").read_text())
        row = next(f for f in data["findings"] if f["title"].startswith("Apache Log4j2"))
        self.assertTrue(row["kev"])

    def test_vault_frontmatter_and_badge(self):
        f = self.by_title("Apache Log4j2")
        note = (self.store.path / vault.VAULT_DIR / "findings" / f"{f.id}.md").read_text()
        self.assertIn("kev: true", note)
        self.assertIn("epss: 0.94358", note)
        self.assertIn(f'cves: ["{KEV_CVE}"]', note)
        self.assertIn("**Severity:** Medium (KEV · EPSS 0.94)", note)
        queue = (self.store.path / vault.VAULT_DIR / f"{vault.REVIEW}.md").read_text()
        self.assertIn("| **KEV**, EPSS 0.94 |", queue)
        method = (self.store.path / vault.VAULT_DIR / f"{vault.METHOD}.md").read_text()
        self.assertIn("first.org/epss", method)

    def run_cli(self, *argv) -> str:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--runs-dir", str(self.tmp / "runs"), *argv])
        self.assertEqual(code, 0)
        return out.getvalue()

    def test_cli_findings_and_show(self):
        listing = self.run_cli("findings", "run", "--severity", "medium")
        self.assertIn("Apache Log4j2 remote code execution [REVIEW] [KEV · EPSS 0.94]", listing)
        self.assertIn(f"cve={KEV_CVE}", listing)
        mediums = [ln for ln in listing.splitlines() if ln.strip().startswith("MEDIUM")]
        self.assertIn("Apache Log4j2", mediums[0])          # KEV first within a severity
        shown = self.run_cli("show", "run", "--finding", self.by_title("Apache Log4j2").id)
        self.assertIn(f"CISA KEV: {KEV_CVE} is known to be exploited", shown)

    def test_cli_enrich_command_with_a_policy_file(self):
        policy = self.tmp / "policy.json"
        policy.write_text(json.dumps({"enrich": {
            "kev_url": self.url("kev.json"), "epss_url": self.url("epss.csv.gz"),
            "range_urls": {"cloudflare": [self.url("cloudflare.txt")]}}}))
        out = self.run_cli("enrich", "run", "--scope", str(self.scope_path),
                           "--policy", str(policy), "--json")
        self.assertEqual(json.loads(out[out.index("{"):])["enrich"]["kev_findings"], 2)
        plan = self.run_cli("enrich", "run", "--scope", str(self.scope_path),
                            "--policy", str(policy), "--dry-run")
        self.assertIn("[dry-run] would reuse the copy", plan)

    def test_run_and_resume_enrich_before_the_report(self):
        calls: list[str] = []

        def stage(name):
            return mock.patch.object(pipeline, name,
                                     side_effect=lambda *a, **k: calls.append(name) or {
                                         "paths": {"markdown": "x"}, "review_items": 0})

        with stage("discover"), stage("probe"), stage("chase_leads"), stage("screenshot"), \
                stage("enrich"), stage("make_report"), \
                mock.patch.object(pipeline, "doctor", return_value={}):
            pipeline.run_all(self.store, Scope.load(ROOT / "examples" / "lab" / "scope.json"),
                             self.policy, Runner(self.store))
            self.assertEqual(calls[-2:], ["enrich", "make_report"])
            calls.clear()
            self.run_cli("resume", "run", "--scope", str(self.scope_path))
            self.assertEqual(calls[-2:], ["enrich", "make_report"])

    def test_unknown_enrich_policy_key_is_refused(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"enrich": {"kev": "x"}})


if __name__ == "__main__":
    unittest.main()
