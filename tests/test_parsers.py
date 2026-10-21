"""nmap XML and nuclei JSONL parsing, against fixtures captured from real output."""

import json
import tempfile
import unittest
from pathlib import Path

from extscan.scope import Scope
from extscan.tools import nmap, nuclei

FIXTURES = Path(__file__).parent / "fixtures"


def scope_for(targets, **extra) -> Scope:
    data = {
        "engagement": "t", "client": "c",
        "authorization": {"reference": "T-1", "authorized_by": "x@test"},
        "targets": targets, **extra,
    }
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(data, fh)
    fh.close()
    return Scope.load(fh.name)


class TestNmapTcpParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = scope_for(["203.0.113.0/24"])
        cls.xml = (FIXTURES / "nmap-tcp.xml").read_text()
        cls.hosts, cls.services, cls.findings = nmap.parse_xml(
            cls.xml, scope=cls.scope, source="nmap-tcp")

    def test_extracts_up_hosts_only_in_scope(self):
        ips = {h.ip for h in self.hosts}
        self.assertEqual(ips, {"203.0.113.10", "203.0.113.11", "203.0.113.12"})

    def test_drops_out_of_scope_host(self):
        """The fixture includes 198.51.100.99, which the scope excludes."""
        self.assertNotIn("198.51.100.99", {h.ip for h in self.hosts})
        self.assertNotIn("198.51.100.99", {s.host for s in self.services})

    def test_collects_hostnames(self):
        host = next(h for h in self.hosts if h.ip == "203.0.113.10")
        self.assertIn("www.example-client.test", host.hostnames)
        self.assertIn("shop.example-client.test", host.hostnames)

    def test_os_guess_takes_best_match(self):
        host = next(h for h in self.hosts if h.ip == "203.0.113.10")
        self.assertIn("Linux 3.10 - 4.11", host.os_guess)
        self.assertIn("94", host.os_guess)

    def test_only_open_ports_become_services(self):
        ports = {(s.host, s.port) for s in self.services}
        self.assertIn(("203.0.113.10", 22), ports)
        self.assertIn(("203.0.113.10", 6379), ports)
        # 8080 is filtered in the fixture and must not appear.
        self.assertNotIn(("203.0.113.10", 8080), ports)

    def test_service_version_detail(self):
        ssh = next(s for s in self.services if s.port == 22)
        self.assertEqual(ssh.product, "OpenSSH")
        self.assertEqual(ssh.version, "7.4")
        self.assertIn("cpe:/a:openbsd:openssh:7.4", ssh.cpe)

    def test_tls_detected_from_tunnel_attribute(self):
        https = next(s for s in self.services if s.port == 443)
        self.assertTrue(https.is_tls)
        self.assertTrue(https.is_http)
        self.assertEqual(https.base_url(), "https://203.0.113.10")

    def test_plain_http_url_includes_port_when_nonstandard(self):
        svc = next(s for s in self.services if s.port == 80)
        self.assertEqual(svc.base_url(), "http://203.0.113.10")

    def test_script_output_captured(self):
        http = next(s for s in self.services if s.port == 80)
        self.assertIn("http-title", http.scripts)
        self.assertEqual(http.scripts["http-title"], "Example Client Storefront")

    def test_table_valued_script_still_captured(self):
        """ssl-cert carries its data in child elements, not an output attribute."""
        https = next(s for s in self.services if s.port == 443)
        self.assertIn("ssl-cert", https.scripts)
        self.assertIn("www.example-client.test", https.scripts["ssl-cert"])

    def test_vulners_becomes_tentative_review_finding(self):
        vulners = [f for f in self.findings if "vulners" in f.source]
        self.assertEqual(len(vulners), 1)
        f = vulners[0]
        self.assertEqual(f.confidence, "tentative")
        self.assertTrue(f.review_required)
        self.assertIn("CVE-2021-44790", f.evidence)

    def test_ftp_anon_is_medium(self):
        ftp = next(f for f in self.findings if "ftp-anon" in f.source)
        self.assertEqual(ftp.severity, "medium")

    def test_host_level_script_recorded(self):
        host_findings = [f for f in self.findings if "smb-os-discovery" in f.source]
        self.assertEqual(len(host_findings), 1)
        self.assertEqual(host_findings[0].host, "203.0.113.11")
        self.assertIsNone(host_findings[0].port)

    def test_findings_are_stable_across_reparse(self):
        """Re-parsing must not create new finding ids, or re-scans duplicate."""
        _, _, again = nmap.parse_xml(self.xml, scope=self.scope, source="nmap-tcp")
        self.assertEqual({f.id for f in self.findings}, {f.id for f in again})

    def test_malformed_xml_raises_valueerror(self):
        with self.assertRaises(ValueError):
            nmap.parse_xml("<nmaprun><host></nmap", scope=self.scope)

    def test_empty_scan_parses_cleanly(self):
        hosts, services, findings = nmap.parse_xml(
            '<?xml version="1.0"?><nmaprun></nmaprun>', scope=self.scope)
        self.assertEqual((hosts, services, findings), ([], [], []))


class TestNmapUdpParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = scope_for(["203.0.113.0/24"])
        cls.hosts, cls.services, cls.findings = nmap.parse_xml(
            (FIXTURES / "nmap-udp.xml").read_text(), scope=cls.scope, source="nmap-udp")

    def test_udp_services_recorded(self):
        ports = {s.port for s in self.services}
        self.assertEqual(ports, {161, 123, 53})
        self.assertTrue(all(s.proto == "udp" for s in self.services))

    def test_open_filtered_state_is_kept(self):
        """nmap's ambiguous UDP state must not be discarded as closed."""
        dns = next(s for s in self.services if s.port == 53)
        self.assertEqual(dns.state, "open|filtered")

    def test_snmp_service_is_not_http(self):
        snmp_svc = next(s for s in self.services if s.port == 161)
        self.assertFalse(snmp_svc.is_http)
        self.assertFalse(snmp_svc.is_tls)


class TestNmapArgvConstruction(unittest.TestCase):
    def setUp(self):
        from extscan.policy import Policy
        self.scope = scope_for(["203.0.113.0/24"], exclude=["203.0.113.5"])
        self.policy = Policy.for_profile("standard")

    def test_tcp_argv_has_xml_output_and_targets(self):
        argv = nmap.tcp_argv(self.scope, self.policy, "/tmp/out.xml")
        self.assertEqual(argv[0], "nmap")
        self.assertIn("-oX", argv)
        self.assertIn("/tmp/out.xml", argv)
        self.assertIn("203.0.113.0/24", argv)
        self.assertIn("--exclude", argv)

    def test_udp_argv_requests_udp_scan(self):
        argv = nmap.udp_argv(self.scope, self.policy, "/tmp/u.xml")
        self.assertIn("-sU", argv)

    def test_never_requests_dos_or_exploit_scripts(self):
        argv = nmap.tcp_argv(self.scope, self.policy, "/tmp/out.xml")
        joined = " ".join(argv)
        self.assertNotIn("exploit", joined)
        self.assertNotIn("dos", joined.replace("--dns", ""))

    def test_thorough_profile_scans_all_ports(self):
        from extscan.policy import Policy
        argv = nmap.tcp_argv(self.scope, Policy.for_profile("thorough"), "/tmp/o.xml")
        self.assertIn("1-65535", argv)


class TestNucleiParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = scope_for(["203.0.113.0/24"])
        cls.text = (FIXTURES / "nuclei.jsonl").read_text()
        cls.findings, cls.leads = nuclei.parse_jsonl(cls.text, scope=cls.scope)

    def test_skips_malformed_lines(self):
        """The fixture contains a junk line and a dict with no template id."""
        self.assertTrue(len(self.findings) >= 5)
        for f in self.findings:
            self.assertTrue(f.title)

    def test_severity_carried_through(self):
        log4j = next(f for f in self.findings if "Log4j" in f.title)
        self.assertEqual(log4j.severity, "critical")
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", log4j.references)

    def test_remediation_becomes_recommendation(self):
        log4j = next(f for f in self.findings if "Log4j" in f.title)
        self.assertIn("2.17.1", log4j.recommendation)

    def test_request_response_kept_as_evidence(self):
        git = next(f for f in self.findings if "Git Config" in f.title)
        self.assertIn("repositoryformatversion", git.evidence)

    def test_extracted_results_in_evidence(self):
        apache = next(f for f in self.findings if "Apache Version" in f.title)
        self.assertIn("Apache/2.4.6", apache.evidence)

    def test_swagger_hit_raises_openapi_lead(self):
        kinds = {l.kind for l in self.leads}
        self.assertIn("openapi", kinds)
        lead = next(l for l in self.leads if l.kind == "openapi")
        self.assertEqual(lead.url, "https://203.0.113.10/swagger.json")

    def test_git_hit_raises_git_lead(self):
        self.assertIn("git_exposure", {l.kind for l in self.leads})

    def test_swagger_flagged_for_human_review(self):
        swagger = next(f for f in self.findings if "Swagger" in f.title)
        self.assertTrue(swagger.review_required)
        self.assertIn("auditor", swagger.review_reason.lower())

    def test_login_panel_flagged_for_review(self):
        panel = next(f for f in self.findings if "Tomcat Manager" in f.title)
        self.assertTrue(panel.review_required)

    def test_out_of_scope_result_is_suppressed_not_chased(self):
        """nuclei followed a redirect offsite; we record it but never probe it."""
        suppressed = [f for f in self.findings if "out-of-scope" in f.title]
        self.assertEqual(len(suppressed), 1)
        self.assertTrue(suppressed[0].review_required)
        # And crucially, no lead points at the third party.
        for lead in self.leads:
            self.assertNotIn("evil-third-party", lead.url)
            self.assertTrue(self.scope.contains(lead.host) or not lead.host)

    def test_no_scope_means_no_filtering(self):
        findings, _ = nuclei.parse_jsonl(self.text, scope=None)
        self.assertTrue(any("evil-third-party" in f.evidence for f in findings))

    def test_empty_input(self):
        self.assertEqual(nuclei.parse_jsonl("", scope=self.scope), ([], []))


class TestNucleiArgv(unittest.TestCase):
    def setUp(self):
        from extscan.policy import Policy
        self.policy = Policy.for_profile("standard")

    def test_excludes_destructive_template_families(self):
        argv = nuclei.argv(self.policy, "/tmp/t.txt", "/tmp/o.jsonl")
        self.assertIn("-exclude-tags", argv)
        excluded = argv[argv.index("-exclude-tags") + 1]
        for tag in ("dos", "intrusive", "fuzz", "brute-force"):
            self.assertIn(tag, excluded)

    def test_out_of_band_detection_disabled_by_default(self):
        """interactsh would relay client traffic through a third-party server."""
        self.assertIn("-no-interactsh", nuclei.argv(self.policy, "/t", "/o"))

    def test_rate_limited(self):
        argv = nuclei.argv(self.policy, "/t", "/o")
        self.assertIn("-rate-limit", argv)

    def test_allow_intrusive_opt_in_removes_exclusions(self):
        self.policy.nuclei.allow_intrusive = True
        self.assertNotIn("-exclude-tags", nuclei.argv(self.policy, "/t", "/o"))


if __name__ == "__main__":
    unittest.main()
