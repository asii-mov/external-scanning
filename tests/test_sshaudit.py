"""ssh-audit adapter: argv, JSON parsing, severity mapping, and the probe.

Fixtures are real ssh-audit 3.9.0 output (`-j -n --skip-rate-test -t 5`):

* ssh-audit-weak.json: OpenSSH 9.6p1 on 127.0.0.1 with legacy algorithms
  enabled on purpose (group1/group14-sha1, 3DES, CBC, hmac-md5, ssh-rsa).
* ssh-audit-openssh96-default.json: the same sshd with its stock algorithms.
* ssh-audit-lab-banner-only.json: the lab's banner-only port 2222, a
  connection error (exit 1) that prints the banner JSON and an [exception]
  line.
"""

import json
import shutil
import unittest
from pathlib import Path
from typing import ClassVar

from extscan import probes
from extscan.models import Service
from extscan.policy import Policy
from extscan.runner import Result
from extscan.scope import ScopeError
from extscan.tools import sshaudit
from tests.test_coverage_gaps import _Stage

FIXTURES = Path(__file__).parent / "fixtures"
WEAK = (FIXTURES / "ssh-audit-weak.json").read_text()
DEFAULT = (FIXTURES / "ssh-audit-openssh96-default.json").read_text()
BANNER_ONLY = (FIXTURES / "ssh-audit-lab-banner-only.json").read_text()

NMAP_AUTH = "Supported authentication methods: \n    publickey\n    password"


def by_tag(findings, tag):
    return [f for f in findings if tag in f.tags]


class TestArgv(unittest.TestCase):
    def setUp(self):
        self.policy = Policy().ssh_audit

    def test_fixed_flags_timeout_and_target(self):
        self.assertEqual(sshaudit.argv(self.policy, "127.0.0.1", 2222),
                         ["ssh-audit", "-j", "-n", "--skip-rate-test", "-t", "5",
                          "127.0.0.1:2222"])

    def test_ipv6_target_is_bracketed(self):
        self.assertEqual(sshaudit.argv(self.policy, "2001:db8::1", 22)[-1],
                         "[2001:db8::1]:22")

    def test_connect_timeout_comes_from_policy(self):
        policy = Policy.from_dict({"ssh_audit": {"connect_timeout_sec": 9}}).ssh_audit
        cmd = sshaudit.argv(policy, "127.0.0.1", 22)
        self.assertEqual(cmd[cmd.index("-t") + 1], "9")

    def test_allowed_extra_args_go_before_the_target(self):
        policy = Policy.from_dict({"ssh_audit": {"extra_args": ["-4"]}}).ssh_audit
        cmd = sshaudit.argv(policy, "127.0.0.1", 22)
        self.assertEqual(cmd[-2:], ["-4", "127.0.0.1:22"])

    def test_target_that_looks_like_a_flag_is_refused(self):
        for host in ("--dheat", "-c", "a b", ""):
            with self.subTest(host=host), self.assertRaises(ValueError):
                sshaudit.argv(self.policy, host, 22)

    def test_unknown_policy_key_is_rejected(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"ssh_audit": {"rate_test": True}})

    def test_refusal_names_the_dangerous_flag(self):
        with self.assertRaises(ValueError) as ctx:
            Policy.from_dict({"ssh_audit": {"extra_args": ["--dheat", "4"]}})
        self.assertIn("--dheat", str(ctx.exception))
        self.assertIn("DoS", str(ctx.exception))


class TestParseWeakServer(unittest.TestCase):
    def setUp(self):
        self.findings = sshaudit.parse_json(WEAK, "127.0.0.1", 22)

    def test_one_summary_and_one_grouped_weak_finding(self):
        self.assertEqual([f.title for f in self.findings], [
            "SSH configuration audit of 127.0.0.1:22 (ssh-audit)",
            "Weak SSH algorithms offered on 127.0.0.1:22: 3 key exchange, "
            "1 host key, 2 cipher, 1 MAC",
        ])
        for f in self.findings:
            self.assertEqual((f.host, f.port, f.proto, f.source),
                             ("127.0.0.1", 22, "tcp", "ssh-audit"))

    def test_weak_finding_takes_the_worst_mapped_severity(self):
        weak = by_tag(self.findings, "weak-algorithm")[0]
        self.assertEqual(weak.severity, "medium")
        self.assertEqual(weak.confidence, "firm")
        for line in ("[medium] diffie-hellman-group1-sha1", "[low] diffie-hellman-group14-sha1",
                     "[low] ssh-rsa (2048-bit)", "[medium] 3des-cbc", "[low] aes128-cbc",
                     "[medium] hmac-md5"):
            self.assertIn(line, weak.evidence)

    def test_opinion_and_hardening_notes_stay_out_of_the_weak_finding(self):
        weak = by_tag(self.findings, "weak-algorithm")[0].evidence
        for name in ("ecdh-sha2-nistp256", "curve25519-sha256", "hmac-sha1 ",
                     "umac-64@openssh.com", "rsa-sha2-512"):
            self.assertNotIn(name, weak)
        summary = self.findings[0].evidence
        self.assertIn("[info] ecdh-sha2-nistp256", summary)
        self.assertIn("[info] hmac-sha1 --", summary)
        self.assertIn("[ok] ssh-ed25519", summary)

    def test_summary_records_banner_and_sha256_fingerprints(self):
        summary = self.findings[0]
        self.assertEqual(summary.severity, "info")
        self.assertIn("banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20", summary.evidence)
        self.assertIn("ssh-ed25519 SHA256:xeOpnQfUivKEGavknC+rwo1mYaFzu3h2oYC/2vvUQxw",
                      summary.evidence)
        self.assertNotIn("MD5:", summary.evidence)

    def test_unknown_auth_methods_leave_the_summary_for_review(self):
        summary = self.findings[0]
        self.assertTrue(summary.review_required)
        self.assertIn("not observed", summary.evidence)

    def test_strict_kex_means_no_terrapin_finding(self):
        self.assertEqual(by_tag(self.findings, "terrapin"), [])

    def test_ids_are_stable_across_parses(self):
        again = sshaudit.parse_json(WEAK, "127.0.0.1", 22)
        self.assertEqual([f.id for f in self.findings], [f.id for f in again])


class TestParseStockServer(unittest.TestCase):
    def test_stock_openssh_gets_no_weak_algorithm_finding(self):
        """NIST curves, HMAC-SHA1 and post-quantum warnings are hardening
        advice, not weaknesses: a default OpenSSH 9.6 reports info only."""
        findings = sshaudit.parse_json(DEFAULT, "127.0.0.1", 22, auth_methods=["publickey"])
        self.assertEqual([f.severity for f in findings], ["info"])
        self.assertFalse(findings[0].review_required)
        self.assertIn("[info] hmac-sha1-etm@openssh.com", findings[0].evidence)
        self.assertIn("(nmap ssh-auth-methods): publickey", findings[0].evidence)


class TestClassify(unittest.TestCase):
    cases: ClassVar = [
        ("enc", {"algorithm": "none"}, "high"),
        ("mac", {"algorithm": "none"}, "high"),
        ("enc", {"algorithm": "arcfour256"}, "medium"),
        ("enc", {"algorithm": "blowfish-cbc"}, "medium"),
        ("mac", {"algorithm": "hmac-sha1-96"}, "medium"),
        ("key", {"algorithm": "ssh-dss"}, "medium"),
        ("key", {"algorithm": "ecdsa-sha2-nistp256",
                 "notes": {"fail": ["using elliptic curves that are suspected as being "
                                    "backdoored by the U.S. National Security Agency"]}},
         "info"),
        ("key", {"algorithm": "rsa-sha2-512", "keysize": 1024}, "medium"),
        ("kex", {"algorithm": "diffie-hellman-group-exchange-sha256", "keysize": 1024},
         "medium"),
        ("kex", {"algorithm": "diffie-hellman-group-exchange-sha256", "keysize": 3072},
         None),
        ("kex", {"algorithm": "weird@example", "notes": {"fail": ["using unknown algorithm"]}},
         "info"),
        ("enc", {"algorithm": "aes256-cbc"}, "low"),
        ("enc", {"algorithm": "chacha20-poly1305@openssh.com",
                 "notes": {"warn": ["vulnerable to the Terrapin attack (CVE-2023-48795), "
                                    "allowing message prefix truncation"]}}, None),
        ("enc", {"algorithm": "aes128-ctr", "notes": {"info": ["available since"]}}, None),
    ]

    def test_mapping(self):
        for category, entry, expected in self.cases:
            with self.subTest(entry=entry["algorithm"], category=category):
                self.assertEqual(sshaudit.classify(category, entry), expected)


class TestVariants(unittest.TestCase):
    """Shapes the fixtures do not cover, derived from the weak fixture."""

    def variant(self, edit):
        data = json.loads(WEAK)
        edit(data)
        return json.dumps(data)

    def test_terrapin_without_strict_kex_is_medium_for_review(self):
        def edit(d):
            d["kex"] = [k for k in d["kex"] if not k["algorithm"].startswith("kex-strict")]
            for e in d["enc"]:
                if e["algorithm"].startswith("chacha20"):
                    e["notes"].setdefault("warn", []).append(
                        "vulnerable to the Terrapin attack (CVE-2023-48795), "
                        "allowing message prefix truncation")
        terrapin = by_tag(sshaudit.parse_json(self.variant(edit), "127.0.0.1", 22),
                          "terrapin")
        self.assertEqual(len(terrapin), 1)
        self.assertEqual(terrapin[0].severity, "medium")
        self.assertTrue(terrapin[0].review_required)
        self.assertIn("chacha20-poly1305@openssh.com", terrapin[0].evidence)

    def test_legacy_cves_are_tentative_banner_matches(self):
        def edit(d):
            d["cves"] = [{"name": "CVE-2016-6210", "cvssv2": 4.3, "description": "user enum"},
                         {"name": "CVE-2016-10009", "cvssv2": 7.5, "description": "agent"}]
        cve = by_tag(sshaudit.parse_json(self.variant(edit), "127.0.0.1", 22), "cve")
        self.assertEqual(len(cve), 1)
        self.assertEqual((cve[0].severity, cve[0].confidence), ("medium", "tentative"))
        self.assertTrue(cve[0].review_required)
        self.assertIn("CVE-2016-10009 (CVSSv2 7.5)", cve[0].evidence)

        def low(d):
            d["cves"] = [{"name": "CVE-2016-6210", "cvssv2": "4.3", "description": "x"}]
        cve = by_tag(sshaudit.parse_json(self.variant(low), "h", 22), "cve")
        self.assertEqual(cve[0].severity, "low")

    def test_current_release_reports_no_cves(self):
        self.assertEqual(json.loads(WEAK)["cves"], [])
        self.assertEqual(by_tag(sshaudit.parse_json(WEAK, "h", 22), "cve"), [])

    def test_ssh1_banner_is_high(self):
        def edit(d):
            d["banner"]["protocol"] = "1.99"
        v1 = by_tag(sshaudit.parse_json(self.variant(edit), "h", 22), "sshv1")
        self.assertEqual([f.severity for f in v1], ["high"])

    def test_hostile_server_text_is_bounded_and_printable(self):
        def edit(d):
            d["banner"]["raw"] = "SSH-2.0-x\x1b[2J\x00" + "A" * 5000
            d["enc"] = ([{"algorithm": "3des-cbc\n## injected", "notes": {}}]
                        + [{"algorithm": f"x{i}"} for i in range(5000)]
                        + ["junk", {"algorithm": 7}, None])
            d["fingerprints"] = "not a list"
            d["cves"] = {"not": "a list"}
        findings = sshaudit.parse_json(self.variant(edit), "h", 22)
        summary = findings[0].evidence
        self.assertNotIn("\x1b", summary)
        self.assertNotIn("\x00", summary)
        self.assertNotIn("\n## injected", "\n".join(f.evidence for f in findings))
        self.assertLessEqual(len(summary), 6000)
        self.assertIn("cipher (200):", summary)

    def test_non_object_json_is_an_error(self):
        for text in ("", "[]", "{", "no json here"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                sshaudit.parse_json(text, "h", 22)


class TestBannerOnlyAndFailures(unittest.TestCase):
    def test_trailing_exception_line_does_not_break_loading(self):
        data = sshaudit.load_json(BANNER_ONLY)
        self.assertEqual(data["banner"]["software"], "OpenSSH_7.4")
        self.assertIn("[exception]", BANNER_ONLY)

    def test_banner_only_document_is_not_an_audit(self):
        with self.assertRaises(ValueError):
            sshaudit.parse_json(BANNER_ONLY, "127.0.0.2", 2222)

    def result(self, rc, stdout="", **kw):
        return Result(["ssh-audit"], rc, stdout, "", 0.1, **kw)

    def test_exit_codes(self):
        weak = sshaudit.load_json(WEAK)
        for rc in (0, 2, 3):
            self.assertEqual(sshaudit.audit_failure(self.result(rc, WEAK), weak), "", rc)
        failure = sshaudit.audit_failure(self.result(1, BANNER_ONLY),
                                         sshaudit.load_json(BANNER_ONLY))
        self.assertEqual(failure, "could not complete the key exchange: "
                                  "[exception] error reading packet (empty)")
        self.assertEqual(sshaudit.audit_failure(self.result(255), None), "exited 255")
        self.assertEqual(sshaudit.audit_failure(self.result(3, "garbage"), None),
                         "produced no parseable JSON")
        self.assertEqual(sshaudit.audit_failure(self.result(None, timed_out=True), None),
                         "timed out")
        self.assertEqual(sshaudit.audit_failure(self.result(-9), None), "killed by SIGKILL")


class TestAuthMethods(unittest.TestCase):
    def test_parses_nmap_ssh_auth_methods_output(self):
        self.assertEqual(sshaudit.parse_auth_methods(NMAP_AUTH), ["publickey", "password"])
        self.assertEqual(sshaudit.parse_auth_methods(
            "Supported authentication methods: \n    publickey\n    keyboard-interactive\n"
            "    publickey"), ["publickey", "keyboard-interactive"])
        self.assertEqual(sshaudit.parse_auth_methods("none_auth"), ["none"])
        self.assertEqual(sshaudit.parse_auth_methods(""), [])
        self.assertEqual(sshaudit.parse_auth_methods("ERROR: Script execution failed"), [])

    def test_password_offered_is_low_for_review(self):
        findings = sshaudit.parse_json(DEFAULT, "h", 22,
                                       auth_methods=sshaudit.parse_auth_methods(NMAP_AUTH))
        pw = by_tag(findings, "password-auth")
        self.assertEqual([f.severity for f in pw], ["low"])
        self.assertTrue(pw[0].review_required)
        self.assertIn("No credential was tried", pw[0].description)

    def test_none_auth_is_high(self):
        findings = sshaudit.parse_json(DEFAULT, "h", 22, auth_methods=["none"])
        self.assertIn("high", [f.severity for f in by_tag(findings, "authentication")])


class TestProbe(_Stage):
    svc = Service(host="127.0.0.1", port=2222, proto="tcp", name="ssh",
                  product="OpenSSH", version="9.6p1")

    def fake_ssh_audit(self, fixture: str, rc: int):
        (self.tmp / "out.json").write_text((FIXTURES / fixture).read_text())
        self.fake_tool("ssh-audit",
                       f'printf "%s\\n" "$@" > {self.tmp}/argv\n'
                       f"{shutil.which('cat')} {self.tmp}/out.json\nexit {rc}")

    def test_registered_after_the_banner_probe_with_the_same_matcher(self):
        names = probes.all_probe_names()
        self.assertIn("ssh", names)
        self.assertIn("ssh_audit", names)
        self.assertGreater(names.index("ssh_audit"), names.index("ssh"))
        ssh = next(p for p in probes.REGISTRY if p.name == "ssh")
        audit = next(p for p in probes.REGISTRY if p.name == "ssh_audit")
        for svc in (self.svc, Service(host="h", port=22, proto="tcp"),
                    Service(host="h", port=2200, proto="tcp", name="ssh"),
                    Service(host="h", port=22, proto="udp"),
                    Service(host="h", port=80, proto="tcp", name="http")):
            self.assertEqual(ssh.matches(svc), audit.matches(svc), svc)

    def test_completed_audit_with_failures_records_findings(self):
        self.fake_ssh_audit("ssh-audit-weak.json", 3)
        with self.only_fake_tools_on_path():
            after = self.probe(self.svc, only=["ssh_audit"])
        self.assertEqual(self.gaps(), [])
        self.assertEqual(after.probed_by, ["ssh_audit"])
        titles = [f.title for f in self.store.findings()]
        self.assertIn("SSH configuration audit of 127.0.0.1:2222 (ssh-audit)", titles)
        argv = (self.tmp / "argv").read_text().split()
        self.assertIn("--skip-rate-test", argv)
        self.assertEqual(argv[-1], "127.0.0.1:2222")
        self.assertTrue((self.store.path / "raw" / "ssh-audit-127.0.0.1-2222.stdout").exists())

    def test_auth_methods_from_nmap_reach_the_findings(self):
        self.fake_ssh_audit("ssh-audit-openssh96-default.json", 3)
        svc = Service(host="127.0.0.1", port=22, proto="tcp", name="ssh",
                      scripts={"ssh-auth-methods": NMAP_AUTH})
        with self.only_fake_tools_on_path():
            self.probe(svc, only=["ssh_audit"])
        self.assertIn("SSH password authentication offered on 127.0.0.1:22",
                      [f.title for f in self.store.findings()])

    def test_missing_ssh_audit_is_a_gap(self):
        with self.only_fake_tools_on_path():
            after = self.probe(self.svc, only=["ssh_audit"])
        self.assertEqual(self.gaps(), [("probe:ssh_audit", "ssh_audit", ["127.0.0.1"])])
        self.assertIn("ssh-audit", self.store.degradations()[0].reason)
        self.assertNotIn("ssh_audit", after.probed_by)

    def test_connection_error_is_a_gap_not_a_clean_pass(self):
        self.fake_ssh_audit("ssh-audit-lab-banner-only.json", 1)
        with self.only_fake_tools_on_path():
            after = self.probe(self.svc, only=["ssh_audit"])
        self.assertEqual(self.gaps(), [("probe:ssh_audit", "ssh_audit", ["127.0.0.1"])])
        self.assertIn("could not complete the key exchange",
                      self.store.degradations()[0].reason)
        self.assertNotIn("ssh_audit", after.probed_by)
        self.assertEqual(self.store.findings(), [])

    def test_unparseable_output_is_a_gap(self):
        self.fake_tool("ssh-audit", "echo not-json; exit 0")
        with self.only_fake_tools_on_path():
            after = self.probe(self.svc, only=["ssh_audit"])
        self.assertEqual(self.gaps(), [("probe:ssh_audit", "ssh_audit", ["127.0.0.1"])])
        self.assertNotIn("ssh_audit", after.probed_by)

    def test_timeout_comes_from_the_policy(self):
        self.policy = Policy.from_dict({"ssh_audit": {"timeout_sec": 1}})
        self.fake_tool("ssh-audit", f"exec {shutil.which('sleep')} 5")
        with self.only_fake_tools_on_path():
            after = self.probe(self.svc, only=["ssh_audit"])
        self.assertEqual(self.gaps(), [("probe:ssh_audit", "ssh_audit", ["127.0.0.1"])])
        self.assertIn("timed out", self.store.degradations()[0].reason)
        self.assertNotIn("ssh_audit", after.probed_by)

    def test_gap_clears_once_a_rerun_succeeds(self):
        with self.only_fake_tools_on_path():
            self.probe(self.svc, only=["ssh_audit"])
        self.assertEqual(len(self.gaps()), 1)
        self.fake_ssh_audit("ssh-audit-weak.json", 3)
        with self.only_fake_tools_on_path():
            after = self.probe(self.store.services()[0], only=["ssh_audit"])
        self.assertEqual(self.gaps(), [])
        self.assertEqual(after.probed_by, ["ssh_audit"])

    def test_out_of_scope_host_is_refused_before_running(self):
        self.fake_ssh_audit("ssh-audit-weak.json", 0)
        with self.only_fake_tools_on_path(), self.assertRaises(ScopeError):
            sshaudit.run(self.runner, self.scope, self.policy.ssh_audit, "192.0.2.1", 22)
        self.assertFalse((self.tmp / "argv").exists())

    def test_fixture_was_captured_with_the_adapter_argv(self):
        """Keep the documented capture command and the builder in step."""
        self.assertEqual(sshaudit.argv(Policy().ssh_audit, "127.0.0.1", 2299)[1:],
                         ["-j", "-n", "--skip-rate-test", "-t", "5", "127.0.0.1:2299"])
        self.assertEqual(json.loads(WEAK)["target"], "127.0.0.1:2299")


if __name__ == "__main__":
    unittest.main()
