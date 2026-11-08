"""testssl.sh: service matching, argv, JSON parsing, and gaps through the pipeline.

Fixtures in tests/fixtures/testssl/ are real testssl.sh 3.2.5 flat JSON
(`--jsonfile`), captured only against 127.0.0.2, re-serialised one record per
line, with the local install path in `engine_problem` replaced by
/opt/testssl.sh:

* lab-https-8443.json: the default run against the lab's 8443 (tests/lab.py).
* lab-https-8443-ids-friendly.json: `-p -s -P -f -S -h -U --ids-friendly`
  against 8443, so Heartbleed, CCS, Ticketbleed and ROBOT are absent.
* lab-mysql-3306-no-tls.json: `--starttls mysql` against the lab's MySQL
  greeting, which offers no TLS.
* closed-port.json: a closed port on 127.0.0.2.
* weak-tls-19443.json, starttls-smtp-12525.json,
  starttls-absent-smtp-12526.json: throwaway listeners on 127.0.0.2 (not
  part of tests/lab.py) with a deliberately weak TLS 1.0-1.2 context, an
  SMTP server offering STARTTLS with it, and one that does not.

Vulnerable results (Heartbleed and friends) cannot be produced by a modern
local TLS stack, so those tests edit records of a real capture into the
documented VULNERABLE form; each such test says so.
"""

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from extscan import chase, pipeline
from extscan.models import Lead, Service
from extscan.policy import Policy
from extscan.probes import ProbeContext
from extscan.runner import Runner
from extscan.scope import Authorization, Scope
from extscan.store import Store
from extscan.tools import testssl

FIXTURES = Path(__file__).parent / "fixtures"
TS = FIXTURES / "testssl"
LAB = "127.0.0.2"


def lab_scope() -> Scope:
    return Scope(engagement="t", client="c",
                 authorization=Authorization(reference="T", authorized_by="x"),
                 targets=[f"{LAB}/32"], allow_private=True)


def records(name: str) -> list[testssl.Record]:
    return testssl.load_records((TS / name).read_text())


def edited(name: str, **changes: tuple[str, str]) -> list[testssl.Record]:
    """A real capture with some records set to (severity, finding)."""
    out = records(name)
    for r in out:
        if r.id in changes:
            r.severity, r.finding = changes[r.id]
    return out


def by_tag(audit: testssl.Audit, tag: str):
    return [f for f in audit.findings if tag in f.tags]


class TestServiceMatching(unittest.TestCase):
    def mode(self, **kw):
        return testssl.tls_mode(Service(host=LAB, proto=kw.pop("proto", "tcp"), **kw))

    def test_implicit_tls(self):
        self.assertEqual(self.mode(port=8443, name="http", tunnel="ssl"), ("tls", ""))
        self.assertEqual(self.mode(port=443, name="https"), ("tls", ""))
        self.assertEqual(self.mode(port=993, name="imaps"), ("tls", ""))
        self.assertEqual(self.mode(port=465, name="smtp", tunnel="ssl"), ("tls", ""))
        self.assertEqual(self.mode(port=636, name=""), ("tls", ""))

    def test_starttls_by_nmap_name(self):
        cases = {"smtp": "smtp", "submission": "smtp", "imap": "imap", "pop3": "pop3",
                 "ftp": "ftp", "ldap": "ldap", "postgresql": "postgres",
                 "mysql": "mysql", "xmpp-client": "xmpp", "xmpp-server": "xmpp-server",
                 "nntp": "nntp", "sieve": "sieve", "lmtp": "lmtp", "telnet": "telnet"}
        for name, proto in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.mode(port=10000, name=name), ("starttls", proto))

    def test_port_is_only_a_fallback_for_nameless_services(self):
        self.assertEqual(self.mode(port=587, name=""), ("starttls", "smtp"))
        self.assertEqual(self.mode(port=5432, name="tcpwrapped"), ("starttls", "postgres"))
        self.assertIsNone(self.mode(port=25, name="http"))
        self.assertIsNone(self.mode(port=3306, name="ssh"))

    def test_unsupported_and_udp_are_not_matched(self):
        self.assertIsNone(self.mode(port=6667, name="irc"))
        self.assertIsNone(self.mode(port=22, name="ssh"))
        self.assertIsNone(self.mode(port=161, name="snmp", proto="udp"))


class TestArgv(unittest.TestCase):
    def test_shape(self):
        cmd = testssl.argv(Policy(), LAB, 8443, "/out.json")
        self.assertEqual(cmd[0], "testssl.sh")
        self.assertEqual(cmd[-1], f"{LAB}:8443")
        for flag in ("--quiet", "--warnings", "batch", "--jsonfile", "/out.json",
                     "--connect-timeout", "--openssl-timeout", "--nodns"):
            self.assertIn(flag, cmd)
        self.assertNotIn("--starttls", cmd)
        self.assertNotIn("-U", cmd)   # the default run, not a subset

    def test_starttls_and_fast(self):
        policy = Policy.from_dict({"testssl": {"fast": True}})
        cmd = testssl.argv(policy, LAB, 25, "/o.json", starttls="smtp")
        self.assertEqual(cmd[cmd.index("--starttls") + 1], "smtp")
        for flag in testssl.DEFAULT_RUN_FLAGS_FAST:
            self.assertIn(flag, cmd)
        self.assertNotIn("-c", cmd)

    def test_xmpp_keeps_dns_for_the_domain(self):
        self.assertNotIn("--nodns", testssl.argv(Policy(), LAB, 5222, "/o", "xmpp"))

    def test_ipv6_is_bracketed(self):
        self.assertEqual(testssl.argv(Policy(), "2001:db8::1", 443, "/o")[-1],
                         "[2001:db8::1]:443")

    def test_policy_values_reach_the_command(self):
        policy = Policy.from_dict({"testssl": {"connect_timeout_sec": 3,
                                               "extra_args": ["--ids-friendly"]}})
        cmd = testssl.argv(policy, LAB, 443, "/o")
        self.assertEqual(cmd[cmd.index("--connect-timeout") + 1], "3")
        self.assertEqual(cmd[-2], "--ids-friendly")
        self.assertEqual(cmd[cmd.index("--user-agent") + 1], policy.http.user_agent)


class TestParseLabHttps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = testssl.parse(records("lab-https-8443.json"), LAB, 8443,
                                  scope=lab_scope())

    def test_summary_carries_the_grade(self):
        summary = self.audit.findings[0]
        self.assertEqual(summary.title, f"TLS grade T on {LAB}:8443 (testssl.sh)")
        self.assertEqual(summary.severity, "info")
        self.assertIn("Grade capped to T", summary.evidence)
        self.assertIn("protocols offered: TLS 1.2, TLS 1.3", summary.evidence)
        self.assertIn("client simulation:", summary.evidence)
        self.assertEqual(self.audit.grade, "T")

    def test_every_named_check_ran(self):
        self.assertEqual(self.audit.gaps, [])

    def test_findings_are_grouped(self):
        titles = [f.title for f in self.audit.findings]
        self.assertEqual(len(titles), 4, titles)
        self.assertIn(f"LUCKY13: CBC timing (CVE-2013-0169) on {LAB}:8443", titles)
        self.assertEqual(len(by_tag(self.audit, "weak-cipher")), 1)
        self.assertEqual(by_tag(self.audit, "deprecated-protocol"), [])

    def test_certificate_severities_follow_extscan_scale(self):
        [cert] = by_tag(self.audit, "certificate")
        # testssl.sh: CRITICAL self-signed, HIGH expiry < 30 days, HIGH no CRL/OCSP.
        self.assertEqual(cert.severity, "low")
        self.assertTrue(cert.review_required)
        self.assertIn("self signed", cert.evidence)
        self.assertNotIn("cert_notAfter: HIGH", cert.evidence.split("\n\n")[0])

    def test_header_checks_are_left_to_http_fingerprint(self):
        self.assertFalse(any("HSTS" in f.title or "header" in f.title.lower()
                             for f in self.audit.findings))

    def test_every_finding_is_attributed(self):
        for f in self.audit.findings:
            self.assertEqual((f.host, f.port, f.source), (LAB, 8443, "testssl.sh"))
            self.assertIn("testssl", f.tags)


class TestParseWeakTls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = testssl.parse(records("weak-tls-19443.json"), LAB, 19443)

    def test_deprecated_protocols_are_medium(self):
        [proto] = by_tag(self.audit, "deprecated-protocol")
        self.assertEqual(proto.severity, "medium")   # testssl.sh says LOW
        self.assertIn("TLS 1.0 offered", proto.title)
        self.assertIn("TLS 1.1 offered", proto.title)

    def test_anonymous_suites_are_high_like_sslscan(self):
        [ciphers] = by_tag(self.audit, "weak-cipher")
        self.assertEqual(ciphers.severity, "high")   # testssl.sh says CRITICAL
        self.assertIn("anonymous key exchange", ciphers.title)
        self.assertIn("AECDH-AES256-SHA", ciphers.evidence)

    def test_beast_keeps_the_headline_verdict(self):
        [beast] = [f for f in self.audit.findings if f.title.startswith("BEAST")]
        self.assertEqual(beast.severity, "low")      # "likely mitigated"
        self.assertIn("BEAST_CBC_TLS1", beast.evidence)
        self.assertEqual(beast.references,
                         ["https://nvd.nist.gov/vuln/detail/CVE-2011-3389"])


class TestParseGaps(unittest.TestCase):
    def test_ids_friendly_skips_are_gaps_not_passes(self):
        audit = testssl.parse(records("lab-https-8443-ids-friendly.json"), LAB, 8443)
        self.assertEqual(sorted(g for g, _w in audit.gaps),
                         ["CCS", "ROBOT", "heartbleed", "ticketbleed"])
        self.assertIn("checks that did not complete", audit.findings[0].evidence)

    def test_warn_on_a_check_is_a_gap_and_no_finding(self):
        audit = testssl.parse(edited("lab-https-8443.json", secure_renego=(
            "WARN", "OpenSSL handshake didn't succeed")), LAB, 8443)
        self.assertEqual(audit.gaps, [("secure_renego", "OpenSSL handshake didn't succeed")])
        self.assertFalse(any("renegotiation" in f.title.lower() for f in audit.findings))

    def test_missing_socat_is_a_gap_for_starttls_injection(self):
        # The record testssl.sh 3.2.5 writes without socat, as captured.
        audit = testssl.parse(edited("starttls-smtp-12525.json", starttls_injection=(
            "WARN", "Need socat for this")), LAB, 12525, starttls="smtp")
        self.assertEqual(audit.gaps, [("starttls_injection", "Need socat for this")])

    def test_run_level_notices_are_not_gaps(self):
        audit = testssl.parse(records("lab-https-8443.json"), LAB, 8443)
        self.assertNotIn("engine_problem", [g for g, _w in audit.gaps])
        self.assertIn("Target is not a server name", audit.findings[0].evidence)


class TestParseVulnerable(unittest.TestCase):
    """Records edited into testssl.sh's VULNERABLE form (see module docstring)."""

    @classmethod
    def setUpClass(cls):
        cls.audit = testssl.parse(edited(
            "lab-https-8443.json",
            heartbleed=("CRITICAL", "VULNERABLE (NOT ok)"),
            ROBOT=("HIGH", "VULNERABLE (NOT ok)"),
            secure_client_renego=("HIGH", "VULNERABLE, DoS threat"),
            SWEET32=("LOW", "uses 64 bit block ciphers"),
            TLS1=("LOW", "offered (deprecated)"),
        ), LAB, 8443)
        cls.titles = {f.title.split(" on ")[0]: f for f in cls.audit.findings}

    def test_one_finding_per_vulnerable_check(self):
        for label in ("Heartbleed (CVE-2014-0160)", "ROBOT (Bleichenbacher oracle)",
                      "Client-initiated renegotiation allowed (CVE-2011-1473)",
                      "SWEET32: 64-bit block ciphers (CVE-2016-2183)"):
            self.assertIn(label, self.titles)

    def test_severity_and_review(self):
        hb = self.titles["Heartbleed (CVE-2014-0160)"]
        self.assertEqual(hb.severity, "critical")
        self.assertTrue(hb.review_required)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2014-0160", hb.references)
        sweet = self.titles["SWEET32: 64-bit block ciphers (CVE-2016-2183)"]
        self.assertEqual(sweet.severity, "low")
        self.assertFalse(sweet.review_required)

    def test_tls10_override(self):
        [proto] = by_tag(self.audit, "deprecated-protocol")
        self.assertEqual(proto.severity, "medium")


class TestParseStarttls(unittest.TestCase):
    def test_smtp_audit(self):
        audit = testssl.parse(records("starttls-smtp-12525.json"), LAB, 12525,
                              starttls="smtp")
        self.assertEqual(audit.gaps, [])  # no Ticketbleed/BREACH expected off HTTP
        self.assertTrue(all("starttls:smtp" in f.tags for f in audit.findings))
        self.assertIn("(STARTTLS smtp)", audit.findings[0].evidence)
        self.assertTrue(by_tag(audit, "deprecated-protocol"))

    def test_no_starttls_offered_is_a_finding(self):
        audit = testssl.parse(records("starttls-absent-smtp-12526.json"), LAB, 12526,
                              starttls="smtp")
        [f] = audit.findings
        self.assertEqual(f.title, f"SMTP on {LAB}:12526 does not offer STARTTLS")
        self.assertEqual((f.severity, f.confidence), ("medium", "tentative"))
        self.assertTrue(f.review_required)
        self.assertIn("No STARTTLS found", f.evidence)

    def test_mysql_without_tls(self):
        audit = testssl.parse(records("lab-mysql-3306-no-tls.json"), LAB, 3306,
                              starttls="mysql")
        self.assertEqual(audit.findings[0].title,
                         f"MYSQL on {LAB}:3306 does not offer STARTTLS")


class TestParseFailures(unittest.TestCase):
    def test_no_tls_on_a_tls_service_is_a_failure(self):
        with self.assertRaises(testssl.ScanFailed):
            testssl.parse(records("lab-mysql-3306-no-tls.json"), LAB, 3306)

    def test_unreachable_is_a_failure(self):
        with self.assertRaisesRegex(testssl.ScanFailed, "Can't connect"):
            testssl.parse(records("closed-port.json"), LAB, 1)

    def test_interrupted_scan_is_a_failure(self):
        recs = records("lab-https-8443.json")
        recs.append(testssl.Record("scanTime", "WARN", "Scan interrupted"))
        with self.assertRaisesRegex(testssl.ScanFailed, "interrupted"):
            testssl.parse(recs, LAB, 8443)

    def test_no_protocol_results_is_a_failure(self):
        recs = [r for r in records("lab-https-8443.json") if r.id not in
                testssl.PROTOCOL_LABELS]
        with self.assertRaises(testssl.ScanFailed):
            testssl.parse(recs, LAB, 8443)

    def test_out_of_scope_records_are_dropped(self):
        scope = Scope(engagement="t", client="c",
                      authorization=Authorization(reference="T", authorized_by="x"),
                      targets=["192.0.2.0/24"])
        with self.assertRaises(testssl.ScanFailed):
            testssl.parse(records("lab-https-8443.json"), LAB, 8443, scope=scope)

    def test_garbage_json(self):
        text = (TS / "lab-https-8443.json").read_text()
        for bad in (text[: len(text) // 2], "{}", "", "\x00"):
            with self.subTest(bad=bad[:20]), self.assertRaises(ValueError):
                testssl.load_records(bad)
        self.assertEqual(testssl.load_records('[1, {"x": 2}, {"id": "TLS1"}]')[0].id,
                         "TLS1")


# ---------------------------------------------------------------------------
# Through the pipeline, with a fake testssl.sh on PATH
# ---------------------------------------------------------------------------

def _copy_after(flag: str, fixture: Path) -> str:
    return ('while [ $# -gt 0 ]; do [ "$1" = ' + flag + ' ] && '
            f'/bin/cp {fixture} "$2"; shift; done')


class _Stage(unittest.TestCase):
    svc = Service(host=LAB, port=8443, proto="tcp", name="http", tunnel="ssl")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.scope = lab_scope()
        self.store = Store.create(self.tmp / "runs", "t", run_id="r")
        self.store.write_meta({"run_id": "r"})
        self.runner = Runner(self.store)
        self.policy = Policy()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake(self, name: str, script: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{script}\n")
        path.chmod(0o755)

    def fake_testssl(self, fixture: str, rc: int = 0) -> None:
        self.fake("testssl.sh", f"{_copy_after('--jsonfile', TS / fixture)}; exit {rc}")

    def path_env(self, **extra):
        return mock.patch.dict(os.environ, {"PATH": str(self.bin), **extra})

    def probe(self, only, svc=None, force=False):
        self.store.save_services([svc or self.svc])
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.probe(self.store, self.scope, self.policy, self.runner,
                           only=only, force=force)
        return self.store.services()[0]

    def gaps(self):
        return [(d.stage, d.component) for d in self.store.degradations()]

    def stages_run(self):
        return [c["stage"] for c in self.store.commands()]


class TestProbe(_Stage):
    def test_clean_run_marks_the_service_and_skips_sslscan(self):
        self.fake_testssl("lab-https-8443.json")
        self.fake("sslscan", "exit 1")
        with self.path_env():
            svc = self.probe(["testssl", "sslscan"])
        self.assertEqual(self.gaps(), [])
        self.assertEqual(sorted(svc.probed_by), ["sslscan", "testssl"])
        self.assertEqual(self.stages_run(), ["probe:testssl"])
        titles = [f.title for f in self.store.findings()]
        self.assertIn(f"TLS grade T on {LAB}:8443 (testssl.sh)", titles)
        self.assertTrue((self.store.raw / f"testssl-{LAB}-8443.json").is_file())

    def test_ambiguous_exit_code_with_results_is_not_a_failure(self):
        self.fake_testssl("starttls-smtp-12525.json", rc=8)
        smtp = Service(host=LAB, port=12525, proto="tcp", name="smtp")
        with self.path_env():
            svc = self.probe(["testssl"], svc=smtp)
        self.assertEqual(self.gaps(), [])
        self.assertIn("testssl", svc.probed_by)
        argv = self.store.commands()[0]["argv"]
        self.assertEqual(argv[argv.index("--starttls") + 1], "smtp")

    def test_missing_testssl_falls_back_to_sslscan_and_is_a_gap(self):
        self.fake("sslscan", "for a in \"$@\"; do case $a in --xml=*) "
                             f"/bin/cp {FIXTURES / 'sslscan.xml'} \"${{a#--xml=}}\";; "
                             "esac; done; exit 0")
        with self.path_env():
            svc = self.probe(["testssl", "sslscan"])
        self.assertEqual(self.gaps(), [("probe:testssl", "testssl")])
        self.assertIn("named TLS vulnerability checks did not run",
                      self.store.degradations()[0].reason)
        self.assertEqual(svc.probed_by, ["sslscan"])
        self.assertEqual(self.stages_run(), ["probe:sslscan"])

    def test_both_missing_are_two_gaps(self):
        with self.path_env():
            svc = self.probe(["testssl", "sslscan"])
        self.assertEqual(sorted(self.gaps()), [("probe:sslscan", "sslscan"),
                                               ("probe:testssl", "testssl")])
        self.assertEqual(svc.probed_by, [])

    def test_missing_testssl_on_starttls_names_the_protocol(self):
        with self.path_env():
            self.probe(["testssl"], svc=Service(host=LAB, port=143, proto="tcp",
                                                name="imap"))
        self.assertIn("STARTTLS (imap)", self.store.degradations()[0].reason)

    def test_failures_are_gaps_and_stay_unprobed(self):
        timeout = Policy.from_dict({"testssl": {"timeout_sec": 1}})
        cases = {
            "no json": ("exit 1", None),
            "killed": (f"{_copy_after('--jsonfile', TS / 'lab-https-8443.json')}; "
                       "kill -9 $$", None),
            "timeout": (f"exec {shutil.which('sleep')} 5", timeout),
            "unreachable": (_copy_after("--jsonfile", TS / "closed-port.json")
                            + "; exit 246", None),
            "garbled": ("while [ $# -gt 0 ]; do [ \"$1\" = --jsonfile ] && "
                        "printf '[{' > \"$2\"; shift; done", None),
        }
        for label, (script, policy) in cases.items():
            with self.subTest(label):
                self.tearDown()
                self.setUp()
                if policy:
                    self.policy = policy
                self.fake("testssl.sh", script)
                with self.path_env():
                    svc = self.probe(["testssl"])
                self.assertEqual(self.gaps(), [("probe:testssl", "testssl")])
                self.assertNotIn("testssl", svc.probed_by)
                self.assertEqual(self.store.findings(), [])

    def test_stale_json_from_an_earlier_attempt_is_not_reused(self):
        self.store.write_raw(f"testssl-{LAB}-8443.json",
                             (TS / "lab-https-8443.json").read_text())
        self.fake("testssl.sh", "exit 1")
        with self.path_env():
            svc = self.probe(["testssl"])
        self.assertNotIn("testssl", svc.probed_by)

    def test_partial_run_keeps_findings_records_a_gap_and_clears_on_rerun(self):
        self.fake_testssl("lab-https-8443-ids-friendly.json")
        with self.path_env():
            svc = self.probe(["testssl"])
        self.assertEqual(self.gaps(), [(testssl.GAP_STAGE, "testssl.sh")])
        gap = self.store.degradations()[0]
        for check in ("heartbleed", "CCS", "ticketbleed", "ROBOT"):
            self.assertIn(check, gap.impact)
        self.assertIn("unknown, not clean", gap.impact)
        self.assertIn("testssl", svc.probed_by)
        self.assertTrue(self.store.findings())

        self.fake_testssl("lab-https-8443.json")
        with self.path_env():
            self.probe(["testssl"], svc=svc, force=True)
        self.assertEqual(self.gaps(), [])

    def test_child_environment_is_minimal_with_phone_out_pinned_off(self):
        dump = self.tmp / "env.txt"
        self.fake("testssl.sh", f"/usr/bin/env > {dump}; "
                                f"{_copy_after('--jsonfile', TS / 'lab-https-8443.json')}")
        with self.path_env(PHONE_OUT="true", FNAME="targets.txt", BASICAUTH="u:p",
                           SSL_NATIVE="true"):
            self.probe(["testssl"])
        env = dict(line.split("=", 1) for line in dump.read_text().splitlines()
                   if "=" in line)
        self.assertEqual(env.get("PHONE_OUT"), "false")
        for leaked in ("FNAME", "BASICAUTH", "SSL_NATIVE"):
            self.assertNotIn(leaked, env)
        self.assertEqual(env["PATH"], str(self.bin))

    def test_dry_run_runs_nothing(self):
        self.runner = Runner(self.store, dry_run=True)
        with self.path_env(), contextlib.redirect_stdout(io.StringIO()):
            svc = self.probe(["testssl"])
        self.assertEqual(self.gaps(), [])
        self.assertEqual(self.store.findings(), [])
        self.assertIn("testssl", svc.probed_by)


class TestTlsProbeNoLongerEmitsTlsDetail(unittest.TestCase):
    def test_source(self):
        source = (Path(__file__).parent.parent / "extscan" / "probes.py").read_text()
        self.assertNotIn('kind="tls_detail"', source)


class TestTlsDetailLeadInOldRuns(_Stage):
    lead = Lead(kind="tls_detail", host=LAB, port=8443, params={"untested": ["SSLv3"]})

    def chase(self):
        ctx = ProbeContext(scope=self.scope, policy=self.policy, runner=self.runner)
        return chase.chase(ctx, self.lead)

    def test_superseded_when_the_probe_already_ran(self):
        self.store.save_services([Service(**{**self.svc.to_dict(),
                                             "probed_by": ["testssl"]})])
        with self.path_env():
            result = self.chase()
        self.assertTrue(result.note.startswith("superseded"))
        self.assertEqual(self.stages_run(), [])

    def test_runs_the_audit_and_marks_the_service(self):
        self.store.save_services([self.svc])
        self.fake_testssl("lab-https-8443.json")
        with self.path_env():
            result = self.chase()
        self.assertTrue(result.findings)
        self.assertEqual(self.stages_run(), ["chase:tls_detail"])
        self.assertIn("testssl", self.store.services()[0].probed_by)

    def test_missing_testssl_fails_the_lead_visibly(self):
        self.store.save_services([self.svc])
        with self.path_env():
            result = self.chase()
        self.assertTrue(result.note.startswith("handler error"))
        self.assertIn("testssl.sh not installed", result.note)


if __name__ == "__main__":
    unittest.main()
