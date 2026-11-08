"""`extscan diff`: comparing two runs without letting a coverage gap read as a fix.

The old run is the committed lab run. The new run is a copy of it, edited the
way a retest would change it: a port opened, one closed, a finding fixed, a
nuclei title reworded, a version bumped, and checks lost to coverage gaps.
"""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from extscan import cli, diff
from extscan.models import Finding, issue_key_for
from extscan.store import Store

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "lab-run"
HOST = "127.0.0.2"


def _edit(path: Path, name: str, fn):
    data = json.loads((path / name).read_text())
    data = fn(data)
    (path / name).write_text(json.dumps(data, indent=2))


def _drop(findings, pred):
    kept = [f for f in findings if not pred(f)]
    assert len(kept) < len(findings), "the edit matched no finding"
    return kept


class DiffFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.old = self.tmp / "old-run"
        self.new = self.tmp / "new-run"
        shutil.copytree(FIXTURE, self.old)
        shutil.copytree(FIXTURE, self.new)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def compare(self):
        return diff.compare(Store(self.old), Store(self.new))


class TestIssueKey(unittest.TestCase):
    def test_reworded_nuclei_title_keeps_the_key_but_not_the_id(self):
        a = Finding(title="Redis Server - Unauthenticated Access", host=HOST, port=6379,
                    source="nuclei:exposed-redis")
        b = Finding(title="Redis - Unauthenticated Access Detected", host=HOST, port=6379,
                    source="nuclei:exposed-redis")
        self.assertNotEqual(a.id, b.id)
        self.assertEqual(a.issue_key, b.issue_key)
        self.assertEqual(a.check_id, "nuclei:exposed-redis")

    def test_key_separates_host_port_proto_and_check(self):
        base = {"title": "x", "host": HOST, "port": 80, "source": "nuclei:a"}
        key = Finding(**base).issue_key
        for change in ({"host": "127.0.0.3"}, {"port": 81}, {"proto": "udp"},
                       {"source": "nuclei:b"}):
            self.assertNotEqual(key, Finding(**{**base, **change}).issue_key, change)

    def test_severity_is_not_part_of_the_key(self):
        a = Finding(title="x", host=HOST, port=80, source="nuclei:a", severity="low")
        b = Finding(title="x", host=HOST, port=80, source="nuclei:a", severity="high")
        self.assertEqual(a.issue_key, b.issue_key)

    def test_nse_script_id_is_the_check_for_both_nmap_passes(self):
        tcp = Finding(title="nmap host script: fcrdns", host=HOST, source="nmap-tcp:fcrdns")
        udp = Finding(title="nmap host script: fcrdns", host=HOST, source="nmap-udp:fcrdns")
        self.assertEqual(tcp.check_id, "nmap:fcrdns")
        self.assertEqual(tcp.issue_key, udp.issue_key)

    def test_volatile_title_parts_do_not_change_the_key(self):
        pairs = [
            ("HTTP service: ACME Billing on 1.2.3.4:8080", "HTTP service: Intranet on 1.2.3.4:8080",
             "extscan:http"),
            ("Exposed API specification: ACME API (9 operations)",
             "Exposed API specification: Billing (12 operations)", "extscan:openapi"),
            ("Deprecated TLS/SSL protocols accepted on 1.2.3.4:443: TLSv1.0, TLSv1.1",
             "Deprecated TLS/SSL protocols accepted on 1.2.3.4:443: TLSv1.0", "sslscan"),
            ("TLS endpoint 1.2.3.4:443 (TLSv1.2)", "TLS endpoint 1.2.3.4:443 (TLSv1.3)",
             "extscan:tls"),
            ("Content review: http://1.2.3.4:8080/metrics",
             "Content review: https://1.2.3.4:8080/metrics", "extscan:web_paths"),
        ]
        for a, b, src in pairs:
            fa = Finding(title=a, host="1.2.3.4", port=8080, source=src)
            fb = Finding(title=b, host="1.2.3.4", port=8080, source=src)
            self.assertEqual(fa.issue_key, fb.issue_key, (a, b))

    def test_different_paths_are_different_issues(self):
        a = Finding(title="Content review: http://1.2.3.4/metrics", host="1.2.3.4", port=80,
                    source="extscan:web_paths")
        b = Finding(title="Content review: http://1.2.3.4/robots.txt", host="1.2.3.4", port=80,
                    source="extscan:web_paths")
        self.assertNotEqual(a.issue_key, b.issue_key)

    def test_old_findings_without_a_key_get_one_on_load(self):
        raw = json.loads((FIXTURE / "findings.json").read_text())
        self.assertNotIn("issue_key", raw[0])
        f = Finding.from_dict(raw[0])
        self.assertEqual(f.issue_key, issue_key_for(f))
        self.assertEqual(f.id, raw[0]["id"])
        self.assertIn("issue_key", f.to_dict())
        self.assertEqual(Finding.from_dict(f.to_dict()).issue_key, f.issue_key)


class TestIdenticalRuns(DiffFixture):
    def test_a_run_against_its_copy_shows_no_change(self):
        s = self.compare()["summary"]
        self.assertEqual(s["findings_new"] + s["findings_resolved"]
                         + s["findings_not_reobserved"], 0)
        self.assertEqual(s["services_new"] + s["services_closed"] + s["services_changed"], 0)
        self.assertEqual(s["findings_still_open"], len({
            issue_key_for(f) for f in Store(self.old).findings()}))
        self.assertEqual(s["gaps_still_open"], 1)


class TestRetest(DiffFixture):
    """One edited copy of the lab run covering every diff state."""

    def setUp(self):
        super().setUp()

        def services(data):
            for s in data:
                if s["port"] == 8080:
                    s["version"] = "1.24.0"
                if s["port"] == 8443:
                    s["probed_by"].remove("tls")       # the tls probe failed
            data = [s for s in data if s["port"] not in (2222, 10161)]
            data.append({"host": HOST, "port": 5432, "proto": "tcp", "name": "postgresql",
                         "product": "PostgreSQL DB", "version": "16.1",
                         "probed_by": ["exposure"]})
            return data
        _edit(self.new, "services.json", services)

        def findings(data):
            # Fixed: /metrics no longer served on 8080.
            data = _drop(data, lambda f: f["source"] == "extscan:paths" and f["port"] == 8080
                         and f["title"].startswith("Exposed /metrics"))
            # Gone with the closed SSH port.
            data = _drop(data, lambda f: f["port"] == 2222)
            # Lost to the tls probe failure, not fixed.
            data = _drop(data, lambda f: f["source"] == "extscan:tls"
                         and f["title"].startswith("Self-signed"))
            # Lost with the UDP pass.
            data = _drop(data, lambda f: f["proto"] == "udp" or f["source"].startswith("nmap-udp"))
            for f in data:
                if f["source"] == "nuclei:exposed-redis":
                    f["title"] = "Redis - Unauthenticated Access Detected"
                    del f["id"]                          # recomputed from the new title
                if f["source"] == "nuclei:elasticsearch":
                    f["severity"] = "medium"
            data.append(Finding(title="PostgreSQL reachable from the internet on "
                                      f"{HOST}:5432/tcp", severity="high", host=HOST,
                                port=5432, source="extscan:exposure").to_dict())
            return data
        _edit(self.new, "findings.json", findings)

        def degradations(data):
            return [
                *data,
                {"stage": "probe:tls", "component": "tls",
                 "reason": f"{HOST}/tcp/8443: TimeoutError: handshake timed out",
                 "impact": "The tls check did not run on 127.0.0.2/tcp/8443.",
                 "hosts": [HOST]},
                {"stage": "discover:udp", "component": "nmap",
                 "reason": "nmap -sU requires root and the run is unprivileged",
                 "impact": "No UDP scanning was performed.", "severity": "serious"},
            ]
        _edit(self.new, "degradations.json", degradations)

        def meta(m):
            m["run_id"] = "new-run"
            m["created"] += 86400 * 90
            m["policy"]["nmap"]["tcp_ports"] += ",5432"
            del m["stages"]["discover"]["udp"]
            return m
        _edit(self.new, "run.json", meta)
        self.result = self.compare()

    def keys(self, section, status):
        return self.result[section][status]

    def find(self, status, pred):
        return [e for e in self.result["findings"][status] if pred(e)]

    def test_new_port_is_a_new_service_with_its_finding(self):
        new = self.keys("services", "new")
        self.assertEqual([e["id"] for e in new], [f"{HOST}/tcp/5432"])
        self.assertTrue(self.find("new", lambda e: e["port"] == 5432))

    def test_fixed_finding_is_resolved(self):
        hit = self.find("resolved", lambda e: e["port"] == 8080 and "/metrics" in e["title"]
                        and e["sources"] == ["extscan:paths"])
        self.assertEqual(len(hit), 1)
        self.assertNotIn("note", hit[0])

    def test_closed_port_closes_the_service_and_resolves_its_findings(self):
        self.assertEqual([e["id"] for e in self.keys("services", "closed")], [f"{HOST}/tcp/2222"])
        ssh = self.find("resolved", lambda e: e["port"] == 2222)
        self.assertTrue(ssh)
        self.assertTrue(all(e["note"] == "the service is no longer open" for e in ssh))

    def test_reworded_title_is_still_the_same_issue(self):
        hit = self.find("still_open", lambda e: e["check"] == "nuclei:exposed-redis")
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["old_title"], "Redis Server - Unauthenticated Access")
        self.assertFalse(self.find("new", lambda e: e["check"] == "nuclei:exposed-redis"))
        self.assertFalse(self.find("resolved", lambda e: e["check"] == "nuclei:exposed-redis"))

    def test_finding_lost_to_a_degradation_is_not_reobserved(self):
        self.assertFalse(self.find("resolved", lambda e: e["sources"] == ["extscan:tls"]))
        hit = self.find("not_reobserved", lambda e: e["sources"] == ["extscan:tls"])
        self.assertEqual(len(hit), 1)
        self.assertIn("probe:tls", hit[0]["reason"])

    def test_udp_gap_keeps_snmp_open_rather_than_closed(self):
        self.assertFalse([e for e in self.keys("services", "closed") if e["proto"] == "udp"])
        udp = self.keys("services", "not_reobserved")
        self.assertEqual([e["id"] for e in udp], [f"{HOST}/udp/10161"])
        self.assertIn("UDP", udp[0]["reason"])
        snmp = self.find("not_reobserved", lambda e: e["proto"] == "udp")
        self.assertTrue(snmp)
        self.assertFalse(self.find("resolved", lambda e: e["proto"] == "udp"))
        # Host scripts from the UDP pass were also seen by the TCP pass.
        self.assertFalse(self.find("resolved", lambda e: e["check"] == "nmap:fcrdns"))

    def test_version_change_is_reported(self):
        changed = {e["id"]: e["changes"] for e in self.keys("services", "changed")}
        self.assertEqual(changed, {f"{HOST}/tcp/8080": {"version": ["1.18.0", "1.24.0"]}})

    def test_severity_change_is_reported(self):
        hit = [e for e in self.result["findings"]["severity_changed"]
               if e["check"] == "nuclei:elasticsearch"]
        self.assertEqual(len(hit), 1)
        self.assertEqual((hit[0]["old_severity"], hit[0]["severity"]), ("low", "medium"))

    def test_coverage_gap_changes(self):
        new = {(g["stage"], g["component"]) for g in self.keys("coverage_gaps", "new")}
        self.assertEqual(new, {("probe:tls", "tls"), ("discover:udp", "nmap")})
        self.assertEqual(len(self.keys("coverage_gaps", "still_open")), 1)

    def test_policy_change_is_a_warning(self):
        keys = [c["key"] for c in self.result["policy_changes"]]
        self.assertEqual(keys, ["nmap.tcp_ports"])
        self.assertTrue(any("different policies" in w for w in self.result["warnings"]))

    def test_nothing_claimed_resolved_is_behind_a_gap(self):
        for e in self.result["findings"]["resolved"]:
            self.assertNotEqual(e["proto"], "udp", e)
            self.assertFalse(e["port"] == 8443 and e["sources"] == ["extscan:tls"], e)

    def test_markdown_and_json_are_written_to_the_new_run(self):
        md, js = diff.write(Store(self.new), self.result)
        self.assertEqual(md, self.new / "diff-old-run.md")
        text = md.read_text()
        for heading in ("## Summary", "### New services", "### Closed services",
                        "### Not re-observed (coverage gap)", "### Changed product or version",
                        "### Severity changed", "### Resolved", "## Coverage gaps"):
            self.assertIn(heading, text)
        self.assertIn("(was: Redis Server - Unauthenticated Access)", text)
        self.assertEqual(json.loads(js.read_text())["summary"], self.result["summary"])


class TestScopeChange(DiffFixture):
    def test_hosts_outside_the_new_scope_are_not_claimed_closed(self):
        def meta(m):
            m["scope"]["targets"] = ["127.0.0.3/32"]
            return m
        _edit(self.new, "run.json", meta)
        _edit(self.new, "services.json", lambda d: [])
        _edit(self.new, "findings.json", lambda d: [])
        r = self.compare()
        s = r["summary"]
        self.assertEqual(s["services_closed"] + s["findings_resolved"], 0)
        self.assertEqual(s["services_outside_overlap"], 9)
        self.assertGreater(s["findings_outside_overlap"], 100)
        self.assertIn("targets", r["scope_changes"])
        self.assertTrue(any("different scopes" in w for w in r["warnings"]))

    def test_unprobed_new_run_resolves_nothing(self):
        """A new run that stopped after discovery fixes nothing."""
        def meta(m):
            for stage in ("probe", "chase", "report"):
                del m["stages"][stage]
            return m
        _edit(self.new, "run.json", meta)
        _edit(self.new, "findings.json",
              lambda d: [f for f in d if f["source"].startswith("nmap")])
        _edit(self.new, "services.json",
              lambda d: [{**s, "probed_by": []} for s in d])
        s = self.compare()["summary"]
        self.assertEqual(s["findings_resolved"], 0)
        self.assertGreater(s["findings_not_reobserved"], 50)


class TestCli(DiffFixture):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["--runs-dir", str(self.tmp), *argv])
        return rc, out.getvalue(), err.getvalue()

    def test_diff_by_run_id_writes_reports_and_exits_zero(self):
        _edit(self.new, "findings.json", lambda d: [*d, Finding(
            title="New thing", host=HOST, port=8080, source="nuclei:new-thing").to_dict()])
        rc, out, _ = self.run_cli("diff", "old-run", "new-run")
        self.assertEqual(rc, 0)
        self.assertIn("1 new", out)
        self.assertTrue((self.new / "diff-old-run.md").exists())
        self.assertTrue((self.new / "diff-old-run.json").exists())
        rc, _, _ = self.run_cli("diff", "old-run", "new-run", "--fail-on-new")
        self.assertEqual(rc, 1)

    def test_fail_on_new_passes_when_nothing_is_new(self):
        rc, _, _ = self.run_cli("diff", str(self.old), str(self.new), "--fail-on-new")
        self.assertEqual(rc, 0)

    def test_json_output(self):
        rc, out, _ = self.run_cli("--json", "diff", "old-run", "new-run")
        self.assertEqual(rc, 0)
        self.assertIn("summary", json.loads(out))

    def test_invalid_arguments_exit_two(self):
        self.assertEqual(self.run_cli("diff", "old-run", "old-run")[0], 2)
        self.assertEqual(self.run_cli("diff", "old-run", "no-such-run")[0], 2)
        self.assertEqual(self.run_cli("diff", "old-run", "../bad id")[0], 2)


if __name__ == "__main__":
    unittest.main()
