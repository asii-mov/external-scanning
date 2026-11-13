"""Run-to-run diff: five states, and "gone" only when the new run looked.

The pair of runs is planted by evals/diff.py from a copy of the committed
lab fixture. The fixture itself is never written to.
"""

import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from evals import diff as planted

from extscan import cli
from extscan.diff import SOURCE_CHECKS, check_for, diff_runs, render_markdown
from extscan.models import Finding, Lead
from extscan.probes import all_probe_names
from extscan.resilience import Degradation
from extscan.store import Store
from extscan.triage import diff_key, issue_key

LAB = planted.LAB


def _fixture_digest() -> str:
    h = hashlib.sha256()
    for p in sorted(planted.FIXTURE.rglob("*")):
        if p.is_file():
            h.update(p.name.encode() + p.read_bytes())
    return h.hexdigest()


class _Pair(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.old, self.new = planted.build_pair(self.tmp)

    def diff(self) -> dict:
        return diff_runs(self.old, self.new)

    def state(self, result, host, port, title) -> dict:
        return planted.states_of(result, {"host": host, "port": port, "title": title})

    def drop(self, store: Store, title_start: str) -> Finding:
        findings = store.findings()
        hit = next(f for f in findings if f.title.startswith(title_start))
        store.replace_findings([f for f in findings if f.id != hit.id])
        return hit


class TestPlantedPair(_Pair):
    def test_every_planted_transition(self):
        result = self.diff()
        for case in planted.PLANTED:
            with self.subTest(case=case["id"]):
                self.assertEqual(planted.judge(result, case), "")

    def test_all_five_states_occur(self):
        counts = self.diff()["counts"]
        for state in ("new", "changed", "same", "gone", "not_rechecked"):
            self.assertGreater(counts["findings"][state], 0, state)
        for state in ("opened", "closed", "not_rescanned", "changed", "same"):
            self.assertGreater(counts["services"][state], 0, state)

    def test_title_that_moved_by_a_count_or_version_is_one_finding(self):
        result = self.diff()
        for title in (r"API operation\(s\) declare", r"^TLS endpoint", r"^HTTP service: ACME"):
            states = set()
            for port in (8080, 8443):
                states |= set(self.state(result, LAB, port, title))
            self.assertEqual(states, {"changed"}, title)
        tls = self.state(result, LAB, 8443, r"^TLS endpoint")["changed"][0]
        self.assertEqual(tls["changes"]["version"],
                         [f"TLS endpoint {LAB}:8443 (TLSv1.3)", f"TLS endpoint {LAB}:8443 (TLSv1.2)"])

    def test_finding_missing_behind_a_nuclei_gap_is_not_rechecked(self):
        result = self.diff()
        hit = self.state(result, LAB, 8080, r"^Generic Env File Disclosure")
        self.assertEqual(list(hit), ["not_rechecked"])
        self.assertIn("nuclei", hit["not_rechecked"][0]["reason"])
        # No nuclei finding on a port that is still open may be called gone.
        open_ports = {s.port for s in self.new.services() if s.host == LAB}
        self.assertEqual([r["title"] for r in result["findings"]["gone"]
                          if r["source"].startswith("nuclei") and r["host"] == LAB
                          and r["port"] in open_ports], [])

    def test_gap_alone_is_enough_even_when_probed_by_still_lists_nuclei(self):
        """A failed re-run leaves `nuclei` in probed_by from the first pass."""
        planted._rewrite(self.new, "services.json", lambda rows: [
            {**s, "probed_by": sorted({*s["probed_by"], "nuclei"})} if s["host"] == LAB else s
            for s in rows])
        hit = self.state(self.diff(), LAB, 8080, r"^Generic Env File Disclosure")
        self.assertEqual(list(hit), ["not_rechecked"])

    def test_finding_missing_after_a_clean_recheck_is_gone(self):
        result = self.diff()
        self.assertEqual(list(self.state(result, LAB, 8081, r"^Verbose ASP\.NET")), ["gone"])
        # nuclei failed on the lab host only: elsewhere its silence counts.
        self.assertEqual(list(self.state(result, planted.STAYS, 443, r"Path Traversal")),
                         ["gone"])

    def test_host_dropped_from_scope_is_not_rechecked(self):
        result = self.diff()
        hit = self.state(result, planted.DESCOPED, 22, r"^SSH service")
        self.assertEqual(list(hit), ["not_rechecked"])
        self.assertIn("scope", hit["not_rechecked"][0]["reason"])
        svc = planted.states_of(result, {"service": (planted.DESCOPED, "tcp", 22)})
        self.assertEqual(list(svc), ["not_rescanned"])

    def test_closed_port_needs_the_port_to_have_been_scanned(self):
        result = self.diff()
        self.assertEqual(list(planted.states_of(result, {"service": (LAB, "tcp", 3306)})),
                         ["closed"])
        hit = planted.states_of(result, {"service": (planted.STAYS, "tcp", 8888)})
        self.assertIn("port list", hit["not_rescanned"][0]["reason"])

    def test_output_is_ordered_for_a_person(self):
        result = self.diff()
        text = render_markdown(result)
        order = [text.index(h) for h in ("## New findings", "## Changed findings",
                                         "## Not re-checked", "## Gone", "## Services")]
        self.assertEqual(order, sorted(order))
        self.assertLess(text.index("| Not re-checked | "), text.index("## New findings"))
        self.assertIn("They are not resolved", text)
        ranks = ["critical", "high", "medium", "low", "info"]
        for state in ("new", "not_rechecked", "gone"):
            seen = [ranks.index(r["severity"]) for r in result["findings"][state]]
            self.assertEqual(seen, sorted(seen), state)
        self.assertTrue(all(r["reason"] for r in result["findings"]["not_rechecked"]))

    def test_new_finding_says_when_the_old_run_could_not_have_seen_it(self):
        # Port 9000 was not in the old run's port list.
        self.new.add_findings([Finding(title=f"Exposed /.git/config on {LAB}:9000",
                                       severity="high", host=LAB, port=9000,
                                       source="extscan:paths")])
        result = self.diff()
        row = self.state(result, LAB, 9000, r"^Exposed /\.git")["new"][0]
        self.assertIn("old run did not check this", row["note"])
        plain = self.state(result, LAB, 8080, r"^Exposed /phpinfo")["new"][0]
        self.assertNotIn("note", plain)


class TestDidTheRunLook(_Pair):
    def test_stage_that_never_ran(self):
        self.drop(self.new, "GraphQL introspection enabled at http://")
        meta = self.new.meta()
        meta["stages"].pop("chase")
        self.new.write_meta(meta)
        hit = self.state(self.diff(), LAB, 8080, r"^GraphQL introspection")
        self.assertEqual(hit["not_rechecked"][0]["reason"], "the chase stage did not run")

    def test_chase_finding_with_its_lead_unfinished(self):
        self.drop(self.new, "GraphQL introspection enabled at http://")
        self.new.add_leads([Lead(kind="graphql", host=LAB, port=8080,
                                 url=f"http://{LAB}:8080/graphql?x=1", status="failed")])
        hit = self.state(self.diff(), LAB, 8080, r"^GraphQL introspection")
        self.assertIn("follow-up is failed", hit["not_rechecked"][0]["reason"])

    def test_chase_finding_gone_when_everything_behind_it_ran(self):
        # 8081 is not behind the planted nuclei gap for this: give it nuclei back.
        planted._rewrite(self.new, "services.json", lambda rows: [
            {**s, "probed_by": [*s["probed_by"], "nuclei"]} if s["port"] == 8081 else s
            for s in rows])
        planted._rewrite(self.new, "degradations.json", lambda rows: [
            d for d in rows if d["stage"] != "probe:nuclei"])
        self.drop(self.new, f"Content review: http://{LAB}:8081/trace.axd")
        hit = self.state(self.diff(), LAB, 8081, r"^Content review: .*trace\.axd")
        self.assertEqual(list(hit), ["gone"])

    def test_chase_finding_behind_a_failed_parent_probe(self):
        self.drop(self.new, f"Content review: http://{LAB}:8081/trace.axd")
        hit = self.state(self.diff(), LAB, 8081, r"^Content review: .*trace\.axd")
        self.assertEqual(list(hit), ["not_rechecked"])      # nuclei raises web_paths leads

    def test_probe_gap_for_another_port_does_not_taint_this_one(self):
        self.new.add_degradation(Degradation(
            stage="probe:iis", component="iis", reason=f"{LAB}/tcp/9999: TimeoutError: x",
            impact="The iis check did not run.", hosts=[LAB]))
        result = self.diff()
        self.assertEqual(list(self.state(result, LAB, 8081, r"^Verbose ASP\.NET")), ["gone"])
        self.new.add_degradation(Degradation(
            stage="probe:iis", component="iis", reason=f"{LAB}/tcp/8081: TimeoutError: x",
            impact="The iis check did not run.", hosts=[LAB]))
        hit = self.state(self.diff(), LAB, 8081, r"^Verbose ASP\.NET")
        self.assertEqual(list(hit), ["not_rechecked"])

    def test_different_nuclei_selection_is_not_a_recheck(self):
        meta = self.new.meta()
        meta["policy"]["nuclei"]["severities"] = ["high", "critical"]
        self.new.write_meta(meta)
        hit = self.state(self.diff(), planted.STAYS, 443, r"Path Traversal")
        self.assertIn("template selection", hit["not_rechecked"][0]["reason"])

    def test_different_nmap_scripts_is_not_a_recheck(self):
        self.drop(self.new, f"banner on {LAB}:2222/tcp")
        self.assertEqual(list(self.state(self.diff(), LAB, 2222, r"^banner on")), ["gone"])
        meta = self.new.meta()
        meta["policy"]["nmap"]["scripts"] = "default"
        self.new.write_meta(meta)
        hit = self.state(self.diff(), LAB, 2222, r"^banner on")
        self.assertIn("script selection", hit["not_rechecked"][0]["reason"])

    def test_discovery_that_never_ran(self):
        meta = self.new.meta()
        meta["stages"].pop("discover")
        self.new.write_meta(meta)
        result = self.diff()
        self.assertEqual(result["counts"]["services"]["closed"], 0)
        hit = self.state(result, LAB, 3306, r"^MySQL reachable")
        self.assertEqual(hit["not_rechecked"][0]["reason"], "discovery did not run")

    def test_every_source_the_code_emits_maps_to_a_check(self):
        for f in Store(planted.FIXTURE).findings():
            self.assertIsNotNone(check_for(f.source), f.source)
        self.assertIsNone(check_for("analyst"))
        self.assertIsNone(check_for("llm-analysis"))
        probes = {c.name for c in SOURCE_CHECKS.values() if c.kind == "probe"}
        parents = {p for c in SOURCE_CHECKS.values() for p in c.parents}
        self.assertLessEqual((probes | parents) - {"nuclei"}, set(all_probe_names()))


class TestDiffKey(unittest.TestCase):
    def key(self, title, source="extscan:x"):
        return diff_key(Finding(title=title, source=source, host="203.0.113.5", port=443))

    def test_counts_versions_and_page_titles_do_not_move_the_key(self):
        same = [
            ("5 API operation(s) declare no authentication",
             "12 API operation(s) declare no authentication", "extscan:openapi"),
            ("TLS endpoint 203.0.113.5:443 (TLSv1.3)", "TLS endpoint 203.0.113.5:443 (TLSv1.2)",
             "extscan:tls"),
            ("HTTP service: Welcome on 203.0.113.5:443", "HTTP service: Sign in on 203.0.113.5:443",
             "extscan:http"),
            ("Exposed API specification: Billing API (9 operations)",
             "Exposed API specification: Billing v2 (11 operations)", "extscan:openapi"),
            ("Known-vulnerability candidates on http nginx 1.18.0",
             "Known-vulnerability candidates on http nginx 1.24.0", "nmap-tcp:vulners"),
            ("Subdomain enumeration for example.com: 12 name(s)",
             "Subdomain enumeration for example.com: 15 name(s)", "extscan:subdomains"),
            ("Certificate key below 2048 bits on 203.0.113.5:443 (1024 bit)",
             "Certificate key below 2048 bits on 203.0.113.5:443 (512 bit)", "sslscan"),
        ]
        for a, b, source in same:
            self.assertEqual(self.key(a, source), self.key(b, source), a)

    def test_different_issues_keep_different_keys(self):
        different = [
            ("Exposed /.env on 203.0.113.5:443", "Exposed /metrics on 203.0.113.5:443"),
            ("Credential-bearing file readable at https://203.0.113.5/.env",
             "Credential-bearing file readable at https://203.0.113.5/backup/.env"),
            ("Exposed /v2/swagger.json on 203.0.113.5:443",
             "Exposed /v3/api-docs on 203.0.113.5:443"),
            ("Expired certificate on 203.0.113.5:443", "Self-signed certificate on 203.0.113.5:443"),
        ]
        for a, b in different:
            self.assertNotEqual(self.key(a), self.key(b), a)

    def test_nmap_pass_label_is_not_part_of_the_key(self):
        self.assertEqual(self.key("nmap host script: fcrdns", "nmap-tcp:fcrdns"),
                         self.key("nmap host script: fcrdns", "nmap-udp:fcrdns"))

    def test_triage_grouping_key_is_unchanged(self):
        f = Finding(title="5 API operation(s) at https://203.0.113.5:8443/api on 203.0.113.5:8443",
                    source="extscan:openapi")
        self.assertEqual(issue_key(f), "extscan:openapi|5 api operation(s) at <url> on <host>:<port>")


class TestCli(_Pair):
    def run_cli(self, *argv) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--runs-dir", str(self.tmp), *argv])
        return code, out.getvalue()

    def test_diff_writes_both_files_into_the_new_run_and_exits_zero(self):
        code, out = self.run_cli("diff", "old", "new")
        self.assertEqual(code, 0)
        self.assertIn("# Changes from `old` to `new`", out)
        written = json.loads((self.new.path / "diff.json").read_text())
        self.assertEqual(written["counts"], self.diff()["counts"])
        self.assertIn("## Not re-checked", (self.new.path / "diff.md").read_text())
        self.assertFalse((self.old.path / "diff.md").exists())

    def test_json_gives_the_full_structure(self):
        code, out = self.run_cli("diff", "old", "new", "--json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(set(data["findings"]), {"new", "changed", "not_rechecked", "gone", "same"})
        self.assertEqual(set(data["services"]),
                         {"opened", "closed", "not_rescanned", "changed", "same"})
        self.assertEqual(data["old"]["run_id"], "old")

    def test_run_directories_work_and_the_fixture_is_left_alone(self):
        before = _fixture_digest()
        code, _ = self.run_cli("diff", str(planted.FIXTURE), str(self.new.path), "--no-write")
        self.assertEqual(code, 0)
        self.assertFalse((self.new.path / "diff.md").exists())
        code, _ = self.run_cli("diff", str(self.old.path), str(planted.FIXTURE), "--no-write")
        self.assertEqual(code, 0)
        self.assertEqual(_fixture_digest(), before)

    def test_a_run_compared_with_itself_is_all_same(self):
        counts = diff_runs(self.old, self.old)["counts"]
        self.assertEqual({k: v for k, v in counts["findings"].items() if v},
                         {"same": len(self.old.findings())})

    def test_hostile_titles_cannot_inject_markdown(self):
        self.new.add_findings([Finding(title="x\n# Injected heading [[link]] `code` <b>",
                                       severity="high", host=LAB, port=8080,
                                       source="extscan:paths")])
        text = render_markdown(self.diff())
        self.assertNotIn("\n# Injected", text)
        self.assertNotIn("[[link]]", text)


class TestEval(unittest.TestCase):
    def test_diff_eval_passes(self):
        result = planted.run()
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["correct"], result["planted"])


if __name__ == "__main__":
    unittest.main()
