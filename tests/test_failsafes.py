"""Failsafes: the scan stays on what the scope file names, and nothing that
goes wrong goes unsaid.

Each test here pins one way a run could have touched something it was not
given, or come back looking clean when it was not.
"""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from extscan import cli, pipeline
from extscan.models import Finding, Lead, Service
from extscan.policy import (
    Policy,
    check_nmap_extra_args,
    check_nuclei_extra_args,
)
from extscan.resilience import Degradation
from extscan.scope import Scope, ScopeError
from extscan.store import Store
from extscan.tools import net, nmap, nuclei, snmp

from .test_llm import GOOD_REPLY, client_for

SCOPE = {
    "engagement": "t", "client": "c",
    "authorization": {"reference": "T", "authorized_by": "x"},
    "targets": ["203.0.113.0/29"], "exclude": ["203.0.113.5"],
}


class _Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.runs = self.tmp / "runs"

    def scope_file(self, **overrides) -> Path:
        path = self.tmp / "scope.json"
        path.write_text(json.dumps({**SCOPE, **overrides}))
        return path

    def cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--runs-dir", str(self.runs), *argv])
        return code, out.getvalue(), err.getvalue()


class TestScopeFileIsReadStrictly(_Case):
    def test_a_misspelt_key_is_refused_not_ignored(self):
        # `exlude` read as "nothing excluded" would scan the excluded host.
        data = {k: v for k, v in SCOPE.items() if k != "exclude"}
        path = self.tmp / "scope.json"
        path.write_text(json.dumps({**data, "exlude": ["203.0.113.5"]}))
        with self.assertRaises(ScopeError) as cm:
            Scope.load(path)
        self.assertIn("exlude", str(cm.exception))

    def test_a_misspelt_authorization_key_is_refused(self):
        auth = {"reference": "T", "authorized_by": "x",
                "window_ends": "2020-01-01T00:00:00Z"}
        with self.assertRaises(ScopeError) as cm:
            Scope.load(self.scope_file(authorization=auth))
        self.assertIn("window_ends", str(cm.exception))

    def test_comment_keys_are_allowed(self):
        scope = Scope.load(self.scope_file(**{"//note": "why this host is excluded"}))
        self.assertTrue(scope.is_excluded("203.0.113.5"))

    def test_a_string_where_a_list_belongs_is_refused(self):
        with self.assertRaises(ScopeError):
            Scope.load(self.scope_file(exclude="203.0.113.5"))

    def test_an_enormous_range_is_refused_without_walking_it(self):
        with self.assertRaises(ScopeError) as cm:
            Scope.load(self.scope_file(targets=["2001:db8::/32"], exclude=[]))
        self.assertIn("max_hosts", str(cm.exception))


class TestExcludedHostsNeverReachNmap(_Case):
    def test_every_chunk_size_leaves_the_excluded_host_out(self):
        scope = Scope.load(self.scope_file())
        for size in (0, 2, 100):
            flat = [h for chunk in nmap.chunk_targets(scope, size) for h in chunk]
            self.assertNotIn("203.0.113.5", flat, size)
            self.assertNotIn("203.0.113.0/29", flat, size)


class TestExtraArgsCannotWidenTheScan(unittest.TestCase):
    def test_tuning_flags_pass(self):
        check_nmap_extra_args(["--max-rate", "100", "--scan-delay=500ms", "-n", "-T2"])

    def test_targets_spoofing_scripts_and_output_are_refused(self):
        for bad in (["198.51.100.7"], ["-iL", "hosts.txt"], ["-iR", "100"],
                    ["--script", "vuln"], ["--script=dos"], ["-D", "RND:5"],
                    ["-S", "198.51.100.1"], ["-sI", "198.51.100.9"],
                    ["--exclude", "203.0.113.1"], ["-oA", "elsewhere"], ["--proxies", "x"],
                    ["--max-rate", "198.51.100.7"], ["-n", "10"], ["--max-rate"]):
            with self.assertRaises(ValueError, msg=bad):
                check_nmap_extra_args(bad)

    def test_a_policy_file_with_a_target_in_extra_args_does_not_load(self):
        with self.assertRaises(ValueError) as cm:
            Policy.from_dict({"nmap": {"extra_args": ["198.51.100.7"]}})
        self.assertIn("scope file", str(cm.exception))

    def test_nmap_argv_refuses_extra_args_set_after_loading(self):
        scope = Scope(engagement="t", client="c", authorization=mock.Mock(),
                      targets=["203.0.113.1/32"])
        policy = Policy.for_profile("standard")
        policy.nmap.extra_args = ["-iL", "/etc/hosts"]
        for build in (nmap.tcp_argv, nmap.udp_argv, nmap.sweep_argv):
            with self.assertRaises(ValueError):
                build(scope, policy, "out/scan")

    def test_udp_gets_the_same_rate_cap_as_tcp(self):
        scope = Scope(engagement="t", client="c", authorization=mock.Mock(),
                      targets=["203.0.113.1/32"])
        policy = Policy.for_profile("standard")
        policy.nmap.extra_args = ["--max-rate", "50"]
        self.assertIn("--max-rate", nmap.udp_argv(scope, policy, "out/scan"))

    def test_nuclei_targets_proxies_and_uploads_are_refused(self):
        check_nuclei_extra_args(["-stats", "-bulk-size", "10"])
        for bad in (["-u", "https://example.org"], ["-list", "urls.txt"],
                    ["--target=https://example.org"], ["-proxy", "http://x:8080"],
                    ["-cloud-upload"], ["-follow-redirects"], ["-itags", "dos"],
                    ["-interactsh-server", "oast.example"], ["-code"]):
            with self.assertRaises(ValueError, msg=bad):
                check_nuclei_extra_args(bad)

    def test_nuclei_does_not_follow_redirects_unless_asked(self):
        policy = Policy.for_profile("standard")
        self.assertIn("-disable-redirects", nuclei.argv(policy, "/t", "/o"))
        policy.nuclei.follow_redirects = True
        self.assertNotIn("-disable-redirects", nuclei.argv(policy, "/t", "/o"))


class TestAllowedNamesAreCheckedWhereTheyPoint(_Case):
    def setUp(self):
        super().setUp()
        self.scope = Scope.load(self.scope_file(allow_hostnames=["www.ours.example"]))

    @staticmethod
    def answers(*addresses):
        return lambda host, port: [(2, 1, 6, "", (a, 0)) for a in addresses]

    def test_a_name_pointing_at_the_metadata_service_is_refused(self):
        with self.assertRaises(ScopeError) as cm:
            self.scope.assert_resolves_in_bounds(
                "www.ours.example", resolve=self.answers("169.254.169.254"))
        self.assertIn("internal", str(cm.exception))

    def test_a_name_pointing_at_an_excluded_address_is_refused(self):
        with self.assertRaises(ScopeError) as cm:
            self.scope.assert_resolves_in_bounds(
                "www.ours.example", resolve=self.answers("203.0.113.5"))
        self.assertIn("excludes", str(cm.exception))

    def test_a_name_pointing_at_a_public_address_passes(self):
        self.scope.assert_resolves_in_bounds(
            "www.ours.example", resolve=self.answers("198.51.100.20"))

    def test_fetch_reports_the_refusal_and_sends_nothing(self):
        policy = Policy.for_profile("standard").http
        with mock.patch("socket.getaddrinfo", self.answers("10.0.0.8")), \
                mock.patch.object(net, "_opener") as opener:
            resp = net.fetch("http://www.ours.example/", self.scope, policy)
        self.assertIn("scope refusal", resp.error)
        opener.return_value.open.assert_not_called()


class TestScopeChangesAreOnTheRecord(_Case):
    def test_a_widened_scope_is_warned_about_and_recorded_once(self):
        path = self.scope_file()
        self.cli("init", "--scope", str(path), "--id", "r")
        path.write_text(json.dumps({**SCOPE, "targets": [*SCOPE["targets"], "198.51.100.14"],
                                    "exclude": []}))
        code, _, err = self.cli("recon", "r")
        self.assertEqual(code, 0)
        self.assertIn("198.51.100.14", err)
        self.assertIn("exclusions removed: 203.0.113.5", err)
        meta = Store.open(str(self.runs), "r").meta()
        self.assertEqual(len(meta["warnings"]), 1)
        self.assertIn("198.51.100.14", meta["scope"]["targets"])
        self.assertEqual(len(meta["scope_history"]), 1)
        # The same file again is no longer a change.
        _, _, err = self.cli("recon", "r")
        self.assertEqual(err, "")
        self.assertEqual(len(Store.open(str(self.runs), "r").meta()["warnings"]), 1)

    def test_an_unchanged_scope_says_nothing(self):
        path = self.scope_file()
        self.cli("init", "--scope", str(path), "--id", "r")
        _, _, err = self.cli("recon", "r")
        self.assertEqual(err, "")


class TestTheWindowIsCheckedDuringAStage(_Case):
    def test_discovery_stops_at_the_batch_after_the_window_closes(self):
        scope = Scope.load(self.scope_file(allow_private=True, targets=["127.0.0.0/29"],
                                           exclude=[]))
        policy = Policy.for_profile("standard")
        policy.nmap.chunk_size, policy.nmap.sweep = 2, "never"
        store = pipeline.init_run(str(self.runs), scope, policy, run_id="w")
        from extscan import discovery
        from extscan.runner import Result, Runner
        ran = []

        def one_batch(runner, scope_, policy_, kind, batch):
            ran.append(batch.key)
            scope_.authorization.window_end = "2001-01-01T00:00:00Z"   # closes mid-pass
            return Result(["nmap"], 0, "", "", 0.0), "<nmaprun></nmaprun>", ""

        with mock.patch.object(discovery, "_run_batch", side_effect=one_batch), \
                mock.patch.object(discovery, "_finish"), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(ScopeError):
            discovery.run_pass(store, scope, policy, Runner(store), "tcp", False)
        self.assertEqual(len(ran), 1)


class TestNothingFallsBackQuietly(_Case):
    def setUp(self):
        super().setUp()
        self.cli("init", "--scope", str(self.scope_file()), "--id", "r")
        self.store = Store.open(str(self.runs), "r")

    def test_a_saved_policy_that_no_longer_loads_stops_the_command(self):
        meta = self.store.meta()
        meta["policy"]["nmap"]["no_such_setting"] = 1
        self.store.write_meta(meta)
        code, _, err = self.cli("probe", "r")
        self.assertEqual(code, 2)
        self.assertIn("no_such_setting", err)

    def test_a_damaged_run_json_is_an_error_not_an_empty_run(self):
        (self.store.path / "run.json").write_text("{ not json")
        code, _, err = self.cli("status", "r")
        self.assertEqual(code, 2)
        self.assertIn("damaged", err)

    def test_a_policy_file_that_is_not_json_is_named(self):
        bad = self.tmp / "policy.json"
        bad.write_text("{")
        code, _, err = self.cli("init", "--scope", str(self.scope_file()),
                                "--policy", str(bad), "--id", "r2")
        self.assertEqual(code, 2)
        self.assertIn("policy.json", err)

    def test_unreadable_command_log_lines_are_reported(self):
        scope = Scope.load(self.scope_file())
        with (self.store.path / "commands.jsonl").open("a") as fh:
            fh.write('{"argv": ["nmap"], "started": 0, "duration": 0, "returncode": 0}\n')
            fh.write('{"argv": ["nucl\n')
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(self.store, scope)
        self.assertTrue(any("commands.jsonl" in w for w in self.store.meta()["warnings"]))
        self.assertIn("commands.jsonl could not be read",
                      (self.store.path / "report.md").read_text())

    def test_damaged_nuclei_output_is_a_gap_and_clears_on_a_clean_rerun(self):
        self.assertEqual(nuclei.unparseable_lines('{"a": 1}\n\n{"trunc\n[1]\n'), 2)
        svc = Service(host="203.0.113.1", port=80, proto="tcp", name="http")
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline._nuclei_output_gap(self.store, "", [svc], "2 line(s) could not be read")
        gaps = self.store.degradations()
        self.assertEqual([(g.stage, g.hosts) for g in gaps],
                         [("probe:nuclei-output", ["203.0.113.1"])])
        pipeline._nuclei_output_gap(self.store, "", [svc], "")
        self.assertEqual(self.store.degradations(), [])

    def test_snmp_send_failure_is_raised_not_read_as_silence(self):
        sock = mock.Mock()
        sock.sendto.side_effect = OSError(101, "Network is unreachable")
        with mock.patch("socket.socket", return_value=sock), self.assertRaises(OSError):
            snmp.snmp_get("203.0.113.1", "public", "1.3.6.1.2.1.1.1.0")
        sock.sendto.side_effect = ConnectionRefusedError()
        with mock.patch("socket.socket", return_value=sock):
            self.assertIsNone(snmp.snmp_get("203.0.113.1", "public", "1.3.6.1.2.1.1.1.0"))


class TestExitCodeSaysWhenCoverageWasLost(_Case):
    def run_with(self, gaps: list[Degradation], *extra: str) -> tuple[int, str]:
        def fake_run_all(store, scope, policy, runner, **kwargs):
            for gap in gaps:
                store.add_degradation(gap)
            return {"report": {"paths": {"markdown": "report.md"}, "review_items": 0}}

        with mock.patch.object(pipeline, "run_all", side_effect=fake_run_all):
            code, out, _ = self.cli("run", "--scope", str(self.scope_file()), *extra)
        return code, out

    def test_a_complete_run_exits_zero_and_says_so(self):
        code, out = self.run_with([])
        self.assertEqual(code, 0)
        self.assertIn("No coverage gaps", out)

    def test_a_serious_gap_exits_three_and_is_printed(self):
        code, out = self.run_with([Degradation(
            stage="discover:udp", component="nmap", reason="needs root",
            impact="No UDP scanning was performed.", severity="serious")])
        self.assertEqual(code, 3)
        self.assertIn("1 coverage gap(s), 1 serious", out)
        self.assertIn("No UDP scanning was performed.", out)

    def test_a_warning_gap_is_printed_and_exits_zero(self):
        code, out = self.run_with([Degradation(
            stage="screenshot", component="chromium", reason="r", impact="i")])
        self.assertEqual(code, 0)
        self.assertIn("1 coverage gap(s), 0 serious", out)

    def test_json_output_carries_the_gap_counts(self):
        code, out = self.run_with([Degradation(
            stage="probe:nuclei", component="nuclei", reason="r", impact="i",
            severity="serious")], "--json")
        self.assertEqual(code, 3)
        data = json.loads(out[out.index("{"):])
        self.assertEqual(data["coverage_gaps"], {"total": 1, "serious": 1})


class TestAnalyseStage(_Case):
    """Model notes for the reader: bounded, labelled, and never silently absent."""

    def setUp(self):
        super().setUp()
        self.scope = Scope.load(self.scope_file())
        self.policy = Policy.for_profile("standard")
        self.policy.llm.enabled = True
        self.store = pipeline.init_run(str(self.runs), self.scope, self.policy, run_id="a")
        self.store.add_findings([
            Finding(title="Exposed admin API", severity="high", host="203.0.113.1",
                    port=443, source="extscan:http", evidence="GET /admin 200"),
            Finding(title="Redis without auth", severity="critical", host="203.0.113.2",
                    port=6379, source="extscan:exposure"),
            Finding(title="Server header", severity="info", host="203.0.113.1",
                    port=443, source="extscan:http"),
        ])

    def analyse(self, llm, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return pipeline.analyse(self.store, self.scope, self.policy, llm, **kwargs)

    def notes(self):
        return [f for f in self.store.findings() if f.source == "llm-analysis"]

    def test_writes_one_flagged_info_note_per_finding_at_or_above_the_floor(self):
        result = self.analyse(client_for([GOOD_REPLY, GOOD_REPLY]))
        self.assertEqual(result["analysed"], 2)
        notes = self.notes()
        self.assertEqual({n.title for n in notes},
                         {"Model analysis: Exposed admin API",
                          "Model analysis: Redis without auth"})
        self.assertTrue(all(n.severity == "info" and n.review_required for n in notes))
        self.assertEqual(self.store.degradations(), [])
        self.assertEqual(self.store.meta()["stages"]["analyse"]["analysed"], 2)

    def test_a_second_pass_does_not_ask_again(self):
        self.analyse(client_for([GOOD_REPLY, GOOD_REPLY]))
        llm = client_for([])
        self.assertEqual(self.analyse(llm)["analysed"], 0)
        self.assertEqual(llm.provider.calls, [])

    def test_findings_the_model_did_not_cover_are_one_named_gap(self):
        result = self.analyse(client_for([GOOD_REPLY, "this is not json"]))
        self.assertEqual((result["analysed"], result["not_analysed"]), (1, 1))
        gap, = self.store.degradations()
        self.assertEqual(gap.stage, "analyse")
        self.assertIn("1 of 2", gap.reason)
        # ... and a later clean pass clears it.
        self.analyse(client_for([GOOD_REPLY]))
        self.assertEqual(self.store.degradations(), [])

    def test_the_cap_is_recorded_not_applied_quietly(self):
        self.policy.llm.max_findings = 1
        result = self.analyse(client_for([GOOD_REPLY]))
        self.assertEqual((result["analysed"], result["not_analysed"]), (1, 1))
        self.assertIn("llm.max_findings is 1", self.store.degradations()[0].reason)
        # The most severe finding is the one that got the note.
        self.assertEqual(self.notes()[0].title, "Model analysis: Redis without auth")

    def test_a_dry_run_asks_nothing_and_stores_nothing(self):
        llm = client_for([])
        result = self.analyse(llm, dry_run=True)
        self.assertEqual(result["planned"], 2)
        self.assertEqual(llm.provider.calls, [])
        self.assertNotIn("analyse", self.store.meta()["stages"])

    def test_no_model_means_no_stage_and_no_gap(self):
        self.assertTrue(self.analyse(None)["disabled"])
        self.assertEqual(self.store.degradations(), [])

    def test_a_reply_cut_off_at_max_tokens_is_named_as_that(self):
        llm = client_for(['{"summary": "half an ans'])
        llm.provider.last_stop_reason = "max_tokens"
        self.analyse(llm)
        self.assertIn("llm.max_tokens", self.store.degradations()[0].reason)


class TestSecurityNotes(_Case):
    def test_unfinished_followups_and_out_of_scope_assets_are_handed_over(self):
        from extscan.report import security_notes
        from extscan.triage import triage
        findings = [
            Finding(title="API specification references hosts outside the engagement scope",
                    host="203.0.113.1", port=443, tags=["openapi", "scope", "asset-discovery"]),
            Finding(title="OpenSSH 7.4 (version match)", severity="high", host="203.0.113.1",
                    port=22, confidence="tentative", source="nmap-tcp:vulners"),
            Finding(title="Model analysis: x", host="203.0.113.1", source="llm-analysis",
                    confidence="tentative"),
        ]
        leads = [
            Lead(kind="openapi", host="203.0.113.1", port=443, reason="spec exposed",
                 status="done"),
            Lead(kind="graphql", host="203.0.113.1", port=443, reason="endpoint found"),
            Lead(kind="secret_file", host="203.0.113.1", port=80, reason=".env",
                 status="failed", attempts=2, last_error="timed out"),
        ]
        notes = security_notes(triage(findings), leads)
        self.assertEqual([(u["kind"], u["state"]) for u in notes["unfinished_followups"]],
                         [("graphql", "not attempted"), ("secret_file", "failed")])
        self.assertEqual(len(notes["outside_scope"]), 1)
        self.assertEqual([r["title"] for r in notes["to_confirm"]],
                         ["OpenSSH 7.4 (version match)"])
        self.assertEqual([r["source"] for r in notes["analysis_notes"]], ["llm-analysis"])


if __name__ == "__main__":
    unittest.main()
