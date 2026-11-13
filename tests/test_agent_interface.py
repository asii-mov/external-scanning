"""What a person or agent driving the CLI relies on: flags work where the
docs put them, a policy file means what it says, and --dry-run sends nothing.
"""

import contextlib
import io
import json
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from extscan import cli, pipeline
from extscan.models import Lead, Service
from extscan.policy import Policy
from extscan.runner import Runner
from extscan.scope import Scope
from extscan.store import Store
from extscan.tools import nmap

from .targetapp import Handler

ROOT = Path(__file__).parent.parent


class _RunCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.scope_path = self.tmp / "scope.json"
        self.scope_path.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["127.0.0.1/32"], "allow_private": True,
        }))
        self.runs = self.tmp / "runs"

    def cli(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["--runs-dir", str(self.runs), *argv])
        return code, out.getvalue()


class TestGlobalFlagsOnEitherSide(_RunCase):
    def setUp(self):
        super().setUp()
        self.cli("init", "--scope", str(self.scope_path), "--id", "r")

    def test_json_after_the_subcommand(self):
        _, out = self.cli("status", "r", "--json")
        self.assertEqual(json.loads(out)["run_id"], "r")

    def test_json_before_the_subcommand_still_works(self):
        _, out = self.cli("--json", "status", "r")
        self.assertEqual(json.loads(out)["run_id"], "r")

    def test_a_flag_given_before_is_not_reset_by_its_absence_after(self):
        _, out = self.cli("--json", "gaps", "r")
        self.assertEqual(json.loads(out), [])

    def test_runs_dir_after_the_subcommand(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["status", "r", "--runs-dir", str(self.runs), "--json"])
        self.assertEqual(json.loads(out.getvalue())["run_id"], "r")


class TestPolicyFileMeansWhatItSays(unittest.TestCase):
    def test_top_level_limits_are_loaded(self):
        p = Policy.from_dict({"max_workers": 3, "max_lead_attempts": 5})
        self.assertEqual((p.max_workers, p.max_lead_attempts), (3, 5))

    def test_gentle_example_really_lowers_concurrency(self):
        self.assertEqual(Policy.load(ROOT / "examples" / "policy.gentle.json").max_workers, 3)

    def test_unknown_top_level_key_is_refused(self):
        with self.assertRaisesRegex(ValueError, "max_worker"):
            Policy.from_dict({"max_worker": 3})

    def test_every_shipped_policy_loads(self):
        for path in sorted((ROOT / "examples").rglob("policy*.json")):
            with self.subTest(path=path.name):
                Policy.load(path)

    def test_a_saved_policy_round_trips(self):
        p = Policy.for_profile("quick")
        p.max_workers = 2
        self.assertEqual(Policy.from_dict(p.to_dict(), profile="quick").to_dict(), p.to_dict())


class TestDryRunSendsNothing(_RunCase):
    def setUp(self):
        super().setUp()
        self.requests = []

        class Counting(Handler):
            def parse_request(inner):
                self.requests.append(1)
                return super().parse_request()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Counting)
        threading.Thread(target=self.server.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        port = self.server.server_address[1]

        self.scope = Scope.load(self.scope_path)
        self.policy = Policy()
        self.store = pipeline.init_run(str(self.runs), self.scope, self.policy, run_id="r")
        self.store.save_services([Service(host="127.0.0.1", port=port, proto="tcp",
                                          name="http")])
        self.store.add_leads([Lead(kind="web_paths", host="127.0.0.1", port=port,
                                   url=f"http://127.0.0.1:{port}/metrics", reason="r")])
        self.dry = Runner(self.store, dry_run=True)

    def quiet(self, fn, *args, **kwargs):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = fn(self.store, self.scope, self.policy, self.dry, *args, **kwargs)
        return result, out.getvalue()

    def test_probe_plans_and_sends_nothing(self):
        result, out = self.quiet(pipeline.probe)
        self.assertEqual(self.requests, [])
        self.assertIn("[dry-run] would run http_fingerprint", out)
        self.assertIn("[dry-run] would run vhosts", out)
        self.assertEqual(result["planned"], 2)
        self.assertEqual(self.store.services()[0].probed_by, [])
        self.assertEqual(self.store.findings(), [])

    def test_chase_plans_and_sends_nothing(self):
        result, out = self.quiet(pipeline.chase_leads)
        self.assertEqual(self.requests, [])
        self.assertIn("[dry-run] would chase web_paths", out)
        self.assertEqual([ld.status for ld in self.store.leads()], ["open"])
        self.assertEqual(result["planned"], 1)

    def test_discover_keeps_the_checkpoints_and_stage_record_of_a_real_run(self):
        self.store.checkpoint("discover:tcp", "chunk-0001")
        self.store.mark_stage("discover", tcp={"hosts": 1})
        self.quiet(pipeline.discover, udp=False)
        self.assertEqual(self.store.checkpoints("discover:tcp"), {"chunk-0001"})
        self.assertEqual(self.store.meta()["stages"]["discover"]["tcp"], {"hosts": 1})


class TestStoreBatching(unittest.TestCase):
    def test_mark_probed_many_matches_one_at_a_time(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store.create(d, "r")
            a, b = (Service(host="127.0.0.1", port=p, proto="tcp") for p in (80, 443))
            store.save_services([a, b])
            store.mark_probed_many([(a.id, "tls"), (a.id, "tls"), (b.id, "tls"),
                                    ("nope", "tls")])
            store.mark_probed(b.id, "nuclei")
            self.assertEqual({s.port: s.probed_by for s in store.services()},
                             {80: ["tls"], 443: ["tls", "nuclei"]})


class TestReviewQueueStaysWorthReading(unittest.TestCase):
    def flags(self, **scripts: str) -> dict[str, bool]:
        svc = Service(host="127.0.0.1", port=80, proto="tcp", name="http",
                      scripts={k.replace("_", "-"): v for k, v in scripts.items()})
        return {f.title.split(" ")[0]: f.review_required
                for f in nmap._findings_from_scripts(svc, "nmap-tcp")}

    def test_housekeeping_scripts_are_reported_but_not_queued(self):
        flags = self.flags(http_date="Mon, 01 Jan 2026", http_title="Billing",
                           http_methods="Potentially risky methods: PUT")
        self.assertEqual(flags, {"http-date": False, "http-title": True, "http-methods": True})

    def test_a_script_that_found_nothing_is_not_queued(self):
        flags = self.flags(http_malware_host="false",
                           http_comments_displayer="Couldn't find any comments.",
                           http_enum="/admin/: Possible admin folder")
        self.assertEqual(flags, {"http-malware-host": False, "http-comments-displayer": False,
                                 "http-enum": True})


if __name__ == "__main__":
    unittest.main()
