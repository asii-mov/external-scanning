"""End-to-end: probe -> chase -> report against a live local target.

This is the test that would have caught the two bugs found during development:
an OpenAPI `servers` base path being dropped when building endpoint URLs, and
a soft-404 being reported as a confirmed open API endpoint.

Discovery is seeded from an nmap XML fixture rather than run, so the suite needs
no nmap and no privileges.
"""

import atexit
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from extscan import pipeline
from extscan.models import Service
from extscan.policy import Policy
from extscan.probes import ProbeContext
from extscan.runner import Runner
from extscan.scope import Scope, ScopeError
from extscan.store import Store
from extscan.triage import triage

from .targetapp import TargetApp


class _Harness:
    """One live target and one completed pipeline run, shared by every class.

    Built once and cached: the assertions below all interrogate the same run,
    and starting a server plus re-running the pipeline per test class would
    make the suite slow for no extra coverage.
    """

    _instance: "_Harness | None" = None

    def __init__(self):
        self.app = TargetApp()
        self.app.__enter__()
        self.tmp = Path(tempfile.mkdtemp(prefix="extscan-test-"))

        scope_path = self.tmp / "scope.json"
        scope_path.write_text(json.dumps({
            "engagement": "pipeline e2e",
            "client": "self-test",
            "authorization": {
                "reference": "LOCAL-TEST",
                "authorized_by": "test harness (loopback only)",
            },
            "targets": ["127.0.0.1/32"],
            "allow_private": True,
            "max_hosts": 2,
        }))
        self.scope = Scope.load(scope_path)

        self.policy = Policy.for_profile("standard")
        self.policy.http.timeout_sec = 5
        self.policy.max_workers = 4

        self.store = pipeline.init_run(str(self.tmp / "runs"), self.scope, self.policy,
                                       run_id="e2e")
        self.store.save_services([Service(
            host="127.0.0.1", port=self.app.port, proto="tcp", name="http",
            product="nginx", version="1.18.0",
        )])
        self.runner = Runner(self.store)

        # The stages narrate progress for interactive use; keep it out of the
        # test report.
        with redirect_stdout(io.StringIO()):
            pipeline.probe(self.store, self.scope, self.policy, self.runner,
                           skip_nuclei=True)
            pipeline.chase_leads(self.store, self.scope, self.policy, self.runner,
                                 rounds=3)
            self.result = pipeline.make_report(self.store, self.scope, self.runner)

        self.findings = self.store.findings()
        self.report = (self.store.path / "report.md").read_text()

    @classmethod
    def get(cls) -> "_Harness":
        if cls._instance is None:
            cls._instance = cls()
            atexit.register(cls._instance.close)
        return cls._instance

    def close(self):
        self.app.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)


class PipelineTestCase(unittest.TestCase):
    """Base class exposing the shared run as familiar attributes."""

    @classmethod
    def setUpClass(cls):
        h = _Harness.get()
        cls.app, cls.scope, cls.policy = h.app, h.scope, h.policy
        cls.store, cls.runner = h.store, h.runner
        cls.findings, cls.report, cls.result = h.findings, h.report, h.result

    def titled(self, needle: str):
        return [f for f in self.findings if needle.lower() in f.title.lower()]


class TestDisclosurePaths(PipelineTestCase):
    def test_env_file_found_and_graded_critical(self):
        hits = self.titled("credential-bearing file")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "critical")
        self.assertTrue(hits[0].review_required)

    def test_secret_values_never_appear_in_the_report(self):
        """The report proves exposure; it must not become a copy of the secrets."""
        for secret in ("fake-stripe-value-for-tests-only",
                       "fake-jwt-signing-value-for-tests",
                       "fake-aws-key-id-for-tests",
                       "fake-smtp-password",
                       "NOT-A-REAL-PASSWORD"):
            self.assertNotIn(secret, self.report, f"leaked {secret!r} into report.md")

    def test_secret_key_names_are_reported(self):
        hits = self.titled("credential-bearing file")
        self.assertIn("STRIPE_SECRET_KEY", hits[0].evidence)
        self.assertIn("redacted", hits[0].evidence)

    def test_soft_404_paths_are_not_reported_as_present(self):
        """The target answers 200 for every unknown path."""
        for path in ("/web.config", "/.DS_Store", "/phpinfo.php", "/server-status",
                     "/debug/pprof/", "/swagger-ui.html"):
            self.assertEqual(self.titled(f"Exposed {path} on"), [],
                             f"{path} is a soft-404 and must not be a finding")

    def test_protected_path_recorded_as_access_controlled(self):
        hits = self.titled("/actuator present but access-controlled")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "info")

    def test_robots_txt_found(self):
        self.assertEqual(len(self.titled("Exposed /robots.txt")), 1)

    def test_version_headers_flagged(self):
        hits = self.titled("version-disclosing http headers")
        self.assertEqual(len(hits), 1)
        self.assertIn("nginx/1.18.0", hits[0].evidence)
        self.assertIn("Express", hits[0].evidence)      # X-Powered-By


class TestOpenApiChase(PipelineTestCase):
    def test_spec_discovered_and_parsed(self):
        hits = self.titled("Exposed API specification")
        self.assertTrue(hits)
        self.assertIn("ACME Billing API", hits[0].title)
        self.assertIn("9 operations", hits[0].title)

    def test_unauthenticated_operations_enumerated(self):
        hits = self.titled("declare no authentication")
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual(f.severity, "high")           # includes write methods
        self.assertEqual(f.confidence, "tentative")    # spec is intent, not proof
        self.assertTrue(f.review_required)
        # The two unauthenticated writes from the fixture spec.
        self.assertIn("POST   /invoices", f.evidence)
        self.assertIn("DELETE /invoices/{id}", f.evidence)

    def test_global_security_respected(self):
        """Operations inheriting the global requirement are not called open."""
        f = self.titled("declare no authentication")[0]
        self.assertNotIn("POST   /payments/token", f.evidence)

    def test_offscope_server_in_spec_is_noted_not_scanned(self):
        hits = self.titled("references hosts outside the engagement scope")
        self.assertEqual(len(hits), 1)
        self.assertIn("internal-billing.corp.acme.example", hits[0].evidence)
        # And nothing was fetched from it.
        for cmd in self.store.commands():
            self.assertNotIn("internal-billing", " ".join(cmd.get("argv", [])))

    def test_sensitive_operations_heuristic_is_narrow(self):
        """It must flag admin/internal, not every business noun."""
        hits = self.titled("sensitive-looking resources")
        self.assertTrue(hits)
        evidence = hits[0].evidence
        self.assertIn("/admin/users", evidence)
        self.assertIn("/internal/debug/config", evidence)
        self.assertNotIn("/health", evidence)


class TestApiEndpointVerification(PipelineTestCase):
    """The bug that mattered: base paths dropped, soft-404s believed."""

    def test_endpoint_urls_keep_the_spec_server_base_path(self):
        confirmed = self.titled("Unauthenticated API endpoint confirmed")
        self.assertTrue(confirmed)
        for f in confirmed:
            self.assertIn("/api/", f.title, "server base path was dropped")

    def test_admin_endpoint_confirmed_and_graded_high(self):
        hits = [f for f in self.titled("Unauthenticated API endpoint confirmed")
                if "/api/admin/users" in f.title]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")     # sensitive path

    def test_harmless_endpoint_graded_lower(self):
        hits = [f for f in self.titled("Unauthenticated API endpoint confirmed")
                if "/api/health" in f.title]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")   # open, but a liveness probe

    def test_endpoint_enforcing_auth_reported_as_doc_defect(self):
        hits = self.titled("enforces authentication despite spec")
        self.assertEqual(len(hits), 1)
        self.assertIn("/api/internal/debug/config", hits[0].title)
        self.assertEqual(hits[0].severity, "info")

    def test_write_operations_are_never_invoked(self):
        """No POST/PUT/PATCH/DELETE may be sent to a documented write op."""
        for lead in self.store.leads():
            if lead.kind == "api_endpoint":
                self.assertEqual(lead.params.get("method"), "get")
        self.assertEqual(self.titled("Unauthenticated API endpoint confirmed: POST"), [])


class TestGraphQlChase(PipelineTestCase):
    def test_endpoint_detected_despite_400_response(self):
        self.assertEqual(len(self.titled("Exposed /graphql")), 1)

    def test_introspection_reported_with_schema_detail(self):
        hits = self.titled("GraphQL introspection enabled")
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual(f.severity, "medium")
        self.assertTrue(f.review_required)
        self.assertIn("Mutation", f.description)
        self.assertIn("User", f.evidence)

    def test_mutation_presence_raised_in_review_reason(self):
        f = self.titled("GraphQL introspection enabled")[0]
        self.assertIn("mutation", f.review_reason.lower())


class TestLeadLifecycle(PipelineTestCase):
    def test_all_leads_resolved(self):
        self.assertEqual(self.store.leads("open"), [])

    def test_leads_carry_outcome_notes(self):
        for lead in self.store.leads():
            self.assertTrue(lead.note, f"lead {lead.kind} has no outcome note")

    def test_depth_is_bounded(self):
        for lead in self.store.leads():
            self.assertLessEqual(lead.depth, self.policy.max_lead_depth + 1)

    def test_chase_cascaded_at_least_one_level(self):
        """openapi -> api_endpoint proves the loop re-queues its own output."""
        kinds = {l.kind for l in self.store.leads()}
        self.assertIn("openapi", kinds)
        self.assertIn("api_endpoint", kinds)
        spawned = [l for l in self.store.leads() if l.kind == "api_endpoint"]
        self.assertTrue(all(l.depth >= 1 for l in spawned))


class TestReportOutput(PipelineTestCase):
    def test_both_formats_written(self):
        self.assertTrue((self.store.path / "report.md").exists())
        self.assertTrue((self.store.path / "report.json").exists())

    def test_authorisation_recorded_in_report(self):
        self.assertIn("LOCAL-TEST", self.report)
        self.assertIn("test harness (loopback only)", self.report)

    def test_review_queue_present_and_ordered(self):
        self.assertIn("## Manual review queue", self.report)
        queue = triage(self.findings, self.store.services()).review_queue
        self.assertTrue(queue)
        self.assertEqual(queue[0].severity, "critical")   # the .env

    def test_limitations_section_states_read_only(self):
        self.assertIn("All checks were read-only", self.report)
        self.assertIn("Absence of a finding is not evidence", self.report)

    def test_command_log_appended(self):
        self.assertIn("Methodology and limitations", self.report)

    def test_json_report_is_valid_and_complete(self):
        data = json.loads((self.store.path / "report.json").read_text())
        for key in ("engagement", "stats", "review_queue", "findings", "services"):
            self.assertIn(key, data)
        self.assertEqual(len(data["findings"]), len(self.findings))

    def test_evidence_cannot_break_out_of_code_fences(self):
        """Attacker-controlled bodies must not inject markdown into the report."""
        from extscan.report import _fence
        fenced = _fence("safe\n```\n# Injected heading\n")
        self.assertNotIn("\n```\n# Injected", fenced)
        self.assertIn("'''", fenced)


class TestScopeEnforcementDuringChase(PipelineTestCase):
    """Leads derived from target output must still be scope-checked."""

    def test_offscope_lead_is_refused_not_fetched(self):
        from extscan.chase import chase
        from extscan.models import Lead

        ctx = ProbeContext(scope=self.scope, policy=self.policy, runner=self.runner)
        lead = Lead(kind="web_paths", host="169.254.169.254", port=80,
                    url="http://169.254.169.254/latest/meta-data/",
                    reason="hostile redirect target")
        result = chase(ctx, lead)
        self.assertEqual(result.findings, [])
        self.assertIn("scope", result.note.lower())

    def test_offscope_openapi_server_refused(self):
        with self.assertRaises(ScopeError):
            self.scope.assert_url("https://internal-billing.corp.acme.example/api")

    def test_unknown_lead_kind_handled_gracefully(self):
        from extscan.chase import chase
        from extscan.models import Lead

        ctx = ProbeContext(scope=self.scope, policy=self.policy, runner=self.runner)
        result = chase(ctx, Lead(kind="not_a_real_kind", host="127.0.0.1"))
        self.assertEqual(result.findings, [])
        self.assertIn("no handler", result.note)


class TestStoreDurability(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="extscan-store-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_findings_deduplicate_across_reruns(self):
        from extscan.models import Finding

        store = Store.create(self.tmp, "dedup")
        store.write_meta({"run_id": store.run_id})
        f = Finding(title="same thing", host="203.0.113.1", port=443, source="t")
        self.assertEqual(store.add_findings([f]), 1)
        self.assertEqual(store.add_findings([f]), 0)
        self.assertEqual(len(store.findings()), 1)

    def test_services_merge_rather_than_clobber(self):
        store = Store.create(self.tmp, "merge")
        store.write_meta({"run_id": store.run_id})
        store.save_services([Service(host="h", port=443, proto="tcp", name="https",
                                     probed_by=["tls"])])
        store.save_services([Service(host="h", port=443, proto="tcp", name="https",
                                     probed_by=["nuclei"])])
        services = store.services()
        self.assertEqual(len(services), 1)
        self.assertEqual(sorted(services[0].probed_by), ["nuclei", "tls"])

    def test_latest_resolves_to_newest_run(self):
        a = Store.create(self.tmp, "first", run_id="aaa")
        a.write_meta({"run_id": "aaa"})
        b = Store.create(self.tmp, "second", run_id="bbb")
        b.write_meta({"run_id": "bbb"})
        self.assertEqual(Store.open(self.tmp, "latest").run_id, "bbb")

    def test_rejects_path_traversal_in_run_id(self):
        for bad in ("../escape", "/etc", "a/b", ""):
            with self.assertRaises((ValueError, FileNotFoundError), msg=bad):
                Store.open(self.tmp, bad)

    def test_raw_filenames_are_sanitised(self):
        store = Store.create(self.tmp, "raw")
        path = store.raw_path("../../etc/passwd")
        self.assertEqual(path.parent, store.raw)
        self.assertNotIn("..", path.name)


if __name__ == "__main__":
    unittest.main()
