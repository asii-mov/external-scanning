"""The Obsidian vault rendered from the committed lab run.

Checks the properties a reader relies on: every link opens a note, every
finding and gap is somewhere a reader will see it, the auditor view comes
before the story, and nothing secret or hostile survives into the notes.
"""

import contextlib
import io
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from extscan import pipeline, vault
from extscan.models import Finding
from extscan.resilience import Degradation
from extscan.scope import Scope
from extscan.screenshots import SHOTS_FILE, Shot, plan, save
from extscan.store import Store

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "lab-run"
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
       b"\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00"
       b"\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")
LINK_RE = re.compile(r"!?\[\[([^\]|#]+)(?:[|#][^\]]*)?\]\]")
SECRETS = ["NOT-A-REAL-PASSWORD", "fake-stripe-value-for-tests-only",
           "fake-jwt-signing-value-for-tests", "fake-aws-key-id-for-tests"]


class _VaultCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(FIXTURE, self.tmp / "run")
        self.store = Store(self.tmp / "run")
        self.scope = Scope.load(ROOT / "examples" / "lab" / "scope.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_screenshots(self):
        shots = plan(self.store.services(), self.store.findings(), limit=60)
        for s in shots:
            (self.store.path / s.file).parent.mkdir(parents=True, exist_ok=True)
            (self.store.path / s.file).write_bytes(PNG)
            s.status, s.http_status, s.page_title = "captured", 200, "Lab page"
        save(self.store.path, shots)
        return shots

    def render(self):
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(self.store, self.scope)
        return self.store.path / vault.VAULT_DIR

    def notes(self, root: Path) -> dict[str, str]:
        return {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob("*.md")}


class TestVaultFromLabRun(_VaultCase):
    def setUp(self):
        super().setUp()
        self.shots = self.fake_screenshots()
        self.root = self.render()
        self.all = self.notes(self.root)
        self.summary = self.all[f"{vault.SUMMARY}.md"]

    def test_every_wikilink_resolves(self):
        for name, text in self.all.items():
            for target in LINK_RE.findall(text):
                path = self.root / target
                exists = path.is_file() or path.with_name(path.name + ".md").is_file()
                self.assertTrue(exists, f"{name} links to missing {target!r}")

    def test_every_finding_has_a_note_and_a_host_link(self):
        findings = self.store.findings()
        host_text = "".join(t for n, t in self.all.items() if n.startswith("hosts/"))
        for f in findings:
            self.assertIn(f"findings/{f.id}.md", self.all)
            # Findings nuclei could not attribute to a host are listed in the summary.
            self.assertIn(f"[[findings/{f.id}|", host_text if f.host else self.summary)

    def test_every_notable_finding_is_in_the_narrative(self):
        for f in self.store.findings():
            if f.severity != "info":
                self.assertIn(f"[[findings/{f.id}|", self.summary, f.title)

    def test_every_review_item_is_in_the_queue_note(self):
        queue = self.all[f"{vault.REVIEW}.md"]
        rows = [ln for ln in queue.splitlines() if re.match(r"^\| \d+ \|", ln)]
        self.assertEqual(len(rows), 42)

    def test_auditor_view_comes_before_the_story(self):
        warning = self.summary.index("[!warning] Before this report goes out")
        self.assertLess(warning, self.summary.index("## 1. Scope and authorisation"))
        self.assertIn("42 items need an auditor's decision", self.summary)

    def test_story_runs_in_the_order_the_work_happened(self):
        order = ["Scope and authorisation", "Discovery: what was listening",
                 "Web applications", "Following up", "What we did not cover"]
        positions = [self.summary.index(f". {h}\n") for h in order]
        self.assertEqual(positions, sorted(positions))

    def test_discovery_quotes_the_real_nmap_commands(self):
        self.assertIn("nmap -sS -sV", self.summary)
        self.assertIn("nmap -sU -sV", self.summary)

    def test_snmp_proof_names_the_community_and_sysdescr(self):
        self.assertIn("community=public", self.summary)
        self.assertIn("sysDescr: Linux lab-router", self.summary)

    def test_secret_values_never_reach_any_report(self):
        outputs = {**self.all,
                   "report.md": (self.store.path / "report.md").read_text(),
                   "report.json": (self.store.path / "report.json").read_text()}
        for name, text in outputs.items():
            for secret in SECRETS:
                self.assertNotIn(secret, text, f"{secret} leaked into {name}")
        self.assertIn("STRIPE_SECRET_KEY=<redacted, 32 chars>", self.summary)

    def test_screenshots_are_embedded_and_copied(self):
        for shot in self.shots:
            name = Path(shot.file).name
            self.assertTrue((self.root / "attachments" / name).is_file())
        self.assertIn("![[attachments/127.0.0.2-8080.png]]", self.summary)
        host = self.all["hosts/127.0.0.2.md"]
        self.assertIn("![[attachments/127.0.0.2-8443.png]]", host)

    def test_images_stay_out_of_report_json(self):
        report = (self.store.path / "report.json").read_text()
        self.assertNotIn(".png", report)

    def test_frontmatter_is_valid_for_dataview(self):
        for name, text in self.all.items():
            self.assertTrue(text.startswith("---\n"), name)
            block = text.split("---\n", 2)[1]
            for line in block.splitlines():
                key, _, value = line.partition(": ")
                self.assertRegex(key, r"^[a-z_]+$", name)
                json.loads(value)
        fm = self.all["findings/" + self.store.findings()[0].id + ".md"]
        self.assertIn('"severity/', fm)

    def test_duplicate_proofs_collapse(self):
        # Three nuclei templates and a path check all read the same .env.
        self.assertEqual(self.summary.count("GET http://127.0.0.2:8080/.env -> 200 OK"), 1)
        self.assertIn("Also flagged by", self.summary)


class TestVaultGapsAndRerender(_VaultCase):
    def test_gaps_are_in_summary_and_gap_note(self):
        self.store.add_degradation(Degradation(
            stage="probe:nuclei", component="nuclei", reason="nuclei killed",
            impact="Templated web checks did not complete against 5 web services.",
            severity="serious", hosts=["127.0.0.2"], remedy="rerun"))
        root = self.render()
        summary = (root / f"{vault.SUMMARY}.md").read_text()
        gaps = (root / f"{vault.GAPS}.md").read_text()
        self.assertIn("1 coverage gap, 1 serious", summary)
        self.assertIn("Templated web checks did not complete", summary)
        self.assertIn("Templated web checks did not complete", gaps)
        self.assertLess(summary.index("coverage gap"), summary.index("## 1."))

    def test_missing_screenshots_are_said_out_loud(self):
        root = self.render()
        summary = (root / f"{vault.SUMMARY}.md").read_text()
        self.assertIn("_No screenshot of this service._", summary)

    def test_rerender_removes_stale_notes_and_keeps_the_testers(self):
        root = self.render()
        mine = root / "my notes.md"
        mine.write_text("tester's own notes")
        (root / ".obsidian").mkdir()
        (root / ".obsidian" / "app.json").write_text("{}")
        gone = self.store.findings()[0]
        self.store.replace_findings(self.store.findings()[1:])
        self.render()
        self.assertFalse((root / "findings" / f"{gone.id}.md").exists())
        self.assertTrue(mine.exists())
        self.assertTrue((root / ".obsidian" / "app.json").exists())


class TestHostileText(_VaultCase):
    """Scanner output is attacker-controlled. It must render as text."""

    def test_markup_in_titles_and_page_titles_is_inert(self):
        hostile = "![[../../secret]] <img src=http://evil.example/x> %%hide [x](http://e)"
        self.store.add_findings([Finding(
            title=f"HTTP service: {hostile}", severity="high", host="127.0.0.2",
            port=8080, source="extscan:http", description=hostile,
            evidence=f"GET http://127.0.0.2:8080 -> 200 OK\ntitle: {hostile}")])
        shots = self.fake_screenshots()
        shots[0].page_title = hostile
        save(self.store.path, shots)
        root = self.render()
        live = [r"(?<!\\)!\[\[\.\./", r"(?<!\\)<img", r"(?<!\\)%%", r"(?<!\\)\]\(http"]
        for name, text in self.notes(root).items():
            outside_fences = re.sub(r"```text\n.*?\n```", "", text, flags=re.S)
            outside_code = re.sub(r"`[^`\n]*`", "", outside_fences)
            for pattern in live:
                self.assertNotRegex(outside_code, pattern, name)
        summary = (root / f"{vault.SUMMARY}.md").read_text()
        self.assertIn("\\<img src", summary)        # shown, escaped


class TestRedaction(_VaultCase):
    def test_custom_community_is_redacted_and_default_kept(self):
        self.store.add_findings([Finding(
            title="SNMP readable with guessable community string `acmeNOC2024`",
            severity="medium", host="127.0.0.2", port=10161, proto="udp",
            source="extscan:snmp",
            description="answered using the community string `acmeNOC2024` (v2c).",
            evidence="sysDescr: core-router\nversion: v2c",
            tags=["snmp", "default-credentials", "community:acmeNOC2024"])])
        root = self.render()
        outputs = [*self.notes(root).values(), (self.store.path / "report.md").read_text(),
                   (self.store.path / "report.json").read_text()]
        for text in outputs:
            self.assertNotIn("acmeNOC2024", text)
        summary = (root / f"{vault.SUMMARY}.md").read_text()
        self.assertIn("community=public", summary)
        self.assertIn("<redacted community, 11 chars>", summary)
        # Run state keeps it, so the finding can be re-checked.
        raw = (self.store.path / "findings.json").read_text()
        self.assertIn("acmeNOC2024", raw)

    def test_header_names_that_contain_uri_are_not_secrets(self):
        from extscan.redact import redact_text
        text = "content-security-policy: none\nAPI_KEY=abcdef\nsid: ASP.NET_SessionId=zz99"
        out = redact_text(text)
        self.assertIn("content-security-policy: none", out)
        self.assertIn("API_KEY=<redacted, 6 chars>", out)
        self.assertNotIn("zz99", out)


class TestScreenshotPlan(unittest.TestCase):
    def setUp(self):
        self.store = Store(FIXTURE)

    def test_roots_first_and_secret_pages_never_planned(self):
        shots = plan(self.store.services(), self.store.findings(), limit=60)
        roots = [s for s in shots if s.kind == "service"]
        self.assertEqual({s.url for s in roots},
                         {"http://127.0.0.2:2375", "http://127.0.0.2:8080",
                          "http://127.0.0.2:8081", "https://127.0.0.2:8443",
                          "http://127.0.0.2:9200"})
        self.assertEqual(shots[:len(roots)], roots)
        urls = {s.url for s in shots}
        for secret in (".env", "trace.axd", "elmah.axd"):
            self.assertFalse(any(secret in u for u in urls), secret)
        self.assertIn("http://127.0.0.2:8080/swagger.json", urls)

    def test_limit_never_drops_a_service_root(self):
        shots = plan(self.store.services(), self.store.findings(), limit=1)
        self.assertEqual(len(shots), 5)
        self.assertTrue(all(s.kind == "service" for s in shots))


class TestScreenshotStage(_VaultCase):
    def run_stage(self, factory, **kw):
        from extscan.policy import Policy
        with contextlib.redirect_stdout(io.StringIO()):
            return pipeline.screenshot(self.store, self.scope, Policy(),
                                       shooter_factory=factory, **kw)

    def test_missing_browser_is_a_coverage_gap(self):
        from extscan.screenshots import BrowserUnavailable

        @contextlib.contextmanager
        def missing():
            raise BrowserUnavailable("playwright is not installed")
            yield

        self.run_stage(missing)
        gaps = self.store.degradations()
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].stage, "screenshot")
        self.assertIn("text only", gaps[0].impact)
        self.assertFalse((self.store.path / SHOTS_FILE).exists())

    def test_failed_root_is_a_gap_and_a_retry_clears_it(self):
        def shooter(fail):
            @contextlib.contextmanager
            def factory():
                def shoot(url, path):
                    if fail and url == "http://127.0.0.2:8081":
                        raise TimeoutError("page did not load")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(PNG)
                    return {"title": "t", "status": 200, "final_url": url, "blocked": []}
                yield shoot
            return factory

        self.run_stage(shooter(True))
        gaps = self.store.degradations()
        self.assertEqual(len(gaps), 1)
        self.assertIn("http://127.0.0.2:8081", gaps[0].impact)

        calls = []

        @contextlib.contextmanager
        def counting():
            with shooter(False)() as shoot:
                yield lambda url, path: (calls.append(url), shoot(url, path))[1]

        self.run_stage(counting)
        self.assertEqual(calls, ["http://127.0.0.2:8081"])
        self.assertEqual(self.store.degradations(), [])

    def test_dry_run_takes_no_pictures(self):
        @contextlib.contextmanager
        def boom():
            raise AssertionError("dry run must not start a browser")
            yield

        result = self.run_stage(boom, dry_run=True)
        self.assertTrue(result["dry_run"])

    def test_capture_records_a_failure_without_raising(self):
        from extscan.screenshots import capture
        shot = Shot(url="http://127.0.0.2:8080", kind="service", service="x",
                    file="screenshots/x.png")

        def shoot(url, path):
            raise RuntimeError("net::ERR_CONNECTION_REFUSED\nmore")

        with contextlib.redirect_stdout(io.StringIO()):
            capture(self.store.path, [shot], shoot)
        self.assertEqual(shot.status, "failed")
        self.assertEqual(shot.error, "RuntimeError: net::ERR_CONNECTION_REFUSED")


if __name__ == "__main__":
    unittest.main()
