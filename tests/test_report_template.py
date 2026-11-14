"""The report template: a team can change the layout, and cannot break the
report by doing so without being told."""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from extscan import cli, pipeline, template
from extscan.models import Finding, Service
from extscan.policy import Policy
from extscan.report import DEFAULT_TEMPLATE, TemplateError, load_template
from extscan.resilience import Degradation
from extscan.scope import Scope
from extscan.store import Store

REQUIRED = "{{coverage_gaps}}\n{{review_queue}}\n"


def render(text: str, **context) -> str:
    return template.render(template.parse(text), context)


class TestTemplateLanguage(unittest.TestCase):
    def test_values_and_dotted_names(self):
        self.assertEqual(render("# {{a}} / {{b.c}}\n", a="x", b={"c": "y"}), "# x / y\n")

    def test_if_keeps_or_drops_a_block_and_leaves_no_blank_lines(self):
        text = "top\n<!-- if gaps -->\n## Gaps\n{{gaps}}\n<!-- end -->\nbottom\n"
        self.assertEqual(render(text, gaps="one"), "top\n## Gaps\none\nbottom\n")
        self.assertEqual(render(text, gaps=""), "top\nbottom\n")

    def test_if_not(self):
        text = "<!-- if not items -->\nnone\n<!-- end -->\n"
        self.assertEqual(render(text, items=[]), "none\n")
        self.assertEqual(render(text, items=[1]), "\n")

    def test_each_repeats_and_nests(self):
        text = ("<!-- each g in groups -->\n## {{g.name}}\n"
                "<!-- each f in g.items -->\n- {{f.t}}\n<!-- end -->\n<!-- end -->\n")
        groups = [{"name": "A", "items": [{"t": "1"}, {"t": "2"}]},
                  {"name": "B", "items": []}]
        self.assertEqual(render(text, groups=groups), "## A\n- 1\n- 2\n## B\n")

    def test_notes_never_reach_the_output(self):
        self.assertEqual(render("<!--# for editors only -->\nbody\n"), "body\n")

    def test_substituted_text_is_not_read_as_template(self):
        # A page title the target chose must stay literal.
        hostile = "{{secret}} <!-- each x in y --> <!-- end -->"
        self.assertEqual(render("{{title}}\n", title=hostile, secret="LEAK"), hostile + "\n")

    def test_blank_lines_inside_code_fences_are_kept(self):
        evidence = "```text\na\n\n\n\nb\n```"
        self.assertEqual(render("x\n\n\n\n{{e}}\n", e=evidence), f"x\n\n{evidence}\n")

    def test_mistakes_are_errors_with_a_line_number(self):
        for text, needle in (
            ("{{nope}}", "no value named 'nope'"),
            ("{{a.b}}", "'a.b' does not exist"),
            ("line\n<!-- if a -->\nunclosed", "template:2"),
            ("<!-- end -->", "closes nothing"),
            ("<!-- each a -->x<!-- end -->", "each item in list"),
            ("{{ a b }}", "is not a name"),
            ("<!-- each x in a -->{{x}}<!-- end -->", "not a list"),
        ):
            with self.assertRaises(TemplateError, msg=text) as cm:
                render(text, a="scalar")
            self.assertIn(needle, str(cm.exception))


class TestLoadingATemplate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, text: str) -> Path:
        path = self.tmp / "layout.md"
        path.write_text(text)
        return path

    def test_the_built_in_template_loads(self):
        self.assertEqual(load_template().label, "built-in template")
        self.assertEqual(load_template("").label, "built-in template")

    def test_a_missing_file_is_an_error(self):
        with self.assertRaises(TemplateError) as cm:
            load_template(self.tmp / "absent.md")
        self.assertIn("cannot be read", str(cm.exception))

    def test_coverage_gaps_and_review_queue_cannot_be_dropped(self):
        for kept, missing in (("{{review_queue}}", "coverage_gaps"),
                              ("{{coverage_gaps}}", "review_queue")):
            with self.assertRaises(TemplateError) as cm:
                load_template(self.write(f"# {{{{engagement}}}}\n{kept}\n"))
            self.assertIn(missing, str(cm.exception))

    def test_an_unknown_name_is_caught_at_load_even_inside_a_branch_not_taken(self):
        text = REQUIRED + "<!-- if systemic -->\n{{finding.severty}}\n<!-- end -->\n"
        with self.assertRaises(TemplateError) as cm:
            load_template(self.write(text))
        self.assertIn("finding", str(cm.exception))

    def test_a_misspelt_finding_field_is_caught_and_the_fields_listed(self):
        text = REQUIRED + "<!-- each f in findings -->\n{{f.severty}}\n<!-- end -->\n"
        with self.assertRaises(TemplateError) as cm:
            load_template(self.write(text))
        self.assertIn("severity_label", str(cm.exception))

    def test_every_documented_name_exists(self):
        """docs/REPORT_TEMPLATE.md is what a team edits from: each name in
        its tables has to be one the report really provides."""
        import re

        from extscan.report import _sample_context
        doc = (Path(__file__).parent.parent / "docs" / "REPORT_TEMPLATE.md").read_text()
        sample = _sample_context()
        names = set(re.findall(r"^\| `\{\{([a-z_.]+)\}\}`", doc, re.M))
        self.assertGreater(len(names), 25)
        top = {n for n in names if "." not in n}
        self.assertEqual(top, set(sample) - {"findings", "severities"})
        finding = {n.split(".", 1)[1] for n in names if n.startswith("finding.")}
        self.assertEqual(finding, set(sample["findings"][0]))
        group = {n.split(".", 1)[1] for n in names if n.startswith("group.")}
        self.assertEqual(group | {"findings"}, set(sample["severities"][0]))


class TestReportsFollowTheTemplate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.scope_path = self.tmp / "scope.json"
        self.scope_path.write_text(json.dumps({
            "engagement": "Perimeter", "client": "Us",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["203.0.113.0/29"],
        }))
        self.scope = Scope.load(self.scope_path)
        self.runs = self.tmp / "runs"
        self.custom = self.tmp / "ours.md"
        self.custom.write_text(
            "# {{engagement}}: weekly perimeter check\n\n"
            "Owner: security-team\n\n"
            "## Not checked\n\n"
            "<!-- if not coverage_gaps -->\nEverything planned was checked.\n<!-- end -->\n"
            "{{coverage_gaps}}\n\n"
            "## For triage\n\n{{review_queue}}\n\n{{security_notes}}\n\n"
            "## Issues\n\n"
            "<!-- each f in findings -->\n"
            "- [{{f.severity_label}}] {{f.title}} ({{f.target}})\n"
            "<!-- end -->\n")

    def make_run(self, run_id: str, policy: Policy | None = None) -> Store:
        store = pipeline.init_run(str(self.runs), self.scope,
                                  policy or Policy.for_profile("standard"), run_id=run_id)
        store.save_services([Service(host="203.0.113.1", port=443, proto="tcp", name="https")])
        store.add_findings([Finding(title="Admin panel exposed", severity="high",
                                    host="203.0.113.1", port=443, source="extscan:http",
                                    review_required=True, review_reason="Is this meant?")])
        return store

    def cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--runs-dir", str(self.runs), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_default_report_has_the_handover_sections(self):
        store = self.make_run("d")
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(store, self.scope)
        md = (store.path / "report.md").read_text()
        for heading in ("## Manual review queue", "## Notes for the security team",
                        "## Findings", "## Methodology and limitations"):
            self.assertIn(heading, md)
        self.assertIn("Report layout: built-in template.", md)
        report = json.loads((store.path / "report.json").read_text())
        self.assertIn("unfinished_followups", report["security_notes"])

    def test_a_custom_template_changes_the_layout(self):
        store = self.make_run("c")
        code, _, err = self.cli("report", "c", "--template", str(self.custom))
        self.assertEqual((code, err), (0, ""))
        md = (store.path / "report.md").read_text()
        self.assertTrue(md.startswith("# Perimeter: weekly perimeter check\n"))
        self.assertIn("Owner: security-team", md)
        self.assertIn("Everything planned was checked.", md)
        self.assertIn("- [High] Admin panel exposed (203.0.113.1:443/tcp)", md)
        self.assertNotIn("## Service inventory", md)
        self.assertLess(md.index("## Not checked"), md.index("## Issues"))

    def test_gaps_show_up_wherever_the_template_put_them(self):
        store = self.make_run("g")
        store.add_degradation(Degradation(stage="discover:udp", component="nmap",
                                          reason="r", impact="No UDP scanning was performed.",
                                          severity="serious"))
        self.cli("report", "g", "--template", str(self.custom))
        md = (store.path / "report.md").read_text()
        self.assertIn("No UDP scanning was performed.", md)
        self.assertNotIn("Everything planned was checked.", md)

    def test_the_policy_names_the_template_and_later_reports_keep_using_it(self):
        policy = Policy.from_dict({"report": {"template": str(self.custom)}})
        store = self.make_run("p", policy)
        code, _, _ = self.cli("report", "p")
        self.assertEqual(code, 0)
        md = (store.path / "report.md").read_text()
        self.assertTrue(md.startswith("# Perimeter: weekly perimeter check\n"))

    def test_a_broken_template_stops_the_run_before_anything_is_scanned(self):
        self.custom.write_text("# {{engagement}}\n{{review_queue}}\n")   # no coverage_gaps
        code, _, err = self.cli("run", "--scope", str(self.scope_path),
                                "--template", str(self.custom))
        self.assertEqual(code, 2)
        self.assertIn("report template error", err)
        self.assertIn("coverage_gaps", err)
        self.assertFalse(self.runs.exists() and any(self.runs.iterdir()))

    def test_a_broken_template_leaves_the_previous_report_in_place(self):
        store = self.make_run("k")
        self.cli("report", "k")
        before = (store.path / "report.md").read_text()
        self.custom.write_text(REQUIRED + "{{no_such_section}}\n")
        code, _, err = self.cli("report", "k", "--template", str(self.custom))
        self.assertEqual(code, 2)
        self.assertIn("no_such_section", err)
        self.assertEqual((store.path / "report.md").read_text(), before)

    def test_template_command_writes_a_copy_and_checks_it(self):
        out = self.tmp / "copy.md"
        self.assertEqual(self.cli("template", "--out", str(out))[0], 0)
        self.assertEqual(out.read_text(), DEFAULT_TEMPLATE.read_text())
        self.assertEqual(self.cli("template", "--out", str(out))[0], 2)     # no overwrite
        self.assertEqual(self.cli("template", "--check", str(out))[0], 0)
        out.write_text("{{review_queue}}")
        code, _, err = self.cli("template", "--check", str(out))
        self.assertEqual(code, 2)
        self.assertIn("coverage_gaps", err)


if __name__ == "__main__":
    unittest.main()
