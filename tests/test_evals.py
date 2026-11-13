"""The evals in `evals/` hold their thresholds, and the skill matches the CLI.

These run on every test run, so detection quality, false positives, request
counts and the bookkeeping budgets are regressions the suite catches, not
numbers someone remembers to look at.
"""

import contextlib
import io
import json
import re
import shlex
import tempfile
import unittest
from pathlib import Path

from evals import bench, local, score

from extscan import cli
from extscan.policy import Policy

ROOT = Path(__file__).parent.parent
SKILLS = [ROOT / ".claude" / "skills" / "extscan" / "SKILL.md",
          ROOT / ".agents" / "skills" / "extscan" / "SKILL.md"]


class TestLabScorecard(unittest.TestCase):
    def expected_with(self, item: dict) -> Path:
        expected = json.loads(score.LAB.read_text())
        expected["must_find"].append(item)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "expected.json"
        path.write_text(json.dumps(expected))
        return path

    def test_fixture_run_meets_every_threshold(self):
        result = score.score(score.FIXTURE)
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["recall"], 1.0)

    def test_a_missing_item_with_no_gap_fails(self):
        path = self.expected_with({"id": "planted", "port": 1, "source": "extscan:none",
                                   "title": "never reported", "severity": "high"})
        result = score.score(score.FIXTURE, path)
        self.assertIn("planted", result["missed"])
        self.assertFalse(result["passed"])

    def test_a_missing_item_behind_a_recorded_gap_is_not_assessed(self):
        path = self.expected_with({"id": "shot", "port": 1, "source": "extscan:none",
                                   "title": "never reported", "severity": "info",
                                   "needs": "screenshot"})
        result = score.score(score.FIXTURE, path)
        self.assertEqual(result["missed"], [])
        self.assertEqual(len(result["not_assessed"]), 1)


class TestLocalDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = local.run()

    def test_every_planted_issue_is_found_at_its_severity(self):
        self.assertEqual(self.result["missed"], [])
        self.assertEqual(self.result["wrong_severity"], [])

    def test_clean_targets_produce_nothing_above_info(self):
        """Covers the single-page app that answers 200 for every path."""
        self.assertEqual(self.result["false_positives"], [])

    def test_request_and_time_budgets_hold(self):
        self.assertEqual(self.result["over_budget"], [])


class TestBudgets(unittest.TestCase):
    def test_marking_a_thousand_services_is_one_write(self):
        self.assertLess(bench.mark_probed_seconds(1000),
                        bench.BUDGETS["mark_probed_1000_services"])

    def test_silent_snmp_agent_costs_one_timeout_per_round(self):
        policy = Policy()
        policy.snmp.timeout_sec = 0.3
        policy.snmp.retries = 1
        self.assertLess(bench.snmp_silent_seconds(policy), bench.snmp_budget(policy))


def _skill_commands(text: str) -> list[str]:
    """Every `extscan ...` command line in the skill's bash blocks."""
    commands = []
    for block in re.findall(r"```bash\n(.*?)```", text, re.S):
        for line in block.replace("\\\n", " ").splitlines():
            line = line.split(" #")[0].strip()
            if line.startswith("extscan "):
                commands.append(line)
    return commands


class TestSkillMatchesTheCli(unittest.TestCase):
    def test_every_command_in_the_skill_parses(self):
        parser = cli.build_parser()
        for skill in SKILLS:
            if not skill.exists():
                continue
            commands = _skill_commands(skill.read_text())
            self.assertGreater(len(commands), 10, skill)
            for command in commands:
                argv = shlex.split(re.sub(r"<[a-z-]+>", "x", command))[1:]
                with self.subTest(skill=skill.parent.parent.parent.name, command=command), \
                        contextlib.redirect_stderr(io.StringIO()):
                    try:
                        parser.parse_args(argv)
                    except SystemExit:
                        self.fail(f"the skill names a command the CLI rejects: {command}")

    def test_skill_cases_are_well_formed(self):
        data = json.loads((ROOT / "evals" / "skill" / "evals.json").read_text())
        ids = [case["id"] for case in data["evals"]]
        self.assertEqual(len(ids), len(set(ids)))
        for case in data["evals"]:
            self.assertTrue(case["prompt"] and case["expectations"], case["id"])


if __name__ == "__main__":
    unittest.main()
