"""docs/CONFIGURATION.md lists every setting, and this keeps it that way.

A setting that exists and is not written down gets discovered by reading the
source, or not at all. So each policy key, scope key, command, flag and
environment variable in the code must have a row in the reference, and each
row must be for something that exists.
"""

import argparse
import dataclasses
import re
import unittest
from pathlib import Path

from extscan import cli
from extscan.policy import NMAP_EXTRA_FLAGS, NMAP_EXTRA_VALUE_FLAGS, Policy
from extscan.scope import AUTHORIZATION_KEYS, SCOPE_KEYS

ROOT = Path(__file__).parent.parent
DOC = (ROOT / "docs" / "CONFIGURATION.md").read_text()


def section(title: str) -> str:
    """The text under one `## title` heading."""
    match = re.search(rf"^## {re.escape(title)}\n(.*?)(?=^## |\Z)", DOC, re.M | re.S)
    assert match, f"docs/CONFIGURATION.md has no '## {title}' section"
    return match.group(1)


def first_cells(text: str) -> set[str]:
    """The backticked name that starts each table row."""
    return set(re.findall(r"^\| `([^`]+)` \|", text, re.M))


class TestPolicyReference(unittest.TestCase):
    def test_every_policy_key_has_a_row_and_every_row_is_a_key(self):
        policy = Policy.for_profile("standard")
        keys = set()
        for field in dataclasses.fields(Policy):
            value = getattr(policy, field.name)
            if dataclasses.is_dataclass(value):
                keys |= {f"{field.name}.{f.name}" for f in dataclasses.fields(value)}
            else:
                keys.add(field.name)
        documented = first_cells(section("Policy file")) - {"quick", "standard", "thorough"}
        self.assertEqual(documented, keys)

    def test_the_allowed_nmap_extra_args_are_all_listed(self):
        text = section("Policy file")
        ranged = {f"-T{n}" for n in range(1, 5)}       # written as "-T0 to -T5"
        for flag in (NMAP_EXTRA_FLAGS | NMAP_EXTRA_VALUE_FLAGS) - ranged:
            self.assertIn(f"`{flag}`", text, flag)

    def test_settings_that_do_nothing_cannot_be_turned_on(self):
        for data in ({"stop_on_tool_error": True}, {"recon": {"allow_bruteforce": True}}):
            with self.assertRaises(ValueError) as cm:
                Policy.from_dict(data)
            self.assertIn("not implemented", str(cm.exception))
        Policy.from_dict({"stop_on_tool_error": False, "recon": {"allow_bruteforce": False}})


class TestScopeReference(unittest.TestCase):
    def test_every_scope_key_has_a_row_and_every_row_is_a_key(self):
        keys = set(SCOPE_KEYS) | {f"authorization.{k}" for k in AUTHORIZATION_KEYS}
        self.assertEqual(first_cells(section("Scope file")), keys)


class TestCommandReference(unittest.TestCase):
    def setUp(self):
        parser = cli.build_parser()
        self.global_flags = {s for a in parser._actions for s in a.option_strings
                             if s.startswith("--") and s != "--help"}
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        self.commands = sub.choices
        self.text = section("Commands")

    def test_every_command_has_a_row_and_every_row_is_a_command(self):
        rows = first_cells(self.text)
        per_run = {"--scope", "--policy", "--profile"}
        self.assertEqual(rows - self.global_flags - per_run, set(self.commands))
        self.assertLessEqual(self.global_flags, rows)

    def test_every_flag_of_every_command_is_in_its_row(self):
        common = self.global_flags | {"--help"}
        for name, parser in self.commands.items():
            match = re.search(rf"^\| `{re.escape(name)}` \|(.*)$", self.text, re.M)
            self.assertIsNotNone(match, name)
            row = match.group(1) if match else ""
            takes_run = any(a.dest == "run" for a in parser._actions)
            for action in parser._actions:
                for flag in action.option_strings:
                    if not flag.startswith("--") or flag in common:
                        continue
                    if takes_run and flag in ("--scope", "--policy", "--profile"):
                        continue        # documented once, for every run command
                    self.assertIn(f"`{flag}`", row, f"{name} {flag}")
            # ... and the row names no flag the command does not have.
            real = {s for a in parser._actions for s in a.option_strings}
            for flag in re.findall(r"`(--[a-z-]+)`", row.split("|")[1]):
                self.assertIn(flag, real, f"{name} {flag}")


class TestEnvironmentReference(unittest.TestCase):
    def test_every_environment_variable_read_by_the_code_has_a_row(self):
        used = set()
        for path in (ROOT / "extscan").rglob("*.py"):
            source = path.read_text()
            used |= set(re.findall(r'environ(?:\.get|\.pop)?[\[(]\s*"([A-Z][A-Z0-9_]+)"', source))
            used |= set(re.findall(r'^[A-Z_]*ENV = "([A-Z][A-Z0-9_]+)"', source, re.M))
        self.assertTrue(used)
        self.assertLessEqual(used, first_cells(section("Environment variables")))


class TestReadmePointsAtWhatExists(unittest.TestCase):
    def test_every_file_the_readme_names_is_in_the_repo(self):
        readme = (ROOT / "README.md").read_text()
        named = set(re.findall(r"`((?:docs|examples|extscan|tests|scripts|evals)/[\w./-]+)`",
                               readme))
        self.assertGreater(len(named), 10)
        for rel in named:
            self.assertTrue((ROOT / rel).exists(), rel)

    def test_every_command_the_readme_shows_exists(self):
        readme = (ROOT / "README.md").read_text()
        parser = cli.build_parser()
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        code = "\n".join(re.findall(r"^```bash\n(.*?)^```", readme, re.M | re.S))
        shown = set(re.findall(r"^(?:uv run |sudo \S+/)?extscan (?:--\S+ \S+ )?([a-z]+)\b",
                               code, re.M))
        self.assertGreater(len(shown), 10)
        self.assertLessEqual(shown, set(sub.choices))


if __name__ == "__main__":
    unittest.main()
