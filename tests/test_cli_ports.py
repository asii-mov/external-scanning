"""`--tcp-ports` picks the TCP range at init, and discovery scans exactly that."""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from extscan import cli
from extscan.policy import TCP_TOP


class TestTcpPortsOption(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.scope = self.tmp / "scope.json"
        self.scope.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["127.0.0.1/32"], "allow_private": True,
        }))
        self.runs = self.tmp / "runs"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scanned_ports(self, *init_args: str) -> str:
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--runs-dir", str(self.runs), "init", "--scope", str(self.scope),
                      "--id", "r", *init_args])
            cli.main(["--runs-dir", str(self.runs), "--dry-run", "discover", "r", "--tcp-only"])
        argv = json.loads((self.runs / "r" / "commands.jsonl").read_text().splitlines()[0])["argv"]
        return argv[argv.index("-p") + 1]

    def test_all_scans_every_port(self):
        self.assertEqual(self.scanned_ports("--tcp-ports", "all"), "1-65535")

    def test_quick_overrides_the_profile(self):
        self.assertEqual(self.scanned_ports("--profile", "thorough", "--tcp-ports", "quick"),
                         "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,"
                         "3389,5432,5900,6379,8000,8080,8443,9200,27017")

    def test_literal_list_is_passed_through(self):
        self.assertEqual(self.scanned_ports("--tcp-ports", "22,80,8000-8100"), "22,80,8000-8100")

    def test_default_is_the_profile_list(self):
        self.assertEqual(self.scanned_ports(), TCP_TOP)

    def test_rejects_anything_but_a_preset_or_port_list(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
            cli.main(["init", "--scope", str(self.scope), "--tcp-ports", "80 -iL /etc/hosts"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("use quick|top|all or a port list", err.getvalue())
        self.assertFalse(self.runs.exists())


if __name__ == "__main__":
    unittest.main()
