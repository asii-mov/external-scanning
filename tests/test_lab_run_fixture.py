"""The committed lab run still loads and renders with the current code.

tests/fixtures/lab-run is there so reporting work can happen without
scanners. If a schema change stops it loading, this fails first.
"""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

from extscan import pipeline
from extscan.scope import Scope
from extscan.store import Store

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "lab-run"


class TestLabRunFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(FIXTURE, self.tmp / "run")
        self.store = Store(self.tmp / "run")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_state_covers_tcp_and_udp(self):
        ports = {(s.port, s.proto) for s in self.store.services()}
        self.assertIn((8080, "tcp"), ports)
        self.assertIn((10161, "udp"), ports)
        self.assertEqual(self.store.degradations(), [])

    def test_report_rerenders_with_snmp_and_nuclei_findings(self):
        scope = Scope.load(ROOT / "examples" / "lab" / "scope.json")
        (self.store.path / "report.md").unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(self.store, scope)
        report = (self.store.path / "report.md").read_text()
        self.assertIn("SNMP readable with default community string `public`", report)
        self.assertIn("Redis Server - Unauthenticated Access", report)


if __name__ == "__main__":
    unittest.main()
