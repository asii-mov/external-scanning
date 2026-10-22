"""A tool that fails or is absent must leave a coverage gap, never a clean pass.

Each test drives the real stage with a broken or missing tool on PATH and
checks the two things a report reader depends on: the gap is recorded, and
the service is not marked as covered (so `resume` tries it again).
"""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from extscan import pipeline, probes
from extscan.models import Service
from extscan.policy import Policy
from extscan.runner import Runner
from extscan.scope import Scope
from extscan.store import Store
from extscan.tools import nmap


class _Stage(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["127.0.0.1/32"], "allow_private": True,
        }))
        self.scope = Scope.load(sp)
        self.store = Store.create(self.tmp / "runs", "t", run_id="r")
        self.store.write_meta({"run_id": "r"})
        self.runner = Runner(self.store)
        self.policy = Policy()
        self.policy.http.timeout_sec = 1

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_tool(self, name: str, script: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{script}\n")
        path.chmod(0o755)

    def only_fake_tools_on_path(self):
        return mock.patch.dict(os.environ, {"PATH": str(self.bin)})

    def probe(self, svc: Service, only: list[str]):
        self.store.save_services([svc])
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.probe(self.store, self.scope, self.policy, self.runner, only=only)
        return self.store.services()[0]

    def gaps(self):
        return [(d.stage, d.component, d.hosts) for d in self.store.degradations()]


class TestNucleiFailure(_Stage):
    web = Service(host="127.0.0.1", port=9, proto="tcp", name="http")

    def test_killed_nuclei_is_a_gap_and_services_stay_unprobed(self):
        self.fake_tool("nuclei", "kill -9 $$")
        with self.only_fake_tools_on_path():
            svc = self.probe(self.web, only=["nuclei"])
        self.assertEqual(self.gaps(), [("probe:nuclei", "nuclei", ["127.0.0.1"])])
        self.assertEqual(self.store.degradations()[0].severity, "serious")
        self.assertNotIn("nuclei", svc.probed_by)

    def test_missing_nuclei_is_a_gap(self):
        with self.only_fake_tools_on_path():
            svc = self.probe(self.web, only=["nuclei"])
        self.assertEqual(self.gaps(), [("probe:nuclei", "nuclei", ["127.0.0.1"])])
        self.assertNotIn("nuclei", svc.probed_by)

    def test_clean_nuclei_marks_services_probed(self):
        self.fake_tool("nuclei", "exit 0")
        with self.only_fake_tools_on_path():
            svc = self.probe(self.web, only=["nuclei"])
        self.assertEqual(self.gaps(), [])
        self.assertEqual(svc.probed_by, ["nuclei"])


class TestFuzzerFindings(_Stage):
    """Minimized cases from tests/fuzz_failures.py."""

    def test_realtime_signal_is_a_gap_not_a_crash(self):
        self.fake_tool("nuclei", "kill -35 $$")
        with self.only_fake_tools_on_path():
            svc = self.probe(TestNucleiFailure.web, only=["nuclei"])
        self.assertEqual([d.reason for d in self.store.degradations()],
                         ["nuclei killed by signal 35"])
        self.assertNotIn("nuclei", svc.probed_by)

    def test_partial_utf8_in_killed_nuclei_output_is_a_gap_not_a_crash(self):
        self.fake_tool("nuclei", 'while [ $# -gt 0 ]; do [ "$1" = -output ] && '
                                 "printf '\\200' > \"$2\"; shift; done; kill -9 $$")
        with self.only_fake_tools_on_path():
            svc = self.probe(TestNucleiFailure.web, only=["nuclei"])
        self.assertEqual([d.reason for d in self.store.degradations()],
                         ["nuclei killed by SIGKILL"])
        self.assertNotIn("nuclei", svc.probed_by)

    def test_failing_sslscan_is_a_gap(self):
        self.fake_tool("sslscan", "exit 1")
        svc = Service(host="127.0.0.1", port=8443, proto="tcp", name="https")
        with self.only_fake_tools_on_path():
            after = self.probe(svc, only=["sslscan"])
        self.assertEqual(self.gaps(), [("probe:sslscan", "sslscan", ["127.0.0.1"])])
        self.assertNotIn("sslscan", after.probed_by)

    def test_unparseable_nmap_xml_is_a_gap_not_a_crash(self):
        xml = bytearray((Path(__file__).parent / "fixtures" / "nmap-tcp.xml").read_bytes())
        xml[0] = 0
        (self.tmp / "out.xml").write_bytes(bytes(xml))
        self.fake_tool("nmap", 'while [ $# -gt 0 ]; do [ "$1" = -oA ] && '
                               f'/bin/cp {self.tmp}/out.xml "$2.xml"; shift; done; exit 0')
        with self.only_fake_tools_on_path(), contextlib.redirect_stdout(io.StringIO()):
            pipeline.discover(self.store, self.scope, self.policy, self.runner, udp=False)
        self.assertEqual(self.gaps(), [("discover:tcp", "nmap", ["127.0.0.1"])])


class TestProbeFailure(_Stage):
    def test_crashing_probe_is_a_gap_and_retried_next_run(self):
        svc = Service(host="127.0.0.1", port=22, proto="tcp", name="ssh")
        ssh = next(p for p in probes.REGISTRY if p.name == "ssh")
        with mock.patch.object(ssh, "run", side_effect=RuntimeError("boom")):
            after = self.probe(svc, only=["ssh"])
        self.assertEqual(self.gaps(), [("probe:ssh", "ssh", ["127.0.0.1"])])
        self.assertNotIn("ssh", after.probed_by)

        after = self.probe(svc, only=["ssh"])
        self.assertEqual(after.probed_by, ["ssh"])

    def test_missing_sslscan_is_a_gap(self):
        svc = Service(host="127.0.0.1", port=8443, proto="tcp", name="https")
        with self.only_fake_tools_on_path():
            after = self.probe(svc, only=["sslscan"])
        self.assertEqual(self.gaps(), [("probe:sslscan", "sslscan", ["127.0.0.1"])])
        self.assertNotIn("sslscan", after.probed_by)


class TestUnprivilegedUdp(_Stage):
    def test_tcp_only_notice_comes_before_the_scan(self):
        out = io.StringIO()
        with mock.patch.object(nmap, "udp_requires_root", return_value=True), \
                contextlib.redirect_stdout(out):
            pipeline.discover(self.store, self.scope, self.policy,
                              Runner(self.store, dry_run=True))
        lines = out.getvalue().splitlines()
        notice = "Not running as root: this run is TCP only."
        self.assertIn(notice, lines)
        self.assertLess(lines.index(notice), lines.index("→ nmap TCP discovery"))
        self.assertIn("  Re-run as root to add UDP: sudo extscan discover r --udp-only", lines)
        self.assertEqual(self.gaps(), [("discover:udp", "nmap", [])])

    def test_root_rerun_clears_the_udp_gap(self):
        dry = Runner(self.store, dry_run=True)
        with contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(nmap, "udp_requires_root", return_value=True):
                pipeline.discover(self.store, self.scope, self.policy, dry)
            with mock.patch.object(nmap, "udp_requires_root", return_value=False):
                pipeline.discover(self.store, self.scope, self.policy, dry,
                                  tcp=False, udp=True)
        self.assertEqual(self.gaps(), [])


class TestNseScriptSelection(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["203.0.113.1/32"],
        }))
        self.scope = Scope.load(sp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def script_arg(self, argv: list[str]) -> str:
        return argv[argv.index("--script") + 1]

    def test_default_excludes_dos_external_and_slowloris(self):
        argv = nmap.tcp_argv(self.scope, Policy(), "out")
        self.assertEqual(self.script_arg(argv),
                         "(default or safe or vuln) and not "
                         "(dos or external or http-slowloris-check)")

    def test_udp_pass_applies_the_same_exclusions(self):
        argv = nmap.udp_argv(self.scope, Policy(), "out")
        self.assertEqual(self.script_arg(argv),
                         "(default or safe) and not "
                         "(dos or external or http-slowloris-check)")

    def test_empty_exclusion_passes_scripts_through(self):
        policy = Policy()
        policy.nmap.exclude_scripts = []
        argv = nmap.tcp_argv(self.scope, policy, "out")
        self.assertEqual(self.script_arg(argv), "default,safe,vuln")


if __name__ == "__main__":
    unittest.main()
