"""Discovery must say what it did not see, and must not pay for empty space.

Planted cases, each driven through the real stage with a fake `nmap` or
`nuclei` on PATH (`evals/discovery.py` holds the fake nmap, which answers
from a JSON "world" the test can change between runs):

* addresses that did not answer host discovery become one gap per pass;
* nmap's own "I lost accuracy" lines become gaps naming the hosts;
* UDP `open|filtered` is kept as a service and flagged as unconfirmed;
* two-phase discovery fingerprints only hosts with open ports;
* nuclei batches are checkpointed one by one;
* a recon dry run asks nothing and stores nothing.
"""

import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from evals import discovery as fake
from evals import score

from extscan import discovery, pipeline
from extscan.models import Service
from extscan.policy import Policy
from extscan.resilience import RunAborted
from extscan.runner import Runner
from extscan.scope import Scope
from extscan.store import Store
from extscan.tools import nmap, nuclei, subdomains
from tests.test_dns import FakeDns

TCP = discovery.TCP

NET = "203.0.113"

# The two-phase cases: three hosts with open ports, one that is up with
# nothing open, in a /26.
SPARSE = {"open": {f"{NET}.3": [22, 80], f"{NET}.5": [443], f"{NET}.40": [8080]},
          "up": [f"{NET}.9"]}
# For the nmap.parallel cases: a /26 with a bit of everything that leaves a mark.
PARALLEL_WORLD = {
    "open": {f"{NET}.3": [22, 80], f"{NET}.5": [443], f"{NET}.40": [8080],
             f"{NET}.41": [25], f"{NET}.58": [22]},
    "up": [f"{NET}.9", f"{NET}.30"],
    "udp": {f"{NET}.3": {"161": "open"}, f"{NET}.50": {"161": "open|filtered"}},
    "retransmit": [f"{NET}.5"], "host_timeout": [f"{NET}.41"],
    "fail": ["tcp-0006", "udp-0002"], "cut_short": ["tcp-0011"],
}
PLANTED = [(f"{NET}.3", 22, "http"), (f"{NET}.3", 80, "http"),
           (f"{NET}.40", 8080, "http"), (f"{NET}.5", 443, "http")]


class _Case(unittest.TestCase):
    target = f"{NET}.0/28"          # 14 addresses, .1 to .14

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"
        self.world, self.log = self.tmp / "world.json", self.tmp / "calls.jsonl"
        fake.install_fake_nmap(self.bin, self.world, self.log)
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": [self.target], "allow_private": True,
        }))
        self.scope = Scope.load(sp)
        self.store = Store.create(self.tmp / "runs", "t", run_id="r")
        self.store.write_meta({"run_id": "r"})
        self.policy = Policy()

    def set_world(self, **facts):
        fake.write_world(self.world, **facts)

    def discover(self, dry_run=False, **kwargs) -> str:
        kwargs.setdefault("udp", False)
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}), \
                mock.patch.object(nmap, "udp_requires_root", return_value=False), \
                contextlib.redirect_stdout(out):
            pipeline.discover(self.store, self.scope, self.policy,
                              Runner(self.store, dry_run=dry_run), **kwargs)
        return out.getvalue()

    def calls(self) -> list[dict]:
        return fake.calls(self.log)

    def new_calls(self) -> list[dict]:
        """Calls since the last time this was asked."""
        made = self.calls()
        seen, self._seen = getattr(self, "_seen", 0), len(made)
        return made[seen:]

    def gaps(self, component: str | None = None):
        return [d for d in self.store.degradations()
                if component is None or d.component == component]

    def reasons(self) -> list[str]:
        return [d.reason for d in self.store.degradations()]


class TestDiscoveryProbes(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": [f"{NET}.0/28"],
        }))
        self.scope = Scope.load(sp)
        self.policy = Policy()

    def probes(self, argv: list[str]) -> list[str]:
        return [a for a in argv if a.startswith("-P")]

    def test_root_sends_every_probe(self):
        with mock.patch.object(nmap, "_is_root", return_value=True):
            argv = nmap.tcp_argv(self.scope, self.policy, "out")
        self.assertEqual(self.probes(argv), self.policy.nmap.discovery_probes)
        self.assertEqual({a[:3] for a in self.probes(argv)},
                         {"-PE", "-PP", "-PS", "-PA", "-PU"})

    def test_unprivileged_sends_only_the_connect_probes(self):
        with mock.patch.object(nmap, "_is_root", return_value=False):
            argv = nmap.tcp_argv(self.scope, self.policy, "out")
        [probe] = self.probes(argv)
        self.assertTrue(probe.startswith("-PS"))
        # More than nmap's unprivileged default of 80 and 443.
        self.assertGreater(len(probe.split(",")), 10)

    def test_skip_host_discovery_wins(self):
        self.policy.nmap.skip_host_discovery = True
        with mock.patch.object(nmap, "_is_root", return_value=True):
            for build in (nmap.tcp_argv, nmap.udp_argv, nmap.sweep_argv):
                self.assertEqual(self.probes(build(self.scope, self.policy, "out")), ["-Pn"])

    def test_udp_and_sweep_get_the_same_probes(self):
        with mock.patch.object(nmap, "_is_root", return_value=True):
            for build in (nmap.udp_argv, nmap.sweep_argv):
                self.assertEqual(self.probes(build(self.scope, self.policy, "out")),
                                 self.policy.nmap.discovery_probes)

    def test_anything_but_a_probe_flag_is_refused(self):
        for bad in ("--script=exploit", "-Pn", "-PS22 --min-rate 9999", "-iL"):
            self.policy.nmap.discovery_probes = ["-PE", bad]
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "discovery_probes"):
                nmap.tcp_argv(self.scope, self.policy, "out")

    def test_sweep_does_ports_only(self):
        argv = nmap.sweep_argv(self.scope, self.policy, "out", targets=[f"{NET}.1"])
        self.assertNotIn("-sV", argv)
        self.assertNotIn("--script", argv)
        self.assertIn("-n", argv)
        full = nmap.tcp_argv(self.scope, self.policy, "out", targets=[f"{NET}.1"])
        for flag in ("-p", "--max-retries", "--host-timeout"):
            self.assertEqual(argv[argv.index(flag) + 1], full[full.index(flag) + 1])
        self.assertIn(self.policy.nmap.timing, argv)

    def test_phase_two_goes_straight_to_the_open_ports(self):
        argv = nmap.tcp_argv(self.scope, self.policy, "out", targets=[f"{NET}.1"],
                             ports="22,80", assume_up=True)
        self.assertEqual(argv[argv.index("-p") + 1], "22,80")
        self.assertEqual(self.probes(argv), ["-Pn"])
        self.assertIn("-sV", argv)

    def test_port_spec_is_compact(self):
        self.assertEqual(nmap.port_spec([443, 80, 81, 82, 22, 80]), "22,80-82,443")
        self.assertEqual(nmap.port_spec([]), "")

    def test_new_knobs_are_policy_fields(self):
        p = Policy.from_dict({"nmap": {"sweep": "always", "sweep_chunk_size": 64,
                                       "discovery_probes": ["-PS443"]},
                              "nuclei": {"batch_size": 5}})
        self.assertEqual((p.nmap.sweep, p.nmap.sweep_chunk_size, p.nmap.discovery_probes,
                          p.nuclei.batch_size), ("always", 64, ["-PS443"], 5))
        self.assertEqual((Policy().nmap.sweep, Policy().nuclei.batch_size), ("auto", 25))

    def test_unknown_sweep_mode_is_refused(self):
        self.policy.nmap.sweep = "sometimes"
        with self.assertRaisesRegex(ValueError, "auto, always or never"):
            discovery.two_phase(self.scope, self.policy)


class TestUnresponsiveHosts(_Case):
    """14 addresses in batches of 4; three of them answer."""

    def setUp(self):
        super().setUp()
        self.policy.nmap.sweep = "never"
        self.policy.nmap.chunk_size = 4
        self.live = {"open": {f"{NET}.2": [80], f"{NET}.7": [22]}, "up": [f"{NET}.13"]}

    def test_one_gap_for_the_whole_pass(self):
        self.set_world(**self.live)
        out = self.discover()
        self.assertEqual(len(self.calls()), 4)
        [gap] = self.gaps()
        self.assertEqual((gap.stage, gap.component, gap.severity),
                         ("discover:tcp", discovery.HOST_DISCOVERY, "warning"))
        self.assertEqual(gap.reason, "11 of 14 addresses did not answer host discovery")
        self.assertIn("did not port-scan", gap.impact)
        self.assertIn("nmap.skip_host_discovery", gap.remedy)
        self.assertIn("! 11 of 14 addresses", out)

    def test_resume_still_counts_the_batches_it_skips(self):
        self.set_world(**self.live, fail=["nmap-tcp-0002"])
        self.discover()
        self.assertIn("8 of 10 addresses did not answer host discovery", self.reasons())
        self.new_calls()
        self.set_world(**self.live)
        self.discover(resume=True)
        self.assertEqual([c["targets"] for c in self.new_calls()],
                         [[f"{NET}.{i}" for i in (5, 6, 7, 8)]])
        self.assertEqual(self.reasons(), ["11 of 14 addresses did not answer host discovery"])

    def test_the_gap_follows_a_rerun_and_goes_when_every_address_answers(self):
        self.set_world(**self.live)
        self.discover()
        self.set_world(open=self.live["open"], up=[f"{NET}.13", f"{NET}.14"])
        self.discover()
        self.assertEqual(self.reasons(), ["10 of 14 addresses did not answer host discovery"])
        self.set_world(open=self.live["open"], up=self.scope.hosts())
        self.discover()
        self.assertEqual(self.reasons(), [])

    def test_no_gap_when_host_discovery_is_skipped(self):
        self.set_world(**self.live)
        self.discover()
        self.assertEqual(len(self.gaps()), 1)
        self.policy.nmap.skip_host_discovery = True
        self.discover()
        self.assertIn("-Pn", self.calls()[-1]["argv"])
        self.assertEqual(self.reasons(), [])

    def test_a_dry_run_leaves_the_gap_alone(self):
        self.set_world(**self.live)
        self.discover()
        before = self.reasons()
        self.set_world(open={}, up=self.scope.hosts())
        self.discover(dry_run=True)
        self.assertEqual(self.reasons(), before)

    def test_counts_come_from_runstats(self):
        xml = ('<nmaprun><runstats><finished/><hosts up="3" down="9" total="12"/>'
               "</runstats></nmaprun>")
        self.assertEqual(nmap.host_counts(xml), {"up": 3, "down": 9, "total": 12})
        self.assertIsNone(nmap.host_counts("<nmaprun></nmaprun>"))
        self.assertIsNone(nmap.host_counts("<nmaprun><host>"))


class TestNmapAccuracyWarnings(_Case):
    def setUp(self):
        super().setUp()
        self.policy.nmap.skip_host_discovery = True     # keep the host-discovery gap out
        self.open = {f"{NET}.2": [80], f"{NET}.7": [22]}

    def test_retransmission_cap_is_a_gap_naming_the_host_and_clears(self):
        self.set_world(open=self.open, retransmit=[f"{NET}.7"])
        self.discover()
        [gap] = self.gaps()
        self.assertEqual(gap.reason,
                         "tcp-0001 gave up on ports of 1 host(s): retransmission cap hit")
        self.assertEqual((gap.stage, gap.hosts), ("discover:tcp", [f"{NET}.7"]))
        self.assertIn("nmap.max_retries", gap.remedy)
        self.assertIn("rate", gap.remedy)
        self.set_world(open=self.open)
        self.discover()
        self.assertEqual(self.gaps(), [])

    def test_host_timeout_is_a_gap_naming_the_host_and_clears(self):
        self.set_world(open=self.open, host_timeout=[f"{NET}.2"])
        self.discover()
        [gap] = self.gaps()
        self.assertEqual(gap.reason, "tcp-0001 skipped 1 host(s): host timeout")
        self.assertEqual((gap.hosts, gap.severity), ([f"{NET}.2"], "serious"))
        self.assertIn("nmap.host_timeout", gap.remedy)
        self.set_world(open=self.open)
        self.discover(resume=True)      # the batch was checkpointed: nothing re-runs
        self.assertEqual(len(self.gaps()), 1)
        self.discover()
        self.assertEqual(self.gaps(), [])

    def test_host_timeout_is_also_read_from_the_xml(self):
        self.set_world(open=self.open, timedout_xml=[f"{NET}.9"])
        self.discover()
        self.assertEqual([(d.reason, d.hosts) for d in self.gaps()],
                         [("tcp-0001 skipped 1 host(s): host timeout", [f"{NET}.9"])])

    def test_both_sources_naming_one_host_are_one_entry(self):
        self.set_world(open=self.open, host_timeout=[f"{NET}.9"], timedout_xml=[f"{NET}.9"])
        self.discover()
        self.assertEqual([d.hosts for d in self.gaps()], [[f"{NET}.9"]])

    def test_a_batch_cut_short_is_reported_once(self):
        self.set_world(open=self.open, retransmit=[f"{NET}.7"], cut_short=["nmap-tcp-0001"])
        self.discover()
        self.assertEqual(self.reasons(), ["tcp-0001 did not finish (exit 1)"])

    def test_only_addresses_in_scope_are_believed(self):
        stdout = ("Warning: 198.51.100.9 giving up on port because retransmission cap hit (2).\n"
                  f"Warning: {NET}.3 giving up on port because retransmission cap hit (2).\n"
                  "Warning: $(reboot) giving up on port because retransmission cap hit (2).\n"
                  f"Skipping host www.client.example ({NET}.4) due to host timeout\n"
                  f"Skipping host {NET}.5 due to host timeout\n"
                  "Skipping host evil (198.51.100.1) due to host timeout\n")
        self.assertEqual(nmap.accuracy_warnings(stdout, "", self.scope),
                         {"retransmission": [f"{NET}.3"],
                          "host_timeout": [f"{NET}.4", f"{NET}.5"]})


class TestUdpOpenFiltered(_Case):
    def setUp(self):
        super().setUp()
        self.policy.nmap.skip_host_discovery = True
        self.policy.nmap.udp_ports = "123,161"

    def unconfirmed(self):
        return self.gaps(discovery.OPEN_FILTERED)

    def test_kept_as_a_service_and_recorded_as_unconfirmed(self):
        self.set_world(udp={f"{NET}.2": {"161": "open|filtered", "123": "open"},
                            f"{NET}.7": {"161": "open|filtered", "123": "open|filtered"}})
        self.discover(tcp=False, udp=True)
        states = {(s.host, s.port): s.state for s in self.store.services()}
        self.assertEqual(states[(f"{NET}.2", 161)], "open|filtered")
        self.assertEqual(states[(f"{NET}.2", 123)], "open")
        self.assertEqual(len(states), 4)
        [gap] = self.unconfirmed()
        self.assertEqual(gap.reason,
                         "3 UDP port(s) on 2 host(s) were open|filtered (unconfirmed)")
        self.assertEqual((gap.stage, gap.hosts, gap.severity),
                         ("discover:udp", [f"{NET}.2", f"{NET}.7"], "warning"))
        self.assertIn("may not be open", gap.impact)
        self.assertEqual(self.gaps(), [gap])

    def test_updates_and_clears_on_a_rerun(self):
        self.set_world(udp={f"{NET}.2": {"161": "open|filtered"},
                            f"{NET}.7": {"161": "open|filtered"}})
        self.discover(tcp=False, udp=True)
        self.set_world(udp={f"{NET}.2": {"161": "open"}, f"{NET}.7": {"161": "open|filtered"}})
        self.discover(tcp=False, udp=True)
        self.assertEqual([(d.reason, d.hosts) for d in self.unconfirmed()],
                         [("1 UDP port(s) on 1 host(s) were open|filtered (unconfirmed)",
                           [f"{NET}.7"])])
        self.set_world(udp={f"{NET}.2": {"161": "open"}, f"{NET}.7": {"161": "open"}})
        self.discover(tcp=False, udp=True)
        self.assertEqual(self.gaps(), [])

    def test_same_count_on_a_different_host_names_the_new_host(self):
        self.set_world(udp={f"{NET}.2": {"161": "open|filtered"}})
        self.discover(tcp=False, udp=True)
        self.set_world(udp={f"{NET}.7": {"161": "open|filtered"}})
        self.discover(tcp=False, udp=True)
        self.assertEqual([d.hosts for d in self.unconfirmed()], [[f"{NET}.7"]])

    def test_udp_stays_single_phase(self):
        self.policy.nmap.sweep = "always"
        self.set_world(udp={f"{NET}.2": {"161": "open"}})
        self.discover(tcp=False, udp=True)
        self.assertEqual([(c["udp"], c["sV"]) for c in self.calls()], [(True, True)])


class TestTwoPhase(_Case):
    """62 addresses: sweep batches of 32, full-scan batches of 8."""

    target = f"{NET}.0/26"

    def setUp(self):
        super().setUp()
        self.policy.nmap.chunk_size = 8
        self.policy.nmap.sweep_chunk_size = 32
        self.batch_two = [f"{NET}.{i}" for i in range(33, 63)]

    def full_scans(self, calls=None):
        return [c for c in (self.calls() if calls is None else calls) if c["sV"]]

    def services(self):
        return sorted((s.host, s.port, s.name) for s in self.store.services())

    def test_only_hosts_with_open_ports_are_fingerprinted_on_the_union_of_ports(self):
        self.set_world(**SPARSE)
        self.discover()
        sweeps = [c for c in self.calls() if not c["sV"]]
        self.assertEqual([len(c["targets"]) for c in sweeps], [32, 30])
        self.assertTrue(all("-n" in c["argv"] and "--script" not in c["argv"] for c in sweeps))
        self.assertEqual(self.calls()[:2], sweeps)       # the sweep comes first

        full = self.full_scans()
        self.assertEqual([c["targets"] for c in full], [[f"{NET}.3", f"{NET}.5"], [f"{NET}.40"]])
        self.assertEqual([c["argv"][c["argv"].index("-p") + 1] for c in full],
                         ["22,80,443", "8080"])
        self.assertTrue(all("-Pn" in c["argv"] for c in full))
        self.assertEqual(self.services(), PLANTED)

    def test_a_host_with_nothing_open_costs_no_phase_two_work(self):
        self.set_world(**SPARSE)
        self.discover()
        fingerprinted = {t for c in self.full_scans() for t in c["targets"]}
        self.assertEqual(fingerprinted, set(SPARSE["open"]))
        self.assertNotIn(f"{NET}.9", fingerprinted)      # up, nothing open
        self.assertNotIn(f"{NET}.10", fingerprinted)     # never answered

    def test_no_live_hosts_means_no_phase_two_at_all(self):
        self.set_world(up=[f"{NET}.9"])
        self.discover()
        self.assertEqual(self.full_scans(), [])
        self.assertEqual(self.reasons(), ["61 of 62 addresses did not answer host discovery"])

    def test_sweep_output_is_kept_apart_from_scan_results(self):
        self.set_world(**SPARSE)
        self.discover()
        raw = sorted(p.name for p in self.store.raw.glob("*.xml"))
        self.assertEqual(raw, ["nmap-tcp-0001-01.xml", "nmap-tcp-0002-01.xml",
                               "sweep-tcp-0001.xml", "sweep-tcp-0002.xml"])
        # evals/score.py re-reads nmap-*.xml as findings; a sweep is not one.
        self.assertEqual(len(list(self.store.raw.glob("nmap-*.xml"))), 2)
        stages = [c["stage"] for c in self.store.commands()]
        self.assertEqual(stages, ["discover:sweep-tcp-0001", "discover:sweep-tcp-0002",
                                  "discover:tcp-0001-01", "discover:tcp-0002-01"])
        # The vault's discovery narrative quotes the first discover:tcp command.
        quoted = next(c for c in self.store.commands() if "discover:tcp" in c["stage"])
        self.assertIn("-sV", quoted["argv"])

    def test_the_sweeps_unresponsive_hosts_and_warnings_are_gaps(self):
        self.set_world(**SPARSE, retransmit=[f"{NET}.5"], host_timeout=[f"{NET}.44"])
        self.discover()
        self.assertEqual(
            sorted((d.stage, d.reason, d.hosts) for d in self.store.degradations()),
            [("discover:sweep", "58 of 62 addresses did not answer host discovery", []),
             ("discover:sweep", "sweep-tcp-0001 gave up on ports of 1 host(s): "
                                "retransmission cap hit", [f"{NET}.5"]),
             ("discover:sweep", "sweep-tcp-0002 skipped 1 host(s): host timeout",
              [f"{NET}.44"]),
             ("discover:tcp", "tcp-0001-01 gave up on ports of 1 host(s): "
                              "retransmission cap hit", [f"{NET}.5"])])
        self.set_world(open=SPARSE["open"], up=self.scope.hosts())
        self.discover()
        self.assertEqual(self.reasons(), [])

    def test_a_failed_sweep_batch_is_a_gap_and_its_hosts_get_the_full_scan(self):
        self.set_world(**SPARSE, fail=["sweep-tcp-0002", "nmap-tcp-0002-03-full"])
        self.discover()
        by_reason = {d.reason: d for d in self.store.degradations()}
        sweep_gap = by_reason["sweep-tcp-0002 produced no parseable output (exit 1)"]
        self.assertEqual((sweep_gap.stage, sweep_gap.severity, sweep_gap.hosts),
                         ("discover:sweep", "serious", self.batch_two))
        # Not dropped: every host of the failed batch went to a full scan,
        # all ports and with host discovery, since nothing is known about them.
        fallback = [c for c in self.full_scans() if "-full" in c["base"]]
        self.assertEqual([t for c in fallback for t in c["targets"]], self.batch_two)
        all_ports = self.policy.nmap.tcp_ports
        self.assertTrue(all(c["argv"][c["argv"].index("-p") + 1] == all_ports
                            and "-Pn" not in c["argv"] for c in fallback))
        self.assertIn((f"{NET}.40", 8080, "http"), self.services())
        # The part of the fallback that failed is a gap of its own.
        failed = by_reason["tcp-0002-03-full produced no parseable output (exit 1)"]
        self.assertEqual(failed.hosts, self.batch_two[16:24])

        # Resume sweeps the failed batch again, then scans what it finds.
        self.new_calls()
        self.set_world(**SPARSE)
        self.discover(resume=True)
        again = self.new_calls()
        self.assertEqual([(c["sV"], c["targets"]) for c in again],
                         [(False, self.batch_two), (True, [f"{NET}.40"])])
        self.assertEqual(self.reasons(), ["58 of 62 addresses did not answer host discovery"])
        self.assertEqual(self.services(), PLANTED)

    def test_a_failed_sweep_batch_fully_covered_by_the_full_scan_leaves_no_gap(self):
        self.set_world(**SPARSE, fail=["sweep-tcp-0002"])
        out = self.discover()
        self.assertIn("batch failed; 30 host(s) not covered by the sweep", out)
        self.assertEqual(self.services(), PLANTED)
        self.assertEqual(sorted(self.reasons()),
                         ["29 of 30 addresses did not answer host discovery",     # full scans
                          "29 of 32 addresses did not answer host discovery"])    # sweep 1
        self.new_calls()
        self.discover(resume=True)       # nothing left to do, sweep included
        self.assertEqual(self.new_calls(), [])

    def test_resume_works_across_both_phases(self):
        self.set_world(**SPARSE, fail=["nmap-tcp-0001-01"])
        self.discover()
        self.assertIn("tcp-0001-01 produced no parseable output (exit 1)", self.reasons())
        # The sweep saw the ports, so they are in the inventory, undetailed.
        self.assertIn((f"{NET}.3", 80, ""), self.services())
        self.new_calls()
        self.set_world(**SPARSE)
        self.discover(resume=True)
        self.assertEqual([(c["sV"], c["targets"]) for c in self.new_calls()],
                         [(True, [f"{NET}.3", f"{NET}.5"])])
        self.assertEqual(self.reasons(), ["58 of 62 addresses did not answer host discovery"])
        self.assertEqual(self.services(), PLANTED)

    def test_a_resweep_never_wipes_service_detail(self):
        self.set_world(**SPARSE)
        self.discover()
        self.set_world(**SPARSE, fail=["nmap-tcp-"])
        self.discover()
        self.assertEqual(self.services(), PLANTED)

    def test_dry_run_prints_both_phases_and_marks_nothing(self):
        out = self.discover(dry_run=True)
        self.assertEqual(self.calls(), [])
        commands = [line for line in out.splitlines() if line.startswith("  $ nmap")]
        self.assertEqual(len(commands), 3)
        self.assertTrue(all("sweep-tcp-000" in c and "-sV" not in c for c in commands[:2]))
        self.assertIn("-sV", commands[2])
        self.assertIn("-Pn", commands[2])
        self.assertIn("<their open ports>", commands[2])
        self.assertEqual(self.store.checkpoints("discover:sweep"), set())
        self.assertEqual(self.store.checkpoints("discover:tcp"), set())
        self.assertEqual(self.store.batch_stats("discover:sweep"), {})
        self.assertNotIn("discover", self.store.meta().get("stages", {}))
        self.assertEqual(self.store.degradations(), [])
        # The placeholder command is a plan, not something that was run.
        self.assertFalse(any("discover:tcp" in c["stage"] for c in self.store.commands()))

    def test_dry_run_after_a_real_run_keeps_its_state(self):
        self.set_world(**SPARSE)
        self.discover()
        state = (self.store.checkpoints("discover:sweep"), self.store.checkpoints("discover:tcp"),
                 self.store.batch_stats("discover:sweep"), self.reasons())
        out = self.discover(dry_run=True)
        self.assertEqual(len(self.calls()), 4)
        self.assertIn("-p 22,80,443", out)       # the plan uses what the sweep found
        self.assertEqual(state, (self.store.checkpoints("discover:sweep"),
                                 self.store.checkpoints("discover:tcp"),
                                 self.store.batch_stats("discover:sweep"), self.reasons()))

    def test_switching_to_single_phase_supersedes_the_sweeps_gaps(self):
        self.set_world(**SPARSE, retransmit=[f"{NET}.5"])
        self.discover()
        self.assertTrue(any(d.stage == "discover:sweep" for d in self.store.degradations()))
        self.policy.nmap.sweep = "never"
        self.set_world(**SPARSE)
        self.discover()
        self.assertEqual([(d.stage, d.reason) for d in self.store.degradations()],
                         [("discover:tcp", "58 of 62 addresses did not answer host discovery")])


class TestSweepModes(_Case):
    def setUp(self):
        super().setUp()
        self.set_world(open={f"{NET}.2": [80]})

    def test_auto_stays_single_phase_when_the_scope_fits_one_batch(self):
        self.assertEqual(self.policy.nmap.sweep, "auto")
        self.discover()
        [call] = self.calls()
        self.assertTrue(call["sV"])
        self.assertEqual(len(call["targets"]), 14)
        self.assertNotIn("-n", call["argv"])
        self.assertEqual([p.name for p in self.store.raw.glob("*.xml")], ["nmap-tcp-0001.xml"])
        self.assertEqual(self.store.checkpoints("discover:tcp"), {"chunk-0001"})

    def test_auto_goes_two_phase_past_one_batch(self):
        self.policy.nmap.chunk_size = 8
        self.discover()
        self.assertEqual([(c["sV"], len(c["targets"])) for c in self.calls()],
                         [(False, 14), (True, 1)])

    def test_never_and_always_override_the_size_rule(self):
        self.policy.nmap.chunk_size = 8
        self.policy.nmap.sweep = "never"
        self.discover()
        self.assertEqual([c["sV"] for c in self.calls()], [True, True])
        self.log.unlink()
        self.policy.nmap.chunk_size = 32
        self.policy.nmap.sweep = "always"
        self.discover()
        self.assertEqual([c["sV"] for c in self.calls()], [False, True])

    def test_the_eval_scores_two_phase_cheaper_with_the_same_services(self):
        result = fake.run()
        self.assertEqual(result["problems"], [])
        self.assertTrue(result["passed"])
        self.assertLess(result["two_phase"]["fingerprint_attempts"],
                        result["single_phase"]["fingerprint_attempts"])


FAKE_NUCLEI = r'''
import json, sys
args = sys.argv[1:]
targets = open(args[args.index("-list") + 1]).read().split()
with open(__LOG__, "a") as fh:
    fh.write(json.dumps(targets) + "\n")
if any(bad in t for t in targets for bad in __FAIL__):
    sys.exit(1)
with open(args[args.index("-output") + 1], "w") as fh:
    for t in targets:
        port = t.rsplit(":", 1)[1]
        fh.write(json.dumps({"template-id": "planted-" + port, "matched-at": t + "/",
                             "host": t, "ip": "127.0.0.1", "port": port,
                             "info": {"name": "Planted " + port, "severity": "low"}}) + "\n")
'''


class TestParallelBatches(_Case):
    """`nmap.parallel` runs several batches at once and must leave the run
    exactly as one-at-a-time does. 62 addresses in batches of 4."""

    target = f"{NET}.0/26"
    def setUp(self):
        super().setUp()
        self.policy.nmap.chunk_size = 4
        self.policy.nmap.sweep_chunk_size = 8

    def snapshot(self, store: Store | None = None) -> dict:
        store = store or self.store
        return {
            "services": [s.to_dict() for s in store.services()],
            "hosts": sorted((h.ip, h.state, tuple(h.hostnames)) for h in store.hosts()),
            "findings": sorted(f.id for f in store.findings()),
            "gaps": sorted((d.stage, d.component, d.reason, d.impact, d.severity,
                            tuple(d.hosts)) for d in store.degradations()),
            "checkpoints": {stage: sorted(keys)
                            for stage, keys in store.all_checkpoints().items()},
            "figures": {stage: dict(sorted(stats.items()))
                        for stage, stats in store.all_batch_stats().items()},
        }

    def run_with(self, parallel: int, sweep: str, **kwargs) -> tuple[dict, str]:
        """A fresh run of the same scope with `parallel` batches at a time."""
        self.store = Store.create(self.tmp / "runs", "t", run_id=f"{sweep}-{parallel}")
        self.store.write_meta({"run_id": self.store.run_id})
        self.policy.nmap.parallel = parallel
        self.policy.nmap.sweep = sweep
        out = self.discover(**kwargs)
        return self.snapshot(), out

    def test_default_is_one_and_the_gentle_example_says_so(self):
        self.assertEqual(Policy().nmap.parallel, 1)
        gentle = Policy.load(Path(__file__).parent.parent / "examples" / "policy.gentle.json")
        self.assertEqual(gentle.nmap.parallel, 1)
        self.assertEqual(Policy.from_dict({"nmap": {"parallel": 4}}).nmap.parallel, 4)

    def test_less_than_one_is_refused(self):
        self.set_world()
        self.policy.nmap.parallel = 0
        with self.assertRaisesRegex(ValueError, "nmap.parallel"):
            self.discover()

    def test_single_phase_tcp_and_udp_end_in_the_same_state(self):
        self.set_world(**PARALLEL_WORLD)
        serial, _ = self.run_with(1, "never", udp=True)
        parallel, _ = self.run_with(4, "never", udp=True)
        self.assertEqual(parallel, serial)
        # The planted world really did exercise the interesting paths.
        # 16 batches: one failed outright, and the one cut short was salvaged.
        self.assertEqual(len(serial["checkpoints"]["discover:tcp"]), 15)
        self.assertEqual(len(serial["checkpoints"]["discover:udp"]), 15)
        reasons = " | ".join(g[2] for g in serial["gaps"])
        for text in ("tcp-0006 produced no parseable output", "tcp-0011 did not finish",
                     "udp-0002 produced no parseable output", "retransmission cap hit",
                     "host timeout", "did not answer host discovery", "open|filtered"):
            self.assertIn(text, reasons)

    def test_two_phase_ends_in_the_same_state(self):
        self.set_world(**{**PARALLEL_WORLD, "fail": ["sweep-tcp-0002", "tcp-0001-01"]})
        serial, _ = self.run_with(1, "always")
        parallel, _ = self.run_with(4, "always")
        self.assertEqual(parallel, serial)
        self.assertEqual(len(serial["checkpoints"]["discover:sweep"]), 7)   # 8, 1 failed
        self.assertTrue(any(key.endswith("-full") for key in serial["checkpoints"][TCP]))

    def test_parallel_takes_less_wall_clock(self):
        self.policy.nmap.chunk_size = 8            # 8 batches
        self.set_world(**{**SPARSE, "sleep": 0.4})

        def timed(parallel: int) -> tuple[float, dict]:
            started = time.monotonic()
            state, _ = self.run_with(parallel, "never")
            return time.monotonic() - started, state

        serial_seconds, serial = timed(1)
        parallel_seconds, parallel = timed(4)
        self.assertEqual(parallel, serial)
        self.assertGreaterEqual(serial_seconds, 8 * 0.4)
        self.assertLess(parallel_seconds, serial_seconds * 0.6)

    def test_resume_runs_only_what_is_missing_and_clears_the_gap(self):
        self.set_world(**SPARSE, fail=["tcp-0001", "tcp-0010"])
        state, _ = self.run_with(4, "never")
        self.assertEqual(len(state["checkpoints"][TCP]), 14)
        self.assertEqual(sum("produced no parseable output" in g[2] for g in state["gaps"]), 2)
        self.new_calls()

        self.set_world(**SPARSE)
        self.discover(resume=True)
        self.assertEqual(sorted(Path(c["base"]).name for c in self.new_calls()),
                         ["nmap-tcp-0001", "nmap-tcp-0010"])
        resumed = self.snapshot()
        clean, _ = self.run_with(1, "never")
        self.assertEqual(resumed, clean)

    def test_abort_threshold_still_stops_a_pass_where_everything_fails(self):
        self.set_world(**SPARSE, fail=["nmap-tcp-"])
        self.policy.nmap.parallel = 4
        self.policy.nmap.sweep = "never"
        with self.assertRaises(RunAborted):
            self.discover()
        self.assertEqual(self.store.checkpoints(TCP), set())
        self.assertNotIn("discover", self.store.meta().get("stages", {}))
        # It stopped at the threshold (8 of 16) plus at most the batches in flight.
        self.assertLessEqual(len(self.calls()), 8 + 3)
        failed = [r for r in self.reasons() if "produced no parseable output" in r]
        self.assertGreaterEqual(len(failed), 8)

    def test_every_output_line_is_whole_and_names_its_batch(self):
        self.set_world(**PARALLEL_WORLD)
        _, out = self.run_with(4, "never", udp=True)
        batch_lines = [line for line in out.splitlines() if line.startswith("  [")]
        self.assertGreater(len(batch_lines), 60)
        shape = re.compile(r"^  \[(\d+/16\] (tcp|udp)-\d{4}: (\d+ host\(s\), started|finished)"
                           r"|(tcp|udp)-\d{4}\] ! \S.*)$")
        for line in batch_lines:
            self.assertRegex(line, shape)
        # Nothing is reported the serial way, where the batch is implied by
        # the line above.
        self.assertFalse([line for line in out.splitlines() if line.startswith("    !")])
        self.assertIn("  [tcp-0006] ! batch failed; 4 host(s) not covered", out)
        self.assertIn("  [tcp-0011] ! partial: recovered", out)
        for index in range(1, 17):
            self.assertEqual(out.count(f"  [{index}/16] tcp-{index:04d}: finished"), 1)

    def test_dry_run_prints_the_serial_plan_and_runs_nothing(self):
        self.set_world(**PARALLEL_WORLD)
        for sweep in ("never", "always"):
            _, serial = self.run_with(1, sweep, dry_run=True, udp=True)
            one = self.store
            _, parallel = self.run_with(4, sweep, dry_run=True, udp=True)
            self.assertEqual(parallel.replace(str(self.store.path), "RUN"),
                             serial.replace(str(one.path), "RUN"))
            self.assertIn("(dry run)", parallel)
            self.assertEqual(self.store.all_checkpoints(), {})
        self.assertEqual(self.calls(), [])

    def test_ctrl_c_stops_the_batches_in_flight_and_resume_finishes(self):
        # Batch 1 is quick; the others would take a minute each.
        self.set_world(**SPARSE, sleep=60, slow={"tcp-0001": 0})
        self.policy.nmap.parallel = 4
        self.policy.nmap.sweep = "never"
        real_wait, rounds = discovery.wait, []

        def interrupted(*args, **kwargs):
            rounds.append(1)
            if len(rounds) > 1:
                raise KeyboardInterrupt
            return real_wait(*args, **kwargs)

        started = time.monotonic()
        with mock.patch.object(discovery, "wait", side_effect=interrupted), \
                self.assertRaises(KeyboardInterrupt):
            self.discover()
        self.assertLess(time.monotonic() - started, 20)     # did not sit out the scans
        # What had finished is on record; what was stopped left no mark at all.
        self.assertEqual(self.store.checkpoints(TCP), {"chunk-0001"})
        self.assertEqual(sorted((s.host, s.port) for s in self.store.services()),
                         [(f"{NET}.3", 22), (f"{NET}.3", 80)])
        self.assertFalse([r for r in self.reasons() if "tcp-00" in r])
        self.assertNotIn("discover", self.store.meta().get("stages", {}))
        # Started: batch 1, the three beside it, and perhaps the one that
        # took its place. Each was stopped (SIGTERM), not left running.
        self.assertIn(len(self.new_calls()), (4, 5))
        stopped = [c for c in self.store.commands() if c["returncode"] != 0]
        self.assertGreaterEqual(len(stopped), 3)
        self.assertEqual({c["returncode"] for c in stopped}, {-15})

        self.set_world(**SPARSE)
        self.discover(resume=True)
        self.assertEqual(len(self.new_calls()), 15)
        resumed = self.snapshot()
        clean, _ = self.run_with(1, "never")
        self.assertEqual(resumed, clean)


class TestNucleiBatches(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "nuclei.jsonl"
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["127.0.0.1/32"], "allow_private": True,
        }))
        self.scope = Scope.load(sp)
        self.store = Store.create(self.tmp / "runs", "t", run_id="r")
        self.store.write_meta({"run_id": "r"})
        self.policy = Policy()
        self.policy.nuclei.batch_size = 2
        self.store.save_services([Service(host="127.0.0.1", port=p, proto="tcp", name="http")
                                  for p in range(8001, 8006)])

    def nuclei(self, fail=()):
        source = FAKE_NUCLEI.replace("__LOG__", repr(str(self.log))).replace(
            "__FAIL__", repr(list(fail)))
        path = self.bin / "nuclei"
        path.write_text(f"#!{sys.executable}\n{source}")
        path.chmod(0o755)

    def probe(self, dry_run=False, **kwargs) -> str:
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}), contextlib.redirect_stdout(out):
            pipeline.probe(self.store, self.scope, self.policy,
                           Runner(self.store, dry_run=dry_run), only=["nuclei"], **kwargs)
        return out.getvalue()

    def runs(self) -> list[list[int]]:
        """Ports in each nuclei invocation so far, then forget them."""
        if not self.log.exists():
            return []
        lines = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.log.unlink()
        return [[int(t.rsplit(":", 1)[1]) for t in targets] for targets in lines]

    def checked(self) -> list[int]:
        return [s.port for s in self.store.services() if "nuclei" in s.probed_by]

    def planted(self) -> list[str]:
        return sorted(f.title for f in self.store.findings() if f.source.startswith("nuclei"))

    def test_batches_checkpoint_independently(self):
        self.nuclei(fail=[":8003"])
        self.probe()
        self.assertEqual(self.runs(), [[8001, 8002], [8003, 8004], [8005]])
        self.assertEqual(self.checked(), [8001, 8002, 8005])
        # Results of the batches that finished are stored, not held back.
        self.assertEqual(self.planted(), ["Planted 8001", "Planted 8002", "Planted 8005"])
        [gap] = self.store.degradations()
        self.assertEqual((gap.stage, gap.component, gap.severity, gap.hosts),
                         ("probe:nuclei", "nuclei", "serious", ["127.0.0.1"]))
        self.assertRegex(gap.reason, r"^nuclei batch [0-9a-f]{10} exited 1$")
        self.assertIn("against 2 web service(s)", gap.impact)
        self.assertTrue((self.store.raw / gap.remedy.split("raw/")[1].split()[0]).is_file())

        self.nuclei()
        self.probe()
        self.assertEqual(self.runs(), [[8003, 8004]])     # only what was left
        self.assertEqual(self.checked(), [8001, 8002, 8003, 8004, 8005])
        self.assertEqual(self.store.degradations(), [])
        self.assertEqual(len(self.planted()), 5)

        self.probe()
        self.assertEqual(self.runs(), [])                 # nothing left to do
        self.probe(force=True)
        self.assertEqual(len(self.runs()), 3)

    def test_a_gap_names_only_the_failed_batchs_hosts(self):
        self.scope.targets = ["127.0.0.0/29"]
        self.store.save_services([
            Service(host="127.0.0.1", port=8006, proto="tcp", name="http"),
            Service(host="127.0.0.3", port=9001, proto="tcp", name="http")])
        self.nuclei(fail=["127.0.0.3"])
        self.probe()
        self.assertEqual([d.hosts for d in self.store.degradations()], [["127.0.0.3"]])
        self.assertEqual(len(self.checked()), 6)

    def test_each_batch_has_its_own_output_file(self):
        self.nuclei()
        self.probe()
        outputs = sorted(self.store.raw.glob("nuclei-*.jsonl"))
        self.assertEqual(len(outputs), 3)
        self.assertFalse((self.store.raw / "nuclei.jsonl").exists())
        self.assertEqual(len(list(self.store.raw.glob("nuclei-targets-*.txt"))), 3)
        # The offline replay in evals/score.py reads every batch.
        replayed = sorted(f.title for f in score.replay(self.store))
        self.assertEqual(replayed, [f"Planted {p}" for p in range(8001, 8006)])

    def test_one_batch_over_everything_keeps_the_plain_file_names(self):
        self.policy.nuclei.batch_size = 25
        self.nuclei()
        self.probe()
        self.assertEqual(self.runs(), [[8001, 8002, 8003, 8004, 8005]])
        self.assertEqual(sorted(p.name for p in self.store.raw.glob("nuclei*")),
                         ["nuclei-targets.txt", "nuclei.jsonl"])

    def test_a_later_batch_never_overwrites_an_earlier_ones_output(self):
        self.policy.nuclei.batch_size = 25
        self.nuclei()
        self.probe()
        first = (self.store.raw / "nuclei.jsonl").read_text()
        self.store.save_services([Service(host="127.0.0.1", port=8010, proto="tcp", name="http")])
        self.probe()
        self.assertEqual(self.runs()[-1], [8010])
        self.assertEqual((self.store.raw / "nuclei.jsonl").read_text(), first)
        self.assertEqual(len(self.planted()), 6)

    def test_missing_nuclei_is_one_gap_for_every_batch(self):
        self.probe()
        [gap] = self.store.degradations()
        self.assertIn("not found on PATH", gap.reason)
        self.assertIn("against 5 web service(s)", gap.impact)
        self.assertEqual(self.checked(), [])

    def test_dry_run_prints_every_batch_and_marks_nothing(self):
        self.nuclei(fail=[":8003"])
        self.probe()
        self.runs()
        before = [d.reason for d in self.store.degradations()]
        self.nuclei()
        out = self.probe(dry_run=True)
        self.assertEqual(self.runs(), [])
        self.assertEqual(out.count("  $ nuclei"), 1)
        self.assertEqual(self.checked(), [8001, 8002, 8005])
        self.assertEqual([d.reason for d in self.store.degradations()], before)

    def test_batches_are_of_web_services_only(self):
        services = [Service(host="127.0.0.1", port=22, proto="tcp", name="ssh"),
                    *self.store.services()]
        self.assertEqual([[s.port for s in b] for b in nuclei.batches(services, 2)],
                         [[8001, 8002], [8003, 8004], [8005]])
        self.assertEqual(len(nuclei.batches(services, 0)), 1)
        self.assertEqual(nuclei.batches([], 2), [])


class TestReconDryRun(_Case):
    def setUp(self):
        super().setUp()
        self.scope.domains = ["lab.test"]

    def recon(self, ns: FakeDns, dry_run: bool):
        self.policy.dns = ns.policy(timeout_sec=0.2)
        out = io.StringIO()
        asked = mock.Mock(return_value=([subdomains.Enumerated(name="www.lab.test")],
                                        ["crt.sh: timed out"]))
        with mock.patch.object(subdomains, "enumerate_domain", asked), \
                mock.patch.object(subdomains, "_http_get_json",
                                  side_effect=AssertionError("crt.sh was queried"),
                                  create=True), \
                contextlib.redirect_stdout(out):
            result = pipeline.recon(self.store, self.scope, self.policy,
                                    Runner(self.store, dry_run=dry_run))
        return result, out.getvalue(), asked

    def test_dry_run_asks_nothing_and_stores_nothing(self):
        with FakeDns(axfr=True) as ns:
            result, out, asked = self.recon(ns, dry_run=True)
            self.assertEqual(ns.queries, [])
        asked.assert_not_called()
        self.assertIn("[dry-run] would enumerate lab.test via crt.sh", out)
        self.assertIn("[dry-run] dns ", out)
        self.assertTrue(result["dry_run"])
        self.assertEqual((self.store.findings(), self.store.hosts(), self.store.degradations()),
                         ([], [], []))
        self.assertNotIn("recon", self.store.meta().get("stages", {}))
        self.assertEqual(self.store.commands(), [])

    def test_a_real_run_still_does_all_of_it(self):
        with FakeDns(axfr=True) as ns:
            _, _, asked = self.recon(ns, dry_run=False)
            self.assertNotEqual(ns.queries, [])
        asked.assert_called_once()
        self.assertIn("recon", self.store.meta()["stages"])
        self.assertIn("crt.sh: timed out", [d.reason for d in self.store.degradations()])


if __name__ == "__main__":
    unittest.main()
