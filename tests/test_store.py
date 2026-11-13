"""The run store: interface semantics, crash safety, threads, old runs, export.

State lives in `state.db` (SQLite). These tests pin what callers rely on
(return values, ordering, de-duplication keys, merge rules) and the
properties the database was brought in for: a killed writer leaves whole
state, threads can write at once, and a run in the old JSON layout is read
without being touched and imported on its first write.
"""

import contextlib
import io
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from extscan import cli, pipeline
from extscan.diff import diff_runs
from extscan.models import CommandRecord, Finding, Host, Lead, Service
from extscan.resilience import Degradation
from extscan.scope import Scope
from extscan.screenshots import Shot, load, save
from extscan.store import EXPORT_DIR, LEGACY_DIR, STATE_DB, STATE_FILES, Store

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "lab-run"


def finding(i: int, **kw) -> Finding:
    return Finding(title=f"Finding {i}", severity=kw.pop("severity", "low"),
                   host="203.0.113.5", port=443, source="test", **kw)


def lead(i: int, **kw) -> Lead:
    return Lead(kind="web_paths", host="203.0.113.5", port=8000 + i,
                url=f"http://203.0.113.5:{8000 + i}/", **kw)


def gap(reason: str, stage: str = "probe:tls", component: str = "tls", **kw) -> Degradation:
    return Degradation(stage=stage, component=component, reason=reason,
                       impact="not checked", **kw)


def snapshot(path: Path) -> dict:
    """Every file under `path` with its size and mtime."""
    return {p.relative_to(path).as_posix(): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in sorted(path.rglob("*")) if p.is_file()}


def state(store: Store) -> dict:
    """Everything the store holds, as plain data."""
    return {
        "hosts": [h.to_dict() for h in store.hosts()],
        "services": [s.to_dict() for s in store.services()],
        "findings": [f.to_dict() for f in store.findings()],
        "leads": [ld.to_dict() for ld in store.leads()],
        "degradations": [d.to_dict() for d in store.degradations()],
        "checkpoints": store.all_checkpoints(),
        "batches": store.all_batch_stats(),
        "screenshots": store.screenshots(),
    }


class _Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = Store.create(self.tmp / "runs", "t", run_id="r")
        self.store.write_meta({"run_id": "r", "stages": {}})

    def legacy(self, name: str = "old") -> Store:
        shutil.copytree(FIXTURE, self.tmp / "runs" / name)
        return Store(self.tmp / "runs" / name)


class TestInterface(_Case):
    def test_add_findings_counts_new_ids_and_keeps_insertion_order(self):
        self.assertEqual(self.store.add_findings([finding(1), finding(2)]), 2)
        changed = finding(2, severity="critical")       # same id: the first one stays
        self.assertEqual(self.store.add_findings([changed, finding(0), finding(0)]), 1)
        got = self.store.findings()
        self.assertEqual([f.title for f in got], ["Finding 1", "Finding 2", "Finding 0"])
        self.assertEqual(got[1].severity, "low")
        self.assertEqual(self.store.add_findings([]), 0)

    def test_replace_findings_replaces_everything_in_the_given_order(self):
        self.store.add_findings([finding(i) for i in range(5)])
        self.store.replace_findings([finding(9), finding(3)])
        self.assertEqual([f.title for f in self.store.findings()], ["Finding 9", "Finding 3"])

    def test_findings_round_trip_every_field(self):
        f = finding(1, cves=["CVE-2021-44228"], kev=True, epss=0.5, tags=["a"],
                    kev_detail=[{"cve": "CVE-2021-44228"}], evidence="é\n\x00 <b>")
        self.store.add_findings([f])
        self.assertEqual(self.store.findings(), [f])

    def test_add_leads_skips_known_ids_and_stops_at_max_total(self):
        self.assertEqual(self.store.add_leads([lead(i) for i in range(3)], max_total=5), 3)
        # A known lead does not count against the cap, and the cap stops the rest.
        more = [lead(1), lead(10), lead(11), lead(12), lead(13)]
        self.assertEqual(self.store.add_leads(more, max_total=5), 2)
        self.assertEqual([ld.port for ld in self.store.leads()],
                         [8000, 8001, 8002, 8010, 8011])
        self.assertEqual(self.store.add_leads([lead(1), lead(20)], max_total=5), 0)

    def test_update_lead_changes_one_lead_and_reports_a_miss(self):
        a, b = lead(1), lead(2)
        self.store.add_leads([a, b])
        got = self.store.update_lead(b.id, status="done", note="seen", attempts=2)
        self.assertEqual((got.id, got.status, got.note, got.attempts), (b.id, "done", "seen", 2))
        self.assertIsNone(self.store.update_lead("nope", status="done"))
        self.assertEqual([ld.id for ld in self.store.leads("open")], [a.id])
        self.assertEqual([ld.note for ld in self.store.leads("done")], ["seen"])
        self.assertEqual([ld.id for ld in self.store.leads()], [a.id, b.id])   # order kept

    def test_save_hosts_merges_names_and_keeps_what_the_new_record_lacks(self):
        self.store.save_hosts([Host("203.0.113.9", ["b.example"], state="up",
                                    os_guess="Linux", discovered_by="nmap"),
                               Host("203.0.113.1", state="up")])
        self.store.tag_hosts({"203.0.113.9": "cloudflare"}, checked={"cloudflare"})
        self.store.save_hosts([Host("203.0.113.9", ["a.example"], state="", os_guess=None),
                               Host("203.0.113.5", state="down")])
        first, second, third = self.store.hosts()
        self.assertEqual((first.ip, first.hostnames, first.state, first.os_guess,
                          first.discovered_by, first.network),
                         ("203.0.113.9", ["a.example", "b.example"], "up", "Linux", "nmap",
                          "cloudflare"))
        self.assertEqual((second.ip, third.ip), ("203.0.113.1", "203.0.113.5"))

    def test_tag_hosts_sets_clears_and_leaves_unchecked_networks(self):
        self.store.save_hosts([Host("203.0.113.1", network="cloudflare"),
                               Host("203.0.113.2", network="fastly"),
                               Host("203.0.113.3")])
        self.store.tag_hosts({"203.0.113.3": "cloudflare"}, checked={"cloudflare"})
        self.assertEqual([h.network for h in self.store.hosts()], ["", "fastly", "cloudflare"])

    def test_save_services_keeps_probes_and_scripts_and_sorts(self):
        self.store.save_services([
            Service("203.0.113.9", 161, "udp"),
            Service("203.0.113.9", 8080, "tcp", name="http", scripts={"a": "1", "b": "old"},
                    probed_by=["tls", "nuclei"]),
            Service("203.0.113.10", 22, "tcp"),
            Service("203.0.113.9", 22, "tcp")])
        again = Service("203.0.113.9", 8080, "tcp", name="http-alt", scripts={"b": "new"},
                        probed_by=["http_fingerprint"])
        self.store.save_services([again])
        # The caller's object carries the merge too, as it always has.
        self.assertEqual(again.probed_by, ["http_fingerprint", "nuclei", "tls"])
        got = self.store.services()
        self.assertEqual([s.id for s in got],
                         ["203.0.113.10/tcp/22", "203.0.113.9/tcp/22",
                          "203.0.113.9/tcp/8080", "203.0.113.9/udp/161"])
        self.assertEqual((got[2].name, got[2].scripts, got[2].probed_by),
                         ("http-alt", {"a": "1", "b": "new"},
                          ["http_fingerprint", "nuclei", "tls"]))
        self.assertEqual(self.store.service_ids(), {s.id for s in got})

    def test_mark_probed_appends_once_and_ignores_unknown_services(self):
        svc = Service("203.0.113.9", 443, "tcp", probed_by=["tls"])
        self.store.save_services([svc])
        self.store.mark_probed_many([(svc.id, "sslscan"), (svc.id, "tls"), (svc.id, "nuclei"),
                                     (svc.id, "sslscan"), ("203.0.113.1/tcp/1", "tls")])
        self.store.mark_probed(svc.id, "nuclei")
        self.assertEqual(self.store.services()[0].probed_by, ["tls", "sslscan", "nuclei"])
        self.assertEqual(len(self.store.services()), 1)

    def test_gaps_are_keyed_on_stage_component_and_reason(self):
        self.store.add_degradation(gap("a", hosts=["203.0.113.1"]))
        self.store.add_degradation(gap("a", hosts=["203.0.113.2"]))      # same key: ignored
        self.store.add_degradation(gap("a", component="sslscan"))
        self.store.add_degradation(gap("b"))
        got = self.store.degradations()
        self.assertEqual([(d.component, d.reason, d.hosts) for d in got],
                         [("tls", "a", ["203.0.113.1"]), ("sslscan", "a", []), ("tls", "b", [])])
        self.store.remove_degradations(lambda d: d.reason == "a" and d.component == "tls")
        self.store.remove_degradations(lambda d: False)
        self.assertEqual([(d.component, d.reason) for d in self.store.degradations()],
                         [("sslscan", "a"), ("tls", "b")])
        # What a caller does to a returned gap never reaches the store.
        self.store.degradations()[0].hosts.append("x")
        self.assertEqual(self.store.degradations()[0].hosts, [])

    def test_gaps_written_through_another_store_are_seen(self):
        """The decoded gaps are cached; another writer must invalidate it."""
        self.store.add_degradation(gap("a"))
        self.assertEqual(len(self.store.degradations()), 1)
        other = Store(self.store.path)
        other.add_degradation(gap("b"))
        self.assertEqual([d.reason for d in self.store.degradations()], ["a", "b"])
        other.remove_degradations(lambda d: d.reason == "a")
        self.store.remove_degradations(lambda d: d.reason == "a")     # already gone: no-op
        self.assertEqual([d.reason for d in self.store.degradations()], ["b"])

    def test_checkpoints_per_stage(self):
        for key in ("chunk-0002", "chunk-0001", "chunk-0002"):
            self.store.checkpoint("discover:tcp", key)
        self.store.checkpoint("discover:udp", "chunk-0001")
        self.assertEqual(self.store.checkpoints("discover:tcp"), {"chunk-0001", "chunk-0002"})
        self.assertTrue(self.store.is_done("discover:udp", "chunk-0001"))
        self.assertFalse(self.store.is_done("discover:udp", "chunk-0002"))
        self.assertEqual(self.store.all_checkpoints(),
                         {"discover:tcp": ["chunk-0002", "chunk-0001"],
                          "discover:udp": ["chunk-0001"]})
        self.store.clear_checkpoints("discover:tcp")
        self.assertEqual(self.store.checkpoints("discover:tcp"), set())
        self.assertEqual(self.store.checkpoints("discover:udp"), {"chunk-0001"})
        self.store.clear_checkpoints()
        self.assertEqual(self.store.all_checkpoints(), {})

    def test_batch_stats_save_forget_and_keep(self):
        self.store.save_batch_stats("discover:sweep", "chunk-0001", {"asked": 4, "up": 1})
        self.store.save_batch_stats("discover:sweep", "chunk-0002", {"open": {"h": [80]}})
        self.store.save_batch_stats("discover:tcp", "chunk-0001", {})
        self.store.save_batch_stats("discover:sweep", "chunk-0001", {"asked": 4, "up": 2})
        self.assertEqual(self.store.batch_stats("discover:sweep"),
                         {"chunk-0001": {"asked": 4, "up": 2},
                          "chunk-0002": {"open": {"h": [80]}}})
        self.assertEqual(list(self.store.batch_stats("discover:sweep")),
                         ["chunk-0001", "chunk-0002"])
        self.store.save_batch_stats("discover:sweep", "chunk-0002", None)
        self.store.save_batch_stats("discover:sweep", "never-there", None)
        self.store.keep_batch_stats("discover:sweep", [])
        self.assertEqual(self.store.batch_stats("discover:sweep"), {})
        self.assertEqual(self.store.batch_stats("discover:tcp"), {"chunk-0001": {}})

    def test_screenshot_records_go_through_the_store(self):
        shots = [Shot(url="http://203.0.113.5", kind="service", service="203.0.113.5/tcp/80",
                      status="captured", blocked=["http://evil.example/"]),
                 Shot(url="http://203.0.113.5/x", kind="finding",
                      service="203.0.113.5/tcp/80")]
        save(self.store, shots)
        self.assertEqual(load(self.store), shots)
        self.assertEqual(load(self.store.path), shots)       # a directory works too
        save(self.store.path, shots[:1])
        self.assertEqual(load(self.store), shots[:1])
        self.assertFalse((self.store.path / STATE_FILES["screenshots"]).exists())

    def test_counts(self):
        self.store.save_hosts([Host("203.0.113.5")])
        self.store.save_services([Service("203.0.113.5", 443, "tcp")])
        self.store.add_findings([finding(1), finding(2, severity="high", review_required=True)])
        self.store.add_leads([lead(1), lead(2, status="done")])
        self.store.add_degradation(gap("a"))
        self.assertEqual(self.store.counts(), {
            "hosts": 1, "services": 1, "findings": 2,
            "findings_by_severity": {"low": 1, "high": 1}, "review_required": 1,
            "leads_open": 1, "leads_total": 2, "degradations": 1})

    def test_latest_is_the_run_whose_run_json_is_newest(self):
        older = Store.create(self.tmp / "runs", "t", run_id="a-older")
        older.write_meta({"run_id": "a-older"})
        os.utime(older.path / "run.json", (1, 1))
        self.store.add_findings([finding(1)])       # state writes do not touch run.json
        self.assertEqual(Store.open(self.tmp / "runs", "latest").run_id, "r")
        older.mark_stage("probe")
        self.assertEqual(Store.open(self.tmp / "runs", "latest").run_id, "a-older")

    def test_reading_an_empty_run_creates_nothing(self):
        fresh = Store(self.tmp / "runs" / "fresh")
        fresh.path.mkdir()
        self.assertEqual(state(fresh), {k: {} if k in ("checkpoints", "batches") else []
                                        for k in STATE_FILES})
        fresh.remove_degradations(lambda d: True)
        fresh.save_batch_stats("discover:tcp", "x", None)
        fresh.keep_batch_stats("discover:tcp", [])
        self.assertEqual(fresh.counts()["findings"], 0)
        self.assertEqual(fresh.layout, "empty")
        self.assertEqual(list(fresh.path.iterdir()), [])


class TestTransactions(_Case):
    def test_a_failed_transaction_leaves_nothing_behind(self):
        self.store.add_findings([finding(0)])
        self.store.add_degradation(gap("before"))
        with self.assertRaises(RuntimeError), self.store.transaction():
            self.store.add_findings([finding(1)])
            self.store.add_leads([lead(1)])
            self.store.add_degradation(gap("inside"))
            self.store.remove_degradations(lambda d: d.reason == "before")
            self.store.checkpoint("discover:tcp", "chunk-0001")
            # Inside the transaction its own writes are visible.
            self.assertEqual(len(self.store.findings()), 2)
            self.assertEqual([d.reason for d in self.store.degradations()], ["inside"])
            raise RuntimeError("boom")
        self.assertEqual([f.title for f in self.store.findings()], ["Finding 0"])
        self.assertEqual(self.store.leads(), [])
        self.assertEqual([d.reason for d in self.store.degradations()], ["before"])
        self.assertEqual(self.store.checkpoints("discover:tcp"), set())

    def test_a_transaction_commits_once_and_other_stores_see_it_only_then(self):
        other = Store(self.store.path)
        self.store.add_findings([finding(0)])
        with self.store.transaction():
            self.store.add_findings([finding(1)])
            with self.store.transaction():          # nested: joins the outer one
                self.store.checkpoint("discover:tcp", "chunk-0001")
        self.assertEqual(len(other.findings()), 2)
        self.assertEqual(other.checkpoints("discover:tcp"), {"chunk-0001"})

    def test_rollback_journal_not_wal_and_no_side_files_left(self):
        self.store.add_findings([finding(1)])
        self.store.add_degradation(gap("a"))
        db = sqlite3.connect(self.store.db_path)
        self.addCleanup(db.close)
        self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        names = {p.name for p in self.store.path.iterdir()}
        self.assertEqual(names, {"run.json", STATE_DB, "raw"})


WRITER = r"""
import os, sys
from extscan.models import Finding, Lead
from extscan.store import Store

store = Store(sys.argv[1])
mode = sys.argv[2]
if mode == "loop":
    # Batches of 10 findings and one checkpoint, each batch one transaction.
    for batch in range(100000):
        with store.transaction():
            store.add_findings(
                Finding(title=f"F {batch}-{i}", host="203.0.113.5", source="t",
                        evidence="x" * 2000) for i in range(10))
            store.checkpoint("writer", f"batch-{batch:06d}")
        print(batch, flush=True)
else:
    # Die in the middle of a transaction, with part of it already executed.
    with store.transaction():
        store.add_findings([Finding(title="half", host="203.0.113.5", source="t")])
        store.add_leads([Lead(kind="web_paths", host="203.0.113.5")])
        os._exit(9)
"""


class TestCrashSafety(_Case):
    def writer(self, mode: str) -> subprocess.Popen:
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        return subprocess.Popen([sys.executable, "-c", WRITER, str(self.store.path), mode],
                                stdout=subprocess.PIPE, text=True, env=env)

    def test_writer_killed_mid_loop_leaves_whole_batches(self):
        proc = self.writer("loop")
        self.addCleanup(proc.stdout.close)
        reported = -1
        deadline = time.monotonic() + 60
        while reported < 25 and time.monotonic() < deadline:
            reported = int(proc.stdout.readline())
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=30)
        self.assertGreaterEqual(reported, 25)

        findings = self.store.findings()
        done = self.store.checkpoints("writer")
        # Every batch is all there or not there at all, and each one the
        # writer reported before it died is there.
        self.assertEqual(len(findings), 10 * len(done))
        self.assertGreaterEqual(len(done), reported + 1)
        self.assertEqual(done, {f"batch-{n:06d}" for n in range(len(done))})
        titles = {f.title for f in findings}
        self.assertEqual(titles, {f"F {b}-{i}" for b in range(len(done)) for i in range(10)})
        db = sqlite3.connect(self.store.db_path)
        self.addCleanup(db.close)
        self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        # And the run carries on.
        self.assertEqual(self.store.add_findings([finding(1)]), 1)
        self.assertFalse((self.store.path / f"{STATE_DB}-journal").exists())

    def test_death_inside_a_transaction_rolls_all_of_it_back(self):
        self.store.add_findings([finding(0)])
        proc = self.writer("die")
        proc.stdout.close()
        self.assertEqual(proc.wait(timeout=60), 9)
        self.assertEqual([f.title for f in self.store.findings()], ["Finding 0"])
        self.assertEqual(self.store.leads(), [])
        self.assertEqual(self.store.add_leads([lead(1)]), 1)


class TestThreads(_Case):
    def run_threads(self, work, count: int = 8) -> None:
        errors: list[BaseException] = []

        def guarded(n):
            try:
                work(n)
            except BaseException as exc:    # reported below
                errors.append(exc)

        threads = [threading.Thread(target=guarded, args=(n,)) for n in range(count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        self.assertEqual(errors, [])

    def test_threads_write_through_one_store(self):
        services = [Service("203.0.113.5", 1000 + n, "tcp") for n in range(8)]
        self.store.save_services(services)

        def work(n):
            for i in range(40):
                self.store.add_findings([finding(n * 1000 + i), finding(i)])    # i: contended
                self.store.add_leads([lead(n * 100 + i)])
                self.store.checkpoint("stage", f"{n}-{i}")
                self.store.mark_probed(services[i % 8].id, f"probe-{n}")
                self.store.add_degradation(gap(f"{n}-{i}"))
                self.store.remove_degradations(lambda d, n=n, i=i: d.reason == f"{n}-{i - 1}")
                self.store.log_command(CommandRecord(
                    argv=["nmap", "x" * 3000, str(n), str(i)], started=0.0, duration=0.0,
                    returncode=0))
                self.store.findings()

        self.run_threads(work)
        # Thread 0's "Finding i" and the shared "Finding i" are the same id.
        self.assertEqual(len(self.store.findings()), 8 * 40)
        self.assertEqual(len(self.store.leads()), 8 * 40)
        self.assertEqual(len(self.store.checkpoints("stage")), 8 * 40)
        self.assertEqual(sorted(d.reason for d in self.store.degradations()),
                         sorted(f"{n}-39" for n in range(8)))
        for s in self.store.services():
            self.assertEqual(sorted(s.probed_by), [f"probe-{n}" for n in range(8)])
        # Every audit line is whole: 3000-byte arguments did not interleave.
        lines = (self.store.path / "commands.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 8 * 40)
        self.assertEqual({tuple(json.loads(line)["argv"][2:]) for line in lines},
                         {(str(n), str(i)) for n in range(8) for i in range(40)})

    def test_threads_write_through_separate_stores(self):
        """One Store per thread is one connection per thread: SQLite's own
        lock has to keep them apart."""
        def work(n):
            store = Store(self.store.path)
            for i in range(25):
                store.add_findings([finding(n * 1000 + i)])
                store.update_meta(**{f"t{n}": i})
            store.close()

        self.run_threads(work, count=6)
        self.assertEqual(len(self.store.findings()), 6 * 25)

    def test_a_transaction_in_one_thread_is_never_seen_half_done(self):
        stop = threading.Event()
        seen: set[tuple[int, int]] = set()

        def read():
            while not stop.is_set():
                with self.store.transaction():      # one consistent look at both
                    seen.add((len(self.store.findings()), len(self.store.leads())))

        reader = threading.Thread(target=read)
        reader.start()
        try:
            for i in range(100):
                with self.store.transaction():
                    self.store.add_findings([finding(i)])
                    self.store.add_leads([lead(i)])
        finally:
            stop.set()
            reader.join(timeout=60)
        self.assertTrue(seen)
        self.assertEqual({f - ld for f, ld in seen}, {0})


class TestLegacyRuns(_Case):
    """`tests/fixtures/lab-run` is a run in the JSON layout."""

    def test_reading_an_old_run_writes_nothing(self):
        old = self.legacy()
        before = snapshot(old.path)
        got = state(old)
        self.assertEqual(len(got["services"]), 9)
        self.assertEqual(len(got["findings"]), 168)
        self.assertEqual(old.layout, "legacy-json")
        self.assertTrue(old.leads("open") or old.leads("done"))
        old.counts()
        old.service_ids()
        old.commands()
        diff_runs(old, Store(old.path))
        # Calls that have nothing to change are not writes either.
        old.remove_degradations(lambda d: d.stage == "no-such-stage")
        old.save_batch_stats("discover:tcp", "chunk-9999", None)
        old.keep_batch_stats("discover:sweep", [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            for command in ("status", "hosts", "services", "findings", "leads", "gaps"):
                self.assertEqual(cli.main(["--runs-dir", str(old.path.parent), "--json",
                                           command, old.run_id]), 0)
            cli.main(["--runs-dir", str(old.path.parent), "screenshot", old.run_id, "--list"])
        self.assertEqual(snapshot(old.path), before)

    def test_the_committed_fixture_is_still_in_the_old_layout(self):
        """Nothing converts it: it is the compatibility test."""
        self.assertFalse((FIXTURE / STATE_DB).exists())
        self.assertFalse((FIXTURE / LEGACY_DIR).exists())
        self.assertTrue((FIXTURE / "findings.json").exists())
        self.assertEqual(Store(FIXTURE).layout, "legacy-json")

    def test_first_write_imports_the_json_and_moves_it_aside(self):
        old = self.legacy()
        before = state(old)
        files = {name: (old.path / name).read_bytes() for name in STATE_FILES.values()
                 if (old.path / name).exists()}
        self.assertIn("findings.json", files)

        old.add_degradation(gap("planted"))

        self.assertEqual(old.layout, "sqlite")
        after = state(old)
        self.assertEqual(after.pop("degradations")[:-1], before.pop("degradations"))
        self.assertEqual(after, before)
        self.assertEqual(old.degradations()[-1].reason, "planted")
        # No JSON state is left where it could be taken for the live state,
        # and none of it was thrown away.
        for name in STATE_FILES.values():
            self.assertFalse((old.path / name).exists(), name)
        self.assertEqual({p.name: p.read_bytes() for p in (old.path / LEGACY_DIR).iterdir()},
                         files)
        self.assertEqual(state(Store(old.path)), state(old))    # a fresh open agrees

    def test_an_imported_run_still_renders_and_diffs(self):
        old, imported = self.legacy("old"), self.legacy("imported")
        imported.checkpoint("discover:tcp", "chunk-0099")
        scope = Scope.load(ROOT / "examples" / "lab" / "scope.json")
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.make_report(old, scope)
            pipeline.make_report(imported, scope)
        self.assertEqual(old.layout, "legacy-json")     # a report is not a state write
        self.assertEqual((imported.path / "report.md").read_text(),
                         (old.path / "report.md").read_text())
        result = diff_runs(old, imported)
        self.assertEqual(len(result["findings"]["same"]), 168)
        for name in ("new", "gone", "changed", "not_rechecked"):
            self.assertEqual(result["findings"][name], [], name)

    def test_records_from_before_a_field_existed_import_with_its_default(self):
        old = self.legacy()
        self.assertNotIn("cves", json.loads((old.path / "findings.json").read_text())[0])
        first = old.findings()[0]
        old.checkpoint("x", "y")
        self.assertEqual(old.findings()[0], first)
        self.assertEqual(old.findings()[0].cves, [])

    def test_a_database_that_died_while_being_created_is_not_trusted(self):
        """Killed before the import committed: a state.db with no tables.
        The JSON is still the state, and the next write imports it."""
        old = self.legacy()
        before = state(old)
        sqlite3.connect(old.db_path).close()
        old.db_path.touch()
        self.assertEqual(state(old), before)
        self.assertEqual(old.layout, "legacy-json")
        old.checkpoint("discover:tcp", "chunk-0099")
        self.assertEqual(old.layout, "sqlite")
        self.assertEqual(len(old.findings()), 168)
        self.assertFalse((old.path / "findings.json").exists())

    def test_stale_json_next_to_a_database_is_ignored_then_moved_aside(self):
        """Killed after the import committed, before the JSON was moved."""
        old = self.legacy()
        kept = (old.path / "findings.json").read_bytes()
        old.replace_findings([finding(1)])
        (old.path / "findings.json").write_bytes(kept)          # the stale file is back

        again = Store(old.path)
        self.assertEqual([f.title for f in again.findings()], ["Finding 1"])
        again.checkpoint("x", "y")
        self.assertFalse((again.path / "findings.json").exists())
        self.assertEqual([f.title for f in again.findings()], ["Finding 1"])
        self.assertEqual(sorted(p.name for p in (again.path / LEGACY_DIR).glob("findings*")),
                         ["findings.json", "findings.json.1"])


class TestExport(_Case):
    def fill(self) -> None:
        self.store.save_hosts([Host("203.0.113.5", ["a.example"], state="up")])
        self.store.save_services([Service("203.0.113.5", 443, "tcp", name="https",
                                          probed_by=["tls"]),
                                  Service("203.0.113.5", 161, "udp", state="open|filtered")])
        self.store.add_findings([finding(1), finding(2, severity="high")])
        self.store.add_leads([lead(1), lead(2, status="done")])
        self.store.add_degradation(gap("a", hosts=["203.0.113.5"]))
        self.store.checkpoint("discover:tcp", "chunk-0001")
        self.store.save_batch_stats("discover:tcp", "chunk-0001", {"asked": 4, "up": 1})
        save(self.store, [Shot(url="https://203.0.113.5", kind="service",
                               service="203.0.113.5/tcp/443", status="captured")])
        self.store.log_command(CommandRecord(argv=["nmap"], started=1.0, duration=2.0,
                                             returncode=0))

    def test_an_export_reads_back_as_the_same_run(self):
        self.fill()
        written = self.store.export()
        out = self.store.path / EXPORT_DIR
        self.assertEqual({p.name for p in written},
                         {*STATE_FILES.values(), "run.json", "commands.jsonl"})
        self.assertEqual({p.parent for p in written}, {out})
        copy = Store(out)
        self.assertEqual(copy.layout, "legacy-json")
        self.assertEqual(state(copy), state(self.store))
        self.assertEqual(copy.meta(), self.store.meta())
        self.assertEqual(copy.commands(), self.store.commands())
        # Plain JSON, one list of records per file.
        rows = json.loads((out / "findings.json").read_text())
        self.assertEqual([r["title"] for r in rows], ["Finding 1", "Finding 2"])
        # The export changed nothing in the run, and is not taken for its state.
        self.store.add_findings([finding(3)])
        self.assertEqual(len(self.store.findings()), 3)
        self.assertTrue((out / "findings.json").exists())
        self.assertFalse((self.store.path / LEGACY_DIR).exists())

    def test_export_of_an_old_run_matches_its_files(self):
        old = self.legacy()
        before = snapshot(old.path)
        out = self.tmp / "out"
        old.export(out)
        self.assertEqual(snapshot(old.path), before)
        for name in ("services.json", "leads.json", "degradations.json", "checkpoints.json"):
            self.assertEqual(json.loads((out / name).read_text()),
                             json.loads((FIXTURE / name).read_text()), name)
        # Records from before a field existed come out with its default.
        for name, cls in (("hosts.json", Host), ("findings.json", Finding)):
            self.assertEqual(
                json.loads((out / name).read_text()),
                [cls.from_dict(d).to_dict() for d in json.loads((FIXTURE / name).read_text())],
                name)
        self.assertEqual((out / "commands.jsonl").read_bytes(),
                         (FIXTURE / "commands.jsonl").read_bytes())

    def test_export_refuses_the_run_directory_itself(self):
        self.fill()
        with self.assertRaisesRegex(ValueError, "look like live state"):
            self.store.export(self.store.path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(["--runs-dir", str(self.tmp / "runs"), "export", "r",
                             "--out", str(self.store.path)])
        self.assertEqual(code, 2)
        self.assertFalse((self.store.path / "findings.json").exists())

    def cli_json(self, *argv: str):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["--runs-dir", str(self.tmp / "runs"), "--json", *argv]), 0)
        return json.loads(out.getvalue())

    def test_every_collection_is_reachable_from_the_cli(self):
        self.fill()
        self.assertEqual(self.cli_json("hosts", "r"),
                         [h.to_dict() for h in self.store.hosts()])
        self.assertEqual([s["id"] for s in self.cli_json("services", "r")],
                         [s.id for s in self.store.services()])
        self.assertEqual({f["id"] for f in self.cli_json("findings", "r")},
                         {f.id for f in self.store.findings()})
        self.assertEqual(self.cli_json("leads", "r", "--status", "all"),
                         [ld.to_dict() for ld in self.store.leads()])
        self.assertEqual(self.cli_json("gaps", "r"),
                         [d.to_dict() for d in self.store.degradations()])
        self.assertEqual(self.cli_json("screenshot", "r", "--list"), self.store.screenshots())
        status = self.cli_json("status", "r")
        self.assertEqual(status["checkpoints"], {"discover:tcp": 1})
        self.assertEqual(status["layout"], "sqlite")

        out = self.tmp / "exported"
        result = self.cli_json("export", "r", "--out", str(out))
        self.assertEqual(result["out"], str(out))
        self.assertEqual(json.loads((out / "checkpoints.json").read_text()),
                         {"discover:tcp": ["chunk-0001"]})
        self.assertEqual(json.loads((out / "batches.json").read_text()),
                         {"discover:tcp": {"chunk-0001": {"asked": 4, "up": 1}}})
        self.assertEqual(state(Store(out)), state(self.store))

    def test_listing_screenshots_captures_nothing(self):
        self.fill()
        with mock.patch.object(pipeline, "screenshot",
                               side_effect=AssertionError("the stage ran")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["--runs-dir", str(self.tmp / "runs"), "screenshot",
                                       "r", "--list"]), 0)
        self.assertIn("[captured] https://203.0.113.5", out.getvalue())


@unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                 "needs an unprivileged POSIX user")
class TestRootAndUser(_Case):
    """`sudo extscan discover <run> --udp-only` writes into a run the user
    owns. Real root is not available to the suite, so the two halves are
    tested apart: what root would be made to do (a patched euid, a recorded
    chown), and what a user sees when a database is not theirs to write."""

    def as_root(self):
        chowned: list[tuple[str, int, int]] = []
        patches = contextlib.ExitStack()
        patches.enter_context(mock.patch("extscan.store.os.geteuid", return_value=0))
        patches.enter_context(mock.patch(
            "extscan.store.os.chown",
            side_effect=lambda p, uid, gid: chowned.append((Path(p).name, uid, gid))))
        self.addCleanup(patches.close)
        return chowned

    def test_files_root_creates_are_given_to_the_run_directory_owner(self):
        owner = (os.getuid(), self.store.path.stat().st_gid)
        chowned = self.as_root()
        self.store.add_findings([finding(1)])
        self.store.mark_stage("discover")
        self.store.log_command(CommandRecord(argv=["nmap"], started=0.0, duration=0.0,
                                             returncode=0))
        self.assertIn((STATE_DB, *owner), chowned)
        self.assertIn((".run.json.tmp", *owner), chowned)
        self.assertIn(("commands.jsonl", *owner), chowned)

    def test_root_importing_an_old_run_hands_over_the_database_and_the_json(self):
        old = self.legacy()
        chowned = self.as_root()
        old.checkpoint("discover:udp", "chunk-0001")
        self.assertEqual({name for name, _, _ in chowned}, {STATE_DB, LEGACY_DIR})

    def test_a_root_owned_run_directory_is_left_alone(self):
        chowned = self.as_root()
        real = self.store.path.stat()
        fake = os.stat_result((real.st_mode, real.st_ino, real.st_dev, real.st_nlink, 0, 0,
                               real.st_size, real.st_atime, real.st_mtime, real.st_ctime))
        with mock.patch.object(Path, "stat", return_value=fake):
            self.store._hand_over(self.store.db_path)
        self.assertEqual(chowned, [])

    def test_a_database_the_user_cannot_write_says_what_to_chown(self):
        self.store.add_findings([finding(1)])
        self.store.close()
        self.store.db_path.chmod(0o444)             # as a root-owned 0644 file is, to a user
        self.addCleanup(self.store.db_path.chmod, 0o644)
        self.assertEqual(len(self.store.findings()), 1)         # still readable
        with self.assertRaisesRegex(PermissionError, r"sudo chown -R .*runs/r"):
            self.store.add_findings([finding(2)])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(["--runs-dir", str(self.tmp / "runs"), "note", "r",
                             "--title", "t"])
        self.assertEqual(code, 2)
        self.assertIn("sudo chown -R", err.getvalue())
        self.store.close()
        self.store.db_path.chmod(0o644)
        self.assertEqual(self.store.add_findings([finding(2)]), 1)      # and it recovers


if __name__ == "__main__":
    unittest.main()
