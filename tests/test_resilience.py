"""Failure handling: retries, circuit breaking, abort detection, salvage.

The scenario these exist for: a long scan where something breaks partway. The
requirement is never "don't break" -- it is "when you break, lose as little as
possible and say exactly what was lost".
"""

import contextlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from extscan.policy import Policy
from extscan.resilience import (
    AbortThreshold,
    CircuitBreaker,
    CircuitOpen,
    Degradation,
    PermanentError,
    RetryPolicy,
    RunAborted,
    classify,
    is_retryable,
    retry,
)
from extscan.scope import Scope
from extscan.store import Store
from extscan.tools import nmap


class TestErrorClassification(unittest.TestCase):
    def test_timeouts_and_connection_errors_are_transient(self):
        for exc in (TimeoutError("timed out"), ConnectionResetError("reset"),
                    ConnectionRefusedError("refused")):
            self.assertEqual(classify(exc), "transient", repr(exc))

    def test_explicit_permanent_error(self):
        self.assertEqual(classify(PermanentError("bad config")), "permanent")

    def test_http_status_decides_retryability(self):
        import urllib.error

        def err(code):
            return urllib.error.HTTPError("http://x", code, "msg", {}, None)

        for code in (429, 500, 502, 503, 504):
            self.assertEqual(classify(err(code)), "transient", code)
        for code in (400, 401, 403, 404, 422):
            self.assertEqual(classify(err(code)), "permanent", code)

    def test_message_markers_catch_generic_exceptions(self):
        self.assertEqual(classify(RuntimeError("Service Unavailable")), "transient")
        self.assertEqual(classify(RuntimeError("rate limit exceeded")), "transient")
        self.assertEqual(classify(RuntimeError("something odd")), "unknown")

    def test_unknown_not_retried_unless_asked(self):
        exc = RuntimeError("something odd")
        self.assertFalse(is_retryable(exc))
        self.assertTrue(is_retryable(exc, retry_unknown=True))


class TestRetry(unittest.TestCase):
    def setUp(self):
        self.slept: list[float] = []
        self.policy = RetryPolicy(attempts=4, base_delay=1.0, multiplier=2.0,
                                  jitter=0.0, total_budget=1000.0)

    def _sleep(self, seconds):
        self.slept.append(seconds)

    def test_succeeds_without_retry(self):
        calls = []

        def fn():
            calls.append(1)
            return "ok"

        self.assertEqual(retry(fn, self.policy, sleep=self._sleep), "ok")
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.slept, [])

    def test_retries_transient_then_succeeds(self):
        calls = []

        def fn():
            calls.append(1)
            if len(calls) < 3:
                raise TimeoutError("not yet")
            return "ok"

        self.assertEqual(retry(fn, self.policy, sleep=self._sleep), "ok")
        self.assertEqual(len(calls), 3)
        self.assertEqual(self.slept, [1.0, 2.0])        # exponential

    def test_does_not_retry_permanent(self):
        calls = []

        def fn():
            calls.append(1)
            raise PermanentError("bad credentials")

        with self.assertRaises(PermanentError):
            retry(fn, self.policy, sleep=self._sleep)
        self.assertEqual(len(calls), 1, "a permanent failure must not be retried")

    def test_gives_up_after_attempts_and_reraises(self):
        def fn():
            raise TimeoutError("always")

        with self.assertRaises(TimeoutError):
            retry(fn, self.policy, sleep=self._sleep)
        self.assertEqual(len(self.slept), 3)            # 4 attempts, 3 waits

    def test_respects_time_budget(self):
        policy = RetryPolicy(attempts=10, base_delay=10.0, jitter=0.0,
                             total_budget=15.0)

        def fn():
            raise TimeoutError("always")

        with self.assertRaises(TimeoutError):
            retry(fn, policy, sleep=self._sleep)
        # Budget stops it well before 10 attempts.
        self.assertLess(len(self.slept), 4)

    def test_delay_is_capped(self):
        policy = RetryPolicy(attempts=8, base_delay=1.0, multiplier=10.0,
                             max_delay=5.0, jitter=0.0, total_budget=10_000)
        self.assertEqual(policy.delay_for(1), 1.0)
        self.assertEqual(policy.delay_for(5), 5.0)

    def test_jitter_stays_in_range(self):
        policy = RetryPolicy(base_delay=10.0, jitter=0.3, max_delay=100)
        for _ in range(50):
            delay = policy.delay_for(1)
            self.assertGreaterEqual(delay, 7.0)
            self.assertLessEqual(delay, 13.0)

    def test_on_retry_callback_receives_detail(self):
        seen = []

        def fn():
            if len(seen) < 1:
                raise TimeoutError("once")
            return "ok"

        retry(fn, self.policy, on_retry=lambda n, exc, d: seen.append((n, type(exc), d)),
              sleep=self._sleep)
        self.assertEqual(seen[0][0], 1)
        self.assertIs(seen[0][1], TimeoutError)


class TestCircuitBreaker(unittest.TestCase):
    def test_opens_after_threshold(self):
        cb = CircuitBreaker(name="t", failure_threshold=3, cooldown=60)
        self.assertEqual(cb.state, "closed")
        for _ in range(3):
            cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertFalse(cb.allows())
        self.assertEqual(cb.trips, 1)

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        self.assertEqual(cb.state, "closed", "count should have reset on success")

    def test_open_circuit_raises_without_calling(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown=60)
        calls = []
        with self.assertRaises(TimeoutError):
            cb.call(lambda: (_ for _ in ()).throw(TimeoutError("x")))
        with self.assertRaises(CircuitOpen):
            cb.call(lambda: calls.append(1))
        self.assertEqual(calls, [], "the callable must not run while open")

    def test_half_open_after_cooldown_then_closes_on_success(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown=0.0)
        cb.record_failure()
        self.assertEqual(cb.state, "half-open")       # cooldown already elapsed
        self.assertTrue(cb.allows())
        self.assertEqual(cb.call(lambda: "ok"), "ok")
        self.assertEqual(cb.state, "closed")

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown=0.0)
        cb.record_failure()
        self.assertEqual(cb.state, "half-open")
        cb.record_failure()
        self.assertIsNotNone(cb._opened_at)

    def test_permanent_errors_do_not_trip_the_breaker(self):
        """A caller bug should not take out the dependency's circuit."""
        cb = CircuitBreaker(failure_threshold=2)
        for _ in range(5):
            with self.assertRaises(PermanentError):
                cb.call(lambda: (_ for _ in ()).throw(PermanentError("our bug")))
        self.assertEqual(cb.state, "closed")

    def test_bounded_total_calls_when_dependency_is_down(self):
        """The property that matters: a dead dependency costs bounded work."""
        cb = CircuitBreaker(failure_threshold=3, cooldown=600)
        attempts = []

        def dead():
            attempts.append(1)
            raise TimeoutError("down")

        for _ in range(100):
            with contextlib.suppress(TimeoutError, CircuitOpen):
                cb.call(dead)
        self.assertEqual(len(attempts), 3,
                         "100 requests against a dead dependency must not make "
                         "100 calls")


class TestAbortThreshold(unittest.TestCase):
    def test_does_not_abort_before_min_samples(self):
        at = AbortThreshold(min_samples=10, failure_ratio=0.9)
        for _ in range(9):
            at.record(ok=False)
        self.assertFalse(at.should_abort())
        at.check()          # must not raise

    def test_aborts_when_nearly_everything_fails(self):
        at = AbortThreshold(min_samples=5, failure_ratio=0.9)
        for _ in range(10):
            at.record(ok=False)
        self.assertTrue(at.should_abort())
        with self.assertRaises(RunAborted) as cm:
            at.check(context="tcp discovery")
        message = str(cm.exception)
        self.assertIn("tcp discovery", message)
        self.assertIn("local", message)        # tells the operator where to look

    def test_does_not_abort_on_mixed_results(self):
        at = AbortThreshold(min_samples=5, failure_ratio=0.95)
        for i in range(20):
            at.record(ok=(i % 4 == 0))
        self.assertFalse(at.should_abort())


class TestPartialScanSalvage(unittest.TestCase):
    """A timeout must cost one host, not the whole range."""

    HEADER = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
              '<nmaprun scanner="nmap" version="7.94">\n')

    def host(self, last_octet, port):
        return (f'<host><status state="up"/>'
                f'<address addr="203.0.113.{last_octet}" addrtype="ipv4"/>'
                f'<ports><port protocol="tcp" portid="{port}">'
                f'<state state="open"/><service name="http"/></port></ports></host>\n')

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["203.0.113.0/24"],
        }))
        self.scope = Scope.load(sp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_complete_file_is_untouched(self):
        xml = self.HEADER + self.host(10, 80) + "</nmaprun>"
        out, repaired = nmap.salvage_partial_xml(xml)
        self.assertFalse(repaired)
        self.assertEqual(out, xml.rstrip())

    def test_recovers_completed_hosts_from_truncated_file(self):
        xml = (self.HEADER + self.host(10, 443) + self.host(11, 22)
               + '<host><status state="up"/><address addr="203.0.113.12" '
                 'addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
                 '<state state="op')
        out, repaired = nmap.salvage_partial_xml(xml)
        self.assertTrue(repaired)
        hosts, services, _ = nmap.parse_xml(out, scope=self.scope)
        self.assertEqual(len(hosts), 2)
        self.assertEqual({s.port for s in services}, {443, 22})

    def test_truncated_mid_host_drops_only_that_host(self):
        xml = self.HEADER + self.host(10, 443) + '<host><status state="up"/><addre'
        out, _ = nmap.salvage_partial_xml(xml)
        hosts, _, _ = nmap.parse_xml(out, scope=self.scope)
        self.assertEqual([h.ip for h in hosts], ["203.0.113.10"])

    def test_nothing_completed_yields_valid_empty_document(self):
        out, repaired = nmap.salvage_partial_xml(self.HEADER)
        self.assertTrue(repaired)
        hosts, services, _ = nmap.parse_xml(out, scope=self.scope)
        self.assertEqual((hosts, services), ([], []))

    def test_no_root_element_is_unsalvageable(self):
        out, repaired = nmap.salvage_partial_xml('<?xml version="1.0"?>\n<!DOCT')
        self.assertEqual(out, "")
        self.assertFalse(repaired)

    def test_empty_input(self):
        self.assertEqual(nmap.salvage_partial_xml(""), ("", False))

    def test_real_nmap_doctype_is_accepted(self):
        """nmap emits `<!DOCTYPE nmaprun>`; the XML guard must allow it."""
        xml = self.HEADER + self.host(10, 80) + "</nmaprun>"
        hosts, _, _ = nmap.parse_xml(xml, scope=self.scope)
        self.assertEqual(len(hosts), 1)

    def test_entity_declaration_is_refused(self):
        bomb = ('<?xml version="1.0"?>\n<!DOCTYPE nmaprun [<!ENTITY a "x">]>\n'
                '<nmaprun></nmaprun>')
        with self.assertRaises(ValueError) as cm:
            nmap.parse_xml(bomb, scope=self.scope)
        self.assertIn("ENTITY", str(cm.exception))

    def test_doctype_with_internal_subset_is_refused(self):
        with self.assertRaises(ValueError):
            nmap.parse_xml('<!DOCTYPE nmaprun [ ]>\n<nmaprun/>', scope=self.scope)


class TestChunkingAndCheckpoints(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["203.0.113.0/28"],
        }))
        self.scope = Scope.load(sp)
        self.store = Store.create(self.tmp / "runs", "t", run_id="r")
        self.store.write_meta({"run_id": "r"})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_chunks_cover_every_host_exactly_once(self):
        chunks = nmap.chunk_targets(self.scope, 4)
        flat = [host for chunk in chunks for host in chunk]
        self.assertEqual(sorted(flat), sorted(self.scope.hosts()))
        self.assertEqual(len(flat), len(set(flat)))

    def test_chunk_size_zero_disables_chunking(self):
        self.assertEqual(nmap.chunk_targets(self.scope, 0), [self.scope.targets])

    def test_small_scope_is_one_chunk(self):
        self.assertEqual(len(nmap.chunk_targets(self.scope, 100)), 1)

    def test_checkpoints_persist_and_resume_skips(self):
        self.store.checkpoint("discover:tcp", "chunk-0001")
        self.store.checkpoint("discover:tcp", "chunk-0002")
        reopened = Store.open(self.tmp / "runs", "r")
        self.assertEqual(reopened.checkpoints("discover:tcp"),
                         {"chunk-0001", "chunk-0002"})
        self.assertTrue(reopened.is_done("discover:tcp", "chunk-0001"))
        self.assertFalse(reopened.is_done("discover:tcp", "chunk-0003"))

    def test_checkpoints_are_per_stage(self):
        self.store.checkpoint("discover:tcp", "chunk-0001")
        self.assertEqual(self.store.checkpoints("discover:udp"), set())

    def test_clear_checkpoints_for_one_stage(self):
        self.store.checkpoint("discover:tcp", "a")
        self.store.checkpoint("discover:udp", "b")
        self.store.clear_checkpoints("discover:tcp")
        self.assertEqual(self.store.checkpoints("discover:tcp"), set())
        self.assertEqual(self.store.checkpoints("discover:udp"), {"b"})

    def test_checkpointing_is_idempotent(self):
        for _ in range(3):
            self.store.checkpoint("s", "k")
        self.assertEqual(len(self.store.checkpoints("s")), 1)


class TestDegradationRecords(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = Store.create(self.tmp, "t", run_id="r")
        self.store.write_meta({"run_id": "r"})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_recorded_and_survives_reopen(self):
        self.store.add_degradation(Degradation(
            stage="discover:udp", component="nmap",
            reason="needs root", impact="no UDP coverage", severity="serious"))
        reopened = Store.open(self.tmp, "r")
        gaps = reopened.degradations()
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].severity, "serious")
        self.assertEqual(gaps[0].impact, "no UDP coverage")

    def test_duplicates_collapse(self):
        deg = Degradation(stage="probe", component="nuclei",
                          reason="not installed", impact="no web checks")
        self.store.add_degradation(deg)
        self.store.add_degradation(deg)
        self.assertEqual(len(self.store.degradations()), 1)

    def test_surfaced_in_counts(self):
        self.store.add_degradation(Degradation(
            stage="probe", component="x", reason="y", impact="z"))
        self.assertEqual(self.store.counts()["degradations"], 1)

    def test_appears_in_rendered_report(self):
        """A gap nobody reads about is the failure this layer exists to prevent."""
        from extscan.report import render_markdown
        from extscan.triage import triage

        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T-1", "authorized_by": "x"},
            "targets": ["203.0.113.0/29"],
        }))
        scope = Scope.load(sp)
        gap = Degradation(
            stage="discover:udp", component="nmap", reason="needs root",
            impact="No UDP scanning was performed", severity="serious",
            remedy="re-run as root")
        md = render_markdown(scope, triage([], []), [], [], {"run_id": "r"},
                             [], [gap])
        self.assertIn("Coverage gaps", md)
        self.assertIn("No UDP scanning was performed", md)
        self.assertIn("re-run as root", md)
        # And the summary warns, so a skimming reader cannot miss it.
        self.assertIn("coverage gap", md.split("## Manual review queue")[0].lower())


class TestLeadAttemptTracking(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = Store.create(self.tmp, "t", run_id="r")
        self.store.write_meta({"run_id": "r"})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_attempts_and_error_persist(self):
        from extscan.models import Lead

        lead = Lead(kind="openapi", host="203.0.113.1", url="http://x/spec")
        self.store.add_leads([lead])
        self.store.update_lead(lead.id, attempts=2, last_error="TimeoutError: x")
        reloaded = self.store.leads()[0]
        self.assertEqual(reloaded.attempts, 2)
        self.assertIn("TimeoutError", reloaded.last_error)

    def test_policy_caps_attempts(self):
        self.assertGreaterEqual(Policy.for_profile("standard").max_lead_attempts, 1)
        self.assertLessEqual(Policy.for_profile("standard").max_lead_attempts, 10)


if __name__ == "__main__":
    unittest.main()
