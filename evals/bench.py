"""Efficiency benchmarks for the parts of extscan that are not a scanner.

nmap and nuclei own most of a run's wall-clock, and their pace is set by the
policy's rate limits, which are agreed with the client. What extscan itself
controls is the bookkeeping and its own network checks, measured here against
a budget. No scanner and no network beyond loopback.

    uv run python -m evals.bench
"""

from __future__ import annotations

import socket
import tempfile
import time

from extscan.models import Finding, Lead, Service
from extscan.policy import Policy
from extscan.resilience import Degradation
from extscan.store import Store
from extscan.tools import snmp

PROBES = ("http_fingerprint", "tls", "sslscan", "nuclei")


def mark_probed_seconds(services: int = 1000) -> float:
    """Record four probes on each of `services` services, as `probe` does."""
    with tempfile.TemporaryDirectory() as d:
        store = Store.create(d, "bench")
        svcs = [Service(host=f"203.0.113.{i % 250}", port=1000 + i, proto="tcp", name="http")
                for i in range(services)]
        store.save_services(svcs)
        started = time.perf_counter()
        store.mark_probed_many((s.id, p) for s in svcs for p in PROBES)
        return time.perf_counter() - started


def _expect(got: int, want: int) -> None:
    if got != want:
        raise RuntimeError(f"benchmark wrote {got} record(s), expected {want}")


def _bench_store(d: str) -> Store:
    store = Store.create(d, "bench")
    store.write_meta({"run_id": store.run_id})
    return store


def add_findings_seconds(total: int = 20_000, batch: int = 50) -> float:
    """Add `total` findings `batch` at a time, as discovery batches, nuclei
    batches and chased leads do over a large run."""
    with tempfile.TemporaryDirectory() as d:
        store = _bench_store(d)
        findings = [Finding(title=f"Finding {i}", severity="low",
                            host=f"203.0.{i // 250 % 250}.{i % 250}", port=443,
                            source="bench", evidence="GET / HTTP/1.1\n" * 8)
                    for i in range(total)]
        started = time.perf_counter()
        for i in range(0, total, batch):
            store.add_findings(findings[i:i + batch])
        elapsed = time.perf_counter() - started
        _expect(len(store.findings()), total)
        return elapsed


def update_lead_seconds(leads: int = 2000) -> float:
    """Resolve every lead of a `leads`-lead run one at a time, as chase does."""
    with tempfile.TemporaryDirectory() as d:
        store = _bench_store(d)
        made = [Lead(kind="web_paths", host=f"203.0.113.{i % 250}", port=8000 + i,
                     url=f"http://203.0.113.{i % 250}:{8000 + i}/", reason="bench")
                for i in range(leads)]
        store.add_leads(made)
        started = time.perf_counter()
        for ld in made:
            store.update_lead(ld.id, status="done", note="nothing found", attempts=1)
        elapsed = time.perf_counter() - started
        _expect(len(store.leads("done")), leads)
        return elapsed


def checkpoint_seconds(batches: int = 5000) -> float:
    """What discovery records for each finished batch: its figures and its
    checkpoint, together."""
    with tempfile.TemporaryDirectory() as d:
        store = _bench_store(d)
        started = time.perf_counter()
        for i in range(batches):
            key = f"chunk-{i:04d}"
            with store.transaction():
                store.save_batch_stats("discover:sweep", key, {
                    "asked": 256, "up": 4,
                    "open": {f"198.51.{i % 250}.{h}": [80, 443] for h in range(4)}})
                store.checkpoint("discover:sweep", key)
        elapsed = time.perf_counter() - started
        _expect(len(store.checkpoints("discover:sweep")), batches)
        _expect(len(store.batch_stats("discover:sweep")), batches)
        return elapsed


def degradation_cycle_seconds(cycles: int = 1000, standing: int = 500) -> float:
    """Record a gap and clear it again, `cycles` times, on a run that already
    carries `standing` gaps: what every probe and discovery batch does."""
    with tempfile.TemporaryDirectory() as d:
        store = _bench_store(d)
        for i in range(standing):
            store.add_degradation(Degradation(
                stage="probe:tls", component="tls", reason=f"203.0.113.{i}/tcp/443: timed out",
                impact="The tls check did not run.", hosts=[f"203.0.113.{i}"]))
        started = time.perf_counter()
        for i in range(cycles):
            reason = f"tcp-{i:04d} produced no parseable output (exit 1)"
            store.add_degradation(Degradation(
                stage="discover:tcp", component="nmap", reason=reason,
                impact="Hosts in this batch were not scanned.", hosts=["198.51.100.1"]))
            store.remove_degradations(
                lambda g, reason=reason: g.stage == "discover:tcp" and g.reason == reason)
        elapsed = time.perf_counter() - started
        _expect(len(store.degradations()), standing)
        return elapsed


def snmp_silent_seconds(policy: Policy | None = None) -> float:
    """Community check against a port that answers nothing, the common case
    for an `open|filtered` UDP 161."""
    policy = policy or Policy()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
        sink.bind(("127.0.0.1", 0))
        started = time.perf_counter()
        snmp.check_community_strings("127.0.0.1", policy, port=sink.getsockname()[1])
        return time.perf_counter() - started


def snmp_budget(policy: Policy) -> float:
    """One timeout per round, plus the paced sends, plus slack."""
    p = policy.snmp
    sends = len(p.communities) * len(p.versions) * snmp.SWEEP_SEND_GAP
    return (p.retries + 1) * (p.timeout_sec + sends) + 0.5


# The store budgets are set where the JSON-file store (one whole-file rewrite
# per call) could not get, and the SQLite store meets with room to spare.
# Measured on one workstation, old store / new store on tmpfs / new store on
# a disk where each commit is an fsync (about 1 ms):
#   add 20,000 findings          283 s / 1.2 s / 2.8 s
#   update 2000 leads            172 s / 0.4 s / 2.8 s
#   5000 batch records           345 s / 1.0 s / 7.1 s
#   1000 gap cycles               30 s / 0.5 s / 2.7 s
BUDGETS = {
    "mark_probed_1000_services": 2.0,
    "add_20000_findings": 15.0,
    "update_2000_leads": 10.0,
    "checkpoint_5000": 15.0,
    "degradation_1000_cycles": 5.0,
}


def main() -> int:
    policy = Policy()
    rows = [
        ("mark 1000 services x 4 probes", mark_probed_seconds(1000),
         BUDGETS["mark_probed_1000_services"]),
        ("add 20,000 findings in batches of 50", add_findings_seconds(),
         BUDGETS["add_20000_findings"]),
        ("update_lead x 2000 on a 2000-lead run", update_lead_seconds(),
         BUDGETS["update_2000_leads"]),
        ("5000 batches: figures and checkpoint", checkpoint_seconds(),
         BUDGETS["checkpoint_5000"]),
        ("1000 gap add/remove cycles, 500 standing", degradation_cycle_seconds(),
         BUDGETS["degradation_1000_cycles"]),
        ("SNMP check, silent agent, default policy", snmp_silent_seconds(policy),
         snmp_budget(policy)),
    ]
    failed = False
    for label, seconds, budget in rows:
        ok = seconds <= budget
        failed |= not ok
        print(f"{'ok  ' if ok else 'OVER'} {label:<44} {seconds:7.2f}s  (budget {budget:.1f}s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
