"""The nmap passes of the discover stage: batches, checkpoints, coverage gaps.

A pass is a list of batches, run one after another or `nmap.parallel` at a
time. Each finished batch is parsed, stored and checkpointed in one commit,
so a timeout or a kill costs the batches in flight and `extscan resume`
carries on from there.

TCP has two shapes. Single-phase gives every batch of `nmap.chunk_size` hosts
one nmap run that does ports, versions and scripts together. Two-phase first
sweeps the scope for open ports only, in larger batches, then runs that full
scan against just the hosts that had one, on just the ports found. On a
sparse range most addresses have nothing listening, and the sweep is what
keeps them from costing a full scan each.

Whatever nmap could not do properly is recorded as a `Degradation`:

* a batch that failed or was cut short (reason starts with the batch label,
  so a clean re-run of that batch clears it);
* hosts nmap gave up retrying, or skipped on its host timeout (same);
* addresses that did not answer host discovery, one gap per pass;
* UDP ports left `open|filtered`, one gap for the UDP pass.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass

from .policy import Policy
from .resilience import AbortThreshold, Degradation
from .runner import Runner, ToolMissing
from .scope import Scope
from .store import Store
from .tools import nmap

TCP = "discover:tcp"
UDP = "discover:udp"
SWEEP = "discover:sweep"

NMAP_MISSING = str(ToolMissing("nmap"))
HOST_DISCOVERY = "nmap:host-discovery"
OPEN_FILTERED = "nmap:open-filtered"

# A batch label at the start of a gap reason: tcp-0003, udp-0001,
# sweep-tcp-0002, tcp-0002-01, tcp-0002-01-full.
_LABEL_RE = re.compile(r"((?:sweep-)?(?:tcp|udp)-\d{4,}(?:-\d{2,})?(?:-full)?) ")

# execve refuses a single argument over 128 KiB; stay well inside it.
_MAX_PORT_SPEC = 60_000


@dataclass
class Batch:
    key: str                    # checkpoint key
    label: str                  # raw file name and gap-reason prefix
    targets: list[str]
    ports: str | None = None    # phase two: only the ports the sweep found
    assume_up: bool = False     # phase two: the sweep already saw these hosts


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _by_address(hosts) -> list[str]:
    def key(h: str):
        if not _is_ip(h):
            return (9, 0, h)
        return (ipaddress.ip_address(h).version, int(ipaddress.ip_address(h)), h)
    return sorted(hosts, key=key)


def two_phase(scope: Scope, policy: Policy) -> bool:
    """Whether the TCP pass sweeps first. `auto` keeps a scope that fits in
    one batch single-phase, where a sweep would only add a second nmap run."""
    mode = policy.nmap.sweep
    if mode not in ("auto", "always", "never"):
        raise ValueError(f"nmap.sweep is {mode!r}: use auto, always or never")
    if mode != "auto":
        return mode == "always"
    return 0 < policy.nmap.chunk_size < scope.host_count()


def run_pass(store: Store, scope: Scope, policy: Policy, runner: Runner,
             kind: str, resume: bool) -> dict | None:
    """Run the TCP or UDP pass. Returns its totals, or None if nothing ran."""
    if kind == "tcp" and two_phase(scope, policy):
        return _run_two_phase(store, scope, policy, runner, resume)

    chunks = nmap.chunk_targets(scope, policy.nmap.chunk_size)
    if not chunks:
        return None
    stage = f"discover:{kind}"
    batches = [Batch(f"chunk-{i:04d}", f"{kind}-{i:04d}", targets)
               for i, targets in enumerate(chunks, start=1)]
    done = store.checkpoints(stage) if resume else set()
    if not resume and not runner.dry_run:
        _forget(store, [stage] + ([SWEEP] if kind == "tcp" else []))

    totals = _scan(store, scope, policy, runner, kind, stage, batches, done)
    if totals is not None and not runner.dry_run:
        # A single-phase TCP pass covers the scope by itself, so anything a
        # sweep recorded earlier in this run is superseded.
        _settle(store, {stage: batches, **({SWEEP: []} if kind == "tcp" else {})})
    return totals


def _run_two_phase(store: Store, scope: Scope, policy: Policy, runner: Runner,
                   resume: bool) -> dict | None:
    p = policy.nmap
    hosts = scope.hosts()
    if not hosts:
        return None
    sweeps = [Batch(f"chunk-{i:04d}", f"sweep-tcp-{i:04d}", targets)
              for i, targets in enumerate(nmap.split_hosts(hosts, p.sweep_chunk_size), start=1)]
    if not resume and not runner.dry_run:
        _forget(store, [SWEEP, TCP])
    tcp_done = store.checkpoints(TCP) if resume else set()
    sweep_done = store.checkpoints(SWEEP) if resume else set()
    # A sweep batch that failed and whose hosts were then all scanned the
    # single-phase way is covered; sweeping it again would buy nothing.
    sweep_done |= {b.key for i, b in enumerate(sweeps, start=1)
                   if _full_keys(i, b, p.chunk_size) <= tcp_done}

    print(f"  phase 1: sweep {len(hosts)} host(s) for open ports, "
          f"{len(sweeps)} batch(es)")
    swept = _scan(store, scope, policy, runner, "sweep", SWEEP, sweeps, sweep_done)
    if swept is None:
        return None

    found = store.batch_stats(SWEEP)
    plan = _fingerprint_plan(sweeps, found, p, fallback=not runner.dry_run)
    print(f"  phase 2: service detection on {sum(len(b.targets) for b in plan)} host(s) "
          f"with open ports, {len(plan)} batch(es)")
    if runner.dry_run and any(b.key not in found for b in sweeps):
        # Which hosts and ports phase two gets is only known after the sweep.
        shape = nmap.tcp_argv(scope, policy, str(store.raw_path("nmap-tcp-NNNN-NN")),
                              targets=["<hosts the sweep found open ports on>"],
                              ports="<their open ports>", assume_up=True)
        print(f"  $ {' '.join(shape)}")
        print("    (dry run: one such command per batch of hosts with open ports)")
    totals = _scan(store, scope, policy, runner, "tcp", TCP, plan, tcp_done)
    if totals is None:
        return None
    totals["sweep"] = swept

    if not runner.dry_run:
        done_now = store.checkpoints(TCP)
        rescued = tuple(f"{b.label} " for i, b in enumerate(sweeps, start=1)
                        if b.key not in found
                        and _full_keys(i, b, p.chunk_size) <= done_now)
        if rescued:
            store.remove_degradations(
                lambda d: d.stage == SWEEP and d.reason.startswith(rescued))
        _settle(store, {SWEEP: sweeps, TCP: plan})
    return totals


def _full_keys(index: int, sweep: Batch, chunk_size: int) -> set[str]:
    """Checkpoint keys of the single-phase batches that stand in for one
    failed sweep batch."""
    parts = len(nmap.split_hosts(sweep.targets, chunk_size))
    return {f"chunk-{index:04d}-{j:02d}-full" for j in range(1, parts + 1)}


def _fingerprint_plan(sweeps: list[Batch], found: dict[str, dict], p,
                      fallback: bool = True) -> list[Batch]:
    """Phase-two batches, derived from each sweep batch on its own.

    Keeping them tied to their sweep batch is what makes resume work: a
    sweep batch's hosts and results are fixed once it is checkpointed, so its
    phase-two batches have the same members and the same keys on every run.

    A sweep batch with no results (it failed) is not dropped: its hosts get
    the single-phase scan, all ports and with host discovery, under `-full`
    labels.
    """
    plan: list[Batch] = []
    for i, sweep in enumerate(sweeps, start=1):
        stats = found.get(sweep.key)
        if stats is None:
            if fallback:
                plan += [Batch(f"chunk-{i:04d}-{j:02d}-full", f"tcp-{i:04d}-{j:02d}-full", part)
                         for j, part in enumerate(
                             nmap.split_hosts(sweep.targets, p.chunk_size), start=1)]
            continue
        open_ports = stats.get("open", {})
        live = [h for h in sweep.targets if open_ports.get(h)]
        for j, part in enumerate(nmap.split_hosts(live, p.chunk_size), start=1):
            # nmap takes one port list for the whole run, so a batch scans
            # the union of its hosts' open ports.
            spec = nmap.port_spec(port for h in part for port in open_ports[h])
            plan.append(Batch(f"chunk-{i:04d}-{j:02d}", f"tcp-{i:04d}-{j:02d}", part,
                              ports=spec if len(spec) <= _MAX_PORT_SPEC else None,
                              assume_up=True))
    return plan


def _forget(store: Store, stages: list[str]) -> None:
    for stage in stages:
        store.clear_checkpoints(stage)
        store.keep_batch_stats(stage, [])


def _run_batch(runner: Runner, scope: Scope, policy: Policy, kind: str, batch: Batch):
    if kind == "sweep":
        return nmap.run_sweep(runner, scope, policy, targets=batch.targets, label=batch.label)
    if kind == "udp":
        return nmap.run_udp(runner, scope, policy, targets=batch.targets, label=batch.label)
    extra = {"ports": batch.ports, "assume_up": True} if batch.assume_up else {}
    return nmap.run_tcp(runner, scope, policy, targets=batch.targets, label=batch.label,
                        **extra)


def _scan(store: Store, scope: Scope, policy: Policy, runner: Runner, kind: str,
          stage: str, batches: list[Batch], done: set[str]) -> dict | None:
    """Run every batch not in `done`. `kind` is tcp, udp or sweep.

    Returns None when nmap is missing, which is one gap for the whole pass
    rather than one per batch.
    """
    totals = {"hosts": 0, "services": 0, "chunks": len(batches), "chunks_done": 0,
              "chunks_failed": 0, "salvaged": 0,
              "skipped": sum(1 for b in batches if b.key in done)}
    aborter = AbortThreshold(min_samples=max(4, len(batches) // 2), failure_ratio=1.0)
    todo = [(index, batch) for index, batch in enumerate(batches, start=1)
            if batch.key not in done]
    parallel = int(policy.nmap.parallel)
    if parallel < 1:
        raise ValueError(f"nmap.parallel is {policy.nmap.parallel!r}: use 1 or more")
    # A dry run prints its plan in batch order, whatever `parallel` is.
    several = parallel > 1 and len(todo) > 1 and not runner.dry_run

    try:
        run = _scan_parallel if several else _scan_serial
        if not run(store, scope, policy, runner, kind, stage, batches, todo, totals, aborter):
            return None
    finally:
        if not runner.dry_run:
            _update_pass_gaps(store, stage)

    return totals


def _scan_serial(store: Store, scope: Scope, policy: Policy, runner: Runner, kind: str,
                 stage: str, batches: list[Batch], todo: list[tuple[int, Batch]],
                 totals: dict, aborter: AbortThreshold) -> bool:
    """One batch after another. False when nmap is missing."""
    for index, batch in todo:
        print(f"  [{index}/{len(batches)}] {len(batch.targets)} host(s)")
        try:
            outcome = _run_batch(runner, scope, policy, kind, batch)
        except ToolMissing as exc:
            _nmap_missing(store, kind, exc)
            return False
        if outcome[0].skipped:
            print("    (dry run)")
            continue
        _finish(store, scope, kind, stage, batch, outcome, totals, aborter,
                say=lambda text: print(f"    {text}"))
        aborter.check(context=f"{kind} discovery")
    return True


def _scan_parallel(store: Store, scope: Scope, policy: Policy, runner: Runner, kind: str,
                   stage: str, batches: list[Batch], todo: list[tuple[int, Batch]],
                   totals: dict, aborter: AbortThreshold) -> bool:
    """`nmap.parallel` batches at once. False when nmap is missing.

    Only nmap itself runs on the worker threads. Each finished batch is
    parsed, stored, checkpointed and reported here on the calling thread, one
    at a time, exactly as the serial loop does it: so the state on disk never
    depends on how the batches overlapped, and every line printed is whole
    and carries its batch label. Batches finish in any order.

    Anything that stops the pass early (Ctrl-C, the abort threshold) stops
    the nmap runs in flight. They are not checkpointed and leave no gap, the
    same as batches that never started, so `--resume` runs them again.
    """
    workers = min(int(policy.nmap.parallel), len(todo))
    waiting = iter(todo)
    running: dict[Future, tuple[int, Batch]] = {}
    stopping = threading.Event()

    def work(batch: Batch):
        if stopping.is_set():
            return None
        return _run_batch(runner, scope, policy, kind, batch)

    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nmap-batch")
    print(f"  {workers} batches at a time (nmap.parallel)")
    try:
        while True:
            while len(running) < workers:
                item = next(waiting, None)
                if item is None:
                    break
                index, batch = item
                print(f"  [{index}/{len(batches)}] {batch.label}: "
                      f"{len(batch.targets)} host(s), started")
                running[pool.submit(work, batch)] = item
            if not running:
                return True
            finished, _ = wait(running, return_when=FIRST_COMPLETED)
            for fut in sorted(finished, key=lambda f: running[f][0]):
                index, batch = running.pop(fut)
                try:
                    outcome = fut.result()
                except ToolMissing as exc:
                    # Every other batch fails the same way: one gap for the pass.
                    _nmap_missing(store, kind, exc)
                    return False
                label = batch.label
                print(f"  [{index}/{len(batches)}] {label}: finished")
                _finish(store, scope, kind, stage, batch, outcome, totals, aborter,
                        say=lambda text, label=label: print(f"  [{label}] {text}"))
                aborter.check(context=f"{kind} discovery")
    finally:
        # Reached with batches still in flight only on the way out early.
        # A worker may be about to start its nmap, so keep asking until
        # every one of them has come back.
        stopping.set()
        while any(not fut.done() for fut in running):
            runner.terminate_running()
            time.sleep(0.05)
        pool.shutdown(wait=True, cancel_futures=True)


def _nmap_missing(store: Store, kind: str, exc: ToolMissing) -> None:
    proto = "tcp" if kind == "sweep" else kind
    store.add_degradation(Degradation(
        stage=f"discover:{proto}", component="nmap", reason=str(exc),
        impact=f"No {proto.upper()} discovery was performed at all. Every "
               f"{proto.upper()} finding is absent from this report because "
               "the scanner was missing, not because nothing is exposed.",
        severity="serious", recoverable=True,
        remedy="Install nmap and re-run `extscan discover <run> --resume`.",
    ))
    _warn(store, str(exc))


def _finish(store: Store, scope: Scope, kind: str, stage: str, batch: Batch, outcome,
            totals: dict, aborter: AbortThreshold, say) -> None:
    """Parse one batch nmap has finished with, and record it or its failure."""
    res, xml, salvaged = outcome
    try:
        parsed = nmap.parse_xml(xml, scope=scope, source=f"nmap-{kind}") if xml else None
    except ValueError:
        parsed = None
    # Half a sweep cannot say which hosts have nothing open, so it
    # counts as failed and its hosts get the single-phase scan.
    if parsed and not (kind == "sweep" and salvaged):
        _record(store, scope, kind, stage, batch, parsed, res, xml, salvaged, totals, say)
        aborter.record(ok=True)
    else:
        totals["chunks_failed"] += 1
        aborter.record(ok=False)
        with store.transaction():
            store.save_batch_stats(stage, batch.key, None)
            store.add_degradation(_failed(kind, stage, batch, res, cut_short=bool(parsed)))
        say(f"! batch failed; {len(batch.targets)} host(s) not covered"
            + (" by the sweep" if kind == "sweep" else ""))


def _failed(kind: str, stage: str, batch: Batch, res, cut_short: bool) -> Degradation:
    why = "timed out" if res.timed_out else f"exit {res.returncode}"
    n = len(batch.targets)
    if kind == "sweep":
        reason = (f"{batch.label} did not finish ({why})" if cut_short
                  else f"{batch.label} produced no parseable output ({why})")
        impact = (f"The open-port sweep of {n} host(s) failed, so it is not known which "
                  "of them have anything listening. They are scanned the single-phase "
                  "way instead (every port, on every host); if that scan fails as "
                  "well, they are absent from the inventory.")
    else:
        reason = f"{batch.label} produced no parseable output ({why})"
        impact = (f"{n} host(s) in this batch were not scanned for {kind.upper()} "
                  "services and are absent from the inventory.")
    return Degradation(
        stage=stage, component="nmap", reason=reason, impact=impact,
        severity="serious", hosts=batch.targets,
        remedy="Inspect commands.jsonl for the error, then "
               "`extscan discover <run> --resume`.",
    )


def _record(store: Store, scope: Scope, kind: str, stage: str, batch: Batch, parsed,
            res, xml: str, salvaged: bool, totals: dict, say) -> None:
    """Store one parsed batch, checkpoint it, and replace its gaps."""
    hosts, services, findings = parsed
    # One commit for the batch: its results, its checkpoint and its gaps
    # land together, or the batch is not on record and is scanned again.
    with store.transaction():
        _record_batch(store, scope, kind, stage, batch, hosts, services, findings,
                      res, xml, salvaged, say)
    totals["hosts"] += len(hosts)
    totals["services"] += len(services)
    totals["chunks_done"] += 1
    totals["salvaged"] += bool(salvaged)


def _record_batch(store: Store, scope: Scope, kind: str, stage: str, batch: Batch,
                  hosts, services, findings, res, xml: str, salvaged: bool, say) -> None:
    label = batch.label
    if kind == "sweep":
        # The sweep knows a port is open and nothing else. Record it, so the
        # port is in the inventory even if phase two fails, but never over a
        # record that already has the service detail.
        known = store.service_ids()
        store.save_services([s for s in services if s.id not in known])
    else:
        store.save_services(services)
    store.save_hosts(hosts)
    store.add_findings(findings)

    store.save_batch_stats(stage, batch.key, _stats(kind, batch, services, xml))
    store.checkpoint(stage, batch.key)
    proto_stage = TCP if kind == "sweep" else stage
    store.remove_degradations(lambda d: (
        (d.stage == stage and d.reason.startswith(f"{label} "))
        or (d.stage == proto_stage and d.reason == NMAP_MISSING)))

    if salvaged:
        store.add_degradation(Degradation(
            stage=stage, component="nmap",
            reason=f"{label} did not finish "
                   f"({'timeout' if res.timed_out else 'exit ' + str(res.returncode)})",
            impact=f"Results for this batch are partial. {len(hosts)} host(s) "
                   "completed and were recovered from the interrupted scan "
                   "file; any host after that point was not scanned.",
            severity="serious", hosts=batch.targets,
            remedy=f"Re-run with a longer nmap.host_timeout, or resume with "
                   f"`nmap --resume {store.raw_path('nmap-' + label)}.gnmap`.",
        ))
        say(f"! partial: recovered {len(hosts)} host(s) from an interrupted scan")
        # That gap already covers every host in the batch, so nmap's own
        # warnings about some of them are not recorded a second time.
        return

    for gap in _accuracy_gaps(stage, label, nmap.accuracy_warnings(res.stdout, xml, scope)):
        store.add_degradation(gap)
        say(f"! {gap.reason}")


def _stats(kind: str, batch: Batch, services, xml: str) -> dict:
    """The figures the per-pass gaps are built from. Always a dict, because
    for a sweep its presence is what says the batch was swept."""
    stats: dict = {}
    # A phase-two batch runs with -Pn: no host discovery, nothing to count.
    counts = None if batch.assume_up else nmap.host_counts(xml)
    if counts:
        # nmap prints how many addresses were up; how many were asked is ours
        # to know when the batch is a list of addresses.
        asked = len(batch.targets) if all(map(_is_ip, batch.targets)) else counts["total"]
        stats["asked"] = asked
        stats["up"] = min(counts["up"], asked)
    if kind == "sweep":
        ports: dict[str, list[int]] = {}
        for s in services:
            ports.setdefault(s.host, []).append(s.port)
        stats["open"] = {h: sorted(set(p)) for h, p in ports.items()}
    if kind == "udp":
        unsure: dict[str, int] = {}
        for s in services:
            if s.proto == "udp" and s.state == "open|filtered":
                unsure[s.host] = unsure.get(s.host, 0) + 1
        if unsure:
            stats["open_filtered"] = unsure
    return stats


def _accuracy_gaps(stage: str, label: str, warned: dict[str, list[str]]) -> list[Degradation]:
    gaps = []
    hosts = warned.get("retransmission") or []
    if hosts:
        gaps.append(Degradation(
            stage=stage, component="nmap",
            reason=f"{label} gave up on ports of {len(hosts)} host(s): "
                   "retransmission cap hit",
            impact="nmap stopped retrying ports on these hosts before it got an answer, "
                   "so a port that is open there may be missing from the inventory: "
                   + ", ".join(hosts[:20]) + (" ..." if len(hosts) > 20 else ""),
            hosts=hosts,
            remedy="Raise nmap.max_retries, or lower the rate (nmap.timing, "
                   "nmap.min_rate), then re-run `extscan discover <run>`.",
        ))
    hosts = warned.get("host_timeout") or []
    if hosts:
        gaps.append(Degradation(
            stage=stage, component="nmap",
            reason=f"{label} skipped {len(hosts)} host(s): host timeout",
            impact="nmap abandoned these hosts when nmap.host_timeout ran out, so "
                   "their ports were not all scanned and nothing is reported for them: "
                   + ", ".join(hosts[:20]) + (" ..." if len(hosts) > 20 else ""),
            severity="serious", hosts=hosts,
            remedy="Raise nmap.host_timeout, or lower the rate so the hosts answer, "
                   "then re-run `extscan discover <run>`.",
        ))
    return gaps


def _update_pass_gaps(store: Store, stage: str, announce: bool = False) -> None:
    """Rebuild the one-per-pass gaps of `stage` from the figures of every
    batch on record, including the ones a resumed run skipped."""
    stats = list(store.batch_stats(stage).values())
    asked = sum(s.get("asked", 0) for s in stats)
    down = sum(max(0, s.get("asked", 0) - s.get("up", 0)) for s in stats)
    silent = None
    if down:
        silent = Degradation(
            stage=stage, component=HOST_DISCOVERY,
            reason=f"{down} of {asked} addresses did not answer host discovery",
            impact="nmap treated these addresses as down and did not port-scan them. "
                   "A host that drops every discovery probe but has a service "
                   "listening would be among them, and missing from the inventory.",
            remedy="Set `nmap.skip_host_discovery` to true to port-scan every address "
                   "whether it answers or not (slower), or add probes to "
                   "`nmap.discovery_probes`, then re-run `extscan discover <run>`.",
        )
    _replace(store, stage, HOST_DISCOVERY, silent, announce)

    if stage != UDP:
        return
    unsure: dict[str, int] = {}
    for s in stats:
        for host, n in s.get("open_filtered", {}).items():
            unsure[host] = unsure.get(host, 0) + n
    unconfirmed = None
    if unsure:
        hosts = _by_address(unsure)
        unconfirmed = Degradation(
            stage=stage, component=OPEN_FILTERED,
            reason=f"{sum(unsure.values())} UDP port(s) on {len(hosts)} host(s) were "
                   "open|filtered (unconfirmed)",
            impact="nmap got no answer from these ports, which is what an open UDP "
                   "service that ignores the probe and a firewall that drops it both "
                   "look like. They are listed as services and probed, but may not be "
                   "open at all: "
                   + ", ".join(f"{h} ({unsure[h]})" for h in hosts[:20])
                   + (" ..." if len(hosts) > 20 else ""),
            hosts=hosts,
            remedy="Confirm the ones that matter with a protocol-specific client, or "
                   "re-scan them alone at a higher nmap.version_intensity.",
        )
    _replace(store, stage, OPEN_FILTERED, unconfirmed, announce)


def _replace(store: Store, stage: str, component: str, gap: Degradation | None,
             announce: bool) -> None:
    """Leave exactly `gap` (or nothing) on record for this stage and component."""
    store.remove_degradations(lambda d: d.stage == stage and d.component == component and (
        gap is None or (d.reason, d.hosts) != (gap.reason, gap.hosts)))
    if gap is not None:
        store.add_degradation(gap)
        if announce:
            print(f"  ! {gap.reason}")


def _settle(store: Store, plan: dict[str, list[Batch]]) -> None:
    """After a pass that went through its whole plan: drop what the plan has
    superseded, then bring the per-pass gaps up to date.

    Every host in scope is in one of the plan's batches, and a batch that
    failed has a gap under its own label. So figures and gaps filed under a
    label that is no longer in the plan (left by the other discovery mode, or
    by a `-full` scan the sweep has since made unnecessary) describe work
    that has been redone.
    """
    labels = {b.label for batches in plan.values() for b in batches}

    def superseded(d: Degradation) -> bool:
        m = _LABEL_RE.match(d.reason) if d.stage in plan else None
        return bool(m) and m.group(1) not in labels

    store.remove_degradations(superseded)
    for stage, batches in plan.items():
        store.keep_batch_stats(stage, [b.key for b in batches])
        _update_pass_gaps(store, stage, announce=True)


def _warn(store: Store, message: str) -> None:
    meta = store.meta()
    warnings = meta.setdefault("warnings", [])
    if message not in warnings:
        warnings.append(message)
    store.write_meta(meta)
    print(f"  ! {message}")
