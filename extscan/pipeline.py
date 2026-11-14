"""Stage orchestration.

Each stage is a separate callable that reads the run directory, does one thing,
and writes back. That separation is what lets a person (or an agent) stop after
discovery, look at what was found, adjust the policy, and carry on -- which is
the normal shape of real audit work, rather than one opaque button.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import __version__, discovery, vault
from . import chase as chase_mod
from . import enrich as enrich_mod
from . import probes as probes_mod
from . import report as report_mod
from . import screenshots as shots_mod
from .models import Finding, Lead, severity_rank
from .policy import Policy
from .probes import ProbeContext
from .resilience import (
    AbortThreshold,
    CircuitOpen,
    Degradation,
    RetryPolicy,
    RunAborted,
    classify,
    retry,
)
from .runner import Runner, ToolMissing, doctor, udp_rerun_command
from .scope import Scope
from .store import Store
from .tools import dns, nmap, nuclei, subdomains, webid
from .triage import triage


def init_run(runs_dir: str, scope: Scope, policy: Policy,
             run_id: str | None = None) -> Store:
    """Create a run directory and record what we are about to do, and why."""
    scope.assert_window()
    policy.validate()
    # A template that cannot render stops the run here, not after the scan.
    report_mod.load_template(policy.report.template)
    store = Store.create(runs_dir, scope.engagement, run_id=run_id)
    store.write_meta({
        "run_id": store.run_id,
        "extscan_version": __version__,
        "created": time.time(),
        "profile": policy.profile,
        "scope": scope.summary(),
        "policy": policy.to_dict(),
        "stages": {},
        "warnings": [],
    })
    return store


def _coverage_lost(store: Store, deg: Degradation) -> None:
    store.add_degradation(deg)
    print(f"  ! {deg.reason}")
    print(f"    {deg.impact}")


UDP_NEEDS_ROOT = "nmap -sU requires root and the run is unprivileged"
NMAP_MISSING = str(ToolMissing("nmap"))


def _warn(store: Store, message: str) -> None:
    meta = store.meta()
    warnings = meta.setdefault("warnings", [])
    if message not in warnings:
        warnings.append(message)
    store.write_meta(meta)
    print(f"  ! {message}")


def _run_nmap_pass(store: Store, scope: Scope, policy: Policy, runner: Runner,
                   kind: str, resume: bool) -> dict | None:
    """Run one nmap pass (tcp or udp) in checkpointed batches.

    Batching is what makes this survivable. A /22 scanned in one invocation is
    all-or-nothing: a timeout two hours in leaves nothing usable. In batches,
    each completed batch is checkpointed and parsed, a timeout costs only the
    batch in flight, and `--resume`/`extscan resume` picks up from there.
    The batching, and the gaps each batch can leave, live in `discovery.py`.
    """
    return discovery.run_pass(store, scope, policy, runner, kind, resume)


def discover(store: Store, scope: Scope, policy: Policy, runner: Runner,
             tcp: bool = True, udp: bool | None = None,
             resume: bool = False) -> dict:
    scope.assert_window()
    do_udp = policy.nmap.do_udp if udp is None else udp
    udp_blocked = do_udp and nmap.udp_requires_root()
    summary: dict = {"tcp": None, "udp": None}
    rerun = udp_rerun_command(store.path.name)

    if udp_blocked:
        print("Not running as root: this run is TCP only.")
        print(f"  Re-run as root to add UDP: {rerun}")

    if tcp:
        print("→ nmap TCP discovery")
        summary["tcp"] = _run_nmap_pass(store, scope, policy, runner, "tcp", resume)
        if summary["tcp"]:
            print(f"  {summary['tcp']['hosts']} host(s), "
                  f"{summary['tcp']['services']} open TCP port(s)")

    if udp_blocked:
        store.add_degradation(Degradation(
            stage="discover:udp", component="nmap", reason=UDP_NEEDS_ROOT,
            impact="No UDP scanning was performed. SNMP, IPMI, NTP, mDNS and "
                   "other UDP exposure is NOT covered by this report. Absence "
                   "of UDP findings here means the check never ran.",
            severity="serious", recoverable=True,
            remedy=f"Re-run as root: `{rerun}`",
        ))
    elif do_udp:
        store.remove_degradations(
            lambda d: d.stage == "discover:udp" and d.reason == UDP_NEEDS_ROOT)
        print("→ nmap UDP discovery")
        summary["udp"] = _run_nmap_pass(store, scope, policy, runner, "udp", resume)
        if summary["udp"]:
            print(f"  {summary['udp']['services']} open/responding UDP port(s)")

    _check_host_names(store, scope, policy, runner)
    if not runner.dry_run:      # a plan is not a completed stage
        store.mark_stage("discover", **{k: v for k, v in summary.items() if v})
    return summary


def _check_host_names(store: Store, scope: Scope, policy: Policy, runner: Runner) -> None:
    """Name-level DNS checks on the host names of live in-scope hosts, which
    are known once the nmap passes are done. Their gaps live in
    discover:dns, so `discover --resume` retries them."""
    hostnames = {h.ip: h.hostnames for h in store.hosts()
                 if h.state == "up" and h.hostnames and scope.contains(h.ip)}
    if hostnames:
        print("→ DNS checks on the names of in-scope hosts")
    for result in dns.audit_hosts(scope, hostnames, policy.dns, dry_run=runner.dry_run):
        _record_dns(store, "discover:dns", result)
    if runner.dry_run:
        return
    note = dns.names_outside_domains(scope, hostnames)
    kept = [f for f in store.findings()
            if (f.source, f.title) != (dns.SOURCE, dns.OUTSIDE_DOMAINS_TITLE)]
    store.replace_findings(kept + ([note] if note else []))


def recon(store: Store, scope: Scope, policy: Policy, runner: Runner) -> dict:
    """Enumerate subdomains of the scope's domains, split them by scope, then
    audit each domain's DNS (zone transfer, NSEC walk, dangling records).

    Runs before discovery when used, because in-scope names it finds add hosts
    worth scanning. Out-of-scope names are reported and never touched.
    """
    scope.assert_window()
    if not scope.domains:
        print("  no `domains` in the scope file; nothing to enumerate")
        print("  (add e.g. \"domains\": [\"example.com\"] to enable this stage)")
        return {"domains": 0}

    totals = {"domains": len(scope.domains), "names": 0,
              "in_scope": 0, "out_of_scope": 0, "sources_failed": 0, "dns_findings": 0}

    if runner.dry_run:
        # crt.sh and the resolver are queried in-process, so there is no
        # command to withhold: a dry run says what it would do, asks nothing
        # and stores nothing.
        for domain in scope.domains:
            print(f"  [dry-run] would enumerate {domain} via "
                  f"{', '.join(policy.recon.sources)} and resolve the names found")
            _audit_dns(store, scope, policy, runner, domain, [])
        return {**totals, "dry_run": True}

    for domain in scope.domains:
        print(f"→ enumerating {domain} via {', '.join(policy.recon.sources)}")
        results, errors = subdomains.enumerate_domain(
            runner, scope, domain,
            sources=policy.recon.sources,
            resolve_timeout=policy.recon.resolve_timeout,
            use_system_proxy=policy.http.use_system_proxy,
            max_names=policy.recon.max_names,
        )
        findings, hosts = subdomains.to_findings(results, domain)
        store.add_findings(findings)
        if hosts:
            store.save_hosts(hosts)

        in_scope = sum(1 for r in results if r.in_scope)
        totals["names"] += len(results)
        totals["in_scope"] += in_scope
        totals["out_of_scope"] += sum(1 for r in results
                                      if not r.in_scope and r.addresses)
        print(f"  {len(results)} name(s): {in_scope} in scope, "
              f"{len(results) - in_scope} outside or unresolved")

        for error in errors:
            totals["sources_failed"] += 1
            store.add_degradation(Degradation(
                stage="recon", component=f"subdomains:{domain}",
                reason=error[:200],
                impact=f"One enumeration source for {domain} returned nothing, so the "
                       "subdomain list for this domain may be incomplete.",
                remedy="Check connectivity to the source, or install subfinder/amass "
                       "for an additional passive source, then re-run `extscan recon`.",
            ))
            print(f"  ! {error[:160]}")

        totals["dns_findings"] += _audit_dns(store, scope, policy, runner, domain,
                                             [r.name for r in results])

    store.mark_stage("recon", **totals)
    return totals


def _audit_dns(store: Store, scope: Scope, policy: Policy, runner: Runner,
               domain: str, names: list[str]) -> int:
    """Run the DNS checks for one domain. Returns the number of findings."""
    results = dns.audit_zone(scope, domain, names, policy.dns, dry_run=runner.dry_run)
    return sum(_record_dns(store, "recon", r) for r in results)


def _record_dns(store: Store, stage: str, result: dns.CheckResult) -> int:
    """Store one DNS check's findings and artifacts, and record or clear its
    gap under `stage`. A planned (dry-run) result touches nothing."""
    if result.planned:
        print(f"  [dry-run] dns {result.check} for {result.subject}")
        return 0
    store.add_findings(result.findings)
    for name, text in result.artifacts:
        store.write_raw(name, text)
    print(f"  dns {result.check} {result.subject}: {len(result.findings)} finding(s)")
    gap = result.gap(stage)
    if gap:
        _coverage_lost(store, gap)
    # Added before the old ones go, so a crash in between never drops a gap.
    store.remove_degradations(lambda d: (
        d.stage == stage and d.component == result.component
        and (gap is None or d.reason != gap.reason)))
    return len(result.findings)


def probe(store: Store, scope: Scope, policy: Policy, runner: Runner,
          only: list[str] | None = None, force: bool = False,
          skip_nuclei: bool = False) -> dict:
    scope.assert_window()
    services = store.services()
    if not services:
        print("  no services recorded; run discover first")
        return {"probed": 0}

    ctx = ProbeContext(scope=scope, policy=policy, runner=runner)
    nuclei_f = nuclei_l = 0     # stored per batch, so counted as they land

    # Before anything picks its targets: a web application on a port nmap
    # could not name is relabelled here, so nuclei and the probes below see it.
    webid.run(store, scope, policy, services, dry_run=runner.dry_run, only=only, force=force)

    web = [s for s in services if s.is_http]
    unchecked = [s for s in web if "nuclei" not in s.probed_by]
    if skip_nuclei and unchecked and not runner.dry_run:
        _coverage_lost(store, Degradation(
            stage="probe:nuclei", component="nuclei",
            reason="nuclei skipped by the operator (--skip-nuclei)",
            impact=f"Templated web checks were not run against {len(unchecked)} web "
                   "service(s). Any nuclei finding is missing from this report.",
            severity="serious", hosts=sorted({w.host for w in unchecked}),
            remedy="`extscan probe <run> --only nuclei`, or `extscan resume <run>`.",
        ))
    elif web and not skip_nuclei and (only is None or "nuclei" in only):
        # One nuclei run per batch, each stored and marked as it finishes, so
        # a timeout costs one batch and a re-run does only what is left.
        todo = web if force else unchecked
        batches = nuclei.batches(todo, policy.nuclei.batch_size)
        print(f"→ nuclei against {len(todo)} web service(s) in {len(batches)} batch(es)"
              + (f"; {len(web) - len(todo)} already checked" if len(todo) < len(web) else ""))
        still_failing: set[str] = set()
        for number, batch in enumerate(batches, start=1):
            scope.assert_window()
            label = nuclei.batch_label(batch, everything=len(batch) == len(web))
            affected = batch
            targets = f"nuclei-targets-{label}.txt" if label else "nuclei-targets.txt"
            try:
                res, findings, leads = nuclei.run(runner, scope, policy, batch, label)
                failure = res.failure if res else ""
                ran = res is not None and not res.skipped
                reason = f"nuclei batch {label} {failure}" if label else f"nuclei {failure}"
            except ToolMissing as exc:
                # Every remaining batch would fail the same way: one gap for them all.
                findings, leads, failure, ran = [], [], str(exc), False
                reason = f"nuclei {failure}"
                affected = [w for later in batches[number - 1:] for w in later]
            print(f"  [{number}/{len(batches)}] {len(findings)} result(s), {len(leads)} lead(s)")
            if failure:
                still_failing.add(reason)
                _coverage_lost(store, Degradation(
                    stage="probe:nuclei", component="nuclei", reason=reason,
                    impact=f"Templated web checks did not complete against {len(affected)} "
                           "web service(s). Any nuclei finding may be missing from this "
                           "report.",
                    severity="serious", hosts=sorted({w.host for w in affected}),
                    remedy=f"Run nuclei by hand against raw/{targets} to see why, "
                           "then `extscan probe <run> --only nuclei`.",
                ))
                if len(affected) > len(batch):
                    break
            elif ran:
                # Stored before the batch is marked, so a crash in between
                # re-runs the batch instead of losing its results.
                nuclei_f += store.add_findings(findings)
                nuclei_l += store.add_leads(leads, max_total=policy.max_leads_per_run)
                store.mark_probed_many((w.id, "nuclei") for w in batch)
                _nuclei_output_gap(store, label, batch, res.output_problem)
        if not runner.dry_run:
            # Every unchecked service was in a batch just now, so the only
            # nuclei gaps still true are the ones this pass recorded.
            store.remove_degradations(
                lambda d: d.stage == "probe:nuclei" and d.reason not in still_failing)

    jobs: list[tuple[probes_mod.Probe, object]] = []
    for svc in services:
        for p in probes_mod.probes_for(svc):
            if only is not None and p.name not in only:
                continue
            if p.name in svc.probed_by and not force:
                continue
            jobs.append((p, svc))

    if runner.dry_run:
        # The probes speak HTTP, TLS and SNMP in-process, so there is no
        # command to withhold: a dry run lists them and sends nothing.
        for p, svc in jobs:
            print(f"  [dry-run] would run {p.name} on {svc.id}")
        return {"probed": 0, "planned": len(jobs), "dry_run": True}

    added_f, added_l = nuclei_f, nuclei_l
    if jobs:
        print(f"→ {len(jobs)} per-service probe(s) across {len(services)} service(s)")
        # Each probe's result is stored as it completes, on this thread, so a
        # run killed partway keeps what finished and the next run does only
        # the remainder.
        pool = ThreadPoolExecutor(max_workers=max(1, policy.max_workers))
        try:
            futures = {pool.submit(_run_one_probe, ctx, p, svc): (p, svc)
                       for p, svc in jobs}
            for fut in as_completed(futures):
                p, svc = futures[fut]
                try:
                    findings, leads = fut.result()
                except Exception as exc:
                    with store.transaction():
                        _clear_probe_gaps(store, p.name, svc.id)
                        _coverage_lost(store, Degradation(
                            stage=f"probe:{p.name}", component=p.name,
                            reason=f"{svc.id}: {type(exc).__name__}: {exc}"[:300],
                            impact=f"The {p.name} check did not run on {svc.id}.",
                            hosts=[svc.host],
                            remedy=f"Fix the cause, then `extscan probe <run> --only {p.name}`.",
                        ))
                    continue
                new_f, new_l = _store_probe_result(store, ctx, policy, p, svc, findings, leads)
                added_f += new_f
                added_l += new_l
        finally:
            # On Ctrl-C (or any other way out): drop what has not started and
            # wait for what has. Nothing unfinished was marked as done.
            pool.shutdown(wait=True, cancel_futures=True)

    store.mark_stage("probe", findings=added_f, leads=added_l, probes_run=len(jobs))
    print(f"  {added_f} new finding(s), {added_l} new lead(s)")
    return {"probed": len(jobs), "findings": added_f, "leads": added_l}


NUCLEI_OUTPUT = "probe:nuclei-output"


def _nuclei_output_gap(store: Store, label: str, batch: list, problem: str) -> None:
    """nuclei finished, but some of its result lines could not be read: the
    results that were read are kept, and the ones that were not are a gap.
    A clean re-run of the same batch clears it."""
    component = f"nuclei-output:{label or 'all'}"
    store.remove_degradations(
        lambda d: d.stage == NUCLEI_OUTPUT and d.component == component)
    if problem:
        _coverage_lost(store, Degradation(
            stage=NUCLEI_OUTPUT, component=component, reason=problem,
            impact=f"Some nuclei results for {len(batch)} web service(s) were dropped "
                   "because their output lines were damaged. Findings may be missing.",
            hosts=sorted({w.host for w in batch}),
            remedy="Read the file under raw/ by hand, then "
                   "`extscan probe <run> --only nuclei --force`.",
        ))


def _run_one_probe(ctx: ProbeContext, p: probes_mod.Probe, svc):
    return p.run(ctx, svc)


def _clear_probe_gaps(store: Store, probe: str, service_id: str) -> None:
    store.remove_degradations(lambda d: (
        d.stage == f"probe:{probe}" and d.reason.startswith(f"{service_id}: ")))


def _store_probe_result(store: Store, ctx: ProbeContext, policy: Policy,
                        p: probes_mod.Probe, svc, findings: list[Finding],
                        leads: list[Lead]) -> tuple[int, int]:
    """Store one finished probe: its findings and leads, and either the gaps
    it reported about itself (`ProbeContext.report_gap`) or the mark that
    says the service is covered. One transaction, so a kill leaves the probe
    either fully recorded or not recorded and due to run again.

    A probe that reported a gap keeps its findings but is not marked: the
    next run tries again, and a clean pass clears the gap.
    """
    gaps = [g for g in list(ctx.gaps) if (g.probe, g.service_id) == (p.name, svc.id)]
    with store.transaction():
        new_f = store.add_findings(findings)
        new_l = store.add_leads(leads, max_total=policy.max_leads_per_run)
        _clear_probe_gaps(store, p.name, svc.id)
        for g in gaps:
            _coverage_lost(store, Degradation(
                stage=f"probe:{g.probe}", component=g.probe,
                reason=f"{g.service_id}: {g.reason}"[:300], impact=g.impact,
                hosts=[g.host], remedy=g.remedy,
            ))
        if not gaps:
            store.mark_probed(svc.id, p.name)
    return new_f, new_l


def chase_leads(store: Store, scope: Scope, policy: Policy, runner: Runner,
                lead_ids: list[str] | None = None, kinds: list[str] | None = None,
                rounds: int = 2, llm=None) -> dict:
    """Resolve open leads, re-queueing any new ones up to `rounds` passes.

    Every lead is attempted in isolation and its outcome written immediately,
    so an interrupted chase resumes rather than restarts. A lead that keeps
    failing transiently is retried up to `policy.max_lead_attempts` across
    runs and then abandoned with its error recorded -- which stops a single
    unreachable host from blocking the stage on every resume.
    """
    scope.assert_window()
    ctx = ProbeContext(scope=scope, policy=policy, runner=runner, llm=llm)
    total_f = total_l = handled = 0
    abandoned = 0
    retry_policy = RetryPolicy(attempts=2, base_delay=1.0, max_delay=8.0,
                               total_budget=30.0)
    aborter = AbortThreshold(min_samples=15, failure_ratio=0.95)

    for round_no in range(1, max(1, rounds) + 1):
        open_leads = store.leads("open")
        if lead_ids:
            open_leads = [ld for ld in open_leads if ld.id in lead_ids]
        if kinds:
            open_leads = [ld for ld in open_leads if ld.kind in kinds]
        open_leads = [ld for ld in open_leads if ld.depth <= policy.max_lead_depth]
        if not open_leads:
            break

        if runner.dry_run:
            for lead in open_leads:
                print(f"  [dry-run] would chase {lead.kind} {lead.url or lead.host}")
            return {"handled": 0, "planned": len(open_leads), "dry_run": True}

        print(f"→ chase round {round_no}: {len(open_leads)} lead(s)")
        for lead in open_leads:
            scope.assert_window()
            if lead.attempts >= policy.max_lead_attempts:
                store.update_lead(
                    lead.id, status="abandoned",
                    note=f"abandoned after {lead.attempts} attempts: {lead.last_error[:200]}",
                )
                abandoned += 1
                store.add_degradation(Degradation(
                    stage="chase", component=f"lead:{lead.kind}",
                    reason=f"{lead.attempts} failed attempts; last error: {lead.last_error[:160]}",
                    impact=f"The follow-up '{lead.reason[:120]}' was never completed, so "
                           f"whatever {lead.url or lead.host} exposes is unassessed.",
                    hosts=[lead.host] if lead.host else [],
                    remedy="Investigate this item by hand; it is in the review queue.",
                ))
                continue

            attempt_no = lead.attempts + 1
            try:
                result = retry(
                    lambda ld=lead: chase_mod.chase(ctx, ld),
                    retry_policy,
                    on_retry=lambda n, exc, delay, ld=lead: print(
                        f"    retry {n} for {ld.kind} after {type(exc).__name__}; "
                        f"waiting {delay:.1f}s"),
                )
            except CircuitOpen as exc:
                store.update_lead(lead.id, attempts=attempt_no, last_error=str(exc)[:300])
                store.add_degradation(Degradation(
                    stage="chase", component="llm",
                    reason=str(exc)[:200],
                    impact="Model-assisted analysis stopped partway through the "
                           "follow-up queue. Affected leads are still open and are "
                           "listed for manual review; the deterministic findings "
                           "around them are unaffected.",
                    severity="serious",
                    remedy="Restore the model endpoint and run "
                           "`extscan chase <run>` again, or work the open leads by hand.",
                ))
                print(f"  [{lead.kind}] deferred: {str(exc)[:110]}")
                break
            except RunAborted:
                raise
            except Exception as exc:
                verdict = classify(exc)
                store.update_lead(
                    lead.id,
                    status="open" if verdict == "transient" else "failed",
                    attempts=attempt_no,
                    last_error=f"{type(exc).__name__}: {exc}"[:300],
                )
                aborter.record(ok=False)
                print(f"  [{lead.kind}] {verdict} failure: {type(exc).__name__}: "
                      f"{str(exc)[:100]}")
                aborter.check(context="lead chasing")
                continue

            handled += 1
            aborter.record(ok=True)
            status = "done" if (result.findings or result.note) else "skipped"
            if result.note.startswith(("handler error", "scope refusal")):
                status = "failed"
            store.update_lead(lead.id, status=status, note=result.note[:500],
                              attempts=attempt_no)
            total_f += store.add_findings(result.findings)
            total_l += store.add_leads(result.leads, max_total=policy.max_leads_per_run)
            print(f"  [{lead.kind}] {lead.host}:{lead.port or '-'} -> {result.note[:140]}")

        if lead_ids:
            break

    store.mark_stage("chase", leads_handled=handled, findings=total_f,
                     new_leads=total_l, abandoned=abandoned)
    return {"handled": handled, "findings": total_f, "new_leads": total_l,
            "abandoned": abandoned}


SHOTS_UNAVAILABLE = "screenshot browser unavailable"
SHOTS_FAILED = "screenshots failed for some web services"


def screenshot(store: Store, scope: Scope, policy: Policy, force: bool = False,
               shooter_factory=None, dry_run: bool = False) -> dict:
    """Capture each web service's root page, plus pages behind findings.

    `shooter_factory` is a context manager yielding a Shooter; tests pass a
    fake. A missing browser is a coverage gap, never a failure.
    """
    scope.assert_window()
    sp = policy.screenshots
    if not sp.enabled:
        print("  screenshots disabled by policy")
        store.mark_stage("screenshot", disabled=True)
        return {"captured": 0, "disabled": True}

    planned = shots_mod.plan(store.services(), store.findings(), sp.max_pages)
    previous = {s.url: s for s in shots_mod.load(store)}
    todo = [s for s in planned
            if force or previous.get(s.url) is None or previous[s.url].status != "captured"]
    if not planned:
        print("  no web services to screenshot")
        store.mark_stage("screenshot", captured=0)
        return {"captured": 0}
    print(f"→ screenshots: {len(todo)} page(s) to capture, "
          f"{len(planned) - len(todo)} already done")
    if dry_run:
        for s in todo:
            print(f"  [dry-run] would capture {s.url}")
        return {"captured": 0, "planned": len(todo), "dry_run": True}

    if shooter_factory is None:
        def shooter_factory():
            return shots_mod.browser_shooter(scope, sp, policy.http.user_agent)

    if todo:
        try:
            with shooter_factory() as shooter:
                store.remove_degradations(
                    lambda d: d.stage == "screenshot" and d.reason == SHOTS_UNAVAILABLE)
                shots_mod.capture(store.path, todo, shooter)
        except shots_mod.BrowserUnavailable as exc:
            _coverage_lost(store, Degradation(
                stage="screenshot", component="chromium", reason=SHOTS_UNAVAILABLE,
                impact=f"No screenshots of {len(todo)} web page(s): {exc}. The report "
                       "describes these services in text only.",
                hosts=sorted({s.service.split("/")[0] for s in todo}),
                remedy="`uv sync --extra screenshots && uv run playwright install "
                       "chromium`, then `extscan screenshot <run>`.",
            ))
            return {"captured": 0, "unavailable": str(exc)}

    done = {s.url: s for s in todo}
    merged = [done.get(s.url) or previous.get(s.url) or s for s in planned]
    shots_mod.save(store, merged)

    failed_roots = [s for s in merged if s.kind == "service" and s.status != "captured"]
    store.remove_degradations(lambda d: d.stage == "screenshot" and d.reason == SHOTS_FAILED)
    if failed_roots:
        _coverage_lost(store, Degradation(
            stage="screenshot", component="chromium", reason=SHOTS_FAILED,
            impact=f"{len(failed_roots)} web service(s) have no screenshot, so the report "
                   "cannot show what they serve: "
                   + ", ".join(s.url for s in failed_roots[:10]),
            hosts=sorted({s.service.split("/")[0] for s in failed_roots}),
            remedy="Open them by hand, or `extscan screenshot <run>` to retry.",
        ))
    captured = sum(1 for s in merged if s.status == "captured")
    store.mark_stage("screenshot", captured=captured, failed=len(merged) - captured)
    print(f"  {captured} of {len(merged)} page(s) captured")
    return {"captured": captured, "failed": len(merged) - captured}


def enrich(store: Store, scope: Scope, policy: Policy, runner: Runner | None = None,
           fetcher=None) -> dict:
    """Rank findings by known exploitation (CISA KEV, EPSS) and tag hosts
    that sit in published CDN ranges. Downloads public lists only; a dry run
    downloads nothing. `fetcher` replaces the download, for tests."""
    return enrich_mod.run_stage(store, scope, policy,
                                dry_run=bool(runner and runner.dry_run), fetcher=fetcher)


ANALYSE = "analyse"


def analyse(store: Store, scope: Scope, policy: Policy, llm=None,
            dry_run: bool = False) -> dict:
    """Ask the model for a note on each finding at or above
    `llm.analyse_findings_above`, for the people who read the report.

    Each note is its own finding, sourced to `llm-analysis`, informational
    and flagged for review. Nothing here sends a packet to a target, picks
    what gets scanned or changes a severity. A finding the model did not
    get to, for any reason, is counted in one coverage gap: a report must
    not look as if the model had nothing to say about it.
    """
    lp = policy.llm
    if llm is None or lp.analyse_findings_above == "off":
        return {"analysed": 0, "disabled": True}

    from .llm.analyst import LLM_SOURCE, analyse_finding, analysis_title

    floor = severity_rank(lp.analyse_findings_above)
    findings = store.findings()
    have = {(f.host, f.port, f.proto, f.title) for f in findings if f.source == LLM_SOURCE}
    wanted = [f for f in findings
              if f.source != LLM_SOURCE and severity_rank(f.severity) >= floor
              and (f.host, f.port, f.proto, analysis_title(f.title)) not in have]
    wanted.sort(key=lambda f: (-severity_rank(f.severity), not f.kev, f.host, f.port or 0))
    todo, over = wanted[:max(0, int(lp.max_findings))], wanted[max(0, int(lp.max_findings)):]

    if dry_run:
        for f in todo:
            print(f"  [dry-run] would ask the model about {f.id} {f.title[:80]}")
        return {"analysed": 0, "planned": len(todo), "dry_run": True}

    if wanted:
        print(f"→ model notes on {len(todo)} finding(s) at or above "
              f"{lp.analyse_findings_above}"
              + (f"; {len(over)} more are over llm.max_findings" if over else ""))
    done, missed = 0, list(over)
    for index, f in enumerate(todo):
        if not llm.healthy:
            # The circuit is open: the endpoint is down, stop asking.
            missed.extend(todo[index:])
            break
        note = analyse_finding(llm, f)
        if note is None:
            missed.append(f)
            print(f"  ! no note for {f.id}: {llm.stats.last_error[:120] or 'no answer'}")
            continue
        done += store.add_findings([note])

    store.remove_degradations(lambda d: d.stage == ANALYSE)
    if missed:
        cause = llm.stats.last_error or "the model did not answer"
        if over and len(over) == len(missed):
            cause = f"llm.max_findings is {lp.max_findings}"
        _coverage_lost(store, Degradation(
            stage=ANALYSE, component=f"llm:{llm.provider.name}",
            reason=f"{len(missed)} of {len(wanted)} finding(s) got no model note: {cause}"[:300],
            impact=f"{len(missed)} finding(s) at or above {lp.analyse_findings_above} carry "
                   "no model-written note. Their evidence is complete; read it by hand: "
                   + ", ".join(f.id for f in missed[:12])
                   + (f" (+{len(missed) - 12} more)" if len(missed) > 12 else ""),
            hosts=sorted({f.host for f in missed if f.host}),
            remedy="Check `extscan providers`, raise llm.max_findings if that was the "
                   "limit, then `extscan analyse <run>`.",
        ))
    stats = llm.stats.to_dict()
    store.mark_stage(ANALYSE, analysed=done, not_analysed=len(missed), **stats)
    if wanted:
        print(f"  {done} note(s) written, {len(missed)} finding(s) without one")
    return {"analysed": done, "not_analysed": len(missed), "llm": stats}


def make_report(store: Store, scope: Scope, runner: Runner | None = None,
                template: str | None = None) -> dict:
    """Triage and render. `template` is a report template path; None uses
    the one named in the run's saved policy, and "" the built-in one."""
    if template is None:
        template = ((store.meta().get("policy") or {}).get("report") or {}).get("template", "")
    layout = report_mod.load_template(template)
    findings = store.findings()
    leads = store.leads()
    services = store.services()
    hosts = store.hosts()
    triaged = triage(findings, services)

    meta = store.meta()
    if runner is not None and not meta.get("tool_versions"):
        meta["tool_versions"] = {
            "nmap": runner.tool_version("nmap", "--version"),
            "nuclei": runner.tool_version("nuclei", "-version"),
            "openssl": runner.tool_version("openssl", "version"),
        }
        store.write_meta(meta)

    commands = store.commands()
    if store.commands_unreadable:
        _warn(store, f"{store.commands_unreadable} line(s) of commands.jsonl could not be "
                     "read, so the command log in this report is incomplete.")
        meta = store.meta()
    paths = report_mod.write_reports(store.path, scope, triaged, hosts, services,
                                     meta, commands, store.degradations(), leads, layout)
    paths["vault"] = vault.write_vault(store.path, scope, triaged, hosts, services, meta,
                                       store.commands(), store.degradations(), leads,
                                       shots_mod.load(store))
    store.mark_stage("report", **{k: str(v) for k, v in paths.items()})
    return {"paths": {k: str(v) for k, v in paths.items()}, "stats": triaged.stats,
            "review_items": len(triaged.review_queue)}


def run_all(store: Store, scope: Scope, policy: Policy, runner: Runner,
            rounds: int = 2, llm=None, template: str | None = None) -> dict:
    out = {"doctor": doctor()}
    if scope.domains:
        out["recon"] = recon(store, scope, policy, runner)
    out["discover"] = discover(store, scope, policy, runner)
    out["probe"] = probe(store, scope, policy, runner)
    out["chase"] = chase_leads(store, scope, policy, runner, rounds=rounds, llm=llm)
    out["screenshot"] = screenshot(store, scope, policy, dry_run=runner.dry_run)
    out["enrich"] = enrich(store, scope, policy, runner)
    out["analyse"] = analyse(store, scope, policy, llm, dry_run=runner.dry_run)
    out["report"] = make_report(store, scope, runner,
                                template=policy.report.template if template is None
                                else template)
    return out
