"""Stage orchestration.

Each stage is a separate callable that reads the run directory, does one thing,
and writes back. That separation is what lets a person (or an agent) stop after
discovery, look at what was found, adjust the policy, and carry on -- which is
the normal shape of real audit work, rather than one opaque button.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import __version__, redact, vault
from . import chase as chase_mod
from . import probes as probes_mod
from . import report as report_mod
from . import screenshots as shots_mod
from .models import Finding, Lead
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
from .tools import nmap, nuclei, subdomains
from .triage import triage


def init_run(runs_dir: str, scope: Scope, policy: Policy,
             run_id: str | None = None) -> Store:
    """Create a run directory and record what we are about to do, and why."""
    scope.assert_window()
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


def _warn(store: Store, message: str) -> None:
    meta = store.meta()
    warnings = meta.setdefault("warnings", [])
    if message not in warnings:
        warnings.append(message)
    store.write_meta(meta)
    print(f"  ! {message}")


def _run_nmap_pass(store: Store, scope: Scope, policy: Policy, runner: Runner,
                   kind: str, resume: bool) -> dict | None:
    """Run one nmap pass (tcp or udp) in checkpointed chunks.

    Chunking is what makes this survivable. A /22 scanned in one invocation is
    all-or-nothing: a timeout two hours in leaves nothing usable. In batches,
    each completed batch is checkpointed and parsed, a timeout costs only the
    batch in flight, and `--resume`/`extscan resume` picks up from there.
    """
    runner_fn = nmap.run_tcp if kind == "tcp" else nmap.run_udp
    chunks = nmap.chunk_targets(scope, policy.nmap.chunk_size)
    if not chunks:
        return None

    stage_key = f"discover:{kind}"
    done = store.checkpoints(stage_key) if resume else set()
    if not resume:
        store.clear_checkpoints(stage_key)

    totals = {"hosts": 0, "services": 0, "chunks": len(chunks),
              "chunks_done": 0, "chunks_failed": 0, "salvaged": 0, "skipped": len(done)}
    aborter = AbortThreshold(min_samples=max(4, len(chunks) // 2), failure_ratio=1.0)

    for index, targets in enumerate(chunks, start=1):
        key = f"chunk-{index:04d}"
        if key in done:
            continue
        label = f"{kind}-{index:04d}"
        print(f"  [{index}/{len(chunks)}] {len(targets)} host(s)")

        try:
            res, xml, salvaged = runner_fn(runner, scope, policy,
                                           targets=targets, label=label)
        except ToolMissing as exc:
            store.add_degradation(Degradation(
                stage=stage_key, component="nmap", reason=str(exc),
                impact=f"No {kind.upper()} discovery was performed at all. Every "
                       f"{kind.upper()} finding is absent from this report because "
                       "the scanner was missing, not because nothing is exposed.",
                severity="serious", recoverable=True,
                remedy="Install nmap and re-run `extscan discover <run> --resume`.",
            ))
            _warn(store, str(exc))
            return None

        if res.skipped:
            print("    (dry run)")
            continue

        try:
            parsed = nmap.parse_xml(xml, scope=scope, source=f"nmap-{kind}") if xml else None
        except ValueError:
            parsed = None
        if parsed:
            hosts, services, findings = parsed
            store.save_hosts(hosts)
            store.save_services(services)
            store.add_findings(findings)
            totals["hosts"] += len(hosts)
            totals["services"] += len(services)
            totals["chunks_done"] += 1
            store.checkpoint(stage_key, key)
            aborter.record(ok=True)

            if salvaged:
                totals["salvaged"] += 1
                store.add_degradation(Degradation(
                    stage=stage_key, component="nmap",
                    reason=f"{label} did not finish ({'timeout' if res.timed_out else 'exit ' + str(res.returncode)})",
                    impact=f"Results for this batch are partial. {len(hosts)} host(s) "
                           "completed and were recovered from the interrupted scan "
                           "file; any host after that point was not scanned.",
                    severity="serious", hosts=targets,
                    remedy=f"Re-run with a longer nmap.host_timeout, or resume with "
                           f"`nmap --resume {store.raw_path('nmap-' + label)}.gnmap`.",
                ))
                print(f"    ! partial: recovered {len(hosts)} host(s) from an "
                      "interrupted scan")
        else:
            totals["chunks_failed"] += 1
            aborter.record(ok=False)
            store.add_degradation(Degradation(
                stage=stage_key, component="nmap",
                reason=f"{label} produced no parseable output "
                       f"({'timed out' if res.timed_out else 'exit ' + str(res.returncode)})",
                impact=f"{len(targets)} host(s) in this batch were not scanned for "
                       f"{kind.upper()} services and are absent from the inventory.",
                severity="serious", hosts=targets,
                remedy="Inspect commands.jsonl for the error, then "
                       "`extscan discover <run> --resume`.",
            ))
            print(f"    ! batch failed; {len(targets)} host(s) not covered")

        aborter.check(context=f"{kind} discovery")

    return totals


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
        store.remove_degradations("discover:udp", UDP_NEEDS_ROOT)
        print("→ nmap UDP discovery")
        summary["udp"] = _run_nmap_pass(store, scope, policy, runner, "udp", resume)
        if summary["udp"]:
            print(f"  {summary['udp']['services']} open/responding UDP port(s)")

    store.mark_stage("discover", **{k: v for k, v in summary.items() if v})
    return summary


def recon(store: Store, scope: Scope, policy: Policy, runner: Runner) -> dict:
    """Enumerate subdomains of the scope's domains, then split them by scope.

    Runs before discovery when used, because in-scope names it finds add hosts
    worth scanning. Out-of-scope names are reported and never touched.
    """
    scope.assert_window()
    if not scope.domains:
        print("  no `domains` in the scope file; nothing to enumerate")
        print("  (add e.g. \"domains\": [\"example.com\"] to enable this stage)")
        return {"domains": 0}

    totals = {"domains": len(scope.domains), "names": 0,
              "in_scope": 0, "out_of_scope": 0, "sources_failed": 0}

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

    store.mark_stage("recon", **totals)
    return totals


def probe(store: Store, scope: Scope, policy: Policy, runner: Runner,
          only: list[str] | None = None, force: bool = False,
          skip_nuclei: bool = False) -> dict:
    scope.assert_window()
    services = store.services()
    if not services:
        print("  no services recorded; run discover first")
        return {"probed": 0}

    ctx = ProbeContext(scope=scope, policy=policy, runner=runner)
    all_findings: list[Finding] = []
    all_leads: list[Lead] = []

    web = [s for s in services if s.is_http]
    if web and not skip_nuclei and (only is None or "nuclei" in only):
        print(f"→ nuclei against {len(web)} web service(s)")
        try:
            res, findings, leads = nuclei.run(runner, scope, policy, services)
            failure = res.failure if res else ""
        except ToolMissing as exc:
            findings, leads, failure = [], [], str(exc)
        all_findings += findings
        all_leads += leads
        print(f"  {len(findings)} result(s), {len(leads)} lead(s)")
        if failure:
            _coverage_lost(store, Degradation(
                stage="probe:nuclei", component="nuclei", reason=f"nuclei {failure}",
                impact=f"Templated web checks did not complete against {len(web)} web "
                       "service(s). Any nuclei finding may be missing from this report.",
                severity="serious", hosts=sorted({w.host for w in web}),
                remedy="Run nuclei by hand against raw/nuclei-targets.txt to see why, "
                       "then `extscan probe <run> --only nuclei`.",
            ))
        else:
            for w in web:
                store.mark_probed(w.id, "nuclei")

    jobs: list[tuple[probes_mod.Probe, object]] = []
    for svc in services:
        for p in probes_mod.probes_for(svc):
            if only is not None and p.name not in only:
                continue
            if p.name in svc.probed_by and not force:
                continue
            jobs.append((p, svc))

    failed: set[tuple[str, str]] = set()
    if jobs:
        print(f"→ {len(jobs)} per-service probe(s) across {len(services)} service(s)")
        with ThreadPoolExecutor(max_workers=max(1, policy.max_workers)) as pool:
            futures = {pool.submit(_run_one_probe, ctx, p, svc): (p, svc)
                       for p, svc in jobs}
            for fut in as_completed(futures):
                p, svc = futures[fut]
                try:
                    findings, leads = fut.result()
                except Exception as exc:
                    failed.add((p.name, svc.id))
                    _coverage_lost(store, Degradation(
                        stage=f"probe:{p.name}", component=p.name,
                        reason=f"{svc.id}: {type(exc).__name__}: {exc}"[:300],
                        impact=f"The {p.name} check did not run on {svc.id}.",
                        hosts=[svc.host],
                        remedy=f"Fix the cause, then `extscan probe <run> --only {p.name}`.",
                    ))
                    continue
                all_findings += findings
                all_leads += leads

    added_f = store.add_findings(all_findings)
    added_l = store.add_leads(all_leads, max_total=policy.max_leads_per_run)
    for p, svc in jobs:
        if (p.name, svc.id) not in failed:
            store.mark_probed(svc.id, p.name)

    store.mark_stage("probe", findings=added_f, leads=added_l, probes_run=len(jobs))
    print(f"  {added_f} new finding(s), {added_l} new lead(s)")
    return {"probed": len(jobs), "findings": added_f, "leads": added_l}


def _run_one_probe(ctx: ProbeContext, p: probes_mod.Probe, svc):
    return p.run(ctx, svc)


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

        print(f"→ chase round {round_no}: {len(open_leads)} lead(s)")
        for lead in open_leads:
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
                           "`extscan chase <run> --resume`, or work the open leads by hand.",
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
    previous = {s.url: s for s in shots_mod.load(store.path)}
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
                store.remove_degradations("screenshot", SHOTS_UNAVAILABLE)
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
    shots_mod.save(store.path, merged)

    failed_roots = [s for s in merged if s.kind == "service" and s.status != "captured"]
    store.remove_degradations("screenshot", SHOTS_FAILED)
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


def make_report(store: Store, scope: Scope, runner: Runner | None = None) -> dict:
    leads = store.leads()
    communities = redact.secret_communities(store.findings(), leads)
    findings = [redact.scrub_finding(f, communities) for f in store.findings()]
    leads = [redact.scrub_lead(ld, communities) for ld in leads]
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

    paths = report_mod.write_reports(store.path, scope, triaged, hosts, services,
                                     meta, store.commands(), store.degradations())
    paths["vault"] = vault.write_vault(store.path, scope, triaged, hosts, services, meta,
                                       store.commands(), store.degradations(), leads,
                                       shots_mod.load(store.path))
    store.mark_stage("report", **{k: str(v) for k, v in paths.items()})
    return {"paths": {k: str(v) for k, v in paths.items()}, "stats": triaged.stats,
            "review_items": len(triaged.review_queue)}


def run_all(store: Store, scope: Scope, policy: Policy, runner: Runner,
            rounds: int = 2, llm=None) -> dict:
    out = {"doctor": doctor()}
    if scope.domains:
        out["recon"] = recon(store, scope, policy, runner)
    out["discover"] = discover(store, scope, policy, runner)
    out["probe"] = probe(store, scope, policy, runner)
    out["chase"] = chase_leads(store, scope, policy, runner, rounds=rounds, llm=llm)
    out["screenshot"] = screenshot(store, scope, policy, dry_run=runner.dry_run)
    out["report"] = make_report(store, scope, runner)
    return out
