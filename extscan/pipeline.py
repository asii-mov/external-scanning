"""Stage orchestration.

Each stage is a separate callable that reads the run directory, does one thing,
and writes back. That separation is what lets a person (or an agent) stop after
discovery, look at what was found, adjust the policy, and carry on -- which is
the normal shape of real audit work, rather than one opaque button.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import __version__, chase as chase_mod, probes as probes_mod, report as report_mod
from .models import Finding, Lead
from .policy import Policy
from .probes import ProbeContext
from .runner import Runner, ToolMissing, doctor
from .scope import Scope
from .store import Store
from .tools import nmap, nuclei
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


def _warn(store: Store, message: str) -> None:
    meta = store.meta()
    warnings = meta.setdefault("warnings", [])
    if message not in warnings:
        warnings.append(message)
    store.write_meta(meta)
    print(f"  ! {message}")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover(store: Store, scope: Scope, policy: Policy, runner: Runner,
             tcp: bool = True, udp: bool | None = None) -> dict:
    scope.assert_window()
    do_udp = policy.nmap.do_udp if udp is None else udp
    summary = {"tcp": None, "udp": None}

    if tcp:
        print("→ nmap TCP discovery")
        try:
            res, xml = nmap.run_tcp(runner, scope, policy)
        except ToolMissing as exc:
            _warn(store, str(exc))
            return summary
        if xml:
            hosts, services, findings = nmap.parse_xml(xml, scope=scope, source="nmap-tcp")
            store.save_hosts(hosts)
            store.save_services(services)
            store.add_findings(findings)
            summary["tcp"] = {"hosts": len(hosts), "services": len(services)}
            print(f"  {len(hosts)} host(s), {len(services)} open TCP port(s)")
        elif res.skipped:
            print("  (dry run)")
        else:
            _warn(store, f"nmap TCP produced no XML (exit {res.returncode}); "
                         f"see commands.jsonl")

    if do_udp:
        if nmap.udp_requires_root():
            _warn(store, "UDP scan skipped: nmap -sU needs root. Re-run the discover "
                         "stage with sudo, or grant nmap CAP_NET_RAW. Without it, SNMP "
                         "and other UDP exposure is NOT covered by this report.")
        else:
            print("→ nmap UDP discovery")
            try:
                res, xml = nmap.run_udp(runner, scope, policy)
            except ToolMissing as exc:
                _warn(store, str(exc))
                xml, res = "", None
            if xml:
                hosts, services, findings = nmap.parse_xml(xml, scope=scope, source="nmap-udp")
                store.save_hosts(hosts)
                store.save_services(services)
                store.add_findings(findings)
                summary["udp"] = {"hosts": len(hosts), "services": len(services)}
                print(f"  {len(services)} open/responding UDP port(s)")
            elif res is not None and not res.skipped:
                _warn(store, f"nmap UDP produced no XML (exit {res.returncode})")

    store.mark_stage("discover", **{k: v for k, v in summary.items() if v})
    return summary


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------

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

    # nuclei runs once across every web target rather than per service: it
    # manages its own concurrency and rate limiting better than we can by
    # invoking it repeatedly.
    web = [s for s in services if s.is_http]
    if web and not skip_nuclei and (only is None or "nuclei" in only):
        print(f"→ nuclei against {len(web)} web service(s)")
        try:
            res, findings, leads = nuclei.run(runner, scope, policy, services)
            all_findings += findings
            all_leads += leads
            print(f"  {len(findings)} result(s), {len(leads)} lead(s)")
            if res is not None and not res.ok and not res.skipped:
                _warn(store, f"nuclei exited {res.returncode}; results may be partial")
            for s in web:
                store.mark_probed(s.id, "nuclei")
        except ToolMissing as exc:
            _warn(store, f"{exc} Web vulnerability checks did NOT run.")

    # Per-service probes, in a small pool since each is network-bound.
    jobs: list[tuple[probes_mod.Probe, object]] = []
    for svc in services:
        for p in probes_mod.probes_for(svc):
            if only is not None and p.name not in only:
                continue
            if p.name in svc.probed_by and not force:
                continue
            jobs.append((p, svc))

    if jobs:
        print(f"→ {len(jobs)} per-service probe(s) across {len(services)} service(s)")
        with ThreadPoolExecutor(max_workers=max(1, policy.max_workers)) as pool:
            futures = {pool.submit(_run_one_probe, ctx, p, svc): (p, svc)
                       for p, svc in jobs}
            for fut in as_completed(futures):
                p, svc = futures[fut]
                try:
                    findings, leads = fut.result()
                except Exception as exc:                  # noqa: BLE001
                    _warn(store, f"probe {p.name} failed on {svc.id}: "
                                 f"{type(exc).__name__}: {exc}")
                    continue
                all_findings += findings
                all_leads += leads

    # Single-threaded writes: the store is not concurrency-safe by design.
    added_f = store.add_findings(all_findings)
    added_l = store.add_leads(all_leads, max_total=policy.max_leads_per_run)
    for p, svc in jobs:
        store.mark_probed(svc.id, p.name)

    store.mark_stage("probe", findings=added_f, leads=added_l, probes_run=len(jobs))
    print(f"  {added_f} new finding(s), {added_l} new lead(s)")
    return {"probed": len(jobs), "findings": added_f, "leads": added_l}


def _run_one_probe(ctx: ProbeContext, p: probes_mod.Probe, svc):
    return p.run(ctx, svc)


# ---------------------------------------------------------------------------
# Chasing leads
# ---------------------------------------------------------------------------

def chase_leads(store: Store, scope: Scope, policy: Policy, runner: Runner,
                lead_ids: list[str] | None = None, kinds: list[str] | None = None,
                rounds: int = 2) -> dict:
    """Resolve open leads, re-queueing any new ones up to `rounds` passes."""
    scope.assert_window()
    ctx = ProbeContext(scope=scope, policy=policy, runner=runner)
    total_f = total_l = handled = 0

    for round_no in range(1, max(1, rounds) + 1):
        open_leads = store.leads("open")
        if lead_ids:
            open_leads = [l for l in open_leads if l.id in lead_ids]
        if kinds:
            open_leads = [l for l in open_leads if l.kind in kinds]
        open_leads = [l for l in open_leads if l.depth <= policy.max_lead_depth]
        if not open_leads:
            break

        print(f"→ chase round {round_no}: {len(open_leads)} lead(s)")
        for lead in open_leads:
            result = chase_mod.chase(ctx, lead)
            handled += 1
            status = "done" if (result.findings or result.note) else "skipped"
            if result.note.startswith(("handler error", "scope refusal")):
                status = "failed"
            store.update_lead(lead.id, status=status, note=result.note[:500])
            total_f += store.add_findings(result.findings)
            total_l += store.add_leads(result.leads, max_total=policy.max_leads_per_run)
            print(f"  [{lead.kind}] {lead.host}:{lead.port or '-'} -> {result.note[:140]}")

        if lead_ids:
            break          # explicit single-lead request: do not cascade

    store.mark_stage("chase", leads_handled=handled, findings=total_f, new_leads=total_l)
    return {"handled": handled, "findings": total_f, "new_leads": total_l}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def make_report(store: Store, scope: Scope, runner: Runner | None = None) -> dict:
    findings = store.findings()
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
                                     meta, store.commands())
    store.mark_stage("report", **{k: str(v) for k, v in paths.items()})
    return {"paths": {k: str(v) for k, v in paths.items()}, "stats": triaged.stats,
            "review_items": len(triaged.review_queue)}


# ---------------------------------------------------------------------------
# Whole run
# ---------------------------------------------------------------------------

def run_all(store: Store, scope: Scope, policy: Policy, runner: Runner,
            rounds: int = 2) -> dict:
    out = {"doctor": doctor()}
    out["discover"] = discover(store, scope, policy, runner)
    out["probe"] = probe(store, scope, policy, runner)
    out["chase"] = chase_leads(store, scope, policy, runner, rounds=rounds)
    out["report"] = make_report(store, scope, runner)
    return out
