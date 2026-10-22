"""extscan command line.

Designed to be driven either by a person or by an agent, which is why nearly
every read command takes --json: the agent reads structured state between
stages and decides what to do next, instead of the branching logic being
frozen into the tool.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys

from . import __version__, pipeline
from .models import Finding, severity_rank
from .policy import Policy
from .probes import REGISTRY
from .resilience import Degradation
from .runner import Runner, doctor
from .scope import Scope, ScopeError
from .store import Store

DEFAULT_RUNS_DIR = "runs"


def _emit(data, as_json: bool, human) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        human(data)


def _open(args) -> Store:
    return Store.open(args.runs_dir, args.run)


def _scope_for(store: Store, args) -> Scope:
    """Reload the scope file recorded at init, unless overridden.

    Re-reading from disk is deliberate: scope can legitimately change
    mid-engagement (a host gets excluded after the client objects), and the
    enforcement must follow the current file, not a snapshot.
    """
    path = getattr(args, "scope", None) or store.meta().get("scope", {}).get("source_path")
    if not path:
        raise SystemExit("cannot determine the scope file for this run; pass --scope")
    return Scope.load(path)


def _policy_for(store: Store, args) -> Policy:
    if getattr(args, "policy", None):
        return Policy.load(args.policy, profile=getattr(args, "profile", None) or "standard")
    meta = store.meta()
    saved = meta.get("policy")
    profile = meta.get("profile", "standard")
    policy = Policy.for_profile(profile)
    if saved:
        with contextlib.suppress(ValueError, KeyError):
            policy = Policy.from_dict(saved, profile=profile)
    return policy


def _llm_for(store: Store, policy: Policy, args):
    """Build the model client, or None. Never fails a scan over a model."""
    if getattr(args, "no_llm", False):
        return None
    if not policy.llm.enabled:
        return None
    try:
        from .llm import build_client

        client = build_client(policy.llm)
    except Exception as exc:
        store.add_degradation(Degradation(
            stage="llm", component=f"llm:{policy.llm.provider}",
            reason=f"{type(exc).__name__}: {exc}"[:300],
            impact="Model-assisted commentary was requested but no model could be "
                   "reached, so findings carry deterministic evidence only.",
            remedy="Check `extscan providers`, then re-run `extscan chase <run>`.",
        ))
        print(f"  ! model unavailable: {str(exc)[:200]}")
        print("    continuing with deterministic analysis only")
        return None
    if client is not None:
        print(f"  model: {client.provider.name} / "
              f"{getattr(client.provider, 'model', '?')}")
    return client


def _runner(store: Store, args) -> Runner:
    return Runner(store, dry_run=getattr(args, "dry_run", False),
                  verbose=getattr(args, "verbose", False))


def cmd_doctor(args) -> int:
    rows = doctor()

    def human(data):
        print("External tools:\n")
        for tool, info in data.items():
            if tool.startswith("_"):
                continue
            mark = "✓" if info["present"] else "✗"
            print(f"  {mark} {tool:<12} {info['purpose']}")
            if not info["present"]:
                if info.get("install_debian"):
                    print(f"      debian/ubuntu: {info['install_debian']}")
                if info.get("install_macos"):
                    print(f"      macos:         {info['install_macos']}")
        print(f"\nNote: {data['_notes']['nmap_privileges']}")

    _emit(rows, args.json, human)
    missing = [t for t, i in rows.items() if not t.startswith("_") and not i["present"]]
    return 1 if "nmap" in missing else 0


def cmd_init(args) -> int:
    scope = Scope.load(args.scope)
    policy = Policy.load(args.policy, profile=args.profile)
    store = pipeline.init_run(args.runs_dir, scope, policy, run_id=args.id)
    data = {"run_id": store.run_id, "path": str(store.path), "scope": scope.summary()}

    def human(d):
        s = d["scope"]
        print(f"Run {d['run_id']} created at {d['path']}")
        print(f"  engagement: {s['engagement']}  client: {s['client']}")
        print(f"  authorisation: {s['authorization']['reference']} "
              f"(by {s['authorization']['authorized_by']})")
        print(f"  window: {s['window_note']}")
        print(f"  targets: {', '.join(s['targets'])}  -> {s['host_count']} host(s)")
        print(f"\nNext: extscan discover {d['run_id']}")

    _emit(data, args.json, human)
    return 0


def cmd_recon(args) -> int:
    store = _open(args)
    scope = _scope_for(store, args)
    policy = _policy_for(store, args)
    result = pipeline.recon(store, scope, policy, _runner(store, args))
    _emit({"recon": result, "counts": store.counts()}, args.json,
          lambda d: print(f"\n{json.dumps(d['recon'], indent=2)}"))
    return 0


def cmd_discover(args) -> int:
    store = _open(args)
    scope = _scope_for(store, args)
    policy = _policy_for(store, args)
    result = pipeline.discover(store, scope, policy, _runner(store, args),
                               tcp=not args.udp_only,
                               udp=None if not args.tcp_only else False,
                               resume=args.resume)
    _emit({"discover": result, "counts": store.counts()}, args.json,
          lambda d: print(f"\n{json.dumps(d['counts'], indent=2)}"))
    return 0


def cmd_probe(args) -> int:
    store = _open(args)
    scope = _scope_for(store, args)
    policy = _policy_for(store, args)
    result = pipeline.probe(store, scope, policy, _runner(store, args),
                            only=args.only or None, force=args.force,
                            skip_nuclei=args.skip_nuclei)
    _emit({"probe": result, "counts": store.counts()}, args.json,
          lambda d: print(f"\n{json.dumps(d['counts'], indent=2)}"))
    return 0


def cmd_leads(args) -> int:
    store = _open(args)
    leads = store.leads(None if args.status == "all" else args.status)
    data = [ld.to_dict() for ld in leads]

    def human(rows):
        if not rows:
            print("No leads.")
            return
        print(f"{len(rows)} lead(s):\n")
        for ld in rows:
            print(f"  [{ld['status']}] {ld['id']}  {ld['kind']}  "
                  f"{ld['host']}:{ld['port'] or '-'}  depth={ld['depth']}")
            if ld.get("url"):
                print(f"      url: {ld['url']}")
            print(f"      why: {ld['reason']}")
            if ld.get("note"):
                print(f"      outcome: {ld['note']}")
            print()

    _emit(data, args.json, human)
    return 0


def cmd_chase(args) -> int:
    store = _open(args)
    scope = _scope_for(store, args)
    policy = _policy_for(store, args)
    result = pipeline.chase_leads(store, scope, policy, _runner(store, args),
                                  lead_ids=args.lead or None, kinds=args.kind or None,
                                  rounds=args.rounds,
                                  llm=_llm_for(store, policy, args))
    _emit({"chase": result, "counts": store.counts()}, args.json,
          lambda d: print(f"\n{json.dumps(d['counts'], indent=2)}"))
    return 0


def cmd_report(args) -> int:
    store = _open(args)
    scope = _scope_for(store, args)
    result = pipeline.make_report(store, scope, _runner(store, args))

    def human(d):
        print(f"Report written:\n  {d['paths']['markdown']}\n  {d['paths']['json']}")
        print(f"\n{d['review_items']} item(s) in the manual review queue.")
        print(json.dumps(d["stats"], indent=2))

    _emit(result, args.json, human)
    return 0


def cmd_status(args) -> int:
    store = _open(args)
    meta = store.meta()
    data = {
        "run_id": store.run_id, "path": str(store.path),
        "profile": meta.get("profile"), "stages": meta.get("stages", {}),
        "warnings": meta.get("warnings", []), "counts": store.counts(),
        "scope": meta.get("scope", {}),
    }

    def human(d):
        print(f"Run {d['run_id']}  ({d['path']})")
        print(f"  profile: {d['profile']}")
        print(f"  stages:  {', '.join(d['stages']) or 'none yet'}")
        for w in d["warnings"]:
            print(f"  ! {w}")
        print("\n" + json.dumps(d["counts"], indent=2))

    _emit(data, args.json, human)
    return 0


def cmd_services(args) -> int:
    store = _open(args)
    services = store.services()
    if args.web_only:
        services = [s for s in services if s.is_http]
    data = [s.to_dict() | {"id": s.id, "url": s.base_url() if s.is_http else ""}
            for s in services]

    def human(rows):
        if not rows:
            print("No services.")
            return
        print(f"{'HOST':<20} {'PORT':>6} {'PROTO':<5} {'SERVICE':<16} PRODUCT")
        for s in rows:
            product = " ".join(x for x in (s["product"], s["version"]) if x)
            print(f"{s['host']:<20} {s['port']:>6} {s['proto']:<5} "
                  f"{(s['name'] or '?'):<16} {product}")

    _emit(data, args.json, human)
    return 0


def cmd_findings(args) -> int:
    store = _open(args)
    findings = store.findings()
    if args.severity:
        floor = severity_rank(args.severity)
        findings = [f for f in findings if severity_rank(f.severity) >= floor]
    if args.review_only:
        findings = [f for f in findings if f.review_required]
    findings.sort(key=lambda f: (-severity_rank(f.severity), f.host, f.port or 0))
    data = [f.to_dict() for f in findings]

    def human(rows):
        if not rows:
            print("No findings match.")
            return
        for f in rows:
            target = f"{f['host']}:{f['port']}" if f["port"] else f["host"]
            flag = " [REVIEW]" if f["review_required"] else ""
            print(f"  {f['severity'].upper():<8} {target:<22} {f['title']}{flag}")
            print(f"           id={f['id']}  src={f['source']}")

    _emit(data, args.json, human)
    return 0


def cmd_show(args) -> int:
    store = _open(args)
    for f in store.findings():
        if f.id == args.finding:
            _emit(f.to_dict(), args.json, lambda d: print(
                f"{d['severity'].upper()}  {d['title']}\n"
                f"target: {d['host']}:{d['port']}/{d['proto']}\n"
                f"source: {d['source']}\n\n{d['description']}\n"
                + (f"\nREVIEW: {d['review_reason']}\n" if d["review_required"] else "")
                + f"\n--- evidence ---\n{d['evidence']}\n"
                + (f"\n--- recommendation ---\n{d['recommendation']}\n"
                   if d["recommendation"] else "")))
            return 0
    print(f"no finding with id {args.finding!r}", file=sys.stderr)
    return 1


def cmd_note(args) -> int:
    """Record a finding from the agent's or auditor's own analysis.

    The point of this command: when Claude reads an OpenAPI document and
    concludes something no template encodes, that judgement belongs in the same
    report as the tool output, attributed so a reviewer knows where it came from.
    """
    store = _open(args)
    finding = Finding(
        title=args.title, severity=args.severity, host=args.host or "",
        port=args.port, proto=args.proto, source=args.source,
        description=args.description or "", evidence=args.evidence or "",
        recommendation=args.recommendation or "",
        references=args.reference or [],
        review_required=args.review, review_reason=args.review_reason or "",
        confidence=args.confidence, tags=args.tag or [],
    )
    added = store.add_findings([finding])
    _emit({"added": added, "id": finding.id}, args.json,
          lambda d: print(f"{'Recorded' if d['added'] else 'Already present'}: {d['id']}"))
    return 0


def cmd_resolve(args) -> int:
    """Mark a lead resolved by hand, with a note on what was concluded."""
    store = _open(args)
    lead = store.update_lead(args.lead, status=args.status, note=args.note or "")
    if lead is None:
        print(f"no lead with id {args.lead!r}", file=sys.stderr)
        return 1
    _emit(lead.to_dict(), args.json, lambda d: print(f"lead {d['id']} -> {d['status']}"))
    return 0


def cmd_gaps(args) -> int:
    """Show where coverage was lost. The first thing to check after any run."""
    store = _open(args)
    gaps = store.degradations()
    data = [d.to_dict() for d in gaps]

    def human(rows):
        if not rows:
            print("No coverage gaps recorded: every stage completed as intended.")
            return
        serious = [r for r in rows if r["severity"] == "serious"]
        print(f"{len(rows)} coverage gap(s), {len(serious)} serious.\n")
        for r in sorted(rows, key=lambda x: x["severity"] != "serious"):
            mark = "!!" if r["severity"] == "serious" else " !"
            print(f"  {mark} [{r['stage']}] {r['component']}")
            print(f"       lost:   {r['impact']}")
            print(f"       cause:  {r['reason']}")
            if r.get("remedy"):
                print(f"       remedy: {r['remedy']}")
            if r.get("hosts"):
                shown = ", ".join(r["hosts"][:6])
                more = f" (+{len(r['hosts']) - 6} more)" if len(r["hosts"]) > 6 else ""
                print(f"       hosts:  {shown}{more}")
            print()

    _emit(data, args.json, human)
    return 0


def cmd_resume(args) -> int:
    """Carry on a run that was interrupted, skipping completed work."""
    store = _open(args)
    scope = _scope_for(store, args)
    policy = _policy_for(store, args)
    runner = _runner(store, args)
    meta = store.meta()

    print(f"Resuming {store.run_id}")
    print(f"  completed stages: {', '.join(meta.get('stages', {})) or 'none'}")
    for stage in ("discover:tcp", "discover:udp"):
        done = store.checkpoints(stage)
        if done:
            print(f"  {stage}: {len(done)} batch(es) already done")

    out = {}
    out["discover"] = pipeline.discover(store, scope, policy, runner, resume=True)
    out["probe"] = pipeline.probe(store, scope, policy, runner)
    out["chase"] = pipeline.chase_leads(store, scope, policy, runner,
                                        rounds=args.rounds,
                                        llm=_llm_for(store, policy, args))
    out["report"] = pipeline.make_report(store, scope, runner)

    def human(d):
        print(f"\nReport: {d['report']['paths']['markdown']}")
        gaps = store.degradations()
        if gaps:
            print(f"{len(gaps)} coverage gap(s) -- see `extscan gaps {store.run_id}`")

    _emit(out, args.json, human)
    return 0


def cmd_run(args) -> int:
    scope = Scope.load(args.scope)
    policy = Policy.load(args.policy, profile=args.profile)
    store = pipeline.init_run(args.runs_dir, scope, policy, run_id=args.id)
    print(f"Run {store.run_id}\n")
    runner = _runner(store, args)
    result = pipeline.run_all(store, scope, policy, runner, rounds=args.rounds,
                              llm=_llm_for(store, policy, args))

    def human(d):
        print(f"\nReport: {d['report']['paths']['markdown']}")
        print(f"{d['report']['review_items']} item(s) need manual review.")

    _emit({"run_id": store.run_id, **result}, args.json, human)
    return 0


def cmd_providers(args) -> int:
    """Show which model providers this installation can reach, without calling one."""
    from .llm import describe_providers

    policy = Policy.load(getattr(args, "policy", None),
                         profile=getattr(args, "profile", None) or "standard")
    rows = describe_providers(policy.llm)
    data = {"configured": {"enabled": policy.llm.enabled,
                           "provider": policy.llm.provider,
                           "model": policy.llm.model or "(provider default)",
                           "effort": policy.llm.effort},
            "providers": rows}

    def human(d):
        c = d["configured"]
        state = "enabled" if c["enabled"] else "disabled (deterministic scanning only)"
        print(f"Model-assisted analysis: {state}")
        if c["enabled"]:
            print(f"  provider: {c['provider']}   model: {c['model']}   "
                  f"effort: {c['effort']}")
        print("\nProvider availability:\n")
        for row in d["providers"]:
            mark = "OK " if row["available"] else "-- "
            print(f"  {mark} {row['provider']:<12} {row['detail']}")
        if not c["enabled"]:
            print("\nTo enable, set llm.enabled and llm.provider in a policy file:")
            print('  {"llm": {"enabled": true, "provider": "bedrock", '
                  '"aws_region": "eu-west-2"}}')

    _emit(data, args.json, human)
    return 0


def cmd_probes(args) -> int:
    data = [{"name": p.name, "description": p.description} for p in REGISTRY]
    _emit(data, args.json, lambda rows: [
        print(f"  {r['name']:<20} {r['description']}") for r in rows])
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="extscan",
        description="Orchestrated external attack-surface scanning for authorised "
                    "security assessments.",
        epilog="Every run requires a scope file recording written authorisation. "
               "See examples/scope.example.json.",
    )
    ap.add_argument("--version", action="version", version=f"extscan {__version__}")
    ap.add_argument("--runs-dir", default=DEFAULT_RUNS_DIR,
                    help=f"where run directories live (default: {DEFAULT_RUNS_DIR})")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--verbose", action="store_true", help="echo every command executed")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the commands that would run, send no packets")
    ap.add_argument("--no-llm", action="store_true",
                    help="skip model-assisted analysis even if enabled in policy")
    sub = ap.add_subparsers(dest="command", required=True)

    def add_run_arg(p):
        p.add_argument("run", help="run id, or 'latest'")
        p.add_argument("--scope", help="override the scope file for this invocation")
        p.add_argument("--policy", help="override the policy file")
        p.add_argument("--profile", help="override the profile (quick|standard|thorough)")

    p = sub.add_parser("doctor", help="check which external tools are installed")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("probes", help="list registered probes")
    p.set_defaults(func=cmd_probes)

    p = sub.add_parser("providers", help="show model provider availability")
    p.add_argument("--policy", help="policy file to read llm settings from")
    p.add_argument("--profile", help="profile to base settings on")
    p.set_defaults(func=cmd_providers)

    p = sub.add_parser("init", help="create a run from a scope file")
    p.add_argument("--scope", required=True, help="path to the scope/authorisation file")
    p.add_argument("--policy", help="optional policy JSON overlay")
    p.add_argument("--profile", default="standard", choices=["quick", "standard", "thorough"])
    p.add_argument("--id", help="explicit run id")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("recon", help="enumerate subdomains of the scope's domains")
    add_run_arg(p)
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("discover", help="nmap TCP and UDP discovery")
    add_run_arg(p)
    p.add_argument("--tcp-only", action="store_true")
    p.add_argument("--udp-only", action="store_true")
    p.add_argument("--resume", action="store_true",
                   help="skip host batches already completed in this run")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("probe", help="run service-matched probes (incl. nuclei)")
    add_run_arg(p)
    p.add_argument("--only", action="append", metavar="PROBE",
                   help="restrict to a probe name (repeatable); 'nuclei' selects nuclei")
    p.add_argument("--force", action="store_true", help="re-run probes already run")
    p.add_argument("--skip-nuclei", action="store_true")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("leads", help="list follow-ups")
    add_run_arg(p)
    p.add_argument("--status", default="open",
                   choices=["open", "done", "skipped", "failed", "all"])
    p.set_defaults(func=cmd_leads)

    p = sub.add_parser("chase", help="resolve follow-up leads")
    add_run_arg(p)
    p.add_argument("--lead", action="append", metavar="ID",
                   help="chase only this lead id (repeatable)")
    p.add_argument("--kind", action="append", metavar="KIND",
                   help="chase only this lead kind (repeatable)")
    p.add_argument("--rounds", type=int, default=2,
                   help="how many times to re-queue newly raised leads")
    p.set_defaults(func=cmd_chase)

    p = sub.add_parser("report", help="triage and render the report")
    add_run_arg(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("gaps", help="show coverage gaps (what did not get checked)")
    add_run_arg(p)
    p.set_defaults(func=cmd_gaps)

    p = sub.add_parser("resume", help="continue an interrupted run")
    add_run_arg(p)
    p.add_argument("--rounds", type=int, default=2)
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("status", help="show run state")
    add_run_arg(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("services", help="list discovered services")
    add_run_arg(p)
    p.add_argument("--web-only", action="store_true")
    p.set_defaults(func=cmd_services)

    p = sub.add_parser("findings", help="list findings")
    add_run_arg(p)
    p.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"],
                   help="minimum severity")
    p.add_argument("--review-only", action="store_true",
                   help="only items flagged for manual review")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("show", help="show one finding in full")
    add_run_arg(p)
    p.add_argument("--finding", required=True, metavar="ID")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("note", help="record a finding from your own analysis")
    add_run_arg(p)
    p.add_argument("--title", required=True)
    p.add_argument("--severity", default="info",
                   choices=["info", "low", "medium", "high", "critical"])
    p.add_argument("--host", default="")
    p.add_argument("--port", type=int)
    p.add_argument("--proto", default="tcp", choices=["tcp", "udp"])
    p.add_argument("--description", default="")
    p.add_argument("--evidence", default="")
    p.add_argument("--recommendation", default="")
    p.add_argument("--reference", action="append")
    p.add_argument("--tag", action="append")
    p.add_argument("--source", default="analyst",
                   help="who concluded this (default: analyst)")
    p.add_argument("--confidence", default="firm", choices=["firm", "tentative"])
    p.add_argument("--review", action="store_true", help="flag for manual review")
    p.add_argument("--review-reason", default="")
    p.set_defaults(func=cmd_note)

    p = sub.add_parser("resolve", help="mark a lead resolved by hand")
    add_run_arg(p)
    p.add_argument("--lead", required=True, metavar="ID")
    p.add_argument("--status", default="done",
                   choices=["open", "done", "skipped", "failed"])
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("run", help="init + discover + probe + chase + report")
    p.add_argument("--scope", required=True)
    p.add_argument("--policy")
    p.add_argument("--profile", default="standard", choices=["quick", "standard", "thorough"])
    p.add_argument("--id")
    p.add_argument("--rounds", type=int, default=2)
    p.set_defaults(func=cmd_run)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"not found: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted; run state is on disk and can be resumed", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
