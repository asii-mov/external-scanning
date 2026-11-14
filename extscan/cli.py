"""extscan command line.

Designed to be driven either by a person or by an agent, which is why nearly
every read command takes --json: the agent reads structured state between
stages and decides what to do next, instead of the branching logic being
frozen into the tool.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, pipeline
from . import diff as diff_mod
from . import enrich as enrich_mod
from . import report as report_mod
from . import screenshots as shots_mod
from .models import Finding, severity_rank
from .policy import Policy, tcp_port_spec
from .probes import REGISTRY
from .resilience import Degradation, RunAborted
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
    meta = store.meta()
    recorded = meta.get("scope", {})
    path = getattr(args, "scope", None) or recorded.get("source_path")
    if not path:
        raise SystemExit("cannot determine the scope file for this run; pass --scope")
    scope = Scope.load(path)
    changes = scope.changes_since(recorded)
    if changes:
        # Following the current file is right. Doing it without a trace is
        # not: what was scanned must be explainable from the run's own record.
        message = (f"The scope changed after this run was created (now {path}): "
                   + "; ".join(changes))
        print(f"  ! {message}", file=sys.stderr)
        if not getattr(args, "dry_run", False):
            meta.setdefault("warnings", []).append(message)
            meta.setdefault("scope_history", []).append(recorded)
            meta["scope"] = scope.summary()
            store.write_meta(meta)
    return scope


def _policy_for(store: Store, args) -> Policy:
    if getattr(args, "policy", None):
        return Policy.load(args.policy, profile=getattr(args, "profile", None) or "standard")
    meta = store.meta()
    saved = meta.get("policy")
    profile = meta.get("profile", "standard")
    if not saved:
        return Policy.for_profile(profile)
    try:
        return Policy.from_dict(saved, profile=profile)
    except (ValueError, KeyError, TypeError) as exc:
        # Falling back to the defaults here would quietly drop whatever the
        # run was created with: rate limits, excluded scripts, a port list.
        raise ValueError(
            f"the policy saved in {store.path / 'run.json'} cannot be used by this "
            f"version of extscan: {exc}. Pass the policy file again with --policy, "
            "or fix the saved copy.") from exc


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
    store.remove_degradations(lambda d: d.stage == "llm")
    if client is not None:
        print(f"  model: {client.provider.name} / "
              f"{getattr(client.provider, 'model', '?')}")
    return client


def _template_for(policy: Policy, args) -> str:
    """The report template path: --template, else the policy's, else ""."""
    return getattr(args, "template", None) or policy.report.template


def _outcome(store: Store, data: dict, args) -> int:
    """Finish a whole run: say what was not covered, and let the exit code
    say it too, so a scheduled scan with a hole in it does not pass as a
    clean one. 0 is complete, 3 is finished with serious coverage gaps."""
    if getattr(args, "dry_run", False):
        return 0
    gaps = store.degradations()
    serious = [g for g in gaps if g.severity == "serious"]
    data["coverage_gaps"] = {"total": len(gaps), "serious": len(serious)}
    return 3 if serious else 0


def _say_gaps(store: Store, args) -> None:
    if getattr(args, "json", False) or getattr(args, "dry_run", False):
        return
    gaps = store.degradations()
    serious = [g for g in gaps if g.severity == "serious"]
    if not gaps:
        print("No coverage gaps: every stage completed as intended.")
        return
    print(f"{len(gaps)} coverage gap(s), {len(serious)} serious -- "
          f"see `extscan gaps {store.run_id}`")
    for g in serious[:5]:
        print(f"  !! [{g.stage}] {g.impact[:150]}")


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
    if args.tcp_ports:
        policy.nmap.tcp_ports = args.tcp_ports
    if args.template:
        policy.report.template = args.template
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
    result = pipeline.make_report(store, scope, _runner(store, args),
                                  template=getattr(args, "template", None))

    def human(d):
        print(f"Report written:\n  {d['paths']['markdown']}\n  {d['paths']['json']}")
        print(f"  {d['paths']['vault']}  (open the folder as an Obsidian vault)")
        print(f"\n{d['review_items']} item(s) in the manual review queue.")
        print(json.dumps(d["stats"], indent=2))

    _emit(result, args.json, human)
    return 0


def cmd_screenshot(args) -> int:
    store = _open(args)
    if args.list:
        return _list_screenshots(store, args)
    scope = _scope_for(store, args)
    policy = _policy_for(store, args)
    result = pipeline.screenshot(store, scope, policy, force=args.force,
                                 dry_run=args.dry_run)
    _emit({"screenshot": result}, args.json, lambda d: None)
    return 0


def _list_screenshots(store: Store, args) -> int:
    """What the screenshot stage recorded. Captures nothing."""
    data = [s.to_dict() for s in shots_mod.load(store)]

    def human(rows):
        if not rows:
            print("No screenshots recorded.")
            return
        for s in rows:
            print(f"  [{s['status']}] {s['url']}"
                  + (f"  -> {s['file']}" if s["status"] == "captured" else "")
                  + (f"  ({s['error']})" if s["error"] else ""))

    _emit(data, args.json, human)
    return 0


def cmd_enrich(args) -> int:
    """Look findings up in CISA KEV and EPSS, and hosts in CDN ranges."""
    store = _open(args)
    scope = _scope_for(store, args)
    policy = _policy_for(store, args)
    result = pipeline.enrich(store, scope, policy, _runner(store, args))
    _emit({"enrich": result, "counts": store.counts()}, args.json, lambda d: None)
    return 0


def cmd_analyse(args) -> int:
    """Ask the configured model for notes on the findings that matter most."""
    store = _open(args)
    scope = _scope_for(store, args)
    policy = _policy_for(store, args)
    if not policy.llm.enabled:
        print("Model-assisted analysis is off (llm.enabled is false in the policy), "
              "so there is nothing to do.", file=sys.stderr)
        return 2
    llm = _llm_for(store, policy, args)
    result = pipeline.analyse(store, scope, policy, llm,
                              dry_run=getattr(args, "dry_run", False))
    _emit({"analyse": result, "counts": store.counts()}, args.json,
          lambda d: print(f"\n{json.dumps(d['analyse'], indent=2)}"))
    return 0 if llm is not None else 1


def cmd_template(args) -> int:
    """Print the built-in report template, or check an edited copy."""
    if args.check:
        layout = report_mod.load_template(args.check)
        _emit({"template": args.check, "ok": True, "layout": layout.label}, args.json,
              lambda d: print(f"{d['template']}: OK"))
        return 0
    text = report_mod.DEFAULT_TEMPLATE.read_text(encoding="utf-8")
    if args.out:
        out = Path(args.out)
        if out.exists() and not args.force:
            print(f"{out} already exists; pass --force to overwrite it", file=sys.stderr)
            return 2
        out.write_text(text, encoding="utf-8")
        _emit({"written": str(out)}, args.json, lambda d: print(
            f"Wrote {d['written']}. Edit it, check it with `extscan template --check "
            f"{d['written']}`, then use it with --template or report.template."))
        return 0
    sys.stdout.write(text)
    return 0


def _open_run(args, ref: str) -> Store:
    """A run id under --runs-dir, 'latest', or a path to a run directory."""
    if (Path(ref) / "run.json").is_file():
        return Store(ref)
    return Store.open(args.runs_dir, ref)


def cmd_diff(args) -> int:
    """Compare two runs: what is new, changed, gone, and what the newer run
    never looked at again."""
    old, new = _open_run(args, args.old), _open_run(args, args.new)
    result = diff_mod.diff_runs(old, new)
    if not args.no_write:
        paths = diff_mod.write_diff(new.path, result)
        result["paths"] = {k: str(v) for k, v in paths.items()}

    def human(d):
        print(diff_mod.render_text(d))
        for path in d.get("paths", {}).values():
            print(f"written: {path}")

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
        # Batches done per stage; `extscan export` has the keys themselves.
        "checkpoints": {stage: len(keys) for stage, keys in store.all_checkpoints().items()},
        "layout": store.layout,
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


def cmd_hosts(args) -> int:
    store = _open(args)
    data = [h.to_dict() for h in store.hosts()]

    def human(rows):
        if not rows:
            print("No hosts.")
            return
        print(f"{'HOST':<40} {'STATE':<8} {'NETWORK':<12} NAMES")
        for h in rows:
            print(f"{h['ip']:<40} {h['state']:<8} {(h['network'] or '-'):<12} "
                  f"{', '.join(h['hostnames'])}")

    _emit(data, args.json, human)
    return 0


def cmd_export(args) -> int:
    """Write the run's state as plain JSON files, for reading with other tools."""
    store = _open(args)
    try:
        written = store.export(args.out)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    data = {"run_id": store.run_id, "out": str(written[0].parent),
            "files": [p.name for p in written]}

    def human(d):
        print(f"Exported {d['run_id']} to {d['out']}:")
        print("  " + ", ".join(d["files"]))
        print("These are copies. The run's live state stays in state.db.")

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
    # Within a severity: known-exploited first, then by EPSS.
    findings.sort(key=lambda f: (-severity_rank(f.severity), not f.kev, -(f.epss or 0.0),
                                 f.host, f.port or 0))
    data = [f.to_dict() for f in findings]

    def human(rows):
        if not rows:
            print("No findings match.")
            return
        for f in rows:
            target = f"{f['host']}:{f['port']}" if f["port"] else f["host"]
            flag = " [REVIEW]" if f["review_required"] else ""
            mark = enrich_mod.badge(Finding.from_dict(f))
            print(f"  {f['severity'].upper():<8} {target:<22} {f['title']}{flag}"
                  + (f" [{mark}]" if mark else ""))
            print(f"           id={f['id']}  src={f['source']}"
                  + (f"  cve={','.join(f['cves'][:4])}" if f.get("cves") else ""))

    _emit(data, args.json, human)
    return 0


def cmd_show(args) -> int:
    store = _open(args)
    for f in store.findings():
        if f.id == args.finding:
            _emit(f.to_dict(), args.json, lambda d: print(
                f"{d['severity'].upper()}  {d['title']}\n"
                f"target: {d['host']}:{d['port']}/{d['proto']}\n"
                f"source: {d['source']}\n"
                + "".join(f"{line}\n" for line in enrich_mod.cve_lines(Finding.from_dict(d)))
                + f"\n{d['description']}\n"
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
    for stage in ("discover:sweep", "discover:tcp", "discover:udp"):
        done = store.checkpoints(stage)
        if done:
            print(f"  {stage}: {len(done)} batch(es) already done")

    out = {}
    out["discover"] = pipeline.discover(store, scope, policy, runner, resume=True)
    out["probe"] = pipeline.probe(store, scope, policy, runner)
    llm = _llm_for(store, policy, args)
    out["chase"] = pipeline.chase_leads(store, scope, policy, runner,
                                        rounds=args.rounds, llm=llm)
    out["screenshot"] = pipeline.screenshot(store, scope, policy, dry_run=runner.dry_run)
    out["enrich"] = pipeline.enrich(store, scope, policy, runner)
    out["analyse"] = pipeline.analyse(store, scope, policy, llm, dry_run=runner.dry_run)
    out["report"] = pipeline.make_report(store, scope, runner,
                                         template=_template_for(policy, args))
    code = _outcome(store, out, args)
    _emit(out, args.json,
          lambda d: print(f"\nReport: {d['report']['paths']['markdown']}"))
    _say_gaps(store, args)
    return code


def cmd_run(args) -> int:
    scope = Scope.load(args.scope)
    policy = Policy.load(args.policy, profile=args.profile)
    if args.tcp_ports:
        policy.nmap.tcp_ports = args.tcp_ports
    if args.template:
        policy.report.template = args.template
    store = pipeline.init_run(args.runs_dir, scope, policy, run_id=args.id)
    print(f"Run {store.run_id}\n")
    runner = _runner(store, args)
    result = pipeline.run_all(store, scope, policy, runner, rounds=args.rounds,
                              llm=_llm_for(store, policy, args))
    data = {"run_id": store.run_id, **result}

    def human(d):
        print(f"\nReport: {d['report']['paths']['markdown']}")
        print(f"{d['report']['review_items']} item(s) need manual review.")

    code = _outcome(store, data, args)
    _emit(data, args.json, human)
    _say_gaps(store, args)
    return code


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
            print('  {"llm": {"enabled": true, "provider": "anthropic"}}')
            print('  {"llm": {"enabled": true, "provider": "bedrock", '
                  '"aws_region": "eu-west-2"}}')
            print('  {"llm": {"enabled": true, "provider": "azure", '
                  '"azure_resource": "my-foundry-resource"}}')

    _emit(data, args.json, human)
    return 0


def cmd_probes(args) -> int:
    data = [{"name": p.name, "description": p.description} for p in REGISTRY]
    _emit(data, args.json, lambda rows: [
        print(f"  {r['name']:<20} {r['description']}") for r in rows])
    return 0


TCP_PORTS_HELP = ("TCP ports to scan: all (1-65535), top (1-1024 plus common service "
                  "ports), quick (25 common ports), or an nmap list like 22,80,8000-8100. "
                  "Default: the profile's list")


def _tcp_ports(value: str) -> str:
    try:
        return tcp_port_spec(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="extscan",
        description="Orchestrated external attack-surface scanning for authorised "
                    "security assessments.",
        epilog="Every run requires a scope file recording written authorisation. "
               "See examples/scope.example.json.",
    )
    ap.add_argument("--version", action="version", version=f"extscan {__version__}")

    def add_global_args(p, **default):
        p.add_argument("--runs-dir", **(default or {"default": DEFAULT_RUNS_DIR}),
                       help=f"where run directories live (default: {DEFAULT_RUNS_DIR})")
        p.add_argument("--json", action="store_true", **default,
                       help="machine-readable output")
        p.add_argument("--verbose", action="store_true", **default,
                       help="echo every command executed")
        p.add_argument("--dry-run", action="store_true", **default,
                       help="print the commands that would run, send no packets")
        p.add_argument("--no-llm", action="store_true", **default,
                       help="skip model-assisted analysis even if enabled in policy")

    # The global flags work on either side of the subcommand: `extscan --json
    # gaps <run>` and `extscan gaps <run> --json`. After the subcommand they
    # default to SUPPRESS, so an absent flag never overwrites one given before.
    add_global_args(ap)
    common = argparse.ArgumentParser(add_help=False)
    add_global_args(common, default=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="command", required=True)

    def add_cmd(name, **kwargs):
        return sub.add_parser(name, parents=[common], **kwargs)

    def add_run_arg(p):
        p.add_argument("run", help="run id, or 'latest'")
        p.add_argument("--scope", help="override the scope file for this invocation")
        p.add_argument("--policy", help="override the policy file")
        p.add_argument("--profile", help="override the profile (quick|standard|thorough)")

    p = add_cmd("doctor", help="check which external tools are installed")
    p.set_defaults(func=cmd_doctor)

    p = add_cmd("probes", help="list registered probes")
    p.set_defaults(func=cmd_probes)

    p = add_cmd("providers", help="show model provider availability")
    p.add_argument("--policy", help="policy file to read llm settings from")
    p.add_argument("--profile", help="profile to base settings on")
    p.set_defaults(func=cmd_providers)

    p = add_cmd("init", help="create a run from a scope file")
    p.add_argument("--scope", required=True, help="path to the scope/authorisation file")
    p.add_argument("--policy", help="optional policy JSON overlay")
    p.add_argument("--profile", default="standard", choices=["quick", "standard", "thorough"])
    p.add_argument("--tcp-ports", type=_tcp_ports, metavar="all|top|quick|LIST",
                   help=TCP_PORTS_HELP)
    p.add_argument("--id", help="explicit run id")
    p.add_argument("--template", metavar="FILE",
                   help="report layout to use instead of the built-in one "
                        "(see `extscan template`)")
    p.set_defaults(func=cmd_init)

    p = add_cmd("recon", help="subdomains and DNS checks for the scope's domains")
    add_run_arg(p)
    p.set_defaults(func=cmd_recon)

    p = add_cmd("discover", help="nmap TCP and UDP discovery")
    add_run_arg(p)
    p.add_argument("--tcp-only", action="store_true")
    p.add_argument("--udp-only", action="store_true")
    p.add_argument("--resume", action="store_true",
                   help="skip host batches already completed in this run")
    p.set_defaults(func=cmd_discover)

    p = add_cmd("probe", help="run service-matched probes (incl. nuclei)")
    add_run_arg(p)
    p.add_argument("--only", action="append", metavar="PROBE",
                   help="restrict to a probe name (repeatable); 'nuclei' selects nuclei")
    p.add_argument("--force", action="store_true", help="re-run probes already run")
    p.add_argument("--skip-nuclei", action="store_true")
    p.set_defaults(func=cmd_probe)

    p = add_cmd("leads", help="list follow-ups")
    add_run_arg(p)
    p.add_argument("--status", default="open",
                   choices=["open", "done", "skipped", "failed", "all"])
    p.set_defaults(func=cmd_leads)

    p = add_cmd("chase", help="resolve follow-up leads")
    add_run_arg(p)
    p.add_argument("--lead", action="append", metavar="ID",
                   help="chase only this lead id (repeatable)")
    p.add_argument("--kind", action="append", metavar="KIND",
                   help="chase only this lead kind (repeatable)")
    p.add_argument("--rounds", type=int, default=2,
                   help="how many times to re-queue newly raised leads")
    p.set_defaults(func=cmd_chase)

    p = add_cmd("screenshot", help="screenshot web services for the report vault")
    add_run_arg(p)
    p.add_argument("--force", action="store_true", help="recapture pages already captured")
    p.add_argument("--list", action="store_true",
                   help="show the screenshots on record (use with --json); capture nothing")
    p.set_defaults(func=cmd_screenshot)

    p = add_cmd("enrich", help="rank findings by known exploitation (CISA KEV, EPSS) "
                               "and tag hosts in CDN ranges")
    add_run_arg(p)
    p.set_defaults(func=cmd_enrich)

    p = add_cmd("diff", help="compare two runs, separating 'gone' from 'not re-checked'")
    p.add_argument("old", help="the earlier run: id, 'latest', or a run directory")
    p.add_argument("new", help="the later run; diff.md and diff.json are written into it")
    p.add_argument("--no-write", action="store_true",
                   help="print only; do not write diff.md and diff.json")
    p.set_defaults(func=cmd_diff)

    p = add_cmd("report", help="triage and render the report and Obsidian vault")
    add_run_arg(p)
    p.add_argument("--template", metavar="FILE",
                   help="report layout to use instead of the built-in one "
                        "(see `extscan template`)")
    p.set_defaults(func=cmd_report)

    p = add_cmd("analyse", help="model-written notes on the findings that matter most "
                                "(needs llm.enabled in the policy)")
    add_run_arg(p)
    p.set_defaults(func=cmd_analyse)

    p = add_cmd("template", help="print the report template, write a copy to edit, "
                                 "or check an edited copy")
    p.add_argument("--out", metavar="FILE", help="write the built-in template here")
    p.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    p.add_argument("--check", metavar="FILE", help="check an edited template")
    p.set_defaults(func=cmd_template)

    p = add_cmd("gaps", help="show coverage gaps (what did not get checked)")
    add_run_arg(p)
    p.set_defaults(func=cmd_gaps)

    p = add_cmd("resume", help="continue an interrupted run")
    add_run_arg(p)
    p.add_argument("--rounds", type=int, default=2)
    p.add_argument("--template", metavar="FILE",
                   help="report layout to use instead of the built-in one "
                        "(see `extscan template`)")
    p.set_defaults(func=cmd_resume)

    p = add_cmd("status", help="show run state")
    add_run_arg(p)
    p.set_defaults(func=cmd_status)

    p = add_cmd("hosts", help="list discovered hosts")
    add_run_arg(p)
    p.set_defaults(func=cmd_hosts)

    p = add_cmd("export", help="write the run's state as plain JSON files")
    add_run_arg(p)
    p.add_argument("--out", metavar="DIR",
                   help="where to write (default: <run>/export). hosts.json, services.json, "
                        "findings.json, leads.json, degradations.json, checkpoints.json, "
                        "batches.json, screenshots.json, and copies of run.json and "
                        "commands.jsonl")
    p.set_defaults(func=cmd_export)

    p = add_cmd("services", help="list discovered services")
    add_run_arg(p)
    p.add_argument("--web-only", action="store_true")
    p.set_defaults(func=cmd_services)

    p = add_cmd("findings", help="list findings")
    add_run_arg(p)
    p.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"],
                   help="minimum severity")
    p.add_argument("--review-only", action="store_true",
                   help="only items flagged for manual review")
    p.set_defaults(func=cmd_findings)

    p = add_cmd("show", help="show one finding in full")
    add_run_arg(p)
    p.add_argument("--finding", required=True, metavar="ID")
    p.set_defaults(func=cmd_show)

    p = add_cmd("note", help="record a finding from your own analysis")
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

    p = add_cmd("resolve", help="mark a lead resolved by hand")
    add_run_arg(p)
    p.add_argument("--lead", required=True, metavar="ID")
    p.add_argument("--status", default="done",
                   choices=["open", "done", "skipped", "failed"])
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_resolve)

    p = add_cmd("run", help="init + recon + discover + probe + chase + screenshot + "
                            "enrich + report")
    p.add_argument("--scope", required=True)
    p.add_argument("--policy")
    p.add_argument("--profile", default="standard", choices=["quick", "standard", "thorough"])
    p.add_argument("--tcp-ports", type=_tcp_ports, metavar="all|top|quick|LIST",
                   help=TCP_PORTS_HELP)
    p.add_argument("--id")
    p.add_argument("--rounds", type=int, default=2)
    p.add_argument("--template", metavar="FILE",
                   help="report layout to use instead of the built-in one "
                        "(see `extscan template`)")
    p.set_defaults(func=cmd_run)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2
    except report_mod.TemplateError as exc:
        print(f"report template error: {exc}", file=sys.stderr)
        return 2
    except RunAborted as exc:
        print(f"run aborted: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        # Bad policy, damaged run state, bad arguments: a configuration
        # problem with a message written for the operator, not a crash.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"not found: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"permission denied: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted; run state is on disk and can be resumed", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
