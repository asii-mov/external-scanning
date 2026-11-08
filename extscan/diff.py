"""Compare two runs: what changed on the perimeter between them.

`extscan diff <old> <new>` answers the question a quarterly retest is for.
It lists services that opened, closed or changed version, and findings that
are new, still open or resolved.

The rule that reduced coverage must never look clean applies here too. A
finding missing from the new run is only *resolved* when the new run checked
that host, port and check without a coverage gap. Otherwise it is *not
re-observed (coverage gap)*, and the reason is given. In the same way, a
service missing from the new run is only *closed* when discovery covered
that host and port cleanly. Hosts outside either run's scope are compared
for nothing: they are listed apart, so no claim is made about them.

Findings are matched on `issue_key` (host, port, protocol, tool, check), not
on the title-based `id`, so a reworded title is still the same issue. The key
is recomputed from each finding's fields here, so runs written before the
key existed compare the same way as new ones.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Any

from . import probes as probes_mod
from .models import Finding, Service, check_identifier, issue_key_for, severity_rank
from .report import _esc
from .resilience import Degradation
from .store import Store

SERVICE_FIELDS = ("name", "product", "version", "extrainfo", "tunnel")

# Findings from probes whose source is not `extscan:<probe name>`.
PROBE_SOURCES = {
    "extscan:http": "http_fingerprint",
    "extscan:paths": "http_fingerprint",
    "sslscan": "sslscan",
}
# Findings from chase handlers, which only run when a lead asks for them.
CHASE_SOURCES = {
    "extscan:openapi", "extscan:graphql", "extscan:git", "extscan:web_paths",
    "extscan:secret_file", "extscan:api", "extscan:snmp_walk", "testssl.sh",
}
UNFINISHED_LEADS = {"open", "failed", "abandoned"}
_SERVICE_REASON = re.compile(r"^(\S+/(?:tcp|udp)/\d+): ")
_PORT_SPEC = re.compile(r"\d+(-\d+)?(,\d+(-\d+)?)*")


def _probe_for_source(source: str) -> str | None:
    if source in PROBE_SOURCES:
        return PROBE_SOURCES[source]
    tool, _, name = source.partition(":")
    if tool == "extscan" and name in probes_mod.all_probe_names():
        return name
    return None


def _nets(specs) -> list:
    out = []
    for spec in specs or []:
        try:
            out.append(ipaddress.ip_network(str(spec), strict=False))
        except ValueError:
            continue
    return out


def _port_in(spec: str, port: int) -> bool | None:
    """True/False for a literal nmap port list, None when it cannot be read."""
    spec = (spec or "").replace(" ", "")
    if not _PORT_SPEC.fullmatch(spec):
        return None
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        if int(lo) <= port <= int(hi or lo):
            return True
    return False


class RunState:
    """One run directory, loaded once, with the coverage questions the diff asks."""

    def __init__(self, store: Store):
        self.store = store
        self.run_id = store.run_id
        self.meta = store.meta()
        self.services: dict[str, Service] = {s.id: s for s in store.services()}
        self.findings = store.findings()
        self.issues: dict[str, list[Finding]] = {}
        for f in self.findings:
            self.issues.setdefault(issue_key_for(f), []).append(f)
        self.gaps = store.degradations()
        self.leads = store.leads()
        self.scope = self.meta.get("scope") or {}
        self.policy = self.meta.get("policy") or {}
        self.stages = self.meta.get("stages") or {}
        self._targets = _nets(self.scope.get("targets"))
        self._exclude = _nets(self.scope.get("exclude"))
        self._domains = [str(d).lower().rstrip(".") for d in self.scope.get("domains") or []]

    # Scope ----------------------------------------------------------------

    def scope_recorded(self) -> bool:
        return bool(self.scope.get("targets"))

    def in_scope(self, host: str) -> bool:
        """Whether this run was authorised to look at `host`, per run.json."""
        host = (host or "").strip().strip("[]")
        if not host or not self.scope_recorded():
            return True
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            name = host.lower().rstrip(".")
            return any(name == d or name.endswith("." + d) for d in self._domains)
        if any(addr in net for net in self._exclude):
            return False
        return any(addr in net for net in self._targets)

    # Coverage -------------------------------------------------------------

    def gaps_for(self, host: str, stages: tuple[str, ...],
                 service_id: str | None = None) -> list[Degradation]:
        """Recorded gaps in these stages that touch this host (or service).

        A stage name also matches its sub-stages (`probe` matches
        `probe:nuclei`). A gap with no host list applies to every host, and a
        gap with no host to compare against applies, so an unknown is a gap.
        """
        out = []
        for d in self.gaps:
            if not any(d.stage == s or d.stage.startswith(s + ":") for s in stages):
                continue
            if d.hosts and host and host not in d.hosts:
                continue
            m = _SERVICE_REASON.match(d.reason)
            if m and service_id and m.group(1) != service_id:
                continue
            out.append(d)
        return out

    def discovery_gap(self, host: str, proto: str, port: int | None) -> str | None:
        """Why discovery did not cleanly cover host (and port), or None."""
        if not self.in_scope(host):
            return "outside this run's scope"
        if proto not in ("tcp", "udp"):
            return None
        discover = self.stages.get("discover")
        if not discover:
            return "discovery did not complete in this run"
        if not isinstance(discover.get(proto), dict):
            return f"no {proto.upper()} discovery pass ran"
        gaps = self.gaps_for(host, (f"discover:{proto}",))
        if gaps:
            return f"coverage gap in {gaps[0].stage}: {gaps[0].reason}"
        if port is not None:
            spec = (self.policy.get("nmap") or {}).get(f"{proto}_ports", "")
            covered = _port_in(spec, port)
            if covered is None:
                return f"cannot tell whether {port}/{proto} was in the run's port list {spec!r}"
            if not covered:
                return f"{port}/{proto} was not in the run's port list"
        return None

    def check_gap(self, f: Finding) -> str | None:
        """Why this run did not cleanly perform the check behind `f` on f's
        target, or None when it did (so absence of the finding means it is
        gone). A port that discovery covered and found closed counts as
        covered: every check on it is moot."""
        host, proto, port, src = f.host, f.proto, f.port, f.source
        if not self.in_scope(host):
            return "outside this run's scope"
        if not host and port is not None:
            return "the finding records no host, so its target cannot be matched"
        svc: Service | None = None
        if proto in ("tcp", "udp") and port is not None:
            gap = self.discovery_gap(host, proto, port)
            if gap:
                return gap
            sid = f"{host}/{proto}/{port}"
            if sid not in self.services:
                return None
            svc = self.services[sid]
        elif proto in ("tcp", "udp") and host:
            gap = self.discovery_gap(host, "udp" if src.startswith("nmap-udp") else "tcp", None)
            if gap:
                return gap

        tool, _ = check_identifier(src, f.title, host)
        if tool == "nmap":
            if not (self.policy.get("nmap") or {}).get("scripts"):
                return "NSE scripts were disabled in this run's policy"
            return None
        if tool == "nuclei":
            return self._nuclei_gap(host, svc)
        probe = _probe_for_source(src)
        if probe:
            if svc is None:
                return f"no service for the {probe} probe to run on"
            if "probe" not in self.stages:
                return "the probe stage did not complete"
            gaps = self.gaps_for(host, (f"probe:{probe}",), svc.id)
            if gaps:
                return f"coverage gap in {gaps[0].stage}: {gaps[0].reason}"
            if probe not in svc.probed_by:
                return f"the {probe} probe did not run on {svc.id}"
            return None
        if src in CHASE_SOURCES:
            return self._chase_gap(host, port, svc)
        if src == "extscan:subdomains" or proto == "dns":
            return self._dns_gap(src)
        if src == "llm-analysis":
            return "model-assisted finding; the model's judgement is not re-run as a check"
        return f"not an automated check (source {src or 'unknown'}); re-verify by hand"

    def _nuclei_gap(self, host: str, svc: Service | None) -> str | None:
        if "probe" not in self.stages:
            return "the probe stage did not complete"
        gaps = self.gaps_for(host, ("probe:nuclei",))
        if gaps:
            return f"coverage gap in probe:nuclei: {gaps[0].reason}"
        on_host = [s for s in self.services.values() if s.host == host]
        if host and not any("nuclei" in s.probed_by for s in on_host):
            return "nuclei did not run against this host"
        if svc is not None and svc.is_http and "nuclei" not in svc.probed_by:
            return f"nuclei did not run against {svc.id}"
        return None

    def _chase_gap(self, host: str, port: int | None, svc: Service | None) -> str | None:
        # A chase finding depends on the probe or nuclei result that raised
        # its lead, so any gap upstream on this service counts as well.
        if "chase" not in self.stages:
            return "the chase stage did not complete"
        gaps = self.gaps_for(host, ("probe", "chase"), svc.id if svc else None)
        if gaps:
            return f"coverage gap in {gaps[0].stage}: {gaps[0].reason}"
        if svc is not None and not svc.probed_by:
            return f"{svc.id} was not probed"
        for ld in self.leads:
            if ld.host == host and (port is None or ld.port == port) \
                    and ld.status in UNFINISHED_LEADS:
                return f"follow-up {ld.kind} on {host}:{ld.port or '-'} is {ld.status}"
        return None

    def _dns_gap(self, src: str) -> str | None:
        stages = ("recon",) if src == "extscan:subdomains" else ("recon", "discover:dns")
        if src == "extscan:subdomains" and "recon" not in self.stages:
            return "the recon stage did not run"
        if src != "extscan:subdomains" and not ({"recon", "discover"} & set(self.stages)):
            return "no DNS checks ran"
        gaps = self.gaps_for("", stages)
        if gaps:
            return f"coverage gap in {gaps[0].stage}: {gaps[0].reason}"
        return None


# Comparison ---------------------------------------------------------------

def _flatten(d: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(d, dict):
        out: dict[str, Any] = {}
        for k, v in d.items():
            out.update(_flatten(v, f"{prefix}{k}."))
        return out
    return {prefix.rstrip("."): d}


def _service_entry(s: Service) -> dict:
    return {"id": s.id, "host": s.host, "port": s.port, "proto": s.proto,
            "name": s.name, "product": s.product, "version": s.version}


def _issue_entry(key: str, group: list[Finding]) -> dict:
    worst = max(group, key=lambda f: severity_rank(f.severity))
    return {
        "issue_key": key,
        "check": worst.check_id,
        "host": worst.host, "port": worst.port, "proto": worst.proto,
        "severity": worst.severity,
        "title": worst.title,
        "finding_ids": sorted({f.id for f in group}),
        "sources": sorted({f.source for f in group}),
    }


def _first_gap(state: RunState, group: list[Finding]) -> str | None:
    """None if any finding's check was covered, else the first reason."""
    reasons = [state.check_gap(f) for f in group]
    if any(r is None for r in reasons):
        return None
    return reasons[0]


def _sort_key(e: dict):
    return (-severity_rank(e.get("severity", "info")), e.get("host") or "",
            e.get("proto") or "", e.get("port") or 0, e.get("title") or e.get("id") or "")


def _gap_entry(d: Degradation) -> dict:
    return {"stage": d.stage, "component": d.component, "reason": d.reason,
            "impact": d.impact, "severity": d.severity, "hosts": d.hosts}


def compare(old_store: Store, new_store: Store) -> dict:
    old, new = RunState(old_store), RunState(new_store)
    warnings: list[str] = []

    # Scope and policy -----------------------------------------------------
    scope_changes = {}
    for field in ("targets", "exclude", "domains"):
        a = set(map(str, old.scope.get(field) or []))
        b = set(map(str, new.scope.get(field) or []))
        if a != b:
            scope_changes[field] = {"removed": sorted(a - b), "added": sorted(b - a)}
    if not old.scope_recorded() or not new.scope_recorded():
        warnings.append("One run has no scope recorded in run.json, so every host is "
                        "treated as in scope for it.")
    if scope_changes:
        warnings.append("The runs had different scopes. Closed and resolved are only "
                        "claimed for hosts in scope in both runs; the rest are listed "
                        "under 'outside the overlap'.")
    old_pol, new_pol = _flatten(old.policy), _flatten(new.policy)
    policy_changes = [{"key": k, "old": old_pol.get(k), "new": new_pol.get(k)}
                      for k in sorted(set(old_pol) | set(new_pol))
                      if old_pol.get(k) != new_pol.get(k)]
    if policy_changes:
        warnings.append(
            f"The runs used different policies ({len(policy_changes)} setting(s) "
            "differ, listed below). Port lists, UDP and NSE scripts are taken into "
            "account; other changes, such as nuclei tags or templates, can make a "
            "finding disappear without it being fixed.")
    old_tools = old.meta.get("tool_versions") or {}
    new_tools = new.meta.get("tool_versions") or {}
    tool_changes = {k: [old_tools.get(k), new_tools.get(k)]
                    for k in sorted(set(old_tools) | set(new_tools))
                    if old_tools.get(k) != new_tools.get(k)}
    if tool_changes:
        warnings.append("Tool versions differ between the runs: "
                        + ", ".join(f"{k} {v[0] or '?'} -> {v[1] or '?'}"
                                    for k, v in tool_changes.items()) + ".")
    if (old.meta.get("created") or 0) > (new.meta.get("created") or 0):
        warnings.append("The 'old' run was created after the 'new' one; check the "
                        "argument order.")

    # Services -------------------------------------------------------------
    svc: dict[str, list] = {"new": [], "closed": [], "not_reobserved": [],
                            "outside_overlap": [], "changed": []}
    unchanged = 0
    for sid, s in new.services.items():
        if sid in old.services:
            o = old.services[sid]
            changes = {f: [getattr(o, f), getattr(s, f)] for f in SERVICE_FIELDS
                       if getattr(o, f) != getattr(s, f)}
            if changes:
                svc["changed"].append({**_service_entry(s), "changes": changes})
            else:
                unchanged += 1
            continue
        entry = _service_entry(s)
        if not old.in_scope(s.host):
            entry["note"] = "outside the old run's scope"
        else:
            gap = old.discovery_gap(s.host, s.proto, s.port)
            if gap:
                entry["note"] = f"the old run did not cover it: {gap}"
        svc["new"].append(entry)
    for sid, o in old.services.items():
        if sid in new.services:
            continue
        entry = _service_entry(o)
        if not new.in_scope(o.host):
            entry["reason"] = "outside the new run's scope"
            svc["outside_overlap"].append(entry)
            continue
        gap = new.discovery_gap(o.host, o.proto, o.port)
        if gap:
            entry["reason"] = gap
            svc["not_reobserved"].append(entry)
        else:
            svc["closed"].append(entry)

    # Findings -------------------------------------------------------------
    fnd: dict[str, list] = {"new": [], "resolved": [], "not_reobserved": [],
                            "outside_overlap": [], "still_open": [], "severity_changed": []}
    for key, group in new.issues.items():
        entry = _issue_entry(key, group)
        if key in old.issues:
            before = _issue_entry(key, old.issues[key])
            if before["severity"] != entry["severity"]:
                entry["old_severity"] = before["severity"]
                fnd["severity_changed"].append(entry)
            if before["title"] != entry["title"]:
                entry["old_title"] = before["title"]
            fnd["still_open"].append(entry)
            continue
        if not old.in_scope(entry["host"]):
            entry["note"] = "outside the old run's scope"
        else:
            gap = _first_gap(old, group)
            if gap:
                entry["note"] = f"the old run did not cover this check: {gap}"
        fnd["new"].append(entry)
    for key, group in old.issues.items():
        if key in new.issues:
            continue
        entry = _issue_entry(key, group)
        if not new.in_scope(entry["host"]):
            entry["reason"] = "outside the new run's scope"
            fnd["outside_overlap"].append(entry)
            continue
        gap = _first_gap(new, group)
        if gap:
            entry["reason"] = gap
            fnd["not_reobserved"].append(entry)
            continue
        if entry["port"] is not None and entry["proto"] in ("tcp", "udp") and \
                f"{entry['host']}/{entry['proto']}/{entry['port']}" not in new.services:
            entry["note"] = "the service is no longer open"
        fnd["resolved"].append(entry)

    # Coverage gaps --------------------------------------------------------
    def gkey(d: Degradation):
        return (d.stage, d.component, d.reason)
    old_g = {gkey(d): d for d in old.gaps}
    new_g = {gkey(d): d for d in new.gaps}
    gaps = {
        "new": [_gap_entry(d) for k, d in new_g.items() if k not in old_g],
        "closed": [_gap_entry(d) for k, d in old_g.items() if k not in new_g],
        "still_open": [_gap_entry(d) for k, d in new_g.items() if k in old_g],
    }

    for group in (*svc.values(), *fnd.values()):
        group.sort(key=_sort_key)

    def run_info(st: RunState) -> dict:
        return {"run_id": st.run_id, "path": str(st.store.path),
                "created": st.meta.get("created"), "profile": st.meta.get("profile"),
                "engagement": st.scope.get("engagement", "")}

    summary = {
        "services_new": len(svc["new"]), "services_closed": len(svc["closed"]),
        "services_not_reobserved": len(svc["not_reobserved"]),
        "services_changed": len(svc["changed"]), "services_unchanged": unchanged,
        "services_outside_overlap": len(svc["outside_overlap"]),
        "findings_new": len(fnd["new"]), "findings_resolved": len(fnd["resolved"]),
        "findings_not_reobserved": len(fnd["not_reobserved"]),
        "findings_still_open": len(fnd["still_open"]),
        "findings_severity_changed": len(fnd["severity_changed"]),
        "findings_outside_overlap": len(fnd["outside_overlap"]),
        "gaps_new": len(gaps["new"]), "gaps_closed": len(gaps["closed"]),
        "gaps_still_open": len(gaps["still_open"]),
    }
    return {
        "generated": time.time(),
        "old": run_info(old), "new": run_info(new),
        "summary": summary, "warnings": warnings,
        "scope_changes": scope_changes, "policy_changes": policy_changes,
        "tool_changes": tool_changes,
        "services": svc, "findings": fnd, "coverage_gaps": gaps,
    }


# Rendering ----------------------------------------------------------------

def _target(e: dict) -> str:
    if e.get("port") is not None:
        return f"{e.get('host') or '-'}:{e['port']}/{e.get('proto')}"
    return e.get("host") or "-"


def _when(epoch) -> str:
    if not epoch:
        return "n/a"
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(epoch))


def render_markdown(d: dict) -> str:
    out: list[str] = []
    w = out.append
    old, new, s = d["old"], d["new"], d["summary"]
    w(f"# Run comparison: {_esc(old['run_id'])} to {_esc(new['run_id'])}")
    w("")
    w(f"**Engagement:** {_esc(new['engagement'] or old['engagement'] or 'n/a')}  ")
    w(f"**Old run:** `{old['run_id']}` ({_when(old['created'])}, profile "
      f"`{old['profile'] or 'n/a'}`)  ")
    w(f"**New run:** `{new['run_id']}` ({_when(new['created'])}, profile "
      f"`{new['profile'] or 'n/a'}`)  ")
    w(f"**Compared:** {_when(d['generated'])}")
    w("")
    w("A finding missing from the new run is **resolved** only when the new run "
      "performed that check on that host and port without a coverage gap. "
      "Otherwise it is **not re-observed (coverage gap)**: it may still be there. "
      "A service is **closed** only when discovery covered its host and port "
      "cleanly. Findings are matched on their issue key (host, port, protocol, "
      "tool and check), so a reworded title is still the same issue.")
    w("")
    w("## Summary")
    w("")
    w("| | New | Closed / resolved | Not re-observed (coverage gap) | Changed | Still open |")
    w("|---|---|---|---|---|---|")
    w(f"| Services | {s['services_new']} | {s['services_closed']} | "
      f"{s['services_not_reobserved']} | {s['services_changed']} | "
      f"{s['services_unchanged']} unchanged |")
    w(f"| Findings | {s['findings_new']} | {s['findings_resolved']} | "
      f"{s['findings_not_reobserved']} | {s['findings_severity_changed']} severity | "
      f"{s['findings_still_open']} |")
    w(f"| Coverage gaps | {s['gaps_new']} | {s['gaps_closed']} | | | {s['gaps_still_open']} |")
    w("")
    if s["services_outside_overlap"] or s["findings_outside_overlap"]:
        w(f"Outside the overlap of the two scopes, and not compared: "
          f"{s['services_outside_overlap']} service(s), "
          f"{s['findings_outside_overlap']} finding(s).")
        w("")

    if d["warnings"]:
        w("## Warnings")
        w("")
        for msg in d["warnings"]:
            w(f"- {_esc(msg)}")
        w("")
    if d["scope_changes"]:
        w("### Scope differences")
        w("")
        for field, ch in d["scope_changes"].items():
            if ch["removed"]:
                w(f"- `{field}` only in the old run: {_esc(', '.join(ch['removed']))}")
            if ch["added"]:
                w(f"- `{field}` only in the new run: {_esc(', '.join(ch['added']))}")
        w("")
    if d["policy_changes"]:
        w("### Policy differences")
        w("")
        w("| Setting | Old | New |")
        w("|---|---|---|")
        for ch in d["policy_changes"]:
            w(f"| `{ch['key']}` | {_esc(json.dumps(ch['old']))} | {_esc(json.dumps(ch['new']))} |")
        w("")

    sv = d["services"]
    w("## Services")
    w("")
    _service_table(w, "New services", sv["new"], "note")
    _service_table(w, "Closed services", sv["closed"], None)
    _service_table(w, "Not re-observed (coverage gap)", sv["not_reobserved"], "reason")
    if sv["changed"]:
        w("### Changed product or version")
        w("")
        w("| Service | Field | Old | New |")
        w("|---|---|---|---|")
        for e in sv["changed"]:
            for field, (a, b) in e["changes"].items():
                w(f"| {_esc(e['id'])} | {field} | {_esc(str(a)) or '-'} | {_esc(str(b)) or '-'} |")
        w("")
    _service_table(w, "Outside the overlap (not compared)", sv["outside_overlap"], "reason")

    fd = d["findings"]
    w("## Findings")
    w("")
    _finding_table(w, "New findings", fd["new"], "note")
    _finding_table(w, "Resolved", fd["resolved"], "note")
    _finding_table(w, "Not re-observed (coverage gap)", fd["not_reobserved"], "reason")
    if fd["severity_changed"]:
        w("### Severity changed")
        w("")
        w("| Old | New | Target | Finding |")
        w("|---|---|---|---|")
        for e in fd["severity_changed"]:
            w(f"| {e['old_severity'].upper()} | {e['severity'].upper()} | "
              f"{_esc(_target(e))} | {_esc(e['title'])} |")
        w("")
    _finding_table(w, "Still open", fd["still_open"], None)
    _finding_table(w, "Outside the overlap (not compared)", fd["outside_overlap"], "reason")

    g = d["coverage_gaps"]
    w("## Coverage gaps")
    w("")
    for label, rows in (("New in this run", g["new"]), ("Closed since the old run", g["closed"]),
                        ("Still open", g["still_open"])):
        if not rows:
            continue
        w(f"### {label}")
        w("")
        w("| Stage | Component | Reason | Impact |")
        w("|---|---|---|---|")
        for e in rows:
            w(f"| {_esc(e['stage'])} | {_esc(e['component'])} | {_esc(e['reason'])} | "
              f"{_esc(e['impact'])} |")
        w("")
    if not any(g.values()):
        w("Neither run recorded a coverage gap.")
        w("")
    return "\n".join(out) + "\n"


def _service_table(w, label: str, rows: list[dict], extra: str | None) -> None:
    if not rows:
        return
    w(f"### {label}")
    w("")
    head = "| Service | Name | Product | Version |" + (" Note |" if extra else "")
    w(head)
    w("|---|---|---|---|" + ("---|" if extra else ""))
    for e in rows:
        line = (f"| {_esc(e['id'])} | {_esc(e['name']) or '-'} | {_esc(e['product']) or '-'} "
                f"| {_esc(e['version']) or '-'} |")
        if extra:
            line += f" {_esc(e.get(extra, ''))} |"
        w(line)
    w("")


def _finding_table(w, label: str, rows: list[dict], extra: str | None) -> None:
    if not rows:
        return
    w(f"### {label} ({len(rows)})")
    w("")
    w("| Severity | Target | Finding | Check |" + (" Note |" if extra else ""))
    w("|---|---|---|---|" + ("---|" if extra else ""))
    for e in rows:
        title = e["title"]
        if e.get("old_title"):
            title += f" (was: {e['old_title']})"
        line = (f"| {e['severity'].upper()} | {_esc(_target(e))} | {_esc(title)} | "
                f"`{_esc(e['check']).replace('`', '')}` |")
        if extra:
            line += f" {_esc(e.get(extra, ''))} |"
        w(line)
    w("")


def output_paths(new_store: Store, old_run_id: str) -> tuple[Path, Path]:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", old_run_id).strip("-.") or "old"
    base = new_store.path / f"diff-{slug[:64]}"
    return base.with_suffix(".md"), base.with_suffix(".json")


def write(new_store: Store, result: dict) -> tuple[Path, Path]:
    md, js = output_paths(new_store, result["old"]["run_id"])
    md.write_text(render_markdown(result))
    js.write_text(json.dumps(result, indent=2, default=str))
    return md, js


def console_summary(result: dict, paths: tuple[Path, Path] | None = None) -> str:
    s = result["summary"]
    lines = [
        f"Compared {result['old']['run_id']} -> {result['new']['run_id']}",
        f"  services: {s['services_new']} new, {s['services_closed']} closed, "
        f"{s['services_not_reobserved']} not re-observed (coverage gap), "
        f"{s['services_changed']} changed",
        f"  findings: {s['findings_new']} new, {s['findings_resolved']} resolved, "
        f"{s['findings_not_reobserved']} not re-observed (coverage gap), "
        f"{s['findings_still_open']} still open "
        f"({s['findings_severity_changed']} with a severity change)",
        f"  coverage gaps: {s['gaps_new']} new, {s['gaps_closed']} closed, "
        f"{s['gaps_still_open']} still open",
    ]
    if s["services_outside_overlap"] or s["findings_outside_overlap"]:
        lines.append(f"  outside the scope overlap: {s['services_outside_overlap']} "
                     f"service(s), {s['findings_outside_overlap']} finding(s), not compared")
    lines += [f"  ! {msg}" for msg in result["warnings"]]
    if paths:
        lines.append(f"  wrote {paths[0]} and {paths[1].name}")
    return "\n".join(lines)
