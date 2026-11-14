"""Report rendering.

The structure follows how an external audit actually gets consumed: the client
reads the summary, the remediation team reads the findings, and the auditor
works the manual-review queue before any of it goes out. The queue is first
among the working sections for that reason -- it is the handover from
automation to the person signing the report.

Every claim is accompanied by what produced it, and the appendix carries the
full command log, so a client who disputes a finding can reproduce it.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import enrich
from . import template as tpl
from .models import Finding, Host, Lead, Service
from .resilience import Degradation
from .scope import Authorization, Scope
from .template import TemplateError
from .triage import TriageResult, triage

DEFAULT_TEMPLATE = Path(__file__).parent / "templates" / "report.md"

# Sections a template may move or retitle but not drop. A report that leaves
# out what was never checked, or what a person still has to decide, reads as
# a clean result when it is not one.
REQUIRED_SECTIONS = ("coverage_gaps", "review_queue")

# Finding sources that are a person's or a model's reasoning, not tool output.
ANALYSIS_SOURCES = ("llm-analysis", "analyst")

SEV_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Informational",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _ts(epoch: float | None = None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(epoch))


def _fence(text: str, limit: int = 2500) -> str:
    """Fence evidence, neutralising any fence markers inside it.

    Scanner evidence is attacker-influenced text. Without this, a response body
    containing ``` would break out of the code block and could inject headings
    or links into the report a client reads.
    """
    body = (text or "").strip()
    if len(body) > limit:
        body = body[:limit] + f"\n... [truncated, {len(text)} bytes total]"
    body = body.replace("```", "'''")
    return "```text\n" + body + "\n```"


def _esc(text: str) -> str:
    """Escape pipes and newlines for Markdown table cells."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _exploited(kev: bool, epss: float | None, version_match: bool = False) -> str:
    parts = []
    if kev:
        parts.append("**KEV**" + (" (version match)" if version_match else ""))
    if epss is not None:
        parts.append(f"EPSS {epss:.2f}")
    return ", ".join(parts) or "-"


def _enrichment_lines(stage: dict | None) -> list[str]:
    """What the exploitation ranking in this report rests on."""
    if not stage:
        return ["Findings were not checked against CISA KEV or EPSS, and hosts were not "
                "checked against CDN ranges: the `enrich` stage did not run.", ""]
    if stage.get("disabled"):
        return ["Findings were not checked against CISA KEV or EPSS, and hosts were not "
                f"checked against CDN ranges: {_esc(str(stage.get('reason', 'disabled')))}.",
                ""]
    out = ["Exploitation data used for ranking (severity is never changed by it):", ""]
    kev, epss = stage.get("kev"), stage.get("epss")
    if stage.get("skipped"):
        out.append(f"- KEV and EPSS were not fetched: {_esc(str(stage['skipped']))}.")
    if kev:
        out.append(f"- CISA Known Exploited Vulnerabilities catalogue, version "
                   f"{_esc(str(kev.get('catalog_version') or '?'))}, released "
                   f"{_esc(str(kev.get('date_released') or '?'))}, "
                   f"{kev.get('count', '?')} entries, fetched {_esc(str(kev.get('fetched')))}.")
    if epss:
        out.append(f"- EPSS model {_esc(str(epss.get('model_version') or '?'))}, scores of "
                   f"{_esc(str(epss.get('score_date') or '?'))}, fetched "
                   f"{_esc(str(epss.get('fetched')))}. {enrich.EPSS_ATTRIBUTION}")
    ranges = (stage.get("networks") or {}).get("ranges") or {}
    if ranges:
        out.append("- CDN and cloud address ranges published by: "
                   + ", ".join(f"{_esc(p)} ({r.get('networks', '?')} ranges)"
                               for p, r in ranges.items()) + ".")
    if not (kev or epss) and not stage.get("skipped"):
        out.append("- Neither KEV nor EPSS could be loaded; see Coverage gaps.")
    out.append("")
    return out


def _authorisation_block(scope: Scope) -> str:
    a = scope.authorization
    if not a.reference:
        return ("- Not recorded. The scope was a plain list of targets, which "
                "carries no sign-off.")
    out = [f"- **Reference:** {a.reference}", f"- **Authorised by:** {a.authorized_by}"]
    if a.window_start or a.window_end:
        out.append(f"- **Testing window:** {a.window_start or 'open'} to "
                   f"{a.window_end or 'open'}")
    if a.notes:
        out.append(f"- **Constraints:** {a.notes}")
    return "\n".join(out)


def _scope_block(scope: Scope) -> str:
    out = [f"- `{t}`" for t in scope.targets]
    if scope.exclude:
        out += ["", "Excluded by agreement:"]
        out += [f"- `{t}`" for t in scope.exclude]
    return "\n".join(out)


def _summary_block(triaged: TriageResult, hosts: list[Host],
                   degradations: list[Degradation]) -> str:
    stats = triaged.stats
    by_sev = stats["findings_by_severity"]
    out: list[str] = []
    w = out.append
    w(f"{stats['hosts_with_findings']} of {len(hosts)} responding host(s) produced "
      f"findings across {stats['services_total']} open service(s) "
      f"({stats['services_tcp']} TCP, {stats['services_udp']} UDP, "
      f"{stats['web_services']} speaking HTTP).")
    w("")
    w("| Severity | Findings |")
    w("|---|---|")
    for sev in SEV_ORDER:
        if by_sev.get(sev):
            w(f"| {SEV_LABEL[sev]} | {by_sev[sev]} |")
    w(f"| **Total** | **{stats['findings_total']}** |")
    w("")
    w(f"{stats['review_items']} item(s) require manual review before this report is "
      f"issued; {stats['distinct_issues']} distinct issue(s) were identified, of which "
      f"{stats['systemic_issues']} appear across three or more hosts.")
    if degradations:
        serious = sum(1 for d in degradations if d.severity == "serious")
        w("")
        w(f"> ⚠️ **This assessment has {len(degradations)} coverage gap(s)"
          f"{f', {serious} serious' if serious else ''}.** Parts of the intended "
          "testing did not complete, so some absences in this report reflect "
          "checks that did not run rather than exposure that is not there. "
          "See the coverage gaps section before drawing conclusions.")
    return "\n".join(out)


def _review_queue_block(triaged: TriageResult) -> str:
    if not triaged.review_queue:
        return "_Nothing flagged for manual review._"
    out: list[str] = []
    w = out.append
    w("Automated checks establish that something is exposed; they cannot decide "
      "whether it is acceptable for this client. Each item below names the "
      "specific question an auditor needs to answer. Work top to bottom.")
    w("")
    if any(item.kev for item in triaged.review_queue):
        w("Items marked **KEV** concern a CVE in CISA's Known Exploited "
          "Vulnerabilities catalogue. They are listed ahead of items one severity "
          "level higher, because exploitation is known and not predicted.")
        w("")
    w("| # | Severity | Exploited | Item | Target | An auditor must decide |")
    w("|---|---|---|---|---|---|")
    for item in triaged.review_queue:
        label = _esc(item.title)
        if item.instances:
            label += f" _(+{len(item.instances) - 1} related, listed below)_"
        w(f"| {item.priority} | {SEV_LABEL.get(item.severity, item.severity)} "
          f"| {_exploited(item.kev, item.epss, item.version_match)} "
          f"| {label} | `{_esc(item.target)}` | {_esc(item.question)} |")
    grouped_items = [i for i in triaged.review_queue if i.instances]
    if grouped_items:
        w("")
        w("Where one queue entry covers several instances:")
        w("")
        for item in grouped_items:
            w(f"- **#{item.priority}** ({len(item.instances)} instances):")
            for inst in item.instances[:15]:
                w(f"  - {inst}")
            if len(item.instances) > 15:
                w(f"  - _... and {len(item.instances) - 15} more_")
    return "\n".join(out)


def _target(host: str, port: int | None, proto: str = "tcp") -> str:
    return f"{host}:{port}/{proto}" if port else (host or "n/a")


def _is_analysis(f: Finding) -> bool:
    return f.source in ANALYSIS_SOURCES or f.source.endswith("-analysis")


def _outside_scope(f: Finding) -> bool:
    return "out-of-scope" in f.tags or {"scope", "asset-discovery"} <= set(f.tags)


def security_notes(triaged: TriageResult, leads: list[Lead] | None) -> dict:
    """What a person has to pick up after the scan, beyond the review queue.

    Four lists, each of things the scanner saw and could not or would not
    settle by itself: follow-ups it did not finish, assets it saw outside the
    scope file and left alone, findings inferred from a version or a
    specification, and notes written by an analyst or a model.
    """
    unfinished = []
    for ld in leads or []:
        if ld.status in ("done", "skipped"):
            continue
        if ld.status == "open" and not ld.attempts:
            state = "not attempted"
        elif ld.status == "open":
            state = f"still failing after {ld.attempts} attempt(s)"
        else:
            state = ld.status
        unfinished.append({
            "lead_id": ld.id, "kind": ld.kind,
            "target": ld.url or _target(ld.host, ld.port, ld.proto),
            "why": ld.reason, "state": state,
            "detail": ld.last_error or ld.note,
        })

    def row(f: Finding) -> dict:
        return {"finding_id": f.id, "title": f.title, "source": f.source,
                "target": _target(f.host, f.port, f.proto), "severity": f.severity}

    findings = triaged.findings
    return {
        "unfinished_followups": unfinished,
        "outside_scope": [row(f) for f in findings if _outside_scope(f)],
        "to_confirm": [row(f) for f in findings
                       if f.confidence == "tentative" and not _is_analysis(f)],
        "analysis_notes": [row(f) for f in findings if _is_analysis(f)],
    }


def _finding_rows(rows: list[dict], limit: int = 25) -> list[str]:
    out = [f"- {_esc(r['title'])} on `{_esc(r['target'])}` "
           f"({SEV_LABEL.get(r['severity'], r['severity'])}, finding `{r['finding_id']}`)"
           for r in rows[:limit]]
    if len(rows) > limit:
        out.append(f"- _... and {len(rows) - limit} more: `extscan findings <run>`_")
    return out


def _security_notes_block(notes: dict, run_id: str) -> str:
    out: list[str] = []
    w = out.append
    unfinished, outside = notes["unfinished_followups"], notes["outside_scope"]
    confirm, analysis = notes["to_confirm"], notes["analysis_notes"]
    if not (unfinished or outside or confirm or analysis):
        return ("_Nothing is outstanding beyond the manual review queue: every follow-up "
                "was completed, nothing was seen outside the scope file, and no finding "
                "rests on inference alone._")

    w("Where to look next. These are the things the scan saw and could not settle "
      "by itself. None of them is a confirmed vulnerability; each is a place for a "
      "person to carry on from.")
    if unfinished:
        w("")
        w(f"**Follow-ups the scanner did not finish ({len(unfinished)}).** Whatever these "
          "lead to has not been assessed. Check them by hand, or fix the cause and run "
          f"`extscan chase {run_id}`.")
        w("")
        w("| Follow-up | Target | Why it was raised | State |")
        w("|---|---|---|---|")
        for u in unfinished[:40]:
            state = _esc(u["state"]) + (f": {_esc(u['detail'][:160])}" if u["detail"] else "")
            w(f"| `{_esc(u['kind'])}` | `{_esc(u['target'])}` | {_esc(u['why'])} | {state} |")
        if len(unfinished) > 40:
            w("")
            w(f"_... and {len(unfinished) - 40} more: `extscan leads {run_id} --status all`_")
    if outside:
        w("")
        w(f"**Seen but not touched: outside the scope file ({len(outside)}).** The scanner "
          "does not follow anything out of scope. If these are ours, add them to the "
          "scope file and scan again; if they are not, find out why our systems point "
          "at them.")
        w("")
        out.extend(_finding_rows(outside))
    if confirm:
        w("")
        w(f"**Inferred, not observed ({len(confirm)}).** These findings come from a version "
          "string or a specification, not from behaviour the scanner saw. Confirm each "
          "one before acting on it.")
        w("")
        out.extend(_finding_rows(confirm))
    if analysis:
        w("")
        w(f"**Analyst and model notes ({len(analysis)}).** Written by a person or a "
          "language model about the evidence, and listed with the findings below. Model "
          "notes are commentary on text the target controls: check them against the "
          "evidence.")
        w("")
        out.extend(_finding_rows(analysis))
    w("")
    w(f"To dig in: `extscan show {run_id} --finding <id>` prints a finding's full "
      f"evidence, `extscan leads {run_id} --status all` lists every follow-up, and "
      f"`extscan note {run_id} ...` records what you conclude so it appears in the "
      "next report.")
    return "\n".join(out)


def _systemic_block(triaged: TriageResult) -> str:
    if not triaged.systemic:
        return ""
    out = ["Each of these appears on three or more hosts, so it is one configuration "
           "or process fix rather than a list of individual repairs.", "",
           "| Severity | Issue | Affected hosts |", "|---|---|---|"]
    for s in triaged.systemic:
        shown = ", ".join(f"`{h}`" for h in s.hosts[:8])
        if len(s.hosts) > 8:
            shown += f" (+{len(s.hosts) - 8} more)"
        out.append(f"| {SEV_LABEL.get(s.severity, s.severity)} | {_esc(s.title)} "
                   f"| {len(s.hosts)}: {shown} |")
    return "\n".join(out)


def _finding_fields(f: Finding, number: int) -> dict:
    exploitation = []
    for line in enrich.cve_lines(f):
        head, _, rest = line.partition(": ")
        exploitation.append(f"- **{head}:** {_esc(rest)}" if rest else f"- {_esc(line)}")
    return {
        "number": number, "id": f.id, "title": f.title,
        "severity": f.severity,
        "severity_label": SEV_LABEL.get(f.severity, f.severity),
        "tentative": f.confidence == "tentative", "confidence": f.confidence,
        "target": _target(f.host, f.port, f.proto),
        "host": f.host, "port": f.port or "", "proto": f.proto,
        "source": f.source,
        "tags": ", ".join(f"`{t}`" for t in f.tags),
        "exploitation": "\n".join(exploitation),
        "description": f.description,
        "review_required": f.review_required, "review_reason": f.review_reason,
        "evidence": _fence(f.evidence) if f.evidence else "",
        "recommendation": f.recommendation,
        "references": "\n".join(f"- {r}" for r in f.references),
    }


def _inventory_block(services: list[Service]) -> str:
    if not services:
        return "_No open services recorded._"
    out = ["| Host | Port | Proto | Service | Product / version | Probes run |",
           "|---|---|---|---|---|---|"]
    for s in services:
        product = " ".join(x for x in (s.product, s.version, s.extrainfo) if x)
        out.append(f"| `{s.host}` | {s.port} | {s.proto} | {_esc(s.name) or '?'} "
                   f"| {_esc(product) or '-'} | {', '.join(s.probed_by) or '-'} |")
    return "\n".join(out)


def _host_detail_block(hosts: list[Host]) -> str:
    named = [h for h in hosts if h.hostnames or h.os_guess or h.network]
    if not named:
        return ""
    out = ["| Host | Hostnames | OS guess | Network |", "|---|---|---|---|"]
    for h in named:
        out.append(f"| `{h.ip}` | {_esc(', '.join(h.hostnames)) or '-'} "
                   f"| {_esc(h.os_guess or '-')} | {_esc(enrich.host_network_label(h)) or '-'} |")
    if any(h.network for h in hosts):
        out += ["", "A host with a network named above sits in that provider's published "
                    "address ranges. Its ports and services may be the provider's shared "
                    "edge and not the client's own server."]
    return "\n".join(out)


def _coverage_gaps_block(degradations: list[Degradation]) -> str:
    if not degradations:
        return ""
    serious = [d for d in degradations if d.severity == "serious"]
    out: list[str] = []
    w = out.append
    w(f"{len(degradations)} part(s) of this assessment did not complete as "
      f"intended{f', {len(serious)} of them materially' if serious else ''}. "
      "**Absence of findings in the areas below is not evidence that nothing "
      "is exposed there** -- the check did not run, or ran partially.")
    w("")
    w("| Severity | Stage | What was lost | Remedy |")
    w("|---|---|---|---|")
    for d in sorted(degradations, key=lambda x: x.severity != "serious"):
        label = "Serious" if d.severity == "serious" else "Warning"
        affected = f" ({len(d.hosts)} host(s))" if d.hosts else ""
        w(f"| {label} | `{_esc(d.stage)}` | {_esc(d.impact)}{affected} "
          f"| {_esc(d.remedy) or '-'} |")
    w("")
    w("<details><summary>Technical detail for each gap</summary>")
    w("")
    for d in degradations:
        w(f"- **{_esc(d.component)}** during `{_esc(d.stage)}`: {_esc(d.reason)}")
        if d.hosts:
            shown = ", ".join(f"`{h}`" for h in d.hosts[:12])
            more = f" (+{len(d.hosts) - 12} more)" if len(d.hosts) > 12 else ""
            w(f"  - affected: {shown}{more}")
    w("")
    w("</details>")
    return "\n".join(out)


def _model_lines(stage: dict | None) -> list[str]:
    """What a language model did in this run, when one was used."""
    if not stage:
        return []
    if stage.get("skipped"):
        return [f"Model-written notes were not produced: {_esc(str(stage['skipped']))}.", ""]
    return [f"A language model ({_esc(str(stage.get('provider') or '?'))}, "
            f"{_esc(str(stage.get('model') or '?'))}) wrote notes on "
            f"{stage.get('succeeded', 0)} of {stage.get('requested', 0)} item(s) it was "
            "asked about. Its notes are separate findings marked `llm-analysis`, always "
            "informational and always flagged for review; it chose nothing that was "
            "scanned and changed no severity.", ""]


def _methodology_block(meta: dict, template_label: str) -> str:
    out: list[str] = []
    w = out.append
    stages = meta.get("stages", {})
    w("Stages completed:")
    w("")
    for name in ("discover", "probe", "chase", "report"):
        if name in stages:
            w(f"- `{name}` at {_ts(stages[name].get('completed'))}")
        else:
            w(f"- `{name}` — **not run**")
    w("")
    for warning in meta.get("warnings", []):
        w(f"- ⚠️ {warning}")
    if meta.get("warnings"):
        w("")
    w("Limitations that apply to this report:")
    w("")
    w("- All checks were read-only. No credentials were tested, no data was modified, "
      "and no exploitation was attempted. Findings marked *tentative* are "
      "version-derived or specification-derived and need confirmation.")
    w("- Services behind a WAF, rate limiter or geo-filter may be under-reported.")
    w("- UDP results are less reliable than TCP by nature: silence is ambiguous.")
    w("- Absence of a finding is not evidence of absence of a vulnerability.")
    w("")
    out.extend(_enrichment_lines(stages.get("enrich")))
    out.extend(_model_lines(stages.get("analyse")))
    w(f"Report layout: {template_label}.")
    return "\n".join(out)


def _tool_versions_block(meta: dict) -> str:
    return "\n".join(f"- `{tool}`: {version}"
                     for tool, version in (meta.get("tool_versions") or {}).items())


def _command_log_block(commands: list[dict]) -> str:
    if not commands:
        return ""
    out = [f"{len(commands)} command(s) were executed. Full argv, exit codes and "
           "timings are in `commands.jsonl` in the run directory.", "", "```text"]
    for c in commands[:60]:
        rc = c.get("returncode")
        rc_text = "dry-run" if rc is None and "dry-run" in (c.get("error") or "") else rc
        out.append(f"[{_ts(c.get('started'))}] rc={rc_text} "
                   f"{c.get('duration', 0):.1f}s  {' '.join(c.get('argv', []))}")
    if len(commands) > 60:
        out.append(f"... and {len(commands) - 60} more")
    out.append("```")
    return "\n".join(out)


def build_context(scope: Scope, triaged: TriageResult, hosts: list[Host],
                  services: list[Service], meta: dict,
                  commands: list[dict] | None = None,
                  degradations: list[Degradation] | None = None,
                  leads: list[Lead] | None = None,
                  template_label: str = "built-in template") -> dict:
    """Everything a report template can name. `docs/REPORT_TEMPLATE.md` lists
    these for whoever edits a template; keep the two in step."""
    commands = commands or []
    degradations = degradations or []
    run_id = str(meta.get("run_id", "n/a"))

    grouped: dict[str, list[Finding]] = {}
    for f in triaged.findings:
        grouped.setdefault(f.severity, []).append(f)
    severities, flat, number = [], [], 0
    for sev in SEV_ORDER:
        rows = []
        for f in grouped.get(sev) or []:
            number += 1
            rows.append(_finding_fields(f, number))
        if rows:
            severities.append({"key": sev, "label": SEV_LABEL[sev], "count": len(rows),
                               "findings": rows})
            flat.extend(rows)

    return {
        "engagement": scope.engagement,
        "client": scope.client or "n/a",
        "generated": _ts(),
        "run_id": run_id,
        "version": meta.get("extscan_version", ""),
        "profile": meta.get("profile", "standard"),
        "authorisation": _authorisation_block(scope),
        "scope": _scope_block(scope),
        "summary": _summary_block(triaged, hosts, degradations),
        "review_queue": _review_queue_block(triaged),
        "security_notes": _security_notes_block(security_notes(triaged, leads), run_id),
        "systemic": _systemic_block(triaged),
        "severities": severities,
        "findings": flat,
        "findings_total": len(flat),
        "inventory": _inventory_block(services),
        "host_detail": _host_detail_block(hosts),
        "coverage_gaps": _coverage_gaps_block(degradations),
        "gap_count": len(degradations),
        "methodology": _methodology_block(meta, template_label),
        "tool_versions": _tool_versions_block(meta),
        "command_log": _command_log_block(commands),
    }


def _sample_context() -> dict:
    """A context with one of everything, for checking a template's names."""
    scope = Scope(engagement="sample", client="sample",
                  authorization=Authorization("REF-1", "someone", "2026-01-01T00:00:00Z",
                                              "2026-01-02T00:00:00Z", "none"),
                  targets=["192.0.2.1"], exclude=["192.0.2.2"])
    finding = Finding(title="Sample", severity="high", host="192.0.2.1", port=443,
                      source="sample", description="d", evidence="e", recommendation="r",
                      references=["https://example.com"], review_required=True,
                      review_reason="why", confidence="tentative", tags=["sample"])
    service = Service(host="192.0.2.1", port=443, proto="tcp", name="https")
    gap = Degradation(stage="probe", component="sample", reason="r", impact="i")
    lead = Lead(kind="openapi", host="192.0.2.1", port=443, reason="sample")
    return build_context(scope, triage([finding], [service]),
                         [Host(ip="192.0.2.1", hostnames=["a.example"])], [service],
                         {"run_id": "sample", "tool_versions": {"nmap": "0"}},
                         [{"argv": ["nmap"], "started": 0, "duration": 0, "returncode": 0}],
                         [gap], [lead])


class Template:
    """A parsed report template, checked before it is used."""

    def __init__(self, text: str, source: str, label: str):
        self.source, self.label = source, label
        self.nodes = tpl.parse(text, source)
        used = {n.split(".")[0] for n in tpl.names(self.nodes)}
        missing = [s for s in REQUIRED_SECTIONS if s not in used]
        if missing:
            raise TemplateError(
                f"{source}: the template leaves out "
                + " and ".join("{{" + m + "}}" for m in missing)
                + ". A report must say what was not checked and what a person still "
                "has to decide. Move or retitle those sections freely, but keep them.")
        tpl.check(self.nodes, _sample_context(), source)

    def render(self, context: dict) -> str:
        return tpl.render(self.nodes, context, self.source)


def load_template(path: str | Path | None = None) -> Template:
    """Load and check a report template. None or "" means the built-in one.

    Raises TemplateError for a missing file, bad syntax, an unknown name or
    a dropped required section, so a broken template stops a run at the
    start and not when the report is written.
    """
    if not path:
        return Template(DEFAULT_TEMPLATE.read_text(encoding="utf-8"),
                        str(DEFAULT_TEMPLATE), "built-in template")
    p = Path(path).expanduser()
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise TemplateError(f"report template {p} cannot be read: "
                            f"{exc.strerror or exc}") from exc
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return Template(text, str(p), f"`{p.name}` (sha256 {digest})")


def render_markdown(scope: Scope, triaged: TriageResult, hosts: list[Host],
                    services: list[Service], meta: dict,
                    commands: list[dict] | None = None,
                    degradations: list[Degradation] | None = None,
                    leads: list[Lead] | None = None,
                    template: Template | None = None) -> str:
    template = template or load_template()
    return template.render(build_context(scope, triaged, hosts, services, meta, commands,
                                         degradations, leads, template.label))


def render_json(scope: Scope, triaged: TriageResult, hosts: list[Host],
                services: list[Service], meta: dict,
                degradations: list[Degradation] | None = None,
                leads: list[Lead] | None = None) -> str:
    return json.dumps({
        "engagement": scope.summary(),
        "run": meta,
        "stats": triaged.stats,
        "review_queue": [r.to_dict() for r in triaged.review_queue],
        "security_notes": security_notes(triaged, leads),
        "systemic": [s.to_dict() for s in triaged.systemic],
        "hosts": [h.to_dict() for h in hosts],
        "services": [s.to_dict() for s in services],
        "findings": [f.to_dict() for f in triaged.findings],
        "coverage_gaps": [d.to_dict() for d in (degradations or [])],
    }, indent=2, default=str)


def write_reports(path: Path, scope: Scope, triaged: TriageResult, hosts: list[Host],
                  services: list[Service], meta: dict,
                  commands: list[dict] | None = None,
                  degradations: list[Degradation] | None = None,
                  leads: list[Lead] | None = None,
                  template: Template | None = None) -> dict[str, Path]:
    md = path / "report.md"
    js = path / "report.json"
    # Rendered before anything is written, so a template error leaves the
    # previous report in place instead of half of a new one.
    markdown = render_markdown(scope, triaged, hosts, services, meta, commands,
                               degradations, leads, template)
    md.write_text(markdown)
    js.write_text(render_json(scope, triaged, hosts, services, meta, degradations, leads))
    return {"markdown": md, "json": js}
