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

import json
import time
from pathlib import Path

from .models import Finding, Host, Service
from .resilience import Degradation
from .scope import Scope
from .triage import TriageResult

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


def render_markdown(scope: Scope, triaged: TriageResult, hosts: list[Host],
                    services: list[Service], meta: dict,
                    commands: list[dict] | None = None,
                    degradations: list[Degradation] | None = None) -> str:
    stats = triaged.stats
    by_sev = stats["findings_by_severity"]
    commands = commands or []
    degradations = degradations or []
    out: list[str] = []
    w = out.append

    # -- header ----------------------------------------------------------
    w(f"# External attack surface assessment: {scope.engagement}")
    w("")
    w(f"**Client:** {scope.client or 'n/a'}  ")
    w(f"**Report generated:** {_ts()}  ")
    w(f"**Run id:** `{meta.get('run_id', 'n/a')}`  ")
    w(f"**Tooling:** extscan {meta.get('extscan_version', '')}, profile "
      f"`{meta.get('profile', 'standard')}`")
    w("")
    w("## Authorisation")
    w("")
    a = scope.authorization
    w(f"- **Reference:** {a.reference}")
    w(f"- **Authorised by:** {a.authorized_by}")
    if a.window_start or a.window_end:
        w(f"- **Testing window:** {a.window_start or 'open'} to {a.window_end or 'open'}")
    if a.notes:
        w(f"- **Constraints:** {a.notes}")
    w("")
    w("### Scope")
    w("")
    for t in scope.targets:
        w(f"- `{t}`")
    if scope.exclude:
        w("")
        w("Excluded by agreement:")
        for t in scope.exclude:
            w(f"- `{t}`")
    w("")

    # -- summary ---------------------------------------------------------
    w("## Summary")
    w("")
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
    w("")
    if degradations:
        serious = sum(1 for d in degradations if d.severity == "serious")
        w(f"> ⚠️ **This assessment has {len(degradations)} coverage gap(s)"
          f"{f', {serious} serious' if serious else ''}.** Parts of the intended "
          "testing did not complete, so some absences in this report reflect "
          "checks that did not run rather than exposure that is not there. "
          "See [Coverage gaps](#coverage-gaps) before drawing conclusions.")
        w("")

    # -- review queue ----------------------------------------------------
    w("## Manual review queue")
    w("")
    if not triaged.review_queue:
        w("_Nothing flagged for manual review._")
        w("")
    else:
        w("Automated checks establish that something is exposed; they cannot decide "
          "whether it is acceptable for this client. Each item below names the "
          "specific question an auditor needs to answer. Work top to bottom.")
        w("")
        w("| # | Severity | Item | Target | An auditor must decide |")
        w("|---|---|---|---|---|")
        for item in triaged.review_queue:
            label = _esc(item.title)
            if item.instances:
                label += f" _(+{len(item.instances) - 1} related, listed below)_"
            w(f"| {item.priority} | {SEV_LABEL.get(item.severity, item.severity)} "
              f"| {label} | `{_esc(item.target)}` | {_esc(item.question)} |")
        w("")
        grouped_items = [i for i in triaged.review_queue if i.instances]
        if grouped_items:
            w("Where one queue entry covers several instances:")
            w("")
            for item in grouped_items:
                w(f"- **#{item.priority}** ({len(item.instances)} instances):")
                for inst in item.instances[:15]:
                    w(f"  - {inst}")
                if len(item.instances) > 15:
                    w(f"  - _... and {len(item.instances) - 15} more_")
            w("")

    # -- systemic --------------------------------------------------------
    if triaged.systemic:
        w("## Systemic issues")
        w("")
        w("Each of these appears on three or more hosts, so it is one configuration "
          "or process fix rather than a list of individual repairs.")
        w("")
        w("| Severity | Issue | Affected hosts |")
        w("|---|---|---|")
        for s in triaged.systemic:
            shown = ", ".join(f"`{h}`" for h in s.hosts[:8])
            if len(s.hosts) > 8:
                shown += f" (+{len(s.hosts) - 8} more)"
            w(f"| {SEV_LABEL.get(s.severity, s.severity)} | {_esc(s.title)} "
              f"| {len(s.hosts)}: {shown} |")
        w("")

    # -- findings --------------------------------------------------------
    w("## Findings")
    w("")
    grouped: dict[str, list[Finding]] = {}
    for f in triaged.findings:
        grouped.setdefault(f.severity, []).append(f)

    counter = 0
    for sev in SEV_ORDER:
        group = grouped.get(sev) or []
        if not group:
            continue
        w(f"### {SEV_LABEL[sev]} ({len(group)})")
        w("")
        for f in group:
            counter += 1
            target = f"{f.host}:{f.port}/{f.proto}" if f.port else (f.host or "n/a")
            w(f"#### {counter}. {f.title}")
            w("")
            w(f"- **Severity:** {SEV_LABEL.get(f.severity, f.severity)}"
              + ("  (tentative -- needs confirmation)" if f.confidence == "tentative" else ""))
            w(f"- **Affected:** `{target}`")
            w(f"- **Detected by:** `{f.source}`")
            w(f"- **Finding id:** `{f.id}`")
            if f.tags:
                w("- **Tags:** " + ", ".join(f"`{t}`" for t in f.tags))
            w("")
            if f.description:
                w(f.description)
                w("")
            if f.review_required:
                w(f"> **Requires manual review.** {f.review_reason}")
                w("")
            if f.evidence:
                w("**Evidence**")
                w("")
                w(_fence(f.evidence))
                w("")
            if f.recommendation:
                w("**Recommendation**")
                w("")
                w(f.recommendation)
                w("")
            if f.references:
                w("**References**")
                w("")
                for r in f.references:
                    w(f"- {r}")
                w("")

    # -- inventory -------------------------------------------------------
    w("## Service inventory")
    w("")
    if not services:
        w("_No open services recorded._")
        w("")
    else:
        w("| Host | Port | Proto | Service | Product / version | Probes run |")
        w("|---|---|---|---|---|---|")
        for s in services:
            product = " ".join(x for x in (s.product, s.version, s.extrainfo) if x)
            w(f"| `{s.host}` | {s.port} | {s.proto} | {_esc(s.name) or '?'} "
              f"| {_esc(product) or '-'} | {', '.join(s.probed_by) or '-'} |")
        w("")

    hostnames = [h for h in hosts if h.hostnames or h.os_guess]
    if hostnames:
        w("### Host detail")
        w("")
        w("| Host | Hostnames | OS guess |")
        w("|---|---|---|")
        for h in hostnames:
            w(f"| `{h.ip}` | {_esc(', '.join(h.hostnames)) or '-'} "
              f"| {_esc(h.os_guess or '-')} |")
        w("")

    # -- coverage gaps ---------------------------------------------------
    #
    # Deliberately placed before the inventory rather than in an appendix. A
    # reader who skims the findings and stops must still see what was not
    # checked, otherwise this report overstates its own coverage.
    if degradations:
        serious = [d for d in degradations if d.severity == "serious"]
        w("## Coverage gaps")
        w("")
        w(f"{len(degradations)} part(s) of this assessment did not complete as "
          f"intended{f', {len(serious)} of them materially' if serious else ''}. "
          "**Absence of findings in the areas below is not evidence that nothing "
          "is exposed there** -- the check did not run, or ran partially.")
        w("")
        w("| Severity | Stage | What was lost | Remedy |")
        w("|---|---|---|---|")
        for d in sorted(degradations, key=lambda x: x.severity != "serious"):
            label = "Serious" if d.severity == "serious" else "Warning"
            hosts = f" ({len(d.hosts)} host(s))" if d.hosts else ""
            w(f"| {label} | `{_esc(d.stage)}` | {_esc(d.impact)}{hosts} "
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
        w("")

    # -- methodology -----------------------------------------------------
    w("## Methodology and limitations")
    w("")
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

    if meta.get("tool_versions"):
        w("### Tool versions")
        w("")
        for tool, version in meta["tool_versions"].items():
            w(f"- `{tool}`: {version}")
        w("")

    if commands:
        w("### Command log")
        w("")
        w(f"{len(commands)} command(s) were executed. Full argv, exit codes and "
          "timings are in `commands.jsonl` in the run directory.")
        w("")
        w("```text")
        for c in commands[:60]:
            rc = c.get("returncode")
            rc_text = "dry-run" if rc is None and "dry-run" in (c.get("error") or "") else rc
            w(f"[{_ts(c.get('started'))}] rc={rc_text} "
              f"{c.get('duration', 0):.1f}s  {' '.join(c.get('argv', []))}")
        if len(commands) > 60:
            w(f"... and {len(commands) - 60} more")
        w("```")
        w("")

    return "\n".join(out) + "\n"


def render_json(scope: Scope, triaged: TriageResult, hosts: list[Host],
                services: list[Service], meta: dict,
                degradations: list[Degradation] | None = None) -> str:
    return json.dumps({
        "engagement": scope.summary(),
        "run": meta,
        "stats": triaged.stats,
        "review_queue": [r.to_dict() for r in triaged.review_queue],
        "systemic": [s.to_dict() for s in triaged.systemic],
        "hosts": [h.to_dict() for h in hosts],
        "services": [s.to_dict() for s in services],
        "findings": [f.to_dict() for f in triaged.findings],
        "coverage_gaps": [d.to_dict() for d in (degradations or [])],
    }, indent=2, default=str)


def write_reports(path: Path, scope: Scope, triaged: TriageResult, hosts: list[Host],
                  services: list[Service], meta: dict,
                  commands: list[dict] | None = None,
                  degradations: list[Degradation] | None = None) -> dict[str, Path]:
    md = path / "report.md"
    js = path / "report.json"
    md.write_text(render_markdown(scope, triaged, hosts, services, meta, commands,
                                  degradations))
    js.write_text(render_json(scope, triaged, hosts, services, meta, degradations))
    return {"markdown": md, "json": js}
