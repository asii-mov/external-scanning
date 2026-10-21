"""Triage: turn a pile of findings into something an auditor can work through.

Three jobs:

* order by what matters, not by the order tools happened to emit;
* collapse the same issue repeated across many hosts into one systemic item,
  because "TLS 1.0 enabled" on forty hosts is one remediation task, not forty
  findings, and a report that pretends otherwise gets skimmed;
* build the manual-review queue -- the list of things automation found but
  cannot judge, each with the specific question a person needs to answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Finding, Service, severity_rank

# Findings carrying these tags go to the top of the review queue: they are the
# cases where a human's judgement changes the severity most.
HIGH_VALUE_REVIEW_TAGS = [
    "secrets", "api", "openapi", "git", "default-credentials", "exposure",
    "authentication", "graphql", "source-disclosure",
]

SYSTEMIC_THRESHOLD = 3          # same issue on this many hosts -> systemic


@dataclass
class ReviewItem:
    """One entry in the manual-review queue."""

    priority: int                      # 1 = look at this first
    title: str
    target: str
    severity: str
    question: str                      # what the human must decide
    finding_ids: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    evidence_hint: str = ""
    # When normalisation collapses several findings into one item (the same
    # issue on many hosts, or several URLs on one host), these are the distinct
    # things it covers. Without them the auditor is told "an API endpoint is
    # open" and has to go digging for which ones.
    instances: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "priority": self.priority, "title": self.title, "target": self.target,
            "severity": self.severity, "question": self.question,
            "finding_ids": self.finding_ids, "hosts": self.hosts,
            "evidence_hint": self.evidence_hint, "instances": self.instances,
        }


@dataclass
class SystemicIssue:
    title: str
    severity: str
    hosts: list[str]
    finding_ids: list[str]

    def to_dict(self) -> dict:
        return {"title": self.title, "severity": self.severity,
                "hosts": self.hosts, "finding_ids": self.finding_ids}


@dataclass
class TriageResult:
    findings: list[Finding]
    review_queue: list[ReviewItem]
    systemic: list[SystemicIssue]
    stats: dict

    def to_dict(self) -> dict:
        return {
            "stats": self.stats,
            "review_queue": [r.to_dict() for r in self.review_queue],
            "systemic": [s.to_dict() for s in self.systemic],
        }


# Strip host/port/URL detail so the same issue on different hosts collapses.
_NORMALISE = [
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<host>"),
    (re.compile(r"\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I), "<host6>"),
    (re.compile(r":\d{1,5}\b"), ":<port>"),
    (re.compile(r"https?://\S+"), "<url>"),
]


def issue_key(f: Finding) -> str:
    text = f.title
    for pattern, repl in _NORMALISE:
        text = pattern.sub(repl, text)
    return f"{f.source}|{text.strip().lower()}"


def _sort_key(f: Finding):
    # Severity first, then review-flagged items, then host/port for stability.
    try:
        octets = tuple(int(x) for x in f.host.split("."))
    except (ValueError, AttributeError):
        octets = (0,)
    return (-severity_rank(f.severity), not f.review_required, octets, f.port or 0, f.title)


def _review_question(f: Finding) -> str:
    if f.review_reason:
        return f.review_reason
    return ("Confirm the finding and decide whether the exposure is intended for "
            "this client.")


def _priority(f: Finding, systemic_hosts: int) -> int:
    """Lower is more urgent. Severity dominates; tags and spread break ties."""
    base = (4 - severity_rank(f.severity)) * 100          # critical=0 .. info=400
    if any(t in HIGH_VALUE_REVIEW_TAGS for t in f.tags):
        base -= 30
    if f.confidence == "tentative":
        base += 10                                        # needs confirming, slightly lower
    base -= min(systemic_hosts, 10)                       # breadth nudges it up
    return base


def triage(findings: list[Finding], services: list[Service] | None = None) -> TriageResult:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(issue_key(f), []).append(f)

    systemic: list[SystemicIssue] = []
    for key, group in groups.items():
        hosts = sorted({f.host for f in group if f.host})
        if len(hosts) >= SYSTEMIC_THRESHOLD:
            worst = max(group, key=lambda f: severity_rank(f.severity))
            systemic.append(SystemicIssue(
                title=worst.title, severity=worst.severity, hosts=hosts,
                finding_ids=[f.id for f in group],
            ))
    systemic.sort(key=lambda s: (-severity_rank(s.severity), -len(s.hosts)))

    # Review queue, one entry per distinct issue rather than per host.
    queue: list[ReviewItem] = []
    for key, group in groups.items():
        flagged = [f for f in group if f.review_required]
        if not flagged:
            continue
        worst = max(flagged, key=lambda f: severity_rank(f.severity))
        hosts = sorted({f.host for f in flagged if f.host})
        if len(hosts) > 1:
            target = f"{len(hosts)} hosts: " + ", ".join(hosts[:5]) + \
                     (f" (+{len(hosts) - 5} more)" if len(hosts) > 5 else "")
        else:
            port = worst.port
            target = f"{worst.host}:{port}/{worst.proto}" if port else (worst.host or "n/a")

        # Keep each collapsed finding's own title where they differ, so a group
        # of several URLs or hosts stays actionable.
        titles = sorted({f.title for f in flagged})
        instances = titles if len(titles) > 1 else []

        # Use the group's highest severity for the headline, which may come
        # from a finding other than the one whose title we show.
        queue.append(ReviewItem(
            priority=_priority(worst, len(hosts)),
            title=worst.title, target=target, severity=worst.severity,
            question=_review_question(worst),
            finding_ids=[f.id for f in flagged], hosts=hosts,
            evidence_hint=worst.evidence.splitlines()[0][:200] if worst.evidence else "",
            instances=instances,
        ))

    queue.sort(key=lambda r: (r.priority, -severity_rank(r.severity), r.title))
    for i, item in enumerate(queue, start=1):
        item.priority = i          # renumber to a clean 1..n work order

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    services = services or []
    stats = {
        "findings_total": len(findings),
        "findings_by_severity": by_sev,
        "distinct_issues": len(groups),
        "review_items": len(queue),
        "systemic_issues": len(systemic),
        "hosts_with_findings": len({f.host for f in findings if f.host}),
        "services_total": len(services),
        "services_tcp": sum(1 for s in services if s.proto == "tcp"),
        "services_udp": sum(1 for s in services if s.proto == "udp"),
        "web_services": sum(1 for s in services if s.is_http),
    }

    return TriageResult(
        findings=sorted(findings, key=_sort_key),
        review_queue=queue, systemic=systemic, stats=stats,
    )
