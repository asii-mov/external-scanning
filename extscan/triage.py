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

HIGH_VALUE_REVIEW_TAGS = [
    "secrets", "api", "openapi", "git", "default-credentials", "exposure",
    "authentication", "graphql", "source-disclosure",
]

SYSTEMIC_THRESHOLD = 3


@dataclass
class ReviewItem:
    """One entry in the manual-review queue."""

    priority: int
    title: str
    target: str
    severity: str
    question: str
    finding_ids: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    evidence_hint: str = ""
    instances: list[str] = field(default_factory=list)
    kev: bool = False
    epss: float | None = None
    cves: list[str] = field(default_factory=list)
    version_match: bool = False     # the CVEs are version-string candidates

    def to_dict(self) -> dict:
        return {
            "priority": self.priority, "title": self.title, "target": self.target,
            "severity": self.severity, "question": self.question,
            "finding_ids": self.finding_ids, "hosts": self.hosts,
            "evidence_hint": self.evidence_hint, "instances": self.instances,
            "kev": self.kev, "epss": self.epss, "cves": self.cves,
            "version_match": self.version_match,
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


_URL_RE = re.compile(r"https?://[^\s/]+(/[^\s?#]*)?\S*")
_DIFF_NORMALISE = [
    (re.compile(r"\b(?:tls|ssl)v?\d(?:\.\d)?\b", re.I), "<tls>"),
    (re.compile(r"\bv?\d+(?:\.\d+)+[\w.+~-]*"), "<ver>"),
    (re.compile(r"(?<![\w/.-])\d+(?![\w/.-])"), "<n>"),
]
# Titles that end in text the target chose (a page title, an API's name).
_DIFF_TITLE_STEMS = {
    "extscan:http": re.compile(r"^(HTTP service): .* (on \S+)$"),
    "extscan:openapi": re.compile(r"^(Exposed API specification): .*()$"),
}


def diff_key(f: Finding) -> str:
    """`issue_key` for matching one finding across two runs of the same scope.

    `issue_key` groups the same issue across hosts within a run, and stays as
    it is. Between runs a title also moves for reasons that are not a new
    issue: a page title is edited, a version is patched, a count goes from 5
    to 6, nmap is run as `nmap-udp` instead of `nmap-tcp`. Those parts are
    masked here. A URL keeps its path, because two endpoints on one port are
    two findings.
    """
    text = f.title
    stem = _DIFF_TITLE_STEMS.get(f.source)
    if stem:
        text = stem.sub(lambda m: " ".join(g for g in m.groups() if g), text)
    paths: list[str] = []

    def keep_path(m: re.Match) -> str:
        paths.append(m.group(1) or "/")
        return f"<url{len(paths) - 1}>"

    text = _URL_RE.sub(keep_path, text)
    for pattern, repl in (*_NORMALISE[:3], *_DIFF_NORMALISE):
        text = pattern.sub(repl, text)
    for i, path in enumerate(paths):
        text = text.replace(f"<url{i}>", f"<url>{path}")
    source = re.sub(r"^nmap-(?:tcp|udp):", "nmap:", f.source)
    return f"{source}|{' '.join(text.split()).lower()}"


def _sort_key(f: Finding):
    try:
        octets = tuple(int(x) for x in f.host.split("."))
    except (ValueError, AttributeError):
        octets = (0,)
    # Severity first, as before. Within a severity: known-exploited, then by
    # EPSS, then the items a person has to judge.
    return (-severity_rank(f.severity), not f.kev, -(f.epss or 0.0),
            not f.review_required, octets, f.port or 0, f.title)


def _review_question(f: Finding) -> str:
    if f.review_reason:
        return f.review_reason
    return ("Confirm the finding and decide whether the exposure is intended for "
            "this client.")


def _priority(f: Finding, systemic_hosts: int) -> int:
    """Lower is more urgent. Severity dominates; tags and spread break ties."""
    base = (4 - severity_rank(f.severity)) * 100
    if any(t in HIGH_VALUE_REVIEW_TAGS for t in f.tags):
        base -= 30
    if f.confidence == "tentative":
        base += 10
    base -= min(systemic_hosts, 10)
    return base


def _queue_band(severity: str, kev: bool, tentative: bool) -> int:
    """Where a review item sits before anything else is compared. Lower first.

    The rule, exactly:

    * every severity has a band two steps wide: critical 0, high 2, medium 4,
      low 6, info 8;
    * a KEV-listed item moves up three steps. That puts it above every
      non-KEV item of its own severity and of the severity one level up, and
      below non-KEV items two levels up: a KEV medium (1) comes before a
      non-KEV high (2) and after a non-KEV critical (0);
    * a KEV-listed item whose CVEs are only version-string candidates
      (confidence "tentative", e.g. nmap vulners) moves up one step: first
      within its own severity, never above the level up. A version match is
      a lead, and should not displace a confirmed critical.

    Inside a band the order is: higher severity, then higher EPSS, then the
    older tie-breaks in `_priority`. Severity itself is never changed.
    """
    lift = 0 if not kev else (1 if tentative else 3)
    return 2 * (4 - severity_rank(severity)) - lift


def triage(findings: list[Finding], services: list[Service] | None = None) -> TriageResult:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(issue_key(f), []).append(f)

    systemic: list[SystemicIssue] = []
    for group in groups.values():
        hosts = sorted({f.host for f in group if f.host})
        if len(hosts) >= SYSTEMIC_THRESHOLD:
            worst = max(group, key=lambda f: severity_rank(f.severity))
            systemic.append(SystemicIssue(
                title=worst.title, severity=worst.severity, hosts=hosts,
                finding_ids=[f.id for f in group],
            ))
    systemic.sort(key=lambda s: (-severity_rank(s.severity), -len(s.hosts)))

    queue: list[ReviewItem] = []
    order: dict[int, tuple] = {}
    for group in groups.values():
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

        titles = sorted({f.title for f in flagged})
        instances = titles if len(titles) > 1 else []

        listed = [f for f in flagged if f.kev]
        # The item is as exploited as its most certain KEV-listed member.
        kev_tentative = bool(listed) and all(f.confidence == "tentative" for f in listed)
        scores = [f.epss for f in flagged if f.epss is not None]
        item = ReviewItem(
            priority=_priority(worst, len(hosts)),
            title=worst.title, target=target, severity=worst.severity,
            question=_review_question(worst),
            finding_ids=[f.id for f in flagged], hosts=hosts,
            evidence_hint=worst.evidence.splitlines()[0][:200] if worst.evidence else "",
            instances=instances,
            kev=bool(listed), epss=max(scores) if scores else None,
            cves=sorted({c for f in flagged for c in f.cves}),
            version_match=any(f.cves and "version-match" in f.tags for f in flagged),
        )
        order[id(item)] = (_queue_band(item.severity, item.kev, kev_tentative),
                           -severity_rank(item.severity), -(item.epss or 0.0),
                           item.priority, item.title)
        queue.append(item)

    queue.sort(key=lambda r: order[id(r)])
    for i, item in enumerate(queue, start=1):
        item.priority = i

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
