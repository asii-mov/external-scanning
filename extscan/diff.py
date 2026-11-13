"""Compare two runs of the same engagement.

A diff of two scans has a trap in it. Something that was there last time and
is absent now is either fixed, or was not looked at this time, and the two
read the same in the data: no record. Reporting an unscanned host's findings
as resolved is the worst thing this tool could tell a client.

So there are five states, not four:

* new            in the new run only
* changed        in both, and severity, confidence, version, title or
                 evidence differs
* same           in both, nothing differs
* gone           in the old run only, and the new run did look
* not re-checked in the old run only, and the new run did not look: the host
                 left the scope, discovery had a gap for it, the port was
                 outside the scanned list, the check that produces the
                 finding did not complete there, or the stage never ran

Findings are matched on host, protocol, port and `triage.diff_key`, never on
`Finding.id`: the id hashes the title, and titles carry page titles, versions
and counts. Services are matched on host, protocol and port.

Whether the new run "looked" is decided from what it recorded: the scope
summary and port lists in run.json, the stages it completed, its coverage
gaps, each service's `probed_by`, and its leads. When that cannot be decided
(an unknown finding source, an unreadable port list) the answer is "not
re-checked".
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .discovery import HOST_DISCOVERY, OPEN_FILTERED
from .models import Finding, Service, severity_rank
from .resilience import Degradation
from .store import Store
from .triage import diff_key

NEW, CHANGED, SAME, GONE, NOT_RECHECKED = "new", "changed", "same", "gone", "not_rechecked"
OPENED, CLOSED, NOT_RESCANNED = "opened", "closed", "not_rescanned"
FINDING_STATES = (NEW, CHANGED, NOT_RECHECKED, GONE, SAME)
SERVICE_STATES = (OPENED, CLOSED, NOT_RESCANNED, CHANGED, SAME)


@dataclass(frozen=True)
class Check:
    """What has to have happened in a run for a finding source to be produced.

    kind    nmap   an NSE script result: discovery of that protocol
            probe  a per-service check recorded in `Service.probed_by`
            chase  a follow-up on a lead, after the probes in `parents`
            stage  a whole stage, with no per-service record
    name    protocol, probe name, lead kind, or stage name(s)
    """

    kind: str
    name: str = ""
    parents: tuple[str, ...] = ()
    stages: tuple[str, ...] = ()
    gap_stages: tuple[str, ...] = ()
    gap_component: str = ""


_WEB = ("http_fingerprint", "nuclei")

# The one table mapping a finding's `source` to the check behind it. A source
# that is not here (an analyst's note, model commentary, a tool added later)
# is never called gone.
SOURCE_CHECKS: dict[str, Check] = {
    "nuclei": Check("probe", "nuclei"),
    "extscan:http": Check("probe", "http_fingerprint"),
    "extscan:paths": Check("probe", "http_fingerprint"),
    "extscan:edge": Check("probe", "http_fingerprint"),
    "extscan:vhost": Check("probe", "vhosts"),
    "extscan:tls": Check("probe", "tls"),
    "extscan:snmp": Check("probe", "snmp"),
    "extscan:exposure": Check("probe", "exposure"),
    "extscan:ssh": Check("probe", "ssh"),
    "extscan:iis": Check("probe", "iis"),
    "sslscan": Check("probe", "sslscan"),
    "extscan:openapi": Check("chase", "openapi", parents=_WEB),
    "extscan:graphql": Check("chase", "graphql", parents=_WEB),
    "extscan:api": Check("chase", "api_endpoint", parents=_WEB),
    "extscan:secret_file": Check("chase", "secret_file", parents=_WEB),
    "extscan:git": Check("chase", "git_exposure", parents=_WEB),
    "extscan:web_paths": Check("chase", "web_paths", parents=_WEB),
    "extscan:snmp_walk": Check("chase", "snmp_walk", parents=("snmp",)),
    "testssl.sh": Check("chase", "tls_detail", parents=("tls",)),
    "extscan:subdomains": Check("stage", stages=("recon",), gap_stages=("recon",)),
    "extscan:dns": Check("stage", stages=("recon", "discover"),
                         gap_stages=("recon", "discover:dns")),
    "extscan:network": Check("stage", stages=("enrich",), gap_stages=("enrich",),
                             gap_component="ranges:"),
}
SOURCE_PREFIX_CHECKS: list[tuple[str, Check]] = [
    ("nmap-tcp:", Check("nmap", "tcp")),
    ("nmap-udp:", Check("nmap", "udp")),
    ("nuclei:", Check("probe", "nuclei")),
]


def check_for(source: str) -> Check | None:
    if source in SOURCE_CHECKS:
        return SOURCE_CHECKS[source]
    for prefix, check in SOURCE_PREFIX_CHECKS:
        if source.startswith(prefix):
            return check
    return None


# --- a run, as the diff reads it --------------------------------------------

def _port_ranges(spec: object) -> list[tuple[int, int]] | None:
    """Parse an nmap port list. None when it cannot be read."""
    out: list[tuple[int, int]] = []
    for part in str(spec or "").split(","):
        part = re.sub(r"^[TU]:", "", part.strip())
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not m:
            return None
        out.append((int(m.group(1)), int(m.group(2) or m.group(1))))
    return out


def _networks(specs: object) -> list:
    nets = []
    for spec in specs if isinstance(specs, list) else []:
        try:
            nets.append(ipaddress.ip_network(str(spec), strict=False))
        except ValueError:
            continue
    return nets


class RunView:
    """Read-only view of one run directory."""

    def __init__(self, store: Store):
        self.run_id = store.run_id
        self.meta = store.meta()
        self.stages: dict = self.meta.get("stages") or {}
        self.policy: dict = self.meta.get("policy") or {}
        scope = self.meta.get("scope") or {}
        self.targets = _networks(scope.get("targets"))
        self.exclude = _networks(scope.get("exclude"))
        self.findings: list[Finding] = store.findings()
        self.answered = {h.ip for h in store.hosts() if h.state == "up"}
        self.services: dict[tuple, Service] = {
            (s.host, s.proto, s.port): s for s in store.services()}
        self.answered |= {host for host, _, _ in self.services}
        self.gaps: list[Degradation] = store.degradations()
        self.leads = store.leads()

    def nmap(self, key: str, default=None):
        return (self.policy.get("nmap") or {}).get(key, default)

    def in_scope(self, host: str) -> bool:
        """False only for an address the scope summary clearly leaves out."""
        try:
            addr = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return True                 # a name, or no host: decided elsewhere
        if not self.targets:
            return True
        if any(addr in net for net in self.exclude):
            return False
        return any(addr in net for net in self.targets)

    def gaps_for(self, host: str, stage_ok) -> list[Degradation]:
        """Gaps whose stage passes `stage_ok` and that cover `host`. A gap
        that names no hosts covers all of them."""
        return [d for d in self.gaps if stage_ok(d.stage) and _names(d, host)]


def _names(d: Degradation, host: str) -> bool:
    if not d.hosts or not host or host in d.hosts:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    for entry in d.hosts:
        try:
            if "/" in entry and addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


# --- did the run look? ------------------------------------------------------

def discovery_reason(run: RunView, host: str, proto: str) -> str | None:
    """Why `host` was not scanned for `proto` ports in `run`, or None."""
    stage = run.stages.get("discover")
    if stage is None:
        return "discovery did not run"
    if not stage.get(proto):
        return f"{proto.upper()} discovery did not run"
    # The sweep of two-phase discovery is TCP only.
    other = ("discover:udp",) if proto == "tcp" else ("discover:tcp", "discover:sweep")
    for d in run.gaps:
        if not (d.stage == "discover" or d.stage.startswith("discover:")) \
                or d.stage in (*other, "discover:dns"):
            continue
        if d.component == OPEN_FILTERED:
            continue        # about ports that are listed, not about missing ones
        if d.component == HOST_DISCOVERY:
            # The gap carries a count, not addresses. It applies to exactly
            # the hosts this run did not see up: for those, "no open port"
            # means nmap never port-scanned them.
            if host and host not in run.answered:
                return "the host did not answer host discovery, so its ports were not scanned"
            continue
        if _names(d, host):
            return f"discovery gap: {d.reason}"
    return None


def port_reason(run: RunView, proto: str, port: int) -> str | None:
    """Why `port` was outside what `run` scanned, or None when it was in."""
    if proto == "udp" and run.nmap("do_udp", True) is False:
        return "UDP scanning is off in the run's policy"
    spec = run.nmap(f"{proto}_ports")
    ranges = _port_ranges(spec)
    if ranges is None:
        return f"the run's {proto.upper()} port list could not be read"
    if not any(lo <= port <= hi for lo, hi in ranges):
        return f"port {port}/{proto} is not in the run's port list"
    return None


def service_reason(run: RunView, host: str, proto: str, port: int) -> str | None:
    """For a service absent from `run`: why the run cannot say it is closed.
    None means the run scanned that host and port and found nothing open."""
    if not run.in_scope(host):
        return "host is outside the run's scope"
    return discovery_reason(run, host, proto) or port_reason(run, proto, port)


_SERVICE_GAP_RE = re.compile(r"^(\S+/(?:tcp|udp)/\d+): ")


def _probe_gap(run: RunView, name: str, svc: Service) -> str | None:
    for d in run.gaps_for(svc.host, lambda s: s == f"probe:{name}"):
        m = _SERVICE_GAP_RE.match(d.reason)
        if m and m.group(1) != svc.id:
            continue                # a gap for another port on the same host
        return f"{name} gap: {d.reason}"
    return None


def _selection_differs(run: RunView, ref: RunView, section: str, keys: tuple) -> bool:
    a, b = run.policy.get(section) or {}, ref.policy.get(section) or {}
    return any(a.get(k) != b.get(k) for k in keys)


def finding_reason(run: RunView, f: Finding, ref: RunView) -> tuple[str | None, str]:
    """For a finding of `ref` that is absent from `run`: did `run` look?

    Returns (reason, detail). A reason means `run` did not re-check it. With
    no reason, detail says what the run saw instead ("port is closed").
    """
    if f.host and not run.in_scope(f.host):
        return "host is outside the run's scope", ""
    check = check_for(f.source)
    if check is None:
        return (f"nothing maps source `{f.source}` to a check, so its absence "
                "proves nothing"), ""

    if check.kind == "stage":
        for name in check.stages:
            if name in ref.stages and name not in run.stages:
                return f"the {name} stage did not run", ""
            if (run.stages.get(name) or {}).get("disabled"):
                return f"the {name} stage was disabled", ""
        gaps = [d for d in run.gaps_for(f.host, lambda s: s in check.gap_stages)
                if d.component.startswith(check.gap_component)]
        return (f"{gaps[0].stage} gap: {gaps[0].reason}", "") if gaps else (None, "")

    proto = check.name if check.kind == "nmap" else f.proto
    svc = None
    if f.host and f.port:
        svc = run.services.get((f.host, f.proto, f.port))
        if svc is None:
            why = service_reason(run, f.host, f.proto, f.port)
            return (why, "") if why else (None, "the port is no longer open")

    if check.kind == "nmap":
        why = discovery_reason(run, f.host, proto)
        if why:
            return why, ""
        if _selection_differs(run, ref, "nmap", ("scripts", "exclude_scripts")):
            return "the nmap script selection differs between the runs", ""
        return None, "the script reported nothing this time"

    if "probe" not in run.stages:
        return "the probe stage did not run", ""
    if check.kind == "chase":
        if "chase" not in run.stages:
            return "the chase stage did not run", ""
        for lead in run.leads:
            if (lead.kind == check.name and lead.host == f.host and lead.port == f.port
                    and lead.status in ("open", "failed", "abandoned")):
                return f"the {lead.kind} follow-up is {lead.status}, not completed", ""
        gaps = [d for d in run.gaps_for(f.host, lambda s: s == "chase")
                if d.component == f"lead:{check.name}"]
        if gaps:
            return f"chase gap: {gaps[0].reason}", ""

    # The probe itself, or for a follow-up the probes that raise its lead.
    names = (check.name,) if check.kind == "probe" else check.parents
    if svc is not None:
        old_svc = ref.services.get((f.host, f.proto, f.port))
        for name in names:
            # A parent probe only has to have run if it applied last time.
            if check.kind == "chase" and old_svc and name not in old_svc.probed_by:
                continue
            gap = _probe_gap(run, name, svc)
            if gap:
                return gap, ""
            if name not in svc.probed_by:
                return f"{name} did not complete on {svc.id}", ""
    else:
        gaps = [d for name in names
                for d in run.gaps_for(f.host, lambda s, name=name: s == f"probe:{name}")]
        if gaps:
            return f"{gaps[0].stage} gap: {gaps[0].reason}", ""
    if check.name == "nuclei" and _selection_differs(
            run, ref, "nuclei", ("severities", "exclude_tags", "include_tags", "templates")):
        return "the nuclei template selection differs between the runs", ""
    if check.kind == "chase":
        return None, "the follow-up found nothing this time"
    return None, "the check ran and reported nothing"


# --- comparing --------------------------------------------------------------

_VERSION_RE = re.compile(r"\b(?:tls|ssl)?v?\d+(?:\.\d+)+[\w.+~-]*|\b(?:tls|ssl)v\d\b", re.I)
# nmap scripts whose whole output is a clock, a counter or a per-connection
# value. Their evidence differs on every run and says nothing.
_VOLATILE_SCRIPTS = {"clock-skew", "http-date", "ssl-date", "qscan", "ipidseq", "path-mtu",
                     "redis-info", "mysql-info", "uptime"}
_VOLATILE_LINE_RE = re.compile(
    r"^\s*(?:date|expires|last-modified|set-cookie|etag|age|x-request-id|x-amz-\S+|"
    r"cf-ray|x-served-by|x-timer|x-cache\S*|report-to|nel|content-length)\s*:.*$",
    re.I | re.M)
_VOLATILE_TOKENS = [
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\w*,? \d{1,2} \w{3} \d{4}\b"),
    re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|s|sec|seconds)\b"),
    re.compile(r"\b[0-9a-f]{32,}\b", re.I),
]


def _evidence(f: Finding) -> str:
    """Evidence with clocks, request ids and timings masked, for comparing."""
    if f.source.rsplit(":", 1)[-1] in _VOLATILE_SCRIPTS:
        return ""
    text = _VOLATILE_LINE_RE.sub("", f.evidence or "")
    for pattern in _VOLATILE_TOKENS:
        text = pattern.sub("<t>", text)
    return " ".join(text.split())


def finding_changes(old: Finding, new: Finding) -> dict[str, list]:
    changes: dict[str, list] = {}
    for name in ("severity", "confidence", "kev"):
        if getattr(old, name) != getattr(new, name):
            changes[name] = [getattr(old, name), getattr(new, name)]
    if old.title != new.title:
        only_version = _VERSION_RE.sub("<v>", old.title) == _VERSION_RE.sub("<v>", new.title)
        changes["version" if only_version else "title"] = [old.title, new.title]
    if _evidence(old) != _evidence(new):
        changes["evidence"] = ["differs", "differs"]
    return changes


def service_changes(old: Service, new: Service) -> dict[str, list]:
    return {name: [getattr(old, name), getattr(new, name)]
            for name in ("state", "name", "product", "version", "tunnel")
            if getattr(old, name) != getattr(new, name)}


def finding_key(f: Finding) -> tuple:
    return (f.host, f.proto, f.port, diff_key(f))


def _entry(f: Finding, **extra) -> dict:
    return {"host": f.host, "port": f.port, "proto": f.proto, "source": f.source,
            "severity": f.severity, "confidence": f.confidence, "title": f.title,
            "id": f.id, "kev": f.kev, "key": diff_key(f), **extra}


def _pair(olds: list[Finding], news: list[Finding]):
    """Pair findings that share a key. The same wording pairs first, so one
    of two look-alikes changing does not shuffle both."""
    olds, news = sorted(olds, key=lambda f: (f.source, f.title)), \
        sorted(news, key=lambda f: (f.source, f.title))
    pairs = []
    for o in list(olds):
        match = next((n for n in news if (n.source, n.title) == (o.source, o.title)), None)
        if match:
            pairs.append((o, match))
            olds.remove(o)
            news.remove(match)
    while olds and news:
        pairs.append((olds.pop(0), news.pop(0)))
    return pairs, olds, news


def _order(entries: list[dict]) -> list[dict]:
    return sorted(entries, key=lambda e: (
        -severity_rank(e["severity"]), not e.get("kev"), e["host"], e["port"] or 0,
        e["title"]))


def diff_findings(old: RunView, new: RunView) -> dict[str, list[dict]]:
    by_key: dict[tuple, tuple[list, list]] = {}
    for f in old.findings:
        by_key.setdefault(finding_key(f), ([], []))[0].append(f)
    for f in new.findings:
        by_key.setdefault(finding_key(f), ([], []))[1].append(f)

    out: dict[str, list[dict]] = {state: [] for state in FINDING_STATES}
    for olds, news in by_key.values():
        pairs, only_old, only_new = _pair(olds, news)
        for o, n in pairs:
            changes = finding_changes(o, n)
            if changes:
                out[CHANGED].append(_entry(n, old_id=o.id, changes=changes))
            else:
                out[SAME].append(_entry(n, old_id=o.id))
        for o in only_old:
            reason, detail = finding_reason(new, o, old)
            if reason:
                out[NOT_RECHECKED].append(_entry(o, reason=reason))
            else:
                out[GONE].append(_entry(o, detail=detail))
        for n in only_new:
            # New to us is not the same as newly exposed: say so when the
            # old run could not have seen it.
            reason, _ = finding_reason(old, n, new)
            out[NEW].append(_entry(n, **({"note": f"the old run did not check this: {reason}"}
                                         if reason else {})))
    out = {state: _order(rows) for state, rows in out.items()}
    # Changes a person must read first: anything but evidence-only.
    out[CHANGED].sort(key=lambda e: set(e["changes"]) == {"evidence"})
    return out


def _svc_entry(s: Service, **extra) -> dict:
    return {"host": s.host, "port": s.port, "proto": s.proto, "name": s.name,
            "product": " ".join(x for x in (s.product, s.version) if x), **extra}


def diff_services(old: RunView, new: RunView) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {state: [] for state in SERVICE_STATES}
    for key in sorted(set(old.services) | set(new.services),
                      key=lambda k: (k[0], k[1], k[2])):
        o, n = old.services.get(key), new.services.get(key)
        if o and n:
            changes = service_changes(o, n)
            out[CHANGED if changes else SAME].append(
                _svc_entry(n, **({"changes": changes} if changes else {})))
        elif o:
            reason = service_reason(new, *key)
            if reason:
                out[NOT_RESCANNED].append(_svc_entry(o, reason=reason))
            else:
                out[CLOSED].append(_svc_entry(o))
        else:
            reason = service_reason(old, *key)
            out[OPENED].append(_svc_entry(n, **(
                {"note": f"the old run did not scan this: {reason}"} if reason else {})))
    return out


def diff_runs(old_store: Store, new_store: Store) -> dict:
    """The full comparison, as plain data."""
    old, new = RunView(old_store), RunView(new_store)
    findings = diff_findings(old, new)
    services = diff_services(old, new)
    reasons: dict[str, int] = {}
    for row in findings[NOT_RECHECKED]:
        reasons[row["reason"]] = reasons.get(row["reason"], 0) + 1
    return {
        "old": {"run_id": old.run_id, "created": old.meta.get("created"),
                "stages": sorted(old.stages)},
        "new": {"run_id": new.run_id, "created": new.meta.get("created"),
                "stages": sorted(new.stages), "coverage_gaps": len(new.gaps)},
        "counts": {
            "findings": {state: len(findings[state]) for state in FINDING_STATES},
            "services": {state: len(services[state]) for state in SERVICE_STATES},
        },
        "not_rechecked_reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
        "findings": findings,
        "services": services,
    }


# --- rendering --------------------------------------------------------------

def _md(text: object, limit: int = 300) -> str:
    """Target-chosen text made safe for a Markdown line."""
    flat = " ".join(str(text if text is not None else "").split())[:limit]
    return re.sub(r"([\\`*_\[\]<>|#])", r"\\\1", flat)


def _where(e: dict) -> str:
    if not e["host"]:
        return "(no host)"
    return f"{e['host']}:{e['port']}/{e['proto']}" if e["port"] else e["host"]


def _finding_line(e: dict) -> str:
    kev = " KEV" if e.get("kev") else ""
    return f"- **{e['severity'].upper()}{kev}** `{_where(e)}` {_md(e['title'])} (`{e['source']}`)"


def _change_text(changes: dict) -> str:
    parts = []
    for name, (before, after) in changes.items():
        if name == "evidence":
            parts.append("evidence differs")
        elif name == "kev":
            parts.append("now on the CISA KEV list" if after else "no longer on the KEV list")
        else:
            parts.append(f"{name}: {_md(before, 120)} → {_md(after, 120)}")
    return "; ".join(parts)


def render_markdown(result: dict) -> str:
    fc, sc = result["counts"]["findings"], result["counts"]["services"]
    f, s = result["findings"], result["services"]
    out: list[str] = []
    w = out.append
    w(f"# Changes from `{result['old']['run_id']}` to `{result['new']['run_id']}`")
    w("")
    w("| Findings | Count |")
    w("|---|---|")
    w(f"| New | {fc[NEW]} |")
    w(f"| Changed | {fc[CHANGED]} |")
    w(f"| Not re-checked | {fc[NOT_RECHECKED]} |")
    w(f"| Gone | {fc[GONE]} |")
    w(f"| Same | {fc[SAME]} |")
    w("")
    w(f"Services: {sc[OPENED]} opened, {sc[CLOSED]} closed, "
      f"{sc[NOT_RESCANNED]} not re-scanned, {sc[CHANGED]} changed, {sc[SAME]} the same.")
    w("")
    if fc[NOT_RECHECKED] or sc[NOT_RESCANNED]:
        w(f"**{fc[NOT_RECHECKED]} finding(s) and {sc[NOT_RESCANNED]} service(s) from the "
          "old run were not looked at again.** They are not resolved. The new run did "
          "not cover them, for the reasons given below.")
        w("")

    w(f"## New findings ({fc[NEW]})")
    w("")
    for e in f[NEW]:
        w(_finding_line(e))
        if e.get("note"):
            w(f"  - {_md(e['note'])}")
    if not f[NEW]:
        w("_None._")
    w("")

    w(f"## Changed findings ({fc[CHANGED]})")
    w("")
    for e in f[CHANGED]:
        w(_finding_line(e))
        w(f"  - {_change_text(e['changes'])}")
    if not f[CHANGED]:
        w("_None._")
    w("")

    w(f"## Not re-checked ({fc[NOT_RECHECKED]})")
    w("")
    if f[NOT_RECHECKED]:
        w("Present in the old run, absent from the new one, and the new run did not "
          "look. Treat each as still open.")
        w("")
        for reason, count in result["not_rechecked_reasons"].items():
            w(f"- {count} finding(s): {_md(reason)}")
        w("")
        for e in f[NOT_RECHECKED]:
            w(_finding_line(e))
            w(f"  - not re-checked: {_md(e['reason'])}")
    else:
        w("_None._")
    w("")

    w(f"## Gone ({fc[GONE]})")
    w("")
    if f[GONE]:
        w("Present in the old run, absent from the new one, and the new run did look.")
        w("")
    for e in f[GONE]:
        w(_finding_line(e))
        if e.get("detail"):
            w(f"  - {_md(e['detail'])}")
    if not f[GONE]:
        w("_None._")
    w("")

    w("## Services")
    w("")
    for state, label in ((OPENED, "Opened"), (CLOSED, "Closed"),
                         (NOT_RESCANNED, "Not re-scanned"), (CHANGED, "Changed")):
        w(f"### {label} ({sc[state]})")
        w("")
        for e in s[state]:
            line = (f"- `{e['host']}:{e['port']}/{e['proto']}` {_md(e['name']) or '?'} "
                    f"{_md(e['product'])}").rstrip()
            w(line)
            for key in ("reason", "note"):
                if e.get(key):
                    w(f"  - {_md(e[key])}")
            if e.get("changes"):
                w(f"  - {_change_text(e['changes'])}")
        if not s[state]:
            w("_None._")
        w("")
    return "\n".join(out)


render_text = render_markdown


def write_diff(run_dir: Path, result: dict) -> dict[str, Path]:
    md, js = Path(run_dir) / "diff.md", Path(run_dir) / "diff.json"
    md.write_text(render_markdown(result))
    js.write_text(json.dumps(result, indent=2, default=str))
    return {"markdown": md, "json": js}
