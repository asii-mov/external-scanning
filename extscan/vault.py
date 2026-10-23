"""The report as an Obsidian vault: a pentest narrative plus linked notes.

`report.md` is the flat deliverable. The vault is how a tester tells the
story: what was in scope, what discovery found, what each service turned out
to be (with screenshots), what proved it, what the follow-ups found, and what
was never checked. It opens as an Obsidian vault as-is:

    runs/<run-id>/report/
        00 Summary.md            the narrative, and the entry point
        Manual review queue.md   decisions an auditor owes before issue
        Coverage gaps.md         what did not get checked
        Methodology.md           stages, tools, the full command log
        hosts/<ip>.md            services, screenshots, findings per host
        findings/<id>.md         evidence, proof, reproduction, remediation
        attachments/*.png        screenshots

Every note has YAML frontmatter, so Dataview can query severity, host, port.

Most of the text here is scanner output, which the target controls: page
titles, banners, response bodies. Outside code fences and code spans it is
escaped, so a page titled `![[...]]` or `<img src=...>` renders as text and
cannot embed notes or make Obsidian fetch a URL when the vault is opened.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import time
from collections import Counter
from pathlib import Path

from .models import Finding, Host, Lead, Service, severity_rank
from .report import SEV_LABEL, SEV_ORDER, _fence, _ts
from .resilience import Degradation
from .scope import Scope
from .screenshots import Shot, finding_url
from .triage import TriageResult, issue_key

VAULT_DIR = "report"
SUMMARY = "00 Summary"
REVIEW = "Manual review queue"
GAPS = "Coverage gaps"
METHOD = "Methodology"
MANIFEST = ".extscan-generated.json"

# Findings raised by following up a lead rather than by the first pass.
CHASE_SOURCES = {"extscan:api", "extscan:git", "extscan:graphql", "extscan:openapi",
                 "extscan:secret_file", "extscan:snmp_walk", "extscan:web_paths"}
REMOTE_NAMES = {"ssh", "telnet", "ms-wbt-server", "rdp", "vnc", "ftp", "ftps", "winrm",
                "wsman", "x11", "rlogin", "rsh"}

FAMILIES = [
    ("web", "Web applications",
     "{n} service(s) are web applications. We loaded each one in a headless browser "
     "to see what it actually serves, then ran nuclei and extscan's own web checks "
     "against it: disclosure paths, response headers, and TLS where it was offered."),
    ("exposed", "Datastores and management interfaces",
     "{n} service(s) are datastores or management APIs, the kind of thing that "
     "normally sits behind a firewall. Being reachable from outside is the finding in "
     "itself. The evidence below shows what each one gave away."),
    ("remote", "Remote access",
     "{n} service(s) offer remote administration. We recorded what each one "
     "identifies as. No logins were attempted."),
    ("udp", "UDP services",
     "{n} UDP service(s) answered. For SNMP we tried a short list of well-known "
     "community strings, read-only, which is how most SNMP exposure is found."),
    ("other", "Other services",
     "{n} further service(s) did not fit the groups above."),
]

_MD_SPECIAL = re.compile(r"([\\*_\[\]<>|#!~=$%{}^])")
_KEEP_HEADERS = {"server", "content-type", "location", "x-powered-by", "www-authenticate",
                 "content-length", "x-aspnet-version", "title"}


# --- escaping ---------------------------------------------------------------

def _text(s: object, limit: int = 600) -> str:
    """Untrusted text, safe inline. Backtick pairs survive as code spans."""
    flat = " ".join(str(s or "").split())
    if len(flat) > limit:
        flat = flat[:limit] + "…"
    parts = flat.split("`")
    if len(parts) % 2 == 0:              # unbalanced: treat every backtick as text
        parts = [flat.replace("`", "'")]
    out = []
    for i, part in enumerate(parts):
        out.append(f"`{part}`" if i % 2 and part else _MD_SPECIAL.sub(r"\\\1", part))
    return "".join(out)


def _code(s: object, limit: int = 300) -> str:
    flat = " ".join(str(s or "").split()).replace("`", "'")[:limit]
    return f"`{flat}`" if flat else "-"


def _alias(s: object, limit: int = 120) -> str:
    """Untrusted text for wikilink aliases and frontmatter, where escapes do not apply."""
    flat = re.sub(r"[\[\]|#^<>`%]", "", " ".join(str(s or "").split()))
    return flat[:limit] or "untitled"


def _note_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._") or "unnamed"


def _link(target: str, alias: object = None) -> str:
    return f"[[{target}|{_alias(alias)}]]" if alias is not None else f"[[{target}]]"


def host_link(ip: str) -> str:
    return _link(f"hosts/{_note_name(ip)}", ip)


def finding_link(f: Finding) -> str:
    return _link(f"findings/{f.id}", f.title)


def _frontmatter(fields: dict) -> str:
    lines = ["---"]
    for k, v in fields.items():
        if v is None:
            continue
        lines.append(f"{k}: {json.dumps(v)}")
    lines.append("---")
    return "\n".join(lines)


def _tag(s: str) -> str:
    t = re.sub(r"[^A-Za-z0-9_/-]+", "-", s).strip("-/")
    return t if t and not t.isdigit() else ""


# --- small helpers ----------------------------------------------------------

def _when(epoch: float | None) -> str:
    return time.strftime("%d %b %Y at %H:%M UTC", time.gmtime(epoch)) if epoch else "an unrecorded time"


def _dur(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds} seconds"
    minutes = round(seconds / 60)
    if minutes < 90:
        return f"{minutes} minutes"
    return f"{minutes // 60} h {minutes % 60} min"


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _sev(f: Finding) -> str:
    return SEV_LABEL.get(f.severity, f.severity.title())


def _svc_key(f: Finding) -> tuple[str, int | None, str]:
    return (f.host, f.port, f.proto)


def _first_sentences(text: str, n: int = 2) -> str:
    flat = " ".join((text or "").split())
    parts = re.split(r"(?<=[.!?])\s+", flat)
    return " ".join(parts[:n])


def _family(svc: Service, findings: list[Finding]) -> str:
    if any(f.source == "extscan:exposure" for f in findings):
        return "exposed"
    if svc.proto == "tcp" and svc.is_http:
        return "web"
    if svc.proto == "udp":
        return "udp"
    if svc.name.lower() in REMOTE_NAMES:
        return "remote"
    return "other"


# --- proof and reproduction -------------------------------------------------

def _clip(lines: list[str], width: int = 240) -> list[str]:
    return [ln if len(ln) <= width else ln[:width] + " …" for ln in lines]


def proof(f: Finding, max_body: int = 12) -> str:
    """A short fenced excerpt that proves the finding, or "" if there is none."""
    return _fence("\n".join(_clip(_proof_lines(f, max_body)))) if (f.evidence or "").strip() else ""


def _proof_lines(f: Finding, max_body: int) -> list[str]:
    ev = (f.evidence or "").strip()
    if not ev:
        return ""
    if f.source == "extscan:snmp":
        community = next((t.split(":", 1)[1] for t in f.tags if t.startswith("community:")),
                         "?")
        fields = dict(line.split(": ", 1) for line in ev.splitlines() if ": " in line)
        port = f.port or 161
        head = (f"SNMP {fields.get('version', 'v2c')} GET sysDescr.0 -> "
                f"{f.host}:{port}/udp  community={community}")
        return [head, f"sysDescr: {fields.get('sysDescr', '?')}"]
    if "--- request ---" in ev:
        return _nuclei_proof(ev, max_body)
    lines = ev.splitlines()
    if re.match(r"^(GET|POST|HEAD|OPTIONS)\s+\S+\s+->", lines[0]):
        return _http_proof(lines, max_body)
    excerpt = lines[:max_body + 2]
    if len(lines) > len(excerpt):
        excerpt.append(f"... ({len(lines) - len(excerpt)} more line(s) in the finding note)")
    return excerpt


def _trim_headers(headers: list[str]) -> list[str]:
    return [h for h in headers if h.split(":", 1)[0].strip().lower() in _KEEP_HEADERS]


def _http_proof(lines: list[str], max_body: int) -> list[str]:
    head, rest = lines[0], lines[1:]
    if "" in rest:
        blank = rest.index("")
        headers, body = rest[:blank], rest[blank + 1:]
    else:                                # no header block: it is all summary
        headers, body = [], rest
    out = [head, *_trim_headers(headers)[:4]]
    body = [b for b in body if b.strip()] if len(body) > max_body else body
    if body:
        out += ["", *body[:max_body]]
        if len(body) > max_body:
            out.append(f"... ({len(body) - max_body} more line(s) in the finding note)")
    return out


def _nuclei_proof(ev: str, max_body: int) -> list[str]:
    pre, _, after = ev.partition("--- request ---")
    request, _, response = after.partition("--- response ---")
    req = [ln for ln in request.strip().splitlines() if ln.strip()]
    out = [ln for ln in pre.strip().splitlines() if ln.startswith("matched-at")]
    if req:
        out += ["", req[0], *[r for r in req[1:] if r.lower().startswith("host:")]]
    resp = response.strip("\n").splitlines()
    if resp:
        blank = resp.index("") if "" in resp else len(resp)
        out += ["", resp[0], *_trim_headers(resp[1:blank])]
        body = [b for b in resp[blank + 1:] if b.strip()]
        if body:
            out += ["", *body[:max_body]]
            if len(body) > max_body:
                out.append(f"... ({len(body) - max_body} more line(s) in the finding note)")
    return out


def reproduce(f: Finding, run_id: str) -> str:
    """Commands a reviewer can run to see the finding for themselves."""
    url = finding_url(f)
    if f.source == "extscan:snmp":
        community = next((t.split(":", 1)[1] for t in f.tags if t.startswith("community:")),
                         "<community>")
        if community.startswith("<"):
            community = "<community string, see raw state>"
        version = "1" if "version: v1" in f.evidence else "2c"
        return (f"snmpget -v{version} -c {shlex.quote(community)} "
                f"{f.host}:{f.port or 161} 1.3.6.1.2.1.1.1.0")
    if f.source.startswith("nuclei:") and url:
        return f"nuclei -u {shlex.quote(url)} -id {shlex.quote(f.source.split(':', 1)[1])}"
    if f.source == "extscan:graphql" and url:
        return (f"curl -sk -i -X POST {shlex.quote(url)} -H 'Content-Type: application/json' "
                "--data '{\"query\":\"{__schema{types{name}}}\"}'")
    if url:
        return f"curl -sk -i {shlex.quote(url)}"
    if f.source.startswith(("nmap-tcp:", "nmap-udp:")) and f.port:
        script = f.source.split(":", 1)[1]
        udp = "-sU " if f.proto == "udp" else ""
        if script in {"port-states", "unusual-port", "banner", "fingerprint-strings"}:
            return f"nmap {udp}-sV -p {f.port} {f.host}"
        return f"nmap {udp}-sV -p {f.port} --script {shlex.quote(script)} {f.host}"
    if f.source == "extscan:exposure" and f.port:
        udp = "-sU " if f.proto == "udp" else ""
        return f"nmap {udp}-sV -p {f.port} {f.host}"
    return f"extscan show {run_id} --finding {f.id}"


# --- the vault --------------------------------------------------------------

class _Vault:
    def __init__(self, root: Path, run_dir: Path, scope: Scope, triaged: TriageResult,
                 hosts: list[Host], services: list[Service], meta: dict,
                 commands: list[dict], degradations: list[Degradation],
                 leads: list[Lead], shots: list[Shot]):
        self.root, self.run_dir = root, run_dir
        self.scope, self.triaged, self.meta = scope, triaged, meta
        self.hosts, self.services = hosts, services
        self.commands, self.degradations, self.leads = commands, degradations, leads
        self.findings = triaged.findings
        self.run_id = meta.get("run_id", run_dir.name)
        self.written: list[str] = []

        self.by_service: dict[tuple, list[Finding]] = {}
        for f in self.findings:
            self.by_service.setdefault(_svc_key(f), []).append(f)
        self.svc_by_key = {(s.host, s.port, s.proto): s for s in services}
        self.svc_keys = set(self.svc_by_key)
        self.told: dict[str, str] = {}

        self.shots = [s for s in shots if s.status == "captured"
                      and (run_dir / s.file).is_file()]
        self.shots_failed = [s for s in shots if s.status != "captured"]
        self.shot_for_service = {s.service: s for s in self.shots if s.kind == "service"}
        self.shots_for_finding: dict[str, list[Shot]] = {}
        for s in self.shots:
            for fid in s.finding_ids:
                self.shots_for_finding.setdefault(fid, []).append(s)

    # file plumbing

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text.rstrip() + "\n")
        self.written.append(rel)

    def attach(self, shot: Shot) -> str:
        name = Path(shot.file).name
        rel = f"attachments/{name}"
        (self.root / "attachments").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.run_dir / shot.file, self.root / rel)
        if rel not in self.written:
            self.written.append(rel)
        return rel

    def embed(self, shot: Shot) -> str:
        return f"![[{self.attach(shot)}]]"

    def caption(self, shot: Shot) -> str:
        bits = [_code(shot.url)]
        if shot.http_status:
            bits.append(f"HTTP {shot.http_status}")
        if shot.final_url and shot.final_url.rstrip("/") != shot.url.rstrip("/"):
            bits.append(f"ended at {_code(shot.final_url)}")
        if shot.blocked:
            bits.append(f"{_plural(len(shot.blocked), 'off-scope request')} blocked")
        return "_" + ", ".join(bits) + "_"

    # rendering

    def render(self) -> None:
        for f in self.findings:
            self.write(f"findings/{f.id}.md", self.finding_note(f))
        for h in self._all_hosts():
            self.write(f"hosts/{_note_name(h.ip)}.md", self.host_note(h))
        self.write(f"{REVIEW}.md", self.review_note())
        self.write(f"{GAPS}.md", self.gaps_note())
        self.write(f"{METHOD}.md", self.method_note())
        self.write(f"{SUMMARY}.md", self.summary_note())

    def _all_hosts(self) -> list[Host]:
        known = {h.ip: h for h in self.hosts}
        for ip in sorted({s.host for s in self.services} | {f.host for f in self.findings}):
            if ip and ip not in known:
                known[ip] = Host(ip=ip)
        return list(known.values())

    def where(self, f: Finding) -> str:
        svc = self.svc_by_key.get(_svc_key(f))
        if svc and svc.proto == "tcp" and svc.is_http:
            return svc.base_url()
        return f"{f.host}:{f.port}/{f.proto}" if f.port else f.host

    def tell(self, findings: list[Finding]) -> list[str]:
        """Narrate notable findings once each.

        Several checks often prove the same thing (three nuclei templates and
        a path check all reading one `.env`): the first carries the proof and
        the rest are named under it. An issue already told for another
        service, such as the same app on 80 and 443, gets a one-line pointer.
        """
        notable = sorted((f for f in findings if f.severity != "info"),
                         key=lambda f: (-severity_rank(f.severity),
                                        f.source.startswith("nuclei:")))
        heads: list[Finding] = []
        also: dict[str, list[Finding]] = {}
        repeats: list[tuple[Finding, str]] = []
        by_proof: dict[str, Finding] = {}
        for f in notable:
            key, here = issue_key(f), self.where(f)
            if self.told.get(key, here) != here:
                repeats.append((f, self.told[key]))
                continue
            self.told.setdefault(key, here)
            pk = finding_url(f) or proof(f)
            if pk and pk in by_proof:
                also.setdefault(by_proof[pk].id, []).append(f)
                continue
            if pk:
                by_proof[pk] = f
            heads.append(f)
        out: list[str] = []
        for f in heads:
            out += self.finding_block(f, also.get(f.id, []))
        if repeats:
            out += ["Already described for another service, and present here too:", ""]
            out += [f"- **{_sev(f)}**: {finding_link(f)}, as on {_code(where)}"
                    for f, where in repeats]
            out.append("")
        return out

    def finding_block(self, f: Finding, also: list[Finding] | None = None) -> list[str]:
        out = [f"**{_sev(f)}: {finding_link(f)}.** {_text(_first_sentences(f.description))}"]
        if f.confidence == "tentative":
            out[0] += " _Tentative: needs confirmation._"
        if also:
            out[0] += " Also flagged by " + ", ".join(finding_link(g) for g in also) + "."
        out.append("")
        p = proof(f)
        if p:
            out += [p, ""]
        for shot in self.shots_for_finding.get(f.id, []):
            if shot.kind == "finding":
                out += [self.embed(shot), self.caption(shot), ""]
        return out

    def summary_note(self) -> str:
        st = self.triaged.stats
        sev = st["findings_by_severity"]
        a = self.scope.authorization
        out: list[str] = [_frontmatter({
            "generator": "extscan", "type": "summary", "run_id": self.run_id,
            "engagement": self.scope.engagement, "client": self.scope.client,
            "generated": _ts(),
            **{s: sev.get(s, 0) for s in SEV_ORDER},
            "review_items": st["review_items"], "coverage_gaps": len(self.degradations),
            "tags": ["extscan/summary"],
        }), ""]
        w = out.append
        w(f"# {_text(self.scope.engagement)}: external assessment")
        w("")

        counts = ", ".join(f"{sev[s]} {SEV_LABEL[s].lower()}" for s in SEV_ORDER if sev.get(s))
        w("> [!abstract] In short")
        w(f"> We tested {_plural(len(self.scope.targets), 'range')} for "
          f"{_text(self.scope.client or 'the client')} and found "
          f"{_plural(st['services_total'], 'open service')} on "
          f"{_plural(len(self._all_hosts()), 'host')}. That produced "
          f"{_plural(st['findings_total'], 'finding')}"
          + (f" ({counts})." if counts else "."))
        top = self._top_issues()
        if top:
            w(">")
            w("> The most serious problems:")
            for f, n in top:
                where = f" (on {_plural(n, 'service')})" if n > 1 else ""
                w(f"> - **{_sev(f)}**: {finding_link(f)}{where}")
        w("")

        w("> [!warning] Before this report goes out")
        if self.triaged.review_queue:
            w(f"> - **{_plural(len(self.triaged.review_queue), 'item')} need an "
              f"auditor's decision.** Work through {_link(REVIEW)} first.")
        else:
            w(f"> - Nothing is waiting in the {_link(REVIEW)}.")
        if self.degradations:
            serious = sum(1 for d in self.degradations if d.severity == "serious")
            w(f"> - **{_plural(len(self.degradations), 'coverage gap')}"
              f"{f', {serious} serious' if serious else ''}.** Part of the testing did "
              f"not complete, so a missing finding may be a check that never ran. See "
              f"{_link(GAPS)}.")
        else:
            w(f"> - Every planned check completed. {_link(GAPS)} has the detail.")
        w("")

        n = 0

        def section(title: str) -> None:
            nonlocal n
            n += 1
            w(f"## {n}. {title}")
            w("")

        section("Scope and authorisation")
        window = ""
        if a.window_start or a.window_end:
            window = (f" The agreed testing window ran from {_text(a.window_start or 'open')} "
                      f"to {_text(a.window_end or 'open')}.")
        w(f"{_text(a.authorized_by)} authorised this assessment under reference "
          f"{_code(a.reference)}.{window} The agreed scope was:")
        w("")
        for t in self.scope.targets:
            w(f"- {_code(t)}")
        if self.scope.exclude:
            w("")
            w("We agreed to leave these alone, and did:")
            w("")
            for t in self.scope.exclude:
                w(f"- {_code(t)}")
        w("")
        if a.notes:
            w(f"Constraints: {_text(a.notes)}")
            w("")
        w("All testing was read-only. We tried no passwords beyond a short list of "
          "default SNMP community strings, changed no data, and exploited nothing. Every request was checked against the scope before it "
          "was sent, including redirects.")
        w("")

        section("Discovery: what was listening")
        out += self._discovery()

        groups: dict[str, list[Service]] = {}
        for svc in self.services:
            fs = self.by_service.get((svc.host, svc.port, svc.proto), [])
            groups.setdefault(_family(svc, fs), []).append(svc)
        for key, title, intro in FAMILIES:
            svcs = groups.get(key)
            if not svcs:
                continue
            section(title)
            w(intro.format(n=len(svcs)))
            w("")
            for svc in svcs:
                out += self._service_story(svc)

        orphans = [f for f in self.findings
                   if _svc_key(f) not in self.svc_keys and f.source not in CHASE_SOURCES
                   and f.severity != "info"]
        if orphans:
            section("Host-wide observations")
            out += self.tell(orphans)

        section("Following up")
        out += self._follow_ups()

        section("What we did not cover")
        out += self._not_covered()

        w("## Notes in this vault")
        w("")
        w(f"- {_link(REVIEW)}, {_link(GAPS)}, {_link(METHOD)}")
        w("- Hosts: " + ", ".join(host_link(h.ip) for h in self._all_hosts()))
        w(f"- {_plural(len(self.findings), 'finding note')} under `findings/`")
        unattributed = [f for f in self.findings if not f.host]
        if unattributed:
            w("- Not tied to a host: " + ", ".join(finding_link(f) for f in unattributed))
        return "\n".join(out)

    def _top_issues(self) -> list[tuple[Finding, int]]:
        seen: dict[str, list[Finding]] = {}
        for f in self.findings:
            if severity_rank(f.severity) >= severity_rank("high"):
                seen.setdefault(issue_key(f), []).append(f)
        ranked = sorted(seen.values(), key=lambda fs: (-severity_rank(fs[0].severity),
                                                       -len(fs)))
        return [(fs[0], len({_svc_key(f) for f in fs})) for fs in ranked[:6]]

    def _discovery(self) -> list[str]:
        out: list[str] = []
        w = out.append
        disc = [c for c in self.commands if str(c.get("stage", "")).startswith("discover")]
        tcp = [c for c in disc if "discover:tcp" in str(c.get("stage", ""))]
        udp = [c for c in disc if "discover:udp" in str(c.get("stage", ""))]
        if disc:
            start = min(c.get("started", 0) for c in disc)
            end = max(c.get("started", 0) + c.get("duration", 0) for c in disc)
            kinds = "a TCP port scan" + (" and a UDP scan" if udp else "")
            w(f"We started on {_when(start)} with {kinds} of the whole scope, using nmap "
              f"with service-version detection. Discovery took {_dur(end - start)}.")
        else:
            w("No discovery commands are recorded for this run, so the inventory below "
              "came from an earlier or imported run.")
        if not udp:
            udp_gap = any(d.stage.startswith("discover") and "udp" in
                          f"{d.reason} {d.impact}".lower() for d in self.degradations)
            w("")
            w("**UDP was not scanned in this run**"
              + (f", see {_link(GAPS)}." if udp_gap else ".")
              + " Any SNMP, DNS or VPN exposure on UDP is not covered.")
        w("")
        for label, cmds in (("TCP", tcp), ("UDP", udp)):
            if cmds:
                w(f"The {label} scan, as run:")
                w("")
                w(_fence(shlex.join(str(a) for a in cmds[0].get("argv", []))))
                if len(cmds) > 1:
                    w(f"_({len(cmds) - 1} more {label} batch(es) in {_link(METHOD)})_")
                w("")

        st = self.triaged.stats
        if not self.services:
            w("Discovery found **no open services**. Nothing further could be tested.")
            w("")
            return out
        w(f"It found {_plural(len({s.host for s in self.services}), 'responsive host')} "
          f"with {_plural(st['services_total'], 'open service')}: {st['services_tcp']} TCP "
          f"and {st['services_udp']} UDP.")
        w("")
        w("| Host | Port | Service | Product | Findings |")
        w("|---|---|---|---|---|")
        for s in self.services:
            fs = self.by_service.get((s.host, s.port, s.proto), [])
            worst = max(fs, key=lambda f: severity_rank(f.severity), default=None)
            product = " ".join(x for x in (s.product, s.version) if x)
            notable = sum(1 for f in fs if f.severity != "info")
            cell = f"{notable}, worst {_sev(worst).lower()}" if worst and notable else "info only"
            w(f"| {host_link(s.host)} | {s.port}/{s.proto} | {_text(s.name) or '?'} "
              f"| {_text(product) or '-'} | {cell if fs else '-'} |")
        w("")
        return out

    def _service_story(self, svc: Service) -> list[str]:
        out: list[str] = []
        w = out.append
        fs = [f for f in self.by_service.get((svc.host, svc.port, svc.proto), [])
              if f.source not in CHASE_SOURCES]
        label = svc.base_url() if svc.proto == "tcp" and svc.is_http else \
            f"{svc.host}:{svc.port}/{svc.proto}"
        w(f"### {_code(label)}")
        w("")
        shot = self.shot_for_service.get(svc.id)
        desc = []
        if shot and shot.page_title:
            desc.append(f"The page title is “{_text(shot.page_title, 150)}”.")
        product = " ".join(x for x in (svc.product, svc.version, svc.extrainfo) if x)
        if product:
            desc.append(f"It identifies as {_code(product)}.")
        elif svc.name:
            desc.append(f"nmap identified it as {_code(svc.name)}, with no version.")
        if svc.probed_by:
            desc.append("We ran " + ", ".join(_code(p) for p in svc.probed_by)
                        + f" against it. Details are in {host_link(svc.host)}.")
        else:
            desc.append("**No checks completed against this service.**")
        w(" ".join(desc))
        w("")
        if shot:
            w(self.embed(shot))
            w(self.caption(shot))
            w("")
        elif svc.proto == "tcp" and svc.is_http:
            w("_No screenshot of this service._")
            w("")

        notable = [f for f in fs if f.severity != "info"]
        if notable:
            w("What we found:")
            w("")
            out += self.tell(notable)
        info = len(fs) - len(notable)
        if info:
            w(("Nothing above informational. " if not notable else "")
              + f"We also recorded {_plural(info, 'informational observation')}, "
              f"listed on {host_link(svc.host)}.")
            w("")
        elif not notable:
            w("Nothing was found on this service.")
            w("")
        return out

    def _follow_ups(self) -> list[str]:
        out: list[str] = []
        w = out.append
        if not self.leads:
            w("The first pass raised no follow-up leads.")
            w("")
        else:
            status = Counter(ld.status for ld in self.leads)
            w(f"The first pass raised {_plural(len(self.leads), 'lead')}: things worth a "
              "closer look, like an API specification or a readable file. We followed "
              f"them up. {status.get('done', 0)} were resolved"
              + "".join(f", {n} {s}" for s, n in sorted(status.items()) if s != "done")
              + ".")
            w("")
            seen: set[tuple] = set()
            shown = 0
            for ld in self.leads:
                key = (ld.kind, ld.note or ld.url or ld.host)
                if key in seen or ld.status != "done":
                    continue
                seen.add(key)
                shown += 1
                if shown > 30:
                    continue
                target = ld.url or f"{ld.host}:{ld.port or '-'}"
                w(f"- {_code(ld.kind)} at {_code(target)}: {_text(ld.note) or 'done'}")
            if shown > 30:
                w(f"- _... and {shown - 30} more in `leads.json`_")
            w("")

        found = sorted((f for f in self.findings if f.source in CHASE_SOURCES),
                       key=lambda f: -severity_rank(f.severity))
        notable = [f for f in found if f.severity != "info"]
        if notable:
            w("What the follow-ups proved:")
            w("")
            out += self.tell(notable)
        if len(found) > len(notable):
            w(f"They also produced {_plural(len(found) - len(notable), 'informational note')}"
              ", kept in the host notes.")
            w("")
        return out

    def _not_covered(self) -> list[str]:
        out: list[str] = []
        w = out.append
        if self.degradations:
            w(f"Not everything ran. **Where a check below did not complete, the absence "
              f"of a finding means nothing.** {_link(GAPS)} has the detail and the fix.")
            w("")
            for d in sorted(self.degradations, key=lambda x: x.severity != "serious"):
                tag = "**Serious:** " if d.severity == "serious" else ""
                w(f"- {tag}{_text(d.impact)}")
            w("")
        else:
            w("Every planned stage completed, and no tool failed.")
            w("")
        open_leads = [ld for ld in self.leads if ld.status != "done"]
        if open_leads:
            w(f"{_plural(len(open_leads), 'lead')} were not resolved, so whatever lies "
              "behind them is untested:")
            w("")
            for ld in open_leads[:20]:
                w(f"- {_code(ld.kind)} at {_code(ld.url or ld.host)} ({ld.status}): "
                  f"{_text(ld.last_error or ld.reason, 200)}")
            w("")
        if self.shots_failed:
            w(f"{_plural(len(self.shots_failed), 'page')} could not be screenshotted:")
            w("")
            for s in self.shots_failed[:20]:
                w(f"- {_code(s.url)}: {_text(s.error, 200) or s.status}")
            w("")
        w("Limits that always apply: checks were read-only, so anything that needs "
          "credentials or exploitation to see is out of reach. A WAF, rate limiter or "
          "geo-filter can hide services. UDP silence is ambiguous. Version-matched "
          "findings are tentative until confirmed.")
        w("")
        return out

    def host_note(self, h: Host) -> str:
        svcs = [s for s in self.services if s.host == h.ip]
        fs = sorted((f for f in self.findings if f.host == h.ip),
                    key=lambda f: (-severity_rank(f.severity), f.port or 0))
        sev = Counter(f.severity for f in fs)
        out = [_frontmatter({
            "generator": "extscan", "type": "host", "ip": h.ip,
            "hostnames": [_alias(n) for n in h.hostnames],
            "os_guess": _alias(h.os_guess) if h.os_guess else None,
            "services": len(svcs), "findings": len(fs),
            **{s: sev.get(s, 0) for s in SEV_ORDER},
            "tags": ["extscan/host"],
        }), ""]
        w = out.append
        w(f"# {_text(h.ip)}")
        w("")
        w(f"Back to {_link(SUMMARY)}.")
        if h.hostnames:
            w("")
            w("Hostnames: " + ", ".join(_code(n) for n in h.hostnames))
        if h.os_guess:
            w("")
            w(f"OS guess: {_text(h.os_guess)}")
        w("")
        w("## Services")
        w("")
        if svcs:
            w("| Port | Service | Product | Checks run | Findings |")
            w("|---|---|---|---|---|")
            for s in svcs:
                product = " ".join(x for x in (s.product, s.version, s.extrainfo) if x)
                n = len(self.by_service.get((s.host, s.port, s.proto), []))
                w(f"| {s.port}/{s.proto} | {_text(s.name) or '?'} | {_text(product) or '-'} "
                  f"| {', '.join(_code(p) for p in s.probed_by) or '**none**'} | {n} |")
        else:
            w("_No open services recorded._")
        w("")
        host_shots = [s for s in self.shots if s.service.split("/")[0] == h.ip]
        if host_shots:
            w("## Screenshots")
            w("")
            for shot in host_shots:
                w(self.embed(shot))
                w(self.caption(shot))
                w("")
        w("## Findings")
        w("")
        if not fs:
            w("_None._")
        for level in SEV_ORDER:
            group = [f for f in fs if f.severity == level]
            if not group:
                continue
            w(f"### {SEV_LABEL[level]} ({len(group)})")
            w("")
            for f in group:
                where = f"{f.port}/{f.proto}" if f.port else "host"
                w(f"- {finding_link(f)} ({where})")
            w("")
        return "\n".join(out)

    def finding_note(self, f: Finding) -> str:
        out = [_frontmatter({
            "generator": "extscan", "type": "finding", "id": f.id,
            "title": _alias(f.title, 300), "aliases": [_alias(f.title)],
            "severity": f.severity, "host": f.host, "port": f.port, "proto": f.proto,
            "source": f.source, "confidence": f.confidence,
            "review_required": f.review_required, "labels": [_alias(t) for t in f.tags],
            "tags": ["extscan/finding", f"severity/{f.severity}",
                     *sorted({t for t in map(_tag, f.tags) if t})],
        }), ""]
        w = out.append
        w(f"# {_text(f.title, 300)}")
        w("")
        target = f"{f.host}:{f.port}/{f.proto}" if f.port else f.host
        w(f"**Severity:** {_sev(f)}"
          + (" (tentative, needs confirmation)" if f.confidence == "tentative" else "")
          + f" · **Host:** {host_link(f.host) if f.host else '-'}"
          + f" · **Service:** {_code(target)} · **Detected by:** {_code(f.source)}")
        w("")
        if f.review_required:
            w("> [!todo] Requires manual review")
            w(f"> {_text(f.review_reason) or 'See the review queue.'} "
              f"Listed in {_link(REVIEW)}.")
            w("")
        if f.description:
            w("## What we saw")
            w("")
            w(_text(f.description, 4000))
            w("")
        p = proof(f)
        if p:
            w("## Proof")
            w("")
            w(p)
            w("")
        for shot in self.shots_for_finding.get(f.id, []):
            w(self.embed(shot))
            w(self.caption(shot))
            w("")
        w("## Reproduce")
        w("")
        w(_fence(reproduce(f, self.run_id)))
        w("")
        if f.evidence and f.evidence.strip() != re.sub(r"^```text\n|\n```$", "", p).strip():
            w("## Full evidence")
            w("")
            w(_fence(f.evidence, limit=6000))
            w("")
        if f.recommendation:
            w("## Remediation")
            w("")
            w(_text(f.recommendation, 4000))
            w("")
        if f.references:
            w("## References")
            w("")
            for r in f.references:
                w(f"- {_code(r)}")
            w("")
        return "\n".join(out)

    def review_note(self) -> str:
        out = [_frontmatter({"generator": "extscan", "type": "review-queue",
                             "items": len(self.triaged.review_queue),
                             "tags": ["extscan/review"]}), ""]
        w = out.append
        w(f"# {REVIEW}")
        w("")
        w(f"Back to {_link(SUMMARY)}.")
        w("")
        if not self.triaged.review_queue:
            w("_Nothing flagged for manual review._")
            return "\n".join(out)
        w("Automated checks establish that something is exposed. They cannot decide "
          "whether it is acceptable for this client. Each item names the question an "
          "auditor must answer. Work top to bottom.")
        w("")
        by_id = {f.id: f for f in self.findings}
        w("| # | Severity | Item | Target | An auditor must decide |")
        w("|---|---|---|---|---|")
        for item in self.triaged.review_queue:
            f = next((by_id[i] for i in item.finding_ids if i in by_id), None)
            label = finding_link(f) if f else _text(item.title)
            if len(item.finding_ids) > 1:
                label += f" (+{len(item.finding_ids) - 1} related)"
            w(f"| {item.priority} | {SEV_LABEL.get(item.severity, item.severity)} "
              f"| {label} | {_code(item.target)} | {_text(item.question)} |")
        w("")
        grouped = [i for i in self.triaged.review_queue if len(i.finding_ids) > 1]
        if grouped:
            w("## Items covering several instances")
            w("")
            for item in grouped:
                w(f"- **#{item.priority}** {_text(item.title, 200)}:")
                for fid in item.finding_ids[:20]:
                    if fid in by_id:
                        g = by_id[fid]
                        w(f"  - {finding_link(g)} ({_code(f'{g.host}:{g.port}')})")
            w("")
        return "\n".join(out)

    def gaps_note(self) -> str:
        out = [_frontmatter({"generator": "extscan", "type": "coverage-gaps",
                             "gaps": len(self.degradations),
                             "serious": sum(1 for d in self.degradations
                                            if d.severity == "serious"),
                             "tags": ["extscan/gaps"]}), ""]
        w = out.append
        w(f"# {GAPS}")
        w("")
        w(f"Back to {_link(SUMMARY)}.")
        w("")
        if not self.degradations:
            w("No coverage gaps. Every planned stage completed and no tool failed.")
            w("")
        else:
            w("**Absence of findings in these areas is not evidence that nothing is "
              "exposed there.** The check did not run, or ran partially.")
            w("")
            for d in sorted(self.degradations, key=lambda x: x.severity != "serious"):
                w(f"## {'Serious' if d.severity == 'serious' else 'Warning'}: "
                  f"{_code(d.stage)}")
                w("")
                w(f"- **What was lost:** {_text(d.impact)}")
                w(f"- **Cause:** {_code(d.component)}: {_text(d.reason)}")
                if d.hosts:
                    shown = ", ".join(host_link(h) for h in d.hosts[:20])
                    more = f" (+{len(d.hosts) - 20} more)" if len(d.hosts) > 20 else ""
                    w(f"- **Hosts:** {shown}{more}")
                if d.remedy:
                    w(f"- **Fix:** {_text(d.remedy)}")
                w("")
        stages = self.meta.get("stages", {})
        w("## Stages")
        w("")
        for name in ("recon", "discover", "probe", "chase", "screenshot", "report"):
            if name in stages:
                w(f"- `{name}`: completed {_when(stages[name].get('completed'))}")
            elif name not in ("recon", "report"):
                w(f"- `{name}`: **not run**")
        return "\n".join(out)

    def method_note(self) -> str:
        out = [_frontmatter({"generator": "extscan", "type": "methodology",
                             "commands": len(self.commands),
                             "tags": ["extscan/methodology"]}), ""]
        w = out.append
        w(f"# {METHOD}")
        w("")
        w(f"Back to {_link(SUMMARY)}.")
        w("")
        w(f"Run {_code(self.run_id)}, extscan {_text(self.meta.get('extscan_version', ''))}, "
          f"profile {_code(self.meta.get('profile', 'standard'))}.")
        w("")
        w("1. **Discover.** nmap TCP and UDP scans with service detection and safe NSE "
          "scripts. Scripts in the `dos` and `external` categories are excluded.")
        w("2. **Probe.** nuclei against every web service, without DoS, fuzzing, "
          "brute-force or default-login templates, then extscan's own per-service "
          "checks (HTTP paths and headers, TLS, SNMP, IIS).")
        w("3. **Chase.** Follow-up leads from the probes: API specifications, GraphQL, "
          "readable files, SNMP walks.")
        w("4. **Screenshot.** Headless Chromium, every request scope-checked. Pages "
          "holding secrets are not captured.")
        w("5. **Report.** Triage, then this vault. Secret values and non-default SNMP "
          "community strings are redacted here. The run directory keeps them raw.")
        w("")
        for warning in self.meta.get("warnings", []):
            w(f"> [!warning] {_text(warning)}")
            w("")
        if self.meta.get("tool_versions"):
            w("## Tool versions")
            w("")
            for tool, version in self.meta["tool_versions"].items():
                clean = re.sub(r"\x1b\[[0-9;]*m", "", str(version))
                w(f"- {_code(tool)}: {_code(clean)}")
            w("")
        w("## Command log")
        w("")
        if not self.commands:
            w("_No commands recorded._")
            return "\n".join(out)
        w(f"{_plural(len(self.commands), 'command')} ran. Exit codes, timings and output "
          "paths are in `commands.jsonl` in the run directory.")
        w("")
        lines = []
        for c in self.commands:
            rc = c.get("returncode")
            lines.append(f"[{_ts(c.get('started'))}] {c.get('stage', '')} rc={rc} "
                         f"{c.get('duration', 0):.1f}s\n  "
                         + shlex.join(str(a) for a in c.get("argv", [])))
        w(_fence("\n".join(lines), limit=60_000))
        return "\n".join(out)


def _clean_stale(root: Path, keep: set[str]) -> None:
    """Remove files a previous render wrote that this one did not.

    Only files listed in the previous manifest are touched, so notes a tester
    added and Obsidian's own `.obsidian/` settings survive a re-render.
    """
    manifest = root / MANIFEST
    if not manifest.exists():
        return
    try:
        previous = json.loads(manifest.read_text())
    except json.JSONDecodeError:
        return
    for rel in previous:
        if not isinstance(rel, str) or rel in keep or ".." in Path(rel).parts:
            continue
        target = root / rel
        if target.is_file():
            target.unlink()


def write_vault(run_dir: Path, scope: Scope, triaged: TriageResult, hosts: list[Host],
                services: list[Service], meta: dict, commands: list[dict] | None = None,
                degradations: list[Degradation] | None = None,
                leads: list[Lead] | None = None, shots: list[Shot] | None = None) -> Path:
    root = run_dir / VAULT_DIR
    root.mkdir(parents=True, exist_ok=True)
    v = _Vault(root, run_dir, scope, triaged, hosts, services, meta, commands or [],
               degradations or [], leads or [], shots or [])
    v.render()
    _clean_stale(root, set(v.written))
    (root / MANIFEST).write_text(json.dumps(sorted(v.written), indent=1))
    return root / f"{SUMMARY}.md"
