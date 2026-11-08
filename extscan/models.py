"""Core data model for a scanning engagement.

Everything the pipeline produces is one of these five records. They are plain
dataclasses that round-trip through JSON so each stage can hand state to the
next (and to an agent reading the run directory) without a database.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    try:
        return SEVERITIES.index(sev.lower())
    except ValueError:
        return 0


def _now() -> float:
    return time.time()


def _stable_id(*parts: Any) -> str:
    """Short deterministic id, so re-running a stage does not duplicate records."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:12]


@dataclass
class Host:
    ip: str
    hostnames: list[str] = field(default_factory=list)
    state: str = "unknown"
    os_guess: str | None = None
    discovered_by: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Host:
        return cls(**d)


@dataclass
class Service:
    """One open port on one host, as reported by discovery."""

    host: str
    port: int
    proto: str
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    probed_by: list[str] = field(default_factory=list)
    # The CDN/WAF seen in front of the service, e.g. "Cloudflare (CDN/WAF)".
    # Empty when none was identified or the waf_detect probe has not run.
    edge: str = ""

    @property
    def id(self) -> str:
        return f"{self.host}/{self.proto}/{self.port}"

    @property
    def is_tls(self) -> bool:
        if self.tunnel == "ssl":
            return True
        name = self.name.lower()
        return name.endswith("https") or name in {"ssl", "tls"} or self.port in {443, 8443, 9443}

    @property
    def is_http(self) -> bool:
        """True for anything that looks like it speaks HTTP(S)."""
        name = self.name.lower()
        if name in {"http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http"}:
            return True
        if "http" in name:
            return True
        return self.proto == "tcp" and self.port in {
            80, 81, 443, 591, 2375, 2376, 3000, 4443, 5000, 7001, 8000, 8008,
            8080, 8081, 8088, 8443, 8834, 8888, 9000, 9090, 9443, 10000,
        }

    def base_url(self) -> str:
        scheme = "https" if self.is_tls else "http"
        default = 443 if scheme == "https" else 80
        hostpart = self.host
        if ":" in hostpart:
            hostpart = f"[{hostpart}]"
        if self.port == default:
            return f"{scheme}://{hostpart}"
        return f"{scheme}://{hostpart}:{self.port}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Service:
        return cls(**d)


@dataclass
class Finding:
    """Something worth putting in the report."""

    title: str
    severity: str = "info"
    host: str = ""
    port: int | None = None
    proto: str = "tcp"
    source: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    review_required: bool = False
    review_reason: str = ""
    confidence: str = "firm"
    tags: list[str] = field(default_factory=list)
    created: float = field(default_factory=_now)
    id: str = ""
    issue_key: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _stable_id("finding", self.host, self.port, self.proto, self.title, self.source)
        if not self.issue_key:
            self.issue_key = issue_key_for(self)

    @property
    def check_id(self) -> str:
        """`tool:check`, the part of the issue key that names what was tested."""
        tool, check = check_identifier(self.source, self.title, self.host)
        return f"{tool}:{check}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(**d)


# Sources whose part after the colon is the tool's own check id: a nuclei
# template id, or an NSE script id (nmap-tcp and nmap-udp are one tool).
_CHECK_ID_TOOLS = ("nuclei", "nmap-tcp", "nmap-udp", "nmap")
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/?#]+([/?#]\S*)?", re.I)
_PORT_RE = re.compile(r":\d{1,5}(?:/(?:tcp|udp))?\b")
_PAREN_RE = re.compile(r"\s\([^()]*\)")


def _title_skeleton(title: str, host: str) -> str:
    """The stable part of a title, for sources with no check id of their own.

    Drops what changes between runs without the issue changing: the host and
    port (already in the key), a URL's scheme and authority (its path is
    kept, because different paths are different issues), counts and version
    numbers, parenthesised detail such as a verb list, and free text after a
    colon such as a page title or a protocol list. A colon followed by a path is kept, so `Content review: /metrics`
    and `Content review: /robots.txt` stay apart.
    """
    t = _URL_RE.sub(lambda m: m.group(1) or "/", title or "")
    if host:
        t = t.replace(f"[{host}]", " ").replace(host, " ")
    t = _PORT_RE.sub(" ", t)
    t = _PAREN_RE.sub(" ", t)
    head, sep, tail = t.partition(": ")
    if sep and not tail.lstrip().startswith("/"):
        t = head
    words = [w if w.startswith("/") else re.sub(r"\d+", "#", w)
             for w in t.replace("`", "").lower().split()]
    while words and words[-1] in {"on", "at", "for", "of", "-", ":"}:
        words.pop()
    return " ".join(words).rstrip(":") or "untitled"


def check_identifier(source: str, title: str, host: str = "") -> tuple[str, str]:
    """(tool, check) for a finding, the coarse identity of what was tested.

    nuclei findings carry the template id (`nuclei:<template-id>`) and nmap
    findings the NSE script id (`nmap-tcp:<script>`), so those are used as is.
    extscan's own probes and chase handlers, sslscan, testssl.sh, DNS checks,
    model and analyst findings have no check id beyond their source, and one
    source emits several different issues, so the check is the title with its
    volatile parts removed (see `_title_skeleton`).
    """
    tool, sep, check = (source or "").partition(":")
    if sep and check and tool in _CHECK_ID_TOOLS:
        return ("nmap" if tool.startswith("nmap") else tool), check
    return source or "unknown", _title_skeleton(title, host)


def issue_key_for(f: Finding) -> str:
    """Stable key for "the same issue" across runs: host, port, protocol,
    tool and check, but not the title wording or the severity. `id` stays
    title-based, so existing run directories and vault links keep working."""
    tool, check = check_identifier(f.source, f.title, f.host)
    return _stable_id("issue", (f.host or "").lower(), f.proto, f.port, tool, check)


@dataclass
class Lead:
    """A follow-up worth chasing, emitted by a probe or by the agent.

    Leads are what make this a loop instead of a one-shot pipeline: nuclei
    reporting a swagger endpoint produces an `openapi` lead, chasing which may
    produce further findings and further leads, down to a depth cap.
    """

    kind: str
    host: str
    port: int | None = None
    proto: str = "tcp"
    url: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    origin: str = ""
    depth: int = 0
    status: str = "open"
    note: str = ""
    attempts: int = 0
    last_error: str = ""
    created: float = field(default_factory=_now)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _stable_id("lead", self.kind, self.host, self.port, self.url,
                                 sorted(self.params.items()))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Lead:
        return cls(**d)


@dataclass
class CommandRecord:
    """Audit trail entry. Pentest reports live or die on reproducibility."""

    argv: list[str]
    started: float
    duration: float
    returncode: int | None
    stdout_path: str = ""
    stderr_path: str = ""
    stage: str = ""
    timed_out: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
