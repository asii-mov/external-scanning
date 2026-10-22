"""Core data model for a scanning engagement.

Everything the pipeline produces is one of these five records. They are plain
dataclasses that round-trip through JSON so each stage can hand state to the
next (and to an agent reading the run directory) without a database.
"""

from __future__ import annotations

import hashlib
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

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _stable_id("finding", self.host, self.port, self.proto, self.title, self.source)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(**d)


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
