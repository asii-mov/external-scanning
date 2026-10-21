"""Engagement scope: who authorised this, what may be touched, what may not.

Two jobs here, and the second is the one that matters once the pipeline starts
looping. First, refuse to run at all without a scope file that records written
authorisation. Second, re-check every single target immediately before it is
touched -- including targets derived from tool output.

That second check is not paranoia. Leads come from scanner results, HTTP
redirects and OpenAPI `servers` blocks, all of which are controlled by the
thing being scanned. A host that redirects to 169.254.169.254 or to a
competitor's netblock must not drag the scan along with it.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ScopeError(Exception):
    """Raised when something would be touched that is not authorised."""


# Ranges that mean "internal network" for the purposes of an *external* audit.
#
# Listed explicitly rather than using ipaddress' .is_private, which also covers
# the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) and RFC 2544 benchmarking space. Those are not internal
# space, and rejecting them would reject the example scope files and every
# write-up that uses documentation addresses.
_INTERNAL_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8",            # RFC 1918
        "172.16.0.0/12",         # RFC 1918
        "192.168.0.0/16",        # RFC 1918
        "127.0.0.0/8",           # loopback
        "169.254.0.0/16",        # link-local, incl. cloud metadata
        "100.64.0.0/10",         # RFC 6598 CGNAT
        "::1/128",               # IPv6 loopback
        "fc00::/7",              # IPv6 unique local
        "fe80::/10",             # IPv6 link-local
    )
]


def _is_internal(net: ipaddress._BaseNetwork) -> bool:
    return any(
        net.version == internal.version and net.overlaps(internal)
        for internal in _INTERNAL_NETS
    )


@dataclass
class Authorization:
    reference: str
    authorized_by: str
    window_start: str = ""
    window_end: str = ""
    notes: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> Authorization:
        missing = [k for k in ("reference", "authorized_by") if not d.get(k)]
        if missing:
            raise ScopeError(
                "scope.authorization is missing required field(s): "
                + ", ".join(missing)
                + ". Record the ticket/contract reference and the person who "
                "signed off before scanning anything."
            )
        return cls(
            reference=str(d["reference"]),
            authorized_by=str(d["authorized_by"]),
            window_start=str(d.get("window_start", "")),
            window_end=str(d.get("window_end", "")),
            notes=str(d.get("notes", "")),
        )


def _parse_ts(value: str) -> dt.datetime:
    v = value.strip().replace("Z", "+00:00")
    stamp = dt.datetime.fromisoformat(v)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    return stamp


@dataclass
class Scope:
    engagement: str
    client: str
    authorization: Authorization
    targets: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    allow_hostnames: list[str] = field(default_factory=list)
    # Domains the client owns, for subdomain enumeration. Listing a domain
    # authorises *enumeration* of it, not scanning of whatever it resolves to:
    # a discovered name is only scannable if its address is in `targets`.
    domains: list[str] = field(default_factory=list)
    max_hosts: int = 1024
    allow_private: bool = False
    source_path: str = ""

    # -- loading ---------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> Scope:
        p = Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}")
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            raise ScopeError(f"scope file {p} is not valid JSON: {exc}") from exc
        if "authorization" not in data:
            raise ScopeError(
                f"{p} has no `authorization` block. extscan will not scan a "
                "target without a recorded sign-off; see examples/scope.example.json"
            )
        if not data.get("targets"):
            raise ScopeError(f"{p} lists no targets")
        scope = cls(
            engagement=str(data.get("engagement", "unnamed engagement")),
            client=str(data.get("client", "")),
            authorization=Authorization.from_dict(data["authorization"]),
            targets=[str(t) for t in data["targets"]],
            exclude=[str(t) for t in data.get("exclude", [])],
            allow_hostnames=[h.lower() for h in data.get("allow_hostnames", [])],
            domains=[d.lower().strip().rstrip(".") for d in data.get("domains", [])],
            max_hosts=int(data.get("max_hosts", 1024)),
            allow_private=bool(data.get("allow_private", False)),
            source_path=str(p),
        )
        scope.validate()
        return scope

    def validate(self) -> None:
        """Parse every network now, so a typo fails before any packet is sent."""
        for spec in self.targets + self.exclude:
            try:
                ipaddress.ip_network(spec, strict=False)
            except ValueError as exc:
                raise ScopeError(f"bad target/exclude entry {spec!r}: {exc}") from exc
        if not self.allow_private:
            for net in self._networks(self.targets):
                if _is_internal(net):
                    raise ScopeError(
                        f"target {net} is internal/loopback address space but "
                        "scope.allow_private is false. Set it to true only if the "
                        "engagement really covers internal space -- on an external "
                        "audit this usually means a typo in the target list."
                    )
        n = self.host_count()
        if n > self.max_hosts:
            raise ScopeError(
                f"scope expands to {n} hosts, over max_hosts={self.max_hosts}. "
                "Raise max_hosts deliberately or narrow the targets."
            )

    # -- expansion -------------------------------------------------------

    @staticmethod
    def _networks(specs: list[str]) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(s, strict=False) for s in specs]

    def host_count(self) -> int:
        return sum(1 for _ in self._iter_hosts())

    def _iter_hosts(self):
        seen: set[str] = set()
        for net in self._networks(self.targets):
            # /32 and /31 have no "hosts" in ipaddress terms; iterate the net.
            iterator = net.hosts() if net.num_addresses > 2 else iter(net)
            for addr in iterator:
                s = str(addr)
                if s in seen or self.is_excluded(s):
                    continue
                seen.add(s)
                yield s

    def hosts(self) -> list[str]:
        return list(self._iter_hosts())

    def nmap_target_args(self) -> list[str]:
        """Hand nmap the CIDRs plus --exclude, rather than a huge host list."""
        args = list(self.targets)
        if self.exclude:
            args += ["--exclude", ",".join(self.exclude)]
        return args

    # -- enforcement -----------------------------------------------------

    def is_excluded(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(addr in net for net in self._networks(self.exclude))

    def contains(self, host: str) -> bool:
        """True if `host` is an in-scope IP, or an explicitly allowed hostname."""
        host = (host or "").strip().strip("[]")
        if not host:
            return False
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return host.lower() in self.allow_hostnames
        if self.is_excluded(host):
            return False
        return any(addr in net for net in self._networks(self.targets))

    def assert_host(self, host: str, context: str = "") -> None:
        if not self.contains(host):
            where = f" ({context})" if context else ""
            raise ScopeError(
                f"refusing to touch {host!r}{where}: not in engagement scope. "
                "If this came from scanner output or a redirect, treat it as a "
                "finding to report, not a target to follow."
            )

    def assert_url(self, url: str, context: str = "") -> str:
        """Scope-check a URL before fetching it. Returns the host on success."""
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ScopeError(f"refusing non-HTTP(S) URL {url!r} ({parts.scheme or 'no scheme'})")
        host = (parts.hostname or "").strip()
        if not host:
            raise ScopeError(f"refusing URL with no host: {url!r}")
        self.assert_host(host, context or f"url {url}")
        return host

    def in_window(self, now: dt.datetime | None = None) -> tuple[bool, str]:
        """Check the testing window. Returns (ok, human-readable reason)."""
        a = self.authorization
        if not a.window_start and not a.window_end:
            return True, "no window recorded in scope file"
        now = now or dt.datetime.now(dt.timezone.utc)
        try:
            if a.window_start and now < _parse_ts(a.window_start):
                return False, f"testing window opens {a.window_start}"
            if a.window_end and now > _parse_ts(a.window_end):
                return False, f"testing window closed {a.window_end}"
        except ValueError as exc:
            return False, f"unparseable window in scope file: {exc}"
        return True, "within authorised window"

    def assert_window(self, now: dt.datetime | None = None) -> None:
        ok, why = self.in_window(now)
        if not ok:
            raise ScopeError(
                f"outside the authorised testing window: {why}. "
                "Amend the scope file only with the client's written agreement."
            )

    def summary(self) -> dict:
        ok, why = self.in_window()
        return {
            "engagement": self.engagement,
            "client": self.client,
            "authorization": {
                "reference": self.authorization.reference,
                "authorized_by": self.authorization.authorized_by,
                "window_start": self.authorization.window_start,
                "window_end": self.authorization.window_end,
                "notes": self.authorization.notes,
            },
            "targets": self.targets,
            "exclude": self.exclude,
            "domains": self.domains,
            "host_count": self.host_count(),
            "window_ok": ok,
            "window_note": why,
            "source_path": self.source_path,
        }
