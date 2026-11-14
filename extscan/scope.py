"""Engagement scope: who authorised this, what may be touched, what may not.

Two jobs here, and the second is the one that matters once the pipeline starts
looping. First, refuse to run at all without a scope file: either JSON, which
records the written authorisation, or a plain list of targets, one per line,
where the person running the scan is trusted to hold it. Second, re-check
every single target immediately before it is touched -- including targets
derived from tool output.

That second check is not paranoia. Leads come from scanner results, HTTP
redirects and OpenAPI `servers` blocks, all of which are controlled by the
thing being scanned. A host that redirects to 169.254.169.254 or to a
competitor's netblock must not drag the scan along with it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ScopeError(Exception):
    """Raised when something would be touched that is not authorised."""


# Listed explicitly rather than using ipaddress' .is_private, which also covers
# the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) and RFC 2544 benchmarking space. Those are not internal
# space, and rejecting them would reject the example scope files and every
# write-up that uses documentation addresses.
_INTERNAL_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


SCOPE_KEYS = frozenset({
    "engagement", "client", "authorization", "targets", "exclude",
    "allow_hostnames", "domains", "max_hosts", "allow_private",
})
AUTHORIZATION_KEYS = frozenset({
    "reference", "authorized_by", "window_start", "window_end", "notes",
})


def _reject_unknown(data: dict, known: frozenset, where: str) -> None:
    unknown = sorted(k for k in data if k not in known and not str(k).startswith("//"))
    if unknown:
        raise ScopeError(
            f"{where}: unknown key(s) {', '.join(repr(k) for k in unknown)}. "
            f"Known keys: {', '.join(sorted(known))}. A misspelt key is refused "
            "because it would otherwise be ignored without a word.")


# A range is refused above this size whatever max_hosts says: it is expanded
# address by address, and a slip such as 10.0.0.1-11.0.0.1 must fail at once.
_MAX_RANGE = 65536


def expand_target(spec: str) -> list[str]:
    """One target as written -> the entries `Scope` works with.

    An address or a CIDR range passes through. A range, `12.1.1.1-100` (the
    last octet) or `12.1.1.1-12.1.2.20`, becomes its addresses one by one,
    because both ends of a range are meant, and a CIDR block would drop its
    network and broadcast addresses.
    """
    spec = spec.strip()
    if "-" not in spec:
        return [spec]
    first_text, _, last_text = (part.strip() for part in spec.partition("-"))
    try:
        first = ipaddress.ip_address(first_text)
        if last_text.isdigit() and first.version == 4:
            last = ipaddress.ip_address(first_text.rsplit(".", 1)[0] + "." + last_text)
        else:
            last = ipaddress.ip_address(last_text)
    except ValueError as exc:
        raise ScopeError(f"bad target/exclude entry {spec!r}: {exc}. A range is written "
                         "12.1.1.1-100 or 12.1.1.1-12.1.2.20") from exc
    if first.version != last.version or int(last) < int(first):
        raise ScopeError(f"bad target/exclude entry {spec!r}: the range ends before it starts")
    size = int(last) - int(first) + 1
    if size > _MAX_RANGE:
        raise ScopeError(f"range {spec!r} holds {size} addresses; write a range "
                         f"over {_MAX_RANGE} as CIDR blocks")
    return [str(first + i) for i in range(size)]


def _expand_all(specs: list[str]) -> list[str]:
    return [entry for spec in specs for entry in expand_target(str(spec))]


def _is_internal(net: ipaddress._BaseNetwork) -> bool:
    return any(
        net.version == internal.version and net.overlaps(internal)
        for internal in _INTERNAL_NETS
    )


def is_internal_address(address: str) -> bool:
    try:
        return _is_internal(ipaddress.ip_network(address))
    except ValueError:
        return False


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
    domains: list[str] = field(default_factory=list)
    max_hosts: int = 1024
    allow_private: bool = False
    source_path: str = ""
    sha256: str = ""            # of the scope file as loaded; "" when built in code

    @classmethod
    def load(cls, path: str | Path) -> Scope:
        p = Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}")
        raw = p.read_text()
        if not raw.lstrip().startswith("{"):
            return cls._load_target_list(p, raw)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ScopeError(f"scope file {p} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ScopeError(f"scope file {p} must hold a JSON object")
        # A misspelt key must not be read as "not set": `exlude` would scan
        # the hosts someone asked to leave alone. Keys starting with // are
        # comments.
        _reject_unknown(data, SCOPE_KEYS, f"scope file {p}")
        for key in ("targets", "exclude", "allow_hostnames", "domains"):
            value = data.get(key, [])
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ScopeError(f"scope file {p}: `{key}` must be a list of strings")
        if "authorization" not in data:
            raise ScopeError(
                f"{p} has no `authorization` block. extscan will not scan a "
                "target without a recorded sign-off; see examples/scope.example.json"
            )
        if not data.get("targets"):
            raise ScopeError(f"{p} lists no targets")
        if not isinstance(data["authorization"], dict):
            raise ScopeError(f"scope file {p}: `authorization` must be an object")
        _reject_unknown(data["authorization"], AUTHORIZATION_KEYS,
                        f"scope file {p}, authorization")
        scope = cls(
            engagement=str(data.get("engagement", "unnamed engagement")),
            client=str(data.get("client", "")),
            authorization=Authorization.from_dict(data["authorization"]),
            targets=_expand_all(data["targets"]),
            exclude=_expand_all(data.get("exclude", [])),
            allow_hostnames=[h.lower() for h in data.get("allow_hostnames", [])],
            domains=[d.lower().strip().rstrip(".") for d in data.get("domains", [])],
            max_hosts=int(data.get("max_hosts", 1024)),
            allow_private=bool(data.get("allow_private", False)),
            source_path=str(p),
            sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )
        scope.validate()
        return scope

    @classmethod
    def _load_target_list(cls, p: Path, raw: str) -> Scope:
        """A plain-text scope: one address, CIDR range or range per line.

        `#` starts a comment and blank lines are skipped. The file records
        no authorisation: whoever runs the scan is trusted to list only
        ranges they are authorised to test. Everything a JSON scope can set
        beyond targets keeps its default, so internal address space and
        more than 1024 hosts are still refused.
        """
        targets: list[str] = []
        for number, line in enumerate(raw.splitlines(), 1):
            for entry in line.split("#", 1)[0].replace(",", " ").split():
                try:
                    expanded = expand_target(entry)
                    for spec in expanded:
                        ipaddress.ip_network(spec, strict=False)
                except (ScopeError, ValueError) as exc:
                    raise ScopeError(
                        f"scope file {p}, line {number}: {entry!r} is not an address, "
                        f"a CIDR range or a range such as 12.1.1.1-100 ({exc})") from exc
                targets += expanded
        if not targets:
            raise ScopeError(f"{p} lists no targets")
        scope = cls(
            engagement=p.stem,
            client="",
            authorization=Authorization(reference="", authorized_by=""),
            targets=list(dict.fromkeys(targets)),
            source_path=str(p),
            sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )
        try:
            scope.validate()
        except ScopeError as exc:
            raise ScopeError(
                f"{exc} A plain list of targets cannot change that setting; use a "
                "JSON scope file (examples/scope.example.json).") from exc
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
        for label, text in (("window_start", self.authorization.window_start),
                            ("window_end", self.authorization.window_end)):
            if text:
                try:
                    _parse_ts(text)
                except ValueError as exc:
                    raise ScopeError(f"authorization.{label} {text!r} is not a date and "
                                     f"time such as 2026-11-01T00:00:00Z: {exc}") from exc
        # Counted from the network sizes first: walking a mistyped /8 or an
        # IPv6 /64 address by address would hang before it could be refused.
        upper = sum(net.num_addresses for net in self._networks(self.targets))
        if upper > max(self.max_hosts, 0) + sum(
                net.num_addresses for net in self._networks(self.exclude)) + 2 * len(self.targets):
            raise ScopeError(
                f"scope expands to about {upper} addresses, over max_hosts="
                f"{self.max_hosts}. Raise max_hosts deliberately or narrow the targets.")
        n = self.host_count()
        if n > self.max_hosts:
            raise ScopeError(
                f"scope expands to {n} hosts, over max_hosts={self.max_hosts}. "
                "Raise max_hosts deliberately or narrow the targets."
            )

    @staticmethod
    def _networks(specs: list[str]) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(s, strict=False) for s in specs]

    def host_count(self) -> int:
        return sum(1 for _ in self._iter_hosts())

    def _iter_hosts(self):
        seen: set[str] = set()
        for net in self._networks(self.targets):
            for addr in net.hosts():
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

    def assert_resolves_in_bounds(self, host: str, context: str = "",
                                  resolve=None) -> None:
        """Check where an allowed host name points before connecting to it.

        `allow_hostnames` passes a name, and the connection then goes to
        whatever DNS answers, which the scope file never saw. So the answer
        is checked: an excluded address is refused, and so is internal
        address space (loopback, RFC 1918, link-local and with it the cloud
        metadata service) unless the scope allows private targets. A name
        that points outside `targets` is allowed, because that is what
        `allow_hostnames` is for. A name that does not resolve is left for
        the request itself to fail on. IP literals pass straight through.
        """
        host = (host or "").strip().strip("[]")
        try:
            ipaddress.ip_address(host)
            return
        except ValueError:
            pass
        try:
            infos = (resolve or socket.getaddrinfo)(host, None)
        except OSError:
            return
        where = f" ({context})" if context else ""
        for info in infos:
            address = str(info[4][0]).split("%")[0]
            if self.is_excluded(address):
                raise ScopeError(f"refusing {host!r}{where}: it resolves to {address}, "
                                 "which the scope file excludes")
            if not self.allow_private and is_internal_address(address):
                raise ScopeError(
                    f"refusing {host!r}{where}: it resolves to {address}, which is "
                    "internal address space, and scope.allow_private is false")

    def assert_dns_name(self, name: str, context: str = "") -> str:
        """Gate a DNS query name. Returns the name normalised, or raises.

        A name passes when it is a `domains` entry or sits under one at a
        label boundary, so `evilexample.com` is not under `example.com`.
        This is consent to enumerate names only. It never makes the
        addresses those names resolve to scannable.
        """
        normal = (name or "").strip().lower()
        if normal.endswith("."):
            normal = normal[:-1]
        if normal and any(normal == d or normal.endswith("." + d) for d in self.domains):
            return normal
        where = f" ({context})" if context else ""
        raise ScopeError(
            f"refusing DNS query for {name!r}{where}: not under any scope domain. "
            "A name found in a DNS answer is a finding to report, not a zone to query."
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
            "sha256": self.sha256,
            "allow_hostnames": self.allow_hostnames,
            "allow_private": self.allow_private,
        }

    def changes_since(self, recorded: dict) -> list[str]:
        """What differs between this scope and the summary stored when the
        run was created, in words. Empty when nothing that decides what may
        be touched has changed."""
        if not recorded:
            return []
        out = []
        for key, label in (("targets", "targets"), ("exclude", "exclusions"),
                           ("domains", "domains"), ("allow_hostnames", "allowed host names")):
            if key not in recorded:
                continue        # a run made before this field was stored
            before, now = set(recorded[key] or []), set(getattr(self, key))
            if now - before:
                out.append(f"{label} added: {', '.join(sorted(now - before))}")
            if before - now:
                out.append(f"{label} removed: {', '.join(sorted(before - now))}")
        if "allow_private" in recorded and bool(recorded["allow_private"]) != self.allow_private:
            out.append(f"allow_private is now {str(self.allow_private).lower()}")
        old_auth = recorded.get("authorization") or {}
        for key in ("reference", "authorized_by", "window_start", "window_end"):
            if key in old_auth and old_auth[key] != getattr(self.authorization, key):
                out.append(f"authorization.{key} changed from {old_auth[key]!r} to "
                           f"{getattr(self.authorization, key)!r}")
        return out
