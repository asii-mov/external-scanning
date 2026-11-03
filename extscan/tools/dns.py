"""DNS misconfiguration checks for the domains listed in the scope file.

Three report-only checks run against each `scope.domains` entry: zone transfer
(AXFR) against the zone's authoritative servers, DNSSEC NSEC zone walking
(NSEC3 is recognised, never cracked), and dangling CNAME/MX/NS records that
could allow a subdomain takeover.

Listing a domain authorises enumerating its names, not scanning what they
point to. So every packet goes through `_Client._send`, which allows three
lanes and nothing else:

* resolver: any record type, for names under a scope domain, to the
  configured recursive resolver;
* exists: A/AAAA only, for any name, to the resolver. This answers "does the
  CNAME/MX/NS target exist?" without contacting the target;
* auth: names under the zone an authority was learned for, sent to that
  zone's own nameservers.

Only opcode QUERY is ever encoded. The wire code is stdlib only, like
`snmp.py`, and every network or parse failure becomes a status, never an
exception.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from extscan.models import Finding
from extscan.policy import DnsPolicy
from extscan.resilience import Degradation
from extscan.scope import Scope, ScopeError

SOURCE = "extscan:dns"
STAGE = "recon"


@dataclass(frozen=True)
class CheckResult:
    """What one check learned about one zone, and what it could not cover.

    A dry run gives `planned` results: nothing was sent, so nothing is
    covered or lost. Otherwise `lost` lists each piece of coverage that did
    not happen; the findings from the parts that did run are kept.
    """

    check: str
    zone: str
    findings: tuple[Finding, ...] = ()
    lost: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    artifacts: tuple[tuple[str, str], ...] = ()
    planned: bool = False

    @property
    def component(self) -> str:
        return f"dns:{self.check}:{self.zone}"

    @property
    def covered(self) -> bool:
        return not self.planned and not self.lost

    @property
    def partial(self) -> bool:
        return not self.planned and bool(self.lost)

    def gap(self) -> Degradation | None:
        if not self.partial:
            return None
        check = next(c for c in CHECKS if c.name == self.check)
        return Degradation(stage=STAGE, component=self.component,
                           reason="; ".join(self.lost)[:200],
                           impact=check.impact.format(zone=self.zone),
                           remedy=check.remedy, hosts=[self.zone])

_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "OPT": 41, "DS": 43, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48,
    "NSEC3": 50, "NSEC3PARAM": 51, "AXFR": 252,
}
_TYPE_NAMES = {code: name for name, code in _TYPES.items()}

_QR = 0x8000
_RD = 0x0100
_TC = 0x0200
_DO = 0x8000
_CLASS_IN = 1
_EDNS_PAYLOAD = 1232
_MAX_POINTER_HOPS = 64
_MAX_NAMESERVERS = 8

_RCODES = {0: "ok", 2: "servfail", 3: "nxdomain", 5: "refused", 9: "notauth"}

Status = Literal["ok", "nodata", "nxdomain", "servfail", "refused", "notauth",
                 "timeout", "error"]
_UNANSWERED = frozenset({"timeout", "error", "servfail"})


@dataclass(frozen=True)
class _Record:
    name: str
    type: str
    data: str
    ttl: int


@dataclass(frozen=True)
class _Answer:
    status: Status
    records: tuple[_Record, ...] = ()
    detail: str = ""

    def of(self, rtype: str, owner: str | None = None) -> list[str]:
        return [r.data for r in self.records
                if r.type == rtype and (owner is None or r.name == owner)]


@dataclass(frozen=True)
class _Authority:
    """An authoritative server for one in-scope zone. Only
    `_Client.authorities` builds these, from that zone's own NS answer."""

    zone: str
    host: str
    address: str


def _normalise(name: str) -> str:
    name = name.strip().lower()
    return name[:-1] if name.endswith(".") else name


def _under(name: str, zone: str) -> bool:
    return name == zone or name.endswith("." + zone)


def _encode_name(name: str) -> bytes:
    name = _normalise(name)
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise ValueError(f"bad label {label!r}")
        out += bytes([len(raw)]) + raw
    if len(out) + 1 > 255:
        raise ValueError("name longer than 255 bytes")
    return bytes(out) + b"\x00"


def _encode_query(qid: int, name: str, rtype: str, dnssec: bool, rd: bool) -> bytes:
    # The opcode bits (0x7800) are never set, so every message is a QUERY.
    flags = _RD if rd else 0
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 1 if dnssec else 0)
    question = _encode_name(name) + struct.pack("!HH", _TYPES[rtype], _CLASS_IN)
    if not dnssec:
        return header + question
    opt = b"\x00" + struct.pack("!HHIH", _TYPES["OPT"], _EDNS_PAYLOAD, _DO, 0)
    return header + question + opt


def _read_name(buf: bytes, pos: int) -> tuple[str, int]:
    """Return (name, position after it). Pointers must point backwards and
    are hop-limited, so a hostile packet cannot make this loop."""
    labels: list[str] = []
    resume: int | None = None
    hops = 0
    length = 0
    while True:
        if pos >= len(buf):
            raise ValueError("name runs past the packet")
        size = buf[pos]
        if size & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            target = ((size & 0x3F) << 8) | buf[pos + 1]
            if target >= pos:
                raise ValueError("compression pointer does not point backwards")
            hops += 1
            if hops > _MAX_POINTER_HOPS:
                raise ValueError("compression pointer loop")
            if resume is None:
                resume = pos + 2
            pos = target
            continue
        if size & 0xC0:
            raise ValueError("unsupported label type")
        pos += 1
        if size == 0:
            break
        if pos + size > len(buf):
            raise ValueError("label runs past the packet")
        length += size + 1
        if length > 255:
            raise ValueError("name longer than 255 bytes")
        labels.append(buf[pos:pos + size].decode("ascii", "replace").lower())
        pos += size
    return ".".join(labels), resume if resume is not None else pos


def _read_bitmap(buf: bytes, pos: int, end: int) -> list[str]:
    types: list[str] = []
    while pos < end:
        if pos + 2 > end:
            raise ValueError("truncated type bitmap")
        window, size = buf[pos], buf[pos + 1]
        pos += 2
        if not 1 <= size <= 32 or pos + size > end:
            raise ValueError("bad type bitmap window")
        for i, byte in enumerate(buf[pos:pos + size]):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    code = window * 256 + i * 8 + bit
                    types.append(_TYPE_NAMES.get(code, f"TYPE{code}"))
        pos += size
    return types


def _read_rdata(buf: bytes, pos: int, end: int, rtype: int) -> str:
    def name_at(p: int) -> tuple[str, int]:
        name, after = _read_name(buf, p)
        if after > end:
            raise ValueError("name runs past its record")
        return name, after

    def ints(fmt: str, p: int) -> tuple[tuple[int, ...], int]:
        size = struct.calcsize(fmt)
        if p + size > end:
            raise ValueError("truncated record data")
        return struct.unpack_from(fmt, buf, p), p + size

    def chunk(p: int) -> tuple[bytes, int]:
        if p >= end or p + 1 + buf[p] > end:
            raise ValueError("truncated record data")
        return buf[p + 1:p + 1 + buf[p]], p + 1 + buf[p]

    kind = _TYPE_NAMES.get(rtype)
    if kind == "A" and end - pos == 4:
        return str(ipaddress.IPv4Address(buf[pos:end]))
    if kind == "AAAA" and end - pos == 16:
        return str(ipaddress.IPv6Address(buf[pos:end]))
    if kind in ("A", "AAAA"):
        raise ValueError(f"bad {kind} record length")
    if kind in ("NS", "CNAME", "PTR"):
        return name_at(pos)[0]
    if kind == "MX":
        (pref,), p = ints("!H", pos)
        return f"{pref} {name_at(p)[0] or '.'}"
    if kind == "SOA":
        mname, p = name_at(pos)
        rname, p = name_at(p)
        numbers, _ = ints("!IIIII", p)
        return " ".join([mname, rname, *map(str, numbers)])
    if kind == "NSEC":
        nxt, p = name_at(pos)
        return " ".join([nxt, *_read_bitmap(buf, p, end)])
    if kind in ("NSEC3", "NSEC3PARAM"):
        (alg, flags, iterations), p = ints("!BBH", pos)
        salt, p = chunk(p)
        fields = [str(alg), str(flags), str(iterations), salt.hex() or "-"]
        if kind == "NSEC3":
            digest, p = chunk(p)
            fields.append(base64.b32hexencode(digest).decode().lower().rstrip("="))
            fields += _read_bitmap(buf, p, end)
        return " ".join(fields)
    return buf[pos:end].hex()[:200]


def _decode(packet: bytes, qid: int) -> _Answer:
    """Parse a reply into presentation-form records. Total: any malformed
    input becomes status "error"; it never raises and never loops."""
    try:
        if len(packet) < 12:
            raise ValueError("shorter than a DNS header")
        rid, flags, qdcount, ancount, nscount, _ = struct.unpack_from("!HHHHHH", packet)
        if rid != qid:
            raise ValueError("reply id does not match the query")
        if not flags & _QR:
            raise ValueError("not a response")
        pos = 12
        for _ in range(qdcount):
            _, pos = _read_name(packet, pos)
            pos += 4
        records: list[_Record] = []
        for _ in range(ancount + nscount):
            name, pos = _read_name(packet, pos)
            if pos + 10 > len(packet):
                raise ValueError("truncated record header")
            rtype, _rclass, ttl, rdlength = struct.unpack_from("!HHIH", packet, pos)
            pos += 10
            end = pos + rdlength
            if end > len(packet):
                raise ValueError("record data runs past the packet")
            if rtype != _TYPES["OPT"]:
                records.append(_Record(name, _TYPE_NAMES.get(rtype, f"TYPE{rtype}"),
                                       _read_rdata(packet, pos, end, rtype), ttl))
            pos = end
    except (ValueError, struct.error) as exc:
        return _Answer("error", detail=f"malformed reply: {exc}")
    rcode = flags & 0x000F
    if rcode not in _RCODES:
        return _Answer("error", tuple(records), f"rcode {rcode}")
    status = _RCODES[rcode]
    if status == "ok" and not ancount:
        status = "nodata"
    return _Answer(status, tuple(records))


def _recv_exact(sock: socket.socket, size: int, deadline: float, idle: float) -> bytes:
    data = b""
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(min(idle, remaining))
        piece = sock.recv(size - len(data))
        if not piece:
            break
        data += piece
    return data


def _recv_message(sock: socket.socket, deadline: float, idle: float) -> bytes | None:
    """One length-prefixed TCP message, or None on a clean close before it."""
    head = _recv_exact(sock, 2, deadline, idle)
    if not head:
        return None
    if len(head) < 2:
        raise ConnectionError("connection closed mid-message")
    size = int.from_bytes(head, "big")
    body = _recv_exact(sock, size, deadline, idle)
    if len(body) < size:
        raise ConnectionError("connection closed mid-message")
    return body


def _frame(packet: bytes) -> bytes:
    return struct.pack("!H", len(packet)) + packet


def _family(address: str) -> int:
    return socket.AF_INET6 if ":" in address else socket.AF_INET


def _udp(server: tuple[str, int], packet: bytes, qid: int, timeout: float) -> bytes:
    with socket.socket(_family(server[0]), socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect(server)
        sock.send(packet)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            sock.settimeout(remaining)
            data = sock.recv(65535)
            if len(data) >= 4 and int.from_bytes(data[:2], "big") == qid:
                return data


def _tcp_query(server: tuple[str, int], packet: bytes, qid: int, timeout: float) -> _Answer:
    with socket.create_connection(server, timeout=timeout) as sock:
        sock.sendall(_frame(packet))
        reply = _recv_message(sock, time.monotonic() + timeout, timeout)
    if reply is None:
        return _Answer("error", detail=f"{server[0]} closed the connection without a reply")
    return _decode(reply, qid)


def _axfr(server: tuple[str, int], packet: bytes, qid: int, timeout: float,
          limit: int) -> _Answer:
    """Read an AXFR message stream until the closing SOA, the record limit,
    or an overall deadline, so a server that drips data cannot stall the run."""
    deadline = time.monotonic() + timeout * 20
    records: list[_Record] = []
    with socket.create_connection(server, timeout=timeout) as sock:
        sock.sendall(_frame(packet))
        while True:
            message = _recv_message(sock, deadline, timeout)
            if message is None:
                if not records:
                    # Many servers refuse AXFR by closing the connection.
                    return _Answer("refused", detail="closed the connection without a reply")
                return _Answer("ok", tuple(records), "the transfer ended before its closing SOA")
            part = _decode(message, qid)
            if part.status != "ok":
                if not records:
                    return part
                return _Answer("ok", tuple(records),
                               f"the transfer broke off: {part.detail or part.status}")
            if not records and (not part.records or part.records[0].type != "SOA"):
                return _Answer("error", detail="the transfer did not start with an SOA")
            records.extend(part.records)
            if len(records) >= limit:
                return _Answer("ok", tuple(records[:limit]), f"stopped after {limit} records")
            if len(records) > 1 and records[-1].type == "SOA":
                return _Answer("ok", tuple(records))


def _server(spec: str, port: int) -> tuple[str, int]:
    """"ip", "ip:port", "[v6]:port" or a bare IPv6 address."""
    spec = spec.strip()
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        return host, int(rest.lstrip(":") or port)
    if spec.count(":") == 1:
        host, _, p = spec.partition(":")
        return host, int(p)
    return spec, port


def _system_resolvers(path: str = "/etc/resolv.conf") -> list[str]:
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return []
    return [parts[1] for parts in (line.split() for line in lines)
            if len(parts) >= 2 and parts[0] == "nameserver"]


class _Client:
    """Stdlib DNS client. `_send` is the one place a packet leaves from, and
    it chooses the server itself from the lane, so no caller can aim a query
    at an arbitrary host. Every verb returns an `_Answer`; the only exception
    that escapes is ScopeError."""

    def __init__(self, scope: Scope, policy: DnsPolicy):
        self.scope = scope
        self.policy = policy
        self.resolvers = [_server(s, 53) for s in (policy.resolvers or _system_resolvers())]
        self._cache: dict[tuple[str, str, str], _Answer] = {}
        self._last_send = 0.0

    def lookup(self, name: str, rtype: str) -> _Answer:
        return self._cached("resolver", name, rtype)

    def exists(self, name: str) -> _Answer:
        return self._cached("exists", name, "A")

    def ask(self, auth: _Authority, name: str, rtype: str, dnssec: bool = False) -> _Answer:
        return self._send(name, rtype, "auth", auth, dnssec)

    def authorities(self, zone: str, parent: _Authority | None = None
                    ) -> tuple[list[_Authority], tuple[str, ...]]:
        """The zone's nameservers with an address each, plus the reasons any
        could not be learned. An empty list with no reasons means the name
        is not a delegated zone.

        With `parent`, the NS set comes from the parent zone's referral
        rather than the resolver, which usually answers SERVFAIL for the
        broken delegations a takeover check is looking for."""
        answer = self.ask(parent, zone, "NS") if parent else self.lookup(zone, "NS")
        if answer.status in _UNANSWERED:
            return [], (f"NS lookup for {zone} failed: {answer.detail or answer.status}",)
        found: list[_Authority] = []
        gaps: list[str] = []
        for host in sorted(set(answer.of("NS", zone)))[:_MAX_NAMESERVERS]:
            address = self.exists(host)
            if address.status in _UNANSWERED:
                gaps.append(f"address of nameserver {host} unknown: "
                            f"{address.detail or address.status}")
            elif address.of("A"):
                found.append(_Authority(zone, host, address.of("A")[0]))
        return found, tuple(gaps)

    def _cached(self, lane: str, name: str, rtype: str) -> _Answer:
        key = (lane, _normalise(name), rtype)
        if key not in self._cache:
            answer = self._send(name, rtype, lane)
            if answer.status in ("timeout", "error"):
                return answer
            self._cache[key] = answer
        return self._cache[key]

    def _send(self, name: str, rtype: str, lane: str, auth: _Authority | None = None,
              dnssec: bool = False) -> _Answer:
        if lane == "exists":
            if rtype not in ("A", "AAAA"):
                raise ScopeError(f"refusing {rtype} query for {name!r}: names outside "
                                 "scope may only be checked for existence")
            name = _normalise(name)
        else:
            name = self.scope.assert_dns_name(name, f"dns {rtype} query")
            if lane == "auth" and (auth is None or not _under(name, auth.zone)):
                raise ScopeError(f"refusing to ask a nameserver of "
                                 f"{auth.zone if auth else '?'} about {name!r}")
        servers = [(auth.address, self.policy.port)] if auth else self.resolvers
        if not servers:
            return _Answer("error", detail="no DNS resolver configured")
        answer = _Answer("error", detail="not sent")
        for server in servers:
            for _attempt in range(self.policy.retries + 1):
                answer = self._exchange(server, name, rtype, lane, dnssec)
                if answer.status != "timeout":
                    break
            if answer.status not in ("timeout", "error"):
                return answer
        return answer

    def _exchange(self, server: tuple[str, int], name: str, rtype: str, lane: str,
                  dnssec: bool) -> _Answer:
        wait = self._last_send + self.policy.query_interval_sec - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last_send = time.monotonic()
        qid = int.from_bytes(os.urandom(2), "big")
        where = f"{server[0]}:{server[1]}"
        try:
            packet = _encode_query(qid, name, rtype, dnssec, rd=lane != "auth")
        except ValueError as exc:
            return _Answer("error", detail=f"{name!r} cannot be encoded: {exc}")
        timeout = self.policy.timeout_sec
        try:
            if rtype == "AXFR":
                return _axfr(server, packet, qid, timeout, self.policy.max_axfr_records)
            reply = _udp(server, packet, qid, timeout)
            if struct.unpack_from("!H", reply, 2)[0] & _TC:
                return _tcp_query(server, packet, qid, timeout)
            return _decode(reply, qid)
        except TimeoutError:
            return _Answer("timeout", detail=f"{where} did not answer {rtype} {name}")
        except OSError as exc:
            return _Answer("error", detail=f"{where}: {exc.strerror or exc}")


def _encodable(name: str) -> bool:
    try:
        _encode_name(name)
    except ValueError:
        return False
    return True


@dataclass
class _Zone:
    zone: str
    client: _Client
    policy: DnsPolicy
    names: set[str]
    authorities: list[_Authority] = field(default_factory=list)
    authority_gaps: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Check:
    name: str
    needs_authorities: bool
    impact: str
    remedy: str
    run: Callable[[_Zone], CheckResult]


def audit_zone(scope: Scope, zone: str, known_names: list[str], policy: DnsPolicy, *,
               dry_run: bool = False) -> list[CheckResult]:
    """Run every enabled check against one in-scope zone, one result each.

    Network trouble never raises: it becomes `lost` entries. Raises
    ValueError for an unknown `policy.skip` name and ScopeError for a zone
    outside scope.domains, both before any packet. Names in `known_names`
    outside the zone are dropped, not queried. A dry run opens no socket.
    """
    unknown = sorted(set(policy.skip) - {c.name for c in CHECKS})
    if unknown:
        raise ValueError(f"unknown dns.skip check(s) {unknown}; "
                         f"choose from {[c.name for c in CHECKS]}")
    zone = scope.assert_dns_name(zone, "dns audit")
    enabled = [c for c in CHECKS if c.name not in policy.skip]
    if dry_run:
        return [CheckResult(c.name, zone, planned=True) for c in enabled]
    client = _Client(scope, policy)
    authorities, gaps = client.authorities(zone)
    names = {n for n in map(_normalise, known_names) if _under(n, zone) and _encodable(n)}
    z = _Zone(zone, client, policy, names | {zone}, authorities, gaps)
    results = []
    for check in enabled:
        if check.needs_authorities and not z.authorities:
            result = CheckResult(check.name, zone, lost=gaps)
        else:
            result = check.run(z)
        z.names |= {n for n in result.names if _encodable(n)}
        results.append(result)
    return results


def _finding(z: _Zone, check: str, title: str, severity: str, **fields) -> Finding:
    tags = ["dns", check, *fields.pop("tags", [])]
    fields["evidence"] = fields.get("evidence", "")[:4000]
    return Finding(title=title, severity=severity, host=z.zone, port=None, proto="dns",
                   source=SOURCE, tags=tags, **fields)


def _candidate(z: _Zone, title: str, severity: str, description: str,
               evidence: str) -> Finding:
    return _finding(
        z, "takeover", title, severity, description=description, evidence=evidence,
        recommendation="Remove the record if the resource behind it is gone, or "
                       "re-create the resource in an account the client controls.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
        review_required=True, confidence="tentative", tags=["takeover-candidate"],
        review_reason="Confirm with the client that the target is unclaimed. extscan "
                      "only read DNS; it did not contact the target or try to claim it.")


def _ask_any(z: _Zone, name: str, rtype: str, dnssec: bool = False
             ) -> tuple[_Authority | None, _Answer]:
    answer = _Answer("error", detail=f"no nameserver of {z.zone} answered")
    for auth in z.authorities:
        answer = z.client.ask(auth, name, rtype, dnssec)
        if answer.status not in _UNANSWERED:
            return auth, answer
    return None, answer


def _axfr_check(z: _Zone) -> CheckResult:
    findings: list[Finding] = []
    lost = list(z.authority_gaps)
    names: set[str] = set()
    artifacts: list[tuple[str, str]] = []
    for auth in z.authorities:
        answer = z.client.ask(auth, z.zone, "AXFR")
        if answer.status in ("refused", "notauth", "nxdomain", "nodata"):
            continue
        if answer.status != "ok":
            lost.append(f"AXFR from {auth.host} ({auth.address}): "
                        f"{answer.detail or answer.status}")
            continue
        names |= {r.name for r in answer.records if _under(r.name, z.zone)}
        lines = [f"{r.name}. {r.ttl} IN {r.type} {r.data}" for r in answer.records]
        artifacts.append((f"dns-axfr-{z.zone}-{auth.host}.txt", "\n".join(lines) + "\n"))
        note = f" ({answer.detail})" if answer.detail else ""
        findings.append(_finding(
            z, "axfr", f"Zone transfer (AXFR) of {z.zone} allowed by {auth.host}", "medium",
            description=f"The nameserver {auth.host} ({auth.address}) answered a full zone "
                        f"transfer request for {z.zone} from an unauthenticated external "
                        f"host and returned {len(answer.records)} record(s){note}. A zone "
                        "transfer hands over every name in the zone, including hosts that "
                        "are linked from nowhere, which shortcuts reconnaissance.",
            evidence="\n".join(lines[:60]),
            recommendation="Allow AXFR only from the secondary nameservers' addresses, "
                           "ideally with TSIG keys (BIND `allow-transfer`, the Zone "
                           "Transfers tab in Windows DNS).",
            references=["https://www.rfc-editor.org/rfc/rfc5936"]))
    return CheckResult("axfr", z.zone, tuple(findings), tuple(lost), tuple(sorted(names)),
                       tuple(artifacts))


def _nsec_walk(z: _Zone) -> CheckResult:
    auth, param = _ask_any(z, z.zone, "NSEC3PARAM", dnssec=True)
    if auth is None:
        return CheckResult("nsec-walk", z.zone,
                           lost=(f"DNSSEC probe failed: {param.detail or param.status}",))
    if param.of("NSEC3PARAM", z.zone):
        alg, flags, iterations, salt = param.of("NSEC3PARAM", z.zone)[0].split()[:4]
        return CheckResult("nsec-walk", z.zone, (_finding(
            z, "nsec-walk", f"{z.zone} uses DNSSEC NSEC3 denial of existence", "info",
            description="NSEC3 hashes the names in its denial chain, so the zone cannot "
                        "be listed by walking it. The hashes can still be collected and "
                        "guessed offline against a word list; extscan does not do that.",
            evidence=f"NSEC3PARAM algorithm {alg}, flags {flags}, "
                     f"iterations {iterations}, salt {salt}",
            references=["https://www.rfc-editor.org/rfc/rfc5155",
                        "https://www.rfc-editor.org/rfc/rfc9276"]),))
    answer = z.client.ask(auth, z.zone, "NSEC", dnssec=True)
    if answer.status in _UNANSWERED:
        return CheckResult("nsec-walk", z.zone,
                           lost=(f"NSEC query to {auth.host}: {answer.detail or answer.status}",))
    if not answer.of("NSEC", z.zone):
        return CheckResult("nsec-walk", z.zone)
    walked, lost = _walk(z, auth, answer)
    finding = _finding(
        z, "nsec-walk", f"DNSSEC NSEC records let anyone list the names in {z.zone}", "low",
        description=f"{z.zone} is signed with NSEC records. Each one names the next name "
                    "in the zone, so following the chain lists the zone much like a zone "
                    f"transfer. extscan walked {len(walked)} name(s) from {auth.host}"
                    + (f", then stopped: {lost}." if lost else "."),
        evidence="\n".join(walked),
        recommendation="If the zone holds names that should not be listed, re-sign it "
                       "with NSEC3, or use online signing with minimal denial answers.",
        references=["https://www.rfc-editor.org/rfc/rfc4034#section-4",
                    "https://www.rfc-editor.org/rfc/rfc5155"])
    return CheckResult("nsec-walk", z.zone, (finding,), (lost,) if lost else (),
                       tuple(walked), ((f"dns-nsec-{z.zone}.txt", "\n".join(walked) + "\n"),))


def _walk(z: _Zone, auth: _Authority, answer: _Answer) -> tuple[list[str], str]:
    """Follow next-owner links from the apex. A link out of the zone, a loop,
    a timeout or the step bound ends the walk; the name it stopped at is
    never queried."""
    walked = [z.zone]
    current = z.zone
    for _ in range(z.policy.max_walk_steps):
        links = answer.of("NSEC", current)
        if not links:
            return walked, f"no NSEC record came back for {current}"
        nxt = _normalise(links[0].split()[0])
        if nxt == z.zone:
            return walked, ""
        if not _under(nxt, z.zone):
            return walked, f"the NSEC chain left the zone at {current} -> {nxt}"
        if nxt in walked:
            return walked, f"the NSEC chain loops at {nxt}"
        walked.append(nxt)
        current = nxt
        answer = z.client.ask(auth, current, "NSEC", dnssec=True)
        if answer.status in _UNANSWERED:
            return walked, f"no answer for {current}: {answer.detail or answer.status}"
    return walked, f"stopped after dns.max_walk_steps={z.policy.max_walk_steps} links"


def _dangling_cname(z: _Zone, name: str) -> tuple[list[Finding], bool]:
    answer = z.client.lookup(name, "A")
    if answer.status in _UNANSWERED:
        return [], False
    chain = [r for r in answer.records if r.type == "CNAME"]
    if answer.status != "nxdomain" or not chain:
        return [], True
    target = _normalise(chain[-1].data)
    suffix = next((s for s in CLAIMABLE_SUFFIXES if _under(target, s)), "")
    where = (f"{suffix} is a provider where anyone can usually create that name"
             if suffix else "if the resource or domain behind it can be registered by "
                            "someone else")
    return [_candidate(
        z, f"Dangling CNAME {name} -> {target}", "medium" if suffix else "low",
        description=f"{name} is an alias for {target}, which does not exist (NXDOMAIN). "
                    f"Whoever creates {target} would control what {name} serves; "
                    f"{where}.",
        evidence="\n".join(f"{r.name} CNAME {r.data}" for r in chain)
                 + f"\n{target}: NXDOMAIN")], True


def _dangling_mx(z: _Zone, name: str) -> tuple[list[Finding], bool]:
    answer = z.client.lookup(name, "MX")
    if answer.status in _UNANSWERED:
        return [], False
    findings, answered = [], True
    for host in sorted({d.split()[-1] for d in answer.of("MX", name)} - {"."}):
        target = z.client.exists(host)
        if target.status in _UNANSWERED:
            answered = False
        elif target.status == "nxdomain":
            findings.append(_candidate(
                z, f"Dangling MX {name} -> {host}", "low",
                description=f"{name} lists {host} as a mail exchanger, and {host} does not "
                            "exist. If its domain can be registered, whoever registers it "
                            f"can receive mail sent to {name}.",
                evidence=f"{name} MX {host}\n{host}: NXDOMAIN"))
    return findings, answered


def _dangling_ns(z: _Zone, name: str) -> tuple[list[Finding], bool]:
    """Lapsed nameserver domains and lame delegations, for the apex and for
    any name the apex's own servers refer elsewhere."""
    if name == z.zone:
        parent, answer = None, z.client.lookup(name, "NS")
    elif z.authorities:
        parent, answer = _ask_any(z, name, "NS")
    else:
        return [], not z.authority_gaps
    if answer.status in _UNANSWERED:
        return [], False
    hosts = sorted(set(answer.of("NS", name)))
    findings, answered = [], True
    for host in hosts:
        target = z.client.exists(host)
        if target.status in _UNANSWERED:
            answered = False
        elif target.status == "nxdomain":
            findings.append(_candidate(
                z, f"Delegation of {name} to missing nameserver {host}", "medium",
                description=f"{name} is delegated to {host}, which does not exist. If the "
                            f"domain of {host} has lapsed, whoever registers it controls "
                            f"the {name} zone.",
                evidence=f"{name} NS {host}\n{host}: NXDOMAIN"))
    if not hosts:
        return findings, answered
    auths, gaps = ((z.authorities, z.authority_gaps) if parent is None
                   else z.client.authorities(name, parent))
    statuses = {a.host: z.client.ask(a, name, "SOA").status for a in auths}
    if gaps or any(s in ("timeout", "error") for s in statuses.values()):
        return findings, False
    if statuses and all(s in _LAME for s in statuses.values()):
        findings.append(_candidate(
            z, f"Lame delegation of {name}", "medium",
            description=f"{name} is delegated to {', '.join(sorted(statuses))}, and no "
                        "nameserver in that set answers for it. A deleted hosted zone "
                        "looks like this (for example on Route 53 or Azure DNS); at some "
                        f"providers anyone can create the zone again and take over {name}.",
            evidence="\n".join(f"SOA {name} @ {h}: {s.upper()}"
                               for h, s in sorted(statuses.items()))))
    return findings, answered


def _takeover(z: _Zone) -> CheckResult:
    ordered = [z.zone, *sorted(z.names - {z.zone})]
    checked, over = ordered[:z.policy.max_names], ordered[z.policy.max_names:]
    findings: list[Finding] = []
    unanswered: list[str] = []
    for name in checked:
        answered = True
        for probe in (_dangling_cname, _dangling_mx, _dangling_ns):
            found, ok = probe(z, name)
            findings += found
            answered = answered and ok
        if not answered:
            unanswered.append(name)
    lost = []
    if unanswered:
        lost.append(f"{len(unanswered)} of {len(checked)} name(s) got no answer "
                    f"(first: {unanswered[0]})")
    if over:
        lost.append(f"{len(over)} name(s) over dns.max_names={z.policy.max_names} "
                    "were not checked")
    return CheckResult("takeover", z.zone, tuple(findings), tuple(lost))


_LAME = frozenset({"refused", "servfail", "notauth"})

# From can-i-take-over-xyz: suffixes where a dangling CNAME is often claimable.
CLAIMABLE_SUFFIXES = (
    "s3.amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "azurewebsites.net",
    "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net",
    "azureedge.net", "herokuapp.com", "herokudns.com", "github.io", "netlify.app",
    "fastly.net", "ghost.io", "surge.sh", "readthedocs.io", "pantheonsite.io",
    "wordpress.com", "zendesk.com", "myshopify.com", "bitbucket.io",
)

# In run order: the two discovery checks feed the names they find into takeover.
CHECKS: tuple[_Check, ...] = (
    _Check("axfr", True,
           "Zone transfer was not tested against every nameserver of {zone}.",
           "Check TCP/53 reachability to the nameservers, then re-run `extscan recon`.",
           _axfr_check),
    _Check("nsec-walk", True,
           "DNSSEC zone walking was not completed for {zone}.",
           "Raise dns.max_walk_steps or check reachability, then re-run `extscan recon`.",
           _nsec_walk),
    _Check("takeover", False,
           "Some names under {zone} were not checked for dangling CNAME, MX or NS records.",
           "Check the resolver (dns.resolvers), then re-run `extscan recon`.",
           _takeover),
)
