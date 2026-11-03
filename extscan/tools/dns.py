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
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from extscan.policy import DnsPolicy
from extscan.scope import Scope, ScopeError

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


def _recv_exact(sock: socket.socket, size: int, deadline: float) -> bytes:
    data = b""
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(remaining)
        piece = sock.recv(size - len(data))
        if not piece:
            break
        data += piece
    return data


def _recv_message(sock: socket.socket, deadline: float) -> bytes | None:
    """One length-prefixed TCP message, or None on a clean close before it."""
    head = _recv_exact(sock, 2, deadline)
    if not head:
        return None
    if len(head) < 2:
        raise ConnectionError("connection closed mid-message")
    size = int.from_bytes(head, "big")
    body = _recv_exact(sock, size, deadline)
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
        reply = _recv_message(sock, time.monotonic() + timeout)
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
            message = _recv_message(sock, deadline)
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
