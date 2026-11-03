"""DNS checks against a loopback fake server. No test here sends a packet
anywhere but 127.0.0.1.

FakeDns has its own small encoder, independent of extscan's codec, so a bug
in one cannot hide a matching bug in the other.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
import time
import unittest
from collections.abc import Callable
from dataclasses import dataclass

from extscan.policy import DnsPolicy
from extscan.scope import Authorization, Scope, ScopeError
from extscan.tools import dns

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "AAAA": 28, "OPT": 41,
         "NSEC": 47, "NSEC3": 50, "NSEC3PARAM": 51, "AXFR": 252}
TYPE_NAMES = {code: name for name, code in TYPES.items()}

APEX = "lab.test"
SOA = ("lab.test", "SOA", "ns1.lab.test hostmaster.lab.test 1 3600 600 86400 300")
ZONE = [
    SOA,
    ("lab.test", "NS", "ns1.lab.test"),
    ("ns1.lab.test", "A", "127.0.0.1"),
    ("lab.test", "MX", "10 mail.lab.test"),
    ("mail.lab.test", "A", "192.0.2.25"),
    ("www.lab.test", "A", "192.0.2.80"),
]


def wire_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    return b"".join(bytes([len(label)]) + label.encode()
                    for label in name.split(".")) + b"\x00"


def bitmap(types: list[str]) -> bytes:
    codes = sorted(TYPES[t] for t in types)
    bits = bytearray(codes[-1] // 8 + 1)
    for code in codes:
        bits[code // 8] |= 0x80 >> (code % 8)
    return bytes([0, len(bits)]) + bytes(bits)


def rdata(rtype: str, data: str) -> bytes:
    fields = data.split()
    if rtype == "A":
        return socket.inet_aton(data)
    if rtype in ("NS", "CNAME"):
        return wire_name(data)
    if rtype == "MX":
        return struct.pack("!H", int(fields[0])) + wire_name(fields[1])
    if rtype == "SOA":
        return (wire_name(fields[0]) + wire_name(fields[1])
                + struct.pack("!IIIII", *map(int, fields[2:])))
    if rtype == "NSEC":
        return wire_name(fields[0]) + bitmap(fields[1:])
    if rtype == "NSEC3PARAM":
        salt = bytes.fromhex(fields[3]) if fields[3] != "-" else b""
        return struct.pack("!BBHB", *map(int, fields[:3]), len(salt)) + salt
    raise ValueError(rtype)


def rr(owner: str, rtype: str, data: str, qname: str) -> bytes:
    # Owners equal to the question name are compressed, as real servers do.
    name = b"\xc0\x0c" if owner == qname else wire_name(owner)
    body = rdata(rtype, data)
    return name + struct.pack("!HHIH", TYPES[rtype], 1, 300, len(body)) + body


@dataclass(frozen=True)
class Query:
    name: str
    qtype: str
    proto: str
    opcode: int
    rd: bool
    do: bool


def parse_query(packet: bytes) -> tuple[int, Query]:
    qid, flags, _qd, _an, _ns, arcount = struct.unpack_from("!HHHHHH", packet)
    pos, labels = 12, []
    while packet[pos]:
        labels.append(packet[pos + 1:pos + 1 + packet[pos]].decode())
        pos += 1 + packet[pos]
    qtype = struct.unpack_from("!H", packet, pos + 1)[0]
    pos += 5
    do = False
    if arcount:
        do = bool(struct.unpack_from("!HHIH", packet, pos + 1)[2] & 0x8000)
    return qid, Query(".".join(labels).lower(), TYPE_NAMES.get(qtype, f"TYPE{qtype}"),
                      "", (flags >> 11) & 0xF, bool(flags & 0x0100), do)


def response(qid: int, q: Query, rcode: int = 0, answer=(), authority=(),
             tc: bool = False) -> bytes:
    flags = 0x8000 | 0x0400 | 0x0080 | rcode | (0x0200 if tc else 0)
    flags |= 0x0100 if q.rd else 0
    header = struct.pack("!HHHHHH", qid, flags, 1, len(answer), len(authority), 0)
    question = wire_name(q.name) + struct.pack("!HH", TYPES.get(q.qtype, 255), 1)
    return header + question + b"".join(rr(*r, q.name) for r in (*answer, *authority))


class FakeDns:
    """Resolver and authority in one, on UDP and TCP at the same loopback port.

    `axfr` is True (serve the zone), False (REFUSED) or "silent" (accept the
    connection, never reply). `silent` drops every query, `truncate` sets TC
    on every UDP reply, `refuse` holds (name, type) pairs answered REFUSED,
    and `raw(qid, query)` may return replacement bytes for a reply.
    """

    def __init__(self, records=ZONE, *, axfr=False, silent=False, truncate=False,
                 refuse=(), raw: Callable[[int, Query], bytes | None] | None = None):
        self.records = [tuple(r) for r in records]
        self.axfr, self.silent, self.truncate = axfr, silent, truncate
        self.refuse = set(refuse)
        self.raw = raw
        self.queries: list[Query] = []
        self._stop = threading.Event()
        self.udp, self.tcp = self._bind()
        self.port = self.udp.getsockname()[1]

    @staticmethod
    def _bind():
        for _ in range(20):
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("127.0.0.1", 0))
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                tcp.bind(("127.0.0.1", udp.getsockname()[1]))
            except OSError:
                udp.close()
                tcp.close()
                continue
            tcp.listen(8)
            return udp, tcp
        raise RuntimeError("no free port for both UDP and TCP")

    def __enter__(self):
        for target in (self._serve_udp, self._serve_tcp):
            threading.Thread(target=target, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.udp.close()
        self.tcp.close()

    def policy(self, **overrides) -> DnsPolicy:
        settings = {"resolvers": [f"127.0.0.1:{self.port}"], "port": self.port,
                    "timeout_sec": 0.5, "retries": 0, "query_interval_sec": 0.0}
        settings.update(overrides)
        return DnsPolicy(**settings)

    def asked(self, qtype: str | None = None) -> list[str]:
        return [q.name for q in self.queries if qtype is None or q.qtype == qtype]

    def _serve_udp(self):
        self.udp.settimeout(0.1)
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            reply = self._handle(data, "udp")
            if reply:
                with contextlib.suppress(OSError):
                    self.udp.sendto(reply[0], addr)

    def _serve_tcp(self):
        self.tcp.settimeout(0.1)
        while not self._stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._tcp_conn, args=(conn,), daemon=True).start()

    def _tcp_conn(self, conn: socket.socket):
        with conn:
            conn.settimeout(2)
            try:
                size = int.from_bytes(conn.recv(2), "big")
                data = b""
                while len(data) < size:
                    data += conn.recv(size - len(data))
                for message in self._handle(data, "tcp") or []:
                    conn.sendall(struct.pack("!H", len(message)) + message)
                if self.silent or (self.axfr == "silent" and b"\x00\xfc\x00\x01" in data):
                    self._stop.wait(3)
            except OSError:
                pass

    def _handle(self, data: bytes, proto: str) -> list[bytes] | None:
        qid, q = parse_query(data)
        q = Query(q.name, q.qtype, proto, q.opcode, q.rd, q.do)
        self.queries.append(q)
        if self.silent:
            return None
        if self.raw:
            crafted = self.raw(qid, q)
            if crafted is not None:
                return [crafted]
        if q.qtype == "AXFR":
            return self._transfer(qid, q)
        if proto == "udp" and self.truncate:
            return [response(qid, q, tc=True)]
        rcode, answer, authority = self.resolve(q)
        return [response(qid, q, rcode, answer, authority)]

    def _transfer(self, qid: int, q: Query) -> list[bytes] | None:
        if self.axfr == "silent" or q.proto != "tcp":
            return None
        if not self.axfr:
            return [response(qid, q, rcode=5)]
        body = [r for r in self.records if dns._under(r[0], APEX) and r != SOA]
        half = len(body) // 2
        return [response(qid, q, answer=[SOA, *body[:half]]),
                response(qid, q, answer=[*body[half:], SOA])]

    def resolve(self, q: Query):
        if (q.name, q.qtype) in self.refuse:
            return 5, [], []
        name, chain = q.name, []
        for _ in range(8):
            if not q.rd and name != APEX:
                cut = self._delegation(name)
                if cut:
                    return 0, [], cut
            owned = [r for r in self.records if r[0] == name]
            hits = [r for r in owned if r[1] == q.qtype]
            if hits:
                return 0, chain + hits, []
            cname = [r for r in owned if r[1] == "CNAME"]
            if cname and q.qtype != "CNAME":
                chain.append(cname[0])
                name = cname[0][2]
                continue
            negative = [SOA] if dns._under(name, APEX) else []
            if owned or any(r[0].endswith("." + name) for r in self.records):
                return 0, chain, negative
            return 3, chain, negative
        return 2, chain, []

    def _delegation(self, name: str):
        """A referral, as the parent's authority gives it without recursion."""
        labels = name.split(".")
        for i in range(len(labels) - 1):
            cut = ".".join(labels[i:])
            if cut == APEX:
                return None
            ns = [r for r in self.records if r[0] == cut and r[1] == "NS"]
            if ns:
                return ns
        return None


def lab_scope(*domains: str) -> Scope:
    return Scope(engagement="dns test", client="self-test",
                 authorization=Authorization(reference="LOCAL-TEST",
                                             authorized_by="test harness"),
                 targets=["192.0.2.0/24"], domains=list(domains or [APEX]))


class TestScopeGate(unittest.TestCase):
    def test_apex_and_subdomains_pass_normalised(self):
        scope = lab_scope()
        self.assertEqual(scope.assert_dns_name("lab.test"), "lab.test")
        self.assertEqual(scope.assert_dns_name("A.B.Lab.Test."), "a.b.lab.test")

    def test_suffix_trick_and_unrelated_names_are_refused(self):
        scope = lab_scope()
        for name in ("evillab.test", "lab.test.evil.test", "test", "", "lab.test.."):
            with self.assertRaises(ScopeError, msg=name):
                scope.assert_dns_name(name)

    def test_no_domains_means_nothing_passes(self):
        scope = lab_scope()
        scope.domains = []
        with self.assertRaises(ScopeError):
            scope.assert_dns_name("lab.test")


class TestTransport(unittest.TestCase):
    def client(self, ns: FakeDns, scope: Scope | None = None) -> dns._Client:
        return dns._Client(scope or lab_scope(), ns.policy())

    def test_resolver_lookup_returns_records(self):
        with FakeDns() as ns:
            answer = self.client(ns).lookup("www.lab.test", "A")
        self.assertEqual(answer.status, "ok")
        self.assertEqual(answer.of("A"), ["192.0.2.80"])
        self.assertEqual([(q.name, q.qtype, q.proto, q.rd) for q in ns.queries],
                         [("www.lab.test", "A", "udp", True)])

    def test_truncated_udp_reply_is_retried_over_tcp(self):
        with FakeDns(truncate=True) as ns:
            answer = self.client(ns).lookup("lab.test", "MX")
        self.assertEqual(answer.of("MX"), ["10 mail.lab.test"])
        self.assertEqual([q.proto for q in ns.queries], ["udp", "tcp"])

    def test_nxdomain_and_nodata_are_distinct(self):
        with FakeDns() as ns:
            client = self.client(ns)
            self.assertEqual(client.lookup("nope.lab.test", "A").status, "nxdomain")
            self.assertEqual(client.lookup("www.lab.test", "MX").status, "nodata")

    def test_silent_server_is_a_timeout(self):
        with FakeDns(silent=True) as ns:
            answer = self.client(ns).lookup("www.lab.test", "A")
        self.assertEqual(answer.status, "timeout")

    def test_malformed_replies_are_errors_within_the_timeout(self):
        def header(qid, q, ancount=1):
            return (struct.pack("!HHHHHH", qid, 0x8180, 1, ancount, 0, 0)
                    + wire_name(q.name) + struct.pack("!HH", 1, 1))

        def pointer_loop(qid, q):
            start = len(header(qid, q))
            return header(qid, q) + b"\x01a" + struct.pack("!H", 0xC000 | start)

        def forward_pointer(qid, q):
            return header(qid, q) + struct.pack("!H", 0xC000 | 0x3FFF)

        def truncated(qid, q):
            full = response(qid, q, answer=[("www.lab.test", "A", "192.0.2.80")])
            return full[:len(full) - 3]

        for craft in (pointer_loop, forward_pointer, truncated):
            with FakeDns(raw=craft) as ns, self.subTest(craft.__name__):
                started = time.monotonic()
                answer = self.client(ns).lookup("www.lab.test", "A")
                self.assertEqual(answer.status, "error")
                self.assertLess(time.monotonic() - started, ns.policy().timeout_sec)

    def test_reply_with_a_different_id_is_ignored(self):
        def wrong_id(qid, q):
            return response((qid + 1) & 0xFFFF, q, answer=[("www.lab.test", "A", "192.0.2.1")])

        with FakeDns(raw=wrong_id) as ns:
            answer = self.client(ns).lookup("www.lab.test", "A")
        self.assertEqual(answer.status, "timeout")

    def test_resolver_lane_refuses_names_outside_scope(self):
        with FakeDns() as ns, self.assertRaises(ScopeError):
            self.client(ns).lookup("www.example.test", "A")
        self.assertEqual(ns.queries, [])

    def test_exists_lane_allows_any_name_but_only_addresses(self):
        with FakeDns() as ns:
            client = self.client(ns)
            self.assertEqual(client.exists("elsewhere.example.test").status, "nxdomain")
            with self.assertRaises(ScopeError):
                client._send("elsewhere.example.test", "MX", "exists")
        self.assertEqual([(q.name, q.qtype) for q in ns.queries],
                         [("elsewhere.example.test", "A")])

    def test_authority_is_only_asked_about_its_own_zone(self):
        with FakeDns() as ns:
            client = self.client(ns, lab_scope(APEX, "other.test"))
            auths, gaps = client.authorities(APEX)
            self.assertEqual([(a.host, a.address) for a in auths],
                             [("ns1.lab.test", "127.0.0.1")])
            self.assertEqual(gaps, ())
            self.assertEqual(client.ask(auths[0], "www.lab.test", "A").of("A"),
                             ["192.0.2.80"])
            with self.assertRaises(ScopeError):
                client.ask(auths[0], "www.other.test", "A")
        self.assertNotIn("www.other.test", ns.asked())
        self.assertFalse(ns.queries[-1].rd)


if __name__ == "__main__":
    unittest.main()
