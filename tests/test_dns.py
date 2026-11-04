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

    It is authoritative for every zone with an SOA in `records`, the way one
    server can host a parent and its child, and gives referrals for other
    delegations.

    `axfr` is True (serve the zone), False (REFUSED) or "silent" (accept the
    connection, never reply). `silent` drops every query, `truncate` sets TC
    on every UDP reply, `refuse` holds (name, type) pairs answered REFUSED,
    and `raw(qid, query)` may return replacement bytes for a reply.
    """

    def __init__(self, records=ZONE, *, axfr=False, silent=False, truncate=False,
                 refuse=(), raw: Callable[[int, Query], bytes | None] | None = None):
        self.records = [tuple(r) for r in records]
        self.zones = {r[0] for r in self.records if r[1] == "SOA"}
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
        if not self.axfr or q.name not in self.zones:
            return [response(qid, q, rcode=5)]
        soa = self._soa(q.name)
        body = [r for r in self.records if r != soa and (
            self._hosting(r[0]) == q.name
            or (r[1] == "NS" and r[0] in self.zones and dns._under(r[0], q.name)))]
        half = len(body) // 2
        return [response(qid, q, answer=[soa, *body[:half]]),
                response(qid, q, answer=[*body[half:], soa])]

    def _hosting(self, name: str) -> str | None:
        """The deepest zone this server is authoritative for that holds `name`."""
        return max((z for z in self.zones if dns._under(name, z)), key=len, default=None)

    def _soa(self, zone: str):
        return next(r for r in self.records if r[0] == zone and r[1] == "SOA")

    def resolve(self, q: Query):
        if (q.name, q.qtype) in self.refuse:
            return 5, [], []
        name, chain = q.name, []
        for _ in range(8):
            if not q.rd:
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
            zone = self._hosting(name)
            negative = [self._soa(zone)] if zone else []
            if owned or any(r[0].endswith("." + name) for r in self.records):
                return 0, chain, negative
            return 3, chain, negative
        return 2, chain, []

    def _delegation(self, name: str):
        """A referral, as the parent's authority gives it without recursion."""
        labels = name.split(".")
        for i in range(len(labels) - 1):
            cut = ".".join(labels[i:])
            if cut in self.zones:
                return None
            ns = [r for r in self.records if r[0] == cut and r[1] == "NS"]
            if ns:
                return ns
        return None


def lab_scope(*domains: str, allow_private: bool = True) -> Scope:
    return Scope(engagement="dns test", client="self-test",
                 authorization=Authorization(reference="LOCAL-TEST",
                                             authorized_by="test harness"),
                 targets=["192.0.2.0/24"], domains=list(domains or [APEX]),
                 allow_private=allow_private)


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
            start = len(header(qid, q))
            target = wire_name("x.lab.test")
            return (header(qid, q) + struct.pack("!HHHIH", 0xC000 | (start + 12), 5, 1, 300,
                                                 len(target)) + target)

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


NSEC_ZONE = [*ZONE,
             ("vpn-admin.lab.test", "A", "192.0.2.9"),
             ("lab.test", "NSEC", "mail.lab.test NS SOA MX NSEC"),
             ("mail.lab.test", "NSEC", "ns1.lab.test A NSEC"),
             ("ns1.lab.test", "NSEC", "vpn-admin.lab.test A NSEC"),
             ("vpn-admin.lab.test", "NSEC", "www.lab.test A NSEC"),
             ("www.lab.test", "NSEC", "lab.test A NSEC")]

TAKEOVER_ZONE = [*ZONE,
                 ("assets.lab.test", "CNAME", "lab-assets.s3.amazonaws.com"),
                 ("old.lab.test", "CNAME", "old-app.vendor.test"),
                 ("shop.lab.test", "CNAME", "lab-shop.herokuapp.com"),
                 ("lab-shop.herokuapp.com", "A", "192.0.2.99"),
                 ("news.lab.test", "MX", "10 mx.lapsed-mail.test"),
                 ("dev.lab.test", "NS", "ns.lapsed-dns.test"),
                 ("lame.lab.test", "NS", "ns1.lab.test")]
TAKEOVER_NAMES = ["assets.lab.test", "old.lab.test", "shop.lab.test", "news.lab.test",
                  "dev.lab.test", "lame.lab.test", "www.lab.test"]


def audit(ns: FakeDns, known=(), scope: Scope | None = None, **policy):
    results = dns.audit_zone(scope or lab_scope(), APEX, list(known), ns.policy(**policy))
    return {r.check: r for r in results}


def with_link(records, owner: str, nxt: str):
    return [(o, t, f"{nxt} A NSEC") if (o, t) == (owner, "NSEC") else (o, t, d)
            for o, t, d in records]


class TestZoneTransfer(unittest.TestCase):
    def test_allowed_transfer_is_a_medium_finding_with_the_dump(self):
        with FakeDns(axfr=True) as ns:
            axfr = audit(ns)["axfr"]
        self.assertTrue(axfr.covered)
        [finding] = axfr.findings
        self.assertEqual((finding.severity, finding.host, finding.proto, finding.port),
                         ("medium", APEX, "dns", None))
        self.assertIn("ns1.lab.test", finding.title)
        [(name, dump)] = axfr.artifacts
        self.assertIn("ns1.lab.test", name)
        self.assertIn("www.lab.test. 300 IN A 192.0.2.80", dump)
        self.assertEqual([q.proto for q in ns.queries if q.qtype == "AXFR"], ["tcp"])

    def test_nameserver_on_an_internal_address_is_never_queried(self):
        with FakeDns(axfr=True) as ns:
            axfr = audit(ns, scope=lab_scope(allow_private=False))["axfr"]
        self.assertFalse(axfr.covered)
        self.assertEqual(axfr.findings, ())
        self.assertIn("internal address 127.0.0.1", axfr.gap("recon").reason)
        self.assertNotIn("AXFR", [q.qtype for q in ns.queries])

    def test_refused_transfer_is_covered_with_no_finding(self):
        with FakeDns(axfr=False) as ns:
            axfr = audit(ns)["axfr"]
        self.assertTrue(axfr.covered)
        self.assertEqual(axfr.findings, ())
        self.assertIsNone(axfr.gap("recon"))

    def test_silent_nameserver_is_a_named_gap(self):
        with FakeDns(axfr="silent") as ns:
            axfr = audit(ns)["axfr"]
        self.assertFalse(axfr.covered)
        gap = axfr.gap("recon")
        self.assertEqual(gap.component, "dns:axfr:lab.test")
        self.assertIn("ns1.lab.test", gap.reason)

    def test_unreachable_resolver_loses_every_check(self):
        with FakeDns(silent=True) as ns:
            results = audit(ns)
        self.assertEqual(sorted(results), ["axfr", "nsec-walk", "takeover"])
        self.assertTrue(all(r.gap("recon") is not None for r in results.values()))

    def test_names_from_the_transfer_are_checked_for_takeover(self):
        with FakeDns(TAKEOVER_ZONE, axfr=True) as ns:
            takeover = audit(ns)["takeover"]
        self.assertIn("Dangling CNAME assets.lab.test -> lab-assets.s3.amazonaws.com",
                      [f.title for f in takeover.findings])


class TestNsecWalk(unittest.TestCase):
    def test_walk_lists_every_name_and_stops_at_the_apex(self):
        with FakeDns(NSEC_ZONE) as ns:
            walk = audit(ns)["nsec-walk"]
        self.assertTrue(walk.covered)
        self.assertEqual(walk.names, ("lab.test", "mail.lab.test", "ns1.lab.test",
                                      "vpn-admin.lab.test", "www.lab.test"))
        [finding] = walk.findings
        self.assertEqual(finding.severity, "low")
        self.assertIn("vpn-admin.lab.test", finding.evidence)
        self.assertEqual(ns.asked("NSEC").count("lab.test"), 1)
        self.assertTrue(all(q.do and not q.rd for q in ns.queries if q.qtype == "NSEC"))

    def test_looping_chain_ends_the_walk_as_partial(self):
        with FakeDns(with_link(NSEC_ZONE, "www.lab.test", "mail.lab.test")) as ns:
            walk = audit(ns)["nsec-walk"]
        self.assertFalse(walk.covered)
        self.assertEqual(walk.gap("recon").component, "dns:nsec-walk:lab.test")
        self.assertLessEqual(len(ns.asked("NSEC")), 5)

    def test_walk_is_bounded_by_max_walk_steps(self):
        with FakeDns(NSEC_ZONE) as ns:
            walk = audit(ns, max_walk_steps=2)["nsec-walk"]
        self.assertFalse(walk.covered)
        self.assertEqual(len(ns.asked("NSEC")), 3)
        self.assertEqual(walk.findings[0].severity, "low")

    def test_link_out_of_the_zone_is_never_followed(self):
        with FakeDns(with_link(NSEC_ZONE, "ns1.lab.test", "x.evil.test")) as ns:
            walk = audit(ns, scope=lab_scope(APEX, "evil.test"))["nsec-walk"]
        self.assertFalse(walk.covered)
        self.assertNotIn("x.evil.test", ns.asked())
        self.assertEqual(walk.names, ("lab.test", "mail.lab.test", "ns1.lab.test"))

    def test_nsec3_zone_is_reported_without_walking(self):
        with FakeDns([*ZONE, ("lab.test", "NSEC3PARAM", "1 0 10 abcd")]) as ns:
            walk = audit(ns)["nsec-walk"]
        self.assertTrue(walk.covered)
        [finding] = walk.findings
        self.assertEqual(finding.severity, "info")
        self.assertIn("iterations 10, salt abcd", finding.evidence)
        self.assertEqual(ns.asked("NSEC"), [])

    def test_unsigned_zone_is_covered_with_no_finding(self):
        with FakeDns() as ns:
            walk = audit(ns)["nsec-walk"]
        self.assertTrue(walk.covered)
        self.assertEqual(walk.findings, ())


class TestTakeoverCandidates(unittest.TestCase):
    def test_each_dangling_record_is_one_candidate(self):
        with FakeDns(TAKEOVER_ZONE, refuse={("lame.lab.test", "SOA")}) as ns:
            takeover = audit(ns, TAKEOVER_NAMES)["takeover"]
        self.assertTrue(takeover.covered)
        self.assertEqual(sorted((f.title, f.severity) for f in takeover.findings), [
            ("Dangling CNAME assets.lab.test -> lab-assets.s3.amazonaws.com", "medium"),
            ("Dangling CNAME old.lab.test -> old-app.vendor.test", "low"),
            ("Dangling MX news.lab.test -> mx.lapsed-mail.test", "low"),
            ("Delegation of dev.lab.test to missing nameserver ns.lapsed-dns.test",
             "medium"),
            ("Lame delegation of lame.lab.test", "medium"),
        ])
        for f in takeover.findings:
            self.assertTrue(f.review_required, f.title)
            self.assertEqual(f.confidence, "tentative")
            self.assertIn("takeover-candidate", f.tags)
            self.assertEqual((f.host, f.proto, f.source), (APEX, "dns", "extscan:dns"))

    def test_live_targets_and_healthy_delegations_give_nothing(self):
        with FakeDns(TAKEOVER_ZONE) as ns:
            takeover = audit(ns, ["shop.lab.test", "lame.lab.test", "www.lab.test"])
        self.assertEqual(takeover["takeover"].findings, ())

    def test_targets_outside_the_zone_are_only_asked_for_addresses(self):
        with FakeDns(TAKEOVER_ZONE, refuse={("lame.lab.test", "SOA")}) as ns:
            audit(ns, [*TAKEOVER_NAMES, "www.example.test", "evillab.test"])
        outside = [q for q in ns.queries if not dns._under(q.name, APEX)]
        self.assertEqual(sorted({q.name for q in outside}),
                         ["mx.lapsed-mail.test", "ns.lapsed-dns.test"])
        self.assertTrue(all(q.qtype == "A" and q.rd for q in outside))
        self.assertNotIn("www.example.test", ns.asked())
        self.assertNotIn("evillab.test", ns.asked())

    def test_names_past_max_names_are_a_gap(self):
        with FakeDns(TAKEOVER_ZONE) as ns:
            takeover = audit(ns, TAKEOVER_NAMES, max_names=3)["takeover"]
        self.assertIn("over dns.max_names=3", takeover.gap("recon").reason)


def child_zone(zone: str, *names: str):
    """A signed sub-zone, delegated from lab.test and hosted on the same fake."""
    owners = [zone, *names, f"ns1.{zone}"]
    return [(zone, "SOA", f"ns1.{zone} hostmaster.lab.test 1 3600 600 86400 300"),
            (zone, "NS", f"ns1.{zone}"),
            (f"ns1.{zone}", "A", "127.0.0.1"),
            *[(n, "A", "192.0.2.40") for n in names],
            *[(o, "NSEC", f"{owners[(i + 1) % len(owners)]} A NSEC")
              for i, o in enumerate(owners)]]


EU_ZONE = child_zone("eu.lab.test", "app.eu.lab.test")
US_ZONE = child_zone("us.lab.test")
SUBZONE_CHECKS = {"AXFR", "NSEC", "NSEC3PARAM"}


def zone_queries(ns: FakeDns, zone: str) -> list[tuple[str, str]]:
    return [(q.name, q.qtype) for q in ns.queries
            if q.qtype in SUBZONE_CHECKS and dns._under(q.name, zone)]


class TestSubZones(unittest.TestCase):
    def results(self, records, scope: Scope | None = None, **policy):
        with FakeDns(records, axfr=True) as ns:
            results = dns.audit_zone(scope or lab_scope(), APEX, [], ns.policy(**policy))
        return ns, {r.component: r for r in results}

    def test_by_default_a_sub_zone_is_only_checked_for_takeover(self):
        ns, results = self.results([*ZONE, *EU_ZONE])
        self.assertIn("eu.lab.test", ns.asked("SOA"))
        self.assertEqual(zone_queries(ns, "eu.lab.test"), [])
        self.assertEqual(sorted(results), ["dns:axfr:lab.test", "dns:nsec-walk:lab.test",
                                           "dns:takeover:lab.test"])

    def test_opted_in_sub_zones_are_transferred_and_walked(self):
        ns, results = self.results([*ZONE, *EU_ZONE], subzones=True)
        self.assertEqual(sorted(results), [
            "dns:axfr:eu.lab.test", "dns:axfr:lab.test", "dns:nsec-walk:eu.lab.test",
            "dns:nsec-walk:lab.test", "dns:subzones:lab.test", "dns:takeover:lab.test"])
        self.assertTrue(all(r.covered for r in results.values()))
        [axfr] = results["dns:axfr:eu.lab.test"].findings
        self.assertEqual((axfr.title, axfr.host),
                         ("Zone transfer (AXFR) of eu.lab.test allowed by ns1.eu.lab.test",
                          "eu.lab.test"))
        [walk] = results["dns:nsec-walk:eu.lab.test"].findings
        self.assertIn("app.eu.lab.test", walk.evidence)
        self.assertEqual(ns.asked("AXFR"), ["lab.test", "eu.lab.test"])
        self.assertTrue(all(not q.rd for q in ns.queries if q.qtype in SUBZONE_CHECKS))

    def test_sub_zones_past_the_cap_are_lost_coverage(self):
        ns, results = self.results([*ZONE, *EU_ZONE, *US_ZONE], subzones=True,
                                   max_subzones=1)
        self.assertIn("dns:axfr:eu.lab.test", results)
        self.assertNotIn("dns:axfr:us.lab.test", results)
        self.assertEqual(zone_queries(ns, "us.lab.test"), [])
        gap = results["dns:subzones:lab.test"].gap("recon")
        self.assertIn("1 delegated sub-zone(s) over dns.max_subzones=1", gap.reason)
        self.assertIn("us.lab.test", gap.reason)

    def test_sub_zone_with_no_reachable_nameserver_is_lost_coverage(self):
        records = [r for r in [*ZONE, *EU_ZONE] if r[:2] != ("ns1.eu.lab.test", "A")]
        _, results = self.results(records, subzones=True)
        for check in ("axfr", "nsec-walk"):
            self.assertIn("no nameserver of eu.lab.test has an address",
                          results[f"dns:{check}:eu.lab.test"].gap("recon").reason)

    def test_sub_zone_that_is_a_scope_domain_is_left_to_its_own_audit(self):
        ns, results = self.results([*ZONE, *EU_ZONE], lab_scope(APEX, "eu.lab.test"),
                                   subzones=True)
        self.assertNotIn("dns:axfr:eu.lab.test", results)
        self.assertEqual(zone_queries(ns, "eu.lab.test"), [])

    def test_skipping_takeover_leaves_sub_zones_as_a_gap(self):
        ns, results = self.results([*ZONE, *EU_ZONE], subzones=True, skip=["takeover"])
        self.assertEqual(zone_queries(ns, "eu.lab.test"), [])
        self.assertIn("takeover", results["dns:subzones:lab.test"].gap("recon").reason)

    def test_dry_run_plans_the_sub_zone_audit_and_sends_nothing(self):
        with FakeDns([*ZONE, *EU_ZONE], axfr=True) as ns:
            results = dns.audit_zone(lab_scope(), APEX, [], ns.policy(subzones=True),
                                     dry_run=True)
        self.assertEqual(ns.queries, [])
        self.assertEqual([r.check for r in results],
                         ["axfr", "nsec-walk", "takeover", "subzones"])
        self.assertTrue(all(r.planned for r in results))


HOST = "192.0.2.5"
CLIENT_ZONE = [("client.test", "SOA", "ns1.client.test hostmaster.client.test 1 3600 600 86400 300"),
               ("client.test", "NS", "ns1.client.test"),
               ("ns1.client.test", "A", "127.0.0.1"),
               ("client.test", "NSEC", "host5.client.test NS SOA NSEC"),
               ("host5.client.test", "CNAME", "gone-app.herokuapp.com"),
               ("host6.client.test", "MX", "10 mx.lapsed-mail.test"),
               ("host7.client.test", "A", HOST)]
ZONE_QUERIES = {"NS", "SOA", "AXFR", "NSEC", "NSEC3PARAM"}


def audit_hosts(ns: FakeDns, hostnames: dict, scope: Scope | None = None, **policy):
    return dns.audit_hosts(scope or lab_scope(), hostnames, ns.policy(**policy))


class TestHostNames(unittest.TestCase):
    def test_dangling_records_on_host_names_are_findings_on_that_address(self):
        with FakeDns([*ZONE, *CLIENT_ZONE]) as ns:
            [result] = audit_hosts(ns, {HOST: ["host5.client.test", "Host6.Client.Test.",
                                               "host7.client.test"]})
        self.assertTrue(result.covered)
        self.assertEqual(result.component, "dns:host-names:192.0.2.5")
        self.assertEqual(sorted((f.title, f.severity) for f in result.findings), [
            ("Dangling CNAME host5.client.test -> gone-app.herokuapp.com", "medium"),
            ("Dangling MX host6.client.test -> mx.lapsed-mail.test", "low"),
        ])
        for f in result.findings:
            self.assertEqual((f.host, f.proto, f.source), (HOST, "dns", "extscan:dns"))
            self.assertTrue(f.review_required, f.title)
            self.assertEqual(f.confidence, "tentative")
            self.assertIn("takeover-candidate", f.tags)

    def test_the_zone_of_a_host_name_gets_no_zone_level_query(self):
        with FakeDns([*ZONE, *CLIENT_ZONE], axfr=True) as ns:
            audit_hosts(ns, {HOST: ["host5.client.test", "host6.client.test"]})
        self.assertTrue(ns.queries)
        self.assertEqual([q for q in ns.queries if q.qtype in ZONE_QUERIES], [])
        self.assertNotIn("client.test", ns.asked())
        self.assertTrue(all(q.rd for q in ns.queries))
        self.assertEqual(sorted({(q.name, q.qtype) for q in ns.queries
                                 if q.name.startswith("host")}),
                         [("host5.client.test", "A"), ("host5.client.test", "MX"),
                          ("host6.client.test", "A"), ("host6.client.test", "MX")])

    def test_unanswered_names_are_a_gap_on_the_address(self):
        with FakeDns(silent=True) as ns:
            [result] = audit_hosts(ns, {HOST: ["host5.client.test"]})
        gap = result.gap("discover:dns")
        self.assertEqual((gap.stage, gap.component, gap.hosts),
                         ("discover:dns", "dns:host-names:192.0.2.5", [HOST]))
        self.assertIn("1 of 1 name(s) got no answer", gap.reason)

    def test_address_outside_scope_is_refused_before_any_packet(self):
        with FakeDns(CLIENT_ZONE) as ns, self.assertRaises(ScopeError):
            audit_hosts(ns, {HOST: ["host7.client.test"], "198.51.100.7": ["host5.client.test"]})
        self.assertEqual(ns.queries, [])

    def test_dry_run_and_skip_send_nothing(self):
        with FakeDns(CLIENT_ZONE) as ns:
            planned = dns.audit_hosts(lab_scope(), {HOST: ["host5.client.test"], "192.0.2.6": []},
                                      ns.policy(), dry_run=True)
            skipped = audit_hosts(ns, {HOST: ["host5.client.test"]}, skip=["host-names"])
        self.assertEqual(ns.queries, [])
        self.assertEqual([(r.subject, r.planned) for r in planned], [(HOST, True)])
        self.assertEqual(skipped, [])


class TestNamesOutsideDomains(unittest.TestCase):
    def test_lists_only_names_under_no_scope_domain(self):
        finding = dns.names_outside_domains(lab_scope(), {
            HOST: ["host5.client.test", "www.lab.test"], "192.0.2.6": ["Evillab.Test."]})
        self.assertEqual((finding.severity, finding.host), ("info", ""))
        self.assertEqual(finding.evidence.splitlines(),
                         ["192.0.2.6  evillab.test", "192.0.2.5  host5.client.test"])
        self.assertTrue(finding.review_required)
        self.assertIn("scope.domains", finding.review_reason)

    def test_nothing_when_every_name_is_under_a_scope_domain(self):
        self.assertIsNone(dns.names_outside_domains(lab_scope(), {HOST: ["www.lab.test"]}))


class TestAuditBoundaries(unittest.TestCase):
    def test_zone_outside_scope_is_refused_before_any_packet(self):
        with FakeDns() as ns, self.assertRaises(ScopeError):
            dns.audit_zone(lab_scope(), "example.test", [], ns.policy())
        self.assertEqual(ns.queries, [])

    def test_dry_run_sends_nothing_and_plans_every_check(self):
        with FakeDns() as ns:
            results = dns.audit_zone(lab_scope(), APEX, TAKEOVER_NAMES, ns.policy(),
                                     dry_run=True)
        self.assertEqual(ns.queries, [])
        self.assertEqual([r.check for r in results], ["axfr", "nsec-walk", "takeover"])
        self.assertTrue(all(r.planned and not r.covered and r.gap("recon") is None
                            for r in results))

    def test_skipped_checks_send_nothing(self):
        with FakeDns(NSEC_ZONE, axfr=True) as ns:
            results = audit(ns, skip=["axfr", "nsec-walk"])
        self.assertEqual(sorted(results), ["takeover"])
        self.assertEqual(ns.asked("AXFR") + ns.asked("NSEC"), [])


if __name__ == "__main__":
    unittest.main()
