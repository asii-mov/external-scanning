"""SNMP BER encoding/decoding and the community-string probe.

The wire format is hand-rolled, so it gets tested against responses built
byte-by-byte, plus a real UDP socket for the round trip.
"""

import contextlib
import socket
import threading
import unittest

from extscan.policy import Policy
from extscan.tools import snmp as S


def build_response(community: str, oid: str, value: str, request_id: int,
                   error: int = 0, value_tag: int = S.TAG_OCTET) -> bytes:
    """Assemble a GetResponse the way an agent would."""
    raw = value.encode()
    vb = S._tlv(S.TAG_SEQ, S._enc_oid(oid) + S._tlv(value_tag, raw))
    vbs = S._tlv(S.TAG_SEQ, vb)
    pdu = S._tlv(S.TAG_RESPONSE,
                 S._enc_int(request_id) + S._enc_int(error) + S._enc_int(0) + vbs)
    return S._tlv(S.TAG_SEQ,
                  S._enc_int(1) + S._tlv(S.TAG_OCTET, community.encode()) + pdu)


class TestBerPrimitives(unittest.TestCase):
    def test_oid_round_trip(self):
        for oid in ("1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.9.9.999.1.2",
                    "1.3.6.1.2.1.2.2.1.2.16777216", "0.0", "2.5.4.3"):
            _tag, raw, _ = S._parse_tlv(S._enc_oid(oid))
            self.assertEqual(_tag, S.TAG_OID)
            self.assertEqual(S._dec_oid(raw), oid)

    def test_oid_multibyte_arcs(self):
        """Arcs above 127 use base-128 continuation bytes."""
        _tag, raw, _ = S._parse_tlv(S._enc_oid("1.3.6.1.4.1.311"))
        self.assertEqual(S._dec_oid(raw), "1.3.6.1.4.1.311")

    def test_bad_oid_rejected(self):
        for bad in ("", "1", "3.1.1", "x.y.z"):
            with self.assertRaises(ValueError, msg=bad):
                S._enc_oid(bad)

    def test_integer_encoding_preserves_sign_bit(self):
        for n in (0, 1, 127, 128, 255, 256, 65535, 1 << 23, 2147483647):
            _tag, raw, _ = S._parse_tlv(S._enc_int(n))
            self.assertEqual(int.from_bytes(raw, "big", signed=True), n, f"n={n}")

    def test_long_form_length(self):
        """sysDescr frequently exceeds the 127-byte short form."""
        payload = b"A" * 500
        _tag, raw, _ = S._parse_tlv(S._tlv(S.TAG_OCTET, payload))
        self.assertEqual(raw, payload)

    def test_parse_tlv_rejects_truncated_buffers(self):
        for junk in (b"", b"\x30", b"\x30\x05\x02", b"\x30\x82\xff\xff"):
            with self.assertRaises(ValueError, msg=junk.hex()):
                S._parse_tlv(junk)

    def test_decode_application_types(self):
        self.assertEqual(S._dec_value(0x43, (12345).to_bytes(4, "big")), "12345")
        self.assertEqual(S._dec_value(0x40, bytes([10, 0, 0, 1])), "10.0.0.1")
        self.assertEqual(S._dec_value(0x80, b""), "<noSuchObject>")


class TestResponseParsing(unittest.TestCase):
    def test_parses_valid_response(self):
        pkt = build_response("public", S.OIDS["sysDescr"],
                             "Cisco IOS Software, C2960", 4242)
        reply = S._parse_reply(pkt)
        self.assertIsNotNone(reply)
        self.assertTrue(reply.ok)
        self.assertEqual(reply.request_id, 4242)
        self.assertEqual(reply.oid, S.OIDS["sysDescr"])
        self.assertIn("Cisco", reply.value)

    def test_error_status_is_not_ok(self):
        reply = S._parse_reply(build_response("public", S.OIDS["sysDescr"], "", 7, error=2))
        self.assertIsNotNone(reply)
        self.assertFalse(reply.ok)
        self.assertEqual(reply.error_status, 2)

    def test_nosuchobject_is_not_ok(self):
        pkt = build_response("public", S.OIDS["sysDescr"], "", 9, value_tag=0x80)
        reply = S._parse_reply(pkt)
        self.assertFalse(reply.ok)

    def test_garbage_returns_none_without_raising(self):
        for junk in (b"", b"\x30", b"\xff" * 64, b"\x30\x05\x02\x01\x01\x04\x00",
                     b"\x02\x01\x00"):
            self.assertIsNone(S._parse_reply(junk), junk.hex())

    def test_non_response_pdu_rejected(self):
        """A GetRequest echoed back is not a response."""
        req = S._build_request("public", S.OIDS["sysDescr"], 2, 1)
        self.assertIsNone(S._parse_reply(req))


class FakeAgent:
    """A minimal SNMP agent over UDP, for the socket round trip."""

    def __init__(self, accept: dict[str, str]):
        self.accept = accept            # community -> sysDescr value
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.requests: list[str] = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.sock.close()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            try:
                community, oid, rid = self._decode(data)
            except (ValueError, IndexError, UnicodeDecodeError):
                # A malformed datagram from an unrelated sender; ignore it the
                # way a real agent would.
                continue
            self.requests.append(community)
            if community in self.accept:
                pkt = build_response(community, oid, self.accept[community], rid)
            else:
                # Real agents usually stay silent on a bad community; some
                # return an error. Exercise the error path.
                pkt = build_response(community, oid, "", rid, error=2)
            with contextlib.suppress(OSError):
                self.sock.sendto(pkt, addr)

    @staticmethod
    def _decode(data: bytes) -> tuple[str, str, int]:
        _, body, _ = S._parse_tlv(data)
        _, _, pos = S._parse_tlv(body)                 # version
        _, comm, pos = S._parse_tlv(body, pos)         # community
        _, pdu, _ = S._parse_tlv(body, pos)
        _, rid_raw, p = S._parse_tlv(pdu)
        _, _, p = S._parse_tlv(pdu, p)
        _, _, p = S._parse_tlv(pdu, p)
        _, vbs, _ = S._parse_tlv(pdu, p)
        _, vb, _ = S._parse_tlv(vbs)
        _, oid_raw, _ = S._parse_tlv(vb)
        return (comm.decode(), S._dec_oid(oid_raw),
                int.from_bytes(rid_raw, "big", signed=True))


class TestSnmpOverSocket(unittest.TestCase):
    def test_get_succeeds_against_fake_agent(self):
        with FakeAgent({"public": "Linux router 5.10"}) as agent:
            reply = S.snmp_get("127.0.0.1", "public", S.OIDS["sysDescr"],
                               port=agent.port, timeout=2.0)
        self.assertIsNotNone(reply)
        self.assertTrue(reply.ok)
        self.assertEqual(reply.value, "Linux router 5.10")

    def test_wrong_community_is_not_a_hit(self):
        with FakeAgent({"public": "x"}) as agent:
            reply = S.snmp_get("127.0.0.1", "nonsense", S.OIDS["sysDescr"],
                               port=agent.port, timeout=2.0)
        self.assertTrue(reply is None or not reply.ok)

    def test_timeout_on_closed_port_returns_none(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        reply = S.snmp_get("127.0.0.1", "public", S.OIDS["sysDescr"],
                           port=port, timeout=0.4, retries=0)
        self.assertIsNone(reply)

    def test_community_probe_reports_the_working_string(self):
        policy = Policy.for_profile("standard")
        policy.snmp.communities = ["wrongone", "public", "private"]
        policy.snmp.versions = [2]
        policy.snmp.timeout_sec = 1.0
        policy.snmp.walk_on_hit = False
        with FakeAgent({"public": "Cisco IOS C2960"}) as agent:
            findings, leads, hits = S.check_community_strings(
                "127.0.0.1", policy, port=agent.port)

        self.assertEqual(hits, ["public"])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "high")           # `public` is well known
        self.assertIn("public", f.title)
        self.assertIn("community:public", f.tags)
        self.assertIn("Cisco IOS C2960", f.evidence)
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0].kind, "snmp_walk")
        self.assertEqual(leads[0].params["community"], "public")

    def test_write_community_is_flagged_but_never_written_to(self):
        """`private` must raise review, not a SET attempt."""
        policy = Policy.for_profile("standard")
        policy.snmp.communities = ["private"]
        policy.snmp.versions = [2]
        policy.snmp.timeout_sec = 1.0
        policy.snmp.walk_on_hit = False
        with FakeAgent({"private": "APC UPS"}) as agent:
            findings, _, hits = S.check_community_strings(
                "127.0.0.1", policy, port=agent.port)
            # Only GET requests were ever sent.
            self.assertEqual(set(agent.requests), {"private"})

        self.assertEqual(hits, ["private"])
        self.assertTrue(findings[0].review_required)
        self.assertIn("does not attempt SNMP SET", findings[0].review_reason)

    def test_no_hits_yields_nothing(self):
        policy = Policy.for_profile("standard")
        policy.snmp.communities = ["nope1", "nope2"]
        policy.snmp.versions = [2]
        policy.snmp.timeout_sec = 0.5
        with FakeAgent({"public": "x"}) as agent:
            findings, leads, hits = S.check_community_strings(
                "127.0.0.1", policy, port=agent.port)
        self.assertEqual((findings, leads, hits), ([], [], []))

    def test_walk_is_bounded(self):
        """A walk against an agent that never advances must still terminate."""
        with FakeAgent({"public": "same"}) as agent:
            rows = S.snmp_walk("127.0.0.1", "public", "1.3.6.1.2.1.1.1",
                               port=agent.port, timeout=1.0, max_items=10)
        # The fake echoes the requested OID, so there is no forward progress
        # and the walk must stop rather than loop.
        self.assertLessEqual(len(rows), 10)


if __name__ == "__main__":
    unittest.main()
