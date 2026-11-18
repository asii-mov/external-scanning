"""IP redaction before text reaches a model provider.

Addresses here are placeholders (TEST-NET, RFC 1918, documentation IPv6).
The end-to-end check through the real SDK is `evals/redaction.py`, run from
`TestRedactionEval` when the SDK is installed.
"""

import importlib.util
import ipaddress
import json
import random
import re
import threading
import unittest

from hypothesis import given, settings
from hypothesis import strategies as st

from extscan.llm import LLMClient, build_client
from extscan.llm.base import SYSTEM_PROMPT, build_prompt
from extscan.llm.redact import SYSTEM_NOTE, IPRedactor, RedactionError
from extscan.policy import LLMPolicy, Policy

from .test_llm import FakeProvider


def _redactor(seed=1):
    return IPRedactor(rng=random.Random(seed))


class TestMapping(unittest.TestCase):
    def test_real_addresses_are_replaced_and_restored(self):
        r = _redactor()
        text = "hosts 203.0.113.10, 10.20.30.40:8080 and http://192.168.77.12/admin"
        out = r.redact(text)
        for real in ("203.0.113.10", "10.20.30.40", "192.168.77.12"):
            self.assertNotIn(real, out)
        self.assertEqual(r.restore(out), text)

    def test_kind_is_kept(self):
        r = _redactor()
        pairs = {"127.0.0.2": ipaddress.ip_network("127.0.0.0/8"),
                 "10.1.2.3": ipaddress.ip_network("10.0.0.0/8"),
                 "172.16.5.9": ipaddress.ip_network("172.16.0.0/12"),
                 "192.168.1.5": ipaddress.ip_network("192.168.0.0/16"),
                 "100.64.1.2": ipaddress.ip_network("100.64.0.0/10")}
        for real, pool in pairs.items():
            fake = ipaddress.ip_address(r.redact(real))
            self.assertIn(fake, pool, real)
            self.assertNotEqual(str(fake), real)
        public = ipaddress.ip_address(r.redact("203.0.113.10"))
        self.assertTrue(public.is_global)

    def test_same_24_stays_together_and_host_octet_is_kept(self):
        r = _redactor()
        a, b = r.redact("10.20.30.40"), r.redact("10.20.30.41")
        self.assertEqual(a.rsplit(".", 1)[0], b.rsplit(".", 1)[0])
        self.assertTrue(a.endswith(".40") and b.endswith(".41"))

    def test_an_address_in_a_url_path_is_still_redacted(self):
        r = _redactor()
        out = r.redact("GET /api/10.20.30.40 and x=/10.20.30.41")
        self.assertNotIn("10.20.30.40", out)
        self.assertNotIn("10.20.30.41", out)

    def test_word_slash_and_label_prefixes_do_not_hide_an_address(self):
        r = _redactor()
        cases = ["https://really-long-hostname.internal.corp.example.com/203.0.113.10",
                 "tcp/10.20.30.40:443", "admin/10.20.30.41", "ipAdEntAddr.10.20.30.42",
                 "X-Forwarded-For:2001:db8:abcd:12::10",
                 "fd12:3456:789a:1::5: connection refused", "fd12:3456:789a:1::6."]
        for text in cases:
            out = r.redact(text)
            self.assertNotEqual(out, text, text)
            self.assertEqual(r.restore(out), text)

    def test_truncation_cannot_leave_part_of_a_real_address(self):
        provider = FakeProvider()
        client = LLMClient(provider=provider, max_input_chars=20)
        client.analyse("q", "x" * 12 + "10.20.30.40 and more")
        self.assertNotIn("10.20.3", provider.calls[0][1])

    def test_restores_are_not_counted_as_redactions(self):
        r = _redactor()
        out = r.redact("10.20.30.40")
        r.restore(out)
        self.assertEqual((r.replaced, r.restored), (1, 1))

    def test_mapping_is_stable_within_a_session(self):
        r = _redactor()
        self.assertEqual(r.redact("198.51.100.7"), r.redact("x 198.51.100.7").split()[1])

    def test_derived_addresses_map_back(self):
        """The model works out the gateway and the network from a fake."""
        r = _redactor()
        fake = r.redact("10.20.30.40")
        net = fake.rsplit(".", 1)[0]
        self.assertEqual(r.restore(f"gw {net}.1 net {net}.0/24"),
                         "gw 10.20.30.1 net 10.20.30.0/24")

    def test_unrelated_addresses_in_the_reply_are_left_alone(self):
        r = _redactor()
        r.redact("10.20.30.40")
        self.assertEqual(r.restore("compare with 8.8.8.8"), "compare with 8.8.8.8")

    def test_defanged_addresses_are_redacted_and_stay_defanged(self):
        r = _redactor()
        out = r.redact("ioc 192[.]0[.]2[.]44")
        self.assertNotIn("192[.]0[.]2[.]44", out)
        self.assertEqual(out.count("[.]"), 3)
        self.assertEqual(r.restore(out), "ioc 192[.]0[.]2[.]44")

    def test_ipv6_maps_per_64_and_keeps_kind(self):
        r = _redactor()
        g = ipaddress.ip_address(r.redact("2001:db8:abcd:12::10"))
        u = ipaddress.ip_address(r.redact("fd12:3456:789a:1::5"))
        self.assertTrue(g in ipaddress.ip_network("2000::/3") and g.is_global)
        self.assertIn(u, ipaddress.ip_network("fc00::/7"))
        self.assertEqual(int(g) & 0xFFFF, 0x10)
        self.assertEqual(r.restore(f"[{g}]:443"), "[2001:db8:abcd:12::10]:443")

    def test_ipv4_mapped_ipv6_is_redacted_through_its_ipv4_part(self):
        r = _redactor()
        out = r.redact("::ffff:10.20.30.40")
        self.assertNotIn("10.20.30.40", out)
        self.assertEqual(r.restore(out), "::ffff:10.20.30.40")

    def test_a_real_address_inside_an_assigned_fake_network_round_trips(self):
        """Collision: a later real /24 equals an earlier fake /24."""
        r = _redactor()
        fake = r.redact("10.20.30.40")
        colliding_real = fake.rsplit(".", 1)[0] + ".7"
        text = f"a 10.20.30.40 b {colliding_real}"
        out = r.redact(text)
        self.assertNotIn(colliding_real, out)
        self.assertEqual(r.restore(out), text)


class TestFalsePositives(unittest.TestCase):
    KEEP = ("1.3.6.1.2.1.1.1.0", ".1.3.6.1.4.1.9", "version 1.2.3.4", "v2.0.0.1",
            "255.255.255.0", "255.255.255.255", "169.254.169.254", "0.0.0.0/0",
            "224.0.0.251", "fe80::1%eth0", "::1", "ff02::1", "aa:bb:cc:dd:ee:ff",
            "12:30:45", "std::vector", "OpenSSH_7.4p1", "10.0.0.256",
            "Mozilla/5.0 (X11) Chrome/128.0.0.0 Safari/537.36")

    def test_non_identifying_strings_are_unchanged(self):
        r = _redactor()
        for s in self.KEEP:
            self.assertEqual(r.redact(s), s, s)
        self.assertEqual(r.replaced, 0)


class TestProperties(unittest.TestCase):
    octet = st.integers(0, 255)

    @settings(max_examples=300, deadline=None)
    @given(st.lists(st.tuples(octet, octet, octet, octet), min_size=1, max_size=6),
           st.sampled_from([" ", ", ", ":443 ", "/24 ", "\n", '"']))
    def test_round_trip_and_no_identifying_address_survives(self, addrs, sep):
        r = _redactor(seed=len(addrs))
        ips = [".".join(map(str, a)) for a in addrs]
        text = "x " + sep.join(ips) + " y"
        out = r.redact(text)
        self.assertEqual(r.restore(out), text)
        for ip in ips:
            v = ipaddress.ip_address(ip)
            keep = (v in ipaddress.ip_network("0.0.0.0/8") or v.is_link_local
                    or v.is_multicast or v in ipaddress.ip_network("240.0.0.0/4"))
            if not keep:
                self.assertIsNone(re.search(rf"(?<![\d.]){re.escape(ip)}(?!\d)", out),
                                  f"{ip} survived in {out!r}")

    @settings(max_examples=300, deadline=None)
    @given(st.integers(0, 2**64 - 1), st.integers(0, 2**64 - 1),
           st.sampled_from(["2001:db8", "fd12:3456", "2a00:1450"]),
           st.sampled_from(["", "Host:", "X-Real-IP:", "[", "addr=", "\t"]),
           st.sampled_from(["", "]:443", ": refused", ".", ",", "%eth0", "/64"]))
    def test_ipv6_in_context_is_redacted_and_round_trips(self, net, iid, head,
                                                          prefix, suffix):
        r = _redactor()
        base = int(ipaddress.IPv6Address(head + "::")) | ((net >> 32) << 64)
        addr = str(ipaddress.IPv6Address(base | iid))
        text = f"x {prefix}{addr}{suffix} y"
        out = r.redact(text)
        self.assertNotIn(addr, out)
        self.assertEqual(r.restore(out), text)

    @settings(max_examples=200, deadline=None)
    @given(st.text(max_size=200))
    def test_arbitrary_text_round_trips(self, text):
        r = _redactor()
        self.assertEqual(r.restore(r.redact(text)), text)


class TestWholePool(unittest.TestCase):
    def test_every_24_of_a_block_gets_its_own_fake_and_none_maps_to_itself(self):
        r = _redactor()
        fakes = {r.redact(f"192.168.{i}.1").split(".")[2] for i in range(256)}
        self.assertEqual(len(fakes), 256)
        for i in range(256):
            self.assertNotEqual(r.redact(f"192.168.{i}.1"), f"192.168.{i}.1")


class TestClient(unittest.TestCase):
    def test_prompt_and_context_are_redacted_and_reply_restored(self):
        provider = FakeProvider()
        # The model quotes back whatever fake it was shown.
        def reply(system, user):
            fake = user.split("host ")[1].split()[0]
            return json.dumps({"summary": f"host {fake} is exposed",
                               "severity_opinion": "low"}), "m"
        provider.complete = lambda system, user, **kw: (
            provider.calls.append((system, user)) or reply(system, user))
        client = LLMClient(provider=provider)
        analysis = client.analyse("Assess host 203.0.113.10 now",
                                  "Server at 10.20.30.40:8080",
                                  context={"host": "203.0.113.10", "port": 8080})
        system, user = provider.calls[0]
        self.assertNotIn("203.0.113.10", user)
        self.assertNotIn("10.20.30.40", user)
        self.assertIn(SYSTEM_NOTE.strip()[:40], system)
        self.assertEqual(analysis.summary, "host 203.0.113.10 is exposed")
        self.assertTrue(client.stats.ip_redaction)
        self.assertGreaterEqual(client.stats.redacted_addresses, 3)

    def test_off_sends_the_prompt_byte_identical(self):
        provider = FakeProvider()
        LLMClient(provider=provider, redact_ips=False).analyse(
            "q 203.0.113.10", "e 10.20.30.40", context={"host": "203.0.113.10"})
        system, user = provider.calls[0]
        self.assertEqual(system, SYSTEM_PROMPT)
        self.assertEqual(user, build_prompt("q 203.0.113.10", "e 10.20.30.40",
                                            {"host": "203.0.113.10"}))

    def test_redaction_failure_is_not_sent(self):
        provider = FakeProvider()
        client = LLMClient(provider=provider)

        def boom(text):
            raise RedactionError("pool exhausted")
        client.redactor.redact = boom
        self.assertIsNone(client.analyse("q", "e 10.0.0.1"))
        self.assertEqual(provider.calls, [])
        self.assertEqual(client.stats.failed, 1)
        self.assertIn("pool exhausted", client.stats.last_error)

    def test_one_mapping_across_threads(self):
        client = LLMClient(provider=FakeProvider())
        outs = []

        def go():
            outs.append(client.redactor.redact("10.20.30.40"))
        threads = [threading.Thread(target=go) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(outs)), 1)


class TestToggle(unittest.TestCase):
    def test_default_is_on(self):
        self.assertTrue(LLMPolicy().redact_ips)

    @unittest.skipUnless(importlib.util.find_spec("anthropic"), "needs the anthropic SDK")
    def test_policy_and_flag_override(self):
        policy = LLMPolicy(enabled=True, provider="anthropic", redact_ips=False)
        self.assertFalse(build_client(policy).redact_ips)
        policy = LLMPolicy(enabled=True, provider="anthropic")
        self.assertTrue(build_client(policy).redact_ips)
        self.assertFalse(build_client(policy, redact_ips=False).redact_ips)

    def test_a_non_boolean_setting_is_refused(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"llm": {"redact_ips": "no"}})


@unittest.skipUnless(importlib.util.find_spec("anthropic"), "needs the anthropic SDK")
class TestRedactionEval(unittest.TestCase):
    """The end-to-end eval: real SDK, a capture server, the analyse CLI."""

    def test_eval_passes_on_the_lab_fixture(self):
        import tempfile
        from pathlib import Path

        from evals import redaction
        with tempfile.TemporaryDirectory() as tmp:
            for mode in ("off", "on", "synthetic"):
                result = redaction.run_pass(redaction.FIXTURE, mode, Path(tmp))
                self.assertEqual(result["problems"], [], mode)


if __name__ == "__main__":
    unittest.main()
