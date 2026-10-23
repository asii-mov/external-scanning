"""The local lab starts, and each listener answers like the product it imitates.

Binds 127.0.0.3 rather than the lab's default address so the suite still
passes while someone has the lab running.
"""

import json
import socket
import ssl
import unittest
import urllib.request

from extscan.policy import Policy
from extscan.tools import snmp

from . import lab

HOST = "127.0.0.3"


def _recv(port: int, send: bytes = b"") -> bytes:
    with socket.create_connection((HOST, port), timeout=3) as s:
        if send:
            s.sendall(send)
        return s.recv(4096)


class TestLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = lab.start(HOST)

    @classmethod
    def tearDownClass(cls):
        lab.stop(cls.servers)

    def test_banners(self):
        self.assertTrue(_recv(lab.PORTS["ssh"]).startswith(b"SSH-2.0-OpenSSH_7.4"))
        self.assertIn(b"5.7.33-log", _recv(lab.PORTS["mysql"]))
        self.assertEqual(_recv(lab.PORTS["redis"], b"PING\r\n"), b"+PONG\r\n")

    def test_http_services(self):
        with urllib.request.urlopen(f"http://{HOST}:{lab.PORTS['elasticsearch']}/") as r:
            self.assertEqual(json.load(r)["tagline"], "You Know, for Search")
        with urllib.request.urlopen(f"http://{HOST}:{lab.PORTS['iis']}/") as r:
            self.assertEqual(r.headers["Server"], "Microsoft-IIS/8.5")

    def test_https_serves_spec_pointing_at_lab_address(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://{HOST}:{lab.PORTS['https']}/swagger.json"
        with urllib.request.urlopen(url, context=ctx) as r:
            spec = json.load(r)
        self.assertEqual(spec["servers"][0]["url"], f"http://{HOST}:{lab.PORTS['http']}/api")

    def test_idle_tls_client_does_not_block_others(self):
        """nmap's NULL probe connects and sends nothing; the port must stay usable."""
        with socket.create_connection((HOST, lab.PORTS["https"]), timeout=3):
            self.test_https_serves_spec_pointing_at_lab_address()

    def test_snmp_public_community(self):
        _f, _l, hits = snmp.check_community_strings(HOST, Policy(), port=lab.PORTS["snmp"])
        self.assertEqual(hits, ["public"])


if __name__ == "__main__":
    unittest.main()
