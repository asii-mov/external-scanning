"""Scope and authorisation enforcement.

These are the tests that matter most: a bug here means scanning something
nobody authorised.
"""

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from extscan.scope import Scope, ScopeError

BASE = {
    "engagement": "test",
    "client": "Test Client",
    "authorization": {"reference": "TICKET-1", "authorized_by": "someone@test"},
    "targets": ["203.0.113.0/29"],
}


def write_scope(**overrides) -> str:
    data = {**BASE, **overrides}
    path = Path(tempfile.mkdtemp()) / "scope.json"
    path.write_text(json.dumps(data))
    return str(path)


def write_targets(text: str) -> str:
    path = Path(tempfile.mkdtemp()) / "targets.txt"
    path.write_text(text)
    return str(path)


class TestPlainTargetList(unittest.TestCase):
    def test_one_target_per_line_with_comments_and_blank_lines(self):
        scope = Scope.load(write_targets(
            "# perimeter\n203.0.113.1/29\n\n198.51.100.14  # the VPN\n"))
        self.assertEqual(scope.targets, ["203.0.113.1/29", "198.51.100.14"])
        self.assertTrue(scope.contains("203.0.113.6"))
        self.assertTrue(scope.contains("198.51.100.14"))
        self.assertFalse(scope.contains("198.51.100.15"))

    def test_no_authorisation_is_needed_and_none_is_recorded(self):
        scope = Scope.load(write_targets("203.0.113.1\n"))
        self.assertEqual(scope.authorization.reference, "")
        self.assertEqual(scope.engagement, "targets")
        self.assertEqual(scope.in_window()[0], True)

    def test_a_last_octet_range_includes_both_ends(self):
        scope = Scope.load(write_targets("203.0.113.1-100\n"))
        self.assertEqual(scope.host_count(), 100)
        self.assertEqual(scope.hosts()[0], "203.0.113.1")
        self.assertEqual(scope.hosts()[-1], "203.0.113.100")
        self.assertFalse(scope.contains("203.0.113.101"))

    def test_a_full_range_crosses_an_octet(self):
        scope = Scope.load(write_targets("203.0.113.254-203.0.114.1\n"))
        self.assertEqual(scope.hosts(), ["203.0.113.254", "203.0.113.255",
                                         "203.0.114.0", "203.0.114.1"])

    def test_a_line_that_is_not_a_target_is_refused_with_its_line_number(self):
        for bad in ("www.example.com", "203.0.113.1-999", "203.0.113.9-1", "203.0.113.0/33"):
            with self.assertRaises(ScopeError) as cm:
                Scope.load(write_targets(f"203.0.113.1\n{bad}\n"))
            self.assertIn("line 2", str(cm.exception), bad)

    def test_an_empty_list_is_refused(self):
        with self.assertRaises(ScopeError):
            Scope.load(write_targets("# nothing yet\n\n"))

    def test_internal_space_and_oversized_lists_are_still_refused(self):
        for text in ("10.0.0.1\n", "127.0.0.2\n", "203.0.0.0/16\n"):
            with self.assertRaises(ScopeError) as cm:
                Scope.load(write_targets(text))
            self.assertIn("JSON scope file", str(cm.exception), text)

    def test_a_huge_range_is_refused_before_it_is_expanded(self):
        with self.assertRaises(ScopeError) as cm:
            Scope.load(write_targets("11.0.0.1-12.0.0.1\n"))
        self.assertIn("CIDR", str(cm.exception))

    def test_a_json_scope_takes_ranges_in_targets_and_exclude(self):
        scope = Scope.load(write_scope(targets=["203.0.113.1-10"], exclude=["203.0.113.4-5"]))
        self.assertEqual(scope.host_count(), 8)
        self.assertFalse(scope.contains("203.0.113.4"))

    def test_broken_json_is_not_read_as_a_target_list(self):
        path = Path(tempfile.mkdtemp()) / "scope.json"
        path.write_text('{"targets": ["203.0.113.1"]')
        with self.assertRaises(ScopeError) as cm:
            Scope.load(path)
        self.assertIn("not valid JSON", str(cm.exception))

    def test_the_report_says_no_authorisation_was_recorded(self):
        from extscan.report import _authorisation_block
        block = _authorisation_block(Scope.load(write_targets("203.0.113.1\n")))
        self.assertIn("Not recorded", block)


class TestScopeLoading(unittest.TestCase):
    def test_loads_valid_scope(self):
        scope = Scope.load(write_scope())
        self.assertEqual(scope.engagement, "test")
        self.assertEqual(scope.authorization.reference, "TICKET-1")

    def test_refuses_missing_authorization_block(self):
        data = dict(BASE)
        del data["authorization"]
        path = Path(tempfile.mkdtemp()) / "scope.json"
        path.write_text(json.dumps(data))
        with self.assertRaises(ScopeError) as cm:
            Scope.load(path)
        self.assertIn("authorization", str(cm.exception))

    def test_refuses_authorization_without_signoff(self):
        with self.assertRaises(ScopeError) as cm:
            Scope.load(write_scope(authorization={"reference": "TICKET-1"}))
        self.assertIn("authorized_by", str(cm.exception))

    def test_refuses_empty_targets(self):
        with self.assertRaises(ScopeError):
            Scope.load(write_scope(targets=[]))

    def test_refuses_malformed_cidr(self):
        with self.assertRaises(ScopeError) as cm:
            Scope.load(write_scope(targets=["203.0.113.0/99"]))
        self.assertIn("bad target", str(cm.exception))

    def test_refuses_private_range_unless_opted_in(self):
        with self.assertRaises(ScopeError) as cm:
            Scope.load(write_scope(targets=["10.0.0.0/24"]))
        self.assertIn("allow_private", str(cm.exception))
        # Explicit opt-in is honoured.
        scope = Scope.load(write_scope(targets=["10.0.0.0/30"], allow_private=True))
        self.assertTrue(scope.contains("10.0.0.1"))

    def test_refuses_scope_larger_than_max_hosts(self):
        with self.assertRaises(ScopeError) as cm:
            Scope.load(write_scope(targets=["203.0.113.0/24"], max_hosts=10))
        self.assertIn("max_hosts", str(cm.exception))

    def test_missing_file(self):
        with self.assertRaises(ScopeError):
            Scope.load("/nonexistent/scope.json")


class TestScopeMembership(unittest.TestCase):
    def setUp(self):
        self.scope = Scope.load(write_scope(
            targets=["203.0.113.0/29", "198.51.100.14/32"],
            exclude=["203.0.113.5"],
            allow_hostnames=["www.example-client.test"],
        ))

    def test_in_scope_addresses(self):
        for ip in ("203.0.113.1", "203.0.113.6", "198.51.100.14"):
            self.assertTrue(self.scope.contains(ip), ip)

    def test_out_of_scope_addresses(self):
        for ip in ("203.0.113.9", "198.51.100.15", "192.0.2.1", "8.8.8.8"):
            self.assertFalse(self.scope.contains(ip), ip)

    def test_exclusion_wins_over_target_range(self):
        self.assertFalse(self.scope.contains("203.0.113.5"))
        self.assertNotIn("203.0.113.5", self.scope.hosts())

    def test_hostnames_only_when_allowlisted(self):
        self.assertTrue(self.scope.contains("www.example-client.test"))
        self.assertTrue(self.scope.contains("WWW.EXAMPLE-CLIENT.TEST"))
        self.assertFalse(self.scope.contains("api.example-client.test"))

    def test_garbage_is_not_in_scope(self):
        for junk in ("", "   ", "not-a-host", "999.999.999.999", None):
            self.assertFalse(self.scope.contains(junk), repr(junk))

    def test_assert_host_raises_with_guidance(self):
        with self.assertRaises(ScopeError) as cm:
            self.scope.assert_host("8.8.8.8", context="redirect target")
        message = str(cm.exception)
        self.assertIn("8.8.8.8", message)
        self.assertIn("redirect target", message)

    def test_nmap_target_args_include_exclusions(self):
        args = self.scope.nmap_target_args()
        self.assertIn("--exclude", args)
        self.assertIn("203.0.113.5", args)


class TestUrlScoping(unittest.TestCase):
    """The SSRF guard for URLs derived from scanner output."""

    def setUp(self):
        self.scope = Scope.load(write_scope(targets=["203.0.113.0/29"]))

    def test_accepts_in_scope_url(self):
        host = self.scope.assert_url("https://203.0.113.2:8443/swagger.json")
        self.assertEqual(host, "203.0.113.2")

    def test_rejects_cloud_metadata_endpoint(self):
        # The canonical hostile redirect target.
        with self.assertRaises(ScopeError):
            self.scope.assert_url("http://169.254.169.254/latest/meta-data/")

    def test_rejects_localhost_and_offscope(self):
        for url in ("http://127.0.0.1:8080/", "https://evil.test/x",
                    "http://[::1]/", "https://203.0.113.99/"):
            with self.assertRaises(ScopeError, msg=url):
                self.scope.assert_url(url)

    def test_rejects_non_http_schemes(self):
        for url in ("file:///etc/passwd", "gopher://203.0.113.2/",
                    "ftp://203.0.113.2/", "203.0.113.2/no-scheme"):
            with self.assertRaises(ScopeError, msg=url):
                self.scope.assert_url(url)

    def test_rejects_url_with_no_host(self):
        with self.assertRaises(ScopeError):
            self.scope.assert_url("http:///just-a-path")


class TestTestingWindow(unittest.TestCase):
    def test_no_window_is_permitted(self):
        scope = Scope.load(write_scope())
        ok, _ = scope.in_window()
        self.assertTrue(ok)

    def test_before_window_opens(self):
        scope = Scope.load(write_scope(authorization={
            **BASE["authorization"],
            "window_start": "2030-01-01T00:00:00Z",
        }))
        ok, why = scope.in_window()
        self.assertFalse(ok)
        self.assertIn("opens", why)
        with self.assertRaises(ScopeError):
            scope.assert_window()

    def test_after_window_closes(self):
        scope = Scope.load(write_scope(authorization={
            **BASE["authorization"],
            "window_end": "2020-01-01T00:00:00Z",
        }))
        ok, why = scope.in_window()
        self.assertFalse(ok)
        self.assertIn("closed", why)

    def test_inside_window(self):
        now = dt.datetime.now(dt.timezone.utc)
        scope = Scope.load(write_scope(authorization={
            **BASE["authorization"],
            "window_start": (now - dt.timedelta(days=1)).isoformat(),
            "window_end": (now + dt.timedelta(days=1)).isoformat(),
        }))
        self.assertTrue(scope.in_window()[0])

    def test_unparseable_window_fails_closed(self):
        # Refused when the file is loaded, before a run can start on it.
        with self.assertRaises(ScopeError) as cm:
            Scope.load(write_scope(authorization={
                **BASE["authorization"], "window_end": "next tuesday",
            }))
        self.assertIn("window_end", str(cm.exception))
        # And a scope built in code with a bad window still fails closed.
        scope = Scope.load(write_scope())
        scope.authorization.window_end = "next tuesday"
        ok, why = scope.in_window()
        self.assertFalse(ok)
        self.assertIn("unparseable", why)


class TestHostExpansion(unittest.TestCase):
    def test_expands_cidr_without_network_and_broadcast(self):
        scope = Scope.load(write_scope(targets=["203.0.113.0/29"]))
        hosts = scope.hosts()
        self.assertNotIn("203.0.113.0", hosts)
        self.assertNotIn("203.0.113.7", hosts)
        self.assertIn("203.0.113.1", hosts)

    def test_single_host_target(self):
        scope = Scope.load(write_scope(targets=["198.51.100.14/32"]))
        self.assertEqual(scope.hosts(), ["198.51.100.14"])

    def test_overlapping_targets_deduplicate(self):
        scope = Scope.load(write_scope(targets=["203.0.113.0/29", "203.0.113.0/30"]))
        hosts = scope.hosts()
        self.assertEqual(len(hosts), len(set(hosts)))


if __name__ == "__main__":
    unittest.main()
