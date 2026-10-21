"""Triage ordering, deduplication and the manual-review queue."""

import unittest

from extscan.models import Finding, Service
from extscan.triage import issue_key, triage


def f(title, severity="info", host="203.0.113.10", port=443, review=False,
      reason="", source="test", tags=None, confidence="firm") -> Finding:
    return Finding(title=title, severity=severity, host=host, port=port,
                   source=source, review_required=review, review_reason=reason,
                   tags=tags or [], confidence=confidence)


class TestIssueKey(unittest.TestCase):
    def test_same_issue_on_different_hosts_collapses(self):
        a = f("Deprecated TLS versions enabled on 203.0.113.10:443", host="203.0.113.10")
        b = f("Deprecated TLS versions enabled on 203.0.113.11:443", host="203.0.113.11")
        self.assertEqual(issue_key(a), issue_key(b))

    def test_urls_are_normalised(self):
        a = f("Content review: https://203.0.113.10/robots.txt")
        b = f("Content review: https://203.0.113.11/metrics")
        self.assertEqual(issue_key(a), issue_key(b))

    def test_different_issues_stay_distinct(self):
        a = f("Expired TLS certificate on 203.0.113.10:443")
        b = f("Self-signed TLS certificate on 203.0.113.10:443")
        self.assertNotEqual(issue_key(a), issue_key(b))

    def test_same_title_from_different_tools_stays_distinct(self):
        a = f("Exposed swagger", source="nuclei:swagger")
        b = f("Exposed swagger", source="extscan:paths")
        self.assertNotEqual(issue_key(a), issue_key(b))

    def test_ipv6_normalised(self):
        a = f("TLS endpoint 2001:db8::1:443", host="2001:db8::1")
        b = f("TLS endpoint 2001:db8::2:443", host="2001:db8::2")
        self.assertEqual(issue_key(a), issue_key(b))


class TestOrdering(unittest.TestCase):
    def test_sorted_by_severity_descending(self):
        result = triage([
            f("i", "info"), f("c", "critical"), f("m", "medium"),
            f("h", "high"), f("l", "low"),
        ])
        self.assertEqual([x.title for x in result.findings],
                         ["c", "h", "m", "l", "i"])

    def test_review_items_precede_non_review_at_equal_severity(self):
        result = triage([
            f("plain", "high", review=False),
            f("needs review", "high", review=True, reason="why"),
        ])
        self.assertEqual(result.findings[0].title, "needs review")

    def test_hosts_sorted_numerically_not_lexically(self):
        result = triage([
            f("x", "high", host="203.0.113.100"),
            f("x", "high", host="203.0.113.9"),
        ])
        self.assertEqual([x.host for x in result.findings],
                         ["203.0.113.9", "203.0.113.100"])


class TestReviewQueue(unittest.TestCase):
    def test_only_flagged_findings_enter_the_queue(self):
        result = triage([
            f("flagged", "high", review=True, reason="decide X"),
            f("not flagged", "critical", review=False),
        ])
        self.assertEqual(len(result.review_queue), 1)
        self.assertEqual(result.review_queue[0].title, "flagged")

    def test_queue_is_numbered_from_one(self):
        result = triage([
            f("a", "low", review=True, reason="r"),
            f("b", "critical", review=True, reason="r"),
            f("c", "medium", review=True, reason="r"),
        ])
        self.assertEqual([i.priority for i in result.review_queue], [1, 2, 3])
        self.assertEqual(result.review_queue[0].title, "b")   # critical first

    def test_review_reason_becomes_the_question(self):
        result = triage([f("x", "high", review=True,
                           reason="Decide whether this is intended.")])
        self.assertEqual(result.review_queue[0].question,
                         "Decide whether this is intended.")

    def test_missing_reason_gets_a_default_question(self):
        result = triage([f("x", "high", review=True, reason="")])
        self.assertIn("Confirm", result.review_queue[0].question)

    def test_high_value_tags_outrank_same_severity(self):
        result = triage([
            f("boring", "medium", review=True, reason="r", tags=["http"]),
            f("secrets", "medium", review=True, reason="r", tags=["secrets"]),
        ])
        self.assertEqual(result.review_queue[0].title, "secrets")

    def test_collapsed_group_lists_its_instances(self):
        """An auditor must still see which endpoints the one entry covers."""
        result = triage([
            f("Unauthenticated API endpoint confirmed reachable: https://h/api/health",
              "medium", review=True, reason="r", source="extscan:api"),
            f("Unauthenticated API endpoint confirmed reachable: https://h/api/admin/users",
              "high", review=True, reason="r", source="extscan:api"),
        ])
        self.assertEqual(len(result.review_queue), 1)
        item = result.review_queue[0]
        self.assertEqual(item.severity, "high")        # worst of the group
        self.assertEqual(len(item.instances), 2)
        self.assertTrue(any("admin/users" in i for i in item.instances))
        self.assertEqual(len(item.finding_ids), 2)

    def test_single_instance_group_has_no_instance_list(self):
        result = triage([f("only one", "high", review=True, reason="r")])
        self.assertEqual(result.review_queue[0].instances, [])

    def test_multi_host_target_summarised(self):
        findings = [f(f"TLS 1.0 enabled on 203.0.113.{i}:443", "medium",
                      host=f"203.0.113.{i}", review=True, reason="r")
                    for i in range(1, 8)]
        result = triage(findings)
        item = result.review_queue[0]
        self.assertIn("7 hosts", item.target)
        self.assertIn("more", item.target)             # truncated host list
        self.assertEqual(len(item.hosts), 7)


class TestSystemicIssues(unittest.TestCase):
    def test_three_or_more_hosts_is_systemic(self):
        findings = [f(f"Deprecated TLS on 203.0.113.{i}:443", "medium",
                      host=f"203.0.113.{i}") for i in (1, 2, 3)]
        result = triage(findings)
        self.assertEqual(len(result.systemic), 1)
        self.assertEqual(len(result.systemic[0].hosts), 3)

    def test_two_hosts_is_not_systemic(self):
        findings = [f(f"Deprecated TLS on 203.0.113.{i}:443", "medium",
                      host=f"203.0.113.{i}") for i in (1, 2)]
        self.assertEqual(triage(findings).systemic, [])

    def test_systemic_sorted_by_severity_then_breadth(self):
        findings = []
        findings += [f(f"Low thing on 203.0.113.{i}:1", "low", host=f"203.0.113.{i}")
                     for i in range(1, 9)]
        findings += [f(f"High thing on 203.0.113.{i}:2", "high", host=f"203.0.113.{i}")
                     for i in range(1, 4)]
        result = triage(findings)
        self.assertEqual(result.systemic[0].severity, "high")


class TestStats(unittest.TestCase):
    def test_counts(self):
        services = [
            Service(host="203.0.113.10", port=443, proto="tcp", name="https", tunnel="ssl"),
            Service(host="203.0.113.10", port=161, proto="udp", name="snmp"),
            Service(host="203.0.113.11", port=22, proto="tcp", name="ssh"),
        ]
        result = triage([f("a", "high"), f("b", "high", host="203.0.113.11"),
                         f("c", "info")], services)
        s = result.stats
        self.assertEqual(s["findings_total"], 3)
        self.assertEqual(s["findings_by_severity"], {"high": 2, "info": 1})
        self.assertEqual(s["services_tcp"], 2)
        self.assertEqual(s["services_udp"], 1)
        self.assertEqual(s["web_services"], 1)
        self.assertEqual(s["hosts_with_findings"], 2)

    def test_empty_input(self):
        result = triage([], [])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.review_queue, [])
        self.assertEqual(result.stats["findings_total"], 0)


if __name__ == "__main__":
    unittest.main()
