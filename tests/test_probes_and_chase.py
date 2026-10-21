"""Probe and chase helpers: the judgement calls that keep reports honest.

Soft-404 handling, secret redaction and API URL joining get their own tests
because each one, when wrong, produces a confident false positive in a
document a client reads.
"""

import unittest

from extscan.chase import _join_api, _looks_like_app_error, _parse_yaml_paths
from extscan.models import Service
from extscan.probes import SENSITIVE_TCP, SENSITIVE_UDP, _looks_like_real_hit, _redact
from extscan.tools.net import Response


def resp(status=200, body="", ctype="text/html", **kw) -> Response:
    return Response(url="http://203.0.113.10/x", status=status,
                    headers={"content-type": ctype},
                    body=body.encode() if isinstance(body, str) else body, **kw)


class TestSoftFourOhFour(unittest.TestCase):
    """An SPA that serves index.html for every path must not light up."""

    def test_app_shell_is_not_a_hit(self):
        shell = "<html><head><title>App</title></head><body><h1>Page not found</h1></body></html>"
        self.assertFalse(_looks_like_real_hit("/config.json", resp(200, shell)))

    def test_404_status_is_never_a_hit(self):
        self.assertFalse(_looks_like_real_hit("/.env", resp(404, "nope")))

    def test_swagger_needs_json_shape(self):
        html = "<html><body>welcome to our site</body></html>"
        self.assertFalse(_looks_like_real_hit("/swagger.json", resp(200, html)))
        spec = '{"openapi":"3.0.1","paths":{"/a":{}}}'
        self.assertTrue(_looks_like_real_hit(
            "/swagger.json", resp(200, spec, "application/json")))

    def test_git_config_needs_git_markers(self):
        self.assertFalse(_looks_like_real_hit("/.git/config", resp(200, "<html>hi</html>")))
        real = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        self.assertTrue(_looks_like_real_hit("/.git/config", resp(200, real, "text/plain")))

    def test_env_needs_keyvalue_lines(self):
        self.assertFalse(_looks_like_real_hit("/.env", resp(200, "<html>no</html>")))
        self.assertTrue(_looks_like_real_hit(
            "/.env", resp(200, "DATABASE_URL=postgres://x\nDEBUG=false\n", "text/plain")))

    def test_empty_robots_counts_as_present(self):
        self.assertTrue(_looks_like_real_hit("/robots.txt", resp(200, "", "text/plain")))

    def test_html_robots_is_a_miss(self):
        self.assertFalse(_looks_like_real_hit(
            "/robots.txt", resp(200, "<html>home</html>", "text/html")))

    def test_prometheus_metrics_shape(self):
        self.assertTrue(_looks_like_real_hit(
            "/metrics", resp(200, "# HELP x\n# TYPE x counter\nx 1\n", "text/plain")))

    def test_graphql_400_proves_the_endpoint_exists(self):
        """A bare GET on GraphQL is rejected; that rejection is the evidence."""
        body = '{"errors":[{"message":"Must provide query string"}]}'
        self.assertTrue(_looks_like_real_hit(
            "/graphql", resp(400, body, "application/json")))

    def test_graphql_generic_400_is_not_a_hit(self):
        self.assertFalse(_looks_like_real_hit(
            "/graphql", resp(400, "<html>Bad Request</html>", "text/html")))

    def test_actuator_requires_json(self):
        self.assertTrue(_looks_like_real_hit(
            "/actuator", resp(200, '{"_links":{}}', "application/json")))
        self.assertFalse(_looks_like_real_hit(
            "/actuator", resp(200, "<html>404</html>", "text/html")))


class TestRedaction(unittest.TestCase):
    """Evidence must prove exposure without copying the client's secrets."""

    def test_values_removed_keys_kept(self):
        # Placeholder values, chosen not to resemble real credential formats
        # so the repo never trips a secret scanner.
        text = ("DATABASE_URL=postgres://user:fake-db-password@db/app\n"
                "STRIPE_SECRET_KEY=fake-stripe-value\n"
                "DEBUG=false\n")
        out = _redact(text)
        self.assertNotIn("fake-db-password", out)
        self.assertNotIn("fake-stripe-value", out)
        self.assertIn("DATABASE_URL", out)
        self.assertIn("STRIPE_SECRET_KEY", out)
        self.assertIn("redacted", out)
        self.assertIn("DEBUG=false", out)          # non-secret keys survive

    def test_length_preserved_for_triage(self):
        out = _redact("API_TOKEN=0123456789\n")
        self.assertIn("10 chars", out)

    def test_colon_separated_config(self):
        out = _redact("password: fake-password-value\n")
        self.assertNotIn("fake-password-value", out)

    def test_case_insensitive_key_match(self):
        out = _redact("aws_secret_access_key=fake-aws-secret-value\n")
        self.assertNotIn("fake-aws-secret-value", out)

    def test_plain_text_untouched(self):
        text = "User-agent: *\nDisallow: /admin\n"
        self.assertEqual(_redact(text), text)


class TestApiUrlJoining(unittest.TestCase):
    """urljoin silently drops a server's base path; _join_api must not."""

    def test_preserves_server_base_path(self):
        self.assertEqual(_join_api("http://203.0.113.10:8080/api", "/health"),
                         "http://203.0.113.10:8080/api/health")

    def test_handles_trailing_slash(self):
        self.assertEqual(_join_api("https://h/api/", "/v2/users"),
                         "https://h/api/v2/users")

    def test_handles_root_server(self):
        self.assertEqual(_join_api("https://h", "/health"), "https://h/health")

    def test_handles_scheme_relative_server(self):
        self.assertEqual(_join_api("h.test/api", "/x"), "https://h.test/api/x")

    def test_empty_path(self):
        self.assertEqual(_join_api("https://h/api", "/"), "https://h/api")


class TestAppErrorDetection(unittest.TestCase):
    def test_json_is_never_an_error_page(self):
        self.assertFalse(_looks_like_app_error(
            resp(200, '{"status":"ok"}', "application/json")))

    def test_html_not_found_is_an_error_page(self):
        self.assertTrue(_looks_like_app_error(
            resp(200, "<html><h1>Not Found</h1></html>", "text/html")))

    def test_login_page_is_an_error_page(self):
        self.assertTrue(_looks_like_app_error(
            resp(200, "<html><form>Please sign in</form></html>", "text/html")))

    def test_real_html_content_is_not_an_error(self):
        self.assertFalse(_looks_like_app_error(
            resp(200, "<html><body>Invoice #4 total $12</body></html>", "text/html")))


class TestYamlPathExtraction(unittest.TestCase):
    def test_extracts_top_level_paths(self):
        spec = (
            "openapi: 3.0.0\n"
            "info:\n  title: X\n"
            "paths:\n"
            "  /health:\n    get:\n      summary: ok\n"
            "  /users/{id}:\n    get:\n      summary: user\n"
            "components:\n  schemas: {}\n"
        )
        self.assertEqual(_parse_yaml_paths(spec), ["/health", "/users/{id}"])

    def test_stops_at_next_top_level_key(self):
        spec = "paths:\n  /a:\n    get: {}\ncomponents:\n  /b:\n    get: {}\n"
        self.assertEqual(_parse_yaml_paths(spec), ["/a"])

    def test_no_paths_section(self):
        self.assertEqual(_parse_yaml_paths("openapi: 3.0.0\ninfo:\n  title: X\n"), [])


class TestServiceClassification(unittest.TestCase):
    def test_http_detected_by_name(self):
        self.assertTrue(Service(host="h", port=9999, proto="tcp", name="http").is_http)

    def test_http_detected_by_common_port(self):
        self.assertTrue(Service(host="h", port=8080, proto="tcp", name="unknown").is_http)

    def test_udp_port_is_not_http(self):
        self.assertFalse(Service(host="h", port=8080, proto="udp", name="").is_http)

    def test_tls_from_tunnel(self):
        self.assertTrue(Service(host="h", port=9443, proto="tcp", tunnel="ssl").is_tls)

    def test_base_url_omits_default_ports(self):
        self.assertEqual(
            Service(host="h", port=443, proto="tcp", tunnel="ssl").base_url(), "https://h")
        self.assertEqual(
            Service(host="h", port=80, proto="tcp", name="http").base_url(), "http://h")

    def test_ipv6_literal_bracketed_in_url(self):
        svc = Service(host="2001:db8::1", port=8443, proto="tcp", tunnel="ssl")
        self.assertEqual(svc.base_url(), "https://[2001:db8::1]:8443")


class TestExposureTables(unittest.TestCase):
    def test_known_dangerous_ports_are_graded(self):
        for port, minimum in ((6379, "critical"), (27017, "critical"),
                              (3389, "high"), (445, "high"), (2375, "critical")):
            self.assertIn(port, SENSITIVE_TCP)
            self.assertEqual(SENSITIVE_TCP[port][1], minimum, f"port {port}")

    def test_ipmi_flagged_critical_on_udp(self):
        self.assertEqual(SENSITIVE_UDP[623][1], "critical")

    def test_every_entry_explains_why(self):
        for table in (SENSITIVE_TCP, SENSITIVE_UDP):
            for port, (label, sev, why) in table.items():
                self.assertTrue(label, port)
                self.assertIn(sev, ("low", "medium", "high", "critical"), port)
                self.assertGreater(len(why), 20, f"port {port} needs a real explanation")


if __name__ == "__main__":
    unittest.main()
