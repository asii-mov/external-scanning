"""Safety invariants, enforced as tests rather than trusted to review.

Each of these encodes a property that must hold for extscan to be safe to point
at a client's infrastructure. They are cheap to check and they fail loudly if a
future change erodes one.
"""

import ast
import unittest
from pathlib import Path

from extscan.policy import Policy
from extscan.tools import nuclei

SOURCE_DIR = Path(__file__).resolve().parent.parent / "extscan"
SOURCE_FILES = sorted(SOURCE_DIR.rglob("*.py"))


def iter_calls():
    """Yield (path, ast.Call) for every call in the package source."""
    for path in SOURCE_FILES:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                yield path, node


def call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


class TestNoShellExecution(unittest.TestCase):
    """Commands carry target-derived strings; a shell would make those code."""

    def test_no_subprocess_call_uses_a_shell(self):
        offenders = []
        for path, node in iter_calls():
            if call_name(node) not in ("run", "Popen", "call", "check_output",
                                       "check_call"):
                continue
            for kw in node.keywords:
                if kw.arg == "shell":
                    is_false = isinstance(kw.value, ast.Constant) and kw.value.value is False
                    if not is_false:
                        offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(offenders, [], f"shell execution found at {offenders}")

    def test_no_os_system_or_popen(self):
        offenders = [
            f"{path.name}:{node.lineno}"
            for path, node in iter_calls()
            if call_name(node) in ("system", "popen", "spawnl", "spawnv", "execv")
        ]
        self.assertEqual(offenders, [])

    def test_every_subprocess_run_passes_shell_false_explicitly(self):
        """Explicit beats relying on the default, in this file more than most."""
        missing = []
        for path, node in iter_calls():
            if call_name(node) != "run":
                continue
            # Only the subprocess.run calls, not Runner.run / probe.run.
            if not (isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"):
                continue
            if "shell" not in {kw.arg for kw in node.keywords}:
                missing.append(f"{path.name}:{node.lineno}")
        self.assertEqual(missing, [], f"shell= not stated at {missing}")

    def test_no_eval_or_exec(self):
        # Bare names only: `re.compile` is an attribute call and perfectly fine,
        # whereas a bare `compile(...)` is the builtin.
        offenders = [
            f"{path.name}:{node.lineno}"
            for path, node in iter_calls()
            if isinstance(node.func, ast.Name)
            and node.func.id in ("eval", "exec", "compile", "__import__")
        ]
        self.assertEqual(offenders, [])


class TestDefaultPolicyIsNonDestructive(unittest.TestCase):
    def setUp(self):
        self.profiles = {name: Policy.for_profile(name)
                         for name in ("quick", "standard", "thorough")}

    def test_destructive_nuclei_families_excluded_in_every_profile(self):
        for name, policy in self.profiles.items():
            argv = nuclei.argv(policy, "/t", "/o")
            self.assertIn("-exclude-tags", argv, name)
            excluded = argv[argv.index("-exclude-tags") + 1]
            for tag in ("dos", "intrusive", "fuzz", "brute-force"):
                self.assertIn(tag, excluded, f"{name} does not exclude {tag}")

    def test_intrusive_is_opt_in_in_every_profile(self):
        for name, policy in self.profiles.items():
            self.assertFalse(policy.nuclei.allow_intrusive, name)

    def test_out_of_band_detection_off_in_every_profile(self):
        """interactsh would relay client traffic through a third-party host."""
        for name, policy in self.profiles.items():
            self.assertFalse(policy.nuclei.interactsh, name)
            self.assertIn("-no-interactsh", nuclei.argv(policy, "/t", "/o"), name)

    def test_system_proxy_off_in_every_profile(self):
        for name, policy in self.profiles.items():
            self.assertFalse(policy.http.use_system_proxy, name)

    def test_nmap_never_requests_exploit_or_dos_scripts(self):
        for name, policy in self.profiles.items():
            scripts = policy.nmap.scripts
            for banned in ("exploit", "dos", "brute", "malware"):
                self.assertNotIn(banned, scripts, f"{name} nmap scripts include {banned}")

    def test_rate_limits_are_set(self):
        for name, policy in self.profiles.items():
            self.assertGreater(policy.nuclei.rate_limit, 0, name)
            self.assertLessEqual(policy.nuclei.rate_limit, 200, name)
            self.assertGreater(policy.max_workers, 0, name)
            self.assertLessEqual(policy.max_workers, 32, name)

    def test_lead_depth_is_bounded(self):
        for name, policy in self.profiles.items():
            self.assertGreaterEqual(policy.max_lead_depth, 1, name)
            self.assertLessEqual(policy.max_lead_depth, 6, name)
            self.assertLessEqual(policy.max_leads_per_run, 5000, name)

    def test_snmp_communities_are_read_probes_only(self):
        """The probe list exists to test read access; nothing here implies a SET."""
        policy = Policy.for_profile("standard")
        self.assertTrue(policy.snmp.communities)
        self.assertIn("public", policy.snmp.communities)

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            Policy.for_profile("aggressive")


class TestNoSetOperationsInSnmp(unittest.TestCase):
    def test_snmp_module_defines_no_set_pdu(self):
        """A SET would change client state during an audit."""
        source = (SOURCE_DIR / "tools" / "snmp.py").read_text()
        self.assertNotIn("0xA3", source)          # SetRequest PDU tag
        self.assertNotIn("TAG_SET", source)

    def test_only_get_and_getnext_pdus_are_used(self):
        from extscan.tools import snmp
        self.assertEqual(snmp.TAG_GET, 0xA0)
        self.assertEqual(snmp.TAG_GETNEXT, 0xA1)
        self.assertFalse(hasattr(snmp, "snmp_set"))


class TestChaseHandlersRefuseWrites(unittest.TestCase):
    def test_api_endpoint_handler_only_accepts_get(self):
        source = (SOURCE_DIR / "chase.py").read_text()
        self.assertIn('refusing to invoke a non-GET operation', source)

    def test_only_graphql_introspection_is_posted(self):
        """The single POST in the chase layer is a read-only introspection query."""
        source = (SOURCE_DIR / "chase.py").read_text()
        tree = ast.parse(source)
        posts = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value == "POST":
                posts.append(node.lineno)
        # One in _post_json's Request(), and no others.
        self.assertLessEqual(len(posts), 2, f"unexpected POST at lines {posts}")
        self.assertIn("__schema", source)

    def test_introspection_query_contains_no_mutation_call(self):
        from extscan.chase import INTROSPECTION_QUERY
        self.assertIn("__schema", INTROSPECTION_QUERY)
        self.assertNotIn("mutation ", INTROSPECTION_QUERY.lower())


class TestScopeEnforcementIsPresentOnNetworkPaths(unittest.TestCase):
    """Every outbound helper must consult the scope before connecting."""

    def test_fetch_asserts_url_scope(self):
        source = (SOURCE_DIR / "tools" / "net.py").read_text()
        self.assertIn("scope.assert_url", source)

    def test_tls_inspection_asserts_host_scope(self):
        source = (SOURCE_DIR / "tools" / "net.py").read_text()
        self.assertIn("scope.assert_host", source)

    def test_post_json_asserts_url_scope(self):
        source = (SOURCE_DIR / "chase.py").read_text()
        self.assertIn("assert_url(url", source)

    def test_snmp_probe_asserts_host_scope(self):
        source = (SOURCE_DIR / "probes.py").read_text()
        self.assertIn("assert_host", source)

    def test_redirects_are_not_followed_automatically(self):
        """urllib's default redirect handling would bypass the per-hop check."""
        source = (SOURCE_DIR / "tools" / "net.py").read_text()
        self.assertIn("_NoRedirect", source)
        self.assertIn("return None", source)


class TestRedactionIsAppliedToSensitiveEvidence(unittest.TestCase):
    def test_secret_bearing_handlers_redact(self):
        source = (SOURCE_DIR / "chase.py").read_text()
        # Both the secret-file and generic content handlers must redact.
        self.assertIn("_redact(resp.text", source)

    def test_env_like_paths_redacted_in_probe_evidence(self):
        source = (SOURCE_DIR / "probes.py").read_text()
        self.assertIn("body_preview = _redact(body_preview)", source)


class TestAuthorisationCannotBeSkipped(unittest.TestCase):
    def test_init_run_checks_the_testing_window(self):
        source = (SOURCE_DIR / "pipeline.py").read_text()
        self.assertIn("scope.assert_window()", source)

    def test_every_active_stage_checks_the_window(self):
        source = (SOURCE_DIR / "pipeline.py").read_text()
        # init_run, discover, probe, chase_leads
        self.assertGreaterEqual(source.count("scope.assert_window()"), 4)

    def test_scope_load_requires_authorization(self):
        source = (SOURCE_DIR / "scope.py").read_text()
        self.assertIn("has no `authorization` block", source)


if __name__ == "__main__":
    unittest.main()
