"""Safety invariants, enforced as tests rather than trusted to review.

Each of these encodes a property that must hold for extscan to be safe to point
at a client's infrastructure. They are cheap to check and they fail loudly if a
future change erodes one.
"""

import ast
import contextlib
import io
import json
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from extscan import chase as chase_mod
from extscan import pipeline, probes, safety
from extscan.models import Lead, Service
from extscan.policy import Policy
from extscan.runner import Runner
from extscan.safety import CAP_REASON, SafetyClass
from extscan.scope import Authorization, Scope, ScopeError
from extscan.store import Store
from extscan.tools import dns, net, nuclei, sshaudit
from tests.test_dns import (
    CLIENT_ZONE,
    NSEC_ZONE,
    TAKEOVER_NAMES,
    TAKEOVER_ZONE,
    FakeDns,
    lab_scope,
)

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

    def test_credential_templates_excluded_in_every_profile(self):
        """default-login templates submit passwords; that is credential testing."""
        for name, policy in self.profiles.items():
            argv = nuclei.argv(policy, "/t", "/o")
            excluded = argv[argv.index("-exclude-tags") + 1].split(",")
            for tag in ("default-login", "default-logins", "creds-stuffing"):
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


class TestSshAuditNeverRunsRateOrDosTests(unittest.TestCase):
    """ssh-audit runs a connection-rate test unless told not to, and `--dheat`
    is a DoS. The first must always be skipped; the second never sent."""

    DANGEROUS = ("--dheat", "--conn-rate-test")

    def assert_safe(self, argv, label):
        self.assertIn("--skip-rate-test", argv, label)
        for arg in argv:
            self.assertNotIn(arg.split("=", 1)[0], self.DANGEROUS, label)

    def test_every_profile_skips_the_rate_test_and_never_sends_dheat(self):
        for name in ("quick", "standard", "thorough"):
            policy = Policy.for_profile(name)
            for host in ("127.0.0.1", "::1", "ssh.example.test"):
                self.assert_safe(sshaudit.argv(policy.ssh_audit, host, 22), name)

    def test_allowed_extra_args_keep_the_invariant(self):
        policy = Policy.from_dict({"ssh_audit": {"extra_args": ["-4"]}})
        self.assert_safe(sshaudit.argv(policy.ssh_audit, "127.0.0.1", 2222), "-4")

    def test_a_policy_cannot_add_dos_or_rate_flags(self):
        for extra in (["--dheat", "10"], ["--dheat=10"], ["--conn-rate-test", "5"],
                      ["--conn-rate-test=5:10"], ["-g", "2048-8192"], ["-T", "t.txt"],
                      ["-c"], ["--threads", "64"], ["-4g", "1-2"], ["--dhe"]):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                Policy.from_dict({"ssh_audit": {"extra_args": extra}})

    def test_argv_refuses_flags_added_after_the_policy_loaded(self):
        policy = Policy()
        policy.ssh_audit.extra_args.append("--dheat=4")
        with self.assertRaises(ValueError):
            sshaudit.argv(policy.ssh_audit, "127.0.0.1", 22)

    def test_safe_argv_check_rejects_a_hand_built_command(self):
        with self.assertRaises(ValueError):
            sshaudit.assert_safe_argv(["ssh-audit", "-j", "127.0.0.1:22"])
        with self.assertRaises(ValueError):
            sshaudit.assert_safe_argv(["ssh-audit", "--skip-rate-test", "--dheat", "1",
                                       "127.0.0.1:22"])

    def test_ssh_audit_run_asserts_host_scope(self):
        source = (SOURCE_DIR / "tools" / "sshaudit.py").read_text()
        self.assertIn("scope.assert_host", source)


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
        # The GraphQL introspection call, and no others.
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

    def test_chase_makes_no_requests_outside_net_fetch(self):
        source = (SOURCE_DIR / "chase.py").read_text()
        self.assertNotIn("urllib.request", source)

    def test_snmp_probe_asserts_host_scope(self):
        source = (SOURCE_DIR / "probes.py").read_text()
        self.assertIn("assert_host", source)

    def test_post_redirect_off_scope_is_refused(self):
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        scope = Scope(engagement="redirect test", client="self-test",
                      authorization=Authorization(reference="LOCAL-TEST",
                                                  authorized_by="test harness"),
                      targets=["127.0.0.1/32"], allow_private=True)
        resp = net.fetch(f"http://127.0.0.1:{server.server_address[1]}/graphql", scope,
                         Policy().http, method="POST", data=b"{}")
        self.assertEqual(resp.status, 0)
        self.assertIn("scope refusal", resp.error)
        self.assertIn("169.254.169.254", resp.url)

    def test_redirects_are_not_followed_automatically(self):
        """urllib's default redirect handling would bypass the per-hop check."""
        source = (SOURCE_DIR / "tools" / "net.py").read_text()
        self.assertIn("_NoRedirect", source)
        self.assertIn("return None", source)


class TestDnsChecksAreReadOnlyAndScoped(unittest.TestCase):
    source = (SOURCE_DIR / "tools" / "dns.py").read_text()

    def test_every_packet_passes_the_dns_scope_gate(self):
        funcs = [n for n in ast.walk(ast.parse(self.source)) if isinstance(n, ast.FunctionDef)]

        def callers(name: str) -> set[str]:
            return {f.name for f in funcs for c in ast.walk(f)
                    if isinstance(c, ast.Call) and call_name(c) == name}

        send = next(f for f in funcs if f.name == "_send")
        self.assertIn("scope.assert_dns_name", ast.get_source_segment(self.source, send))
        openers = callers("socket") | callers("create_connection")
        self.assertEqual(openers, {"_udp", "_tcp_query", "_axfr"})
        for opener in openers:
            self.assertEqual(callers(opener), {"_exchange"}, opener)
        self.assertEqual(callers("_exchange"), {"_send"})

    def test_only_query_opcode_is_ever_sent(self):
        """UPDATE (5) would change the client's zone; NOTIFY (4) prods its secondaries."""
        names = {n.id for n in ast.walk(ast.parse(self.source)) if isinstance(n, ast.Name)}
        self.assertFalse({n for n in names if "UPDATE" in n.upper() or "NOTIFY" in n.upper()})
        records = [*NSEC_ZONE, *[r for r in TAKEOVER_ZONE if r not in NSEC_ZONE]]
        with FakeDns(records, axfr=True, refuse={("lame.lab.test", "SOA")}) as ns:
            dns.audit_zone(lab_scope(), "lab.test", TAKEOVER_NAMES, ns.policy())
        self.assertGreater(len(ns.queries), 20)
        self.assertEqual({q.opcode for q in ns.queries}, {0})

    def test_dns_module_makes_no_http_requests(self):
        imported = set()
        for node in ast.walk(ast.parse(self.source)):
            if isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported |= {f"{node.module}.{a.name}" for a in node.names}
        banned = ("urllib", "http", "requests", "httpx", "ssl", "extscan.tools.net")
        self.assertEqual(sorted(m for m in imported if m.startswith(banned)), [])

    def test_a_host_name_never_unlocks_its_zone(self):
        """The names of in-scope hosts pass only as A and MX through the
        resolver. The auth lane and zone lookups still need scope.domains."""
        name = "host5.client.test"
        with FakeDns(CLIENT_ZONE) as ns:
            client = dns._Client(lab_scope(), ns.policy(), frozenset({name}))
            auth = dns._Authority("client.test", "ns1.client.test", "127.0.0.1")
            refused = {
                "NS of the name": lambda: client.lookup(name, "NS"),
                "SOA of the name": lambda: client.lookup(name, "SOA"),
                "a name below it": lambda: client.lookup(f"www.{name}", "A"),
                "its parent zone": lambda: client.lookup("client.test", "A"),
                "authorities of the name": lambda: client.authorities(name),
                "authorities of its zone": lambda: client.authorities("client.test"),
                "the auth lane": lambda: client.ask(auth, name, "A"),
                "a transfer": lambda: client.ask(auth, "client.test", "AXFR"),
            }
            for what, call in refused.items():
                with self.subTest(what), self.assertRaises(ScopeError):
                    call()
            self.assertEqual(ns.queries, [])
            client.lookup(name, "A")
            client.lookup(name, "MX")
        self.assertEqual([(q.name, q.qtype, q.rd) for q in ns.queries],
                         [(name, "A", True), (name, "MX", True)])

    def test_unknown_skip_check_is_rejected_before_any_packet(self):
        with FakeDns() as ns:
            policy = Policy.from_dict({"dns": {**ns.policy().__dict__,
                                               "skip": ["zone-bruteforce"]}}).dns
            for dry_run in (False, True):
                with self.assertRaises(ValueError):
                    dns.audit_zone(lab_scope(), "lab.test", [], policy, dry_run=dry_run)
        self.assertEqual(ns.queries, [])


def _have_chromium() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            pw.chromium.launch().close()
    except Exception:
        return False
    return True


@unittest.skipUnless(_have_chromium(), "needs the screenshots extra and its Chromium")
class TestScreenshotsStayInScope(unittest.TestCase):
    """The browser must not send one request outside scope, redirects included.

    Playwright follows a fulfilled 3xx without routing the next hop, so this
    is the property most likely to regress silently.
    """

    def test_no_request_reaches_an_off_scope_server(self):
        import tempfile

        from extscan.policy import ScreenshotPolicy
        from extscan.screenshots import browser_shooter

        hits: list[str] = []

        class Off(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()

        off = ThreadingHTTPServer(("127.0.0.1", 0), Off)
        off_url = f"http://127.0.0.1:{off.server_address[1]}"

        class In(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                redirects = {"/away": f"{off_url}/stolen", "/hop": "/away",
                             "/img": f"{off_url}/via-img.png"}
                if self.path in redirects:
                    self.send_response(302)
                    self.send_header("Location", redirects[self.path])
                    self.end_headers()
                    return
                body = (f'<title>in</title><img src="{off_url}/pixel.png">'
                        f'<img src="/img"><iframe src="{off_url}/frame"></iframe>'
                        f'<script>fetch("{off_url}/xhr")</script>').encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

        inside = ThreadingHTTPServer(("127.0.0.2", 0), In)
        for server in (off, inside):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

        scope = Scope(engagement="screenshot test", client="self-test",
                      authorization=Authorization(reference="LOCAL-TEST",
                                                  authorized_by="test harness"),
                      targets=["127.0.0.2/32"], allow_private=True)
        base = f"http://127.0.0.2:{inside.server_address[1]}"
        with tempfile.TemporaryDirectory() as tmp, \
                browser_shooter(scope, ScreenshotPolicy(timeout_sec=10)) as shoot:
            page = shoot(f"{base}/page", Path(tmp) / "page.png")
            hop = shoot(f"{base}/hop", Path(tmp) / "hop.png")
            self.assertTrue((Path(tmp) / "hop.png").is_file())

        self.assertEqual(hits, [])
        self.assertEqual(page["title"], "in")
        self.assertIn(f"{off_url}/pixel.png", page["blocked"])
        self.assertIn(f"{off_url}/via-img.png", page["blocked"])
        self.assertEqual(hop["blocked"], [f"{off_url}/stolen"])
        self.assertTrue(hop["final_url"].startswith(base))


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


# ---------------------------------------------------------------------------
# Safety classes (extscan/safety.py): every check is labelled, nothing is
# invasive, and the policy's max_safety cap skips what is above it as a gap.
# ---------------------------------------------------------------------------

# The class each existing check was given after reading what it sends. A
# new check is not pinned here; lowering one of these is a safety change and
# must be made here on purpose.
PINNED = {
    "probe": {"http_fingerprint": "active", "tls": "active", "snmp": "active",
              "exposure": "passive", "ssh": "passive", "iis": "loud", "sslscan": "loud",
              "ssh_audit": "loud", "web_fingerprint": "active"},
    "chase": {"openapi": "active", "graphql": "active", "git_exposure": "active",
              "web_paths": "active", "secret_file": "active", "api_endpoint": "active",
              "snmp_walk": "active", "tls_detail": "loud"},
    "stage": {"recon:subdomains": "passive", "dns:host-names": "passive",
              "dns:takeover": "active", "dns:axfr": "active", "dns:nsec-walk": "loud",
              "discover:tcp": "active", "discover:udp": "active", "nmap:nse": "loud",
              "nmap:os-detection": "loud", "probe:nuclei": "loud", "http:paths": "loud",
              "screenshot": "active"},
}

# Names a passive probe must not touch: each one sends packets.
_NETWORK_NAMES = {"net", "snmp", "iis", "sslscan", "runner", "fetch", "inspect_tls"}


class TestEveryCheckHasASafetyLabel(unittest.TestCase):
    def test_every_register_call_passes_safety(self):
        """Read the source, so the failure names the function even if the
        import-time check were ever loosened."""
        tree = ast.parse((SOURCE_DIR / "probes.py").read_text())
        unlabelled = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for deco in node.decorator_list:
                if isinstance(deco, ast.Call) and call_name(deco) == "register" and \
                        "safety" not in {kw.arg for kw in deco.keywords}:
                    unlabelled.append(f"{node.name} (probes.py:{deco.lineno})")
        self.assertEqual(unlabelled, [], f"@register without safety=: {unlabelled}")

    def test_every_registered_probe_has_a_class(self):
        self.assertTrue(probes.REGISTRY)
        for p in probes.REGISTRY:
            self.assertIsInstance(p.safety, SafetyClass, p.name)

    def test_register_without_safety_fails_naming_the_probe(self):
        before = list(probes.REGISTRY)
        with self.assertRaisesRegex(TypeError, "'unlabelled_probe'.*safety="):
            probes.register("unlabelled_probe", lambda s: True, "x")
        with self.assertRaisesRegex(TypeError, "'stringly'"):
            probes.register("stringly", lambda s: True, "x", safety="active")
        self.assertEqual(probes.REGISTRY, before)

    def test_every_chase_handler_has_a_class(self):
        self.assertEqual(set(chase_mod.HANDLER_SAFETY), set(chase_mod.HANDLERS))
        for kind, label in chase_mod.HANDLER_SAFETY.items():
            self.assertIsInstance(label.safety, SafetyClass, kind)
            self.assertTrue(label.why, kind)

    def test_every_stage_has_a_class(self):
        for key, label in safety.STAGES.items():
            self.assertIsInstance(label.safety, SafetyClass, key)
            self.assertTrue(label.why, key)
        dns_checks = {c.name for c in (*dns.CHECKS, dns.HOST_NAMES)}
        self.assertEqual(set(safety.DNS_CHECKS), dns_checks)
        self.assertLessEqual(set(safety.DNS_CHECKS.values()), set(safety.STAGES))

    def test_nothing_is_invasive(self):
        rows = safety.table()
        invasive = [(r["kind"], r["name"]) for r in rows if r["safety"] == "invasive"]
        self.assertEqual(invasive, [])

    def test_table_matches_the_registries(self):
        rows = safety.table()
        by_kind = {k: {r["name"]: r["safety"] for r in rows if r["kind"] == k}
                   for k in ("stage", "probe", "chase")}
        self.assertEqual(len(rows), sum(len(v) for v in by_kind.values()))
        self.assertEqual(by_kind["probe"], {p.name: str(p.safety) for p in probes.REGISTRY})
        self.assertEqual(by_kind["chase"], {k: str(v.safety) for k, v
                                            in chase_mod.HANDLER_SAFETY.items()})
        self.assertEqual(by_kind["stage"], {k: str(v.safety) for k, v
                                            in safety.STAGES.items()})
        self.assertEqual(len(by_kind["probe"]), len(probes.REGISTRY), "duplicate probe names")

    def test_existing_checks_keep_their_pinned_class(self):
        rows = {(r["kind"], r["name"]): r["safety"] for r in safety.table()}
        for kind, pinned in PINNED.items():
            for name, cls in pinned.items():
                self.assertEqual(rows.get((kind, name)), cls, f"{kind} {name}")

    def test_passive_probes_send_nothing(self):
        import inspect
        for p in probes.REGISTRY:
            if p.safety is not SafetyClass.PASSIVE:
                continue
            tree = ast.parse(inspect.getsource(p.run).lstrip())
            used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
                   {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            self.assertEqual(used & _NETWORK_NAMES, set(), f"passive probe {p.name}")

    def test_classes_are_ordered(self):
        self.assertLess(SafetyClass.PASSIVE, SafetyClass.ACTIVE)
        self.assertLess(SafetyClass.ACTIVE, SafetyClass.LOUD)
        self.assertLess(SafetyClass.LOUD, SafetyClass.INVASIVE)
        self.assertIs(SafetyClass.parse("Loud"), SafetyClass.LOUD)
        with self.assertRaises(ValueError):
            SafetyClass.parse("aggressive")


class TestSafetyCapPolicy(unittest.TestCase):
    def test_default_cap_is_loud_in_every_profile(self):
        for name in ("quick", "standard", "thorough"):
            self.assertIs(Policy.for_profile(name).safety_cap(), SafetyClass.LOUD, name)
            self.assertFalse(Policy.for_profile(name).allow_invasive, name)

    def test_max_safety_is_loaded_from_the_top_level(self):
        """policy.py once ignored all but three top-level keys."""
        self.assertIs(Policy.from_dict({"max_safety": "active"}).safety_cap(),
                      SafetyClass.ACTIVE)
        loaded = Policy.from_dict(Policy.from_dict({"max_safety": "PASSIVE"}).to_dict())
        self.assertEqual(loaded.max_safety, "passive")

    def test_example_low_noise_policy_caps_at_active(self):
        path = SOURCE_DIR.parent / "examples" / "policy.active-only.json"
        self.assertIs(Policy.load(path).safety_cap(), SafetyClass.ACTIVE)

    def test_invasive_needs_the_explicit_opt_in(self):
        with self.assertRaisesRegex(ValueError, "allow_invasive"):
            Policy.from_dict({"max_safety": "invasive"})
        with self.assertRaisesRegex(ValueError, "allow_invasive"):
            Policy.from_dict({"max_safety": "invasive", "allow_invasive": "yes"})
        p = Policy.from_dict({"max_safety": "invasive", "allow_invasive": True})
        self.assertIs(p.safety_cap(), SafetyClass.INVASIVE)

    def test_unknown_class_is_rejected(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"max_safety": "aggressive"})

    def test_init_run_refuses_an_unconfirmed_invasive_cap(self):
        policy = Policy()
        policy.max_safety = "invasive"
        scope = lab_scope()
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            pipeline.init_run(tmp, scope, policy)


class _CapStage(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "t", "client": "c",
            "authorization": {"reference": "T", "authorized_by": "x"},
            "targets": ["127.0.0.1/32"], "domains": ["example.test"],
            "allow_private": True,
        }))
        self.scope = Scope.load(sp)
        self.store = Store.create(self.tmp / "runs", "t", run_id="r")
        self.store.write_meta({"run_id": "r"})
        self.runner = Runner(self.store)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def policy(cap: str, **top) -> Policy:
        return Policy.from_dict({"max_safety": cap, **top})

    def cap_gaps(self):
        return sorted((d.stage, d.component) for d in self.store.degradations()
                      if d.reason.startswith(CAP_REASON))

    def quiet(self):
        return contextlib.redirect_stdout(io.StringIO())


def _must_not_run(*_a, **_k):
    raise AssertionError("a check above the safety cap ran")


class TestCapSkipsProbes(_CapStage):
    tls_svc = Service(host="127.0.0.1", port=8443, proto="tcp", name="https", tunnel="ssl")

    def run_probe(self, cap, only):
        with self.quiet():
            pipeline.probe(self.store, self.scope, self.policy(cap), self.runner, only=only)
        return self.store.services()[0]

    def test_loud_probe_skipped_as_a_gap_and_retried_under_a_higher_cap(self):
        self.store.save_services([self.tls_svc])
        tls = next(p for p in probes.REGISTRY if p.name == "tls")
        ssl = next(p for p in probes.REGISTRY if p.name == "sslscan")
        with mock.patch.object(tls, "run", return_value=([], [])), \
                mock.patch.object(ssl, "run", side_effect=_must_not_run):
            svc = self.run_probe("active", ["tls", "sslscan"])
        self.assertEqual(self.cap_gaps(), [("probe:sslscan", "sslscan")])
        gap = self.store.degradations()[0]
        self.assertIn("sslscan is loud, policy max_safety is active", gap.reason)
        self.assertEqual(gap.hosts, ["127.0.0.1"])
        self.assertIn('"max_safety": "loud"', gap.remedy)
        self.assertEqual(svc.probed_by, ["tls"])

        with mock.patch.object(ssl, "run", return_value=([], [])) as ran:
            svc = self.run_probe("loud", ["tls", "sslscan"])
        ran.assert_called_once()
        self.assertEqual(self.cap_gaps(), [])
        self.assertEqual(sorted(svc.probed_by), ["sslscan", "tls"])

    def test_invasive_probe_is_refused_under_the_default_cap(self):
        fake = probes.Probe(name="fake_invasive", matches=lambda s: True,
                            run=mock.Mock(return_value=([], [])),
                            safety=SafetyClass.INVASIVE, description="test only")
        self.store.save_services([self.tls_svc])
        with mock.patch.object(probes, "REGISTRY", [*probes.REGISTRY, fake]):
            svc = self.run_probe("loud", ["fake_invasive"])
            fake.run.assert_not_called()
            self.assertEqual(self.cap_gaps(), [("probe:fake_invasive", "fake_invasive")])
            self.assertEqual(svc.probed_by, [])
            with self.quiet():
                pipeline.probe(self.store, self.scope,
                               self.policy("invasive", allow_invasive=True),
                               self.runner, only=["fake_invasive"])
            fake.run.assert_called_once()

    def test_nuclei_skipped_as_a_serious_gap(self):
        web = Service(host="127.0.0.1", port=9, proto="tcp", name="http")
        self.store.save_services([web])
        with mock.patch.object(pipeline.nuclei, "run", side_effect=_must_not_run):
            svc = self.run_probe("active", ["nuclei"])
        self.assertEqual(self.cap_gaps(), [("probe:nuclei", "nuclei")])
        self.assertEqual(self.store.degradations()[0].severity, "serious")
        self.assertNotIn("nuclei", svc.probed_by)
        self.assertEqual(self.store.commands(), [])

    def test_path_list_dropped_under_active_and_service_left_unmarked(self):
        web = Service(host="127.0.0.1", port=9, proto="tcp", name="http")
        self.store.save_services([web])
        fetched = []

        def fetch(url, *_a, **_k):
            fetched.append(url)
            return net.Response(url=url, status=404, reason="Not Found")

        with mock.patch.object(probes.net, "fetch", side_effect=fetch):
            svc = self.run_probe("active", ["http_fingerprint"])
        self.assertEqual(fetched, [web.base_url()])
        self.assertEqual(self.cap_gaps(), [("probe:http_fingerprint", "http:paths")])
        self.assertNotIn("http_fingerprint", svc.probed_by)

        fetched.clear()
        with mock.patch.object(probes.net, "fetch", side_effect=fetch):
            svc = self.run_probe("loud", ["http_fingerprint"])
        self.assertEqual(len(fetched), 1 + len(Policy().http.paths))
        self.assertEqual(self.cap_gaps(), [])
        self.assertIn("http_fingerprint", svc.probed_by)


class TestCapSkipsChaseAndStages(_CapStage):
    def test_loud_lead_stays_open_with_a_gap(self):
        self.store.add_leads([Lead(kind="tls_detail", host="127.0.0.1", port=443),
                              Lead(kind="web_paths", host="127.0.0.1", port=80,
                                   url="http://127.0.0.1/robots.txt")])
        done = mock.Mock(return_value=chase_mod.ChaseResult([], [], note="ok"))
        with mock.patch.dict(chase_mod.HANDLERS, {"tls_detail": _must_not_run,
                                                  "web_paths": done}), self.quiet():
            pipeline.chase_leads(self.store, self.scope, self.policy("active"), self.runner)
        status = {ld.kind: ld.status for ld in self.store.leads()}
        self.assertEqual(status, {"tls_detail": "open", "web_paths": "done"})
        self.assertEqual(self.cap_gaps(), [("chase", "lead:tls_detail")])

        with mock.patch.dict(chase_mod.HANDLERS, {"tls_detail": done}), self.quiet():
            pipeline.chase_leads(self.store, self.scope, self.policy("loud"), self.runner)
        self.assertEqual({ld.status for ld in self.store.leads()}, {"done"})
        self.assertEqual(self.cap_gaps(), [])

    def test_passive_cap_skips_discovery_without_running_nmap(self):
        with mock.patch.object(pipeline.nmap, "run_tcp", side_effect=_must_not_run), \
                mock.patch.object(pipeline.nmap, "run_udp", side_effect=_must_not_run), \
                mock.patch.object(pipeline.nmap, "udp_requires_root", return_value=False), \
                self.quiet():
            pipeline.discover(self.store, self.scope, self.policy("passive"), self.runner)
        self.assertEqual(self.cap_gaps(), [("discover:tcp", "discover:tcp"),
                                           ("discover:udp", "discover:udp")])
        self.assertTrue(all(d.severity == "serious" for d in self.store.degradations()))

    def test_active_cap_drops_nse_and_os_detection_from_nmap(self):
        self.runner = Runner(self.store, dry_run=True)
        with mock.patch.object(pipeline.nmap, "_is_root", return_value=True), self.quiet():
            pipeline.discover(self.store, self.scope, self.policy("active"), self.runner,
                              udp=False)
        argv = self.store.commands()[0]["argv"]
        self.assertEqual(argv[:2], ["nmap", "-sS"])
        self.assertNotIn("--script", argv)
        self.assertNotIn("-O", argv)
        self.assertEqual(self.cap_gaps(), [("discover", "nmap:nse"),
                                           ("discover", "nmap:os-detection")])

    def test_loud_cap_keeps_nmap_as_it_was(self):
        self.runner = Runner(self.store, dry_run=True)
        with mock.patch.object(pipeline.nmap, "_is_root", return_value=True), self.quiet():
            pipeline.discover(self.store, self.scope, Policy(), self.runner, udp=False)
        argv = self.store.commands()[0]["argv"]
        self.assertIn("--script", argv)
        self.assertIn("-O", argv)
        self.assertEqual(self.cap_gaps(), [])

    def test_active_cap_skips_the_nsec_walk(self):
        with self.quiet():
            policy = pipeline._dns_under_cap(self.store, self.policy("active"), "recon",
                                             [c.name for c in dns.CHECKS], ["example.test"],
                                             "`extscan recon <run>`", dry_run=False)
        self.assertEqual(policy.dns.skip, ["nsec-walk"])
        self.assertEqual(self.cap_gaps(), [("recon", "dns:nsec-walk")])
        results = dns.audit_zone(self.scope, "example.test", [], policy.dns, dry_run=True)
        self.assertNotIn("nsec-walk", {r.check for r in results})

    def test_passive_cap_skips_dns_checks_that_reach_nameservers(self):
        with mock.patch.object(pipeline.subdomains, "enumerate_domain",
                               return_value=([], [])), \
                mock.patch.object(pipeline.dns, "audit_zone", return_value=[]) as audit, \
                self.quiet():
            pipeline.recon(self.store, self.scope, self.policy("passive"), self.runner)
        self.assertEqual(audit.call_args.args[3].skip, ["axfr", "nsec-walk", "takeover"])
        self.assertEqual(self.cap_gaps(), [("recon", "dns:axfr"), ("recon", "dns:nsec-walk"),
                                           ("recon", "dns:takeover")])

    def test_passive_cap_skips_screenshots(self):
        self.store.save_services([Service(host="127.0.0.1", port=9, proto="tcp",
                                          name="http")])
        with self.quiet():
            out = pipeline.screenshot(self.store, self.scope, self.policy("passive"),
                                      shooter_factory=_must_not_run)
        self.assertTrue(out["capped"])
        self.assertEqual(self.cap_gaps(), [("screenshot", "screenshot")])

    def test_report_names_the_cap(self):
        from extscan import report
        from extscan.triage import triage
        with mock.patch.object(pipeline.nmap, "run_tcp", side_effect=_must_not_run), \
                self.quiet():
            pipeline.discover(self.store, self.scope, self.policy("passive"), self.runner,
                              udp=False)
        md = report.render_markdown(self.scope, triage([], []), [], [],
                                    {"policy": self.policy("passive").to_dict()}, [],
                                    self.store.degradations())
        self.assertIn("Safety cap: checks up to `passive` were allowed", md)
        self.assertIn("1 check(s) above the cap were skipped", md)


if __name__ == "__main__":
    unittest.main()
