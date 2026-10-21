"""Lead handlers: the "look further" half of the workflow.

Discovery tells you a port is open. A probe tells you Swagger UI is published
at that port. Neither answers the question the client is paying for, which is
*what does that expose*. These handlers close that gap, and where they cannot
close it safely they hand the auditor a precise question instead of a vague one.

Each handler is deliberately bounded. Reading an OpenAPI document and listing
its unauthenticated write operations is a read. Calling those operations is
not, so that stays a decision for a person: the handler emits a lead and a
review item rather than firing the request.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .models import Finding, Lead
from .probes import ProbeContext, _redact
from .runner import have
from .scope import ScopeError
from .tools import net, snmp

MAX_LISTED = 40          # how many endpoints/items to enumerate in a finding


@dataclass
class ChaseResult:
    findings: list[Finding]
    leads: list[Lead]
    note: str = ""


Handler = Callable[[ProbeContext, Lead], ChaseResult]


# ---------------------------------------------------------------------------
# OpenAPI / Swagger
# ---------------------------------------------------------------------------

SPEC_CANDIDATES = [
    "/swagger.json", "/openapi.json", "/v3/api-docs", "/v2/swagger.json",
    "/swagger/v1/swagger.json", "/api-docs", "/api/swagger.json",
    "/openapi.yaml", "/swagger.yaml", "/api/openapi.json",
]

WRITE_METHODS = {"post", "put", "patch", "delete"}
# Deliberately narrow. An earlier, broader version matched ordinary business
# nouns (user, account, invoice, payment) and flagged nearly every operation in
# a billing API, which makes the signal worthless. These are terms that suggest
# administrative reach or credential handling rather than normal domain data.
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(admin|internal|debug|dump|token|password|passwd|credential|secret|"
    r"apikey|api[_-]key|private[_-]key|backup|impersonat|sudo|su-|privilege|"
    r"role|permission|acl|setting|config)"
)


def _find_spec_url(ctx: ProbeContext, lead: Lead) -> tuple[str, net.Response] | None:
    """Locate the spec document for a Swagger UI page or a bare base URL."""
    candidates: list[str] = []
    if lead.url:
        candidates.append(lead.url)
        # Swagger UI commonly names its spec in a url: "..." initialiser.
        resp = net.fetch(lead.url, ctx.scope, ctx.policy.http)
        if resp.ok and "html" in resp.content_type:
            for m in re.finditer(r"""url['"]?\s*:\s*['"]([^'"]{3,200})['"]""", resp.text):
                candidates.append(urljoin(lead.url, m.group(1)))
            for m in re.finditer(r"""['"]([^'"]*(?:swagger|openapi|api-docs)[^'"]*\.(?:json|yaml|yml))['"]""",
                                 resp.text, re.I):
                candidates.append(urljoin(lead.url, m.group(1)))

    parts = urlsplit(lead.url) if lead.url else None
    base = f"{parts.scheme}://{parts.netloc}" if parts and parts.scheme else ""
    if base:
        candidates += [base + p for p in SPEC_CANDIDATES]

    seen: set[str] = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            ctx.scope.assert_url(url, context="openapi spec fetch")
        except ScopeError:
            continue
        resp = net.fetch(url, ctx.scope, ctx.policy.http)
        if not resp.ok:
            continue
        text = resp.text.lstrip()
        if text.startswith(("{", "[")) and any(k in resp.text[:4000] for k in
                                               ('"swagger"', '"openapi"', '"paths"')):
            return url, resp
        if ("openapi:" in resp.text[:2000] or "swagger:" in resp.text[:2000]) and "paths:" in resp.text:
            return url, resp
    return None


def _join_api(server: str, path: str) -> str:
    """Join an OpenAPI server URL to an operation path.

    Not urljoin: a server of `https://host/api` with operation `/health` must
    become `https://host/api/health`. urljoin treats the trailing `api` as a
    document and yields `https://host/health`, which silently probes the wrong
    URL -- and a soft-404 there reads as a working endpoint.
    """
    if "://" not in server:
        server = "https://" + server.lstrip("/")
    parts = urlsplit(server)
    base_path = parts.path.rstrip("/")
    joined = f"{base_path}/{path.lstrip('/')}" if path.strip("/") else (base_path or "/")
    return f"{parts.scheme}://{parts.netloc}{joined}"


def _parse_yaml_paths(text: str) -> list[str]:
    """Crude path extraction for YAML specs (no YAML parser in stdlib).

    Best-effort on purpose: enough to tell the auditor how large the API is and
    what it covers, marked tentative so nobody treats it as a full parse.
    """
    paths: list[str] = []
    in_paths = False
    for line in text.splitlines():
        if re.match(r"^paths:\s*$", line):
            in_paths = True
            continue
        if in_paths:
            if line and not line[0].isspace():
                break
            m = re.match(r"^\s{1,4}(/\S*?):\s*$", line)
            if m:
                paths.append(m.group(1))
    return paths


def chase_openapi(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    found = _find_spec_url(ctx, lead)
    if not found:
        return ChaseResult([], [], note="no machine-readable spec found at or near this URL")

    spec_url, resp = found
    ctx.runner.store.write_raw(f"openapi-{urlsplit(spec_url).netloc}-"
                               f"{abs(hash(spec_url)) % 10**6}.txt", resp.body)

    host = urlsplit(spec_url).hostname or lead.host
    port = lead.port

    try:
        spec = json.loads(resp.text)
        if not isinstance(spec, dict):
            raise ValueError("spec is not an object")
    except (json.JSONDecodeError, ValueError):
        # YAML fallback: report size and coverage, flag for a human.
        yaml_paths = _parse_yaml_paths(resp.text)
        return ChaseResult([Finding(
            title=f"Exposed OpenAPI document (YAML) at {spec_url}",
            severity="medium", host=host, port=port, source="extscan:openapi",
            description=f"A YAML API description is public. extscan parses JSON specs "
                        f"fully; this one was read heuristically and appears to describe "
                        f"{len(yaml_paths)} path(s).",
            evidence=f"GET {spec_url} -> {resp.status}\npaths (partial):\n"
                     + "\n".join(f"  {p}" for p in yaml_paths[:MAX_LISTED]),
            review_required=True,
            review_reason="Convert the spec to JSON or open it in an API client to "
                          "enumerate operations and authentication requirements.",
            confidence="tentative", tags=["openapi", "api", "yaml"],
        )], [], note=f"YAML spec at {spec_url}, {len(yaml_paths)} paths (heuristic)")

    info = spec.get("info") or {}
    title = str(info.get("title") or "untitled API")
    api_version = str(info.get("version") or "?")
    spec_version = str(spec.get("openapi") or spec.get("swagger") or "?")
    servers = []
    for s in (spec.get("servers") or []):
        if isinstance(s, dict) and s.get("url"):
            servers.append(str(s["url"]))
    if spec.get("host"):                      # Swagger 2.0 style
        schemes = spec.get("schemes") or ["https"]
        servers.append(f"{schemes[0]}://{spec['host']}{spec.get('basePath', '')}")

    global_security = spec.get("security")
    schemes_defined = list(
        (spec.get("components", {}).get("securitySchemes")
         or spec.get("securityDefinitions") or {}).keys()
    )

    paths = spec.get("paths") or {}
    operations: list[tuple[str, str, dict]] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() in ("get", "post", "put", "patch", "delete", "head", "options") \
                    and isinstance(op, dict):
                operations.append((method.lower(), str(path), op))

    unauth: list[tuple[str, str]] = []
    unauth_writes: list[tuple[str, str]] = []
    sensitive: list[tuple[str, str]] = []

    for method, path, op in operations:
        sec = op.get("security", global_security)
        # security: [] on an operation explicitly removes auth; absent + no
        # global requirement means none was ever declared.
        is_open = sec == [] or sec is None
        if is_open:
            unauth.append((method, path))
            if method in WRITE_METHODS:
                unauth_writes.append((method, path))
        if SENSITIVE_PATH_RE.search(path) or SENSITIVE_PATH_RE.search(
                str(op.get("summary", "")) + str(op.get("operationId", ""))):
            sensitive.append((method, path))

    def fmt(items: list[tuple[str, str]]) -> str:
        lines = [f"  {m.upper():6} {p}" for m, p in items[:MAX_LISTED]]
        if len(items) > MAX_LISTED:
            lines.append(f"  ... and {len(items) - MAX_LISTED} more")
        return "\n".join(lines)

    summary = [
        f"spec: {spec_url}",
        f"API: {title} v{api_version} (spec format {spec_version})",
        f"paths: {len(paths)}, operations: {len(operations)}",
        f"declared security schemes: {', '.join(schemes_defined) or 'none'}",
        f"global security requirement: {'yes' if global_security else 'none'}",
    ]
    if servers:
        summary.append("servers: " + ", ".join(servers[:10]))

    findings: list[Finding] = []
    leads: list[Lead] = []

    findings.append(Finding(
        title=f"Exposed API specification: {title} ({len(operations)} operations)",
        severity="medium", host=host, port=port, source="extscan:openapi",
        description=(
            f"A complete machine-readable description of this API is published at "
            f"{spec_url}. It documents {len(operations)} operations across "
            f"{len(paths)} paths, which hands an attacker the full attack surface "
            "including parameter names and types."
        ),
        evidence="\n".join(summary)[:4000],
        recommendation="Serve the specification only to authenticated consumers, or "
                       "publish a redacted version covering only public endpoints.",
        review_required=True,
        review_reason="An auditor must decide whether publishing this spec is intended. "
                      "If the API is public by design this may be acceptable; the "
                      "operations listed below still need review.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
        tags=["openapi", "api", "information-disclosure"],
    ))

    if unauth:
        sev = "high" if unauth_writes else "medium"
        findings.append(Finding(
            title=f"{len(unauth)} API operation(s) declare no authentication"
                  + (f", including {len(unauth_writes)} that modify data" if unauth_writes else ""),
            severity=sev, host=host, port=port, source="extscan:openapi",
            description=(
                "These operations carry no security requirement in the specification, "
                "either explicitly (`security: []`) or because none was ever declared "
                "and there is no global requirement. The specification is a statement of "
                "intent, not proof: the gateway in front of the API may enforce auth "
                "regardless, and an operation may be protected in code but undocumented."
            ),
            evidence=(f"unauthenticated operations ({len(unauth)}):\n{fmt(unauth)}"
                      + (f"\n\nwrite operations with no declared auth ({len(unauth_writes)}):\n"
                         f"{fmt(unauth_writes)}" if unauth_writes else "")),
            recommendation="Declare and enforce authentication on every operation that is "
                           "not deliberately public; verify enforcement at the gateway.",
            review_required=True,
            review_reason=(
                "extscan did not call these endpoints -- invoking undocumented write "
                "operations on a live system risks changing client data. An auditor "
                "should confirm, on the read-only endpoints first, whether the lack of "
                "declared authentication is real."
            ),
            confidence="tentative",
            tags=["openapi", "api", "authentication", "owasp-api"],
        ))

        # One lead per unauthenticated read, so a human or the agent can pick
        # which to verify rather than the tool firing all of them.
        for method, path in unauth[:MAX_LISTED]:
            if method != "get":
                continue
            if "{" in path:
                continue       # needs a real identifier; not safely guessable
            leads.append(Lead(
                kind="api_endpoint", host=host, port=port,
                url=_join_api(servers[0] if servers else spec_url, path),
                params={"method": method, "declared_auth": "none", "spec": spec_url},
                reason=f"GET {path} declares no authentication. Verifying one read-only "
                       "endpoint confirms whether the spec reflects reality.",
                origin="extscan:openapi", depth=lead.depth + 1,
            ))

    if sensitive:
        findings.append(Finding(
            title=f"API exposes {len(sensitive)} operation(s) on sensitive-looking resources",
            severity="info", host=host, port=port, source="extscan:openapi",
            description="Operation paths or names suggest administrative or data-bearing "
                        "functionality. This is a naming heuristic, not a vulnerability.",
            evidence=fmt(sensitive),
            review_required=True,
            review_reason="Decide which of these warrant authenticated testing under a "
                          "separate, explicitly scoped engagement.",
            confidence="tentative", tags=["openapi", "api", "triage-hint"],
        ))

    off_scope = []
    for s in servers:
        try:
            ctx.scope.assert_url(s if "://" in s else f"https://{s}", context="openapi server")
        except ScopeError:
            off_scope.append(s)
    if off_scope:
        findings.append(Finding(
            title="API specification references hosts outside the engagement scope",
            severity="info", host=host, port=port, source="extscan:openapi",
            description="The spec names servers that are not in scope. These were not "
                        "touched. They may be additional assets the client has not "
                        "listed, which is worth raising.",
            evidence="\n".join(off_scope[:20]),
            review_required=True,
            review_reason="Confirm with the client whether these hosts belong to them and "
                          "should be added to scope for a future assessment.",
            tags=["openapi", "scope", "asset-discovery"],
        ))

    # Optional model commentary, as a separate clearly-labelled finding. The
    # deterministic findings above are complete without it.
    if ctx.llm is not None and ctx.policy.llm.analyse_openapi:
        from .llm.analyst import analyse_openapi

        commentary = analyse_openapi(
            ctx.llm, host=host, port=port, spec_url=spec_url,
            spec_text=resp.text,
            operation_summary=(f"{len(operations)} operations, {len(unauth)} with no "
                               f"declared auth, {len(unauth_writes)} of those writes"),
            deterministic_severity="high" if unauth_writes else "medium",
        )
        if commentary is not None:
            findings.append(commentary)

    note = (f"parsed {spec_url}: {len(operations)} operations, "
            f"{len(unauth)} without declared auth ({len(unauth_writes)} writes)")
    return ChaseResult(findings, leads, note=note)


# ---------------------------------------------------------------------------
# GraphQL
# ---------------------------------------------------------------------------

INTROSPECTION_QUERY = (
    '{"query":"{__schema{queryType{name} mutationType{name} '
    'types{name kind fields{name}}}}"}'
)


def chase_graphql(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    url = lead.url or f"http://{lead.host}:{lead.port}/graphql"
    try:
        ctx.scope.assert_url(url, context="graphql introspection")
    except ScopeError as exc:
        return ChaseResult([], [], note=f"skipped: {exc}")

    # Introspection is a read-only query. We never send mutations.
    resp = _post_json(url, INTROSPECTION_QUERY, ctx)

    if resp.status == 0:
        return ChaseResult([], [], note=f"no response: {resp.error}")

    text = resp.text
    if '"__schema"' not in text and '"data"' not in text:
        return ChaseResult([Finding(
            title=f"GraphQL endpoint at {url} did not return a schema",
            severity="info", host=lead.host, port=lead.port, source="extscan:graphql",
            description="The endpoint responded but introspection appears disabled, "
                        "which is the recommended configuration.",
            evidence=f"POST {url} -> {resp.status}\n{text[:800]}",
            tags=["graphql"],
        )], [], note="introspection appears disabled")

    try:
        data = json.loads(text)
        schema = (data.get("data") or {}).get("__schema") or {}
        types = schema.get("types") or []
        mutation = (schema.get("mutationType") or {}).get("name")
        type_names = [str(t.get("name")) for t in types if isinstance(t, dict)]
        field_count = sum(len(t.get("fields") or []) for t in types if isinstance(t, dict))
    except (json.JSONDecodeError, AttributeError):
        type_names, mutation, field_count = [], None, 0

    return ChaseResult([Finding(
        title=f"GraphQL introspection enabled at {url}",
        severity="medium", host=lead.host, port=lead.port, source="extscan:graphql",
        description=(
            f"Introspection returns the full schema: {len(type_names)} types and "
            f"{field_count} fields"
            + (f", with mutations exposed via `{mutation}`." if mutation else ".")
            + " This gives an attacker the complete API surface, including fields that "
            "no client UI references."
        ),
        evidence=f"POST {url} -> {resp.status}\ntypes: "
                 + ", ".join(n for n in type_names[:60] if not n.startswith("__")),
        recommendation="Disable introspection in production and apply query depth/"
                       "complexity limits.",
        review_required=True,
        review_reason=("Review the schema for fields that should not be reachable by "
                       "unauthenticated callers"
                       + (" and for mutations that change data." if mutation else ".")),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
        tags=["graphql", "information-disclosure"],
    )], [], note=f"introspection enabled, {len(type_names)} types")


def _post_json(url: str, body: str, ctx: ProbeContext) -> net.Response:
    """POST a JSON body. Kept separate because net.fetch is GET-shaped."""
    import ssl
    import urllib.error
    import urllib.request

    try:
        ctx.scope.assert_url(url, context="post json")
    except ScopeError as exc:
        return net.Response(url=url, status=0, error=f"scope refusal: {exc}")

    hp = ctx.policy.http
    # Scheme restricted to http/https by assert_url above.
    req = urllib.request.Request(url, data=body.encode(), method="POST")  # noqa: S310
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", hp.user_agent)
    handlers: list = [urllib.request.HTTPSHandler(context=net._ssl_context(hp))]
    if not hp.use_system_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=hp.timeout_sec) as resp:
            return net.Response(url=url, status=resp.status, reason=resp.reason or "",
                                headers={k.lower(): v for k, v in resp.headers.items()},
                                body=resp.read(hp.max_body_bytes))
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read(hp.max_body_bytes)
        except Exception:
            payload = b""
        return net.Response(url=url, status=exc.status, reason=exc.reason or "",
                            headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                            body=payload)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        return net.Response(url=url, status=0, error=f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Git exposure
# ---------------------------------------------------------------------------

def chase_git_exposure(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    base = lead.url.split("/.git")[0] if "/.git" in lead.url else lead.url.rstrip("/")
    results = {}
    for part in ("/.git/config", "/.git/HEAD"):
        resp = net.fetch(base + part, ctx.scope, ctx.policy.http)
        if resp.ok and resp.body:
            results[part] = resp.text[:1500]

    if not results:
        return ChaseResult([], [], note="no readable .git metadata")

    remotes = re.findall(r"url\s*=\s*(\S+)", results.get("/.git/config", ""))
    return ChaseResult([Finding(
        title=f"Git repository metadata readable at {base}/.git/",
        severity="high", host=lead.host, port=lead.port, source="extscan:git",
        description=(
            "The .git directory is served by the web server. Where directory listing or "
            "object fetching is permitted, the entire source history can be reconstructed, "
            "including credentials committed and later removed."
        ),
        evidence="\n\n".join(f"GET {base}{k}\n{_redact(v)}" for k, v in results.items()),
        recommendation="Block .git at the web server or deploy from a build artefact "
                       "rather than a working copy. Rotate any secret ever committed.",
        review_required=True,
        review_reason="Confirm how much is retrievable (config only, or full objects) and "
                      "check the history for credentials. Do not clone client source "
                      "without written agreement on handling.",
        tags=["git", "source-disclosure"],
    )], [], note=f"readable: {', '.join(results)}"
        + (f"; remotes: {', '.join(remotes[:3])}" if remotes else ""))


# ---------------------------------------------------------------------------
# Generic web path / secret file
# ---------------------------------------------------------------------------

def chase_web_paths(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    url = lead.url
    if not url:
        return ChaseResult([], [], note="lead carried no URL")
    resp = net.fetch(url, ctx.scope, ctx.policy.http)
    if resp.status == 0:
        return ChaseResult([], [], note=f"no response: {resp.error}")

    links = []
    if "html" in resp.content_type:
        links = re.findall(r'href=["\']([^"\']{1,200})["\']', resp.text)[:MAX_LISTED]

    return ChaseResult([Finding(
        title=f"Content review: {url}",
        severity="info", host=lead.host, port=lead.port, source="extscan:web_paths",
        description=f"Retrieved for context. {lead.reason}",
        evidence=(f"GET {url} -> {resp.status} {resp.reason}\n"
                  f"content-type: {resp.content_type}  length: {len(resp.body)}\n\n"
                  + _redact(resp.text[:1500])
                  + (("\n\nlinks:\n" + "\n".join(f"  {link}" for link in links)) if links else "")),
        review_required=True,
        review_reason="An auditor should judge whether the content disclosed here matters "
                      "for this client.",
        tags=["http", "content-review"],
    )], [], note=f"{resp.status}, {len(resp.body)} bytes, {len(links)} links")


def chase_secret_file(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    resp = net.fetch(lead.url, ctx.scope, ctx.policy.http)
    if not resp.ok or not resp.body:
        return ChaseResult([], [], note=f"not readable ({resp.status})")

    keys = [m.group(1) for m in re.finditer(
        r"(?im)^([A-Za-z0-9_.\-]*(?:KEY|TOKEN|SECRET|PASS|PASSWORD|CREDENTIAL|DSN|CONN)"
        r"[A-Za-z0-9_.\-]*)\s*[=:]", resp.text)]
    uniq = sorted(set(keys))

    sev = "critical" if uniq else "high"
    return ChaseResult([Finding(
        title=f"Credential-bearing file readable at {lead.url}",
        severity=sev, host=lead.host, port=lead.port, source="extscan:secret_file",
        description=(
            f"The file is served to unauthenticated clients and contains "
            f"{len(uniq)} key(s) whose names indicate secrets. Values are redacted here "
            "deliberately: the finding is that they are reachable, and the report should "
            "not become another copy of the client's credentials."
            if uniq else
            "The file is served to unauthenticated clients. No obvious secret key names "
            "were matched, but the content should be reviewed."
        ),
        evidence=(f"GET {lead.url} -> {resp.status}  length: {len(resp.body)}\n"
                  f"secret-like keys present: {', '.join(uniq[:40]) or 'none matched'}\n\n"
                  + _redact(resp.text[:1200])),
        recommendation="Remove the file from the web root, block the path, and rotate "
                       "every credential it contained -- treat them as compromised.",
        review_required=True,
        review_reason="Confirm these are live production credentials and drive the "
                      "rotation. This is usually the highest-priority item in a report.",
        tags=["secrets", "information-disclosure"],
    )], [], note=f"{len(uniq)} secret-like keys")


# ---------------------------------------------------------------------------
# API endpoint verification (read-only, one endpoint per lead)
# ---------------------------------------------------------------------------

_APP_ERROR_MARKERS = ("not found", "404", "page does not exist", "error occurred",
                      "<title>error", "forbidden", "sign in", "log in")


def _looks_like_app_error(resp: net.Response) -> bool:
    """True when a 200 is really an error page rather than API output."""
    ctype = resp.content_type
    if "json" in ctype or "xml" in ctype:
        return False
    if "html" not in ctype and ctype:
        return False
    text = resp.text[:3000].lower()
    return any(marker in text for marker in _APP_ERROR_MARKERS)


def chase_api_endpoint(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    """Confirm whether one documented-as-unauthenticated GET really is open."""
    if lead.params.get("method", "get").lower() != "get":
        return ChaseResult([], [], note="refusing to invoke a non-GET operation")
    resp = net.fetch(lead.url, ctx.scope, ctx.policy.http)
    if resp.status == 0:
        return ChaseResult([], [], note=f"no response: {resp.error}")

    if resp.status in (401, 403):
        return ChaseResult([Finding(
            title=f"API endpoint enforces authentication despite spec: {lead.url}",
            severity="info", host=lead.host, port=lead.port, source="extscan:api",
            description=f"The specification declared no security requirement, but the "
                        f"endpoint returned {resp.status}. Enforcement is happening "
                        "somewhere other than the spec -- worth reporting as a "
                        "documentation defect rather than an access-control one.",
            evidence=f"GET {lead.url} -> {resp.status} {resp.reason}",
            tags=["api", "documentation"],
        )], [], note=f"{resp.status}: auth enforced")

    if resp.ok and _looks_like_app_error(resp):
        # A 200 that is really the SPA shell or an error page. Claiming this as
        # an open API endpoint would put a false positive in a client report.
        return ChaseResult([], [], note=(
            f"{resp.status} but the body looks like an error/placeholder page "
            f"({resp.content_type}, {len(resp.body)} bytes); treating as inconclusive"
        ))

    if resp.ok:
        # An open liveness probe and an open admin collection are not the same
        # finding. Grade on what the path suggests it reaches.
        path = urlsplit(lead.url).path
        sensitive = bool(SENSITIVE_PATH_RE.search(path))
        severity = "high" if sensitive else "medium"
        return ChaseResult([Finding(
            title=f"Unauthenticated API endpoint confirmed reachable: {lead.url}",
            severity=severity, host=lead.host, port=lead.port, source="extscan:api",
            description="The endpoint returned data without credentials, confirming the "
                        "specification's lack of a security requirement reflects reality."
                        + (" The path suggests administrative or credential-bearing "
                           "functionality, which raises the impact." if sensitive else
                           " Impact depends on what the response contains."),
            evidence=(f"GET {lead.url} -> {resp.status} {resp.reason}\n"
                      f"content-type: {resp.content_type}  length: {len(resp.body)}\n\n"
                      + _redact(resp.text[:1000])),
            recommendation="Require authentication on this endpoint.",
            review_required=True,
            review_reason="Check whether the returned data is sensitive, and whether other "
                          "endpoints from the same spec behave the same way. Do not "
                          "enumerate records beyond what proves the finding.",
            tags=["api", "authentication", "owasp-api"],
        )], [], note=f"{resp.status}: open, {len(resp.body)} bytes")

    return ChaseResult([], [], note=f"{resp.status} {resp.reason}")


# ---------------------------------------------------------------------------
# SNMP walk
# ---------------------------------------------------------------------------

WALK_ROOTS = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ipAdEntAddr": "1.3.6.1.2.1.4.20.1.1",
    "sysORDescr": "1.3.6.1.2.1.1.9.1.3",
}


def chase_snmp_walk(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    community = str(lead.params.get("community") or "public")
    ctx.scope.assert_host(lead.host, context="snmp walk")
    port = lead.port or 161

    collected: dict[str, list[tuple[str, str]]] = {}
    for label, root in WALK_ROOTS.items():
        rows = snmp.snmp_walk(lead.host, community, root, port=port,
                              timeout=ctx.policy.snmp.timeout_sec, max_items=25)
        if rows:
            collected[label] = rows

    if not collected:
        return ChaseResult([], [], note="walk returned nothing")

    evidence_lines = []
    for label, rows in collected.items():
        evidence_lines.append(f"{label}:")
        evidence_lines += [f"  {oid} = {value}" for oid, value in rows[:25]]

    addresses = [value for _oid, value in collected.get("ipAdEntAddr", [])]
    interfaces = [value for _oid, value in collected.get("ifDescr", [])]

    return ChaseResult([Finding(
        title=f"SNMP discloses internal network topology on {lead.host}",
        severity="medium", host=lead.host, port=port, proto="udp",
        source="extscan:snmp_walk",
        description=(
            f"Using community `{community}`, the agent returned "
            f"{len(interfaces)} interface description(s) and "
            f"{len(addresses)} configured IP address(es). This is what the exposure "
            "actually costs the client: a map of internal addressing and hardware, "
            "readable by anyone on the internet."
        ),
        evidence="\n".join(evidence_lines)[:4000],
        recommendation="Filter UDP/161 at the perimeter and move to SNMPv3 authPriv.",
        review_required=True,
        review_reason="Use the disclosed internal addressing to tell the client what an "
                      "attacker learns, and check whether any disclosed address is itself "
                      "reachable from outside (that would be a second, larger finding).",
        tags=["snmp", "information-disclosure", "topology"],
    )], [], note=f"{len(interfaces)} interfaces, {len(addresses)} addresses via `{community}`")


# ---------------------------------------------------------------------------
# TLS detail via an external auditor
# ---------------------------------------------------------------------------

def chase_tls_detail(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    if not have("testssl.sh"):
        return ChaseResult([], [], note=(
            "testssl.sh not installed; protocol support could not be settled. "
            "Install it or test manually before stating which TLS versions are absent."
        ))
    target = f"{lead.host}:{lead.port}"
    out = ctx.runner.store.raw_path(f"testssl-{lead.host}-{lead.port}.json")
    res = ctx.runner.run(
        ["testssl.sh", "--jsonfile", str(out), "--protocols", "--quiet", target],
        stage="chase:tls_detail", timeout=900, stdout_name=f"testssl-{lead.host}-{lead.port}",
    )
    return ChaseResult([Finding(
        title=f"Detailed TLS protocol audit for {target}",
        severity="info", host=lead.host, port=lead.port, source="testssl.sh",
        description="External TLS auditor output; attached for review.",
        evidence=(res.stdout or "")[-3000:] or f"see {out}",
        review_required=True,
        review_reason="Read the protocol/cipher table and report anything below TLS 1.2.",
        tags=["tls"],
    )], [], note=f"testssl.sh exit {res.returncode}")


HANDLERS: dict[str, Handler] = {
    "openapi": chase_openapi,
    "graphql": chase_graphql,
    "git_exposure": chase_git_exposure,
    "web_paths": chase_web_paths,
    "secret_file": chase_secret_file,
    "api_endpoint": chase_api_endpoint,
    "snmp_walk": chase_snmp_walk,
    "tls_detail": chase_tls_detail,
}


def chase(ctx: ProbeContext, lead: Lead) -> ChaseResult:
    handler = HANDLERS.get(lead.kind)
    if handler is None:
        return ChaseResult([], [], note=f"no handler for lead kind {lead.kind!r}")
    if lead.depth > ctx.policy.max_lead_depth:
        return ChaseResult([], [], note=f"depth {lead.depth} exceeds max_lead_depth")
    try:
        return handler(ctx, lead)
    except ScopeError as exc:
        return ChaseResult([], [], note=f"scope refusal: {exc}")
    except Exception as exc:
        # One bad lead must not abort the run; record and move on.
        return ChaseResult([], [], note=f"handler error: {type(exc).__name__}: {exc}")
