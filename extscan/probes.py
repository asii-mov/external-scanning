"""Per-service probes.

A probe declares what it matches and what it does with a match. The registry
is a list, so adding a service family means adding one function here rather
than touching the pipeline -- which is how this grows past the four or five
checks the team starts with.

Every probe is read-only: GET, connect, query. Nothing authenticates, writes,
uploads or exploits. Where impact cannot be established without going further,
the probe raises a finding flagged for human review instead.
"""

from __future__ import annotations

import html
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from .llm.base import SECRET_LINE_RE
from .models import Finding, Lead, Service
from .policy import Policy
from .runner import Runner
from .scope import Scope
from .tools import iis, net, snmp, sslscan


@dataclass
class ProbeContext:
    scope: Scope
    policy: Policy
    runner: Runner
    llm: object | None = None


ProbeFn = Callable[[ProbeContext, Service], tuple[list[Finding], list[Lead]]]


@dataclass
class Probe:
    name: str
    matches: Callable[[Service], bool]
    run: ProbeFn
    description: str = ""


REGISTRY: list[Probe] = []


def register(name: str, matches: Callable[[Service], bool], description: str = ""):
    def deco(fn: ProbeFn) -> ProbeFn:
        REGISTRY.append(Probe(name=name, matches=matches, run=fn, description=description))
        return fn
    return deco


def probes_for(service: Service) -> list[Probe]:
    return [p for p in REGISTRY if p.matches(service)]


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

_BODY_HINTS: list[tuple[str, str, str]] = [
    ("swagger-ui", "openapi", "The page loads Swagger UI; locate and read the spec it renders."),
    ("swagger", "openapi", "Swagger references in the page body."),
    ("openapi", "openapi", "OpenAPI references in the page body."),
    ("graphiql", "graphql", "GraphiQL console present; check introspection."),
    ("__schema", "graphql", "GraphQL schema reference in the body."),
    ("index of /", "web_paths", "Directory listing is enabled."),
    ("phpinfo()", "web_paths", "phpinfo output exposes build and path detail."),
]

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set; downgrade to cleartext is not prevented.",
    "content-security-policy": "No CSP; no in-browser mitigation for injected content.",
    "x-content-type-options": "Missing nosniff.",
    "x-frame-options": "No framing restriction (unless CSP frame-ancestors is set).",
}

VERBOSE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                   "x-generator", "x-drupal-cache", "x-runtime", "via"]


def _title(body_text: str) -> str:
    m = _TITLE_RE.search(body_text)
    return html.unescape(m.group(1)).strip()[:200] if m else ""


@register("http_fingerprint", lambda s: s.is_http,
          "Fetch the root page, record fingerprint headers and security headers.")
def http_fingerprint(ctx: ProbeContext, svc: Service) -> tuple[list[Finding], list[Lead]]:
    findings: list[Finding] = []
    leads: list[Lead] = []
    base = svc.base_url()
    resp = net.fetch(base, ctx.scope, ctx.policy.http)

    if resp.error and resp.status == 0:
        findings.append(Finding(
            title=f"HTTP service on {svc.host}:{svc.port} did not answer cleanly",
            severity="info", host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:http", description=f"Request to {base} failed.",
            evidence=resp.error[:500], confidence="tentative", tags=["http", "no-response"],
        ))
        return findings, leads

    body_text = resp.text
    title = _title(body_text)
    server = resp.headers.get("server", "")

    disclosed = {h: resp.headers[h] for h in VERBOSE_HEADERS if h in resp.headers}
    evidence = [f"GET {base} -> {resp.status} {resp.reason}"]
    if resp.redirect_chain:
        evidence += ["redirects:"] + [f"  {hop}" for hop in resp.redirect_chain]
    if title:
        evidence.append(f"title: {title}")
    for k, v in disclosed.items():
        evidence.append(f"{k}: {v}")

    findings.append(Finding(
        title=f"HTTP service: {title or server or 'untitled'} on {svc.host}:{svc.port}",
        severity="info", host=svc.host, port=svc.port, proto=svc.proto,
        source="extscan:http",
        description=f"An HTTP service is reachable at {base}."
                    + (f" It identifies itself as `{server}`." if server else ""),
        evidence="\n".join(evidence)[:3000],
        review_required=True,
        review_reason="An auditor should confirm whether this application is "
                      "intended to be internet-facing, and who owns it.",
        tags=["http", "fingerprint"],
    ))

    if disclosed:
        findings.append(Finding(
            title=f"Version-disclosing HTTP headers on {svc.host}:{svc.port}",
            severity="low", host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:http",
            description="The server returns headers naming the product and version, "
                        "which lets an attacker select exploits without probing.",
            evidence="\n".join(f"{k}: {v}" for k, v in disclosed.items()),
            recommendation="Suppress or genericise Server/X-Powered-By and similar headers.",
            tags=["http", "information-disclosure"],
        ))

    if svc.is_tls:
        missing = [f"{h}: {why}" for h, why in SECURITY_HEADERS.items() if h not in resp.headers]
        if missing:
            findings.append(Finding(
                title=f"Missing HTTP security headers on {svc.host}:{svc.port}",
                severity="low", host=svc.host, port=svc.port, proto=svc.proto,
                source="extscan:http",
                description="Response headers that harden browser behaviour are absent.",
                evidence="\n".join(missing),
                recommendation="Add HSTS, CSP, X-Content-Type-Options and a framing policy.",
                tags=["http", "headers"],
            ))

    lowered = body_text[:200_000].lower()
    for needle, kind, reason in _BODY_HINTS:
        if needle in lowered:
            leads.append(Lead(kind=kind, host=svc.host, port=svc.port, url=base,
                              reason=reason, origin="extscan:http_fingerprint"))
            break

    if ctx.policy.http.path_checks:
        findings_p, leads_p = _check_paths(ctx, svc, base)
        findings += findings_p
        leads += leads_p

    return findings, leads


_PATH_MEANING: dict[str, tuple[str, str, str]] = {
    "/.git/config":       ("high", "A .git directory is served, which usually means the "
                                   "full source history is retrievable.", "git_exposure"),
    "/.env":              ("high", "An environment file is readable; these normally hold "
                                   "database credentials and API keys.", "secret_file"),
    "/actuator/heapdump": ("critical", "A Spring Boot heap dump is downloadable; heap dumps "
                                       "contain live credentials and session tokens.", "secret_file"),
    "/actuator/env":      ("high", "Spring Boot actuator env endpoint exposes configuration, "
                                   "often including secrets.", "secret_file"),
    "/actuator":          ("medium", "Spring Boot actuator endpoints are exposed.", "web_paths"),
    "/swagger.json":      ("medium", "An OpenAPI/Swagger document is public.", "openapi"),
    "/openapi.json":      ("medium", "An OpenAPI document is public.", "openapi"),
    "/swagger/v1/swagger.json": ("medium", "An OpenAPI document is public.", "openapi"),
    "/v2/swagger.json":   ("medium", "An OpenAPI document is public.", "openapi"),
    "/v3/api-docs":       ("medium", "A springdoc OpenAPI document is public.", "openapi"),
    "/api-docs":          ("medium", "An API documentation endpoint is public.", "openapi"),
    "/swagger-ui.html":   ("medium", "Swagger UI is public.", "openapi"),
    "/graphql":           ("medium", "A GraphQL endpoint is reachable.", "graphql"),
    "/metrics":           ("medium", "A metrics endpoint exposes internal topology.", "web_paths"),
    "/server-status":     ("medium", "Apache mod_status exposes live requests and client IPs.", "web_paths"),
    "/phpinfo.php":       ("medium", "phpinfo() exposes build, paths and extensions.", "web_paths"),
    "/debug/pprof/":      ("medium", "Go pprof debug endpoints are exposed.", "web_paths"),
    "/web.config":        ("high", "An IIS configuration file is readable.", "secret_file"),
    "/config.json":       ("medium", "A configuration file is readable.", "secret_file"),
    "/.DS_Store":         ("low", "A .DS_Store file leaks directory names.", "web_paths"),
    "/robots.txt":        ("info", "robots.txt lists paths the owner would rather not have "
                                   "indexed, which is a useful map.", "web_paths"),
    "/.well-known/security.txt": ("info", "security.txt is published.", ""),
}


def _looks_like_real_hit(path: str, resp: net.Response) -> bool:
    """Guard against soft-404s: a 200 that is really the app's error page.

    Without this check almost every path 'exists' on an SPA that serves
    index.html for everything, and the report fills with noise.
    """
    # A few endpoints prove their own existence by rejecting the request in a
    # characteristic way. GraphQL is the common one: a bare GET gets a 400
    # "must provide query string", which is stronger evidence of a live
    # endpoint than a 200 would be.
    if path == "/graphql" and resp.status in (400, 405, 422):
        text = resp.text[:2000].lower()
        return any(s in text for s in ("query", "graphql", "must provide", "operation"))

    if not resp.ok:
        return False
    body = resp.body
    if not body:
        return path in ("/robots.txt",)
    text = resp.text[:4000].lower()
    ctype = resp.content_type

    if path.endswith((".json", "api-docs")) or path in ("/swagger.json", "/openapi.json", "/v3/api-docs"):
        if "json" not in ctype and not text.lstrip().startswith(("{", "[")):
            return False
        return any(k in text for k in ('"swagger"', '"openapi"', '"paths"', '"info"', "{"))
    if path == "/.git/config":
        return "[core]" in text or "repositoryformatversion" in text
    if path == "/.env":
        return bool(re.search(r"^[A-Z0-9_]{3,}\s*=", resp.text[:4000], re.M))
    if path == "/robots.txt":
        return "html" not in ctype and ("user-agent" in text or "disallow" in text or not text.strip())
    if path == "/.DS_Store":
        return body[:4] == b"\x00\x00\x00\x01" or "bud1" in text
    if path == "/web.config":
        return "<configuration" in text
    if path == "/phpinfo.php":
        return "phpinfo" in text or "php version" in text
    if path == "/server-status":
        return "apache server status" in text
    if path == "/metrics":
        return "html" not in ctype or "# help" in text or "# type" in text
    if path.startswith("/actuator"):
        return "json" in ctype or text.lstrip().startswith("{")
    if path == "/graphql":
        return "graphql" in text or "query" in text or "json" in ctype
    return not any(s in text for s in ("not found", "404", "page does not exist"))


def _check_paths(ctx: ProbeContext, svc: Service,
                 base: str) -> tuple[list[Finding], list[Lead]]:
    findings: list[Finding] = []
    leads: list[Lead] = []
    delay = ctx.policy.http.inter_request_delay

    for path in ctx.policy.http.paths:
        if delay:
            time.sleep(delay)
        url = base.rstrip("/") + path
        resp = net.fetch(url, ctx.scope, ctx.policy.http)
        if resp.status == 0:
            continue

        sev, desc, lead_kind = _PATH_MEANING.get(path, ("info", f"{path} is reachable.", ""))
        hit = _looks_like_real_hit(path, resp)

        if not hit and resp.status in (401, 403) and path not in ("/robots.txt",):
            findings.append(Finding(
                title=f"{path} present but access-controlled on {svc.host}:{svc.port}",
                severity="info", host=svc.host, port=svc.port, proto=svc.proto,
                source="extscan:paths",
                description=f"{url} returned {resp.status}, so the path exists but is "
                            "protected. Worth noting: the protection is the only thing "
                            "standing between the internet and this resource.",
                evidence=f"GET {url} -> {resp.status} {resp.reason}",
                confidence="tentative", tags=["http", "path-check", "protected"],
            ))
            continue
        if not hit:
            continue

        body_preview = resp.text[:1200]
        if path in ("/.env", "/config.json", "/web.config", "/actuator/env"):
            body_preview = _redact(body_preview)

        findings.append(Finding(
            title=f"Exposed {path} on {svc.host}:{svc.port}",
            severity=sev, host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:paths", description=desc,
            evidence=f"GET {url} -> {resp.status} {resp.reason}\n"
                     f"content-type: {resp.content_type}\n"
                     f"length: {len(resp.body)}\n\n{body_preview}",
            recommendation="Remove the file from the document root or block the path at "
                           "the edge; rotate anything it disclosed.",
            review_required=sev in ("medium", "high", "critical"),
            review_reason=("Confirm what this actually discloses for this client and "
                           "whether the exposure is already known/accepted.")
                          if sev in ("medium", "high", "critical") else "",
            tags=["http", "path-check", path],
        ))

        if lead_kind:
            leads.append(Lead(kind=lead_kind, host=svc.host, port=svc.port, url=url,
                              reason=f"{path} responded {resp.status}; establish what it exposes.",
                              origin="extscan:paths"))

    return findings, leads


def _redact(text: str) -> str:
    """Keep key names, drop values.

    A pentest report should prove that credentials are exposed without copying
    them into the deliverable, the ticket system and three mailboxes.
    """
    def sub(m: re.Match) -> str:
        value = m.group(2).strip()
        return f"{m.group(1)}=<redacted, {len(value)} chars>"
    return SECRET_LINE_RE.sub(sub, text)


@register("tls", lambda s: s.proto == "tcp" and s.is_tls,
          "Inspect certificate and offered protocol versions.")
def tls_probe(ctx: ProbeContext, svc: Service) -> tuple[list[Finding], list[Lead]]:
    findings: list[Finding] = []
    leads: list[Lead] = []
    info = net.inspect_tls(svc.host, svc.port, ctx.scope,
                           timeout=float(ctx.policy.http.timeout_sec))

    if info.error and not info.cert_pem:
        findings.append(Finding(
            title=f"TLS handshake failed on {svc.host}:{svc.port}",
            severity="info", host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:tls", description="Could not complete a TLS handshake.",
            evidence=info.error[:400], confidence="tentative", tags=["tls"],
        ))
        return findings, leads

    detail = [
        f"negotiated: {info.negotiated_version}  cipher: {info.cipher}",
        f"subject: {info.subject}", f"issuer: {info.issuer}",
        f"validity: {info.not_before} .. {info.not_after}",
    ]
    if info.sans:
        detail.append("SANs: " + ", ".join(info.sans[:25]))
    if info.protocols:
        detail.append("protocols: " + ", ".join(
            f"{k}={'yes' if v else ('no' if v is False else 'untested')}"
            for k, v in info.protocols.items()))

    findings.append(Finding(
        title=f"TLS endpoint {svc.host}:{svc.port} ({info.negotiated_version})",
        severity="info", host=svc.host, port=svc.port, proto=svc.proto,
        source="extscan:tls", description="TLS configuration as observed.",
        evidence="\n".join(detail)[:3000], tags=["tls", "fingerprint"],
    ))

    if info.expired:
        findings.append(Finding(
            title=f"Expired TLS certificate on {svc.host}:{svc.port}",
            severity="medium", host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:tls",
            description=f"The certificate expired on {info.not_after}. Users are trained "
                        "to click through the warning, which erases the protection.",
            evidence="\n".join(detail[:4]),
            recommendation="Renew and automate renewal.", tags=["tls", "certificate"],
        ))

    if info.self_signed:
        findings.append(Finding(
            title=f"Self-signed TLS certificate on {svc.host}:{svc.port}",
            severity="low", host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:tls",
            description="Subject and issuer match, so the certificate is self-signed and "
                        "provides no identity assurance against interception.",
            evidence=f"subject: {info.subject}\nissuer: {info.issuer}",
            recommendation="Use a certificate from a CA the clients trust.",
            review_required=True,
            review_reason="Decide whether this endpoint is user-facing (a real problem) "
                          "or an internal appliance interface (often accepted).",
            tags=["tls", "certificate"],
        ))

    legacy = [name for name, enabled in info.protocols.items()
              if enabled and name in ("TLSv1.0", "TLSv1.1")]
    if legacy:
        findings.append(Finding(
            title=f"Deprecated TLS versions enabled on {svc.host}:{svc.port}: "
                  + ", ".join(legacy),
            severity="medium", host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:tls",
            description="TLS 1.0/1.1 are deprecated (RFC 8996) and fail PCI DSS.",
            evidence="protocols: " + ", ".join(
                f"{k}={'yes' if v else ('no' if v is False else 'untested')}"
                for k, v in info.protocols.items()),
            recommendation="Require TLS 1.2 or better.",
            references=["https://www.rfc-editor.org/rfc/rfc8996"],
            tags=["tls", "deprecated-protocol"],
        ))

    untested = [k for k, v in info.protocols.items() if v is None]
    if untested:
        leads.append(Lead(
            kind="tls_detail", host=svc.host, port=svc.port,
            params={"untested": untested},
            reason=f"Local OpenSSL could not test {', '.join(untested)}. Run a dedicated "
                   "TLS auditor to settle it rather than reporting an untested version "
                   "as absent.",
            origin="extscan:tls",
        ))

    if info.cert_pem:
        ctx.runner.store.write_raw(f"cert-{svc.host}-{svc.port}.pem", info.cert_pem)

    return findings, leads


def _is_snmp(s: Service) -> bool:
    return s.proto == "udp" and (s.port in (161, 10161) or "snmp" in s.name.lower())


@register("snmp", _is_snmp, "Try default/guessable SNMP community strings, read-only.")
def snmp_probe(ctx: ProbeContext, svc: Service) -> tuple[list[Finding], list[Lead]]:
    ctx.scope.assert_host(svc.host, context="snmp probe")
    findings, leads, hits = snmp.check_community_strings(svc.host, ctx.policy, port=svc.port)
    if not hits:
        findings.append(Finding(
            title=f"SNMP service on {svc.host}:{svc.port}/udp did not accept tested communities",
            severity="info", host=svc.host, port=svc.port, proto="udp",
            source="extscan:snmp",
            description=f"{len(ctx.policy.snmp.communities)} community strings were tried "
                        "read-only; none returned data. The agent may still be reachable "
                        "with a site-specific string, or may require SNMPv3.",
            evidence="tried: " + ", ".join(ctx.policy.snmp.communities),
            tags=["snmp"],
        ))
    return findings, leads


SENSITIVE_TCP: dict[int, tuple[str, str, str]] = {
    23:    ("Telnet", "high", "Telnet carries credentials in cleartext."),
    69:    ("TFTP", "medium", "TFTP is unauthenticated by design."),
    111:   ("rpcbind", "medium", "rpcbind enumerates RPC services and aids amplification."),
    135:   ("MSRPC", "high", "Windows RPC endpoint mapper should never be internet-facing."),
    139:   ("NetBIOS", "high", "NetBIOS session service should never be internet-facing."),
    445:   ("SMB", "high", "SMB on the internet is a standing ransomware entry point."),
    512:   ("rexec", "high", "Legacy remote exec service with cleartext credentials."),
    513:   ("rlogin", "high", "Legacy remote login with cleartext credentials."),
    514:   ("rsh", "high", "Legacy remote shell with trust-based authentication."),
    873:   ("rsync", "medium", "rsync daemons are frequently exported without authentication."),
    1433:  ("MSSQL", "high", "Database engine exposed directly to the internet."),
    1521:  ("Oracle TNS", "high", "Database listener exposed directly to the internet."),
    2049:  ("NFS", "high", "NFS exports reachable from the internet."),
    2375:  ("Docker API (plaintext)", "critical",
            "An unauthenticated Docker socket is container-host takeover."),
    2376:  ("Docker API (TLS)", "high", "Docker API exposed; verify client-cert enforcement."),
    3306:  ("MySQL", "high", "Database engine exposed directly to the internet."),
    3389:  ("RDP", "high", "RDP exposed to the internet; a top ransomware vector."),
    5432:  ("PostgreSQL", "high", "Database engine exposed directly to the internet."),
    5900:  ("VNC", "high", "VNC exposed; often unauthenticated or weakly authenticated."),
    5984:  ("CouchDB", "high", "Document database exposed to the internet."),
    6379:  ("Redis", "critical", "Redis is unauthenticated by default and allows file writes."),
    6443:  ("Kubernetes API", "high", "Cluster API server exposed; verify anonymous access is off."),
    9200:  ("Elasticsearch", "critical", "Elasticsearch has no authentication by default."),
    9300:  ("Elasticsearch transport", "high", "Cluster transport port exposed."),
    10250: ("kubelet API", "critical", "The kubelet API can expose command execution in pods."),
    11211: ("memcached", "high", "memcached is unauthenticated and usable for amplification."),
    27017: ("MongoDB", "critical", "MongoDB has historically shipped without authentication."),
    27018: ("MongoDB shard", "high", "MongoDB shard port exposed."),
    50070: ("Hadoop NameNode", "high", "Hadoop web UI exposed."),
}

SENSITIVE_UDP: dict[int, tuple[str, str, str]] = {
    123:   ("NTP", "low", "Check monlist/mode-6 queries are disabled (amplification)."),
    137:   ("NetBIOS-NS", "medium", "Leaks Windows naming information."),
    623:   ("IPMI/BMC", "critical",
            "Baseboard management controllers expose hardware-level control and have "
            "well-known authentication bypasses."),
    1434:  ("MSSQL browser", "medium", "Discloses database instance names and ports."),
    1900:  ("SSDP/UPnP", "medium", "Usable for reflection/amplification attacks."),
    5353:  ("mDNS", "medium", "Leaks internal hostnames and services."),
    11211: ("memcached", "high", "memcached over UDP is a major amplification vector."),
}


def _is_sensitive(s: Service) -> bool:
    table = SENSITIVE_TCP if s.proto == "tcp" else SENSITIVE_UDP
    return s.port in table


@register("exposure", _is_sensitive,
          "Flag management, database and legacy services reachable from the internet.")
def exposure_probe(ctx: ProbeContext, svc: Service) -> tuple[list[Finding], list[Lead]]:
    table = SENSITIVE_TCP if svc.proto == "tcp" else SENSITIVE_UDP
    label, sev, why = table[svc.port]
    banner = " ".join(x for x in (svc.product, svc.version, svc.extrainfo) if x).strip()

    return [Finding(
        title=f"{label} reachable from the internet on {svc.host}:{svc.port}/{svc.proto}",
        severity=sev, host=svc.host, port=svc.port, proto=svc.proto,
        source="extscan:exposure",
        description=f"{why} Detected as `{svc.name or label}`"
                    + (f" ({banner})" if banner else "") + ".",
        evidence=f"{svc.host}:{svc.port}/{svc.proto} open; service={svc.name}; "
                 f"product={svc.product}; version={svc.version}",
        recommendation="Restrict this port to known management sources at the perimeter, "
                       "or move access behind a VPN/bastion. If the service must be public, "
                       "confirm authentication is enforced and the build is current.",
        review_required=True,
        review_reason=f"Confirm whether {label} on this host is intentional and, if so, "
                      "whether authentication and patch level are adequate. Do not test "
                      "credentials without explicit written approval.",
        tags=["exposure", label.lower().split()[0]],
    )], []


@register("ssh", lambda s: s.proto == "tcp" and (s.port == 22 or "ssh" in s.name.lower()),
          "Record the SSH banner and flag outdated server versions.")
def ssh_probe(ctx: ProbeContext, svc: Service) -> tuple[list[Finding], list[Lead]]:
    banner = " ".join(x for x in (svc.product, svc.version) if x).strip() or svc.name
    findings = [Finding(
        title=f"SSH service on {svc.host}:{svc.port}",
        severity="info", host=svc.host, port=svc.port, proto=svc.proto,
        source="extscan:ssh",
        description=f"SSH is reachable and identifies as `{banner}`.",
        evidence=f"product={svc.product} version={svc.version} extrainfo={svc.extrainfo}",
        review_required=True,
        review_reason="Confirm key-only authentication and whether exposure to the whole "
                      "internet is required. Banner-based version checks are indicative "
                      "only; distributions backport fixes without changing the banner.",
        tags=["ssh"],
    )]
    return findings, []


@register("iis", lambda s: s.is_http and iis.looks_like_iis(s),
          "IIS/ASP.NET checks: diagnostic handlers, WebDAV, 8.3 names, error pages.")
def iis_probe(ctx: ProbeContext, svc: Service) -> tuple[list[Finding], list[Lead]]:
    return iis.probe_iis(svc, ctx.scope, ctx.policy.http)


@register("sslscan", lambda s: s.proto == "tcp" and s.is_tls,
          "Cipher-level TLS audit via sslscan (a coverage gap when not installed).")
def sslscan_probe(ctx: ProbeContext, svc: Service) -> tuple[list[Finding], list[Lead]]:
    """Cipher enumeration, which the built-in TLS probe cannot do.

    Python's ssl module only offers what the local OpenSSL build supports, so
    it cannot prove a server accepts RC4. sslscan links its own crypto and can.
    """
    res, findings = sslscan.run(ctx.runner, ctx.scope, svc.host, svc.port)
    if res.failure:
        raise RuntimeError(f"sslscan {res.failure}")
    return findings, []


def all_probe_names() -> list[str]:
    return [p.name for p in REGISTRY]
