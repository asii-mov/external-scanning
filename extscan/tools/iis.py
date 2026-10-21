"""IIS and ASP.NET enumeration, read-only.

Windows web estates leak in ways that generic web scanning misses, and the
leaks are specific enough to be worth their own module:

* `trace.axd` and `elmah.axd` are diagnostic handlers that, left enabled in
  production, hand an unauthenticated visitor recent requests, headers,
  cookies, session identifiers and stack traces. They are a credential-capture
  endpoint wearing a framework's clothing;
* IIS serves 8.3 short filenames, so `/secret~1.asp` resolves to
  `/secretdocument.aspx`, and the error-code difference between a matching and
  non-matching wildcard turns that into filename enumeration without any
  directory listing;
* WebDAV is frequently left enabled on sites that do not use it, and its verb
  set is a much larger surface than GET/POST.

Everything here is a GET or an OPTIONS. Nothing authenticates, uploads, or
writes -- the WebDAV check reads the advertised verb list rather than trying
PUT, because trying PUT on a client's production server is a change, not a test.
"""

from __future__ import annotations

import re

from extscan.models import Finding, Lead, Service
from extscan.policy import HttpPolicy
from extscan.scope import Scope
from extscan.tools import net

# Diagnostic handlers, in rough order of how bad an exposure they are.
HANDLERS: list[tuple[str, str, str]] = [
    ("/trace.axd", "high",
     "ASP.NET trace viewer. Serves the most recent requests to the application "
     "including headers, cookies, session state and form values -- an "
     "unauthenticated feed of other users' session identifiers."),
    ("/elmah.axd", "high",
     "ELMAH error log viewer. Exposes unhandled-exception detail, stack traces, "
     "connection strings and often full request bodies."),
    ("/glimpse.axd", "medium",
     "Glimpse diagnostics. Exposes routes, configuration and request detail."),
    # IIS paths are case-insensitive, but a reverse proxy or a case-sensitive
    # handler mapping in front of it may not be, so the variant is still worth
    # requesting. Duplicate hits are collapsed below.
    ("/ELMAH.axd", "high", "ELMAH error log viewer (case variant)."),
]

# Files that identify a default or unhardened install.
DEFAULT_FILES: list[tuple[str, str]] = [
    ("/iisstart.htm", "The default IIS landing page is present, which usually means "
                      "a site was provisioned and never configured."),
    ("/iisstart.png", "Default IIS assets are present."),
    ("/welcome.png", "Default IIS assets are present."),
    ("/aspnet_client/", "The aspnet_client directory is browsable."),
]

WEBDAV_VERBS = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK",
                "UNLOCK", "SEARCH", "PUT", "DELETE"}

# Markers of a verbose ASP.NET error page.
_STACK_MARKERS = [
    "server error in", "[httpexception", "[sqlexception", "stack trace:",
    "microsoft .net framework version", "aspxerrorpath", "system.web.",
    "at system.", "runtime error", "<title>runtime error</title>",
]

_VERSION_HEADERS = ["server", "x-aspnet-version", "x-aspnetmvc-version",
                    "x-powered-by", "microsoftsharepointteamservices"]


def looks_like_iis(svc: Service, headers: dict[str, str] | None = None) -> bool:
    """Is this service IIS or ASP.NET?

    Checks the nmap banner and, when available, response headers -- a site
    behind a reverse proxy may only reveal ASP.NET through `X-AspNet-Version`.
    """
    banner = " ".join([svc.product or "", svc.version or "",
                       svc.extrainfo or "", svc.name or ""]).lower()
    if "iis" in banner or "microsoft" in banner or "asp.net" in banner:
        return True
    for cpe in svc.cpe:
        if "microsoft" in cpe.lower() and ("iis" in cpe.lower() or "asp" in cpe.lower()):
            return True
    if headers:
        lowered = {k.lower(): (v or "").lower() for k, v in headers.items()}
        if "microsoft-iis" in lowered.get("server", ""):
            return True
        if any(h in lowered for h in ("x-aspnet-version", "x-aspnetmvc-version")):
            return True
        if "asp.net" in lowered.get("x-powered-by", ""):
            return True
    return False


def _version_disclosure(headers: dict[str, str], host: str,
                        port: int) -> Finding | None:
    disclosed = {h: headers[h] for h in _VERSION_HEADERS if h in headers}
    if not disclosed:
        return None
    return Finding(
        title=f"IIS/ASP.NET version disclosure on {host}:{port}",
        severity="low", host=host, port=port, source="extscan:iis",
        description="Response headers name the web server and framework versions, "
                    "which lets an attacker select exploits for the exact build "
                    "without probing for them. On Windows estates this also "
                    "narrows down the patch level of the host itself.",
        evidence="\n".join(f"{k}: {v}" for k, v in disclosed.items()),
        recommendation="Remove or genericise these headers (`removeServerHeader` in "
                       "requestFiltering, and `enableVersionHeader=false` in "
                       "httpRuntime for ASP.NET).",
        tags=["iis", "aspnet", "information-disclosure"],
    )


def _check_webdav(base: str, scope: Scope, policy: HttpPolicy, host: str,
                  port: int) -> Finding | None:
    """Read the advertised verb list. Never attempts a write verb."""
    resp = net.fetch(base, scope, policy, method="OPTIONS")
    if resp.status == 0:
        return None
    allow = " ".join([resp.headers.get("allow", ""),
                      resp.headers.get("public", "")]).upper()
    dav_header = resp.headers.get("dav", "")
    verbs = {v.strip() for v in re.split(r"[,\s]+", allow) if v.strip()}
    dav_verbs = sorted(verbs & WEBDAV_VERBS)

    if not dav_verbs and not dav_header:
        return None

    write_verbs = sorted(v for v in dav_verbs if v in {"PUT", "DELETE", "MKCOL",
                                                       "COPY", "MOVE"})
    severity = "high" if write_verbs else "medium"
    return Finding(
        title=f"WebDAV appears enabled on {host}:{port}"
              + (f" with write verbs ({', '.join(write_verbs)})" if write_verbs else ""),
        severity=severity, host=host, port=port, source="extscan:iis",
        description=(
            "The server advertises WebDAV methods. WebDAV widens the HTTP surface "
            "well beyond GET/POST and has a long history of authentication bypass "
            "and upload issues. Where write verbs are advertised, the risk is "
            "remote file placement -- which on IIS can mean code execution."
        ),
        evidence=f"OPTIONS {base} -> {resp.status}\n"
                 f"Allow/Public: {allow or '(none)'}\nDAV: {dav_header or '(none)'}",
        recommendation="Remove the WebDAV module if the application does not use it; "
                       "otherwise require authentication and disable write verbs.",
        review_required=True,
        review_reason=(
            "extscan read the advertised verb list only -- it did not attempt PUT or "
            "DELETE, because writing to a client's server is a change rather than a "
            "test. An auditor should confirm whether the write verbs are genuinely "
            "usable, with explicit written approval for that step."
        ),
        confidence="tentative",
        tags=["iis", "webdav"],
    )


def _check_shortnames(base: str, scope: Scope, policy: HttpPolicy, host: str,
                      port: int) -> Finding | None:
    """Detect IIS 8.3 short-name enumeration via the error-code difference.

    The technique: with short names served, a wildcard that matches something
    returns 404 while one that matches nothing returns 400. Two requests
    establish whether the condition exists; enumerating the actual filenames
    would take thousands, which is a separate decision for the auditor.
    """
    matching = f"{base.rstrip('/')}/*~1*/.aspx"
    nonmatching = f"{base.rstrip('/')}/zzqq9xv*~1*/.aspx"

    first = net.fetch(matching, scope, policy)
    second = net.fetch(nonmatching, scope, policy)
    if first.status == 0 or second.status == 0:
        return None

    # The signature is a *difference* between the two, classically 404 vs 400.
    vulnerable = first.status == 404 and second.status == 400
    if not vulnerable:
        return None

    return Finding(
        title=f"IIS 8.3 short-name enumeration possible on {host}:{port}",
        severity="medium", host=host, port=port, source="extscan:iis",
        description=(
            "The server distinguishes matching from non-matching 8.3 short-name "
            "wildcards by status code, which allows an attacker to enumerate file "
            "and directory names character by character without any directory "
            "listing. Names recovered this way routinely include backup copies, "
            "admin pages and configuration files that were never linked."
        ),
        evidence=(f"GET {matching} -> {first.status}\n"
                  f"GET {nonmatching} -> {second.status}\n"
                  "A 404/400 split is the documented indicator."),
        recommendation="Disable 8.3 name generation (`fsutil 8dot3name set 1`) and "
                       "strip existing short names from the web root.",
        review_required=True,
        review_reason=(
            "extscan confirmed the condition with two requests and did not enumerate. "
            "Deciding whether to run a full enumeration -- thousands of requests "
            "against a production site -- is the auditor's call."
        ),
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
        tags=["iis", "shortname", "information-disclosure"],
    )


def _check_verbose_errors(base: str, scope: Scope, policy: HttpPolicy, host: str,
                          port: int) -> Finding | None:
    """Request a path that should fail, and see how much the failure says."""
    probe = f"{base.rstrip('/')}/extscan_nonexistent_%27.aspx"
    resp = net.fetch(probe, scope, policy)
    if resp.status == 0 or not resp.body:
        return None
    body = resp.text[:20_000].lower()
    hits = [marker for marker in _STACK_MARKERS if marker in body]
    if not hits:
        return None

    version = ""
    match = re.search(r"microsoft \.net framework version:?\s*([\d.]+)", body)
    if match:
        version = match.group(1)

    return Finding(
        title=f"Verbose ASP.NET error page on {host}:{port}",
        severity="medium", host=host, port=port, source="extscan:iis",
        description=(
            "The application returns framework error detail to unauthenticated "
            "clients. These pages typically disclose the .NET version, physical "
            "paths on disk, source file names and line numbers, and sometimes "
            "connection strings"
            + (f". The page names .NET {version}." if version else ".")
        ),
        evidence=f"GET {probe} -> {resp.status}\nmatched markers: "
                 f"{', '.join(hits[:6])}\n\n{resp.text[:800]}",
        recommendation="Set `<customErrors mode=\"On\">` and "
                       "`<httpErrors existingResponse=\"Replace\">`, and never ship "
                       "debug builds to production.",
        tags=["iis", "aspnet", "information-disclosure"],
    )


def probe_iis(svc: Service, scope: Scope, policy: HttpPolicy,
              root_headers: dict[str, str] | None = None
              ) -> tuple[list[Finding], list[Lead]]:
    """Run the full read-only IIS/ASP.NET check set against one web service."""
    scope.assert_host(svc.host, context="iis probe")
    base = svc.base_url()
    findings: list[Finding] = []
    leads: list[Lead] = []

    headers = root_headers
    if headers is None:
        root = net.fetch(base, scope, policy)
        headers = root.headers
        if root.status == 0:
            return findings, leads

    version_finding = _version_disclosure(headers, svc.host, svc.port)
    if version_finding:
        findings.append(version_finding)

    # Diagnostic handlers: the highest-value checks here. IIS is
    # case-insensitive, so /elmah.axd and /ELMAH.axd are usually the same
    # handler -- report it once rather than inflating the count.
    seen_handlers: set[str] = set()
    for path, severity, why in HANDLERS:
        url = base.rstrip("/") + path
        resp = net.fetch(url, scope, policy)
        if resp.status in (401, 403):
            findings.append(Finding(
                title=f"{path} present but access-controlled on {svc.host}:{svc.port}",
                severity="info", host=svc.host, port=svc.port, source="extscan:iis",
                description=f"{url} returned {resp.status}, so the handler is "
                            "registered but protected. It should be removed from "
                            "production rather than relying on that protection.",
                evidence=f"GET {url} -> {resp.status}",
                tags=["iis", "aspnet", "handler"],
            ))
            continue
        if not resp.ok or not resp.body:
            continue
        body = resp.text[:8000].lower()
        # Confirm it is the real handler, not the app's catch-all page.
        if path.lower().endswith("trace.axd") and not any(
                marker in body for marker in ("application trace", "trace information",
                                              "requests to this application")):
            continue
        if "elmah" in path.lower() and "error log" not in body and "elmah" not in body:
            continue

        normalised = path.lower()
        if normalised in seen_handlers:
            continue
        seen_handlers.add(normalised)

        findings.append(Finding(
            title=f"Exposed diagnostic handler {path} on {svc.host}:{svc.port}",
            severity=severity, host=svc.host, port=svc.port, source="extscan:iis",
            description=why,
            evidence=f"GET {url} -> {resp.status}\ncontent-type: {resp.content_type}\n"
                     f"length: {len(resp.body)}\n\n{resp.text[:700]}",
            recommendation="Remove the handler registration from web.config in "
                           "production; do not rely on obscurity or on IP filtering "
                           "alone.",
            review_required=True,
            review_reason=(
                "Check what the handler is currently exposing. If it has been "
                "serving other users' session identifiers or credentials, this is an "
                "incident to raise with the client now, not a finding to file."
            ),
            tags=["iis", "aspnet", "handler", "information-disclosure"],
        ))
        leads.append(Lead(
            kind="web_paths", host=svc.host, port=svc.port, url=url,
            reason=f"{path} is serving content; establish what it discloses.",
            origin="extscan:iis",
        ))

    for path, why in DEFAULT_FILES:
        url = base.rstrip("/") + path
        resp = net.fetch(url, scope, policy)
        if resp.ok and resp.body:
            findings.append(Finding(
                title=f"Default IIS content at {path} on {svc.host}:{svc.port}",
                severity="info", host=svc.host, port=svc.port, source="extscan:iis",
                description=why,
                evidence=f"GET {url} -> {resp.status}, {len(resp.body)} bytes",
                review_required=True,
                review_reason="A default install page often means an unmaintained or "
                              "forgotten site. Establish who owns it.",
                tags=["iis", "default-content"],
            ))
            break          # one is enough to make the point

    for check in (_check_webdav, _check_shortnames, _check_verbose_errors):
        finding = check(base, scope, policy, svc.host, svc.port)
        if finding:
            findings.append(finding)

    return findings, leads
