"""nuclei adapter: templated checks against discovered web services.

Two things this module does beyond shelling out:

* it constrains nuclei to non-destructive template families. The default
  exclude list drops dos/intrusive/fuzz/brute-force, and out-of-band
  (interactsh) detection is off, because the public interactsh relay would see
  client traffic;
* it reads results as *leads*, not just findings. A nuclei hit on a swagger
  endpoint is not the end of the story -- it is the start of "so what does
  that API expose?", which is the question the auditors actually want answered.
"""

from __future__ import annotations

import json

from extscan.models import Finding, Lead, Service
from extscan.policy import Policy
from extscan.runner import Result, Runner, require
from extscan.scope import Scope


def argv(policy: Policy, targets_file: str, jsonl_out: str) -> list[str]:
    p = policy.nuclei
    cmd = [
        "nuclei",
        "-list", targets_file,
        "-jsonl", "-output", jsonl_out,
        "-severity", ",".join(p.severities),
        "-rate-limit", str(p.rate_limit),
        "-c", str(p.concurrency),
        "-retries", str(p.retries),
        "-timeout", str(p.request_timeout),
        "-silent", "-no-color",
        "-disable-update-check",
    ]
    if not p.allow_intrusive and p.exclude_tags:
        cmd += ["-exclude-tags", ",".join(p.exclude_tags)]
    if p.include_tags:
        cmd += ["-tags", ",".join(p.include_tags)]
    for t in p.templates:
        cmd += ["-t", t]
    if not p.interactsh:
        cmd.append("-no-interactsh")
    elif p.interactsh_server:
        cmd += ["-interactsh-server", p.interactsh_server]
    cmd += p.extra_args
    return cmd


def write_targets(runner: Runner, services: list[Service]) -> tuple[str, list[str]]:
    """Write the URL list nuclei will read. Returns (path, urls)."""
    urls = [s.base_url() for s in services if s.is_http]
    seen, ordered = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    path = runner.store.raw_path("nuclei-targets.txt")
    path.write_text("\n".join(ordered) + ("\n" if ordered else ""))
    return str(path), ordered


LEAD_TRIGGERS: list[tuple[tuple[str, ...], str, str]] = [
    (("swagger", "openapi", "api-docs", "apidocs", "redoc"), "openapi",
     "An API description document is exposed; enumerate what it describes."),
    (("graphql",), "graphql",
     "A GraphQL endpoint is exposed; check whether introspection is enabled."),
    (("git-config", "git-exposure", ".git"), "git_exposure",
     "A .git directory may be served; check whether source/history is retrievable."),
    (("directory-listing", "dir-listing", "autoindex"), "web_paths",
     "Directory listing is enabled; enumerate what is browsable."),
    (("env-file", "dotenv", ".env"), "secret_file",
     "An environment file may be exposed; it commonly contains credentials."),
    (("actuator", "spring-boot"), "web_paths",
     "Spring Boot actuator endpoints may expose configuration or heap dumps."),
    (("phpinfo",), "web_paths",
     "phpinfo() output exposes build, path and extension detail."),
    (("prometheus", "metrics"), "web_paths",
     "A metrics endpoint may expose internal hostnames and topology."),
    (("elasticsearch", "kibana"), "web_paths",
     "Elasticsearch/Kibana exposure; check whether indices are readable."),
    (("jenkins", "gitlab", "sonarqube", "grafana", "jira", "confluence"), "web_paths",
     "A named application is exposed; check authentication and version."),
]

REVIEW_TRIGGERS: list[tuple[tuple[str, ...], str]] = [
    (("swagger", "openapi", "api-docs", "redoc"),
     "Exposed API documentation. An auditor must decide whether the described "
     "endpoints are meant to be public and whether any are unauthenticated."),
    (("login", "panel", "admin", "dashboard", "console"),
     "An administrative or authentication interface is reachable from the "
     "internet. Whether that is acceptable is a business decision."),
    (("default-login", "default-credential"),
     "A default-credential template matched. Confirm by hand before reporting; "
     "do not change anything on the target."),
    (("takeover", "subdomain-takeover"),
     "Possible takeover condition. Verify ownership before any claim."),
    (("backup", "sql-dump", "db-dump"),
     "A backup or database dump may be downloadable. Confirm content type and "
     "whether it holds real data, without exfiltrating it."),
    (("graphql",),
     "GraphQL endpoint. Check introspection and whether mutations are exposed."),
    (("cors",),
     "CORS policy finding. Judge exploitability against what the origin can reach."),
]


def _matches(needles: tuple[str, ...], haystack: str) -> bool:
    return any(n in haystack for n in needles)


def parse_jsonl(text: str, scope: Scope | None = None,
                depth: int = 0) -> tuple[list[Finding], list[Lead]]:
    """Parse nuclei JSONL into findings plus follow-up leads."""
    findings: list[Finding] = []
    leads: list[Lead] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue

        info = rec.get("info") or {}
        tid = str(rec.get("template-id") or rec.get("templateID") or "unknown")
        name = str(info.get("name") or tid)
        sev = str(info.get("severity") or "info").lower()
        if sev in ("unknown", ""):
            sev = "info"
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        host = str(rec.get("ip") or "").strip()
        matched = str(rec.get("matched-at") or rec.get("matched_at") or rec.get("host") or "")
        url = str(rec.get("url") or matched)

        if not host:
            # Fall back to the host component of the URL when nuclei omits ip.
            from urllib.parse import urlsplit
            host = (urlsplit(matched or url).hostname or "")

        # Drop anything outside scope: nuclei follows redirects, so a result
        # can legitimately name a host we were never authorised to touch.
        if scope is not None and host and not scope.contains(host):
            findings.append(Finding(
                title=f"nuclei result suppressed: out-of-scope host {host}",
                severity="info", source="nuclei",
                description=f"Template `{tid}` matched against {matched!r}, whose host is "
                            "not in the engagement scope. The result is recorded but was "
                            "not investigated further.",
                evidence=matched[:500], review_required=True,
                review_reason="A target redirected the scanner off-scope. Worth noting in "
                              "the report; do not test the third-party host.",
                tags=["out-of-scope", tid],
            ))
            continue

        try:
            port = int(str(rec.get("port") or "").strip() or 0) or None
        except ValueError:
            port = None

        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]

        extracted = rec.get("extracted-results") or rec.get("extracted_results") or []
        if isinstance(extracted, str):
            extracted = [extracted]

        evidence_parts = [f"matched-at: {matched}"]
        if extracted:
            evidence_parts.append("extracted: " + ", ".join(str(e)[:200] for e in extracted[:10]))
        if rec.get("matcher-name"):
            evidence_parts.append(f"matcher: {rec['matcher-name']}")
        for key in ("request", "response"):
            if rec.get(key):
                evidence_parts.append(f"--- {key} ---\n{str(rec[key])[:1500]}")

        haystack = " ".join([tid, name, *(str(t) for t in tags), matched]).lower()

        review_required, review_reason = False, ""
        for needles, reason in REVIEW_TRIGGERS:
            if _matches(needles, haystack):
                review_required, review_reason = True, reason
                break

        findings.append(Finding(
            title=name,
            severity=sev, host=host, port=port, proto="tcp", source=f"nuclei:{tid}",
            description=str(info.get("description") or "").strip()
                        or f"nuclei template `{tid}` matched.",
            evidence="\n".join(evidence_parts)[:6000],
            recommendation=str(info.get("remediation") or "").strip(),
            references=[str(r) for r in refs][:10],
            review_required=review_required, review_reason=review_reason,
            tags=["nuclei", *(str(t) for t in tags)][:12],
        ))

        for needles, kind, reason in LEAD_TRIGGERS:
            if _matches(needles, haystack):
                leads.append(Lead(
                    kind=kind, host=host, port=port, url=matched or url,
                    params={"template": tid, "extracted": [str(e)[:300] for e in extracted[:10]]},
                    reason=reason, origin=f"nuclei:{tid}", depth=depth + 1,
                ))
                break

    return findings, leads


def run(runner: Runner, scope: Scope, policy: Policy,
        services: list[Service]) -> tuple[Result | None, list[Finding], list[Lead]]:
    """Run nuclei against every HTTP-ish service. No web services -> no-op."""
    targets_file, urls = write_targets(runner, services)
    if not urls:
        return None, [], []
    if not runner.dry_run:
        require("nuclei")
    out_path = runner.store.raw_path("nuclei.jsonl")
    cmd = argv(policy, targets_file, str(out_path))
    res = runner.run(cmd, stage="probe:nuclei", timeout=policy.nuclei.timeout_sec,
                     stdout_name="nuclei")
    text = out_path.read_text(errors="replace") if out_path.exists() else ""
    findings, leads = parse_jsonl(text, scope=scope)
    return res, findings, leads
