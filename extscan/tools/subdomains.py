"""Subdomain enumeration, and the scope question it forces.

Enumeration routinely finds more than the engagement covers: a client hands
over three netblocks, and certificate transparency shows forty hostnames, a
dozen of which resolve into a cloud account nobody mentioned. Those are the
most valuable output of this stage and the most dangerous, because the
temptation is to scan them.

This module therefore does one thing that matters more than the enumeration
itself: it splits results into **in-scope** (resolves into the authorised
ranges, so scannable) and **out-of-scope** (reported as asset discovery, never
touched). Getting an asset added to scope is the client's decision, in writing.

Passive sources are preferred. Note that querying certificate transparency
discloses the client's domain to a third party -- the certificates themselves
are already public, but the query is logged, so the source list is explicit in
policy rather than implied.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from extscan.models import Finding, Host
from extscan.runner import Runner, have
from extscan.scope import Scope

CRTSH_URL = "https://crt.sh/?q={query}&output=json"

_HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")


@dataclass
class Enumerated:
    """One discovered name and what resolving it told us."""

    name: str
    addresses: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    in_scope: bool = False
    resolve_error: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "addresses": self.addresses,
                "sources": self.sources, "in_scope": self.in_scope,
                "resolve_error": self.resolve_error}


def _valid_hostname(name: str) -> bool:
    name = name.strip().rstrip(".").lower()
    if not name or len(name) > 253 or "*" in name:
        return False
    return bool(_HOSTNAME_RE.match(name))


def _under_domain(name: str, domain: str) -> bool:
    name, domain = name.lower().rstrip("."), domain.lower().rstrip(".")
    return name == domain or name.endswith("." + domain)


def from_crtsh(domain: str, timeout: float = 30.0,
               use_system_proxy: bool = False) -> tuple[set[str], str]:
    """Query crt.sh for names in issued certificates. Returns (names, error)."""
    url = CRTSH_URL.format(query=urllib.parse.quote(f"%.{domain}"))
    handlers: list = []
    if not use_system_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={  # noqa: S310
        "User-Agent": "extscan/0.2 (authorised security assessment)",
        "Accept": "application/json",
    })
    try:
        with opener.open(req, timeout=timeout) as resp:
            payload = resp.read(16 * 1024 * 1024)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return set(), f"{type(exc).__name__}: {exc}"

    try:
        records = json.loads(payload)
    except json.JSONDecodeError as exc:
        return set(), f"crt.sh returned unparseable JSON: {exc}"

    names: set[str] = set()
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        for field_name in ("name_value", "common_name"):
            raw = record.get(field_name) or ""
            for candidate in str(raw).split("\n"):
                candidate = candidate.strip().lower().lstrip("*.")
                if _valid_hostname(candidate) and _under_domain(candidate, domain):
                    names.add(candidate)
    return names, ""


def from_subfinder(runner: Runner, domain: str,
                   timeout: int = 300) -> tuple[set[str], str]:
    """Use subfinder when installed. Passive by default in recent versions."""
    if not have("subfinder"):
        return set(), "subfinder not installed"
    res = runner.run(["subfinder", "-d", domain, "-silent", "-all"],
                     stage="recon:subfinder", timeout=timeout,
                     stdout_name=f"subfinder-{domain}")
    if res.skipped:
        return set(), "dry run"
    names = {line.strip().lower() for line in (res.stdout or "").splitlines()
             if _valid_hostname(line.strip()) and _under_domain(line.strip(), domain)}
    if not names and not res.ok:
        return set(), f"subfinder exited {res.returncode}"
    return names, ""


def from_amass(runner: Runner, domain: str,
               timeout: int = 600) -> tuple[set[str], str]:
    """Use amass in passive mode. Active mode is deliberately not offered here."""
    if not have("amass"):
        return set(), "amass not installed"
    res = runner.run(["amass", "enum", "-passive", "-d", domain, "-silent"],
                     stage="recon:amass", timeout=timeout,
                     stdout_name=f"amass-{domain}")
    if res.skipped:
        return set(), "dry run"
    names = {line.strip().lower() for line in (res.stdout or "").splitlines()
             if _valid_hostname(line.strip()) and _under_domain(line.strip(), domain)}
    if not names and not res.ok:
        return set(), f"amass exited {res.returncode}"
    return names, ""


def resolve(name: str, timeout: float = 5.0) -> tuple[list[str], str]:
    """Resolve a hostname to addresses using the stdlib resolver.

    getaddrinfo rather than a DNS library: no dependency, and it follows the
    host's own resolver configuration, which is what the auditor's other tools
    will do too.
    """
    original = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.herror, OSError, TimeoutError) as exc:
        return [], f"{type(exc).__name__}: {exc}"
    finally:
        socket.setdefaulttimeout(original)

    addresses = sorted({info[4][0] for info in infos})
    return addresses, ""


def enumerate_domain(runner: Runner, scope: Scope, domain: str, *,
                     sources: list[str], resolve_timeout: float = 5.0,
                     use_system_proxy: bool = False,
                     max_names: int = 2000) -> tuple[list[Enumerated], list[str]]:
    """Enumerate one domain and split the results by scope.

    Returns (results, source_errors). Source errors are returned rather than
    raised because losing one source is a coverage gap to record, not a reason
    to abandon the stage.
    """
    collected: dict[str, set[str]] = {}
    errors: list[str] = []

    for source in sources:
        if source == "crt.sh":
            names, err = from_crtsh(domain, use_system_proxy=use_system_proxy)
        elif source == "subfinder":
            names, err = from_subfinder(runner, domain)
        elif source == "amass":
            names, err = from_amass(runner, domain)
        else:
            names, err = set(), f"unknown source {source!r}"
        if err:
            errors.append(f"{source}: {err}")
        for name in names:
            collected.setdefault(name, set()).add(source)

    results: list[Enumerated] = []
    for name in sorted(collected)[:max_names]:
        addresses, resolve_error = resolve(name, timeout=resolve_timeout)
        in_scope = bool(addresses) and all(scope.contains(a) for a in addresses)
        results.append(Enumerated(
            name=name, addresses=addresses,
            sources=sorted(collected[name]),
            in_scope=in_scope, resolve_error=resolve_error,
        ))

    if len(collected) > max_names:
        errors.append(f"result list truncated at max_names={max_names} "
                      f"({len(collected)} names found)")
    return results, errors


def to_findings(results: list[Enumerated], domain: str) -> tuple[list[Finding], list[Host]]:
    """Build findings and in-scope host records from enumeration results."""
    findings: list[Finding] = []
    hosts: list[Host] = []

    in_scope = [r for r in results if r.in_scope]
    out_of_scope = [r for r in results if not r.in_scope and r.addresses]
    unresolved = [r for r in results if not r.addresses]

    for entry in in_scope:
        for address in entry.addresses:
            hosts.append(Host(ip=address, hostnames=[entry.name],
                              state="unknown", discovered_by="subdomain-enum"))

    if results:
        findings.append(Finding(
            title=f"Subdomain enumeration for {domain}: {len(results)} name(s)",
            severity="info", host="", source="extscan:subdomains",
            description=(
                f"Passive enumeration found {len(results)} name(s) under {domain}: "
                f"{len(in_scope)} resolving into the authorised ranges, "
                f"{len(out_of_scope)} resolving elsewhere, "
                f"{len(unresolved)} not resolving."
            ),
            evidence="\n".join(
                f"{'IN ' if r.in_scope else 'OUT'} {r.name:<50} "
                f"{', '.join(r.addresses) or r.resolve_error or 'no address'}"
                f"   [{', '.join(r.sources)}]"
                for r in results[:120]
            ),
            tags=["recon", "subdomains"],
        ))

    if out_of_scope:
        by_host = "\n".join(f"{r.name:<50} -> {', '.join(r.addresses)}"
                            for r in out_of_scope[:80])
        findings.append(Finding(
            title=f"{len(out_of_scope)} subdomain(s) of {domain} resolve outside the "
                  "engagement scope",
            severity="info", host="", source="extscan:subdomains",
            description=(
                "These names belong to the client's domain but resolve to addresses "
                "that are not in the authorised ranges. They were NOT scanned. "
                "Commonly this is cloud or SaaS infrastructure the asset inventory "
                "has not caught up with -- which makes it exactly the sort of thing "
                "an attacker finds first. Dangling records pointing at "
                "unclaimed cloud resources are also a takeover risk."
            ),
            evidence=by_host,
            recommendation="Confirm ownership with the client and bring genuinely "
                           "owned assets into a future engagement's scope. Remove DNS "
                           "records that point at resources no longer owned.",
            review_required=True,
            review_reason=(
                "Do not test these without written authorisation covering them. The "
                "action here is a conversation with the client about asset inventory, "
                "and a check for dangling records that could be taken over."
            ),
            tags=["recon", "subdomains", "asset-discovery", "scope"],
        ))

    if unresolved:
        findings.append(Finding(
            title=f"{len(unresolved)} enumerated name(s) of {domain} do not resolve",
            severity="info", host="", source="extscan:subdomains",
            description="Names appearing in certificate transparency or other sources "
                        "that currently have no DNS record. These are often "
                        "decommissioned services; a name with a CNAME to an "
                        "unclaimed provider resource is a takeover candidate.",
            evidence="\n".join(f"{r.name}  ({r.resolve_error or 'no address'})"
                               for r in unresolved[:60]),
            review_required=True,
            review_reason="Check whether any of these are dangling CNAMEs pointing at "
                          "claimable third-party resources.",
            tags=["recon", "subdomains", "takeover-candidate"],
        ))

    return findings, hosts
