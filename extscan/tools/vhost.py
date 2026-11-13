"""Virtual-host enumeration: which names does this address serve differently?

Every other web check asks for `http://<ip>:<port>/`, so it sees the default
site and nothing else. One address commonly fronts several applications,
chosen by the `Host` header (and by SNI over TLS), and the others are missed
entirely.

The candidates are names already tied to the address: hostnames recorded for
the host (reverse DNS, in-scope names from recon) and the names in the
service's own certificate. Each is requested once, by `net.request_at`, which
connects to the in-scope IP and only carries the name inside the request. The
name is never resolved, never added to scope and never handed to another
tool: a name that DNS points somewhere else must not move the connection.

Whether a name is a distinct site is decided the way gobuster's vhost mode
does it, against two baselines: the answer by address, and the answer for a
random name that cannot exist under the same parent domain. A name counts
only if it differs from both, so a server that answers every name alike
(wildcard) yields nothing.
"""

from __future__ import annotations

import os
import time

from extscan.models import Finding, Service
from extscan.policy import HttpPolicy
from extscan.scope import Scope
from extscan.tools import net, waf

# Connection failures in a row, after the address itself answered, before the
# check stops and says it was cut off rather than carrying on knocking.
_MAX_CONSECUTIVE_FAILURES = 3


def candidates(svc: Service, hostnames: list[str], sans: list[str],
               limit: int) -> tuple[list[tuple[str, str]], int]:
    """(name, where it came from) to try, and how many were left out by `limit`.

    Recorded hostnames go first: they were tied to this address by DNS, while
    a certificate may list names served somewhere else. Wildcards, IP
    literals and anything that is not a plain hostname are dropped, since
    these strings come from the target.
    """
    seen: dict[str, str] = {}
    for origin, names in (("recorded hostname", hostnames), ("certificate SAN", sans)):
        for raw in names:
            name = net.valid_hostname(raw)
            if name and name not in seen:
                seen[name] = origin
    ordered = list(seen.items())
    return ordered[:limit], max(0, len(ordered) - limit)


def _parent(name: str) -> str:
    labels = name.split(".")
    return ".".join(labels[1:]) if len(labels) > 2 else name


def _random_name(parent: str) -> str:
    name = f"{os.urandom(8).hex()}.{parent}"
    if net.valid_hostname(name):
        return name
    # A parent already at the length limit: fall back to its last two labels.
    return f"{os.urandom(8).hex()}.{'.'.join(parent.split('.')[-2:])}"


def _same_answer(a: net.Response, a_name: str, b: net.Response, b_name: str) -> bool:
    if a.status != b.status:
        return False
    if a.status == 0:
        return True
    a, b = net.without_name(a, a_name), net.without_name(b, b_name)
    if a.headers.get("location", "") != b.headers.get("location", ""):
        return False
    return net.same_page(a, b)


def _describe(resp: net.Response) -> str:
    if resp.status == 0:
        return f"no answer ({resp.error[:120]})"
    text = f"{resp.status} {resp.reason}".strip()
    title = net.page_title(resp.text[:200_000])
    if title:
        text += f", title {title!r}"
    text += f", {len(resp.body)} bytes"
    if resp.headers.get("location"):
        text += f", Location: {resp.headers['location'][:200]}"
    return text


def check(svc: Service, scope: Scope, policy: HttpPolicy,
          names: list[tuple[str, str]]) -> tuple[list[Finding], str]:
    """Request `/` once per name. Returns findings and, if cut short, why."""
    findings: list[Finding] = []
    if not names:
        return findings, ""
    tls = svc.is_tls
    where = f"{svc.host}:{svc.port}"

    def ask(host: str = "") -> net.Response:
        if policy.inter_request_delay:
            time.sleep(policy.inter_request_delay)
        return net.request_at(svc.host, svc.port, scope, policy, tls=tls, host=host)

    by_ip = net.request_at(svc.host, svc.port, scope, policy, tls=tls)
    if by_ip.failed_at == "scope":
        raise RuntimeError(by_ip.error)
    by_ip_name = net.host_header(svc.host, svc.port, tls)
    # A throttled answer is the same for every name, and a name asked just
    # after the throttle starts would look different from baselines taken
    # just before it. Stop instead of comparing.
    if waf.block_signal(by_ip):
        return findings, f"the request by address answered {waf.block_signal(by_ip)}"

    random_for: dict[str, tuple[str, net.Response]] = {}
    failures = 0
    for name, origin in names:
        parent = _parent(name)
        if parent not in random_for:
            random_name = _random_name(parent)
            random_for[parent] = (random_name, ask(random_name))
        random_name, by_random = random_for[parent]

        resp = by_random if waf.block_signal(by_random) else ask(name)
        if waf.block_signal(resp):
            return findings, f"a request by name answered {waf.block_signal(resp)}"
        if resp.status == 0:
            failures = failures + 1 if resp.failed_at == "connect" else 0
            if failures >= _MAX_CONSECUTIVE_FAILURES and by_ip.status:
                return findings, (f"{failures} connections in a row failed after the "
                                  f"address answered ({resp.error[:120]})")
            continue
        failures = 0
        if _same_answer(resp, name, by_ip, by_ip_name) \
                or _same_answer(resp, name, by_random, random_name):
            continue

        scheme = "https" if tls else "http"
        findings.append(Finding(
            title=f"Virtual host {name} on {where} serves a different site",
            severity="info", host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:vhost",
            description=f"Asking {where} for `{name}` (Host header"
                        + (" and TLS SNI" if tls else "") + ") returns a different "
                        "response from the one served by address, and from the one "
                        "served for a made-up name under the same domain. This "
                        "application is not reached when scanning by address, so it "
                        "has had none of the other checks: no path checks, no nuclei, "
                        "no screenshot.",
            evidence="\n".join([
                f"GET {scheme}://{where}/ with Host: {name} -> {_describe(resp)}",
                f"by address ({svc.host}) -> {_describe(by_ip)}",
                f"random name ({random_name}) -> {_describe(by_random)}",
                f"name taken from: {origin}",
            ])[:3000],
            recommendation="Confirm the name belongs to the engagement, then test it by "
                           "name. extscan connected to the in-scope address only and did "
                           "not resolve the name.",
            review_required=True,
            review_reason=f"{name} is a separate application on {where} that this scan "
                          "did not assess. Decide whether it is in scope; if it is, it "
                          "needs testing by name, with the client's agreement that the "
                          "name is theirs.",
            tags=["http", "vhost"],
        ))
    return findings, ""
