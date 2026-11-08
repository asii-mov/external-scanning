"""Safety classes: how much noise each check makes, and a cap on it.

Modelled on BBOT's module flags, with four ordered classes:

- `passive`: no packets to the target. Public DNS records through a
  resolver, certificate transparency, parsing data already collected.
- `active`: ordinary, low-volume traffic a normal client sends. A connect,
  a banner grab, a handful of GETs, a TLS handshake, an SNMP get with a
  community string from a short list.
- `loud`: many requests, or a fingerprintable scanning pattern. Path lists,
  nuclei, NSE script batteries, cipher enumeration, testssl.sh. Safe, but an
  IDS or a watchful admin will notice.
- `invasive`: anything that could change state or affect availability.
  Nothing in extscan is invasive. The class exists so the cap can refuse it.

Every probe (`register(..., safety=)` in probes.py), every chase handler
(`HANDLER_SAFETY` in chase.py) and every pipeline stage (`STAGES` below)
carries a class. The policy's `max_safety` caps them: anything above the cap
is skipped and recorded as a coverage gap, never dropped silently. The
default cap is `loud`, which runs everything extscan has.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .resilience import Degradation


class SafetyClass(IntEnum):
    PASSIVE = 0
    ACTIVE = 1
    LOUD = 2
    INVASIVE = 3

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: object) -> SafetyClass:
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls[value.strip().upper()]
            except KeyError:
                pass
        raise ValueError(f"unknown safety class {value!r}; choose from "
                         f"{', '.join(str(c) for c in cls)}")


PASSIVE = SafetyClass.PASSIVE
ACTIVE = SafetyClass.ACTIVE
LOUD = SafetyClass.LOUD
INVASIVE = SafetyClass.INVASIVE

DEFAULT_CAP = LOUD

# Every gap the cap records starts with this, so it can be told apart from a
# tool failure and cleared when a later run with a higher cap does the work.
CAP_REASON = "skipped by safety cap"


@dataclass(frozen=True)
class Label:
    safety: SafetyClass
    why: str


# The pipeline's own network stages and the policy-gated parts inside them.
# Keys are what the pipeline gates on and what gaps name as their component.
STAGES: dict[str, Label] = {
    "recon:subdomains": Label(PASSIVE, "certificate transparency and passive "
                              "subfinder/amass sources; names resolved through the resolver"),
    "dns:host-names": Label(PASSIVE, "A and MX lookups of nmap-reported host names "
                            "through the resolver"),
    "dns:takeover": Label(ACTIVE, "ordinary NS/SOA lookups sent to the zone's own "
                          "nameservers, plus resolver lookups of CNAME and MX targets"),
    "dns:axfr": Label(ACTIVE, "one zone transfer request per authoritative nameserver"),
    "dns:nsec-walk": Label(LOUD, "walks the NSEC chain, up to dns.max_walk_steps "
                           "queries to the zone's nameservers"),
    "discover:tcp": Label(ACTIVE, "nmap SYN/connect sweep of the policy's port list, "
                          "with -sV banner grabs on open ports"),
    "discover:udp": Label(ACTIVE, "nmap UDP sweep of the policy's port list, with "
                          "-sV probes on responding ports"),
    "nmap:nse": Label(LOUD, "NSE script batteries (nmap.scripts) on every open port"),
    "nmap:os-detection": Label(LOUD, "nmap -O OS fingerprinting, malformed probe "
                               "packets an IDS recognises"),
    "probe:nuclei": Label(LOUD, "thousands of templated requests per web service"),
    "http:paths": Label(LOUD, "the http_fingerprint probe's disclosure-path list "
                        "(http.paths, ~23 GETs per web service)"),
    "screenshot": Label(ACTIVE, "one headless-browser page load per web service "
                        "or finding, every request scope-checked"),
}

# Which DNS check name maps to which STAGES key.
DNS_CHECKS = {"axfr": "dns:axfr", "nsec-walk": "dns:nsec-walk",
              "takeover": "dns:takeover", "host-names": "dns:host-names"}


def stage_safety(key: str) -> SafetyClass:
    return STAGES[key].safety


def over_cap(cls: SafetyClass, cap: SafetyClass) -> bool:
    return cls > cap


def is_cap_gap(d: Degradation) -> bool:
    return d.reason.startswith(CAP_REASON)


def cap_reason(component: str, cls: SafetyClass, cap: SafetyClass) -> str:
    return f"{CAP_REASON}: {component} is {cls}, policy max_safety is {cap}"


def cap_gap(*, stage: str, component: str, cls: SafetyClass, cap: SafetyClass,
            impact: str, rerun: str, hosts: list[str] | None = None,
            severity: str = "warning") -> Degradation:
    """The coverage gap for a check the cap refused to run."""
    return Degradation(
        stage=stage, component=component,
        reason=cap_reason(component, cls, cap),
        impact=impact, severity=severity, hosts=sorted(set(hosts or [])),
        recoverable=True,
        remedy=f"If the engagement permits {cls} checks, set \"max_safety\": "
               f"\"{cls}\" in the policy, then {rerun}.",
    )


def table() -> list[dict]:
    """Every labelled check: stages, probes and chase handlers, one row each."""
    from . import chase, probes

    rows = [{"kind": "stage", "name": name, "safety": str(label.safety),
             "description": label.why} for name, label in STAGES.items()]
    rows += [{"kind": "probe", "name": p.name, "safety": str(p.safety),
              "description": p.description} for p in probes.REGISTRY]
    rows += [{"kind": "chase", "name": kind,
              "safety": str(chase.HANDLER_SAFETY[kind].safety),
              "description": chase.HANDLER_SAFETY[kind].why}
             for kind in chase.HANDLERS]
    return rows
