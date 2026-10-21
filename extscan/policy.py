"""Scan policy: how hard to push, and what is off the table entirely.

Defaults are deliberately read-only and non-disruptive. An external audit's
job is to tell the client what is exposed, not to knock it over, so the
intrusive/DoS/fuzzing families stay excluded unless someone edits a policy
file on purpose and the engagement covers it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

# nmap's default top-1000 TCP is a reasonable opener; full range is opt-in
# because it multiplies scan time on a wide netblock.
TCP_TOP = "1-1024,1080,1194,1433,1521,2049,2082,2083,2375,2376,2483,2484,3000,3128,3268,3306,3389,4443,4444,4786,5000,5432,5555,5601,5672,5900,5984,5985,5986,6379,6443,7001,7002,8000,8008,8009,8080,8081,8088,8089,8161,8200,8443,8500,8834,8888,9000,9042,9090,9092,9200,9300,9443,10000,11211,15672,27017,27018,50000"

# UDP is slow, so a curated list of services that actually matter externally.
UDP_TOP = "53,67,69,123,137,138,161,162,500,514,520,623,1434,1604,1900,3391,4500,5353,11211"


@dataclass
class NmapPolicy:
    tcp_ports: str = TCP_TOP
    udp_ports: str = UDP_TOP
    timing: str = "-T4"
    version_intensity: int = 7
    host_timeout: str = "30m"
    max_retries: int = 2
    min_rate: int = 0                      # 0 = let nmap decide
    scripts: str = "default,safe,vuln"     # categories; never "exploit"/"dos"
    skip_host_discovery: bool = False      # -Pn, for hosts that drop ping
    do_udp: bool = True
    extra_args: list[str] = field(default_factory=list)
    timeout_sec: int = 7200


@dataclass
class NucleiPolicy:
    severities: list[str] = field(default_factory=lambda: ["info", "low", "medium", "high", "critical"])
    exclude_tags: list[str] = field(default_factory=lambda: ["dos", "intrusive", "fuzz", "brute-force"])
    include_tags: list[str] = field(default_factory=list)
    rate_limit: int = 50                   # requests/sec, total
    concurrency: int = 15
    retries: int = 1
    request_timeout: int = 10
    templates: list[str] = field(default_factory=list)   # extra -t paths
    extra_args: list[str] = field(default_factory=list)
    timeout_sec: int = 3600
    allow_intrusive: bool = False          # must be set on purpose
    # Out-of-band detection relays interactions through a public interactsh
    # server, which means client data leaves your infrastructure. Off unless
    # the engagement paperwork covers it (or you self-host and set the URL).
    interactsh: bool = False
    interactsh_server: str = ""


# A short, curated list of paths that disclose information when present. This
# is not directory brute-forcing: it is one GET each for things that should
# never be reachable from the internet, chosen so a full pass is a few dozen
# requests rather than tens of thousands.
DISCLOSURE_PATHS = [
    "/robots.txt",
    "/.well-known/security.txt",
    "/.git/config",
    "/.env",
    "/swagger.json",
    "/openapi.json",
    "/swagger/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/api-docs",
    "/graphql",
    "/actuator",
    "/actuator/env",
    "/actuator/heapdump",
    "/server-status",
    "/phpinfo.php",
    "/metrics",
    "/debug/pprof/",
    "/.DS_Store",
    "/web.config",
    "/config.json",
]


@dataclass
class HttpPolicy:
    timeout_sec: int = 12
    max_redirects: int = 3                 # each hop re-checked against scope
    max_body_bytes: int = 2_000_000
    user_agent: str = "extscan/0.1 (authorised security assessment)"
    verify_tls: bool = False               # audit targets routinely have bad certs
    path_checks: bool = True
    paths: list[str] = field(default_factory=lambda: list(DISCLOSURE_PATHS))
    inter_request_delay: float = 0.0       # seconds; raise to be gentler on fragile hosts
    # Off by default on purpose. If the operator's shell has http_proxy set for
    # unrelated reasons, honouring it would route the client's traffic through
    # a third party and make every result reflect the proxy, not the target.
    # Set true only when the engagement requires a specific egress path.
    use_system_proxy: bool = False


@dataclass
class SnmpPolicy:
    # Read-only GET of sysDescr with each of these. No SET is ever attempted:
    # confirming a write community by writing would change client state.
    communities: list[str] = field(default_factory=lambda: [
        "public", "private", "community", "manager", "admin", "cisco",
        "default", "read", "write", "snmp", "monitor",
    ])
    timeout_sec: float = 2.0
    retries: int = 1
    versions: list[int] = field(default_factory=lambda: [1, 2])  # v1, v2c
    walk_on_hit: bool = True               # pull a few more OIDs after a hit


@dataclass
class Policy:
    profile: str = "standard"
    nmap: NmapPolicy = field(default_factory=NmapPolicy)
    nuclei: NucleiPolicy = field(default_factory=NucleiPolicy)
    http: HttpPolicy = field(default_factory=HttpPolicy)
    snmp: SnmpPolicy = field(default_factory=SnmpPolicy)
    max_lead_depth: int = 3
    max_leads_per_run: int = 500
    stop_on_tool_error: bool = False
    # Per-service probes are network-bound and independent, so they run in a
    # small thread pool. Keep it modest: the point is to finish before the
    # auditor loses interest, not to flood the client's perimeter.
    max_workers: int = 8

    @classmethod
    def for_profile(cls, name: str) -> "Policy":
        p = cls(profile=name)
        if name == "quick":
            p.nmap.tcp_ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017"
            p.nmap.udp_ports = "53,123,161,500,1900,5353"
            p.nmap.scripts = "default,safe"
            p.nmap.version_intensity = 5
            p.nuclei.severities = ["medium", "high", "critical"]
            p.nuclei.rate_limit = 30
            p.max_lead_depth = 2
        elif name == "thorough":
            p.nmap.tcp_ports = "1-65535"
            p.nmap.version_intensity = 9
            p.nmap.host_timeout = "90m"
            p.nmap.timeout_sec = 21600
            p.nuclei.rate_limit = 80
            p.nuclei.timeout_sec = 10800
            p.max_lead_depth = 4
        elif name != "standard":
            raise ValueError(f"unknown profile {name!r} (quick|standard|thorough)")
        return p

    @classmethod
    def load(cls, path: str | Path | None, profile: str = "standard") -> "Policy":
        """Start from a profile, then overlay any JSON file given."""
        p = cls.for_profile(profile)
        if not path:
            return p
        data = json.loads(Path(path).read_text())
        if "profile" in data and data["profile"] != profile:
            p = cls.for_profile(str(data["profile"]))
        for section, cls_ in (("nmap", NmapPolicy), ("nuclei", NucleiPolicy),
                              ("http", HttpPolicy), ("snmp", SnmpPolicy)):
            if section in data:
                current = asdict(getattr(p, section))
                unknown = set(data[section]) - set(current)
                if unknown:
                    raise ValueError(f"unknown {section} policy key(s): {sorted(unknown)}")
                current.update(data[section])
                setattr(p, section, cls_(**current))
        for key in ("max_lead_depth", "max_leads_per_run", "stop_on_tool_error"):
            if key in data:
                setattr(p, key, data[key])
        return p

    def to_dict(self) -> dict:
        return asdict(self)
