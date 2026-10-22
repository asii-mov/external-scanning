"""Scan policy: how hard to push, and what is off the table entirely.

Defaults are deliberately read-only and non-disruptive. An external audit's
job is to tell the client what is exposed, not to knock it over, so the
intrusive/DoS/fuzzing families stay excluded unless someone edits a policy
file on purpose and the engagement covers it.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

TCP_TOP = "1-1024,1080,1194,1433,1521,2049,2082,2083,2375,2376,2483,2484,3000,3128,3268,3306,3389,4443,4444,4786,5000,5432,5555,5601,5672,5900,5984,5985,5986,6379,6443,7001,7002,8000,8008,8009,8080,8081,8088,8089,8161,8200,8443,8500,8834,8888,9000,9042,9090,9092,9200,9300,9443,10000,11211,15672,27017,27018,50000"

UDP_TOP = "53,67,69,123,137,138,161,162,500,514,520,623,1434,1604,1900,3391,4500,5353,11211"


@dataclass
class NmapPolicy:
    tcp_ports: str = TCP_TOP
    udp_ports: str = UDP_TOP
    timing: str = "-T4"
    version_intensity: int = 7
    host_timeout: str = "30m"
    max_retries: int = 2
    min_rate: int = 0
    scripts: str = "default,safe,vuln"
    # NSE categories or script names never run, whatever `scripts` selects.
    # dos: smb-vuln-ms10-054 and friends sit in `vuln` and can crash hosts.
    # external: vulners, dns-blacklist, whois-ip and others send target data
    # to third-party services. http-slowloris-check is `vuln,safe` but holds
    # connections open for minutes, a soft DoS against fragile servers.
    exclude_scripts: list[str] = field(default_factory=lambda: [
        "dos", "external", "http-slowloris-check"])
    skip_host_discovery: bool = False
    do_udp: bool = True
    extra_args: list[str] = field(default_factory=list)
    timeout_sec: int = 7200
    chunk_size: int = 32


@dataclass
class NucleiPolicy:
    severities: list[str] = field(default_factory=lambda: ["info", "low", "medium", "high", "critical"])
    exclude_tags: list[str] = field(default_factory=lambda: ["dos", "intrusive", "fuzz", "brute-force"])
    include_tags: list[str] = field(default_factory=list)
    rate_limit: int = 50
    concurrency: int = 15
    retries: int = 1
    request_timeout: int = 10
    templates: list[str] = field(default_factory=list)
    extra_args: list[str] = field(default_factory=list)
    timeout_sec: int = 3600
    allow_intrusive: bool = False
    interactsh: bool = False
    interactsh_server: str = ""


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
    max_redirects: int = 3
    max_body_bytes: int = 2_000_000
    user_agent: str = "extscan/0.1 (authorised security assessment)"
    verify_tls: bool = False
    path_checks: bool = True
    paths: list[str] = field(default_factory=lambda: list(DISCLOSURE_PATHS))
    inter_request_delay: float = 0.0
    use_system_proxy: bool = False


@dataclass
class SnmpPolicy:
    communities: list[str] = field(default_factory=lambda: [
        "public", "private", "community", "manager", "admin", "cisco",
        "default", "read", "write", "snmp", "monitor",
    ])
    timeout_sec: float = 2.0
    retries: int = 1
    versions: list[int] = field(default_factory=lambda: [1, 2])
    walk_on_hit: bool = True


@dataclass
class ReconPolicy:
    """Subdomain enumeration settings."""

    sources: list[str] = field(default_factory=lambda: ["crt.sh", "subfinder"])
    resolve_timeout: float = 5.0
    max_names: int = 2000
    allow_bruteforce: bool = False


@dataclass
class LLMPolicy:
    """Model-assisted analysis settings.

    Disabled by default, deliberately. A scanner should not start sending a
    client's response bodies to a third-party API because a config file was
    copied from somewhere -- turning this on is a decision with contractual
    implications, so it has to be made explicitly.
    """

    enabled: bool = False
    provider: str = "none"
    model: str = ""
    effort: str = "medium"
    max_tokens: int = 1500
    timeout_sec: int = 60

    aws_region: str = ""
    aws_profile: str = ""
    base_url: str = ""

    max_input_chars: int = 40_000

    sdk_retries: int = 0
    retry_attempts: int = 3
    retry_base_delay: float = 2.0
    retry_budget_sec: int = 90
    circuit_failure_threshold: int = 3
    circuit_cooldown_sec: int = 120

    analyse_openapi: bool = True
    analyse_findings_above: str = "medium"


@dataclass
class Policy:
    profile: str = "standard"
    nmap: NmapPolicy = field(default_factory=NmapPolicy)
    nuclei: NucleiPolicy = field(default_factory=NucleiPolicy)
    http: HttpPolicy = field(default_factory=HttpPolicy)
    snmp: SnmpPolicy = field(default_factory=SnmpPolicy)
    recon: ReconPolicy = field(default_factory=ReconPolicy)
    llm: LLMPolicy = field(default_factory=LLMPolicy)
    max_lead_depth: int = 3
    max_leads_per_run: int = 500
    stop_on_tool_error: bool = False
    max_lead_attempts: int = 3
    max_workers: int = 8

    @classmethod
    def for_profile(cls, name: str) -> Policy:
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
    def load(cls, path: str | Path | None, profile: str = "standard") -> Policy:
        """Start from a profile, then overlay any JSON file given."""
        if not path:
            return cls.for_profile(profile)
        return cls.from_dict(json.loads(Path(path).read_text()), profile)

    @classmethod
    def from_dict(cls, data: dict, profile: str = "standard") -> Policy:
        """Start from a profile, then overlay a policy mapping."""
        p = cls.for_profile(profile)
        if "profile" in data and data["profile"] != profile:
            p = cls.for_profile(str(data["profile"]))
        for section, cls_ in (("nmap", NmapPolicy), ("nuclei", NucleiPolicy),
                              ("http", HttpPolicy), ("snmp", SnmpPolicy),
                              ("recon", ReconPolicy), ("llm", LLMPolicy)):
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
