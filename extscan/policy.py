"""Scan policy: how hard to push, and what is off the table entirely.

Defaults are deliberately read-only and non-disruptive. An external audit's
job is to tell the client what is exposed, not to knock it over, so the
intrusive/DoS/fuzzing families stay excluded unless someone edits a policy
file on purpose and the engagement covers it.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

TCP_TOP = "1-1024,1080,1194,1433,1521,2049,2082,2083,2375,2376,2483,2484,3000,3128,3268,3306,3389,4443,4444,4786,5000,5432,5555,5601,5672,5900,5984,5985,5986,6379,6443,7001,7002,8000,8008,8009,8080,8081,8088,8089,8161,8200,8443,8500,8834,8888,9000,9042,9090,9092,9200,9300,9443,10000,11211,15672,27017,27018,50000"

TCP_QUICK = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017"

# Named choices for `--tcp-ports`. Anything else must be an nmap port spec.
TCP_PORT_PRESETS = {"quick": TCP_QUICK, "top": TCP_TOP, "all": "1-65535"}

UDP_TOP = "53,67,69,123,137,138,161,162,500,514,520,623,1434,1604,1900,3391,4500,5353,11211"


def tcp_port_spec(choice: str) -> str:
    """Resolve a preset name, or check a literal nmap spec such as `22,80,8000-8100`."""
    if choice in TCP_PORT_PRESETS:
        return TCP_PORT_PRESETS[choice]
    if not re.fullmatch(r"\d+(-\d+)?(,\d+(-\d+)?)*", choice):
        raise ValueError(f"{choice!r}: use {'|'.join(TCP_PORT_PRESETS)} "
                         "or a port list such as 22,80,8000-8100")
    return choice


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
    # Host-discovery probes, as nmap flags. nmap's own default is far
    # narrower (unprivileged: a connect to 80 and 443 only), so a host that
    # drops ping and listens elsewhere would be treated as absent. Root sends
    # all of these; an unprivileged run sends only the -PS ones, because the
    # others need raw sockets. `skip_host_discovery` (-Pn) overrides the list.
    discovery_probes: list[str] = field(default_factory=lambda: [
        "-PE", "-PP",
        "-PS21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,"
        "5432,5900,8000,8080,8443",
        "-PA80,443", "-PU53,161"])
    # Two-phase TCP discovery: sweep the scope for open ports (no version
    # detection, no scripts) in batches of `sweep_chunk_size`, then run the
    # full scan only on hosts that had an open port. "auto" uses it when the
    # scope has more hosts than `chunk_size`; "always" and "never" force it.
    sweep: str = "auto"
    sweep_chunk_size: int = 256
    # How many nmap batches run at once (sweep, fingerprint and UDP batches
    # alike). 1 is one after another. More finishes a large range sooner and
    # multiplies the traffic the client's network sees at any moment by the
    # same factor, so it stays 1 unless the engagement allows more.
    parallel: int = 1


@dataclass
class NucleiPolicy:
    # Web services per nuclei invocation. Each batch is checkpointed, so a
    # timeout costs one batch and a re-run does only what is left.
    batch_size: int = 25
    severities: list[str] = field(default_factory=lambda: ["info", "low", "medium", "high", "critical"])
    exclude_tags: list[str] = field(default_factory=lambda: [
        "dos", "intrusive", "fuzz", "brute-force",
        "default-login", "default-logins", "creds-stuffing"])
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
    # Names tried per web service by the virtual-host check (certificate SANs
    # and recorded hostnames). 0 turns the check off.
    max_vhosts: int = 25


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
class SslscanPolicy:
    timeout_sec: int = 300


@dataclass
class ScreenshotPolicy:
    """Browser captures of web services for the report vault.

    Needs the optional `screenshots` extra (Playwright and its Chromium). A
    missing browser is a coverage gap, never a failed run.
    """

    enabled: bool = True
    timeout_sec: int = 20
    max_pages: int = 60
    width: int = 1280
    height: int = 800


@dataclass
class ReconPolicy:
    """Subdomain enumeration settings."""

    sources: list[str] = field(default_factory=lambda: ["crt.sh", "subfinder"])
    resolve_timeout: float = 5.0
    max_names: int = 2000
    allow_bruteforce: bool = False


@dataclass
class DnsPolicy:
    """DNS checks (zone transfer, NSEC walking, dangling records) run inside
    recon for every scope.domains entry, and on in-scope hosts' names at the
    end of discover."""

    resolvers: list[str] = field(default_factory=list)  # "ip" or "ip:port"; [] = resolv.conf
    port: int = 53                      # authoritative servers' port
    timeout_sec: float = 3.0
    retries: int = 1
    query_interval_sec: float = 0.02
    skip: list[str] = field(default_factory=list)   # axfr, nsec-walk, takeover, host-names
    max_names: int = 2000
    max_walk_steps: int = 5000
    max_axfr_records: int = 200_000
    subzones: bool = False              # also transfer and walk delegated sub-zones
    max_subzones: int = 20


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

# Published edge ranges with stable machine-readable URLs. Azure (a dated
# weekly file) and Akamai (nothing published) have none, so they are absent;
# a provider added here by hand is parsed as "every CIDR in the document".
EDGE_RANGE_URLS = {
    "cloudflare": ["https://www.cloudflare.com/ips-v4/", "https://www.cloudflare.com/ips-v6/"],
    "cloudfront": ["https://ip-ranges.amazonaws.com/ip-ranges.json"],
    "fastly": ["https://api.fastly.com/public-ip-list"],
    "google": ["https://www.gstatic.com/ipranges/goog.json"],
    "google-cloud": ["https://www.gstatic.com/ipranges/cloud.json"],
}


@dataclass
class EnrichPolicy:
    """Public feeds fetched by the enrich stage: CISA KEV, EPSS, CDN ranges.

    Nothing about the client is sent, the requests are plain downloads. They
    are still egress from the scanning box, so the stage can be turned off,
    and the downloads are cached and shared between runs.
    """

    enabled: bool = True
    kev_url: str = KEV_URL
    epss_url: str = EPSS_URL
    tag_networks: bool = True
    range_urls: dict[str, list[str]] = field(
        default_factory=lambda: {k: list(v) for k, v in EDGE_RANGE_URLS.items()})
    timeout_sec: int = 30
    # "" puts the cache next to the run directories (<runs-dir>/.feed-cache),
    # so every run of an engagement shares one download a day.
    cache_dir: str = ""
    cache_max_age_hours: float = 24.0


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
    sslscan: SslscanPolicy = field(default_factory=SslscanPolicy)
    recon: ReconPolicy = field(default_factory=ReconPolicy)
    screenshots: ScreenshotPolicy = field(default_factory=ScreenshotPolicy)
    dns: DnsPolicy = field(default_factory=DnsPolicy)
    enrich: EnrichPolicy = field(default_factory=EnrichPolicy)
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
            p.nmap.tcp_ports = TCP_QUICK
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
                              ("sslscan", SslscanPolicy),
                              ("recon", ReconPolicy), ("screenshots", ScreenshotPolicy),
                              ("dns", DnsPolicy), ("enrich", EnrichPolicy),
                              ("llm", LLMPolicy)):
            if section in data:
                current = asdict(getattr(p, section))
                unknown = set(data[section]) - set(current)
                if unknown:
                    raise ValueError(f"unknown {section} policy key(s): {sorted(unknown)}")
                current.update(data[section])
                setattr(p, section, cls_(**current))
        unknown = set(data) - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError(f"unknown policy key(s): {sorted(unknown)}")
        for key in ("max_lead_depth", "max_leads_per_run", "stop_on_tool_error",
                    "max_lead_attempts", "max_workers"):
            if key in data:
                setattr(p, key, data[key])
        return p

    def to_dict(self) -> dict:
        return asdict(self)
