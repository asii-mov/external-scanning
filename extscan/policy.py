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


SEVERITIES = ("info", "low", "medium", "high", "critical")

# nmap flags a policy may add through `nmap.extra_args`. It is a list of what
# is allowed, not of what is banned, because the flags that matter here are
# the ones that choose targets (-iL, -iR, a bare address), spoof or bounce
# (-S, -D, -sI, -b, --proxies), pick scripts past `exclude_scripts`
# (--script), drop the scope's exclusions (--exclude) or move the output the
# parser reads (-oA). Each of those would let a policy file send packets the
# scope file never authorised. Targets come from the scope file only.
NMAP_EXTRA_FLAGS = frozenset({
    "-n", "-R", "-v", "-vv", "-d", "-6", "-r", "--reason", "--traceroute",
    "--version-light", "--version-all", "--defeat-rst-ratelimit",
    "--defeat-icmp-ratelimit", "--unprivileged", "--privileged",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
})
NMAP_EXTRA_VALUE_FLAGS = frozenset({
    "--max-rate", "--min-rate", "--max-parallelism", "--min-parallelism",
    "--scan-delay", "--max-scan-delay", "--min-rtt-timeout", "--max-rtt-timeout",
    "--initial-rtt-timeout", "--max-hostgroup", "--min-hostgroup", "--ttl",
    "--data-length", "--source-port", "-g", "--script-timeout", "--max-os-tries",
    "--stats-every",
})
_NMAP_VALUE_RE = re.compile(r"\d+(\.\d+)?(ms|s|m|h)?")

# nuclei flags `nuclei.extra_args` may not carry: ones that add targets, send
# traffic or results somewhere else, run code, follow redirects, or bring
# excluded templates back.
NUCLEI_FORBIDDEN_FLAGS = frozenset({
    "u", "target", "l", "list", "resume", "eh", "exclude-hosts",
    "proxy", "p", "interactsh-server", "iserver", "interactions-cache-size",
    "cloud-upload", "cup", "dashboard", "pd", "pdu", "dashboard-upload", "auth",
    "code", "headless", "dast", "fuzz", "fuzzing-type", "fuzzing-mode",
    "fr", "follow-redirects", "fhr", "follow-host-redirects",
    "itags", "include-tags", "it", "include-templates",
    "o", "output", "j", "jsonl", "je", "json-export", "jle", "jsonl-export",
    "lfa", "allow-local-file-access", "sni", "i", "interface", "sip", "source-ip",
    "resolvers", "r", "sr", "system-resolvers",
})


def check_nmap_extra_args(args: list[str]) -> None:
    """Raise ValueError unless every entry is an allowed tuning flag."""
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("nmap.extra_args must be a list of strings")
    expect_value = ""
    for arg in args:
        if expect_value:
            if not _NMAP_VALUE_RE.fullmatch(arg):
                raise ValueError(f"nmap.extra_args: {expect_value} takes a number or a "
                                 f"time such as 100 or 500ms, not {arg!r}")
            expect_value = ""
            continue
        flag, sep, value = arg.partition("=")
        if flag in NMAP_EXTRA_VALUE_FLAGS:
            if sep and not _NMAP_VALUE_RE.fullmatch(value):
                raise ValueError(f"nmap.extra_args: {flag} takes a number or a time, "
                                 f"not {value!r}")
            expect_value = "" if sep else flag
            continue
        if arg in NMAP_EXTRA_FLAGS:
            continue
        raise ValueError(
            f"nmap.extra_args: {arg!r} is not allowed. Extra arguments may only tune "
            "timing and verbosity; targets come from the scope file, and scripts, "
            "ports and output from their own policy settings. Allowed: "
            + ", ".join(sorted(NMAP_EXTRA_FLAGS | NMAP_EXTRA_VALUE_FLAGS)))
    if expect_value:
        raise ValueError(f"nmap.extra_args: {expect_value} is missing its value")


def check_nuclei_extra_args(args: list[str]) -> None:
    """Raise ValueError if an entry would add targets or send data elsewhere."""
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("nuclei.extra_args must be a list of strings")
    for arg in args:
        if not arg.startswith("-"):
            continue
        name = arg.lstrip("-").partition("=")[0]
        if name in NUCLEI_FORBIDDEN_FLAGS:
            raise ValueError(
                f"nuclei.extra_args: {arg!r} is not allowed. It would add targets, "
                "follow redirects, bring back excluded templates, or send traffic or "
                "results somewhere the scope file does not cover. Use the matching "
                "policy setting if there is one (nuclei.follow_redirects, "
                "nuclei.interactsh, nuclei.templates).")


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
    # nuclei follows a redirect wherever it points, so a target that answers
    # 302 to another organisation's host gets that host requested from the
    # scanning box. Off by default: a redirect is judged by its status and
    # Location header and never followed. Turning it on trades that guarantee
    # for the templates that only match after a redirect.
    follow_redirects: bool = False


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
    provider: str = "none"          # anthropic | bedrock | azure
    model: str = ""
    effort: str = "medium"
    # Thinking counts against this on current models, so a small value cuts
    # the reply off before the answer. A cut-off reply is reported as such.
    max_tokens: int = 8000
    timeout_sec: int = 120

    aws_region: str = ""
    aws_profile: str = ""
    base_url: str = ""
    # Azure (Claude in Microsoft Foundry). The resource is the name in
    # https://<resource>.services.ai.azure.com; `base_url` replaces it for a
    # private endpoint. `model` is the deployment name. Credentials never go
    # in a policy file, which is copied into every run: the key is read from
    # ANTHROPIC_FOUNDRY_API_KEY, and "entra" uses the Azure credential chain.
    azure_resource: str = ""
    azure_auth: str = "auto"        # auto | api_key | entra

    max_input_chars: int = 40_000

    sdk_retries: int = 0
    retry_attempts: int = 3
    retry_base_delay: float = 2.0
    retry_budget_sec: int = 90
    circuit_failure_threshold: int = 3
    circuit_cooldown_sec: int = 120

    analyse_openapi: bool = True
    # The analyse stage asks the model for a note on each finding at or above
    # this severity ("off" asks for none), up to `max_findings` per run. What
    # the cap leaves out is recorded as a coverage gap.
    analyse_findings_above: str = "medium"
    max_findings: int = 40


@dataclass
class ReportPolicy:
    """How report.md is laid out.

    `template` is the path of a Markdown template; "" uses the one shipped
    in `extscan/templates/report.md`. See docs/REPORT_TEMPLATE.md.
    """

    template: str = ""


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
    report: ReportPolicy = field(default_factory=ReportPolicy)
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
        try:
            data = json.loads(Path(path).read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(f"policy file {path} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"policy file {path} must hold a JSON object")
        return cls.from_dict(data, profile)

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
                              ("llm", LLMPolicy), ("report", ReportPolicy)):
            if section in data:
                if not isinstance(data[section], dict):
                    raise ValueError(f"policy section {section!r} must be an object")
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
        p.validate()
        return p

    def validate(self) -> None:
        """Refuse settings that would let a policy file widen what is
        scanned, or that cannot mean what they say."""
        check_nmap_extra_args(self.nmap.extra_args)
        check_nuclei_extra_args(self.nuclei.extra_args)
        # Two settings exist in saved runs and have never done anything.
        # Turning one on is refused, because a setting that is accepted and
        # ignored reads as if it were in force.
        if self.stop_on_tool_error:
            raise ValueError(
                "stop_on_tool_error is not implemented: a failed tool is recorded as "
                "a coverage gap and the run carries on. Leave it false, and use the "
                "exit code of `extscan run` (3 on a serious gap) to stop a pipeline.")
        if self.recon.allow_bruteforce:
            raise ValueError(
                "recon.allow_bruteforce is not implemented: recon uses passive "
                "sources only. Leave it false.")
        if int(self.nmap.chunk_size) < 1:
            raise ValueError(f"nmap.chunk_size is {self.nmap.chunk_size!r}: use 1 or more")
        if self.llm.analyse_findings_above not in ("off", *SEVERITIES):
            raise ValueError(
                f"llm.analyse_findings_above is {self.llm.analyse_findings_above!r}: "
                f"use one of off, {', '.join(SEVERITIES)}")
        if self.llm.azure_auth not in ("auto", "api_key", "entra"):
            raise ValueError(f"llm.azure_auth is {self.llm.azure_auth!r}: "
                             "use auto, api_key or entra")

    def to_dict(self) -> dict:
        return asdict(self)
