"""testssl.sh adapter: extscan's primary TLS audit.

testssl.sh (https://github.com/testssl/testssl.sh, GPL-2.0) is run as an
external program and its flat JSON output is parsed here. No testssl.sh code
or data is copied into extscan.

Why it is primary: beyond protocols and ciphers (which sslscan also covers) it
runs the named vulnerability checks -- Heartbleed, CCS injection, Ticketbleed,
ROBOT, renegotiation, CRIME, BREACH, POODLE, TLS_FALLBACK_SCSV, SWEET32, FREAK,
DROWN, LOGJAM, BEAST, LUCKY13, Winshock, RC4 -- checks the certificate, gives
an SSL Labs-style grade, and speaks STARTTLS for mail, directory and database
protocols. sslscan stays as the fallback when testssl.sh is not installed.

What is kept off, and why (see also TESTSSL_EXCLUDED_ARGS in policy.py):

* `--phone-out`: CRL downloads and OCSP queries go to the certificate issuer,
  a third party. The environment variable PHONE_OUT does the same, so the
  child runs with a minimal environment and PHONE_OUT pinned to false.
* `-g/--grease` and `-9/--full`: deliberately malformed and oversized
  ClientHellos that fragile TLS stacks hang on. Not part of the default run.
* `--file`, `--mx`, `--ip`, `--proxy`: test or route through hosts other than
  the one scope-checked target.
* `--basicauth`, `--mtls`, `--reqheader`: credentials.

What stays on, knowingly: the default run's Heartbleed, CCS and Ticketbleed
checks read a little server memory (no more than needed to tell), ROBOT sends a
bounded set of oracle queries, and the client-initiated renegotiation check
renegotiates up to ten times on one connection over HTTP to see whether the
server limits it. testssl.sh's own docs call these IDS-visible
(`--ids-friendly` skips the first four), not disruptive. An operator who wants
them off can add `--ids-friendly` to `testssl.extra_args`; the skipped checks
are then reported as coverage gaps rather than passes.

HTTP header checks (HSTS, security headers, banners) are not turned into
findings here: the `http_fingerprint` probe already reports them.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field

from extscan.models import Finding, Service, severity_rank
from extscan.policy import Policy, excluded_testssl_args
from extscan.resilience import Degradation
from extscan.runner import Runner, ToolMissing, have
from extscan.scope import Scope

TOOL = "testssl.sh"

# Variables the child keeps from the operator's environment. Everything else
# is dropped: testssl.sh reads PHONE_OUT, FNAME (mass testing), BASICAUTH,
# SSL_NATIVE and dozens more from the environment, any of which would change
# what runs without appearing in the logged argv.
PASSTHROUGH_ENV = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM",
                   "TESTSSL_INSTALL_DIR")
PINNED_ENV = {"PHONE_OUT": "false"}

# The checks testssl.sh's default run (and `fast`) performs, in its order.
DEFAULT_RUN_FLAGS_FAST = ["-p", "-s", "-P", "-f", "-S", "-h", "-U"]

# --- which services get audited, and how -----------------------------------

# testssl.sh 3.2 `--starttls` protocols, keyed by nmap service name. IRC is
# not supported by testssl.sh ("FIXME: IRC+STARTTLS not yet supported").
STARTTLS_BY_NAME: dict[str, str] = {
    "ftp": "ftp", "smtp": "smtp", "submission": "smtp", "lmtp": "lmtp",
    "pop3": "pop3", "imap": "imap",
    "xmpp": "xmpp", "xmpp-client": "xmpp", "jabber": "xmpp",
    "xmpp-server": "xmpp-server",
    "ldap": "ldap", "nntp": "nntp", "sieve": "sieve", "managesieve": "sieve",
    "postgresql": "postgres", "postgres": "postgres", "mysql": "mysql",
    "telnet": "telnet",
}
# Port fallback, used only when nmap gave no usable name.
STARTTLS_BY_PORT: dict[int, str] = {
    21: "ftp", 23: "telnet", 24: "lmtp", 25: "smtp", 110: "pop3", 119: "nntp",
    143: "imap", 389: "ldap", 587: "smtp", 3306: "mysql", 4190: "sieve",
    5222: "xmpp", 5269: "xmpp-server", 5432: "postgres",
}
# Implicit-TLS service names nmap reports without a `tunnel="ssl"` (no -sV),
# and their ports for the same nameless fallback.
IMPLICIT_TLS_NAMES = {"smtps", "submissions", "imaps", "pop3s", "ldaps", "ftps",
                      "nntps", "ircs", "ircs-u", "xmpps", "xmpp-clients", "sips",
                      "telnets"}
IMPLICIT_TLS_PORTS = {465, 563, 636, 989, 990, 992, 993, 994, 995, 5061, 5223, 6697}
_GENERIC_NAMES = {"", "unknown", "tcpwrapped"}


def tls_mode(svc: Service) -> tuple[str, str] | None:
    """("tls", "") for implicit TLS, ("starttls", proto) for STARTTLS, else None.

    The nmap service name decides; the port is a fallback for nameless
    services, so a web app on 25 is not treated as SMTP.
    """
    if svc.proto != "tcp":
        return None
    name = svc.name.lower().rstrip("?")
    if svc.is_tls or name in IMPLICIT_TLS_NAMES:
        return ("tls", "")
    if name in STARTTLS_BY_NAME:
        return ("starttls", STARTTLS_BY_NAME[name])
    if name in _GENERIC_NAMES:
        if svc.port in IMPLICIT_TLS_PORTS:
            return ("tls", "")
        if svc.port in STARTTLS_BY_PORT:
            return ("starttls", STARTTLS_BY_PORT[svc.port])
    return None


def matches(svc: Service) -> bool:
    return tls_mode(svc) is not None


# --- command line -----------------------------------------------------------

def _uri(host: str, port: int) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"


def argv(policy: Policy, host: str, port: int, json_out: str,
         starttls: str = "") -> list[str]:
    """Build the testssl.sh command. The in-scope URI is always last."""
    p = policy.testssl
    bad = excluded_testssl_args(p.extra_args)
    if bad:
        raise ValueError(f"testssl extra_args not allowed: {', '.join(bad)}")
    cmd = [
        TOOL,
        "--quiet",                 # no banner; also accepts the usage terms
        "--warnings", "batch",     # never wait for a keypress; stop the scan instead
        "--color", "0",            # plain stdout for the audit trail
        "--jsonfile", json_out,    # flat JSON: one record per check
        "--connect-timeout", str(p.connect_timeout_sec),
        "--openssl-timeout", str(p.openssl_timeout_sec),
        "--user-agent", policy.http.user_agent,
    ]
    # Forward lookups only: no PTR or CAA queries. XMPP needs a domain, which
    # testssl.sh takes from the PTR record when given an address.
    if starttls not in ("xmpp", "xmpp-server"):
        cmd += ["--nodns", "min"]
    if p.fast:
        # The default run minus client simulation, which is informational.
        cmd += DEFAULT_RUN_FLAGS_FAST
    if starttls:
        cmd += ["--starttls", starttls]
    cmd += [str(a) for a in p.extra_args]
    cmd.append(_uri(host, port))
    return cmd


def child_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in PASSTHROUGH_ENV if k in os.environ}
    env.update(PINNED_ENV)
    return env


# --- parsing ----------------------------------------------------------------

SEVERITY = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}
_GAP_SEVERITIES = {"WARN", "DEBUG"}
# Run-level notices, not a check that failed. cmdline_ip-target says trust
# results may be wrong for an address target; it is kept as evidence.
_NOTICE_IDS = {"engine_problem", "cmdline_ip-target", "scanTime", "scanProblem"}
_TEST_FAILED = re.compile(r"(?i)\btest(?:ing)? failed\b|\bcould not (?:be )?test")

PROTOCOL_LABELS = {"SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLS1": "TLS 1.0",
                   "TLS1_1": "TLS 1.1", "TLS1_2": "TLS 1.2", "TLS1_3": "TLS 1.3"}

# testssl.sh grades for public web sites. Where extscan rates the same issue
# elsewhere (its TLS probe, sslscan), keep one scale across the report.
# (id pattern, finding pattern, extscan severity or None to drop)
SEVERITY_OVERRIDES: list[tuple[str, str, str | None]] = [
    # extscan's TLS probe and sslscan rate TLS 1.0/1.1 medium (fails PCI DSS).
    (r"^TLS1(_1)?$", r"^offered", "medium"),
    # sslscan rates anonymous key exchange high (NULL and export stay critical).
    (r"^cipherlist_aNULL$", r"", "high"),
    (r"^cipher-", r"\banon\b|\bA(?:EC)?DH-", "high"),
    # Self-signed is low and for review elsewhere in extscan; testssl.sh says
    # critical because a browser would refuse it.
    (r"^cert_chain_of_trust", r"self.signed", "low"),
    (r"^cert_chain_of_trust", r"", "medium"),
    (r"^cert_expirationStatus", r"expired", "medium"),
    (r"^cert_expirationStatus", r"expires", "low"),
    # cert_notAfter repeats cert_expirationStatus's verdict.
    (r"^cert_notAfter", r"", None),
    (r"^cert_revocation", r"Neither CRL nor OCSP", "low"),
    # Scanning by address, the name check fails against almost every
    # certificate (cmdline_ip-target warns of exactly this).
    (r"^cert_trust", r"does not match", "low"),
]


@dataclass(frozen=True)
class VulnCheck:
    key: str           # testssl.sh JSON id (sub-results start with key + "_" or "-")
    label: str
    why: str
    fix: str
    applies: str = "all"   # all | http | starttls-mail


VULN_CHECKS: list[VulnCheck] = [
    VulnCheck("heartbleed", "Heartbleed (CVE-2014-0160)",
              "The heartbeat extension leaks process memory, including private keys "
              "and session data, to an unauthenticated client.",
              "Patch OpenSSL, then rotate the private key and every credential that "
              "transited the service."),
    VulnCheck("CCS", "OpenSSL CCS injection (CVE-2014-0224)",
              "A machine-in-the-middle can force weak keying material.",
              "Upgrade OpenSSL."),
    VulnCheck("ticketbleed", "Ticketbleed (CVE-2016-9244)",
              "F5 BIG-IP session ticket handling leaks up to 31 bytes of memory.",
              "Apply the F5 fix or disable session tickets on the virtual server.",
              applies="http"),
    VulnCheck("ROBOT", "ROBOT (Bleichenbacher oracle)",
              "An RSA padding oracle lets an attacker decrypt recorded sessions or "
              "sign with the server key.",
              "Patch the TLS stack and disable RSA key-transport cipher suites."),
    VulnCheck("secure_renego", "Secure renegotiation (RFC 5746) not supported",
              "Without RFC 5746, renegotiation allows plaintext injection "
              "(CVE-2009-3555).",
              "Enable secure renegotiation or disable renegotiation."),
    VulnCheck("secure_client_renego", "Client-initiated renegotiation allowed "
              "(CVE-2011-1473)",
              "Each renegotiation costs the server far more CPU than the client, "
              "which makes cheap denial of service possible.",
              "Disable client-initiated renegotiation."),
    VulnCheck("CRIME_TLS", "CRIME: TLS compression (CVE-2012-4929)",
              "TLS-level compression leaks secrets such as session cookies.",
              "Disable TLS compression."),
    VulnCheck("BREACH", "BREACH: HTTP compression over TLS (CVE-2013-3587)",
              "Compressed HTTPS responses can leak secrets reflected in the page.",
              "Disable HTTP compression for responses carrying secrets, or apply "
              "BREACH mitigations (token masking, length padding).",
              applies="http"),
    VulnCheck("POODLE_SSL", "POODLE (CVE-2014-3566)",
              "SSLv3 with CBC ciphers lets an attacker decrypt traffic byte by byte.",
              "Disable SSLv3."),
    VulnCheck("fallback_SCSV", "TLS_FALLBACK_SCSV not supported",
              "Without downgrade protection, an attacker can push clients to an "
              "older protocol version.",
              "Support TLS_FALLBACK_SCSV, or offer only TLS 1.2 and later."),
    VulnCheck("SWEET32", "SWEET32: 64-bit block ciphers (CVE-2016-2183)",
              "3DES, IDEA and RC2 are open to birthday attacks on long sessions.",
              "Disable 64-bit block ciphers."),
    VulnCheck("FREAK", "FREAK: export RSA (CVE-2015-0204)",
              "Export-grade RSA can be forced and factored.",
              "Disable export cipher suites."),
    VulnCheck("DROWN", "DROWN: SSLv2 (CVE-2016-0800)",
              "SSLv2 on any server sharing this key lets an attacker decrypt TLS "
              "sessions.",
              "Disable SSLv2 everywhere this certificate's key is used."),
    VulnCheck("LOGJAM", "LOGJAM / weak Diffie-Hellman (CVE-2015-4000)",
              "Export or weak (common or 1024-bit) DH groups can be broken or "
              "downgraded.",
              "Disable DHE-EXPORT and use 2048-bit or larger unique DH groups, "
              "or ECDHE only."),
    VulnCheck("BEAST", "BEAST: CBC in SSLv3/TLS 1.0 (CVE-2011-3389)",
              "CBC ciphers in TLS 1.0 and earlier are open to a chosen-plaintext "
              "attack; modern clients mitigate it.",
              "Disable TLS 1.0 and earlier."),
    VulnCheck("LUCKY13", "LUCKY13: CBC timing (CVE-2013-0169)",
              "CBC cipher suites can leak plaintext through padding timing.",
              "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)."),
    VulnCheck("winshock", "Winshock (MS14-066, CVE-2014-6321)",
              "A Schannel flaw allows remote code execution on unpatched Windows.",
              "Apply MS14-066."),
    VulnCheck("RC4", "RC4 cipher suites (CVE-2013-2566)",
              "RC4 is broken and prohibited by RFC 7465.",
              "Disable RC4."),
    VulnCheck("starttls_injection", "STARTTLS command injection (CVE-2011-0411)",
              "Commands sent before the TLS handshake are processed after it, so a "
              "machine-in-the-middle can inject them.",
              "Discard buffered plaintext when STARTTLS completes (patch the server).",
              applies="starttls-mail"),
]

NAMED_CHECKS = [v.key for v in VULN_CHECKS]


@dataclass
class Record:
    id: str
    severity: str
    finding: str
    cve: str = ""
    ip: str = ""
    port: str = ""


@dataclass
class Audit:
    findings: list[Finding] = field(default_factory=list)
    gaps: list[tuple[str, str]] = field(default_factory=list)   # (check, why)
    grade: str = ""


class ScanFailed(RuntimeError):
    """testssl.sh ran but did not audit the service; a coverage gap."""


class TestsslMissing(ToolMissing):
    __test__ = False

    def __init__(self, starttls: str = ""):
        super().__init__(TOOL)
        if starttls:
            self.args = (f"testssl.sh not installed, so TLS on this STARTTLS "
                         f"({starttls}) service was not audited. See `extscan doctor`.",)
        else:
            self.args = ("testssl.sh not installed, so Heartbleed, ROBOT, DROWN and the "
                         "other named TLS vulnerability checks did not run; sslscan, "
                         "if installed, covered protocols and ciphers only. See "
                         "`extscan doctor`.",)

    def __str__(self) -> str:
        return self.args[0]


def load_records(text: str) -> list[Record]:
    """Parse testssl.sh flat JSON (`--jsonfile`) into records."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse testssl.sh JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("testssl.sh JSON is not a list of findings")
    out = []
    for r in data:
        if not isinstance(r, dict) or not isinstance(r.get("id"), str):
            continue
        out.append(Record(id=r["id"], severity=str(r.get("severity", "")).upper(),
                          finding=str(r.get("finding", "")), cve=str(r.get("cve", "")),
                          ip=str(r.get("ip", "")), port=str(r.get("port", ""))))
    return out


def _severity(rec: Record) -> str | None:
    """extscan severity for an issue record, or None when it is not an issue."""
    sev = SEVERITY.get(rec.severity)
    if sev is None:
        return None
    for id_pat, text_pat, override in SEVERITY_OVERRIDES:
        if re.search(id_pat, rec.id) and re.search(text_pat, rec.finding, re.I):
            return override
    return sev


def _worst(sevs) -> str:
    return max(sevs, key=severity_rank)


def _belongs(rec_id: str, key: str) -> bool:
    return rec_id == key or rec_id.startswith((key + "_", key + "-"))


def _line(rec: Record) -> str:
    return f"{rec.id}: {rec.severity} {rec.finding}".strip()[:300]


def _cve_refs(recs: list[Record]) -> list[str]:
    cves = sorted({c for r in recs for c in r.cve.split() if c.startswith("CVE-")})
    return [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:8]]


def _expected(check: VulnCheck, service: str, starttls: str) -> bool:
    if check.applies == "http":
        return not starttls and service.upper() == "HTTP"
    if check.applies == "starttls-mail":
        return starttls in ("smtp", "imap", "pop3")
    return True


def parse(records: list[Record], host: str, port: int, starttls: str = "",
          scope: Scope | None = None) -> Audit:
    """Turn one service's testssl.sh records into findings and check gaps.

    Raises ScanFailed when testssl.sh did not audit the service at all. A
    STARTTLS service that does not offer TLS is a finding, not a failure.
    """
    target = f"{host}:{port}"
    records = [r for r in records if _in_scope(r, scope)]
    fatal = [r for r in records if r.id == "scanProblem" and r.severity == "FATAL"]
    not_tls = [r for r in records if r.id == "optimal_proto"
               and "doesn't seem to be a TLS/SSL enabled server" in r.finding]

    if starttls and (not_tls or any("No STARTTLS found" in r.finding for r in fatal)):
        reason = (not_tls or fatal)[0].finding
        return Audit(findings=[_no_starttls_finding(host, port, starttls, reason)])
    if fatal:
        raise ScanFailed(f"testssl.sh could not audit {target}: {fatal[0].finding}"[:280])
    if not_tls:
        raise ScanFailed(f"testssl.sh found no TLS on {target}, though discovery "
                         "reported a TLS service")
    if any(r.id == "scanTime" and "interrupted" in r.finding.lower() for r in records):
        raise ScanFailed(f"testssl.sh scan of {target} was interrupted")
    if not any(r.id in PROTOCOL_LABELS for r in records):
        raise ScanFailed(f"testssl.sh reported no protocol results for {target}")

    service = next((r.finding for r in records if r.id == "service"), "")
    audit = Audit()
    tags = ["tls", "testssl", *([f"starttls:{starttls}"] if starttls else [])]
    base = {"host": host, "port": port, "proto": "tcp", "source": "testssl.sh"}

    # Check gaps: WARN/DEBUG on any check, or a named check that never reported.
    for r in records:
        if r.id in _NOTICE_IDS:
            continue
        if r.severity in _GAP_SEVERITIES or _TEST_FAILED.search(r.finding):
            audit.gaps.append((r.id, r.finding[:160] or r.severity))
    seen = {r.id for r in records}
    for check in VULN_CHECKS:
        if _expected(check, service, starttls) and not any(
                _belongs(i, check.key) for i in seen):
            audit.gaps.append((check.key, "not reported by testssl.sh (skipped, "
                                          "e.g. by --ids-friendly, or not run)"))

    # Named vulnerabilities: one finding per check that is not clean.
    for check in VULN_CHECKS:
        recs = [r for r in records if _belongs(r.id, check.key)]
        issues = [(r, s) for r in recs if (s := _severity(r))]
        if not issues:
            continue
        headline = [s for r, s in issues if r.id == check.key]
        sev = _worst(headline) if headline else _worst(s for _r, s in issues)
        verdict = next((r.finding for r in recs if r.id == check.key), issues[0][0].finding)
        audit.findings.append(Finding(
            title=f"{check.label} on {target}",
            severity=sev, **base,
            description=f"{check.why} testssl.sh reports: {verdict[:300]}",
            evidence="\n".join(_line(r) for r in recs)[:3000],
            recommendation=check.fix,
            references=_cve_refs(recs),
            review_required=severity_rank(sev) >= severity_rank("high"),
            review_reason=("Confirm before reporting. Do not attempt to exploit it or "
                           "extract data.") if severity_rank(sev) >= severity_rank("high")
                          else "",
            tags=[*tags, "tls-vulnerability", check.key.lower()],
        ))

    # Protocol support.
    protocols = [r for r in records if r.id in PROTOCOL_LABELS]
    proto_issues = [(r, s) for r in protocols if (s := _severity(r))]
    if proto_issues:
        names = ", ".join(f"{PROTOCOL_LABELS[r.id]} {r.finding}" for r, _s in proto_issues)
        audit.findings.append(Finding(
            title=f"TLS protocol support issues on {target}: {names}"[:200],
            severity=_worst(s for _r, s in proto_issues), **base,
            description="Withdrawn protocol versions are accepted, or current ones are "
                        "missing. SSLv2/SSLv3 are broken; TLS 1.0/1.1 are deprecated "
                        "(RFC 8996) and fail PCI DSS.",
            evidence="\n".join(f"{PROTOCOL_LABELS[r.id]}: {r.finding}"
                               for r in protocols),
            recommendation="Offer TLS 1.2 and TLS 1.3 only.",
            references=["https://www.rfc-editor.org/rfc/rfc8996"],
            tags=[*tags, "deprecated-protocol"],
        ))

    # Cipher strength: one finding for the lot.
    cipher_issues = [(r, s) for r in records if _is_cipher(r.id) and (s := _severity(r))]
    if cipher_issues:
        lists = [(r, s) for r, s in cipher_issues if not r.id.startswith("cipher-")]
        suites = [(r, s) for r, s in cipher_issues if r.id.startswith("cipher-")]
        evidence = [_line(r) for r, _s in lists]
        evidence += [f"{s}: {' '.join(r.finding.split())}" for r, s in suites[:40]]
        worst = _worst(s for _r, s in cipher_issues)
        summary = ", ".join(_cipher_label(r.id) for r, s in lists
                            if s == worst) or "weak suites offered"
        audit.findings.append(Finding(
            title=f"Weak TLS cipher configuration on {target} ({summary})"[:200],
            severity=worst, **base,
            description="testssl.sh found cipher suites or key exchange settings below "
                        "current guidance. Anonymous, NULL and export suites remove "
                        "authentication or encryption outright; CBC, non-forward-secret "
                        "and legacy suites are weaker than the AEAD alternatives.",
            evidence="\n".join(evidence)[:3000],
            recommendation="Restrict the cipher list to AEAD suites with forward secrecy "
                           "(ECDHE with AES-GCM or ChaCha20-Poly1305).",
            tags=[*tags, "weak-cipher"],
        ))

    # Certificate.
    cert = [r for r in records if _is_cert(r.id)]
    cert_issues = [(r, s) for r in cert if (s := _severity(r))]
    if cert_issues:
        about = [_line(r) for r in cert if r.id.split(" ")[0] in _CERT_CONTEXT]
        untrusted = any(r.id.startswith("cert_chain_of_trust") for r, _s in cert_issues)
        audit.findings.append(Finding(
            title=f"TLS certificate issues on {target}: "
                  + "; ".join(r.finding.rstrip(".") for r, _s in cert_issues[:2])[:120],
            severity=_worst(s for _r, s in cert_issues), **base,
            description="testssl.sh found problems with the certificate: "
                        + "; ".join(f"{r.id} {r.finding}" for r, _s in cert_issues)[:600],
            evidence="\n".join([_line(r) for r, _s in cert_issues] + [""] + about)[:3000],
            recommendation="Serve a certificate from a CA the clients trust, naming the "
                           "service's host names, with a 2048-bit or stronger key, and "
                           "automate renewal.",
            review_required=untrusted,
            review_reason="Decide whether this endpoint is user-facing (a real problem) "
                          "or an appliance interface (often accepted)." if untrusted else "",
            tags=[*tags, "certificate"],
        ))

    # Summary, carrying the grade.
    grade = next((r.finding for r in records if r.id == "overall_grade"), "")
    audit.grade = grade
    caps = [r.finding for r in records if r.id.startswith(("grade_cap_reason",
                                                            "grade_cap_warning"))]
    offered = [PROTOCOL_LABELS[r.id] for r in protocols if r.finding.startswith("offered")]
    sims = [r for r in records if r.id.startswith("clientsimulation-")]
    failed_sims = [r.id.removeprefix("clientsimulation-") for r in sims
                   if "no connection" in r.finding.lower()]
    notices = [r.finding for r in records if r.id == "cmdline_ip-target"]
    evidence = [f"target: {target}" + (f" (STARTTLS {starttls})" if starttls else ""),
                f"service detected: {service or '?'}",
                f"protocols offered: {', '.join(offered) or 'none'}"]
    if grade:
        evidence.append(f"grade: {grade}")
        evidence += [f"  {c}" for c in caps]
    if sims:
        evidence.append(f"client simulation: {len(sims) - len(failed_sims)}/{len(sims)} "
                        "connected" + (f"; no connection: {', '.join(failed_sims)}"
                                       if failed_sims else ""))
    if audit.gaps:
        evidence.append("checks that did not complete: "
                        + ", ".join(sorted({g for g, _w in audit.gaps})))
    evidence += [f"note: {n}" for n in notices]
    audit.findings.insert(0, Finding(
        title=(f"TLS grade {grade} on {target} (testssl.sh)" if grade
               else f"TLS audit of {target} (testssl.sh)"),
        severity="info", **base,
        description="testssl.sh audit summary. The grade follows SSL Labs' rating guide "
                    "as implemented by testssl.sh; the findings for this service carry "
                    "the detail." if grade else "testssl.sh audit summary; this run did "
                    "not produce a grade.",
        evidence="\n".join(evidence)[:3000],
        tags=[*tags, "fingerprint"] + (["grade"] if grade else []),
    ))
    return audit


_CERT_CONTEXT = {"cert_commonName", "cert_subjectAltName", "cert_caIssuers",
                 "cert_notBefore", "cert_notAfter", "cert_keySize",
                 "cert_signatureAlgorithm"}


_CIPHER_LABELS = {"NULL": "NULL ciphers", "aNULL": "anonymous key exchange",
                  "EXPORT": "export ciphers", "LOW": "low-strength ciphers",
                  "3DES_IDEA": "3DES/IDEA", "OBSOLETED": "obsolete CBC ciphers",
                  "STRONG_NOFS": "no forward secrecy"}


def _cipher_label(rec_id: str) -> str:
    name = rec_id.removeprefix("cipherlist_")
    return _CIPHER_LABELS.get(name, name)


def _is_cipher(rec_id: str) -> bool:
    return (rec_id.startswith(("cipherlist_", "cipher-", "cipher_order", "FS_"))
            or rec_id in ("FS", "DH_groups"))


def _is_cert(rec_id: str) -> bool:
    return rec_id.startswith(("cert", "OCSP_", "intermediate_cert", "DNS_CAArecord"))


def _in_scope(rec: Record, scope: Scope | None) -> bool:
    """Drop records about a host outside scope (`ip` is "name/address")."""
    if scope is None or not rec.ip or rec.ip == "/":
        return True
    addr = rec.ip.rsplit("/", 1)[-1].strip("[]")
    return not addr or scope.contains(addr)


def _no_starttls_finding(host: str, port: int, proto: str, reason: str) -> Finding:
    sev = "info" if proto == "telnet" else "medium"
    return Finding(
        title=f"{proto.upper()} on {host}:{port} does not offer STARTTLS",
        severity=sev, host=host, port=port, proto="tcp", source="testssl.sh",
        description=f"testssl.sh could not negotiate TLS via STARTTLS ({proto}), so "
                    "this service most likely carries credentials and data in "
                    "cleartext.",
        evidence=f"testssl.sh --starttls {proto}: {reason[:300]}",
        recommendation="Offer and require STARTTLS, or move the service to implicit "
                       "TLS on its dedicated port.",
        review_required=True,
        review_reason=f"Confirm with `openssl s_client -starttls {proto} -connect "
                      f"{host}:{port}`; a server can offer STARTTLS only after a "
                      "greeting testssl.sh did not expect.",
        confidence="tentative",
        tags=["tls", "testssl", f"starttls:{proto}", "cleartext"],
    )


# --- running ----------------------------------------------------------------

GAP_STAGE = "probe:testssl-checks"


def audit(runner: Runner, scope: Scope, policy: Policy, svc: Service,
          stage: str = "probe:testssl") -> list[Finding]:
    """Run testssl.sh against one service and return its findings.

    Raises when the service was not audited, so the caller records a coverage
    gap and leaves the service unmarked. Checks that did not complete inside
    an otherwise good run are recorded as a separate gap (GAP_STAGE) against
    the service, never as passes.
    """
    mode = tls_mode(svc) or ("tls", "")
    starttls = mode[1]
    scope.assert_host(svc.host, context=f"testssl {svc.host}:{svc.port}")
    if not runner.dry_run and not have(TOOL):
        raise TestsslMissing(starttls)

    label = f"testssl-{svc.host}-{svc.port}"
    out = runner.store.raw_path(f"{label}.json")
    out.unlink(missing_ok=True)   # never parse a previous attempt's results
    res = runner.run(argv(policy, svc.host, svc.port, str(out), starttls), stage=stage,
                     timeout=policy.testssl.timeout_sec, stdout_name=label,
                     env=child_env())
    if res.skipped:
        return []
    if res.timed_out or (res.returncode is not None and res.returncode < 0):
        raise ScanFailed(f"testssl.sh {res.failure}")
    text = out.read_text(errors="replace") if out.exists() else ""
    if not text.strip():
        # Exit codes 1-49 count ambiguous results; above 241 is an error.
        raise ScanFailed(f"testssl.sh {res.failure or 'finished'} without writing JSON")
    result = parse(load_records(text), svc.host, svc.port, starttls, scope=scope)

    store = runner.store
    store.remove_degradations(lambda d: d.stage == GAP_STAGE
                              and d.reason.startswith(f"{svc.id}: "))
    if result.gaps:
        checks = sorted({g for g, _w in result.gaps})
        why = "; ".join(f"{g}: {w}" for g, w in result.gaps)
        store.add_degradation(Degradation(
            stage=GAP_STAGE, component=TOOL,
            reason=f"{svc.id}: {len(checks)} check(s) did not complete: {why}"[:300],
            impact=f"testssl.sh could not settle {', '.join(checks)} on "
                   f"{svc.host}:{svc.port}. Those results are unknown, not clean.",
            hosts=[svc.host],
            remedy=f"Read raw/{out.name} for testssl.sh's reason and fix it (for "
                   "example, install socat for the STARTTLS injection check), then "
                   "`extscan probe <run> --only testssl --force`.",
        ))
    return result.findings
