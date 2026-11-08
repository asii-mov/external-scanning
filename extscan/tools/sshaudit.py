"""ssh-audit adapter: an SSH algorithm audit the banner probe cannot give.

The built-in `ssh` probe only repeats nmap's banner. ssh-audit
(https://github.com/jtesta/ssh-audit, MIT, run as a subprocess and never
imported) completes the unauthenticated part of the handshake and reports
every key-exchange, host-key, cipher and MAC algorithm the server offers,
each with its own fail/warn notes. That is a direct statement about the
server's configuration, unlike a version guess from the banner.

Written against ssh-audit 3.9.0 (pinned in scripts/cloud-setup.sh). What this
module relies on from that release:

* flags: `-j` (JSON on stdout), `-n` (no colours), `--skip-rate-test`, and
  `-t N` (connect/read timeout in seconds); the target is one `HOST:PORT`
  positional, with IPv6 as `[addr]:port`. Its argparse has
  `allow_abbrev=False`, so a prefix such as `--dhe` is not `--dheat`.
* exit codes: 0 good, 2 warnings, 3 failures (all three are a completed
  audit), 1 connection error, 255 unknown error. On a connection error it
  still prints a JSON object with only the banner, then an `[exception]`
  line, both on stdout.
* JSON keys: `banner{raw,protocol,software,comments}`, `target`,
  `compression`, `kex|key|enc|mac: [{algorithm, keysize?, notes{fail?,
  warn?, info?}}]`, `fingerprints: [{hostkey, hash_alg, hash}]`,
  `recommendations`, `additional_notes` and `cves`.
* `cves` is always `[]` since v3.3.0, which removed version-to-CVE mapping as
  "wildly inaccurate". Older releases filled it with
  `{name, cvssv2, description}`. Those entries are still parsed, at tentative
  confidence. ssh-audit does not report authentication methods. Those come
  from nmap's `ssh-auth-methods` script output, when it ran.

Safety: by default a standard ssh-audit run also performs a connection-rate
test (up to 38 connections in 1.5 seconds) to gauge DHEat exposure, and
`--dheat` / `--conn-rate-test` turn it into a sustained DoS. `argv` always
passes `--skip-rate-test` and accepts only an allowlist of extra flags, so
no policy file can bring those back. What remains is the standard audit:
one connection for the KEXINIT, plus a few short connections to read each
host-key type and to probe Diffie-Hellman group-exchange modulus sizes.

Severity is deliberately conservative, because ssh-audit's fail/warn levels
are a hardening opinion and not all of them are exploitable. The mapping is
by algorithm, so it does not depend on the wording of the notes:

=========  ==========================================================
high       `none` cipher or MAC (no encryption or integrity); SSH-1
medium     1024-bit or smaller DH groups (Logjam), DSA or < 2048-bit
           RSA host keys, 3DES/DES/RC4/Blowfish/CAST/IDEA ciphers,
           MD5 or 96-bit MACs; Terrapin (CVE-2023-48795) exposure
low        any other algorithm ssh-audit marks *fail* (SHA-1 key
           exchange, `ssh-rsa` SHA-1 signatures, ...), and CBC ciphers
info       NIST-curve "suspected backdoor" fails, HMAC-SHA1 (HMAC is not
           broken by SHA-1 collisions), unknown algorithms, and every
           warn-only note (post-quantum, 2048-bit moduli, encrypt-and-MAC)
=========  ==========================================================

The info-level items go into the per-service summary finding, not a finding
of their own. Each service gets at most one finding per kind: summary, weak
algorithms, Terrapin, SSH-1, banner CVEs, password authentication.
"""

from __future__ import annotations

import json
import re
from typing import Any

from extscan.models import Finding, severity_rank
from extscan.runner import Result, Runner, require
from extscan.scope import Scope

SSH_AUDIT_VERSION = "3.9.0"

# The only fixed argv. `--skip-rate-test` is the safety property.
BASE_FLAGS = ("-j", "-n", "--skip-rate-test")

# Extra flags a policy may add. Everything else is refused, not filtered:
# a policy that asks for something unsafe is a mistake the operator must see.
SAFE_EXTRA_ARGS = frozenset({"-4", "--ipv4", "-6", "--ipv6"})

# Called out by name in the error, because these are the dangerous ones:
# DoS, mass connections, listening servers, multi-target runs, file writes,
# or flags that would override the fixed argv.
FORBIDDEN_FLAGS = (
    "--dheat", "--conn-rate-test", "-g", "--gex-test", "-c", "--client-audit",
    "-T", "--targets", "--threads", "-M", "--make-policy", "-P", "--policy",
    "--socks5", "-p", "--port", "-t", "--timeout", "-j", "--json", "-l", "--level",
)

EXIT_GOOD, EXIT_CONNECTION_ERROR, EXIT_WARNING, EXIT_FAILURE = 0, 1, 2, 3
_COMPLETED = {EXIT_GOOD, EXIT_WARNING, EXIT_FAILURE}

CATEGORIES = {"kex": "key exchange", "key": "host key", "enc": "cipher", "mac": "MAC"}

HARDENING_GUIDES = "https://www.ssh-audit.com/hardening_guides.html"
TERRAPIN_REF = "https://nvd.nist.gov/vuln/detail/CVE-2023-48795"

MAX_ALGORITHMS = 200   # per category; a hostile server can send any number
MAX_TEXT = 300


def check_extra_args(extra: list[str]) -> list[str]:
    """Return the extra args unchanged, or raise ValueError naming the bad ones."""
    if not isinstance(extra, (list, tuple)):
        raise ValueError("ssh_audit.extra_args must be a list of flags")
    bad = [str(a) for a in extra if str(a) not in SAFE_EXTRA_ARGS]
    if bad:
        named = [a for a in bad if a.split("=", 1)[0] in FORBIDDEN_FLAGS]
        why = (f" ({', '.join(named)} would run a rate/DoS test, open many "
               "connections or override the fixed argv)") if named else ""
        raise ValueError(
            f"ssh_audit.extra_args {bad!r} refused{why}. Allowed: "
            f"{sorted(SAFE_EXTRA_ARGS)}")
    return [str(a) for a in extra]


def assert_safe_argv(cmd: list[str]) -> None:
    """The safety invariant, checked on every argv before it is run."""
    if "--skip-rate-test" not in cmd:
        raise ValueError("ssh-audit argv without --skip-rate-test refused")
    for arg in cmd[1:]:
        if arg.split("=", 1)[0] in ("--dheat", "--conn-rate-test"):
            raise ValueError(f"ssh-audit argv with {arg} refused")


def target_spec(host: str, port: int) -> str:
    if not host or host.startswith("-") or any(c.isspace() for c in host):
        raise ValueError(f"refusing ssh-audit target {host!r}")
    return f"[{host}]:{int(port)}" if ":" in host else f"{host}:{int(port)}"


def argv(policy: Any, host: str, port: int) -> list[str]:
    """Build the ssh-audit command from an SshAuditPolicy."""
    connect = max(1, int(policy.connect_timeout_sec))
    cmd = ["ssh-audit", *BASE_FLAGS, "-t", str(connect),
           *check_extra_args(policy.extra_args), target_spec(host, port)]
    assert_safe_argv(cmd)
    return cmd


# --------------------------------------------------------------------------
# Parsing


def load_json(text: str) -> dict:
    """The first JSON object on stdout. ssh-audit may print an
    `[exception] ...` line after it on a connection error."""
    start = text.find("{")
    if start < 0:
        raise ValueError("ssh-audit produced no JSON")
    try:
        data, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse ssh-audit JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("ssh-audit JSON is not an object")
    return data


def _clean(value: Any, limit: int = MAX_TEXT) -> str:
    """Server-controlled text: printable, one line, bounded."""
    text = "" if value is None else str(value)
    text = "".join(c if c.isprintable() else "?" for c in text)
    return text[:limit]


def _notes(entry: dict, level: str) -> list[str]:
    notes = entry.get("notes")
    if not isinstance(notes, dict):
        return []
    items = notes.get(level)
    if not isinstance(items, list):
        return []
    return [_clean(n) for n in items if n is not None]


def _keysize(entry: dict) -> int | None:
    size = entry.get("keysize")
    return size if isinstance(size, int) and not isinstance(size, bool) else None


def _algorithms(data: dict, category: str) -> list[dict]:
    items = data.get(category)
    if not isinstance(items, list):
        return []
    return [e for e in items[:MAX_ALGORITHMS]
            if isinstance(e, dict) and isinstance(e.get("algorithm"), str)]


_NONE = re.compile(r"^none$", re.I)
_BROKEN = {
    "kex": re.compile(r"group1-sha1|^gss-group1-|rsa1024", re.I),
    "key": re.compile(r"^ssh-dss|^x509v3-sign-dss", re.I),
    "enc": re.compile(r"3des|^des|arcfour|rc4|blowfish|cast128|idea", re.I),
    "mac": re.compile(r"md5|-96\b|-96@", re.I),
}
_RSA_KEY = re.compile(r"rsa", re.I)
_DH_KEX = re.compile(r"^diffie-hellman|^gss-", re.I)
_HMAC_SHA1 = re.compile(r"^hmac-sha1(-etm@openssh\.com)?$", re.I)
_CBC = re.compile(r"-cbc\b|cbc@", re.I)
_OPINION = re.compile(r"backdoor", re.I)
_UNKNOWN = "using unknown algorithm"
_TERRAPIN = re.compile(r"terrapin", re.I)


def classify(category: str, entry: dict) -> str | None:
    """Severity of one offered algorithm, or None when it is clean.

    See the module docstring for the table this implements.
    """
    name = entry.get("algorithm", "")
    fails = _notes(entry, "fail")
    warns = [w for w in _notes(entry, "warn") if not _TERRAPIN.search(w)]
    size = _keysize(entry)

    if category in ("enc", "mac") and _NONE.match(name):
        return "high"
    if _BROKEN[category].search(name):
        return "medium"
    if size is not None and size < 2048 and (
            (category == "kex" and _DH_KEX.search(name))
            or (category == "key" and _RSA_KEY.search(name))):
        return "medium"
    if fails:
        if all(f == _UNKNOWN for f in fails):
            return "info"
        if category == "mac" and _HMAC_SHA1.match(name):
            return "info"
        if all(_OPINION.search(f) for f in fails):
            return "info"
        return "low"
    if category == "enc" and _CBC.search(name):
        return "low"
    if warns:
        return "info"
    return None


def _describe(category: str, entry: dict) -> str:
    name = _clean(entry.get("algorithm"), 120)
    size = _keysize(entry)
    parts = [name + (f" ({size}-bit)" if size else "")]
    fails, warns = _notes(entry, "fail"), _notes(entry, "warn")
    if fails:
        parts.append("fail: " + "; ".join(fails))
    if warns:
        parts.append("warn: " + "; ".join(warns))
    return " -- ".join(parts)


def parse_auth_methods(script_output: str) -> list[str]:
    """Methods from nmap's `ssh-auth-methods` NSE output, as stored in
    Service.scripts. Pre-auth: the script sends one `none` request."""
    if not script_output:
        return []
    methods: list[str] = []
    seen_header = False
    for raw in script_output.splitlines():
        line = raw.strip().rstrip(":").strip()
        if not line:
            continue
        if line.lower() == "none_auth":
            methods.append("none")
            continue
        if line.lower().startswith("supported authentication methods"):
            seen_header = True
            rest = line.split(":", 1)[1].strip() if ":" in line else ""
            methods += [m for m in re.split(r"[\s,]+", rest) if m]
            continue
        if seen_header and re.fullmatch(r"[A-Za-z0-9@._-]{1,64}", line):
            methods.append(line)
    out: list[str] = []
    for m in methods:
        m = m.lower()
        if m not in out:
            out.append(m)
    return out


def parse_json(text: str, host: str, port: int,
               auth_methods: list[str] | None = None) -> list[Finding]:
    """Turn one ssh-audit JSON document into findings for host:port."""
    data = load_json(text)
    if not _algorithms(data, "kex"):
        # A banner-only document (connection error) is not an audit; a
        # summary built from it would read as a clean result.
        raise ValueError("ssh-audit JSON has no key-exchange algorithms")
    target = f"{host}:{port}"
    banner = data.get("banner") if isinstance(data.get("banner"), dict) else {}
    raw_banner = _clean(banner.get("raw"), 200)
    software = _clean(banner.get("software"), 120)
    protocol = _clean(banner.get("protocol"), 10)

    common = {"host": host, "port": port, "proto": "tcp", "source": "ssh-audit"}
    findings: list[Finding] = []

    graded: dict[str, list[tuple[str, str]]] = {c: [] for c in CATEGORIES}
    listing: list[str] = []
    terrapin: list[str] = []
    for category, label in CATEGORIES.items():
        entries = _algorithms(data, category)
        listing.append(f"{label} ({len(entries)}):")
        for entry in entries:
            sev = classify(category, entry)
            mark = f"[{sev}] " if sev else "[ok] "
            listing.append(f"  {mark}{_describe(category, entry)}")
            if sev and sev != "info":
                graded[category].append((sev, _describe(category, entry)))
            if any(_TERRAPIN.search(w) for w in _notes(entry, "warn")):
                terrapin.append(_clean(entry.get("algorithm"), 120))

    fingerprints = [
        f"{_clean(fp.get('hostkey'), 60)} {_clean(fp.get('hash_alg'), 10)}:"
        f"{_clean(fp.get('hash'), 120)}"
        for fp in (data.get("fingerprints") or [])[:20]
        if isinstance(fp, dict) and fp.get("hash_alg") == "SHA256"
    ] if isinstance(data.get("fingerprints"), list) else []

    compression = data.get("compression")
    comp = ", ".join(_clean(c, 40) for c in compression[:10]) \
        if isinstance(compression, list) else "?"

    if auth_methods:
        auth_line = "authentication methods (nmap ssh-auth-methods): " \
                    + ", ".join(auth_methods)
    else:
        auth_line = ("authentication methods: not observed (ssh-audit does not "
                     "report them and nmap's ssh-auth-methods script did not run)")

    summary = [f"banner: {raw_banner or '?'}", f"compression: {comp}", auth_line, ""]
    summary += listing
    if fingerprints:
        summary += ["", "host key fingerprints:"] + [f"  {f}" for f in fingerprints]

    findings.append(Finding(
        title=f"SSH configuration audit of {target} (ssh-audit)",
        severity="info", **common,
        description="ssh-audit completed the unauthenticated part of the SSH "
                    "handshake and listed every algorithm the server offers. "
                    "Severities in brackets are extscan's conservative mapping of "
                    "ssh-audit's fail/warn notes; info-level items are hardening "
                    "advice rather than weaknesses.",
        evidence="\n".join(summary)[:6000],
        review_required=not auth_methods,
        review_reason=("Authentication methods were not observed. Confirm the "
                       "server allows key-based authentication only."
                       if not auth_methods else ""),
        references=[HARDENING_GUIDES],
        tags=["ssh", "ssh-audit", "fingerprint"],
    ))

    weak = {c: v for c, v in graded.items() if v}
    if weak:
        worst = max((sev for items in weak.values() for sev, _ in items),
                    key=severity_rank)
        counts = ", ".join(f"{len(v)} {CATEGORIES[c]}" for c, v in weak.items())
        evidence = []
        for category, items in weak.items():
            evidence.append(f"{CATEGORIES[category]}:")
            for sev, text in sorted(items, key=lambda i: -severity_rank(i[0])):
                evidence.append(f"  [{sev}] {text}")
        findings.append(Finding(
            title=f"Weak SSH algorithms offered on {target}: {counts}",
            severity=worst, **common,
            description="The server offers algorithms that are broken or "
                        "deprecated. A client that prefers them, or an attacker "
                        "able to influence negotiation, gets weaker protection "
                        "than the server could provide. This comes from the "
                        "server's own algorithm lists, not from its version.",
            evidence="\n".join(evidence)[:5000],
            recommendation="Remove the listed algorithms from the server's "
                           "KexAlgorithms, HostKeyAlgorithms, Ciphers and MACs "
                           "settings (and replace DSA or short RSA host keys). "
                           "ssh-audit's hardening guides give tested settings "
                           "per platform.",
            references=[HARDENING_GUIDES,
                        "https://www.rfc-editor.org/rfc/rfc9142"],
            tags=["ssh", "ssh-audit", "weak-algorithm"],
        ))

    kex_names = {e.get("algorithm") for e in _algorithms(data, "kex")}
    if terrapin and "kex-strict-s-v00@openssh.com" not in kex_names:
        findings.append(Finding(
            title=f"SSH server exposed to Terrapin (CVE-2023-48795) on {target}",
            severity="medium", **common,
            description="The server offers ChaCha20-Poly1305 or an encrypt-then-MAC "
                        "mode and does not advertise strict key exchange, so a "
                        "machine-in-the-middle can silently drop messages at the "
                        "start of the secure channel (for example, to downgrade "
                        "extension negotiation).",
            evidence="affected algorithms: " + ", ".join(terrapin)
                     + "\nkex-strict-s-v00@openssh.com not offered",
            recommendation="Upgrade the SSH server to a release with strict key "
                           "exchange (OpenSSH 9.6 or a patched distribution "
                           "package), or disable the affected algorithms.",
            review_required=True,
            review_reason="Exploitation needs an active network position, and "
                          "both ends must be patched to close it. Confirm the "
                          "server package and how clients reach it.",
            references=[TERRAPIN_REF, "https://terrapin-attack.com/"],
            tags=["ssh", "ssh-audit", "terrapin", "cve"],
        ))

    if protocol.startswith("1."):
        findings.append(Finding(
            title=f"SSH protocol 1 supported on {target}",
            severity="high", **common,
            description=f"The banner advertises protocol {protocol}, so the server "
                        "still accepts SSH-1, which is cryptographically broken.",
            evidence=f"banner: {raw_banner}",
            recommendation="Disable SSH protocol 1.",
            tags=["ssh", "ssh-audit", "sshv1"],
        ))

    cves = [c for c in (data.get("cves") or [])[:50] if isinstance(c, dict)] \
        if isinstance(data.get("cves"), list) else []
    if cves:
        def score(c: dict) -> float:
            try:
                return float(c.get("cvssv2") or 0)
            except (TypeError, ValueError):
                return 0.0
        top = max(score(c) for c in cves)
        findings.append(Finding(
            title=f"Banner-matched CVEs for {software or 'SSH server'} on {target}",
            severity="medium" if top >= 7.0 else "low", **common,
            description="An older ssh-audit release matched the banner version "
                        "to these CVEs. Distributions backport fixes without "
                        "changing the banner, and ssh-audit itself dropped this "
                        "mapping in v3.3.0 as inaccurate, so treat this as a lead "
                        "to check the installed package, not as a vulnerability.",
            evidence="\n".join(
                f"{_clean(c.get('name'), 40)} (CVSSv2 {_clean(c.get('cvssv2'), 8)}): "
                f"{_clean(c.get('description'), 200)}" for c in cves)[:4000],
            recommendation="Check the installed package version against the "
                           "vendor's advisories before reporting.",
            review_required=True,
            review_reason="Banner-based version match only. Verify the patch "
                          "level on the host before reporting any of these.",
            confidence="tentative",
            tags=["ssh", "ssh-audit", "cve", "banner-version"],
        ))

    methods = auth_methods or []
    if "none" in methods:
        findings.append(Finding(
            title=f"SSH server accepts login without authentication on {target}",
            severity="high", **common,
            description="nmap's ssh-auth-methods check was accepted with the "
                        "`none` method, so a session may open without any credential.",
            evidence="ssh-auth-methods: none_auth",
            recommendation="Require public-key authentication.",
            review_required=True,
            review_reason="Confirm manually what the unauthenticated session "
                          "exposes. Do not go further without written approval.",
            tags=["ssh", "authentication"],
        ))
    interactive = [m for m in methods if m in ("password", "keyboard-interactive")]
    if interactive:
        findings.append(Finding(
            title=f"SSH password authentication offered on {target}",
            severity="low", **common,
            description="The server offers " + " and ".join(interactive)
                        + " authentication before login, so it can be targeted by "
                        "password guessing and credential stuffing. No "
                        "credential was tried.",
            evidence="offered methods: " + ", ".join(methods),
            recommendation="Allow public-key (or certificate) authentication only, "
                           "or restrict the service to known sources.",
            review_required=True,
            review_reason="keyboard-interactive is also used for MFA prompts. "
                          "Confirm whether a second factor is enforced.",
            tags=["ssh", "authentication", "password-auth"],
        ))

    return findings


def audit_failure(res: Result, data: dict | None) -> str:
    """Why this run is not a completed audit, or "" when it is."""
    if res.skipped:
        return ""
    if res.timed_out or (res.returncode is not None and res.returncode < 0):
        return res.failure
    if res.returncode == EXIT_CONNECTION_ERROR:
        tail = [ln.strip() for ln in (res.stdout + "\n" + res.stderr).splitlines()
                if ln.strip().startswith("[exception]")]
        return ("could not complete the key exchange"
                + (f": {_clean(tail[-1], 200)}" if tail else " (exit 1)"))
    if res.returncode not in _COMPLETED:
        return res.failure or f"exited {res.returncode}"
    if data is None:
        return "produced no parseable JSON"
    if not _algorithms(data, "kex"):
        return "reported no key-exchange algorithms"
    return ""


def run(runner: Runner, scope: Scope, policy: Any, host: str, port: int,
        auth_methods: list[str] | None = None) -> tuple[Result, list[Finding], str]:
    """Run ssh-audit against one endpoint. Returns (result, findings, failure)."""
    scope.assert_host(host, context=f"ssh-audit {host}:{port}")
    cmd = argv(policy, host, port)
    if not runner.dry_run:
        require("ssh-audit")
    res = runner.run(cmd, stage="probe:ssh_audit", timeout=int(policy.timeout_sec),
                     stdout_name=f"ssh-audit-{host}-{port}")
    if res.skipped:
        return res, [], ""
    try:
        data = load_json(res.stdout)
    except ValueError:
        data = None
    failure = audit_failure(res, data)
    if failure:
        return res, [], failure
    return res, parse_json(res.stdout, host, port, auth_methods=auth_methods), ""
