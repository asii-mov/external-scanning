"""sslscan adapter: cipher-level TLS detail the built-in probe cannot reach.

extscan's own TLS probe answers "which protocol versions does this accept" by
attempting handshakes, which is enough for the common findings. What it cannot
do from Python's `ssl` module is enumerate individual cipher suites, because
the local OpenSSL build decides which suites it is willing to offer -- a modern
build simply will not propose RC4, so its absence proves nothing about the
server.

sslscan links its own crypto and asks directly, so it can state that a server
accepts 3DES. Where both run, the built-in probe's results are superseded and
this adapter's findings carry the detail.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from extscan.models import Finding
from extscan.runner import Result, Runner, require
from extscan.scope import Scope
from extscan.tools.nmap import reject_hostile_xml

# Matched on the suite name, since sslscan's own `strength` attribute is
# coarse and varies between versions.
_WEAK_PATTERNS: list[tuple[str, str, str]] = [
    (r"\bNULL\b", "critical", "offers a NULL cipher, which provides no encryption at all"),
    (r"\bEXPORT|\bEXP-", "critical", "offers an export-grade cipher (deliberately weakened "
                                     "40/56-bit crypto from the 1990s)"),
    (r"\banon\b|\bADH\b|\bAECDH\b", "high", "offers an anonymous key exchange, which "
                                            "removes authentication and enables "
                                            "machine-in-the-middle"),
    (r"\bRC4\b", "high", "offers RC4, which is broken (RFC 7465 prohibits it)"),
    (r"\bDES-CBC3\b|\b3DES\b", "medium", "offers 3DES, which is vulnerable to Sweet32 "
                                         "and is deprecated"),
    (r"\bDES-CBC-\b", "high", "offers single DES"),
    (r"\bMD5\b", "medium", "offers an MD5-based suite"),
    (r"\bIDEA\b|\bSEED\b|\bCAMELLIA\b.*\bSHA\b", "low", "offers a legacy cipher suite"),
]

DEPRECATED_PROTOCOLS = {"SSLv2": "critical", "SSLv3": "high",
                        "TLSv1.0": "medium", "TLSv1.1": "medium"}


def argv(host: str, port: int, xml_out: str) -> list[str]:
    """Build the sslscan command.

    `--no-colour` keeps the stdout copy readable in the audit trail, and
    `--xml` is what we actually parse.
    """
    return [
        "sslscan",
        "--no-colour",
        "--show-certificate",
        f"--xml={xml_out}",
        f"{host}:{port}",
    ]


def _protocol_label(node: ET.Element) -> str:
    kind = (node.get("type") or "").lower()
    version = node.get("version") or ""
    if kind == "ssl":
        return f"SSLv{version}"
    if version in ("1.0", "1", "1.1", "1.2", "1.3"):
        return f"TLSv{version}" if "." in version else f"TLSv{version}.0"
    return f"{kind.upper()}{version}"


def parse_xml(xml_text: str, scope: Scope | None = None) -> list[Finding]:
    """Turn sslscan XML into findings."""
    if not xml_text.strip():
        return []
    reject_hostile_xml(xml_text, tool="sslscan")
    try:
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError as exc:
        raise ValueError(f"could not parse sslscan XML: {exc}") from exc

    findings: list[Finding] = []

    for test in root.iter("ssltest"):
        host = test.get("host") or ""
        try:
            port = int(test.get("port") or 0) or None
        except ValueError:
            port = None
        if scope is not None and host and not scope.contains(host):
            continue

        target = f"{host}:{port}" if port else host

        enabled, disabled = [], []
        for node in test.findall("protocol"):
            label = _protocol_label(node)
            (enabled if node.get("enabled") == "1" else disabled).append(label)

        bad = [p for p in enabled if p in DEPRECATED_PROTOCOLS]
        if bad:
            worst = max(bad, key=lambda p: ["low", "medium", "high", "critical"]
                        .index(DEPRECATED_PROTOCOLS[p]))
            findings.append(Finding(
                title=f"Deprecated TLS/SSL protocols accepted on {target}: "
                      + ", ".join(sorted(bad)),
                severity=DEPRECATED_PROTOCOLS[worst],
                host=host, port=port, source="sslscan",
                description="These protocol versions are withdrawn and fail PCI DSS. "
                            "Unlike a handshake probe run from this host, sslscan "
                            "carries its own crypto, so this is a direct statement "
                            "about the server rather than about our client library.",
                evidence=f"enabled: {', '.join(enabled) or 'none'}\n"
                         f"disabled: {', '.join(disabled) or 'none'}",
                recommendation="Require TLS 1.2 or better; disable everything older.",
                references=["https://www.rfc-editor.org/rfc/rfc8996"],
                tags=["tls", "sslscan", "deprecated-protocol"],
            ))

        accepted = []
        for node in test.findall("cipher"):
            name = node.get("cipher") or ""
            accepted.append({
                "name": name,
                "version": node.get("sslversion") or "",
                "bits": node.get("bits") or "",
                "strength": (node.get("strength") or "").lower(),
                "status": node.get("status") or "",
            })

        flagged: dict[str, list[str]] = {}
        for entry in accepted:
            for pattern, severity, why in _WEAK_PATTERNS:
                if re.search(pattern, entry["name"], re.I):
                    flagged.setdefault(f"{severity}|{why}", []).append(
                        f"{entry['version']} {entry['name']} ({entry['bits']} bit)")
                    break

        for key, suites in flagged.items():
            severity, why = key.split("|", 1)
            findings.append(Finding(
                title=f"Weak TLS cipher suites on {target}: {why.split(',')[0]}",
                severity=severity, host=host, port=port, source="sslscan",
                description=f"The server {why}.",
                evidence="\n".join(sorted(set(suites))[:30]),
                recommendation="Restrict the cipher list to AEAD suites with forward "
                               "secrecy (ECDHE + AES-GCM or ChaCha20-Poly1305).",
                tags=["tls", "sslscan", "weak-cipher"],
            ))

        low_bits = [e for e in accepted
                    if e["bits"].isdigit() and int(e["bits"]) < 128]
        if low_bits and not flagged:
            findings.append(Finding(
                title=f"Cipher suites below 128-bit accepted on {target}",
                severity="medium", host=host, port=port, source="sslscan",
                description="Suites providing less than 128 bits of symmetric "
                            "strength are accepted.",
                evidence="\n".join(f"{e['version']} {e['name']} ({e['bits']} bit)"
                                   for e in low_bits[:20]),
                recommendation="Raise the minimum cipher strength to 128 bits.",
                tags=["tls", "sslscan", "weak-cipher"],
            ))

        compression = test.find("compression")
        if compression is not None and compression.get("supported") == "1":
            findings.append(Finding(
                title=f"TLS compression enabled on {target} (CRIME)",
                severity="medium", host=host, port=port, source="sslscan",
                description="TLS-level compression enables the CRIME attack against "
                            "secrets in the compressed stream, such as session cookies.",
                evidence="sslscan reports compression supported",
                recommendation="Disable TLS compression.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2012-4929"],
                tags=["tls", "sslscan", "crime"],
            ))

        reneg = test.find("renegotiation")
        if reneg is not None and reneg.get("supported") == "1" \
                and reneg.get("secure") != "1":
            findings.append(Finding(
                title=f"Insecure TLS renegotiation on {target}",
                severity="medium", host=host, port=port, source="sslscan",
                description="The server permits client-initiated renegotiation without "
                            "RFC 5746 secure renegotiation, which allows request "
                            "injection and can be used to amplify CPU cost.",
                evidence="sslscan reports renegotiation supported, secure=0",
                recommendation="Enable secure renegotiation or disable client-initiated "
                               "renegotiation.",
                tags=["tls", "sslscan", "renegotiation"],
            ))

        heartbleed = [n for n in test.findall("heartbleed")
                      if n.get("vulnerable") == "1"]
        if heartbleed:
            findings.append(Finding(
                title=f"Heartbleed (CVE-2014-0160) reported on {target}",
                severity="critical", host=host, port=port, source="sslscan",
                description="The server appears vulnerable to Heartbleed, which leaks "
                            "process memory -- including private keys and session "
                            "tokens -- to an unauthenticated attacker.",
                evidence="vulnerable for: " + ", ".join(
                    n.get("sslversion") or "?" for n in heartbleed),
                recommendation="Patch OpenSSL immediately, then rotate the private key "
                               "and every credential that transited this service.",
                review_required=True,
                review_reason="Confirm before reporting, and treat key rotation as "
                              "urgent if confirmed. Do not extract memory contents.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
                tags=["tls", "sslscan", "cve"],
            ))

        cert = test.find("certificate")
        if cert is not None:
            findings.extend(_certificate_findings(cert, host, port, target))

    return findings


def _text(node: ET.Element | None) -> str:
    return (node.text or "").strip() if node is not None else ""


def _certificate_findings(cert: ET.Element, host: str, port: int | None,
                          target: str) -> list[Finding]:
    out: list[Finding] = []
    sig = _text(cert.find("signature-algorithm"))
    expired = _text(cert.find("expired")).lower()
    self_signed = _text(cert.find("self-signed")).lower()
    pk = cert.find("pk")
    bits = pk.get("bits") if pk is not None else ""
    not_after = _text(cert.find("not-valid-after"))

    detail = (f"signature: {sig}\nkey: {pk.get('type') if pk is not None else '?'} "
              f"{bits} bit\nexpires: {not_after}")

    if expired == "true":
        out.append(Finding(
            title=f"Expired certificate on {target}",
            severity="medium", host=host, port=port, source="sslscan",
            description=f"The certificate expired on {not_after}.",
            evidence=detail, recommendation="Renew and automate renewal.",
            tags=["tls", "sslscan", "certificate"],
        ))
    if self_signed == "true":
        out.append(Finding(
            title=f"Self-signed certificate on {target}",
            severity="low", host=host, port=port, source="sslscan",
            description="The certificate is self-signed, so it provides no identity "
                        "assurance against interception.",
            evidence=detail, review_required=True,
            review_reason="Decide whether this endpoint is user-facing (a real problem) "
                          "or an appliance interface (often accepted).",
            tags=["tls", "sslscan", "certificate"],
        ))
    if re.search(r"\b(?:sha-?1|md5)(?!\d)", sig, re.I):
        out.append(Finding(
            title=f"Certificate signed with a broken hash on {target}: {sig}",
            severity="medium", host=host, port=port, source="sslscan",
            description="SHA-1 and MD5 signatures are forgeable with achievable effort; "
                        "browsers reject such certificates.",
            evidence=detail,
            recommendation="Reissue with a SHA-256 or stronger signature.",
            tags=["tls", "sslscan", "certificate"],
        ))
    if bits.isdigit() and int(bits) < 2048:
        out.append(Finding(
            title=f"Certificate key below 2048 bits on {target} ({bits} bit)",
            severity="medium", host=host, port=port, source="sslscan",
            description="RSA keys under 2048 bits are below current guidance.",
            evidence=detail, recommendation="Reissue with a 2048-bit or stronger key.",
            tags=["tls", "sslscan", "certificate"],
        ))
    return out


def run(runner: Runner, scope: Scope, host: str, port: int,
        timeout: int) -> tuple[Result, list[Finding]]:
    """Run sslscan against one endpoint."""
    scope.assert_host(host, context=f"sslscan {host}:{port}")
    if not runner.dry_run:
        require("sslscan")
    out = runner.store.raw_path(f"sslscan-{host}-{port}.xml")
    res = runner.run(argv(host, port, str(out)), stage="probe:sslscan",
                     timeout=timeout, stdout_name=f"sslscan-{host}-{port}")
    text = out.read_text(errors="replace") if out.exists() else ""
    return res, parse_xml(text, scope=scope)
