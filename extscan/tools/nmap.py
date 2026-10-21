"""nmap adapter: build the argv, run it, parse the XML.

Discovery is split into a TCP pass and a UDP pass because they have very
different cost profiles and failure modes -- a UDP scan that times out should
not cost you the TCP results.

Parsing reads nmap's XML (-oX) rather than screen-scraping normal output, so
service/version/script detail survives intact.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET

from ..models import Finding, Host, Service
from ..policy import Policy
from ..runner import Result, Runner, require
from ..scope import Scope


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def tcp_argv(scope: Scope, policy: Policy, xml_out: str) -> list[str]:
    """Build the TCP discovery command.

    SYN scan when privileged (faster, lighter on the target); connect scan
    otherwise, so an unprivileged run still works.
    """
    p = policy.nmap
    argv = ["nmap", "-sS" if _is_root() else "-sT", "-sV",
            "--version-intensity", str(p.version_intensity)]
    if p.scripts:
        argv += ["--script", p.scripts]
    argv += ["-p", p.tcp_ports, p.timing,
             "--max-retries", str(p.max_retries),
             "--host-timeout", p.host_timeout,
             "--open", "-oX", xml_out]
    if p.min_rate:
        argv += ["--min-rate", str(p.min_rate)]
    if p.skip_host_discovery:
        argv.append("-Pn")
    if _is_root():
        argv.append("-O")               # OS fingerprint; needs raw sockets
    argv += p.extra_args
    argv += scope.nmap_target_args()
    return argv


def udp_argv(scope: Scope, policy: Policy, xml_out: str) -> list[str]:
    p = policy.nmap
    argv = ["nmap", "-sU", "-sV", "--version-intensity", str(min(p.version_intensity, 5)),
            "-p", p.udp_ports, p.timing,
            "--max-retries", str(p.max_retries),
            "--host-timeout", p.host_timeout,
            "--open", "-oX", xml_out]
    # UDP service detection leans on these scripts for SNMP/NTP/DNS/mDNS.
    if p.scripts:
        argv += ["--script", "default,safe"]
    if p.skip_host_discovery:
        argv.append("-Pn")
    argv += scope.nmap_target_args()
    return argv


def _script_map(node: ET.Element) -> dict[str, str]:
    out: dict[str, str] = {}
    for script in node.findall("script"):
        sid = script.get("id") or ""
        text = script.get("output") or ""
        if not text:
            # Table-valued scripts carry their data in child elements.
            text = " ".join(
                (e.get("key") or "") + "=" + (e.text or "")
                for e in script.iter() if e is not script
            ).strip()
        if sid:
            out[sid] = text.strip()
    return out


def parse_xml(xml_text: str, scope: Scope | None = None,
              source: str = "nmap") -> tuple[list[Host], list[Service], list[Finding]]:
    """Turn nmap XML into hosts, services and script-derived findings.

    If a scope is supplied, anything nmap reports outside it is dropped. nmap
    honours --exclude, but a stray CIDR typo or a scope edited mid-engagement
    should not silently widen what ends up in the report.
    """
    hosts: list[Host] = []
    services: list[Service] = []
    findings: list[Finding] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"could not parse nmap XML: {exc}") from exc

    for hnode in root.findall("host"):
        addr = ""
        for anode in hnode.findall("address"):
            if anode.get("addrtype") in ("ipv4", "ipv6"):
                addr = anode.get("addr") or ""
                break
        if not addr:
            continue
        if scope is not None and not scope.contains(addr):
            continue

        state_node = hnode.find("status")
        state = state_node.get("state", "unknown") if state_node is not None else "unknown"

        names = [n.get("name", "") for n in hnode.findall("hostnames/hostname") if n.get("name")]

        os_guess = None
        best = hnode.find("os/osmatch")
        if best is not None:
            os_guess = f"{best.get('name', '')} ({best.get('accuracy', '?')}%)"

        hosts.append(Host(ip=addr, hostnames=names, state=state,
                          os_guess=os_guess, discovered_by=source))

        # Host-level script output (e.g. smb-os-discovery) is worth keeping.
        # nmap nests these under <hostscript>, not directly under <host>.
        hostscript = hnode.find("hostscript")
        host_scripts = _script_map(hostscript) if hostscript is not None else {}
        for sid, text in host_scripts.items():
            if text:
                findings.append(Finding(
                    title=f"nmap host script: {sid}",
                    severity="info", host=addr, source=f"{source}:{sid}",
                    description=f"Host-level nmap script `{sid}` returned output.",
                    evidence=text[:4000], tags=["nmap-script", sid],
                ))

        for pnode in hnode.findall("ports/port"):
            pstate = pnode.find("state")
            port_state = pstate.get("state", "") if pstate is not None else ""
            if not port_state.startswith("open"):
                continue
            try:
                port = int(pnode.get("portid", "0"))
            except ValueError:
                continue
            proto = pnode.get("protocol", "tcp")

            snode = pnode.find("service")
            svc = Service(
                host=addr, port=port, proto=proto, state=port_state,
                name=(snode.get("name", "") if snode is not None else ""),
                product=(snode.get("product", "") if snode is not None else ""),
                version=(snode.get("version", "") if snode is not None else ""),
                extrainfo=(snode.get("extrainfo", "") if snode is not None else ""),
                tunnel=(snode.get("tunnel", "") if snode is not None else ""),
                cpe=[c.text or "" for c in (snode.findall("cpe") if snode is not None else [])],
                scripts=_script_map(pnode),
            )
            services.append(svc)

            findings.extend(_findings_from_scripts(svc, source))

    return hosts, services, findings


# nmap script ids whose output, if present at all, is worth a human's eyes.
_SCRIPT_SEVERITY: dict[str, tuple[str, str]] = {
    "ssl-heartbleed":        ("critical", "Heartbleed (CVE-2014-0160) reported by nmap."),
    "smb-vuln-ms17-010":     ("critical", "MS17-010 / EternalBlue reported by nmap."),
    "ftp-anon":              ("medium", "FTP server allows anonymous login."),
    "nfs-showmount":         ("medium", "NFS exports are listable by unauthenticated clients."),
    "smb-enum-shares":       ("medium", "SMB shares are enumerable."),
    "rdp-ntlm-info":         ("low", "RDP leaks NTLM/domain information pre-authentication."),
    "ssl-cert":              ("info", "TLS certificate details."),
    "ssl-date":              ("info", "TLS server clock/date."),
    "http-title":            ("info", "HTTP page title."),
    "snmp-info":             ("medium", "SNMP responded to an unauthenticated query."),
    "snmp-sysdescr":         ("medium", "SNMP sysDescr readable without authentication."),
    "mongodb-info":          ("high", "MongoDB responded to an unauthenticated query."),
    "redis-info":            ("high", "Redis responded to an unauthenticated query."),
    "memcached-info":        ("high", "memcached responded to an unauthenticated query."),
    "elasticsearch":         ("high", "Elasticsearch responded without authentication."),
}

_REVIEW_SCRIPTS = {
    "http-title", "ssl-cert", "smb-enum-shares", "nfs-showmount", "ftp-anon",
}


def _findings_from_scripts(svc: Service, source: str) -> list[Finding]:
    out: list[Finding] = []
    for sid, text in svc.scripts.items():
        if not text:
            continue
        if sid == "vulners" or sid.startswith("vulners"):
            out.append(Finding(
                title=f"Known-vulnerability candidates on {svc.name or 'service'} "
                      f"{svc.product} {svc.version}".strip(),
                severity="medium", host=svc.host, port=svc.port, proto=svc.proto,
                source=f"{source}:{sid}",
                description="nmap's vulners script matched the detected version against "
                            "known CVEs. Version-based matches are indicative, not proof.",
                evidence=text[:4000],
                review_required=True,
                review_reason="Version-derived CVE matches need confirmation against the "
                              "actual build and backported patches before reporting.",
                confidence="tentative", tags=["cve", "version-match"],
            ))
            continue

        sev, desc = _SCRIPT_SEVERITY.get(sid, ("info", f"nmap script `{sid}` output."))
        needs_review = sid in _REVIEW_SCRIPTS or sid.startswith("http-")
        out.append(Finding(
            title=f"{sid} on {svc.host}:{svc.port}/{svc.proto}",
            severity=sev, host=svc.host, port=svc.port, proto=svc.proto,
            source=f"{source}:{sid}", description=desc, evidence=text[:4000],
            review_required=needs_review and sev == "info",
            review_reason=("Script output is informational; an auditor should judge "
                           "whether what it exposes matters for this client.")
                          if needs_review and sev == "info" else "",
            tags=["nmap-script", sid],
        ))
    return out


def run_tcp(runner: Runner, scope: Scope, policy: Policy) -> tuple[Result, str]:
    """Run the TCP pass. Returns (result, xml_text)."""
    if not runner.dry_run:
        require("nmap")
    xml_path = runner.store.raw_path("nmap-tcp.xml")
    argv = tcp_argv(scope, policy, str(xml_path))
    res = runner.run(argv, stage="discover:tcp", timeout=policy.nmap.timeout_sec,
                     stdout_name="nmap-tcp")
    return res, xml_path.read_text() if xml_path.exists() else ""


def run_udp(runner: Runner, scope: Scope, policy: Policy) -> tuple[Result, str]:
    """Run the UDP pass.

    Needs root for -sU. We surface that as a warning rather than a hard error:
    losing UDP coverage should not abort an otherwise good run, but it must be
    visible, because "no UDP findings" and "UDP never ran" look identical in a
    report otherwise.
    """
    if not runner.dry_run:
        require("nmap")
    xml_path = runner.store.raw_path("nmap-udp.xml")
    argv = udp_argv(scope, policy, str(xml_path))
    res = runner.run(argv, stage="discover:udp", timeout=policy.nmap.timeout_sec,
                     stdout_name="nmap-udp")
    return res, xml_path.read_text() if xml_path.exists() else ""


def udp_requires_root() -> bool:
    return not _is_root()
