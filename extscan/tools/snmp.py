"""SNMP community-string checking, implemented in pure Python.

`snmpwalk` is often absent from a hardened jump box, and net-snmp is a heavy
dependency for what is a very small amount of wire format. So this module
speaks enough SNMPv1/v2c (BER-encoded GET and GETNEXT over UDP/161) to answer
the question the auditors actually ask: does this device answer to `public`,
`private`, or another guessable community?

Deliberate limitation: this only ever *reads*. A community that permits writes
can only be proven by writing, which would change client state during an
audit, so extscan does not attempt SET -- it flags the device for a human to
confirm read-write access through change control.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass

from ..models import Finding, Lead
from ..policy import Policy

# ---------------------------------------------------------------------------
# Minimal BER
# ---------------------------------------------------------------------------

TAG_INT = 0x02
TAG_OCTET = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQ = 0x30
TAG_GET = 0xA0
TAG_GETNEXT = 0xA1
TAG_RESPONSE = 0xA2

# SNMP application types we may see in a reply.
_APP_TYPES = {
    0x40: "IpAddress", 0x41: "Counter32", 0x42: "Gauge32",
    0x43: "TimeTicks", 0x44: "Opaque", 0x46: "Counter64",
    0x80: "noSuchObject", 0x81: "noSuchInstance", 0x82: "endOfMibView",
}

ERROR_STATUS = {
    0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue",
    4: "readOnly", 5: "genErr",
}

OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
}

# Communities that are indefensible on an internet-facing device.
WELL_KNOWN = {"public", "private", "community", "manager", "admin", "default",
              "read", "write", "snmp", "monitor", "cisco", "secret"}
# Conventionally the read-write string on many vendors' defaults.
LIKELY_WRITE = {"private", "write", "manager", "admin", "secret"}


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(value: int) -> bytes:
    if value == 0:
        return _tlv(TAG_INT, b"\x00")
    nbytes = (value.bit_length() + 8) // 8      # leaves room for the sign bit
    return _tlv(TAG_INT, value.to_bytes(nbytes, "big", signed=True))


def _enc_oid(oid: str) -> bytes:
    arcs = [int(a) for a in oid.strip(".").split(".") if a != ""]
    if len(arcs) < 2 or arcs[0] > 2:
        raise ValueError(f"bad OID {oid!r}")
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        if arc < 0x80:
            out.append(arc)
            continue
        chunks = []
        while arc:
            chunks.append(arc & 0x7F)
            arc >>= 7
        chunks.reverse()
        for i, c in enumerate(chunks):
            out.append(c | (0x80 if i < len(chunks) - 1 else 0))
    return _tlv(TAG_OID, bytes(out))


def _dec_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    arcs = [first // 40, first % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(str(a) for a in arcs)


def _parse_tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    """Return (tag, value, next_pos). Raises ValueError on a malformed buffer."""
    if pos + 2 > len(data):
        raise ValueError("truncated TLV header")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or pos + n > len(data):
            raise ValueError("unsupported or truncated length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise ValueError("truncated TLV value")
    return tag, data[pos:pos + length], pos + length


def _dec_value(tag: int, raw: bytes) -> str:
    if tag == TAG_OCTET:
        return raw.decode("utf-8", "replace").strip()
    if tag == TAG_INT:
        return str(int.from_bytes(raw, "big", signed=True)) if raw else "0"
    if tag == TAG_OID:
        return _dec_oid(raw)
    if tag == TAG_NULL:
        return ""
    if tag == 0x40 and len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return str(int.from_bytes(raw, "big")) if raw else "0"
    if tag in (0x80, 0x81, 0x82):
        return f"<{_APP_TYPES[tag]}>"
    return raw.decode("utf-8", "replace").strip() or f"<tag 0x{tag:02x}>"


def _build_request(community: str, oid: str, version: int, request_id: int,
                   pdu_tag: int = TAG_GET) -> bytes:
    varbind = _tlv(TAG_SEQ, _enc_oid(oid) + _tlv(TAG_NULL, b""))
    varbinds = _tlv(TAG_SEQ, varbind)
    pdu = _tlv(pdu_tag, _enc_int(request_id) + _enc_int(0) + _enc_int(0) + varbinds)
    # version field: 0 -> SNMPv1, 1 -> SNMPv2c
    body = _enc_int(0 if version == 1 else 1) + _tlv(TAG_OCTET, community.encode()) + pdu
    return _tlv(TAG_SEQ, body)


@dataclass
class SnmpReply:
    oid: str
    value: str
    error_status: int
    request_id: int

    @property
    def ok(self) -> bool:
        return self.error_status == 0 and not self.value.startswith("<noSuch")


def _parse_reply(data: bytes) -> SnmpReply | None:
    try:
        tag, body, _ = _parse_tlv(data)
        if tag != TAG_SEQ:
            return None
        _, _, pos = _parse_tlv(body)                  # version
        _, _, pos = _parse_tlv(body, pos)             # community
        pdu_tag, pdu, _ = _parse_tlv(body, pos)
        if pdu_tag != TAG_RESPONSE:
            return None
        _, rid_raw, p = _parse_tlv(pdu)
        _, err_raw, p = _parse_tlv(pdu, p)
        _, _, p = _parse_tlv(pdu, p)                  # error-index
        vb_tag, varbinds, _ = _parse_tlv(pdu, p)
        if vb_tag != TAG_SEQ:
            return None
        vb_inner_tag, vb, _ = _parse_tlv(varbinds)
        if vb_inner_tag != TAG_SEQ:
            return None
        otag, oid_raw, q = _parse_tlv(vb)
        vtag, val_raw, _ = _parse_tlv(vb, q)
        return SnmpReply(
            oid=_dec_oid(oid_raw) if otag == TAG_OID else "",
            value=_dec_value(vtag, val_raw),
            error_status=int.from_bytes(err_raw, "big", signed=True) if err_raw else 0,
            request_id=int.from_bytes(rid_raw, "big", signed=True) if rid_raw else 0,
        )
    except (ValueError, IndexError):
        return None


def snmp_get(host: str, community: str, oid: str, *, version: int = 2,
             port: int = 161, timeout: float = 2.0, retries: int = 1,
             pdu_tag: int = TAG_GET) -> SnmpReply | None:
    """One SNMP GET (or GETNEXT). Returns None on timeout or unparseable reply."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for attempt in range(retries + 1):
        request_id = int.from_bytes(os.urandom(3), "big") + 1
        packet = _build_request(community, oid, version, request_id, pdu_tag)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            while True:
                data, _ = sock.recvfrom(65535)
                reply = _parse_reply(data)
                if reply is None:
                    break
                # Ignore stale datagrams from an earlier attempt.
                if reply.request_id == request_id:
                    return reply
        except (socket.timeout, TimeoutError):
            continue
        except OSError:
            return None
        finally:
            sock.close()
    return None


def snmp_walk(host: str, community: str, root: str, *, version: int = 2,
              port: int = 161, timeout: float = 2.0,
              max_items: int = 25) -> list[tuple[str, str]]:
    """Bounded GETNEXT walk. Capped so a large table cannot stall the run."""
    out: list[tuple[str, str]] = []
    oid = root
    for _ in range(max_items):
        reply = snmp_get(host, community, oid, version=version, port=port,
                         timeout=timeout, retries=0, pdu_tag=TAG_GETNEXT)
        if reply is None or not reply.ok or not reply.oid:
            break
        if not reply.oid.startswith(root.rstrip(".")):
            break                                  # walked off the subtree
        if reply.oid == oid:
            break                                  # no forward progress
        out.append((reply.oid, reply.value))
        oid = reply.oid
    return out


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

def check_community_strings(host: str, policy: Policy, port: int = 161
                            ) -> tuple[list[Finding], list[Lead], list[str]]:
    """Try each configured community read-only. Returns (findings, leads, hits)."""
    p = policy.snmp
    findings: list[Finding] = []
    leads: list[Lead] = []
    hits: list[str] = []
    details: dict[str, dict[str, str]] = {}

    for community in p.communities:
        for version in p.versions:
            reply = snmp_get(host, community, OIDS["sysDescr"], version=version,
                             port=port, timeout=p.timeout_sec, retries=p.retries)
            if reply is None:
                continue
            if not reply.ok:
                # The agent answered but refused this community: the service is
                # alive, which is itself worth knowing.
                continue
            hits.append(community)
            info = {"sysDescr": reply.value, "version": f"v{'1' if version == 1 else '2c'}"}
            if p.walk_on_hit:
                for label in ("sysName", "sysLocation", "sysContact", "sysObjectID", "sysUpTime"):
                    r = snmp_get(host, community, OIDS[label], version=version, port=port,
                                 timeout=p.timeout_sec, retries=0)
                    if r is not None and r.ok and r.value:
                        info[label] = r.value
            details[community] = info
            break          # found a working version for this community; move on

    if not hits:
        return findings, leads, hits

    for community in hits:
        info = details.get(community, {})
        well_known = community.lower() in WELL_KNOWN
        likely_write = community.lower() in LIKELY_WRITE
        sev = "high" if well_known else "medium"

        evidence = "\n".join(f"{k}: {v}" for k, v in info.items())
        desc = (
            f"The SNMP agent on {host}:{port}/udp answered an unauthenticated query "
            f"using the community string `{community}` ({info.get('version', 'v2c')}). "
            "SNMP read access typically discloses the device model and firmware, "
            "interface and routing tables, ARP caches and internal addressing -- a "
            "map of the internal network, served to the internet."
        )
        rec = (
            "Restrict UDP/161 to management networks at the perimeter; replace "
            "guessable community strings; prefer SNMPv3 with authPriv. If SNMP is "
            "not in use, disable the agent."
        )

        f = Finding(
            title=f"SNMP readable with {'default' if well_known else 'guessable'} "
                  f"community string `{community}`",
            severity=sev, host=host, port=port, proto="udp", source="extscan:snmp",
            description=desc, evidence=evidence[:4000], recommendation=rec,
            references=["https://www.cisa.gov/news-events/alerts/2017/06/05/simple-network-management-protocol-snmp-vulnerabilities"],
            tags=["snmp", "default-credentials", f"community:{community}"],
        )
        if likely_write:
            f.review_required = True
            f.review_reason = (
                f"`{community}` is conventionally a read-write community. extscan does "
                "not attempt SNMP SET, because a write would alter client state. An "
                "auditor should confirm whether write access is possible via change "
                "control -- if it is, this is critical, not high."
            )
        findings.append(f)

        leads.append(Lead(
            kind="snmp_walk", host=host, port=port, proto="udp",
            params={"community": community,
                    "version": info.get("version", "v2c")},
            reason="Enumerate interfaces and addressing to show the client what this "
                   "community string actually discloses.",
            origin="extscan:snmp",
        ))

    return findings, leads, hits
