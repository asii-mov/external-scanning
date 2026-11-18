"""IP pseudonymisation for text sent to a model.

A model provider does not need the client's real addresses to reason about
evidence, only their shape. It needs to know whether an address is
loopback, private or public, and which hosts share a network. So before a prompt leaves the host, every address is
swapped for a fake one of the same kind, and the swap is undone in the reply.

How an address is mapped:

* IPv4 maps per /24. The network part is swapped and the last octet kept, so
  `10.1.2.7` and `10.1.2.9` land in the same fake /24, and an address the
  model works out for itself (`.1`, the `.0/24`) maps back correctly.
* The kind is kept: loopback stays in 127/8, each RFC 1918 block stays in
  itself, CGNAT stays in 100.64/10, and a public address becomes a different
  public address.
* IPv6 maps per /64 the same way, ULA to ULA and global to global. The
  interface identifier is kept, so an EUI-64 address still carries its MAC.
* Addresses that identify nothing are left alone: 0.0.0.0/8, link-local,
  multicast, 240/4 (which holds netmasks and the broadcast address), and the
  IPv6 loopback, link-local and multicast ranges.

The table lives in memory for one `IPRedactor` and is never written down,
because a saved copy would be the mapping the redaction keeps private.
Fakes are drawn at random rather than hashed, because a hash of a 32-bit value
can be reversed by trying every address.

Not handled, and documented as such: integer and hex forms (`0x0a000001`),
zero-padded octets, dashed hostnames such as `ip-10-0-0-1`, and hostnames in
general. Only addresses are pseudonymised.
"""

from __future__ import annotations

import ipaddress
import random
import re
import secrets
import threading

SYSTEM_NOTE = """\

IP addresses in this request were pseudonymised before it left the auditor's \
network. Each real address was replaced consistently with a fake one of the \
same kind (loopback, private or public), and addresses that share a /24 (a /64 \
for IPv6) still share one, so reason about them exactly as given. Quote every \
address exactly as it appears; they are translated back after you reply. Do \
not guess who owns an address or where it is, because the fake carries no \
such information."""


class RedactionError(Exception):
    """An address could not be pseudonymised, so the text must not be sent."""


_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# Plain dots, and the defanged forms threat reports use: 10[.]0[.]0[.]1.
_SEP = r"(\.|\[\.\]|\(\.\)|\{\.\})"
_V4_RE = re.compile(
    # A dot before is fine after a word ("ipAddr.10.0.0.1"), not after a
    # digit, where the address would be the tail of an OID or version.
    rf"(?<![0-9])(?<![0-9]\.)({_OCTET}){_SEP}({_OCTET}){_SEP}({_OCTET}){_SEP}({_OCTET})"
    # A fifth part means an OID or a version string, not an address.
    r"(?!\d)(?!(?:\.|\[\.\]|\(\.\)|\{\.\})\d)"
)
# "v1.2.3.4", "version 1.2.3.4": a four-part version number, not an address.
_VERSION_BEFORE_RE = re.compile(r"(?i)(?:\bv|\bversion[\s:=]*|\bver[\s:=.]*|"
                                r"\brelease[\s:=]*|\bbuild[\s:=]*|\brev[\s:=.]*)$")
# "Chrome/128.0.0.0" in a User-Agent. Only the N.0.0.0 shape is skipped.
# Any other word/address, such as "tcp/10.0.0.1" or "admin/10.0.0.1", is
# redacted, because a garbled version round-trips harmlessly and a leaked
# address does not.
_PRODUCT_BEFORE_RE = re.compile(r"[A-Za-z]/$")
# Any run of hex digits, colons and dots holding at least two colons; each
# run is then parsed, trimmed of a leading label ("For:") or trailing colon
# ("...::5: refused") if it has to be.
_V6_RUN_RE = re.compile(r"[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z_.\-]+)?")

_V4_KEEP = [ipaddress.ip_network(n) for n in
            ("0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]
# Each pool maps onto itself, so the kind of address survives.
_V4_POOLS = [ipaddress.ip_network(n) for n in
             ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "100.64.0.0/10")]
_V6_ULA = ipaddress.ip_network("fc00::/7")
_V6_GLOBAL = ipaddress.ip_network("2000::/3")

_MAX_DRAWS = 10_000


class IPRedactor:
    """Swaps real addresses for fakes and back, consistently, for one session.

    Thread-safe: the chase stage may ask the model from worker threads, and
    every request in a run has to see the same mapping.
    """

    def __init__(self, rng: random.Random | None = None):
        self._rng = rng or secrets.SystemRandom()
        self._lock = threading.Lock()
        self._v4_fwd: dict[int, int] = {}   # real /24 -> fake /24
        self._v4_rev: dict[int, int] = {}
        self._v6_fwd: dict[int, int] = {}   # real /64 -> fake /64
        self._v6_rev: dict[int, int] = {}
        self.replaced = 0     # addresses swapped on the way out
        self.restored = 0     # addresses swapped back in replies

    # -- public ---------------------------------------------------------------

    def redact(self, text: str) -> str:
        """Replace every identifying address in `text` with its fake."""
        with self._lock:
            text = _V4_RE.sub(lambda m: self._v4(m, forward=True), text)
            return _V6_RUN_RE.sub(lambda m: self._v6(m, forward=True), text)

    def restore(self, text: str) -> str:
        """Undo `redact` in text that came back from the model.

        Only addresses inside a fake network are touched. Anything else the
        model wrote, such as a public resolver it mentions, stays as written.
        """
        with self._lock:
            text = _V4_RE.sub(lambda m: self._v4(m, forward=False), text)
            return _V6_RUN_RE.sub(lambda m: self._v6(m, forward=False), text)

    @property
    def networks(self) -> int:
        """How many distinct real networks have been mapped."""
        return len(self._v4_fwd) + len(self._v6_fwd)

    # -- IPv4 -----------------------------------------------------------------

    def _v4(self, m: re.Match, *, forward: bool) -> str:
        octets = [int(m.group(i)) for i in (1, 3, 5, 7)]
        if forward and (
                _VERSION_BEFORE_RE.search(m.string, max(0, m.start() - 12), m.start())
                or (octets[1:] == [0, 0, 0]
                    and _PRODUCT_BEFORE_RE.search(m.string, max(0, m.start() - 2),
                                                  m.start()))):
            return m.group(0)
        value = int.from_bytes(bytes(octets), "big")
        net, host = value & ~0xFF, value & 0xFF
        if forward:
            if _v4_pool(value) is None:
                return m.group(0)
            mapped = self._v4_fwd.get(net)
            if mapped is None:
                mapped = self._alloc_v4(net)
        else:
            mapped = self._v4_rev.get(net)
            if mapped is None:
                return m.group(0)
        self._count(forward)
        new = (mapped | host).to_bytes(4, "big")
        # Keep the separators as written, so a defanged address stays defanged.
        return (f"{new[0]}{m.group(2)}{new[1]}{m.group(4)}"
                f"{new[2]}{m.group(6)}{new[3]}")

    def _alloc_v4(self, net: int) -> int:
        pool = _v4_pool(net)
        for _ in range(_MAX_DRAWS):
            if pool == "public":
                candidate = self._rng.getrandbits(24) << 8
                if _v4_pool(candidate) != "public" \
                        or not ipaddress.IPv4Address(candidate).is_global:
                    continue
            else:
                span = pool.num_addresses >> 8
                candidate = int(pool.network_address) + (self._rng.randrange(span) << 8)
            if candidate != net and candidate not in self._v4_rev:
                self._v4_fwd[net] = candidate
                self._v4_rev[candidate] = net
                return candidate
        raise RedactionError(
            f"no unused fake /24 left for {ipaddress.IPv4Address(net)}/24; "
            "the request was not sent")

    # -- IPv6 -----------------------------------------------------------------

    def _count(self, forward: bool) -> None:
        if forward:
            self.replaced += 1
        else:
            self.restored += 1

    def _v6(self, m: re.Match, *, forward: bool) -> str:
        full = m.group(0)
        run = full.split("%", 1)[0]     # a zone ("%eth0") is kept as written
        # Trailing punctuation may or may not belong to the address: "::5:
        # refused" ends at the 5, "fd00::" keeps its "::", "2001:db8:::"
        # loses one colon. Try each, longest first.
        ends = [len(run)]
        while ends[-1] and run[ends[-1] - 1] in ".:":
            ends.append(ends[-1] - 1)
        # Then without a leading ":" and without up to two leading labels
        # ("For:2001:db8::1", "abc:fd00::1").
        starts = [0]
        for i, ch in enumerate(run):
            if ch == ":" and len(starts) < 4 and run[i + 1:i + 2] != ":" \
                    and run[i - 1:i] != ":":
                starts.append(i + 1)
        for start, end in ((s, e) for s in starts for e in ends if e - s >= 2):
            candidate = run[start:end]
            try:
                addr = ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            # ::ffff:a.b.c.d had its IPv4 part handled by the IPv4 pass.
            if addr.ipv4_mapped is not None or "." in candidate:
                return full
            new = self._map_v6(addr, forward)
            if new is None:
                return full
            return full[:start] + new + full[end:]
        return full

    def _map_v6(self, addr: ipaddress.IPv6Address, forward: bool) -> str | None:
        value = int(addr)
        prefix, iid = value >> 64 << 64, value & ((1 << 64) - 1)
        if forward:
            pool = _v6_pool(addr)
            if pool is None:
                return None
            mapped = self._v6_fwd.get(prefix)
            if mapped is None:
                mapped = self._alloc_v6(prefix, pool)
        else:
            mapped = self._v6_rev.get(prefix)
            if mapped is None:
                return None
        self._count(forward)
        return str(ipaddress.IPv6Address(mapped | iid))

    def _alloc_v6(self, prefix: int, pool: ipaddress.IPv6Network) -> int:
        base, bits = int(pool.network_address), 64 - pool.prefixlen
        for _ in range(_MAX_DRAWS):
            candidate = base | (self._rng.getrandbits(bits) << 64)
            if pool is _V6_GLOBAL and not ipaddress.IPv6Address(candidate).is_global:
                continue
            if candidate != prefix and candidate not in self._v6_rev:
                self._v6_fwd[prefix] = candidate
                self._v6_rev[candidate] = prefix
                return candidate
        raise RedactionError("no unused fake /64 left; the request was not sent")


def _v4_pool(value: int):
    """The pool an IPv4 address is mapped within, "public", or None to keep it."""
    addr = ipaddress.IPv4Address(value)
    if any(addr in net for net in _V4_KEEP):
        return None
    for pool in _V4_POOLS:
        if addr in pool:
            return pool
    return "public"


def _v6_pool(addr: ipaddress.IPv6Address):
    if addr in _V6_ULA:
        return _V6_ULA
    if addr in _V6_GLOBAL:
        return _V6_GLOBAL
    # Loopback, unspecified, link-local, multicast, and the rest of the
    # reserved space identify nothing.
    return None
