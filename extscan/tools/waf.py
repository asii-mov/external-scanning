"""CDN and web application firewall detection, as a coverage signal.

A WAF or CDN in front of a service changes what every web result means. If
it silently blocks, challenges or rewrites our requests, the probes see the
edge's block page rather than the application, and the report would say "no
findings" for a service that was never really tested. So this module answers
two questions, and both feed coverage gaps rather than findings:

* **What is in front of this service?** `identify` reads what one ordinary
  GET already returns (headers, cookies, a few body markers), the TLS
  certificate text nmap's `ssl-cert` script recorded, and membership of a
  small built-in list of published CDN address ranges. It sends nothing.
* **Did it block us?** `classify_block` recognises challenge pages, vendor
  block pages and rate limiting in a response. `watch` lets the pipeline
  collect every block seen while one probe or one chase lead runs, because
  `net.fetch` reports each response it returns to the active watch.

A slow server is not a WAF. Timeouts, resets and refused connections are
never treated as blocking here: they have honest causes, and treating them
as a WAF would bury real outages under a false explanation. A bare 403 or
503 is not a block either, since access control and overload are ordinary.
Only a vendor fingerprint, HTTP 429, or a 503 that asks us to come back
later (Retry-After) counts.

Signatures are written for extscan from vendor documentation and observed
responses. None are copied from wafw00f or any other tool's data.
"""

from __future__ import annotations

import contextlib
import html
import ipaddress
import re
import threading
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from extscan.resilience import Degradation

# How much of a body to search. Block pages are small; this bounds the cost
# on large ordinary pages.
BODY_SCAN_BYTES = 65_536

BLOCK_STATUSES = {403, 405, 406, 429, 501, 503}


@dataclass(frozen=True)
class EdgeMatch:
    """One piece of evidence that a named CDN or WAF fronts a service."""

    name: str
    kind: str
    evidence: str


@dataclass(frozen=True)
class Block:
    """A response that was a challenge, a block page or rate limiting."""

    vendor: str
    kind: str  # "challenge", "block" or "rate-limit"
    status: int
    url: str
    evidence: str
    retry_after: str = ""

    def describe(self) -> str:
        who = self.vendor or "an unidentified filter"
        verb = {"challenge": "challenged", "block": "blocked",
                "rate-limit": "rate-limited"}.get(self.kind, self.kind)
        extra = f", Retry-After {self.retry_after}" if self.retry_after else ""
        return f"{verb} by {who} (HTTP {self.status}{extra})"


# ---------------------------------------------------------------------------
# Passive identification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Sig:
    name: str
    kind: str
    headers: tuple[tuple[str, str], ...] = ()   # (header, regex on value)
    cookies: tuple[str, ...] = ()               # regex on cookie name
    body: tuple[str, ...] = ()                  # lowercase substrings
    cert: tuple[str, ...] = ()                  # lowercase substrings in cert text


_ANY = r"."

SIGNATURES: tuple[_Sig, ...] = (
    _Sig("Cloudflare", "CDN/WAF",
         headers=(("cf-ray", _ANY), ("cf-cache-status", _ANY), ("cf-mitigated", _ANY),
                  ("server", r"^cloudflare")),
         cookies=(r"^__cf_bm$", r"^__cflb$", r"^__cfruid$", r"^cf_clearance$"),
         body=("/cdn-cgi/challenge-platform/", "/cdn-cgi/l/email-protection"),
         cert=("cloudflare inc", "cloudflaressl.com")),
    _Sig("Akamai", "CDN/WAF",
         headers=(("server", r"^akamaighost"), ("x-akamai-transformed", _ANY),
                  ("x-akamai-request-id", _ANY), ("x-akamai-session-info", _ANY),
                  ("akamai-grn", _ANY), ("akamai-cache-status", _ANY),
                  ("x-cache", r"akamai")),
         cookies=(r"^ak_bmsc$", r"^bm_sv$", r"^bm_sz$", r"^_abck$"),
         cert=("akamaized.net", "akamaihd.net", "edgekey.net", "edgesuite.net",
               "akamaitechnologies.com", "a248.e.akamai.net")),
    _Sig("Amazon CloudFront", "CDN",
         headers=(("x-amz-cf-id", _ANY), ("x-amz-cf-pop", _ANY),
                  ("via", r"cloudfront"), ("x-cache", r"cloudfront"),
                  ("server", r"^cloudfront")),
         cert=("cloudfront.net",)),
    _Sig("AWS WAF", "WAF",
         headers=(("x-amzn-waf-action", _ANY),),
         cookies=(r"^aws-waf-token$",)),
    _Sig("Azure Front Door", "CDN/WAF",
         headers=(("x-azure-ref", _ANY), ("x-fd-healthprobe", _ANY)),
         cert=("azurefd.net",)),
    _Sig("Azure CDN", "CDN",
         headers=(("x-msedge-ref", _ANY),),
         cert=("azureedge.net",)),
    _Sig("Azure Application Gateway", "WAF",
         headers=(("server", r"^microsoft-azure-application-gateway"),)),
    _Sig("Fastly", "CDN",
         headers=(("x-fastly-request-id", _ANY), ("fastly-debug-digest", _ANY),
                  ("x-served-by", r"\bcache-[a-z0-9]+-[a-z]{3}\b"),
                  ("x-timer", r"^s\d+\.\d+,vs\d+"),
                  ("server", r"^fastly")),
         cert=("fastly.net", "fastlylb.net")),
    _Sig("Imperva Incapsula", "CDN/WAF",
         headers=(("x-iinfo", _ANY), ("x-cdn", r"incapsula|imperva")),
         cookies=(r"^incap_ses_", r"^visid_incap_", r"^nlbi_"),
         body=("_incapsula_resource", "incapsula incident id"),
         cert=("incapsula.com", "imperva.com")),
    _Sig("Sucuri", "WAF",
         headers=(("x-sucuri-id", _ANY), ("x-sucuri-cache", _ANY),
                  ("x-sucuri-block", _ANY), ("server", r"^sucuri")),
         body=("sucuri website firewall",),
         cert=("sucuri.net",)),
    _Sig("F5 BIG-IP ASM", "WAF",
         headers=(("x-wa-info", _ANY),),
         cookies=(r"^TS[0-9a-fA-F]{6,}(_\d+)?$",),
         body=("the requested url was rejected. please consult with your administrator",)),
    _Sig("Barracuda", "WAF",
         cookies=(r"^barra_counter_session", r"^BNI__BARRACUDA_LB_COOKIE",
                  r"^BNI_persistence", r"^BNES_")),
    _Sig("Citrix NetScaler AppFirewall", "WAF",
         headers=(("via", r"ns-cache"),),
         cookies=(r"^ns_af$", r"^citrix_ns_id")),
    _Sig("Fortinet FortiWeb", "WAF",
         cookies=(r"^FORTIWAFSID$",)),
    _Sig("ModSecurity", "WAF",
         headers=(("server", r"mod_security"),),
         body=("this error was generated by mod_security",)),
    _Sig("DDoS-Guard", "CDN/WAF",
         headers=(("server", r"^ddos-guard"),),
         cookies=(r"^__ddg[0-9]+",)),
    _Sig("Vercel", "CDN",
         headers=(("x-vercel-id", _ANY), ("server", r"^vercel"))),
    _Sig("Netlify", "CDN",
         headers=(("x-nf-request-id", _ANY), ("server", r"^netlify"))),
    _Sig("KeyCDN", "CDN",
         headers=(("server", r"^keycdn"),)),
)


# Published edge address ranges, transcribed on 2026-11-08 from:
#   Cloudflare  https://www.cloudflare.com/ips-v4 and /ips-v6
#   Fastly      https://api.fastly.com/public-ip-list
#   Imperva     https://my.imperva.com/api/integration/v1/ips
#   CloudFront  https://ip-ranges.amazonaws.com/ip-ranges.json (service
#               CLOUDFRONT, collapsed, only aggregates of /18 or wider for
#               IPv4 and /40 or wider for IPv6, so this list is partial)
# Providers change these. A hit is strong evidence; a miss is not evidence of
# anything, which is why header and cookie signatures come first. Nothing is
# downloaded at runtime: refresh this table by hand.
IP_RANGES_DATE = "2026-11-08"
IP_RANGES: dict[str, tuple[str, tuple[str, ...]]] = {
    "Cloudflare": ("CDN/WAF", (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    )),
    "Fastly": ("CDN", (
        "23.235.32.0/20", "43.249.72.0/22", "90.98.0.0/17", "90.98.128.0/18",
        "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16",
        "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20",
        "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16",
        "2a04:4e40::/32", "2a04:4e42::/31", "2a04:4e44::/32",
    )),
    "Imperva Incapsula": ("CDN/WAF", (
        "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22",
        "185.11.124.0/22", "192.230.64.0/18", "45.64.64.0/22", "107.154.0.0/16",
        "45.60.0.0/16", "45.223.0.0/16", "131.125.128.0/17",
        "2a02:e980::/29",
    )),
    "Amazon CloudFront": ("CDN", (
        "3.160.0.0/13", "3.168.0.0/14", "3.172.0.0/17", "3.173.0.0/16", "3.174.0.0/15",
        "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "13.249.0.0/16",
        "15.158.0.0/16", "18.64.0.0/14", "18.68.0.0/16", "18.154.0.0/15",
        "18.160.0.0/15", "18.164.0.0/15", "18.172.0.0/15", "18.238.0.0/15",
        "18.244.0.0/15", "23.234.192.0/18", "24.110.128.0/17", "51.74.192.0/18",
        "52.46.0.0/18", "52.84.0.0/15", "52.124.128.0/17", "52.222.128.0/17",
        "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/17", "54.230.128.0/18",
        "54.239.128.0/18", "54.240.128.0/18", "64.252.64.0/18", "64.252.128.0/18",
        "65.8.0.0/16", "65.9.0.0/17", "65.9.128.0/18", "70.132.0.0/18",
        "71.152.0.0/17", "99.84.0.0/16", "99.86.0.0/16", "108.138.0.0/15",
        "108.156.0.0/14", "130.176.0.0/17", "130.176.128.0/18", "143.204.0.0/16",
        "144.220.0.0/16",
        "2400:7fc0:500::/40", "2404:c2c0:500::/40", "2600:9000:1000::/36",
        "2600:9000:2000::/35", "2600:9000:4000::/36", "2600:9000:5200::/40",
        "2600:9000:6000::/36", "2600:9000:f000::/38", "2600:9000:f400::/40",
        "2600:9000:f600::/39", "2600:9000:f800::/37",
    )),
}


@lru_cache(maxsize=1)
def _networks() -> tuple[tuple[str, str, Any], ...]:
    out = []
    for name, (kind, cidrs) in IP_RANGES.items():
        for cidr in cidrs:
            out.append((name, kind, ipaddress.ip_network(cidr)))
    return tuple(out)


def ip_provider(ip: str) -> EdgeMatch | None:
    """Which provider's published edge range holds `ip`, if any."""
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return None
    for name, kind, net in _networks():
        if addr.version == net.version and addr in net:
            return EdgeMatch(name, kind, f"address {ip} is in {name}'s published range "
                                         f"{net} (list dated {IP_RANGES_DATE})")
    return None


def cookie_names(set_cookies: list[str] | tuple[str, ...]) -> list[str]:
    """Cookie names from raw Set-Cookie header values."""
    names = []
    for raw in set_cookies or ():
        name = raw.split(";", 1)[0].split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


def _lower_headers(headers: dict[str, str] | None) -> dict[str, str]:
    return {str(k).lower(): str(v or "") for k, v in (headers or {}).items()}


def identify(headers: dict[str, str] | None = None, set_cookies: list[str] | None = None,
             body: str = "", cert_text: str = "", ip: str = "") -> list[EdgeMatch]:
    """Every CDN/WAF signature that matches, one match per provider.

    Pure: works only on what it is given, and sends nothing anywhere.
    """
    hdrs = _lower_headers(headers)
    cookies = cookie_names(set_cookies or [])
    lowered_body = (body or "")[:BODY_SCAN_BYTES].lower()
    lowered_cert = (cert_text or "").lower()
    found: dict[str, EdgeMatch] = {}

    for sig in SIGNATURES:
        evidence = ""
        for header, pattern in sig.headers:
            value = hdrs.get(header)
            if value is not None and re.search(pattern, value, re.I):
                evidence = f"header {header}: {value[:120]}"
                break
        if not evidence:
            for pattern in sig.cookies:
                hit = next((c for c in cookies if re.search(pattern, c)), None)
                if hit:
                    evidence = f"cookie {hit}"
                    break
        if not evidence:
            hit = next((m for m in sig.body if m in lowered_body), None)
            if hit:
                evidence = f"body contains {hit!r}"
        if not evidence:
            hit = next((m for m in sig.cert if m in lowered_cert), None)
            if hit:
                evidence = f"certificate mentions {hit!r}"
        if evidence:
            found.setdefault(sig.name, EdgeMatch(sig.name, sig.kind, evidence))

    # X-CDN names the CDN in its value; take it at its word when nothing more
    # specific matched.
    xcdn = hdrs.get("x-cdn", "").strip()
    known = any(re.search(pattern, xcdn, re.I) for sig in SIGNATURES
                for header, pattern in sig.headers if header == "x-cdn")
    if xcdn and not known:
        name = re.sub(r"[^A-Za-z0-9 ._-]", "", xcdn)[:40] or "unnamed CDN"
        found.setdefault(name, EdgeMatch(name, "CDN", f"header x-cdn: {xcdn[:120]}"))

    if ip:
        by_ip = ip_provider(ip)
        if by_ip and by_ip.name not in found:
            found[by_ip.name] = by_ip

    return list(found.values())


def identify_response(resp: Any, cert_text: str = "", ip: str = "") -> list[EdgeMatch]:
    """`identify` over a `net.Response` (or anything shaped like one)."""
    return identify(getattr(resp, "headers", {}), getattr(resp, "set_cookies", []),
                    _body_text(resp), cert_text, ip)


def edge_label(matches: list[EdgeMatch]) -> str:
    """'Cloudflare (CDN/WAF)', or 'Amazon CloudFront (CDN) + AWS WAF (WAF)'."""
    return " + ".join(f"{m.name} ({m.kind})" for m in matches)


# ---------------------------------------------------------------------------
# Block and challenge classification
# ---------------------------------------------------------------------------

_AKAMAI_REFERENCE = re.compile(r"reference\s*#\s*[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]+")
_CF_ERROR_CODE = re.compile(r"error code:?\s*10[0-9]{2}\b")


def _body_text(resp: Any) -> str:
    text = getattr(resp, "text", None)
    if isinstance(text, str):
        return text[:BODY_SCAN_BYTES]
    body = getattr(resp, "body", b"") or b""
    if isinstance(body, bytes):
        return body[:BODY_SCAN_BYTES].decode("utf-8", "replace")
    return str(body)[:BODY_SCAN_BYTES]


def _vendor_block(status: int, hdrs: dict[str, str], body: str,
                  cookies: list[str]) -> tuple[str, str, str] | None:
    """(vendor, kind, evidence) for a vendor-fingerprinted block, else None."""
    server = hdrs.get("server", "").lower()
    is_cf = "cf-ray" in hdrs or server.startswith("cloudflare")
    blockish = status in BLOCK_STATUSES

    # Cloudflare. cf-mitigated is Cloudflare's own statement that it
    # challenged the request, whatever the status.
    if hdrs.get("cf-mitigated", "").lower() == "challenge":
        return "Cloudflare", "challenge", "header cf-mitigated: challenge"
    if blockish and is_cf:
        if status == 429:
            return "Cloudflare", "rate-limit", "HTTP 429 with cf-ray"
        for marker in ("/cdn-cgi/challenge-platform/", "challenges.cloudflare.com",
                       "cf-browser-verification", "just a moment...",
                       "checking your browser before accessing"):
            if marker in body:
                return "Cloudflare", "challenge", f"challenge page ({marker!r})"
        for marker in ("attention required! | cloudflare", "sorry, you have been blocked",
                       "cf-error-details", "cloudflare ray id"):
            if marker in body:
                return "Cloudflare", "block", f"block page ({marker!r})"
        m = _CF_ERROR_CODE.search(body)
        if m:
            return "Cloudflare", "block", f"block page ({m.group(0)!r})"

    # Akamai: "Access Denied ... Reference #18.2d351ab8.1557333295.a4e16ab".
    if status == 403 and "access denied" in body:
        m = _AKAMAI_REFERENCE.search(body)
        if m:
            return "Akamai", "block", f"Access Denied page with {m.group(0)}"
        if server.startswith("akamaighost"):
            return "Akamai", "block", "Access Denied page from AkamaiGHost"

    # Imperva / Incapsula. The incident ID line is only on its block page;
    # its resource script is also injected into normal pages, so that marker
    # counts only on an error status.
    if "incapsula incident id" in body:
        return "Imperva Incapsula", "block", "block page with an Incapsula incident ID"
    if blockish and ("_incapsula_resource" in body or (
            "this request was blocked by our security service" in body
            and ("x-iinfo" in hdrs or any(c.startswith("incap_ses_") for c in cookies)))):
        return "Imperva Incapsula", "block", "Imperva block page"

    # AWS WAF: its challenge/CAPTCHA actions say so in a header; its block
    # behind CloudFront is CloudFront's "Request blocked" page; behind an
    # ALB it is the ALB's bare 403.
    action = hdrs.get("x-amzn-waf-action", "").lower()
    if action:
        kind = "challenge" if action in ("challenge", "captcha") else "block"
        return "AWS WAF", kind, f"header x-amzn-waf-action: {action}"
    if status == 403 and "request blocked." in body and "cloudfront" in body:
        return "AWS WAF", "block", "CloudFront 'Request blocked' page"
    if status == 403 and server.startswith("awselb") and "403 forbidden" in body:
        return "AWS WAF", "block", f"bare 403 from {hdrs.get('server')} (WAF rule on an ALB)"

    # Sucuri.
    if any(m in body for m in ("sucuri website firewall - access denied",
                               "access denied - sucuri website firewall",
                               "cloudproxy@sucuri.net")):
        return "Sucuri", "block", "Sucuri Website Firewall block page"
    if status == 403 and ("x-sucuri-id" in hdrs or "x-sucuri-block" in hdrs):
        return "Sucuri", "block", "HTTP 403 with a Sucuri header"

    # F5 BIG-IP ASM serves its default block page with a 200, so the text
    # alone decides.
    if "the requested url was rejected. please consult with your administrator" in body:
        return "F5 BIG-IP ASM", "block", "ASM 'The requested URL was rejected' page"

    # ModSecurity.
    if blockish and ("this error was generated by mod_security" in body
                     or "modsecurity action" in body):
        return "ModSecurity", "block", "ModSecurity error page"

    # Azure.
    if status == 403 and "x-azure-ref" in hdrs and "the request is blocked" in body:
        return "Azure Front Door", "block", "Front Door WAF 'The request is blocked' page"
    if status == 403 and server.startswith("microsoft-azure-application-gateway"):
        return "Azure Application Gateway", "block", f"HTTP 403 from {hdrs.get('server')}"

    # DDoS-Guard.
    if blockish and server.startswith("ddos-guard"):
        return "DDoS-Guard", "challenge", f"HTTP {status} from DDoS-Guard"

    return None


def classify_block(resp: Any) -> Block | None:
    """Was this response a challenge, a block page or rate limiting?

    Takes a `net.Response` or anything with `status`, `headers`, `url` and a
    body. Returns None for anything else, including every failed connection:
    a timeout is not a WAF.
    """
    status = int(getattr(resp, "status", 0) or 0)
    if status <= 0:
        return None
    hdrs = _lower_headers(getattr(resp, "headers", {}))
    cookies = cookie_names(getattr(resp, "set_cookies", []) or [])
    # Akamai, among others, entity-encodes its block page text.
    body = html.unescape(_body_text(resp)).lower()
    url = str(getattr(resp, "url", ""))
    retry_after = hdrs.get("retry-after", "").strip()[:40]

    vendor = _vendor_block(status, hdrs, body, cookies)
    if vendor:
        name, kind, evidence = vendor
        return Block(name, kind, status, url, evidence, retry_after)

    if status == 429:
        who = identify(hdrs, getattr(resp, "set_cookies", []) or [])
        return Block(who[0].name if who else "", "rate-limit", status, url,
                     "HTTP 429 Too Many Requests", retry_after)
    if status == 503 and retry_after:
        who = identify(hdrs, getattr(resp, "set_cookies", []) or [])
        return Block(who[0].name if who else "", "rate-limit", status, url,
                     f"HTTP 503 with Retry-After: {retry_after}", retry_after)
    return None


# ---------------------------------------------------------------------------
# Watching a unit of work for blocks
# ---------------------------------------------------------------------------

@dataclass
class BlockLog:
    blocks: list[Block] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.blocks)


_local = threading.local()


@contextlib.contextmanager
def watch() -> Iterator[BlockLog]:
    """Collect every block that `net.fetch` sees on this thread until exit.

    Thread-local, so each probe running in the worker pool has its own log.
    Nested watches shadow the outer one.
    """
    log = BlockLog()
    previous = getattr(_local, "log", None)
    _local.log = log
    try:
        yield log
    finally:
        _local.log = previous


def observe(resp: Any) -> Block | None:
    """Called by `net.fetch` for every response it returns."""
    log = getattr(_local, "log", None)
    if log is None:
        return None
    block = classify_block(resp)
    if block is not None:
        log.blocks.append(block)
    return block


def summarise(blocks: list[Block]) -> str:
    """'3 request(s) challenged by Cloudflare (HTTP 403)', for a gap's reason."""
    if not blocks:
        return "no blocks"
    vendor = Counter(b.vendor or "an unidentified filter" for b in blocks).most_common(1)[0][0]
    kinds = sorted({b.kind for b in blocks})
    verbs = "/".join({"challenge": "challenged", "block": "blocked",
                      "rate-limit": "rate-limited"}.get(k, k) for k in kinds)
    statuses = ", ".join(str(s) for s in sorted({b.status for b in blocks}))
    retry = next((b.retry_after for b in blocks if b.retry_after), "")
    return (f"{len(blocks)} request(s) {verbs} by {vendor} (HTTP {statuses}"
            + (f", Retry-After {retry}" if retry else "") + ")")


class Blocked(Exception):
    """A unit of work completed, but some of its requests were blocked.

    Carries whatever the work produced, so the pipeline can keep it while
    still recording the gap and leaving the work unmarked for a retry.
    """

    def __init__(self, blocks: list[Block], findings: list | None = None,
                 leads: list | None = None):
        self.blocks = list(blocks)
        self.findings = list(findings or [])
        self.leads = list(leads or [])
        super().__init__(summarise(self.blocks))


def _remedy(blocks: list[Block], retry_cmd: str) -> str:
    waits = next((b.retry_after for b in blocks if b.retry_after), "")
    rate = any(b.kind == "rate-limit" for b in blocks)
    advice = ("Ask the client to allowlist the scanner's source address at the "
              "WAF/CDN (or to put the origin address in scope), then "
              f"`{retry_cmd}`.")
    if rate:
        advice = ("Raise `http.inter_request_delay` or lower `max_workers`"
                  + (f" (the server asked for a {waits}s wait)" if waits else "")
                  + ", or ask for the scanner to be allowlisted, then "
                  f"`{retry_cmd}`.")
    return advice


def probe_gap(probe: str, service_id: str, host: str, blocks: list[Block]) -> Degradation:
    """The gap for a probe whose requests were blocked on one service."""
    vendor = Counter(b.vendor or "an unidentified filter" for b in blocks).most_common(1)[0][0]
    return Degradation(
        stage=f"probe:{probe}", component=probe,
        reason=f"{service_id}: {summarise(blocks)}; first at {blocks[0].url} "
               f"({blocks[0].evidence})"[:300],
        impact=f"The {probe} check on {service_id} was blocked or challenged by "
               f"{vendor}, so its results for this service are unreliable: it may "
               "have assessed the block page rather than the application. Absence "
               "of findings here is not evidence that nothing is exposed.",
        severity="serious", hosts=[host],
        remedy=_remedy(blocks, f"extscan probe <run> --only {probe}"),
    )


CHASE_COMPONENT = "waf"


def chase_gap(lead_id: str, lead_kind: str, target: str, host: str,
              blocks: list[Block]) -> Degradation:
    """The gap for a follow-up whose requests were blocked."""
    vendor = Counter(b.vendor or "an unidentified filter" for b in blocks).most_common(1)[0][0]
    return Degradation(
        stage="chase", component=CHASE_COMPONENT,
        reason=f"lead {lead_id} ({lead_kind}): {summarise(blocks)} "
               f"({blocks[0].evidence})"[:300],
        impact=f"The {lead_kind} follow-up on {target} was blocked or challenged by "
               f"{vendor}, so what it exposes is unassessed. Its partial results were "
               "discarded and the lead stays open for a retry.",
        severity="serious", hosts=[host] if host else [],
        remedy=_remedy(blocks, "extscan chase <run>"),
    )


def edge_gap(probe: str, service_id: str, host: str, matches: list[EdgeMatch]) -> Degradation:
    """The note that a service's results describe its CDN/WAF edge."""
    label = edge_label(matches)
    return Degradation(
        stage=f"probe:{probe}", component=probe,
        reason=f"{service_id}: behind {label}; "
               + "; ".join(m.evidence for m in matches)[:200],
        impact=f"{service_id} is served through {label}. Findings for it, and their "
               "absence, describe the edge rather than the origin server: the edge "
               "can filter or rewrite checks without visibly blocking them, and the "
               "origin may be reachable directly with more exposed.",
        severity="warning", hosts=[host],
        remedy="Ask the client for the origin address and, if it is authorised, add "
               "it to the scope and test it directly.",
    )
