"""Website fingerprinting: favicon hashes, technology detection, page grouping.

Three things a reviewer wants from a web estate that a per-service banner does
not give:

* **Favicon hashes.** The Shodan-convention favicon hash (MurmurHash3 x86_32,
  signed, over `base64.encodebytes` of the icon bytes) is the usual pivot for
  "which other hosts run this appliance". It is recorded with MD5 and SHA-256
  so it can be matched against any other source. extscan never looks the hash
  up anywhere: sending target data to a third party is the reviewer's call.
* **Technology detection.** `webtech.detect` over the root response. Edge
  appliances (VPNs, gateways, load-balancer management) get their own finding
  flagged for review, because that is where exploitation-led breaches start.
* **Near-duplicate pages.** A normalised fingerprint of each root page, so the
  report can say "these 14 services serve the same default page". The
  fingerprint is stored in the finding's tags and grouped at report time,
  which keeps grouping correct across `resume` and partial re-probes.

Every request goes through `net.fetch`, so scope checks (per redirect hop) and
timeouts apply. A missing favicon is normal and is recorded, not raised; a
service that does not answer at all raises, so the pipeline records a
coverage gap and leaves the service unmarked for `resume` to retry.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
import time
import urllib.parse
from dataclasses import dataclass, field

from extscan.models import Finding, Lead, Service
from extscan.policy import HttpPolicy
from extscan.scope import Scope
from extscan.tools import net, webtech

# --- MurmurHash3 x86_32 ----------------------------------------------------

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_M32 = 0xFFFFFFFF


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _M32


def murmur3_32(data: bytes | str, seed: int = 0, signed: bool = True) -> int:
    """MurmurHash3 x86_32, matching `mmh3.hash` (signed) by default.

    Pure Python port of Austin Appleby's public-domain reference
    (MurmurHash3.cpp, `MurmurHash3_x86_32`). A str is hashed as UTF-8, as
    mmh3 does.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    length = len(data)
    h = seed & _M32
    nblocks = length // 4
    if nblocks:
        for k in struct.unpack_from(f"<{nblocks}I", data):
            k = (k * _C1) & _M32
            k = ((k << 15) | (k >> 17)) & _M32
            k = (k * _C2) & _M32
            h ^= k
            h = ((h << 13) | (h >> 19)) & _M32
            h = (h * 5 + 0xE6546B64) & _M32

    tail = data[nblocks * 4:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * _C1) & _M32
        k = _rotl(k, 15)
        k = (k * _C2) & _M32
        h ^= k

    h ^= length & _M32
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _M32
    h ^= h >> 16
    if signed and h & 0x80000000:
        return h - 0x100000000
    return h


def favicon_hash(data: bytes) -> int:
    """Shodan's `http.favicon.hash`: mmh3 of the MIME-style base64 of the bytes.

    `base64.encodebytes` inserts a newline every 76 characters and ends with
    one; the hash is taken over that text, newlines included.
    """
    return murmur3_32(base64.encodebytes(data))


@dataclass
class Favicon:
    url: str
    status: int = 0
    size: int = 0
    content_type: str = ""
    mmh3: int | None = None
    md5: str = ""
    sha256: str = ""
    note: str = ""

    @property
    def hashed(self) -> bool:
        return self.mmh3 is not None

    def line(self) -> str:
        if not self.hashed:
            return f"favicon {self.url}: not hashed ({self.note})"
        return (f"favicon {self.url}: mmh3={self.mmh3} md5={self.md5} "
                f"sha256={self.sha256} ({self.size} bytes, "
                f"{self.content_type or 'no content-type'})")


def hash_icon(url: str, data: bytes, content_type: str = "", status: int = 200) -> Favicon:
    return Favicon(url=url, status=status, size=len(data), content_type=content_type,
                   mmh3=favicon_hash(data), md5=hashlib.md5(data).hexdigest(),  # noqa: S324
                   sha256=hashlib.sha256(data).hexdigest())


def _is_icon(resp: net.Response) -> str:
    """Empty string if the response looks like an icon, else why not.

    The common false favicon is an SPA or soft-404 serving its HTML shell for
    every path; hashing that would group unrelated sites by their error page.
    """
    if resp.status == 0:
        return resp.error[:160] or "no response"
    if not resp.ok:
        return f"HTTP {resp.status}"
    if not resp.body:
        return "empty body"
    if resp.truncated:
        return "larger than max_body_bytes; a partial hash would be meaningless"
    head = resp.body[:256].lstrip().lower()
    if "html" in resp.content_type or head.startswith((b"<!doctype html", b"<html")):
        return "served HTML, not an image (soft 404)"
    return ""


_DATA_URI = re.compile(r"^data:([^;,]*)(;base64)?,(.*)$", re.I | re.S)


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urllib.parse.urlsplit(url)
    scheme = p.scheme.lower()
    try:
        port = p.port or {"http": 80, "https": 443}.get(scheme)
    except ValueError:
        port = None
    return scheme, (p.hostname or "").lower(), port


def fetch_favicons(base: str, page_url: str, icon_hrefs: list[str], scope: Scope,
                   policy: HttpPolicy) -> list[Favicon]:
    """/favicon.ico, plus the first same-origin `<link rel=icon>` on the page."""
    out: list[Favicon] = []
    seen: set[str] = set()
    candidates = [base.rstrip("/") + "/favicon.ico"]
    origin = _origin(base)
    for href in icon_hrefs[:5]:
        m = _DATA_URI.match(href)
        if m:
            if not m.group(2):
                continue
            try:
                data = base64.b64decode(m.group(3).strip(), validate=False)
            except (binascii.Error, ValueError):
                continue
            if data and len(data) <= policy.max_body_bytes:
                out.append(hash_icon("data: URI in <link rel=icon>", data, m.group(1)))
                seen.add(out[-1].sha256)
            break
        url = urllib.parse.urljoin(page_url, href)
        if _origin(url) != origin:
            out.append(Favicon(url=url, note="icon link is cross-origin; not fetched"))
            break
        if url not in candidates:
            candidates.append(url)
        break

    for i, url in enumerate(candidates):
        if i and policy.inter_request_delay:
            time.sleep(policy.inter_request_delay)
        resp = net.fetch(url, scope, policy)
        why = _is_icon(resp)
        if why:
            out.append(Favicon(url=url, status=resp.status, note=why))
            continue
        fav = hash_icon(url, resp.body, resp.content_type, resp.status)
        if fav.sha256 in seen:
            continue
        seen.add(fav.sha256)
        out.append(fav)
    return out


# --- page fingerprint ------------------------------------------------------

_COMMENT = re.compile(r"<!--.*?-->", re.S)
_VOLATILE = [
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    re.compile(r"\b[0-9a-f]{8,}\b"),                     # hex ids, hashes, etags
    re.compile(r"[a-z0-9+_\-]{24,}={0,2}"),              # tokens, nonces, viewstate
    re.compile(r"\d+"),                                  # times, dates, counters, ips
]
_TOKEN = re.compile(r"</?[a-z][a-z0-9\-]*|[a-z_]+")
SIMHASH_DISTANCE = 3


@dataclass
class PageFingerprint:
    digest: str = ""          # exact match on normalised content
    simhash: str = ""         # near-duplicate match
    tokens: int = 0

    @property
    def empty(self) -> bool:
        return not self.tokens


def normalise_page(body: str, host: str = "") -> list[str]:
    """Tokens of a page with the parts that vary per request taken out.

    Comments, the service's own host name, and anything that looks like a
    token, id, timestamp or counter are removed; what remains is tag names and
    words, which is what makes two default pages "the same page".
    """
    text = _COMMENT.sub(" ", (body or "")[:500_000]).lower()
    if host:
        text = text.replace(host.lower(), " ")
    for rx in _VOLATILE:
        text = rx.sub(" ", text)
    return _TOKEN.findall(text)


def _simhash(tokens: list[str]) -> int:
    if len(tokens) < 3:
        features = tokens
    else:
        features = [" ".join(tokens[i:i + 3]) for i in range(len(tokens) - 2)]
    weights = [0] * 64
    for feat in features:
        h = int.from_bytes(hashlib.blake2b(feat.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if h >> bit & 1 else -1
    return sum(1 << bit for bit in range(64) if weights[bit] > 0)


def page_fingerprint(body: str, host: str = "") -> PageFingerprint:
    tokens = normalise_page(body, host)
    if not tokens:
        return PageFingerprint()
    digest = hashlib.sha256(" ".join(tokens).encode()).hexdigest()[:16]
    return PageFingerprint(digest=digest, simhash=f"{_simhash(tokens):016x}",
                           tokens=len(tokens))


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


# --- grouping at report time -----------------------------------------------

TAG = "webfp"
_PAGE_TAG = "page-hash:"
_SIM_TAG = "page-simhash:"


@dataclass
class PageGroup:
    services: list[str] = field(default_factory=list)
    titles: list[str] = field(default_factory=list)
    digest: str = ""
    exact: bool = True


def _tag_value(f: Finding, prefix: str) -> str:
    return next((t[len(prefix):] for t in f.tags if t.startswith(prefix)), "")


def _title_of(f: Finding) -> str:
    for line in (f.evidence or "").splitlines():
        if line.startswith("page title: "):
            return line[len("page title: "):].strip()
    return ""


def page_groups(findings: list[Finding], min_size: int = 2,
                distance: int = SIMHASH_DISTANCE) -> list[PageGroup]:
    """Services whose root pages are identical or near-identical.

    Exact matches on the normalised digest group first; simhash within
    `distance` bits then joins near-duplicates (a per-request token or a
    version string the normaliser missed). Largest groups first.
    """
    rows: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for f in findings:
        if TAG not in f.tags:
            continue
        digest, sim = _tag_value(f, _PAGE_TAG), _tag_value(f, _SIM_TAG)
        target = f"{f.host}:{f.port}" if f.port else f.host
        if not digest or not sim or target in seen:
            continue
        seen.add(target)
        rows.append((target, digest, sim, _title_of(f)))

    parent = list(range(len(rows)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            if rows[i][1] == rows[j][1] or hamming(rows[i][2], rows[j][2]) <= distance:
                parent[find(i)] = find(j)

    clusters: dict[int, list[int]] = {}
    for i in range(len(rows)):
        clusters.setdefault(find(i), []).append(i)

    groups = []
    for members in clusters.values():
        if len(members) < min_size:
            continue
        digests = {rows[i][1] for i in members}
        titles = sorted({rows[i][3] for i in members if rows[i][3]})
        groups.append(PageGroup(services=sorted(rows[i][0] for i in members),
                                titles=titles, digest=sorted(digests)[0],
                                exact=len(digests) == 1))
    groups.sort(key=lambda g: (-len(g.services), g.services))
    return groups


# --- the probe -------------------------------------------------------------

def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def probe_web_fingerprint(svc: Service, scope: Scope,
                          policy: HttpPolicy) -> tuple[list[Finding], list[Lead]]:
    base = svc.base_url()
    resp = net.fetch(base, scope, policy)
    if resp.status == 0:
        if resp.error.startswith("scope refusal") and resp.redirect_chain:
            return [Finding(
                title=f"Web fingerprint of {svc.host}:{svc.port}: redirects out of scope",
                severity="info", host=svc.host, port=svc.port, proto=svc.proto,
                source="extscan:webfp",
                description=f"The root page at {base} redirects to a URL outside the "
                            "agreed scope, so it was not followed and the site behind "
                            "it was not fingerprinted.",
                evidence="\n".join(["redirects:", *resp.redirect_chain, resp.error])[:2000],
                confidence="tentative", tags=["http", "fingerprint", "out-of-scope-redirect"],
            )], []
        # The service did not answer: a coverage gap, not a clean result.
        raise RuntimeError(f"root page fetch failed: {resp.error or 'no response'}")

    body = resp.text
    parts = webtech.parse_page(body)
    urls = [base, resp.url] + [hop.rsplit(" -> ", 1)[-1] for hop in resp.redirect_chain]
    techs = webtech.detect(resp.headers, body, urls, parts)
    page = page_fingerprint(body, svc.host)

    if policy.inter_request_delay:
        time.sleep(policy.inter_request_delay)
    icons = fetch_favicons(base, resp.url or base, parts.icons, scope, policy)

    evidence = [f"GET {base} -> {resp.status} {resp.reason}".rstrip()]
    if resp.redirect_chain:
        evidence += ["redirects:"] + [f"  {hop}" for hop in resp.redirect_chain]
    if parts.title:
        evidence.append(f"page title: {parts.title}")
    if page.empty:
        evidence.append("page fingerprint: none (empty page after normalisation)")
    else:
        evidence.append(f"page fingerprint: {page.digest} simhash={page.simhash} "
                        f"tokens={page.tokens}")
    evidence += [fav.line() for fav in icons]
    if techs:
        evidence.append("technologies:")
        for t in techs:
            flag = " [edge]" if t.edge else ""
            evidence.append(f"  {t.label}{flag} ({t.confidence}): " + "; ".join(t.evidence[:4]))
    else:
        evidence.append("technologies: none matched")

    tags = ["http", "fingerprint", TAG]
    if not page.empty:
        tags += [f"{_PAGE_TAG}{page.digest}", f"{_SIM_TAG}{page.simhash}"]
    tags += [f"favicon-mmh3:{fav.mmh3}" for fav in icons if fav.hashed]
    tags += [f"tech:{_slug(t.name)}" for t in techs]

    hashed = [fav for fav in icons if fav.hashed]
    desc = [f"Fingerprint of the root page at {base}."]
    if techs:
        desc.append("Detected: " + ", ".join(t.label for t in techs) + ".")
    if hashed:
        desc.append("The favicon hash follows the Shodan convention "
                    f"(`http.favicon.hash:{hashed[0].mmh3}`), so a reviewer can pivot on it "
                    "to find related assets. extscan did not look it up; doing so shares "
                    "the hash with that service, so check the engagement terms first.")

    findings = [Finding(
        title=f"Web fingerprint of {svc.host}:{svc.port}",
        severity="info", host=svc.host, port=svc.port, proto=svc.proto,
        source="extscan:webfp", description=" ".join(desc),
        evidence="\n".join(evidence)[:4000], tags=tags,
    )]

    for t in techs:
        if not t.edge:
            continue
        findings.append(Finding(
            title=f"Edge appliance identified: {t.label} on {svc.host}:{svc.port}",
            severity="info", host=svc.host, port=svc.port, proto=svc.proto,
            source="extscan:webfp",
            description=f"{base} looks like {t.name} ({t.category}). Internet-facing "
                        "edge products are the most exploited class of software, often "
                        "before a patch exists, so an accurate inventory is what lets "
                        "the client act the day an advisory drops."
                        + (f" {t.note}" if t.note else ""),
            evidence="\n".join(t.evidence)[:2000],
            recommendation="Confirm the product and exact build with the owner, check it "
                           "against current vendor advisories and the CISA KEV catalogue, "
                           "and restrict management interfaces to known sources.",
            review_required=True,
            review_reason=f"Confirm this is {t.name}, establish the running version, and "
                          "check it against current vendor advisories. Version evidence "
                          "from a web page is indicative only.",
            confidence=t.confidence,
            tags=["http", "fingerprint", "edge-appliance", f"tech:{_slug(t.name)}"],
            references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
        ))
    return findings, []
