"""Enrichment: which findings are being exploited, and which hosts are a CDN.

Two questions a scanner cannot answer from the target alone, both settled by
public lists:

* is this CVE known to be exploited (CISA KEV), and how likely is exploitation
  (EPSS)? That decides what a reviewer looks at first. It never changes a
  finding's severity.
* does this address belong to a CDN or cloud edge? Then the ports and
  banners found on it describe the provider's front end, shared with other
  tenants, and not the client's origin server.

The lists are plain downloads and nothing about the client is sent. They are
still egress from a scanning box, so: the stage can be disabled, every
download is cached and shared between runs, a dry run fetches nothing, and a
list that cannot be had is a coverage gap rather than a quiet "nothing is
exploited".
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, Host
from .policy import Policy
from .resilience import Degradation
from .scope import Scope
from .store import Store

STAGE = "enrich"
# Not "extscan:edge": that is the HTTP probe's finding for one service whose
# response headers name an edge product. This one is about address ranges.
EDGE_SOURCE = "extscan:network"
# Set in the environment to treat the stage as disabled whatever the policy
# says: for air-gapped boxes, and for the test suite, which has no network.
OFFLINE_ENV = "EXTSCAN_OFFLINE"

EPSS_ATTRIBUTION = ("EPSS scores are from FIRST's Exploit Prediction Scoring System "
                    "(https://www.first.org/epss/).")
KEV_REVIEW_REASON = ("Listed in CISA's Known Exploited Vulnerabilities catalogue: this is "
                     "being exploited in the wild. Confirm whether the service is really "
                     "affected before anything else in the queue.")

MAX_DOWNLOAD = 300 * 1024 * 1024
MAX_CVES_PER_FINDING = 200

CVE_RE = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.I)
# A reference counts only when it points at the CVE's own record. A template
# for a misconfiguration may cite a blog post about some related CVE.
_CVE_RECORD_URL_RE = re.compile(
    r"(?:nvd\.nist\.gov/vuln/detail/|cve\.org/CVERecord\?id=|"
    r"cve\.mitre\.org/cgi-bin/cvename\.cgi\?name=)(CVE-\d{4}-\d{4,7})\b", re.I)
_VULNERS_SOURCE_RE = re.compile(r"^nmap-(?:tcp|udp):vulners")
# nmap's vulns library prints "State: VULNERABLE" and an "IDs:" line. A
# script that merely ran, or says NOT VULNERABLE, names no CVE of the host.
_NSE_VULNERABLE_RE = re.compile(r"State:\s+(?:LIKELY\s+)?VULNERABLE", re.I)


class FeedError(Exception):
    """A feed could not be fetched or did not parse."""


# --- CVE ids ----------------------------------------------------------------

def is_version_match(f: Finding) -> bool:
    """True when the finding's CVEs are candidates matched on a version
    string (nmap's vulners script), not vulnerabilities that were observed."""
    return "version-match" in f.tags or bool(_VULNERS_SOURCE_RE.match(f.source))


def extract_cves(f: Finding) -> list[str]:
    """CVE ids the finding is about, from the places a tool states them.

    Deliberately not a search of the evidence: a response body can mention
    any CVE (a changelog, a blog page). The two exceptions are structured
    scanner output, where the tool itself is naming the CVEs.
    """
    found: list[str] = [c for c in f.cves if CVE_RE.fullmatch(str(c))]
    template = f.source.split(":", 1)[1] if ":" in f.source else ""
    m = CVE_RE.match(template)            # nuclei template ids: CVE-2021-44228
    if m:
        found.append(m.group(0))
    found += [t for t in f.tags if CVE_RE.fullmatch(str(t))]
    for ref in f.references:
        found += _CVE_RECORD_URL_RE.findall(str(ref))
    found += CVE_RE.findall(f.title)
    if is_version_match(f):
        found += CVE_RE.findall(f.evidence)
    elif f.source.startswith("nmap-") and _NSE_VULNERABLE_RE.search(f.evidence):
        for line in f.evidence.splitlines():
            if "IDs:" in line:
                found += CVE_RE.findall(line)
    out: list[str] = []
    for cve in found:
        cve = cve.upper()
        if cve not in out:
            out.append(cve)
    return out[:MAX_CVES_PER_FINDING]


def badge(f: Finding) -> str:
    """Short exploitation label for tables and one-line listings."""
    parts = []
    if f.kev:
        parts.append("KEV" + (" (version match)" if is_version_match(f) else ""))
    if f.epss is not None:
        parts.append(f"EPSS {f.epss:.2f}")
    return " · ".join(parts)


def cve_lines(f: Finding) -> list[str]:
    """Plain-text lines describing a finding's CVE data, for the renderers."""
    if not f.cves:
        return []
    shown = ", ".join(f.cves[:12]) + (f" (+{len(f.cves) - 12} more)" if len(f.cves) > 12 else "")
    lines = ["CVE: " + shown]
    if is_version_match(f):
        lines.append("These are candidates matched on the detected version string. "
                     "Nothing was observed that confirms any of them.")
    for k in f.kev_detail:
        line = f"CISA KEV: {k.get('cve', '?')} is known to be exploited"
        if k.get("date_added"):
            line += f" (listed {k['date_added']}"
            line += f", remediation due {k['due_date']})" if k.get("due_date") else ")"
        if k.get("ransomware"):
            line += "; used in ransomware campaigns"
        lines.append(line + ".")
    if f.epss is not None:
        line = f"EPSS: {f.epss:.3f}"
        if f.epss_percentile is not None:
            line += f" (percentile {f.epss_percentile:.3f})"
        if f.epss_cve and len(f.cves) > 1:
            line += f" for {f.epss_cve}, the highest of this finding's CVEs"
        lines.append(line + ".")
    return lines


# --- downloads and the cache -------------------------------------------------

Fetcher = Callable[[str, Path, float], None]


def url_fetcher(use_system_proxy: bool = False) -> Fetcher:
    """The real download. Streams to disk, so EPSS never sits in memory."""
    def fetch(url: str, dest: Path, timeout: float) -> None:
        if urllib.parse.urlsplit(url).scheme not in ("https", "http", "file"):
            raise FeedError(f"unsupported URL scheme in {url!r}")
        handlers: list = []
        if not use_system_proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers={  # noqa: S310
            "User-Agent": "extscan (vulnerability feed download)"})
        total = 0
        with opener.open(req, timeout=timeout) as resp, dest.open("wb") as fh:
            while True:
                block = resp.read(1 << 16)
                if not block:
                    break
                total += len(block)
                if total > MAX_DOWNLOAD:
                    raise FeedError(f"{url} is larger than {MAX_DOWNLOAD} bytes")
                fh.write(block)
    return fetch


@dataclass
class Fetched:
    path: Path
    url: str
    fetched_at: float
    from_cache: bool = False
    stale_because: str = ""     # set when a refresh failed and an old copy is used

    def info(self) -> dict:
        out = {"url": self.url, "fetched": _day(self.fetched_at),
               "from_cache": self.from_cache}
        if self.stale_because:
            out["stale"] = self.stale_because
        return out


def _day(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(epoch))


@dataclass
class FeedCache:
    """Downloads kept on disk and reused until they are `max_age` seconds old."""

    directory: Path
    max_age: float
    fetcher: Fetcher
    timeout: float = 30.0
    now: Callable[[], float] = time.time

    def _paths(self, url: str) -> tuple[Path, Path]:
        tail = re.sub(r"[^A-Za-z0-9.-]+", "_", url.rstrip("/").rsplit("/", 1)[-1])[:40]
        name = hashlib.sha256(url.encode()).hexdigest()[:16] + "-" + (tail or "feed")
        return self.directory / name, self.directory / (name + ".meta.json")

    def _cached(self, url: str) -> Fetched | None:
        path, meta = self._paths(url)
        try:
            fetched_at = float(json.loads(meta.read_text())["fetched_at"])
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if not path.is_file():
            return None
        return Fetched(path, url, fetched_at, from_cache=True)

    def fresh(self, url: str) -> Fetched | None:
        hit = self._cached(url)
        if hit and 0 <= self.now() - hit.fetched_at < self.max_age:
            return hit
        return None

    def get(self, url: str) -> Fetched:
        """A fresh copy from the cache, or a download. When the download
        fails and an older copy exists, that copy is returned marked stale:
        last week's catalogue ranks better than none, as long as it says so."""
        hit = self.fresh(url)
        if hit:
            return hit
        path, meta = self._paths(url)
        tmp = path.with_name(path.name + ".part")
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            self.fetcher(url, tmp, self.timeout)
            tmp.replace(path)
            fetched_at = self.now()
            meta.write_text(json.dumps({"url": url, "fetched_at": fetched_at}))
            return Fetched(path, url, fetched_at)
        except (OSError, urllib.error.URLError, FeedError, ValueError) as exc:
            tmp.unlink(missing_ok=True)
            reason = f"{type(exc).__name__}: {exc}"[:200]
            old = self._cached(url)
            if old:
                old.stale_because = reason
                return old
            raise FeedError(reason) from exc

    def discard(self, url: str) -> None:
        """Forget a download that did not parse, so the next run fetches
        again instead of reusing a broken file for a day."""
        for p in self._paths(url):
            p.unlink(missing_ok=True)


# --- feed formats -----------------------------------------------------------

def load_kev(path: Path, wanted: set[str]) -> tuple[dict, dict[str, dict]]:
    """Read the CISA KEV JSON. Returns (catalogue info, entries for `wanted`)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        rows = data["vulnerabilities"]
        entries = {str(r["cveID"]).upper(): r for r in rows}
    except (ValueError, KeyError, TypeError) as exc:
        raise FeedError(f"KEV catalogue did not parse: {type(exc).__name__}: {exc}") from exc
    if not entries:
        raise FeedError("KEV catalogue is empty")
    info = {"catalog_version": str(data.get("catalogVersion", "")),
            "date_released": str(data.get("dateReleased", "")), "count": len(entries)}
    return info, {cve: entries[cve] for cve in wanted if cve in entries}


def load_epss(path: Path, wanted: set[str]) -> tuple[dict, dict[str, tuple[float, float]]]:
    """Read the EPSS daily CSV (gzip or plain), one row at a time.

    The file has about 300,000 rows. Only the rows for `wanted` are kept, so
    memory is a few entries whatever the size of the file.
    """
    info = {"model_version": "", "score_date": "", "rows": 0}
    scores: dict[str, tuple[float, float]] = {}
    try:
        with path.open("rb") as probe:
            gzipped = probe.read(2) == b"\x1f\x8b"
        opener = gzip.open if gzipped else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            header_seen = False
            for line in fh:
                line = line.strip()
                if line.startswith("#"):
                    for part in line.lstrip("#").split(","):
                        key, _, value = part.partition(":")
                        if key.strip() in ("model_version", "score_date"):
                            info[key.strip()] = value.strip()
                    continue
                if not header_seen:
                    if line.lower().split(",")[:3] != ["cve", "epss", "percentile"]:
                        raise FeedError(f"EPSS file has an unexpected header: {line[:80]!r}")
                    header_seen = True
                    continue
                info["rows"] += 1
                cve, _, rest = line.partition(",")
                cve = cve.upper()
                if cve in wanted:
                    score, _, pct = rest.partition(",")
                    scores[cve] = (float(score), float(pct or 0))
    except (OSError, EOFError, ValueError) as exc:
        raise FeedError(f"EPSS file did not parse: {type(exc).__name__}: {exc}") from exc
    if not info["rows"]:
        raise FeedError("EPSS file has no scores")
    return info, scores


def _network(text: object):
    """A plausible published range, or None. A prefix as wide as a /7 is a
    broken or hostile list, and would tag the whole scope as a CDN."""
    if not isinstance(text, str) or "/" not in text:
        return None
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None
    floor = 8 if net.version == 4 else 16
    return net if net.prefixlen >= floor else None


def _walk_strings(node) -> Iterable[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_strings(value)


def parse_ranges(provider: str, text: str) -> list:
    """Networks in one published range document.

    Cloudflare publishes one CIDR per line; Fastly and Google publish JSON,
    read here as "every CIDR in the document". AWS lists every service in one
    file, so only its CLOUDFRONT rows count.
    """
    try:
        doc = json.loads(text)
    except ValueError:
        candidates: Iterable = (line.split("#")[0] for line in text.splitlines())
    else:
        if provider == "cloudfront" and isinstance(doc, dict):
            rows = [*(doc.get("prefixes") or []), *(doc.get("ipv6_prefixes") or [])]
            candidates = [r.get("ip_prefix") or r.get("ipv6_prefix") for r in rows
                          if isinstance(r, dict) and r.get("service") == "CLOUDFRONT"]
        else:
            candidates = _walk_strings(doc)
    nets = [n for n in map(_network, candidates) if n is not None]
    if not nets:
        raise FeedError(f"no address ranges found in the {provider} list")
    return nets


# Providers whose published list is customer address space, not only a shared
# front end. An address in one of these may be the client's own machine.
CLOUD_NOT_EDGE = {"google-cloud"}
PROVIDER_LABEL = {"cloudflare": "Cloudflare", "cloudfront": "Amazon CloudFront",
                  "fastly": "Fastly", "google": "Google", "google-cloud": "Google Cloud"}


@dataclass
class RangeIndex:
    """Longest-prefix lookup over all providers' ranges.

    Keyed by (IP version, prefix length), so a lookup costs one dict probe per
    distinct prefix length instead of one comparison per range per host.
    """

    tables: dict[tuple[int, int], dict[int, tuple[str, str]]] = field(default_factory=dict)

    def add(self, provider: str, nets: Iterable) -> None:
        for net in nets:
            table = self.tables.setdefault((net.version, net.prefixlen), {})
            key = int(net.network_address) >> (net.max_prefixlen - net.prefixlen)
            # Google lists some prefixes both as Google and as Google Cloud.
            # Keep the weaker claim: it may be the client's own machine.
            if key not in table or provider in CLOUD_NOT_EDGE:
                table[key] = (provider, str(net))

    def lookup(self, ip: str) -> tuple[str, str] | None:
        """(provider, matching prefix) for the most specific range, or None."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        value = int(addr)
        lengths = sorted((plen for version, plen in self.tables if version == addr.version),
                         reverse=True)
        for plen in lengths:
            hit = self.tables[(addr.version, plen)].get(value >> (addr.max_prefixlen - plen))
            if hit:
                return hit
        return None


def edge_finding(provider: str, matches: list[tuple[str, str]]) -> Finding:
    """One info finding per provider, listing the tagged addresses."""
    label = PROVIDER_LABEL.get(provider, provider)
    lines = [f"{ip}  in {prefix}" for ip, prefix in matches[:300]]
    if len(matches) > 300:
        lines.append(f"... and {len(matches) - 300} more (`extscan hosts <run> --json`, network={provider})")
    if provider in CLOUD_NOT_EDGE:
        title = f"In-scope addresses are in {label} address space"
        description = (
            f"{len(matches)} in-scope address(es) fall inside ranges {label} publishes for "
            "its customers. Such an address may be the client's own virtual machine, or a "
            "shared load-balancer front end that other tenants also use. Until that is "
            "settled, port and service results for these addresses may describe the "
            "provider's front end and not the client's origin server.")
        question = ("Confirm with the client whether each address is their own instance or "
                    "a shared front end, and that the provider's testing policy allows the "
                    "scan.")
    else:
        title = f"In-scope addresses are served from the {label} edge network"
        description = (
            f"{len(matches)} in-scope address(es) fall inside ranges {label} publishes for "
            "its edge. Port and service results for these addresses describe the "
            "provider's edge, not the client's origin server, and other tenants share the "
            "address. Open ports, TLS settings and server banners found there are the "
            "provider's, and the origin behind them was not tested.")
        question = ("Decide how findings on these addresses are reported, and ask the "
                    "client for the origin addresses if the origin is meant to be in "
                    "scope. Check the provider's policy on testing through its edge.")
    return Finding(
        title=title, severity="info", host="", port=None, source=EDGE_SOURCE,
        description=description, evidence="\n".join(lines),
        recommendation="Add the origin servers to the scope if they are to be assessed, "
                       "and confirm they only accept traffic from the provider.",
        review_required=True, review_reason=question, tags=["edge", provider],
    )


# --- the stage --------------------------------------------------------------

def disabled_reason(policy: Policy) -> str:
    if not policy.enrich.enabled:
        return "enrich.enabled is false in the policy"
    if os.environ.get(OFFLINE_ENV):
        return f"{OFFLINE_ENV} is set in the environment"
    return ""


def cache_for(store: Store, policy: Policy, fetcher: Fetcher | None = None) -> FeedCache:
    ep = policy.enrich
    directory = (Path(ep.cache_dir).expanduser() if ep.cache_dir
                 else store.path.parent / ".feed-cache")
    return FeedCache(directory=directory, max_age=ep.cache_max_age_hours * 3600,
                     fetcher=fetcher or url_fetcher(policy.http.use_system_proxy),
                     timeout=ep.timeout_sec)


def _plan(cache: FeedCache, urls: list[str]) -> None:
    for url in urls:
        hit = cache.fresh(url)
        if hit:
            print(f"  [dry-run] would reuse the copy of {url} fetched {_day(hit.fetched_at)}")
        else:
            print(f"  [dry-run] would fetch {url}")


def _gap(store: Store, component: str, deg: Degradation | None) -> None:
    """Record `deg` as the one gap for this component, or clear the component.

    Added before the old ones go, so a crash in between never drops a gap.
    """
    if deg:
        store.add_degradation(deg)
        print(f"  ! {deg.reason}")
        print(f"    {deg.impact}")
    store.remove_degradations(lambda d: (
        d.stage == STAGE and d.component == component
        and (deg is None or d.reason != deg.reason)))


def _feed(store: Store, cache: FeedCache, component: str, label: str, url: str,
          load: Callable, wanted: set[str], affected: int):
    """Fetch and parse one scoring feed. Returns (info, data), or (None, None)
    with a gap recorded."""
    remedy = (f"Check egress to {url}, or point enrich.{component}_url at a mirror or a "
              "file:// copy, then `extscan enrich <run>`.")
    try:
        got = cache.get(url)
        try:
            info, data = load(got.path, wanted)
        except FeedError:
            cache.discard(url)
            raise
    except FeedError as exc:
        _gap(store, component, Degradation(
            stage=STAGE, component=component,
            reason=f"{label} could not be loaded: {exc}"[:300],
            impact=f"Findings are not ranked by exploitation using {label}: "
                   f"{affected} finding(s) carry CVE ids that were not looked up. A "
                   "finding without a flag or score here was not checked against the "
                   "list.",
            remedy=remedy,
        ))
        return None, None
    if got.stale_because:
        _gap(store, component, Degradation(
            stage=STAGE, component=component,
            reason=f"{label} could not be refreshed: {got.stale_because}"[:300],
            impact=f"Findings are ranked with the copy of {label} fetched "
                   f"{_day(got.fetched_at)}. Anything added to it since is not "
                   "reflected.",
            remedy=remedy,
        ))
    else:
        _gap(store, component, None)
    return {**got.info(), **info}, data


def score_findings(findings: list[Finding], kev: dict[str, dict] | None,
                   epss: dict[str, tuple[float, float]] | None) -> dict:
    """Write KEV and EPSS results onto the findings. A feed that is None was
    not available, and what an earlier enrich stored for it is left alone."""
    flagged = scored = 0
    for f in findings:
        if kev is not None:
            hits = [c for c in f.cves if c in kev]
            f.kev = bool(hits)
            f.kev_detail = [{
                "cve": c, "date_added": str(kev[c].get("dateAdded", "")),
                "due_date": str(kev[c].get("dueDate", "")),
                "ransomware": str(kev[c].get("knownRansomwareCampaignUse", "")).lower()
                              == "known",
                "name": str(kev[c].get("vulnerabilityName", ""))[:200],
            } for c in hits]
            # A known-exploited CVE always reaches the manual review queue.
            if f.kev and not f.review_required:
                f.review_required, f.review_reason = True, KEV_REVIEW_REASON
            elif not f.kev and f.review_reason == KEV_REVIEW_REASON:
                f.review_required, f.review_reason = False, ""
        if epss is not None:
            best = max((c for c in f.cves if c in epss), key=lambda c: epss[c][0],
                       default="")
            f.epss, f.epss_percentile = epss[best] if best else (None, None)
            f.epss_cve = best
        flagged += f.kev
        scored += f.epss is not None
    return {"kev_findings": flagged, "epss_findings": scored}


def _rank(store: Store, policy: Policy, cache: FeedCache, dry_run: bool) -> dict:
    """Part A: CVE ids, then KEV and EPSS."""
    findings = store.findings()
    changed = False
    for f in findings:
        cves = extract_cves(f)
        changed = changed or cves != f.cves
        f.cves = cves
    wanted = {c for f in findings for c in f.cves}
    with_cves = sum(1 for f in findings if f.cves)
    out: dict = {"cves": len(wanted), "findings_with_cves": with_cves}
    ep = policy.enrich
    print(f"→ exploitation data for {len(wanted)} CVE id(s) on {with_cves} finding(s)")

    if dry_run:
        if wanted:
            _plan(cache, [ep.kev_url, ep.epss_url])
        return out
    if not wanted:
        # Nothing to look up, so nothing is fetched and nothing is unranked.
        print("  no finding carries a CVE id; KEV and EPSS not fetched")
        _gap(store, "kev", None)
        _gap(store, "epss", None)
        if changed:
            store.replace_findings(findings)
        return {**out, "skipped": "no finding carries a CVE id"}

    out["kev"], kev = _feed(store, cache, "kev", "the CISA KEV catalogue", ep.kev_url,
                            load_kev, wanted, with_cves)
    out["epss"], epss = _feed(store, cache, "epss", "EPSS", ep.epss_url,
                              load_epss, wanted, with_cves)
    out.update(score_findings(findings, kev, epss))
    store.replace_findings(findings)
    print(f"  {out['kev_findings']} finding(s) on the KEV list, "
          f"{out['epss_findings']} with an EPSS score")
    return out


def _load_provider(cache: FeedCache, provider: str, urls: list[str]) -> tuple[list, dict]:
    nets: list = []
    info: dict = {"sources": []}
    for url in urls:
        got = cache.get(url)
        try:
            nets += parse_ranges(provider,
                                 got.path.read_text(encoding="utf-8", errors="replace"))
        except FeedError:
            cache.discard(url)
            raise
        info["sources"].append(got.info())
    info["networks"] = len(nets)
    return nets, info


def _tag(store: Store, scope: Scope, policy: Policy, cache: FeedCache,
         dry_run: bool) -> dict:
    """Part B: tag hosts that sit in a published CDN or cloud range."""
    ep = policy.enrich
    hosts = [h for h in store.hosts() if scope.contains(h.ip)]
    print(f"→ CDN and cloud ranges for {len(hosts)} in-scope host(s)")
    if dry_run:
        if hosts:
            _plan(cache, [u for urls in ep.range_urls.values() for u in urls])
        return {}
    if not hosts:
        return {"hosts": 0}

    index = RangeIndex()
    loaded: dict[str, dict] = {}
    for provider, urls in ep.range_urls.items():
        component = f"ranges:{provider}"
        try:
            nets, loaded[provider] = _load_provider(cache, provider, list(urls))
        except FeedError as exc:
            _gap(store, component, Degradation(
                stage=STAGE, component=component,
                reason=f"{provider} address ranges could not be loaded: {exc}"[:300],
                impact=f"Hosts were not checked against {PROVIDER_LABEL.get(provider, provider)}"
                       " ranges. A host served from that network is not marked, and its "
                       "results may describe the provider's edge and not the client's "
                       "server.",
                hosts=[h.ip for h in hosts][:500],
                remedy="Check egress to the list's URL (enrich.range_urls), then "
                       "`extscan enrich <run>`.",
            ))
            continue
        _gap(store, component, None)
        index.add(provider, nets)

    matches: dict[str, list[tuple[str, str]]] = {}
    tags: dict[str, str] = {}
    for h in hosts:
        hit = index.lookup(h.ip)
        if hit:
            tags[h.ip] = hit[0]
            matches.setdefault(hit[0], []).append((h.ip, hit[1]))
    # A provider that failed this time keeps its earlier tags and finding.
    store.tag_hosts(tags, checked=set(loaded))
    kept = [f for f in store.findings()
            if not (f.source == EDGE_SOURCE and len(f.tags) > 1 and f.tags[1] in loaded)]
    store.replace_findings(kept + [edge_finding(p, m) for p, m in sorted(matches.items())])
    for provider, found in sorted(matches.items()):
        print(f"  {len(found)} host(s) in {PROVIDER_LABEL.get(provider, provider)} ranges")
    return {"hosts": len(hosts), "tagged": len(tags), "ranges": loaded,
            "by_network": {p: len(m) for p, m in sorted(matches.items())}}


def run_stage(store: Store, scope: Scope, policy: Policy, dry_run: bool = False,
              fetcher: Fetcher | None = None) -> dict:
    """The enrich stage. `fetcher` replaces the download, for tests."""
    why_not = disabled_reason(policy)
    if why_not:
        print(f"  enrichment is off ({why_not}): findings are not ranked by "
              "exploitation and hosts are not checked against CDN ranges")
        if not dry_run:
            store.mark_stage(STAGE, disabled=True, reason=why_not)
        return {"disabled": True, "reason": why_not}

    cache = cache_for(store, policy, fetcher)
    out = _rank(store, policy, cache, dry_run)
    if policy.enrich.tag_networks:
        out["networks"] = _tag(store, scope, policy, cache, dry_run)
    if dry_run:
        return {**out, "dry_run": True}
    store.mark_stage(STAGE, **out)
    return out


def host_network_label(h: Host) -> str:
    return PROVIDER_LABEL.get(h.network, h.network) if h.network else ""
