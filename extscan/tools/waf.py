"""Edge products (WAF, CDN, load balancer) and signs of being blocked.

Passive only. wafw00f and its kin identify a WAF by sending something that
looks like an attack and reading the block page; extscan does not send
attack-shaped requests. Everything here reads the headers and cookies of
responses the other checks already asked for.

Two questions are answered:

* which product sits in front of the service (`fingerprint`), so the report
  describes the edge as well as the origin;
* whether a response says the scanner itself is being challenged or throttled
  (`block_signal`), in which case what follows is not evidence about the
  application.
"""

from __future__ import annotations

from extscan.tools.net import Response

# (product, where, name, value). `where` is "header" or "cookie". For a header
# an empty value means "present at all"; otherwise the value must appear in
# it, case-insensitively. For a cookie `name` is a prefix of the cookie name.
# Every entry is a header or cookie the vendor documents; nothing matches on
# body text, which a page can say anything in.
SIGNATURES: list[tuple[str, str, str, str]] = [
    ("Cloudflare", "header", "cf-ray", ""),
    ("Cloudflare", "header", "server", "cloudflare"),
    ("Akamai", "header", "x-akamai-transformed", ""),
    ("Akamai", "header", "akamai-grn", ""),
    ("Akamai", "header", "server", "akamaighost"),
    ("Imperva (Incapsula)", "cookie", "incap_ses_", ""),
    ("Imperva (Incapsula)", "cookie", "visid_incap_", ""),
    ("Imperva (Incapsula)", "header", "x-iinfo", ""),
    ("Imperva (Incapsula)", "header", "x-cdn", "incapsula"),
    ("Imperva (Incapsula)", "header", "x-cdn", "imperva"),
    ("Sucuri", "header", "x-sucuri-id", ""),
    ("Sucuri", "header", "x-sucuri-cache", ""),
    ("Sucuri", "header", "server", "sucuri"),
    ("AWS CloudFront", "header", "x-amz-cf-id", ""),
    ("AWS CloudFront", "header", "x-amz-cf-pop", ""),
    ("AWS Application Load Balancer", "cookie", "awsalb", ""),
    ("AWS Application Load Balancer", "header", "server", "awselb"),
    ("AWS WAF", "header", "x-amzn-waf-action", ""),
    ("AWS WAF", "cookie", "aws-waf-token", ""),
    ("Fastly", "header", "x-fastly-request-id", ""),
    ("Fastly", "header", "x-served-by", "cache-"),
    ("F5 BIG-IP", "cookie", "bigipserver", ""),
    ("F5 BIG-IP", "header", "server", "bigip"),
    ("F5 BIG-IP", "header", "server", "big-ip"),
    ("Azure Front Door", "header", "x-azure-ref", ""),
]


def _cookie_names(headers: dict[str, str]) -> list[str]:
    """Names of the cookies a response sets, lower-cased.

    Several `Set-Cookie` headers arrive joined with ", ", and an `Expires`
    attribute has a comma of its own, so split on both separators and keep
    whatever sits in front of an `=`. Attribute names (path, expires...) come
    out too; they match no signature.
    """
    names = []
    for chunk in headers.get("set-cookie", "").replace(",", ";").split(";"):
        name, sep, _ = chunk.strip().partition("=")
        if sep and name:
            names.append(name.strip().lower())
    return names


def fingerprint(headers: dict[str, str]) -> list[tuple[str, str]]:
    """Edge products named by a response's headers: (product, what matched)."""
    cookies = _cookie_names(headers)
    found: dict[str, str] = {}
    for product, where, name, value in SIGNATURES:
        if product in found:
            continue
        if where == "cookie":
            hit = next((c for c in cookies if c.startswith(name)), "")
            if hit:
                found[product] = f"cookie {hit}"
        elif name in headers and value in headers[name].lower():
            found[product] = f"{name}: {headers[name][:120]}"
    return list(found.items())


def block_signal(resp: Response) -> str:
    """Why this response means the scanner is being throttled or challenged.

    Empty when it says no such thing. A 403 alone is not a signal: plenty of
    paths are honestly forbidden. The comparison across paths that catches a
    blanket block page lives with the path checks, which have the baseline.
    """
    if resp.status == 429:
        retry = resp.headers.get("retry-after", "")
        return "429 Too Many Requests" + (f" (Retry-After: {retry[:40]})" if retry else "")
    if "cf-mitigated" in resp.headers:
        return f"Cloudflare challenge (cf-mitigated: {resp.headers['cf-mitigated'][:40]})"
    action = resp.headers.get("x-amzn-waf-action", "")
    if action:
        return f"AWS WAF {action[:40]} response (x-amzn-waf-action)"
    return ""
