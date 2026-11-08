"""Technology detection from one HTTP response, Wappalyzer-style but our own.

The signatures below are hand-written for extscan. They are deliberately not
derived from Wappalyzer or enthec/webappanalyzer, whose data is GPL-licensed;
extscan is proprietary, so none of that data may be copied in. Each pattern
here comes from vendor documentation, default pages and headers the products
are commonly seen to send.

Scope is the perimeter: web servers, frameworks and CMSs, DevOps consoles, and
above all edge appliances (SSL-VPNs, gateways, load-balancer management). Edge
products are where exploitation-led breaches concentrate, so a detection of
one is flagged for review rather than buried in an info line.

Detection is passive. It reads the root response the probe already fetched:
headers, cookies, the meta generator, script sources, HTML and the URLs the
redirect chain visited. Nothing here makes a request.

Cookie signatures see every `Set-Cookie` value when the caller passes
`net.Response.set_cookies`; with only the headers dict, just the last one is
visible. They are supplementary evidence, never the only route to a
detection for a product that matters.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

_FLAGS = re.I | re.S


@dataclass(frozen=True)
class Signature:
    """How to recognise one product.

    Every pattern is a regex, matched case-insensitively. A named group
    `version` captures the version where the evidence carries one. Any single
    match counts as a detection; `versions` patterns run only once the product
    is detected, for version strings that are not specific enough to detect
    the product on their own.
    """

    name: str
    category: str
    edge: bool = False
    headers: tuple[tuple[str, str], ...] = ()     # (header name, value regex)
    cookies: tuple[str, ...] = ()                 # cookie-name regex
    meta: tuple[str, ...] = ()                    # <meta name="generator"> content
    html: tuple[str, ...] = ()                    # body regex
    scripts: tuple[str, ...] = ()                 # <script src> regex
    urls: tuple[str, ...] = ()                    # final URL / redirect hops
    versions: tuple[str, ...] = ()                # body regex, once detected
    implies: tuple[str, ...] = ()
    note: str = ""


def _s(name: str, category: str, **kw) -> Signature:
    for key in ("headers", "cookies", "meta", "html", "scripts", "urls",
                "versions", "implies"):
        if key in kw:
            kw[key] = tuple(kw[key])
    return Signature(name=name, category=category, **kw)


_V = r"(?P<version>\d+(?:\.\d+)*)"

SIGNATURES: list[Signature] = [
    # --- web servers, proxies, CDNs -----------------------------------------
    _s("nginx", "web server",
       headers=[("server", rf"^nginx(?:/{_V})?")],
       html=[rf"<center>nginx(?:/{_V})?</center>", r"<title>Welcome to nginx!</title>"]),
    _s("OpenResty", "web server",
       headers=[("server", rf"^openresty(?:/{_V})?")], implies=["nginx"]),
    _s("Apache HTTP Server", "web server",
       headers=[("server", rf"^Apache(?:/{_V})?(?:[\s(]|$)")],
       html=[rf"<address>Apache(?:/{_V})?[^<]*Server at",
             r"<title>Apache2 \w+ Default Page"]),
    _s("Microsoft IIS", "web server",
       headers=[("server", rf"^Microsoft-IIS(?:/{_V})?")],
       html=[r"<title>IIS Windows Server</title>", r"iisstart\.png"]),
    _s("Microsoft HTTPAPI", "web server",
       headers=[("server", rf"^Microsoft-HTTPAPI(?:/{_V})?")]),
    _s("LiteSpeed", "web server", headers=[("server", r"^LiteSpeed")]),
    _s("Caddy", "web server", headers=[("server", r"^Caddy")]),
    _s("Envoy", "proxy",
       headers=[("server", r"^envoy"), ("x-envoy-upstream-service-time", r"")]),
    _s("Varnish", "cache", headers=[("x-varnish", r""), ("via", r"varnish")]),
    _s("Cloudflare", "CDN", headers=[("server", r"^cloudflare"), ("cf-ray", r"")]),
    _s("Amazon CloudFront", "CDN",
       headers=[("x-amz-cf-id", r""), ("via", r"CloudFront")]),
    _s("AWS Elastic Load Balancing", "load balancer",
       headers=[("server", r"^awselb")]),
    _s("Werkzeug", "development server",
       headers=[("server", rf"Werkzeug(?:/{_V})?")],
       note="Werkzeug is Flask's development server and is not meant for production."),

    # --- languages and frameworks -------------------------------------------
    _s("PHP", "language",
       headers=[("x-powered-by", rf"PHP(?:/{_V})?"), ("server", rf"PHP/{_V}")],
       cookies=[r"^PHPSESSID$"]),
    _s("ASP.NET", "framework",
       headers=[("x-aspnet-version", _V), ("x-powered-by", r"ASP\.NET"),
                ("x-aspnetmvc-version", r"")],
       cookies=[r"^ASP\.NET_SessionId$", r"^\.ASPXAUTH$", r"^__RequestVerificationToken"],
       html=[r"name=\"__VIEWSTATE\"", r"name=\"__EVENTVALIDATION\""]),
    _s("Apache Tomcat", "application server",
       headers=[("server", r"^Apache-Coyote")],
       html=[rf"Apache Tomcat/{_V}", r"<title>Apache Tomcat"]),
    _s("Jetty", "application server",
       headers=[("server", r"^Jetty(?:\((?P<version>[^)]+)\))?")],
       html=[r"Powered by Jetty://\s*(?P<version>[\w.\-]+)?"]),
    _s("Spring Boot", "framework",
       headers=[("x-application-context", r"")],
       html=[r"<h1>Whitelabel Error Page</h1>",
             r"This application has no explicit mapping for /error"]),
    _s("Express", "framework", headers=[("x-powered-by", r"^Express$")]),
    _s("Next.js", "framework",
       headers=[("x-powered-by", rf"Next\.js\s*{_V}?")],
       html=[r"/_next/static/", r"id=\"__NEXT_DATA__\""]),
    _s("Django", "framework",
       cookies=[r"^django_language$"],
       html=[r"name=[\"']csrfmiddlewaretoken[\"']",
             r"<title>[^<]*Django (?:site admin|administration)",
             r"You're seeing this error because you have <code>DEBUG = True</code>"]),
    _s("Ruby on Rails", "framework",
       html=[r"<meta[^>]+name=\"csrf-param\"[^>]+content=\"authenticity_token\"",
             r"<meta[^>]+content=\"authenticity_token\"[^>]+name=\"csrf-param\""]),
    _s("Laravel", "framework", cookies=[r"^laravel_session$"], implies=["PHP"]),

    # --- CMS ----------------------------------------------------------------
    _s("WordPress", "CMS",
       meta=[rf"^WordPress\s*{_V}?"],
       headers=[("link", r"rel=\"https://api\.w\.org/\""), ("x-pingback", r"/xmlrpc\.php")],
       html=[r"/wp-content/", r"/wp-includes/"], implies=["PHP"]),
    _s("Drupal", "CMS",
       meta=[rf"^Drupal\s*{_V}?"],
       headers=[("x-generator", rf"Drupal\s*{_V}?"), ("x-drupal-cache", r""),
                ("x-drupal-dynamic-cache", r"")],
       html=[r"drupal-settings-json", r"Drupal\.settings", r"/sites/default/files/"],
       scripts=[r"/core/misc/drupal\.js", r"/misc/drupal\.js"], implies=["PHP"]),
    _s("Joomla", "CMS",
       meta=[r"^Joomla!"],
       scripts=[r"/media/jui/js/", r"/media/system/js/"], implies=["PHP"]),
    _s("Microsoft SharePoint", "CMS",
       headers=[("microsoftsharepointteamservices", _V), ("x-sharepointhealthscore", r"")],
       html=[r"/_layouts/15/"]),

    # --- DevOps and admin consoles ------------------------------------------
    _s("Jenkins", "CI/CD",
       headers=[("x-jenkins", _V), ("x-hudson", r""), ("x-jenkins-session", r"")],
       html=[r"<title>[^<]*\[Jenkins\]</title>"]),
    _s("GitLab", "source control",
       cookies=[r"^_gitlab_session$"], headers=[("x-gitlab-meta", r"")],
       html=[r"<meta[^>]+content=\"GitLab\"", r"gon\.gitlab_url"]),
    _s("Grafana", "monitoring",
       cookies=[r"^grafana_session$"],
       html=[r"window\.grafanaBootData", r"<title>Grafana</title>"],
       versions=[r"\"buildInfo\":\{[^{}]*?\"version\":\"(?P<version>\d[\w.\-+]*)\""]),
    _s("Kibana", "monitoring",
       headers=[("kbn-version", _V), ("kbn-name", r"")],
       html=[r"kbn-injected-metadata", r"<title>Kibana</title>"]),
    _s("Atlassian Confluence", "collaboration",
       headers=[("x-confluence-request-time", r"")],
       html=[r"<meta[^>]+name=\"confluence-", r"com-atlassian-confluence"],
       versions=[r"name=\"ajs-version-number\"\s+content=\"(?P<version>[\d.]+)\""]),
    _s("Atlassian Jira", "collaboration",
       headers=[("x-arequestid", r"")],
       html=[r"<meta[^>]+name=\"application-name\"[^>]+content=\"JIRA\""],
       versions=[r"name=\"ajs-version-number\"\s+content=\"(?P<version>[\d.]+)\"",
                 r"data-version=\"(?P<version>[\d.]+)\""]),
    _s("phpMyAdmin", "admin panel",
       cookies=[r"^phpMyAdmin$", r"^pma_lang$"],
       html=[r"<title>phpMyAdmin"], implies=["PHP"]),
    _s("Webmin", "admin panel", headers=[("server", rf"^MiniServ(?:/{_V})?")]),

    # --- edge appliances: SSL-VPNs, gateways, load-balancer management -------
    _s("Fortinet FortiGate", "SSL-VPN / firewall", edge=True,
       headers=[("server", r"^xxxxxxxx-xxxxx$")],
       cookies=[r"^SVPNCOOKIE$", r"^SVPNNETWORKCOOKIE$"],
       urls=[r"/remote/login"],
       html=[r"/remote/fgt_lang", r"ftnt-fortinet-grid", r"/remote/login\?lang="]),
    _s("Ivanti Connect Secure (Pulse Secure)", "SSL-VPN", edge=True,
       cookies=[r"^DSSignInURL$", r"^DSBrowserID$", r"^DSID$"],
       urls=[r"/dana-na/", r"/dana-cached/"],
       html=[r"/dana-na/", r"/dana-cached/", r"Ivanti Connect Secure",
             r"Pulse Connect Secure"]),
    _s("Palo Alto GlobalProtect", "SSL-VPN", edge=True,
       urls=[r"/global-protect/"],
       html=[r"/global-protect/(?:login\.esp|portal/)", r"GlobalProtect Portal"]),
    _s("Palo Alto PAN-OS management", "firewall management", edge=True,
       urls=[r"/php/login\.php"],
       html=[r"<title>[^<]*Palo Alto Networks"]),
    _s("Citrix NetScaler ADC / Gateway", "SSL-VPN / ADC", edge=True,
       headers=[("via", r"NS-CACHE")],
       cookies=[r"^NSC_[A-Za-z0-9_]+$"],
       urls=[r"/vpn/index\.html", r"/logon/LogonPoint/", r"/nf/auth/"],
       html=[r"/vpn/js/", r"/logon/LogonPoint/", r"NetScaler (?:Gateway|AAA)",
             r"Citrix Gateway"]),
    _s("F5 BIG-IP Configuration Utility", "load balancer management", edge=True,
       urls=[r"/tmui/"],
       html=[r"/tmui/tmui/", r"BIG-IP[^<]{0,20}Configuration Utility"]),
    _s("F5 BIG-IP APM", "SSL-VPN / access gateway", edge=True,
       cookies=[r"^MRHSession$", r"^LastMRH_Session$", r"^F5_ST$"],
       urls=[r"/my\.policy", r"/my\.logon\.php"]),
    _s("F5 BIG-IP", "load balancer", edge=True,
       headers=[("server", r"^BIG-?IP")], cookies=[r"^BIGipServer"],
       note="A BIG-IP persistence cookie or banner shows traffic passes through a "
            "BIG-IP; it does not on its own show the management interface is exposed."),
    _s("SonicWall", "SSL-VPN / firewall", edge=True,
       headers=[("server", r"SonicWALL")],
       urls=[r"/cgi-bin/welcome", r"/sslvpn/"],
       html=[r"<title>[^<]*SonicWall"]),
    _s("Cisco ASA / AnyConnect", "SSL-VPN / firewall", edge=True,
       cookies=[r"^webvpn$", r"^webvpnlogin$", r"^webvpnLang$"],
       urls=[r"/\+CSCOE\+/"],
       html=[r"/\+CSCOE\+/", r"/\+CSCOU\+/"]),
    _s("Check Point Mobile Access", "SSL-VPN", edge=True,
       html=[r"Check Point (?:Mobile Access|SSL Network Extender)"]),
    _s("Microsoft Exchange (OWA)", "mail gateway", edge=True,
       headers=[("x-owa-version", _V), ("x-feserver", r"")],
       urls=[r"/owa/auth/"],
       html=[r"/owa/auth/", r"<title>Outlook Web App</title>"]),
    _s("VMware vCenter / ESXi", "virtualisation management", edge=True,
       html=[r"ID_VC_Welcome", r"ID_EESX_Welcome", r"/vsphere-client/",
             r"<title>[^<]*VMware (?:vSphere|ESXi)"]),
    _s("Progress MOVEit Transfer", "file transfer", edge=True,
       cookies=[r"^siLock"], html=[r"MOVEit Transfer"]),
]

_BY_NAME = {s.name: s for s in SIGNATURES}


@dataclass
class Detection:
    name: str
    category: str
    edge: bool = False
    version: str = ""
    evidence: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def confidence(self) -> str:
        """Firm with two independent signals or a captured version."""
        return "firm" if self.version or len(self.evidence) >= 2 else "tentative"

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}".strip()

    def to_dict(self) -> dict:
        return {"name": self.name, "category": self.category, "edge": self.edge,
                "version": self.version, "evidence": self.evidence,
                "confidence": self.confidence}


@dataclass
class PageParts:
    """What the matcher needs from HTML, extracted once per page."""

    title: str = ""
    generators: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    icons: list[str] = field(default_factory=list)


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts = PageParts()
        self._in_title = False
        self._title: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta" and a.get("name", "").lower() == "generator" and a.get("content"):
            self.parts.generators.append(a["content"].strip())
        elif tag == "script" and a.get("src"):
            self.parts.scripts.append(a["src"].strip())
        elif tag == "link" and a.get("href") and \
                "icon" in a.get("rel", "").lower().split():
            self.parts.icons.append(a["href"].strip())
        elif tag == "title" and not self.parts.title:
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title" and self._in_title:
            self._in_title = False
            self.parts.title = " ".join("".join(self._title).split())[:200]

    def handle_data(self, data):
        if self._in_title and len(self._title) < 50:
            self._title.append(data)


def parse_page(body: str, limit: int = 500_000) -> PageParts:
    """Pull the title, generator, scripts and icon links out of HTML."""
    ex = _Extractor()
    # Hostile HTML must never fail the probe; keep whatever was parsed.
    with contextlib.suppress(Exception):
        ex.feed(body[:limit])
        ex.close()
    if ex._in_title and not ex.parts.title:
        ex.parts.title = " ".join("".join(ex._title).split())[:200]
    return ex.parts


def cookie_names(set_cookie: str) -> list[str]:
    """Cookie names from a Set-Cookie value (or several joined by newline/comma)."""
    names = []
    for chunk in re.split(r"\n|,\s*(?=[^;,=\s]+=)", set_cookie or ""):
        name = chunk.split("=", 1)[0].strip()
        if name and "=" in chunk:
            names.append(name)
    return names


_compiled: dict[str, re.Pattern] = {}


def _rx(pattern: str) -> re.Pattern:
    rx = _compiled.get(pattern)
    if rx is None:
        rx = _compiled[pattern] = re.compile(pattern, _FLAGS)
    return rx


def _version(m: re.Match) -> str:
    if "version" in m.re.groupindex:
        return (m.group("version") or "").strip()
    return ""


def _clip(s: str, n: int = 120) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "..."


def _match(sig: Signature, headers: dict[str, str], body: str, cookies: list[str],
           urls: list[str], parts: PageParts) -> Detection | None:
    det = Detection(sig.name, sig.category, sig.edge, note=sig.note)

    def hit(m: re.Match | None, what: str) -> None:
        if m is None:
            return
        det.evidence.append(what)
        if not det.version:
            det.version = _version(m)

    def first(pattern: str, values: list[str], label: str) -> None:
        for value in values:
            m = _rx(pattern).search(value)
            if m:
                hit(m, f"{label}{_clip(value)}")
                return

    for hname, pattern in sig.headers:
        value = headers.get(hname)
        if value is not None:
            hit(_rx(pattern).search(value), f"header {hname}: {_clip(value)}")
    for pattern in sig.cookies:
        first(pattern, cookies, "cookie ")
    for pattern in sig.meta:
        first(pattern, parts.generators, "meta generator: ")
    for pattern in sig.scripts:
        first(pattern, parts.scripts, "script src: ")
    for pattern in sig.urls:
        first(pattern, urls, "url: ")
    for pattern in sig.html:
        m = _rx(pattern).search(body)
        if m:
            hit(m, f"body matches {_clip(m.group(0), 80)!r}")

    if not det.evidence:
        return None
    if not det.version:
        for pattern in sig.versions:
            m = _rx(pattern).search(body)
            if m and _version(m):
                det.version = _version(m)
                det.evidence.append(f"version from body: {_clip(m.group(0), 80)!r}")
                break
    return det


def detect(headers: dict[str, str], body: str, urls: list[str] | None = None,
           parts: PageParts | None = None,
           set_cookies: list[str] | None = None) -> list[Detection]:
    """Match every signature against one response. Headers must be lower-cased.
    `set_cookies` is every Set-Cookie value (`net.Response.set_cookies`)."""
    body = (body or "")[:500_000]
    parts = parts or parse_page(body)
    cookies = cookie_names("\n".join(set_cookies) if set_cookies
                           else headers.get("set-cookie", ""))
    urls = [u for u in (urls or []) if u]
    found: dict[str, Detection] = {}
    for sig in SIGNATURES:
        det = _match(sig, headers, body, cookies, urls, parts)
        if det:
            found[sig.name] = det

    for det in list(found.values()):
        for implied in _BY_NAME[det.name].implies:
            if implied not in found and implied in _BY_NAME:
                sig = _BY_NAME[implied]
                found[implied] = Detection(sig.name, sig.category, sig.edge, note=sig.note,
                                           evidence=[f"implied by {det.name}"])

    return sorted(found.values(), key=lambda d: (not d.edge, d.category, d.name))
