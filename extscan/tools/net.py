"""HTTP fetching and TLS inspection, stdlib only.

The HTTP side exists so follow-up work (reading an OpenAPI document, checking
whether a path is really browsable) needs no extra dependency. It differs from
a plain `urlopen` in one important way: redirects are followed manually and
every hop is scope-checked before the request goes out.

That matters because by this point in the pipeline the URLs come from the
target: nuclei output, HTML, `servers` entries in a swagger file. A host that
answers `302 Location: http://169.254.169.254/latest/meta-data/` must not get
the auditor's scanner to make that request.
"""

from __future__ import annotations

import contextlib
import dataclasses
import difflib
import html
import http.client
import ipaddress
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from extscan.policy import HttpPolicy
from extscan.scope import Scope, ScopeError


@dataclass
class Response:
    url: str
    status: int
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    redirect_chain: list[str] = field(default_factory=list)
    error: str = ""
    truncated: bool = False
    # Where a raw request (`request_at`) stopped: "scope", "connect", "tls"
    # or "http". Empty when a response was parsed.
    failed_at: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()


def _header_map(message) -> dict[str, str]:
    """Lower-cased headers, repeated ones joined.

    A plain dict keeps only the last `Set-Cookie`, and the cookie that names
    the load balancer is often not the last one.
    """
    out: dict[str, str] = {}
    for k, v in (message.items() if message is not None else []):
        k = k.lower()
        out[k] = f"{out[k]}, {v}" if k in out else v
    return out


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def page_title(body_text: str) -> str:
    m = _TITLE_RE.search(body_text)
    return html.unescape(m.group(1)).strip()[:200] if m else ""


def same_page(a: Response, b: Response) -> bool:
    """True when two responses are the same page, give or take a token."""
    if a.body == b.body:
        return True
    if a.content_type != b.content_type:
        return False
    return difflib.SequenceMatcher(None, a.body[:4000], b.body[:4000],
                                   autojunk=False).ratio() > 0.95


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand redirects back to us instead of following them silently."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _ssl_context(policy: HttpPolicy) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not policy.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _opener(policy: HttpPolicy) -> urllib.request.OpenerDirector:
    handlers: list = [_NoRedirect(), urllib.request.HTTPSHandler(context=_ssl_context(policy))]
    if not policy.use_system_proxy:
        # An empty ProxyHandler disables urllib's env-var proxy discovery.
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def fetch(url: str, scope: Scope, policy: HttpPolicy, *, method: str = "GET",
          data: bytes | None = None,
          extra_headers: dict[str, str] | None = None) -> Response:
    """Fetch a URL, following redirects manually with a scope check per hop."""
    chain: list[str] = []
    current = url
    opener = _opener(policy)

    for hop in range(policy.max_redirects + 1):
        try:
            scope.assert_url(current, context=f"http fetch hop {hop}")
        except ScopeError as exc:
            return Response(url=current, status=0, redirect_chain=chain,
                            error=f"scope refusal: {exc}")

        req = urllib.request.Request(current, data=data, method=method)  # noqa: S310
        req.add_header("User-Agent", policy.user_agent)
        req.add_header("Accept", "*/*")
        req.add_header("Connection", "close")
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)

        try:
            with opener.open(req, timeout=policy.timeout_sec) as resp:
                raw = resp.read(policy.max_body_bytes + 1)
                truncated = len(raw) > policy.max_body_bytes
                return Response(
                    url=current, status=resp.status, reason=resp.reason or "",
                    headers=_header_map(resp.headers),
                    body=raw[:policy.max_body_bytes], redirect_chain=chain,
                    truncated=truncated,
                )
        except urllib.error.HTTPError as exc:
            headers = _header_map(exc.headers)
            if exc.status in (301, 302, 303, 307, 308) and headers.get("location"):
                target = urllib.parse.urljoin(current, headers["location"])
                chain.append(f"{current} -> {exc.status} -> {target}")
                current = target
                if data is not None and exc.status in (301, 302, 303):
                    method, data = "GET", None
                continue
            try:
                body = exc.read(policy.max_body_bytes)
            except Exception:
                body = b""
            return Response(url=current, status=exc.status, reason=exc.reason or "",
                            headers=headers, body=body, redirect_chain=chain)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
            return Response(url=current, status=0, redirect_chain=chain,
                            error=f"{type(exc).__name__}: {exc}")

    return Response(url=current, status=0, redirect_chain=chain,
                    error=f"exceeded max_redirects ({policy.max_redirects})")


_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def valid_hostname(name: str) -> str:
    """Return `name` normalised if it is a plain DNS hostname, else "".

    Names reach the vhost check from certificates and DNS answers, which the
    target controls, and they go into a `Host` header and the TLS SNI. So the
    rule is strict: ASCII letters, digits and hyphens in dot-separated labels
    (punycode passes, raw unicode does not), at least two labels, no
    wildcard, no IP literal, nothing that could split a header line.
    """
    if not isinstance(name, str):
        return ""
    normal = name.strip().lower()
    if normal.endswith("."):
        normal = normal[:-1]
    if not normal or len(normal) > 253:
        return ""
    labels = normal.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(lb) for lb in labels):
        return ""
    if labels[-1].isdigit():
        return ""          # 10.0.0.1, or anything else that parses as an address
    return normal


def host_header(ip: str, port: int, tls: bool) -> str:
    hostpart = f"[{ip}]" if ":" in ip else ip
    return hostpart if port == (443 if tls else 80) else f"{hostpart}:{port}"


def request_at(ip: str, port: int, scope: Scope, policy: HttpPolicy, *, tls: bool,
               host: str = "", path: str = "/") -> Response:
    """One GET to a literal in-scope IP, with a chosen `Host` header and SNI.

    `fetch` hands urllib a URL and urllib resolves the host, so asking for a
    virtual host by name would connect to wherever DNS says that name lives.
    Here the socket always goes to `ip`, which is scope-checked, and the name
    only travels inside the request (Host header, and SNI when `tls`). No
    proxy is involved and redirects are not followed: the `Location` is left
    in the headers for the caller to report.

    Never raises for network trouble. `failed_at` on the result says how far
    the exchange got, which is how a caller tells "port did not accept the
    connection" from "accepted, but does not speak TLS / HTTP".
    """
    label = f"{ip}:{port}"
    url = f"{'https' if tls else 'http'}://{host_header(ip, port, tls)}{path}"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return Response(url=url, status=0, failed_at="scope",
                        error=f"scope refusal: {ip!r} is not an IP address; raw requests "
                              "connect to in-scope addresses only")
    try:
        scope.assert_host(ip, context=f"raw http request to {label}")
    except ScopeError as exc:
        return Response(url=url, status=0, error=f"scope refusal: {exc}", failed_at="scope")

    name = ""
    if host:
        name = valid_hostname(host)
        if not name:
            return Response(url=url, status=0, failed_at="scope",
                            error=f"refusing Host header {host[:80]!r}: not a plain hostname")
    if not path.startswith("/") or any(c in path for c in "\r\n "):
        return Response(url=url, status=0, failed_at="scope", error=f"bad path {path[:80]!r}")

    timeout = float(policy.timeout_sec)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock: socket.socket = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except (OSError, TimeoutError) as exc:
            return Response(url=url, status=0, failed_at="connect",
                            error=f"{type(exc).__name__}: {exc}")
        if tls:
            try:
                sock = _unverified_context().wrap_socket(sock, server_hostname=name or None)
            except (OSError, ssl.SSLError, TimeoutError) as exc:
                return Response(url=url, status=0, failed_at="tls",
                                error=f"{type(exc).__name__}: {exc}")
        request = (f"GET {path} HTTP/1.1\r\n"
                   f"Host: {name or host_header(ip, port, tls)}\r\n"
                   f"User-Agent: {policy.user_agent}\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n")
        try:
            sock.sendall(request.encode("latin-1", "replace"))
            parsed = http.client.HTTPResponse(sock, method="GET")
            parsed.begin()
        except (http.client.HTTPException, OSError, ssl.SSLError, TimeoutError,
                ValueError) as exc:
            return Response(url=url, status=0, failed_at="http",
                            error=f"{type(exc).__name__}: {exc}")
        # The status line is the answer. A body that stalls or is cut short
        # does not turn an HTTP server into a non-HTTP one.
        raw = b""
        with contextlib.suppress(http.client.HTTPException, OSError, ssl.SSLError,
                                 TimeoutError, ValueError):
            raw = parsed.read(policy.max_body_bytes + 1)
        parsed.close()
        return Response(url=url, status=parsed.status, reason=parsed.reason or "",
                        headers=_header_map(parsed.headers),
                        body=raw[:policy.max_body_bytes],
                        truncated=len(raw) > policy.max_body_bytes)
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def without_name(resp: Response, name: str) -> Response:
    """A copy with `name` blanked out of the body and the Location header.

    A server that echoes the requested host ("Welcome to <host>", or a
    redirect to https://<host>/) gives a different page for every name
    without being a different site.
    """
    if not name:
        return resp
    needle = re.compile(re.escape(name.encode()), re.I)
    headers = dict(resp.headers)
    if "location" in headers:
        headers["location"] = re.sub(re.escape(name), "{host}", headers["location"], flags=re.I)
    return dataclasses.replace(resp, body=needle.sub(b"{host}", resp.body), headers=headers)


@dataclass
class TlsInfo:
    host: str
    port: int
    negotiated_version: str = ""
    cipher: str = ""
    cert_pem: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    sans: list[str] = field(default_factory=list)
    self_signed: bool = False
    hostname_matches: bool | None = None
    expired: bool | None = None
    protocols: dict[str, bool | None] = field(default_factory=dict)
    error: str = ""


_PROTO_VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Older OpenSSL builds reject @SECLEVEL, and some reject "ALL" outright.
    for suite in ("ALL:@SECLEVEL=0", "ALL"):
        with contextlib.suppress(ssl.SSLError):
            ctx.set_ciphers(suite)
            break
    return ctx


def _openssl_cert_fields(pem: str) -> dict:
    """Parse a PEM cert with the openssl CLI, which is near-universal.

    Avoids a `cryptography` dependency. If openssl is absent we simply report
    less, rather than failing the probe.
    """
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"],
            input=pem, capture_output=True, text=True, timeout=15, shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {}
    out: dict = {}
    sans: list[str] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("subject="):
            out["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            out["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            out["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            out["not_after"] = line.split("=", 1)[1].strip()
        elif "DNS:" in line or "IP Address:" in line:
            for part in line.split(","):
                part = part.strip()
                if part.startswith(("DNS:", "IP Address:")):
                    sans.append(part.split(":", 1)[1].strip())
    if sans:
        out["sans"] = sans
    return out


def inspect_tls(host: str, port: int, scope: Scope, *, timeout: float = 8.0,
                probe_protocols: bool = True) -> TlsInfo:
    """Collect certificate and protocol detail for one TLS endpoint."""
    scope.assert_host(host, context=f"tls inspect {host}:{port}")
    info = TlsInfo(host=host, port=port)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET

    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(timeout)
            raw_sock.connect((host, port))
            ctx = _unverified_context()
            with ctx.wrap_socket(raw_sock, server_hostname=None) as tls:
                info.negotiated_version = tls.version() or ""
                cipher = tls.cipher()
                info.cipher = f"{cipher[0]} ({cipher[2]} bit)" if cipher else ""
                der = tls.getpeercert(binary_form=True)
                if der:
                    info.cert_pem = ssl.DER_cert_to_PEM_cert(der)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        info.error = f"{type(exc).__name__}: {exc}"
        return info

    if info.cert_pem:
        fields = _openssl_cert_fields(info.cert_pem)
        info.subject = fields.get("subject", "")
        info.issuer = fields.get("issuer", "")
        info.not_before = fields.get("not_before", "")
        info.not_after = fields.get("not_after", "")
        info.sans = fields.get("sans", [])
        if info.subject and info.issuer:
            info.self_signed = info.subject == info.issuer
        if info.not_after:
            info.expired = _cert_expired(info.not_after)

    if probe_protocols:
        info.protocols = _probe_protocols(host, port, family, timeout)

    return info


def _cert_expired(not_after: str) -> bool | None:
    """Parse openssl's date format, e.g. 'Mar  9 12:00:00 2027 GMT'."""
    import datetime as dt
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            when = dt.datetime.strptime(not_after.strip(), fmt)
            return when.replace(tzinfo=dt.timezone.utc) < dt.datetime.now(dt.timezone.utc)
        except ValueError:
            continue
    return None


def _probe_protocols(host: str, port: int, family: int,
                     timeout: float) -> dict[str, bool | None]:
    """Which TLS versions does the server accept?

    None means "could not determine" -- usually the local OpenSSL build refuses
    to speak a deprecated version at all, which is not evidence about the
    server. Reporting that honestly matters: "TLS 1.0 not supported" and "we
    could not ask" are very different claims to put in a client's report.
    """
    results: dict[str, bool | None] = {}
    for label, version in _PROTO_VERSIONS:
        ctx = _unverified_context()
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, OSError):
            results[label] = None
            continue
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                with ctx.wrap_socket(sock, server_hostname=None) as tls:
                    results[label] = tls.version() is not None
        except ssl.SSLError as exc:
            msg = str(exc).lower()
            if any(s in msg for s in ("no protocols available", "unsupported protocol",
                                      "version too low", "no ciphers available")):
                results[label] = None
            else:
                results[label] = False
        except (OSError, TimeoutError):
            results[label] = None
    return results
