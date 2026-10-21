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

import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from ..policy import HttpPolicy
from ..scope import Scope, ScopeError


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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand redirects back to us instead of following them silently."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _ssl_context(policy: HttpPolicy) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not policy.verify_tls:
        # Audit targets routinely present expired or self-signed certs; refusing
        # to connect would hide the very exposure we are looking for. Cert
        # problems are recorded by the TLS probe instead.
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

        req = urllib.request.Request(current, method=method)
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
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=raw[:policy.max_body_bytes], redirect_chain=chain,
                    truncated=truncated,
                )
        except urllib.error.HTTPError as exc:
            headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
            if exc.status in (301, 302, 303, 307, 308) and headers.get("location"):
                target = urllib.parse.urljoin(current, headers["location"])
                chain.append(f"{current} -> {exc.status} -> {target}")
                current = target
                continue
            try:
                body = exc.read(policy.max_body_bytes)
            except Exception:                        # noqa: BLE001 - body is optional
                body = b""
            return Response(url=current, status=exc.status, reason=exc.reason or "",
                            headers=headers, body=body, redirect_chain=chain)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
            return Response(url=current, status=0, redirect_chain=chain,
                            error=f"{type(exc).__name__}: {exc}")

    return Response(url=current, status=0, redirect_chain=chain,
                    error=f"exceeded max_redirects ({policy.max_redirects})")


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

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
    # Allow legacy suites so we can see what the server offers rather than
    # failing the handshake on our own client policy.
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        try:
            ctx.set_ciphers("ALL")
        except ssl.SSLError:
            pass
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
    except (OSError, ssl.SSLError, socket.timeout, TimeoutError) as exc:
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
            # Distinguish "server said no" from "our client could not try".
            if any(s in msg for s in ("no protocols available", "unsupported protocol",
                                      "version too low", "no ciphers available")):
                results[label] = None
            else:
                results[label] = False
        except (OSError, socket.timeout, TimeoutError):
            results[label] = None
    return results
