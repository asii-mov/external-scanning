"""Screenshots of web services, for the report vault.

A contact sheet answers "default install, real application, or printer admin
panel?" faster than any table, and it is what a reader of the narrative
expects to see next to "we found three websites".

Capture uses headless Chromium through Playwright, an optional extra
(`extscan[screenshots]`). Without it the stage records a coverage gap and the
report describes the services in text only.

Scope is enforced per request, not per page. Every request the browser makes
-- subresources, redirect hops, popups -- passes `scope.assert_url` first.
Playwright only routes the first URL of a redirect chain: a 3xx handed to
the browser is followed hop by hop without coming back through the route. So
each request is fetched with redirects disabled and the browser never sees a
3xx. A redirected navigation becomes a meta refresh, which is a new routed
navigation. A redirected subresource is followed here, one checked hop at a
time. Off-scope requests are aborted and listed, never sent.

Pages whose evidence carries secrets (`.env`, config files) are not
captured: a screenshot cannot be redacted, and the report's proof block
already shows the key names.
"""

from __future__ import annotations

import contextlib
import html
import json
import re
import time
from collections.abc import Callable, Generator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .models import Finding, Service, severity_rank
from .policy import ScreenshotPolicy
from .redact import redact_text
from .scope import Scope, ScopeError

SHOTS_FILE = "screenshots.json"
SHOTS_DIR = "screenshots"
MAX_HOPS = 5

# Never photographed, whatever their severity: the page is the secret.
SECRET_PATHS = {"/.env", "/.git/config", "/config.json", "/web.config", "/actuator/env",
                "/actuator/heapdump", "/debug/pprof/", "/.DS_Store", "/trace.axd",
                "/elmah.axd"}

_EVIDENCE_URL_RE = re.compile(r"(?m)^(?:GET\s+|matched-at:\s*|spec:\s*)(https?://\S+)")


@dataclass
class Shot:
    url: str
    kind: str                       # "service" (root page) or "finding"
    service: str                    # Service.id
    file: str = ""                  # relative to the run directory
    status: str = "pending"         # captured | failed
    finding_ids: list[str] = field(default_factory=list)
    page_title: str = ""
    http_status: int | None = None
    final_url: str = ""
    blocked: list[str] = field(default_factory=list)
    error: str = ""
    at: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Shot:
        return cls(**d)


class BrowserUnavailable(RuntimeError):
    """Playwright or its Chromium is not installed."""


def _filename(host: str, port: int, path: str = "") -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/"))[:60].strip("._-")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{host}-{port}")
    return f"{base}-{slug}.png" if slug else f"{base}.png"


def finding_url(f: Finding) -> str:
    """The URL a finding's evidence was fetched from, if it names one."""
    m = _EVIDENCE_URL_RE.search(f.evidence or "")
    return m.group(1).rstrip(".,;") if m else ""


def _holds_secrets(f: Finding, url: str) -> bool:
    path = re.sub(r"^https?://[^/]+", "", url).split("?")[0] or "/"
    if path in SECRET_PATHS or "secrets" in f.tags:
        return True
    return redact_text(f.evidence) != f.evidence


def plan(services: list[Service], findings: list[Finding], limit: int) -> list[Shot]:
    """Root page of every web service, then pages behind medium+ findings."""
    web = {s.id: s for s in services if s.is_http and s.proto == "tcp"}
    shots: dict[str, Shot] = {}
    for svc in web.values():
        shots[svc.base_url()] = Shot(url=svc.base_url(), kind="service", service=svc.id,
                                     file=f"{SHOTS_DIR}/{_filename(svc.host, svc.port)}")

    extra: list[Shot] = []
    for f in sorted(findings, key=lambda x: -severity_rank(x.severity)):
        if severity_rank(f.severity) < severity_rank("medium") or f.port is None:
            continue
        svc_id = f"{f.host}/{f.proto}/{f.port}"
        url = finding_url(f)
        if svc_id not in web or not url or _holds_secrets(f, url):
            continue
        if url.rstrip("/") == web[svc_id].base_url():
            shots[web[svc_id].base_url()].finding_ids.append(f.id)
            continue
        if url in shots:
            shots[url].finding_ids.append(f.id)
            continue
        path = re.sub(r"^https?://[^/]+", "", url)
        shots[url] = Shot(url=url, kind="finding", service=svc_id, finding_ids=[f.id],
                          file=f"{SHOTS_DIR}/{_filename(f.host, f.port, path)}")
        extra.append(shots[url])

    roots = [s for s in shots.values() if s.kind == "service"]
    return (roots + extra)[:max(limit, len(roots))]


def load(run_dir: Path) -> list[Shot]:
    p = run_dir / SHOTS_FILE
    if not p.exists():
        return []
    try:
        return [Shot.from_dict(d) for d in json.loads(p.read_text())]
    except (json.JSONDecodeError, TypeError):
        return []


def save(run_dir: Path, shots: list[Shot]) -> None:
    tmp = run_dir / f".{SHOTS_FILE}.tmp"
    tmp.write_text(json.dumps([s.to_dict() for s in shots], indent=2))
    tmp.replace(run_dir / SHOTS_FILE)


# A shooter takes (url, output path) and returns what the page said about
# itself: {"title", "status", "final_url", "blocked"}. Raises on failure.
Shooter = Callable[[str, Path], dict]


@contextlib.contextmanager
def browser_shooter(scope: Scope, policy: ScreenshotPolicy,
                    user_agent: str = "") -> Generator[Shooter, None, None]:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise BrowserUnavailable(
            "playwright is not installed (install the `screenshots` extra)") from exc

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=True)
        except PlaywrightError as exc:
            raise BrowserUnavailable(f"chromium did not start: {exc}".splitlines()[0]) from exc
        try:
            yield lambda url, path: _shoot(browser, scope, policy, user_agent, url, path)
        finally:
            browser.close()


def _shoot(browser, scope: Scope, policy: ScreenshotPolicy, user_agent: str,
           url: str, path: Path) -> dict:
    scope.assert_url(url, context="screenshot")
    blocked: list[str] = []
    state = {"status": None, "hops": 0}
    timeout_ms = policy.timeout_sec * 1000

    def stub(route, text: str) -> None:
        route.fulfill(status=200, content_type="text/html",
                      body=f"<html><body><h1>extscan</h1><p>{html.escape(text)}</p></body></html>")

    def guard(route, request):
        target = request.url
        if target.split(":", 1)[0] in ("data", "blob", "about"):
            route.continue_()
            return
        nav = request.is_navigation_request()
        current = target
        for _ in range(MAX_HOPS + 1):
            try:
                scope.assert_url(current, context="screenshot subrequest")
            except ScopeError:
                blocked.append(current)
                if nav:
                    stub(route, f"Redirect to {current} blocked: outside the engagement scope.")
                else:
                    route.abort("blockedbyclient")
                return
            try:
                response = route.fetch(url=current if current != target else None,
                                       max_redirects=0, timeout=timeout_ms)
            except Exception:
                route.abort("failed")
                return
            location = response.headers.get("location")
            if not (300 <= response.status < 400 and location):
                if nav:
                    state["status"] = response.status
                route.fulfill(response=response)
                return
            # Never hand the browser a 3xx: it would follow the chain without
            # coming back through this guard.
            nxt = urljoin(current, location)
            if nav:
                state["hops"] += 1
                if state["hops"] > MAX_HOPS:
                    stub(route, "Too many redirects.")
                    return
                try:
                    scope.assert_url(nxt, context="screenshot redirect")
                except ScopeError:
                    blocked.append(nxt)
                    stub(route, f"Redirect to {nxt} blocked: outside the engagement scope.")
                    return
                # A refresh is a fresh navigation, so it is routed here again.
                route.fulfill(status=200, content_type="text/html", body=(
                    '<html><head><meta http-equiv="refresh" content="0;url='
                    f'{html.escape(nxt, quote=True)}"></head></html>'))
                return
            if urlsplit(nxt).scheme != urlsplit(current).scheme:
                route.abort("failed")       # route.fetch cannot change protocol
                return
            current = nxt
        route.abort("failed")

    context = browser.new_context(
        ignore_https_errors=True, service_workers="block", accept_downloads=False,
        viewport={"width": policy.width, "height": policy.height},
        **({"user_agent": user_agent} if user_agent else {}),
    )
    try:
        context.route("**/*", guard)
        page = context.new_page()
        page.goto(url, wait_until="load", timeout=timeout_ms)
        deadline = time.monotonic() + policy.timeout_sec
        while time.monotonic() < deadline:   # let meta-refresh hops settle
            hops = state["hops"]
            with contextlib.suppress(Exception):
                page.wait_for_load_state("networkidle", timeout=3000)
            if state["hops"] == hops:
                break
        with contextlib.suppress(Exception):
            page.wait_for_load_state("load", timeout=timeout_ms)
        path.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path), timeout=timeout_ms)
        return {"title": page.title()[:200], "status": state["status"],
                "final_url": page.url, "blocked": blocked}
    finally:
        context.close()


def capture(run_dir: Path, shots: list[Shot], shooter: Shooter,
            log: Callable[[str], None] = print) -> list[Shot]:
    """Take each planned shot, recording failures rather than raising."""
    for shot in shots:
        try:
            info = shooter(shot.url, run_dir / shot.file)
        except ScopeError as exc:
            shot.status, shot.error = "failed", f"refused: {exc}"[:300]
        except Exception as exc:
            shot.status = "failed"
            shot.error = f"{type(exc).__name__}: {exc}".splitlines()[0][:300]
        else:
            shot.status = "captured"
            shot.page_title = str(info.get("title") or "")
            shot.http_status = info.get("status")
            shot.final_url = str(info.get("final_url") or "")
            shot.blocked = list(info.get("blocked") or [])[:50]
            shot.error = ""
        shot.at = time.time()
        log(f"  [{shot.status}] {shot.url}" + (f"  ({shot.error})" if shot.error else ""))
    return shots
