"""Live detection eval on loopback: no nmap, no nuclei, about two seconds.

Targets on 127.0.0.1, each on an ephemeral port:

* `exposed`  the deliberately exposed billing app (`tests/targetapp.py`).
  Every planted issue in `expected/local.json` must be found, at the stated
  severity.
* `unnamed`  a web app with a readable `.env`, seeded the way nmap reports a
  port it could not name (`unknown`). It must be identified as HTTP and get
  the same checks as any other web service.
* `hardened` answers 404 for everything but `/`, with security headers set.
* `spa`      a single-page app that serves its index, 200, for every path.
  This is the classic source of false positives in path checks.
* `vhosts`   name-based virtual hosting: a default site by address and a
  different application for one `Host` header. Exactly that one name must be
  reported.
* `wildcard` answers every `Host` with the same page, echoing the name. It
  must yield no virtual-host finding.
* `throttled` starts answering 429 partway through the path checks. It must
  end as a coverage gap (`must_gap`), stay unmarked, and stop receiving
  requests.

Two hostnames are recorded for 127.0.0.1, so every target is asked for both.
No clean target may produce a finding above `info`, or any lead, and no
target but `vhosts` may produce a virtual-host finding.

The probe and chase stages run in-process against services seeded by hand,
which is what the unit tests do. Requests are counted per target, so a
change that doubles the traffic sent to a client's host shows up here.

    uv run python -m evals.local            # scorecard
    uv run python -m evals.local --json
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import shutil
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tests import targetapp

from extscan import pipeline
from extscan.models import Host, Service, severity_rank
from extscan.policy import Policy
from extscan.runner import Runner
from extscan.scope import Scope

EXPECTED = Path(__file__).parent / "expected" / "local.json"

SPA_INDEX = ("<!doctype html><html><head><title>Customer portal</title></head>"
             "<body><div id=\"root\"></div><script src=\"/static/app.3f9c.js\"></script>"
             "</body></html>")

HARDENING = {
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in HARDENING.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


class HardenedHandler(_Quiet):
    server_version = "web"
    sys_version = ""

    def do_GET(self):
        if self.path.split("?")[0] == "/":
            return self._send(200, "<html><title>Portal</title></html>")
        return self._send(404, "")

    def do_POST(self):
        return self._send(404, "")


class SpaHandler(_Quiet):
    server_version = "web"
    sys_version = ""

    def do_GET(self):
        return self._send(200, SPA_INDEX)

    def do_POST(self):
        return self._send(405, "")


class UnnamedHandler(_Quiet):
    """An ordinary web app; what makes it a test is the port's nmap label."""

    server_version = "web"
    sys_version = ""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._send(200, "<html><title>Build dashboard</title></html>")
        if path == "/.env":
            return self._send(200, targetapp.ENV, "text/plain")
        return self._send(404, "")

    def do_POST(self):
        return self._send(404, "")


VHOST_NAME = "billing.corp.example"
SAME_SITE_NAME = "www.corp.example"


class VhostHandler(_Quiet):
    """Default site by address; a different application for one name."""

    server_version = "web"
    sys_version = ""

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        if self.path.split("?")[0] != "/":
            return self._send(404, "")
        if host == VHOST_NAME:
            return self._send(200, "<html><title>Billing back office</title>"
                                   "<body><form>Staff sign-in</form></body></html>")
        return self._send(200, "<html><title>Portal</title></html>")

    def do_POST(self):
        return self._send(404, "")


class WildcardHandler(_Quiet):
    """One site for every name, with the requested name in the page."""

    server_version = "web"
    sys_version = ""

    def do_GET(self):
        if self.path.split("?")[0] != "/":
            return self._send(404, "")
        host = (self.headers.get("Host") or "").split(":")[0]
        return self._send(200, f"<html><title>Welcome</title><body>You asked for {host}."
                               "</body></html>")

    def do_POST(self):
        return self._send(404, "")


THROTTLE_AFTER = 8


def _throttled_handler() -> type[BaseHTTPRequestHandler]:
    """A hardened site that answers 429 once it has served a few requests."""
    served = [0]
    lock = threading.Lock()

    class Throttled(HardenedHandler):
        def do_GET(self):
            with lock:
                served[0] += 1
                over = served[0] > THROTTLE_AFTER
            if over:
                return self._send(429, "slow down")
            return super().do_GET()

    return Throttled


def _counting(handler: type[BaseHTTPRequestHandler], counter: list[int]):
    class Counting(handler):
        def parse_request(self):
            counter[0] += 1
            return super().parse_request()
    return Counting


class _Target:
    def __init__(self, name: str, handler: type[BaseHTTPRequestHandler]):
        self.name = name
        self.requests = [0]
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _counting(handler, self.requests))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _matches(finding, want: dict) -> bool:
    return (finding.source.startswith(want["source"])
            and re.search(want["title"], finding.title) is not None)


CLEAN = ("hardened", "spa", "vhosts", "wildcard", "throttled")


def run() -> dict:
    """Run probe and chase against the targets and score the result."""
    targets = [_Target("exposed", targetapp.Handler), _Target("unnamed", UnnamedHandler),
               _Target("hardened", HardenedHandler), _Target("spa", SpaHandler),
               _Target("vhosts", VhostHandler), _Target("wildcard", WildcardHandler),
               _Target("throttled", _throttled_handler())]
    by_name = {t.name: t for t in targets}
    by_port = {t.port: t for t in targets}
    targetapp.SPEC["servers"][0]["url"] = f"http://127.0.0.1:{targets[0].port}/api"
    tmp = Path(tempfile.mkdtemp(prefix="extscan-eval-"))
    try:
        scope_path = tmp / "scope.json"
        scope_path.write_text(json.dumps({
            "engagement": "local eval", "client": "self-test",
            "authorization": {"reference": "LOCAL-EVAL",
                              "authorized_by": "eval harness (loopback only)"},
            "targets": ["127.0.0.1/32"], "allow_private": True, "max_hosts": 2,
        }))
        scope = Scope.load(scope_path)
        policy = Policy.for_profile("standard")
        policy.http.timeout_sec = 5
        store = pipeline.init_run(str(tmp / "runs"), scope, policy, run_id="eval")
        store.save_hosts([Host(ip="127.0.0.1", state="up",
                               hostnames=[VHOST_NAME, SAME_SITE_NAME])])
        store.save_services([Service(host="127.0.0.1", port=t.port, proto="tcp",
                                     name="unknown" if t.name == "unnamed" else "http")
                             for t in targets])
        runner = Runner(store)

        started = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.probe(store, scope, policy, runner, skip_nuclei=True)
            pipeline.chase_leads(store, scope, policy, runner, rounds=3)
        seconds = time.perf_counter() - started

        findings = store.findings()
        leads = store.leads()
        services = {by_port[s.port].name: s for s in store.services()}
        degradations = store.degradations()
        expected = json.loads(EXPECTED.read_text())

        found, missed, wrong_severity = [], [], []
        for want in expected["must_find"]:
            port = by_name[want.get("target", "exposed")].port
            hits = [f for f in findings if f.port == port and _matches(f, want)]
            if not hits:
                missed.append(want["id"])
                continue
            found.append(want["id"])
            if want["severity"] not in {f.severity for f in hits}:
                wrong_severity.append(f"{want['id']}: want {want['severity']}, "
                                      f"got {sorted({f.severity for f in hits})}")

        # A gap is "found" when it is recorded against the service and the
        # probe is left unmarked: a mark would claim the service was covered.
        for want in expected["must_gap"]:
            svc = services[want["target"]]
            probe_name = want["stage"].split(":", 1)[1]
            recorded = any(d.stage == want["stage"] and d.reason.startswith(f"{svc.id}: ")
                           for d in degradations)
            if recorded and probe_name not in svc.probed_by:
                found.append(want["id"])
            else:
                missed.append(want["id"])

        false_positives = []
        for name in CLEAN:
            t = by_name[name]
            false_positives += [f"{t.name}: [{f.severity}] {f.title}" for f in findings
                                if f.port == t.port and severity_rank(f.severity) > 0]
            false_positives += [f"{t.name}: lead {ld.kind} {ld.url}" for ld in leads
                                if ld.port == t.port]
        wanted_vhosts = [w for w in expected["must_find"] if w["source"] == "extscan:vhost"]
        false_positives += [
            f"{by_port[f.port].name}: {f.title}" for f in findings
            if f.source == "extscan:vhost" and not any(
                f.port == by_name[w["target"]].port and _matches(f, w) for w in wanted_vhosts)]

        budget = expected["budgets"]
        requests = {t.name: t.requests[0] for t in targets}
        over_budget = [f"{name}: {n} requests, budget {budget['requests'][name]}"
                       for name, n in requests.items() if n > budget["requests"][name]]
        if seconds > budget["seconds"]:
            over_budget.append(f"{seconds:.1f}s, budget {budget['seconds']}s")

        open_leads = [ld.id for ld in leads if ld.status == "open"
                      and by_port.get(ld.port) is not None]
        total = len(expected["must_find"]) + len(expected["must_gap"])
        return {
            "recall": len(found) / total,
            "found": found, "missed": missed, "wrong_severity": wrong_severity,
            "false_positives": false_positives,
            "requests": requests, "seconds": round(seconds, 2),
            "over_budget": over_budget, "leads_left_open": len(open_leads),
            "gaps": [d.reason for d in degradations if d.stage != "probe:nuclei"],
            "passed": not (missed or wrong_severity or false_positives or over_budget),
        }
    finally:
        for t in targets:
            t.close()
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = run()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"recall           {result['recall']:.0%}  "
              f"({len(result['found'])} found, {len(result['missed'])} missed)")
        for item in result["missed"]:
            print(f"  missed: {item}")
        for item in result["wrong_severity"]:
            print(f"  severity: {item}")
        print(f"false positives  {len(result['false_positives'])}")
        for item in result["false_positives"]:
            print(f"  {item}")
        print(f"requests         {result['requests']}")
        print(f"time             {result['seconds']}s")
        for item in result["gaps"]:
            print(f"  gap: {item}")
        for item in result["over_budget"]:
            print(f"  over budget: {item}")
        print("PASS" if result["passed"] else "FAIL")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
