"""Check that IP redaction keeps real addresses away from the model provider.

A fake Messages API listens on 127.0.0.1 and keeps every request body the
real `anthropic` SDK sends it in memory. `extscan analyse` runs as a separate
process, pointed at it through `llm.base_url`, against a copy of a run. So
what is checked is the bytes that would have left the host, not a function's
return value.

The fake model answers each request by quoting every address it was shown,
plus the `.1` and the `/24` of each IPv4 one, as if it had reasoned about the
gateway and the network. Those come back through the restore step into the
notes written to the run.

Three passes over the same run:

* `off`: `--no-redact-ips`. The baseline: real addresses must reach the
  provider, which shows the leak check can see a leak.
* `on`: redaction on. No real address may reach the provider, and the notes
  must hold the real addresses (and derived ones), never a fake.
* `synthetic`: redaction on, after planting findings whose text holds
  addresses in every form extscan output uses (ip:port, URLs, CIDRs, ranges,
  defanged, IPv6, IPv4-mapped) and strings that must not change (SNMP OIDs,
  four-part versions, netmasks, link-local metadata address).

The leak check is a plain substring search for each known real address, not
the redactor's own pattern, which would be blind to its own misses.

    uv run python -m evals.redaction                 # the committed lab fixture
    uv run python -m evals.redaction runs/<id>       # a run of your own
    uv run python -m evals.redaction --json

Needs the optional SDK (`uv sync --extra llm`). Exit status 1 on any failure.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from extscan.models import Finding
from extscan.store import Store

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "lab-run"

# Deliberately looser than the redactor's pattern: anything dotted-quad-shaped.
_ANY_V4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_ANY_V6 = re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}")
_HEX_COLON_RUN = re.compile(r"[0-9A-Fa-f:]+")

# Planted by the synthetic pass. Placeholder ranges only (TEST-NET, RFC 1918,
# documentation IPv6), never a real network.
SYNTHETIC_REAL = [
    "203.0.113.10", "203.0.113.11", "198.51.100.7", "192.0.2.44",
    "10.20.30.40", "10.20.30.41", "172.16.5.9", "192.168.77.12", "100.64.1.2",
    "127.0.0.2",
    "2001:db8:abcd:12::10", "fd12:3456:789a:1::5",
    "2001:db8:abcd:12::11", "fd12:3456:789a:1::6",
    "10.20.30.43", "10.20.30.44", "10.20.30.45", "198.51.100.8",
]
SYNTHETIC_TEXT = """\
Exposed admin panel at http://203.0.113.10:8080/admin and https://[2001:db8:abcd:12::10]:8443/.
Sibling host 203.0.113.11 answered on 22/tcp. Origin 198.51.100.7 leaks behind the CDN.
X-Forwarded-For: 10.20.30.40, 172.16.5.9
Internal range 10.20.30.0/24 (10.20.30.1-10.20.30.254) referenced in /etc/hosts:
10.20.30.41  db01
192.168.77.12:5432 postgres, ULA fd12:3456:789a:1::5, mapped ::ffff:100.64.1.2
Threat-intel style: 192[.]0[.]2[.]44 and lab loopback 127.0.0.2.
JSON: {"ip":"10.20.30.40","peer":"203.0.113.10"}
X-Forwarded-For:2001:db8:abcd:12::11
connect to fd12:3456:789a:1::6: connection refused
tcp/10.20.30.43:443 admin/10.20.30.44 ipAdEntAddr.10.20.30.45
https://a-rather-long-internal-hostname.corp.example.com/198.51.100.8
"""
# Must arrive at the provider byte-for-byte.
SYNTHETIC_KEEP = [
    "1.3.6.1.2.1.1.1.0", ".1.3.6.1.4.1.9", "version 1.2.3.4", "v2.0.0.1",
    "255.255.255.0", "169.254.169.254", "0.0.0.0/0", "fe80::1%eth0", "::1",
    "aa:bb:cc:dd:ee:ff", "12:30:45",
]


# -- the fake provider -----------------------------------------------------------

class Capture:
    def __init__(self):
        self.bodies: list[str] = []
        self.lock = threading.Lock()


_DEFANGED = re.compile(r"\[\.\]|\(\.\)|\{\.\}")


def _undefang(text: str) -> str:
    return _DEFANGED.sub(".", text)


# "Chrome/128.0.0.0": a product version, not an address. Spelled out here
# rather than imported, so the harness keeps its own idea of what is real.
_PRODUCT_VERSION = re.compile(r"[A-Za-z]/\d+\.0\.0\.0(?!\d)")


def _addresses(text: str) -> list[str]:
    """Every address in text, by a parse rather than the redactor's pattern."""
    text = _PRODUCT_VERSION.sub("", _undefang(text))
    found: list[str] = []
    for m in _ANY_V4.finditer(text):
        with contextlib.suppress(ValueError):
            found.append(str(ipaddress.IPv4Address(m.group(0))))
    # The longest substring of each hex-and-colon run that parses, so a
    # label or trailing colon cannot hide an address from the check.
    for m in _HEX_COLON_RUN.finditer(text):
        run = m.group(0)
        if run.count(":") < 2 or len(run) > 60:
            continue
        cuts = [0] + [i + 1 for i, c in enumerate(run) if c == ":"]
        ends = [len(run), *sorted((i for i, c in enumerate(run) if c == ":"), reverse=True)]
        spans = sorted(((s, e) for s in cuts for e in ends if e - s >= 2),
                       key=lambda span: span[0] - span[1])
        for s, e in spans:
            try:
                addr = ipaddress.IPv6Address(run[s:e])
            except ValueError:
                continue
            if addr.ipv4_mapped is None and _identifying(str(addr)):
                found.append(str(addr))
            break
    return list(dict.fromkeys(found))


def _echo_reply(user_text: str) -> str:
    """What a model that reasoned about the addresses might say."""
    seen = [a for a in _addresses(user_text) if ipaddress.ip_address(a).version == 4]
    derived = []
    for a in seen:
        net = ipaddress.ip_network(f"{a}/24", strict=False)
        derived += [str(net.network_address + 1), str(net)]
    v6 = [a for a in _addresses(user_text) if ipaddress.ip_address(a).version == 6]
    return json.dumps({
        "summary": "Addresses involved: " + ", ".join(seen + v6) + ".",
        "severity_opinion": "low",
        "reasoning": "Gateway and network: " + ", ".join(derived) + ".",
        "questions_for_auditor": [],
        "suggested_followups": [],
    })


def _handler(capture: Capture):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length", 0))).decode()
            with capture.lock:
                capture.bodies.append(body)
            request = json.loads(body)
            user = "".join(
                m["content"] if isinstance(m["content"], str)
                else "".join(b.get("text", "") for b in m["content"])
                for m in request["messages"])
            reply = json.dumps({
                "id": "msg_capture", "type": "message", "role": "assistant",
                "model": request.get("model", "capture"),
                "content": [{"type": "text", "text": _echo_reply(user)}],
                "stop_reason": "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

    return Handler


# -- one pass --------------------------------------------------------------------

def _identifying(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if ip.version == 4:
        return not (ip in ipaddress.ip_network("0.0.0.0/8") or ip.is_link_local
                    or ip.is_multicast or ip in ipaddress.ip_network("240.0.0.0/4"))
    # Only ULA and global unicast identify a network; the rest is reserved.
    return ip in ipaddress.ip_network("fc00::/7") or ip in ipaddress.ip_network("2000::/3")


def _contains(text: str, addr: str) -> bool:
    """Strict: only a digit (IPv4) or hex digit (IPv6) continuing it means
    a different address. Labels, colons and dots around it do not."""
    if ":" in addr:
        pattern = rf"(?<![0-9A-Fa-f]){re.escape(addr)}(?![0-9A-Fa-f])"
    else:
        pattern = rf"(?<!\d){re.escape(addr)}(?!\d)"
    return re.search(pattern, text) is not None


def _mem_available_mib() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    return -1


def run_pass(source: Path, mode: str, workdir: Path) -> dict:
    capture = Capture()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(capture))
    threading.Thread(target=server.serve_forever, daemon=True).start()

    runs = workdir / mode
    shutil.copytree(source, runs / "r")
    store = Store.open(runs, "r")
    if mode == "synthetic":
        hosts = SYNTHETIC_REAL[:3]
        store.add_findings([
            Finding(title=f"Synthetic exposure {i}", severity="high", host=h, port=8080,
                    source="synthetic", description=SYNTHETIC_TEXT,
                    evidence="\n".join(SYNTHETIC_KEEP))
            for i, h in enumerate(hosts)])
    before = store.findings()
    decoys = set(_addresses("\n".join(SYNTHETIC_KEEP)))
    real = sorted(({a for f in before
                    for a in _addresses(f"{f.host} {f.title} {f.description} {f.evidence}")
                    if _identifying(a)} - decoys)
                  | ({*SYNTHETIC_REAL} if mode == "synthetic" else set()))
    store.close()

    policy = workdir / f"policy-{mode}.json"
    policy.write_text(json.dumps({"llm": {
        "enabled": True, "provider": "anthropic", "model": "capture",
        "base_url": f"http://127.0.0.1:{server.server_port}",
        "analyse_findings_above": "info", "max_findings": 500,
        "retry_attempts": 1, "circuit_failure_threshold": 1000}}))
    env = {**os.environ, "ANTHROPIC_API_KEY": "placeholder-not-a-key",
           "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1", "EXTSCAN_OFFLINE": "1"}
    cmd = [sys.executable, "-m", "extscan", "--runs-dir", str(runs), "analyse", "r",
           "--policy", str(policy)]
    if mode == "off":
        cmd.append("--no-redact-ips")
    mem_before = _mem_available_mib()
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=ROOT)
    mem_after = _mem_available_mib()
    server.shutdown()
    server.server_close()

    store = Store.open(runs, "r")
    notes = [f for f in store.findings() if f.source == "llm-analysis"]
    note_text = "\n".join(f"{f.description}\n{f.review_reason}" for f in notes)
    store.close()

    # Defanged forms count as a leak too.
    sent = _undefang("\n".join(capture.bodies))
    leaked = [a for a in real if _contains(sent, a)]
    # A fake is an identifying address the provider saw that is not real.
    fakes = sorted({a for a in _addresses(sent) if _identifying(a)} - set(real) - decoys)
    fakes_in_notes = [a for a in fakes if _contains(note_text, a)]
    real_in_notes = [a for a in real if _contains(note_text, a)]
    result = {
        "mode": mode, "exit": proc.returncode, "requests": len(capture.bodies),
        "notes": len(notes), "real_addresses": real, "leaked": leaked,
        "fakes_sent": fakes, "fakes_in_notes": fakes_in_notes,
        "real_in_notes": real_in_notes,
        "mem_available_mib": [mem_before, mem_after],
        "children_max_rss_mib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024,
        "stderr_tail": proc.stderr[-400:],
    }
    problems = []
    if (proc.returncode != 0 or not notes
            or " 0 finding(s) without one" not in proc.stdout):
        problems.append(f"analyse exited {proc.returncode} with {len(capture.bodies)} "
                        f"request(s) and {len(notes)} note(s)")
    if mode == "off":
        if not leaked:
            problems.append("baseline sent no real address: the leak check proves nothing")
    else:
        if leaked:
            problems.append(f"real addresses reached the provider: {leaked}")
        if fakes_in_notes:
            problems.append(f"fake addresses left in the notes: {fakes_in_notes}")
        if not real_in_notes:
            problems.append("no real address came back into the notes")
        if "pseudonymised" not in sent:
            problems.append("the system prompt does not say addresses are pseudonymised")
    if mode == "synthetic":
        raw_sent = "\n".join(capture.bodies)
        missing_keep = [k for k in SYNTHETIC_KEEP
                        if json.dumps(k)[1:-1] not in raw_sent]
        if missing_keep:
            problems.append(f"strings that must not change were rewritten: {missing_keep}")
        result["kept"] = len(SYNTHETIC_KEEP) - len(missing_keep)
        # Each planted address and the derived .1 must come back as real.
        for a in SYNTHETIC_REAL:
            if not _contains(note_text, a):
                problems.append(f"{a} did not come back into the notes")
        for gw in ("203.0.113.1", "10.20.30.1", "203.0.113.0/24"):
            if gw not in note_text:
                problems.append(f"derived address {gw} did not map back")
    result["problems"] = problems
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run", nargs="?", default=str(FIXTURE))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        import anthropic  # noqa: F401
    except ImportError:
        print("needs the anthropic SDK: uv sync --extra llm", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="extscan-redaction-") as tmp:
        results = [run_pass(Path(args.run), mode, Path(tmp))
                   for mode in ("off", "on", "synthetic")]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            status = "PASS" if not r["problems"] else "FAIL"
            print(f"[{status}] {r['mode']:9} requests={r['requests']:3} "
                  f"notes={r['notes']:3} real={len(r['real_addresses'])} "
                  f"leaked={len(r['leaked'])} fakes_sent={len(r['fakes_sent'])} "
                  f"fakes_in_notes={len(r['fakes_in_notes'])} "
                  f"real_in_notes={len(r['real_in_notes'])} "
                  f"mem_avail={r['mem_available_mib'][0]}->{r['mem_available_mib'][1]}MiB "
                  f"child_rss={r['children_max_rss_mib']}MiB")
            for p in r["problems"]:
                print(f"         - {p}")
    return 0 if all(not r["problems"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
