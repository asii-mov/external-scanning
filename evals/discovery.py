"""Discovery cost eval: single-phase against two-phase on a sparse range.

No scanner and no network. A fake `nmap` on PATH answers from a JSON "world"
(which hosts are up, which ports are open) and logs every invocation, so the
work each mode asks nmap to do can be counted:

* invocations             nmap runs;
* fingerprint attempts    hosts x ports handed to a run with -sV, the
                          expensive part of a real scan.

The scope is a /24 with a handful of live hosts. Two-phase must report the
same services as single-phase and ask for less fingerprint work.

    uv run python -m evals.discovery            # scorecard
    uv run python -m evals.discovery --json

The fake is also what `tests/test_discovery_accuracy.py` plants its cases
with: `install_fake_nmap` and `write_world`.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

from extscan import pipeline
from extscan.policy import Policy
from extscan.runner import Runner
from extscan.scope import Scope
from extscan.store import Store

# The fake reads its world on every call, so a test can change the world
# between two discovery runs. Keys, all optional:
#   open            {host: [tcp ports]}       open TCP ports
#   up              [hosts]                   up, nothing open
#   udp             {host: {port: state}}     UDP port states
#   retransmit      [hosts]                   nmap prints its retransmission-cap warning
#   host_timeout    [hosts]                   nmap prints "Skipping host ..."
#   timedout_xml    [hosts]                   <host timedout="true"> in the XML
#   fail            [text]                    exit 1, no output, if the -oA path has the text
#   cut_short       [text]                    write XML with no closing tag, exit 1
#   sleep           seconds                   every run takes this long
#   slow            {text: seconds}           ... or this long instead, if the -oA path has the text
FAKE_NMAP = r'''
import ipaddress, json, sys, time

WORLD, LOG = __WORLD__, __LOG__
args = sys.argv[1:]
world = json.load(open(WORLD))


def after(flag):
    return args[args.index(flag) + 1] if flag in args else ""


def is_ip(text):
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def expand(spec):
    ports = set()
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        if lo.isdigit():
            ports.update(range(int(lo), int(hi or lo) + 1))
    return ports


base, wanted = after("-oA"), expand(after("-p"))
targets = [a for a in args if is_ip(a)]
udp, versions, assume_up = "-sU" in args, "-sV" in args, "-Pn" in args
with open(LOG, "a") as fh:
    fh.write(json.dumps({"argv": args, "targets": targets, "ports": len(wanted),
                         "sV": versions, "udp": udp, "base": base}) + "\n")
named = [secs for text, secs in world.get("slow", {}).items() if text in base]
time.sleep(max(named) if named else world.get("sleep", 0))
if any(text in base for text in world.get("fail", [])):
    sys.exit(1)

table = world.get("udp", {}) if udp else world.get("open", {})
alive = set(world.get("open", {})) | set(world.get("up", [])) | set(world.get("udp", {}))
up = [t for t in targets if assume_up or t in alive]
out = ['<?xml version="1.0"?>', "<!DOCTYPE nmaprun>", '<nmaprun scanner="nmap">']
for host in targets:
    if host in world.get("timedout_xml", []):
        out.append('<host timedout="true"><status state="up"/>'
                   '<address addr="%s" addrtype="ipv4"/></host>' % host)
        continue
    states = table.get(host, {})
    if not udp:
        states = {str(p): "open" for p in states}
    shown = {p: s for p, s in states.items() if int(p) in wanted}
    if host not in up or not shown:
        continue
    out.append('<host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports>' % host)
    for port, state in sorted(shown.items(), key=lambda kv: int(kv[0])):
        service = '<service name="%s"/>' % ("snmp" if udp else "http") if versions else ""
        out.append('<port protocol="%s" portid="%s"><state state="%s"/>%s</port>'
                   % ("udp" if udp else "tcp", port, state, service))
    out.append("</ports></host>")
cut = any(text in base for text in world.get("cut_short", []))
if not cut:
    out.append('<runstats><finished exit="success"/><hosts up="%d" down="%d" total="%d"/>'
               "</runstats></nmaprun>" % (len(up), len(targets) - len(up), len(targets)))
open(base + ".xml", "w").write("\n".join(out) + "\n")

for host in targets:
    if host in world.get("retransmit", []):
        print("Warning: %s giving up on port because retransmission cap hit (2)." % host)
    if host in world.get("host_timeout", []):
        print("Skipping host edge.example (%s) due to host timeout" % host)
print("Nmap done: %d IP addresses (%d hosts up)" % (len(targets), len(up)))
sys.exit(1 if cut else 0)
'''


def install_fake_nmap(bin_dir: Path, world: Path, log: Path) -> None:
    """Put the fake on `bin_dir` as `nmap`. It runs under this interpreter,
    so it works with PATH cut down to `bin_dir` alone."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    source = FAKE_NMAP.replace("__WORLD__", repr(str(world))).replace("__LOG__", repr(str(log)))
    path = bin_dir / "nmap"
    path.write_text(f"#!{sys.executable}\n{source}")
    path.chmod(0o755)


def write_world(world: Path, **facts) -> None:
    world.write_text(json.dumps(facts))


def calls(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line]


SCOPE = "198.51.100.0/24"       # TEST-NET-2; nothing is sent, the fake answers
LIVE = {
    "198.51.100.3": [22, 80],
    "198.51.100.40": [443],
    "198.51.100.41": [80, 443, 8080],
    "198.51.100.97": [22],
    "198.51.100.130": [3389],
    "198.51.100.200": [80],
    "198.51.100.201": [8443],
    "198.51.100.250": [25, 443],
}
UP_NOTHING_OPEN = ["198.51.100.9", "198.51.100.77"]


def _discover(tmp: Path, mode: str) -> dict:
    """One TCP discovery of the scope in `mode`; what it found and what it cost."""
    root = tmp / mode
    root.mkdir()
    world, log = root / "world.json", root / "calls.jsonl"
    write_world(world, open=LIVE, up=UP_NOTHING_OPEN)
    install_fake_nmap(root / "bin", world, log)
    scope_file = root / "scope.json"
    scope_file.write_text(json.dumps({
        "engagement": "eval", "client": "eval",
        "authorization": {"reference": "EVAL", "authorized_by": "eval"},
        "targets": [SCOPE],
    }))
    scope = Scope.load(scope_file)
    policy = Policy()
    policy.nmap.sweep = mode
    store = Store.create(root / "runs", "eval", run_id="r")
    store.write_meta({"run_id": "r"})
    with mock.patch.dict(os.environ, {"PATH": str(root / "bin")}), \
            contextlib.redirect_stdout(io.StringIO()):
        pipeline.discover(store, scope, policy, Runner(store), udp=False)
    made = calls(log)
    return {
        "services": sorted((s.host, s.port, s.name) for s in store.services()),
        "invocations": len(made),
        "fingerprint_attempts": sum(len(c["targets"]) * c["ports"] for c in made if c["sV"]),
        "hosts_fingerprinted": sum(len(c["targets"]) for c in made if c["sV"]),
        "gaps": [d.reason for d in store.degradations()],
        "addresses": scope.host_count(),
    }


def run() -> dict:
    tmp = Path(tempfile.mkdtemp())
    try:
        single = _discover(tmp, "never")
        two = _discover(tmp, "always")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    expected = sorted((h, p, "http") for h, ports in LIVE.items() for p in ports)
    silent = single["addresses"] - len(LIVE) - len(UP_NOTHING_OPEN)
    want_gap = [f"{silent} of {single['addresses']} addresses did not answer host discovery"]
    problems = []
    if single["services"] != expected:
        problems.append("single-phase did not report the planted services")
    if two["services"] != single["services"]:
        problems.append("two-phase reported different services from single-phase")
    if two["fingerprint_attempts"] >= single["fingerprint_attempts"]:
        problems.append("two-phase did not reduce fingerprint work")
    if two["hosts_fingerprinted"] != len(LIVE):
        problems.append(f"two-phase fingerprinted {two['hosts_fingerprinted']} host(s), "
                        f"want the {len(LIVE)} with open ports")
    for name, result in (("single-phase", single), ("two-phase", two)):
        if result["gaps"] != want_gap:
            problems.append(f"{name} gaps are {result['gaps']}, want {want_gap}")
    keep = ("invocations", "fingerprint_attempts", "hosts_fingerprinted")
    return {
        "addresses": single["addresses"], "live_hosts": len(LIVE),
        "services": len(expected),
        "single_phase": {k: single[k] for k in keep},
        "two_phase": {k: two[k] for k in keep},
        "problems": problems, "passed": not problems,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = run()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"scope                  {result['addresses']} addresses, "
              f"{result['live_hosts']} with open ports, {result['services']} services")
        for name in ("single_phase", "two_phase"):
            r = result[name]
            print(f"{name:<22} {r['invocations']} nmap run(s), "
                  f"{r['hosts_fingerprinted']} host(s) fingerprinted, "
                  f"{r['fingerprint_attempts']} host-port attempts")
        for item in result["problems"]:
            print(f"  problem: {item}")
        print("PASS" if result["passed"] else "FAIL")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
