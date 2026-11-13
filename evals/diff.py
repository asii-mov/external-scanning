"""Score `extscan diff` on a planted pair of runs.

Builds two run directories from the committed lab fixture, with a known list
of differences between them, and checks that each one lands in the right
state. The states that matter most are the ones that are easy to get wrong:

* a finding the new run never looked at must be "not re-checked", not "gone"
* a finding whose title moved by a count, a version or a page title must
  stay one finding, not turn into a "gone" plus a "new"

    uv run python -m evals.diff
    uv run python -m evals.diff --json

Exit status is 1 when any planted transition is classified wrongly.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import tempfile
from pathlib import Path

from extscan.diff import diff_runs
from extscan.models import Finding, Host, Service
from extscan.resilience import Degradation
from extscan.store import Store

FIXTURE = Path(__file__).parent.parent / "tests" / "fixtures" / "lab-run"
LAB = "127.0.0.2"
STAYS, GAPPED, DESCOPED = "203.0.113.5", "203.0.113.6", "203.0.113.9"
SILENT = "203.0.113.4"       # up in the old run, no answer to host discovery in the new


_COLLECTIONS = {
    "hosts.json": (Host, "hosts", "replace_hosts"),
    "services.json": (Service, "services", "replace_services"),
    "findings.json": (Finding, "findings", "replace_findings"),
    "degradations.json": (Degradation, "degradations", "replace_degradations"),
}


def _rewrite(store: Store, name: str, change) -> None:
    """Pass one collection's records, as dicts, through `change`. Named by
    the collection's file in an exported run (`hosts.json`, ...)."""
    cls, read, replace = _COLLECTIONS[name]
    rows = change([record.to_dict() for record in getattr(store, read)()])
    getattr(store, replace)([cls.from_dict(d) for d in rows])


def _finding(host: str, port: int, source: str, title: str, severity="medium", **kw) -> Finding:
    return Finding(title=title, severity=severity, host=host, port=port, source=source,
                   evidence=kw.pop("evidence", "planted"), **kw)


def _build_old(store: Store) -> None:
    """The fixture, plus three hosts so scope and batch changes can be planted."""
    meta = store.meta()
    meta["scope"]["targets"] = [f"{LAB}/32", "203.0.113.0/28"]
    meta["policy"]["nmap"]["tcp_ports"] += ",22,80,443,8888"
    store.write_meta(meta)
    store.save_hosts([Host(ip=ip, state="up") for ip in (STAYS, GAPPED, DESCOPED, SILENT)])
    store.save_services([
        Service(STAYS, 443, "tcp", name="https", product="nginx", version="1.18.0",
                probed_by=["nuclei", "http_fingerprint", "tls"]),
        Service(STAYS, 8888, "tcp", name="http", probed_by=["nuclei", "http_fingerprint"]),
        Service(GAPPED, 80, "tcp", name="http", probed_by=["nuclei", "http_fingerprint"]),
        Service(DESCOPED, 22, "tcp", name="ssh", probed_by=["ssh"]),
        Service(SILENT, 22, "tcp", name="ssh", probed_by=["ssh"]),
    ])
    store.add_findings([
        _finding(STAYS, 443, "nuclei:CVE-2021-41773", "Apache 2.4.49 - Path Traversal", "high"),
        _finding(STAYS, 8888, "extscan:paths", f"Exposed /.env on {STAYS}:8888", "high"),
        _finding(GAPPED, 80, "extscan:paths", f"Exposed /metrics on {GAPPED}:80"),
        _finding(DESCOPED, 22, "extscan:ssh", f"SSH service on {DESCOPED}:22", "info"),
        _finding(SILENT, 22, "extscan:ssh", f"SSH service on {SILENT}:22", "info"),
        _finding(LAB, 8080, "analyst", "Billing export readable without a session", "high"),
    ])


def _build_new(store: Store) -> None:
    meta = store.meta()
    # .9 leaves the scope; port 8888 leaves the port list; no root, so no UDP.
    meta["scope"]["targets"] = [f"{LAB}/32", "203.0.113.0/29"]
    meta["policy"]["nmap"]["tcp_ports"] = meta["policy"]["nmap"]["tcp_ports"].replace(
        ",8888", ",9000")
    meta["stages"]["discover"].pop("udp")
    store.write_meta(meta)

    gone_ports = {(DESCOPED, 22), (GAPPED, 80), (STAYS, 8888), (LAB, 3306), (LAB, 10161),
                  (SILENT, 22)}
    _rewrite(store, "hosts.json", lambda rows: [h for h in rows if h["ip"] != SILENT])

    def services(rows):
        rows = [s for s in rows if (s["host"], s["port"]) not in gone_ports]
        for s in rows:
            if s["host"] == LAB:        # nuclei failed against the lab host
                s["probed_by"] = [p for p in s["probed_by"] if p != "nuclei"]
            if (s["host"], s["port"]) == (LAB, 8443):   # and the TLS probe on one port
                s["probed_by"] = [p for p in s["probed_by"] if p != "tls"]
            if (s["host"], s["port"]) == (LAB, 8080):
                s["product"], s["version"] = "nginx", "1.27.0"
        rows.append(Service(LAB, 9000, "tcp", name="http", probed_by=[]).to_dict())
        return rows

    _rewrite(store, "services.json", services)

    def findings(rows):
        kept = []
        for f in rows:
            where = (f["host"], f["port"])
            if where in gone_ports or f["source"] == "analyst":
                continue
            if f["source"].startswith(("nuclei", "nmap-udp")) and f["host"] == LAB:
                continue
            if f["source"] == "nuclei:CVE-2021-41773":          # patched, and re-checked
                continue
            if f["title"].startswith(("Verbose ASP.NET error page", "Self-signed TLS")):
                continue
            title = f["title"]
            title = title.replace("5 API operation(s)", "6 API operation(s)")
            title = title.replace("(TLSv1.3)", "(TLSv1.2)")
            title = title.replace("ACME Billing — API Console", "ACME Billing — Sign in")
            if title.startswith("Exposed /metrics") and where == (LAB, 8080):
                f["severity"] = "high"
            f["title"] = title          # the id stays the old run's: ids are not the key
            kept.append(f)
        kept.append(_finding(LAB, 8080, "extscan:paths",
                             f"Exposed /phpinfo.php on {LAB}:8080").to_dict())
        return kept

    _rewrite(store, "findings.json", findings)
    for gap in (
        Degradation(stage="probe:nuclei", component="nuclei", reason="nuclei timed out",
                    impact="Templated web checks did not complete.", severity="serious",
                    hosts=[LAB]),
        Degradation(stage="discover:tcp", component="nmap",
                    reason="tcp-0002 produced no parseable output (timed out)",
                    impact="1 host(s) in this batch were not scanned.", severity="serious",
                    hosts=[GAPPED]),
        # Carries a count and no addresses, as discovery records it. It must
        # cover the silent host and nothing that did answer.
        Degradation(stage="discover:tcp", component="nmap:host-discovery",
                    reason="1 of 9 addresses did not answer host discovery",
                    impact="nmap treated these addresses as down."),
        Degradation(stage="discover:udp", component="nmap",
                    reason="nmap -sU requires root and the run is unprivileged",
                    impact="No UDP scanning was performed.", severity="serious"),
    ):
        store.add_degradation(gap)


# What each planted difference must be classified as. `not` lists states the
# item must not appear in under any pairing.
PLANTED = [
    {"id": "new-finding", "host": LAB, "port": 8080, "title": r"^Exposed /phpinfo\.php",
     "expect": "new"},
    {"id": "count-in-title", "host": LAB, "port": 8080, "title": r"API operation\(s\) declare",
     "expect": "changed", "not": ["gone", "new", "not_rechecked"]},
    {"id": "tls-version-in-title", "host": LAB, "port": 8443, "title": r"^TLS endpoint",
     "expect": "changed", "change": "version", "not": ["gone", "new"]},
    {"id": "page-title-in-title", "host": LAB, "port": 8080, "title": r"^HTTP service: ACME",
     "expect": "changed", "not": ["gone", "new"]},
    {"id": "severity-raised", "host": LAB, "port": 8080, "title": r"^Exposed /metrics",
     "expect": "changed", "change": "severity"},
    {"id": "untouched", "host": LAB, "port": 2222, "title": r"^SSH service", "expect": "same"},
    {"id": "nuclei-gap", "host": LAB, "port": 8080, "title": r"^Generic Env File Disclosure",
     "expect": "not_rechecked", "reason": "nuclei"},
    {"id": "nuclei-rechecked-elsewhere", "host": STAYS, "port": 443, "title": r"Path Traversal",
     "expect": "gone"},
    {"id": "clean-recheck", "host": LAB, "port": 8081, "title": r"^Verbose ASP\.NET error page",
     "expect": "gone"},
    {"id": "probe-did-not-complete", "host": LAB, "port": 8443, "title": r"^Self-signed TLS",
     "expect": "not_rechecked", "reason": "tls did not complete"},
    {"id": "port-closed", "host": LAB, "port": 3306, "title": r"^MySQL reachable",
     "expect": "gone"},
    {"id": "host-out-of-scope", "host": DESCOPED, "port": 22, "title": r"^SSH service",
     "expect": "not_rechecked", "reason": "outside the run's scope"},
    {"id": "host-went-silent", "host": SILENT, "port": 22, "title": r"^SSH service",
     "expect": "not_rechecked", "reason": "did not answer host discovery"},
    {"id": "service-host-went-silent", "service": (SILENT, "tcp", 22),
     "expect": "not_rescanned"},
    {"id": "discovery-batch-gap", "host": GAPPED, "port": 80, "title": r"^Exposed /metrics",
     "expect": "not_rechecked", "reason": "discovery gap"},
    {"id": "port-not-in-list", "host": STAYS, "port": 8888, "title": r"^Exposed /\.env",
     "expect": "not_rechecked", "reason": "not in the run's port list"},
    {"id": "udp-not-run", "host": LAB, "port": 10161, "title": r"^SNMP readable",
     "expect": "not_rechecked", "reason": "UDP discovery did not run"},
    {"id": "unknown-source", "host": LAB, "port": 8080, "title": r"^Billing export",
     "expect": "not_rechecked", "reason": "nothing maps source"},
    {"id": "service-opened", "service": (LAB, "tcp", 9000), "expect": "opened"},
    {"id": "service-closed", "service": (LAB, "tcp", 3306), "expect": "closed"},
    {"id": "service-version", "service": (LAB, "tcp", 8080), "expect": "changed"},
    {"id": "service-out-of-scope", "service": (DESCOPED, "tcp", 22), "expect": "not_rescanned"},
    {"id": "service-batch-gap", "service": (GAPPED, "tcp", 80), "expect": "not_rescanned"},
    {"id": "service-port-not-in-list", "service": (STAYS, "tcp", 8888),
     "expect": "not_rescanned"},
    {"id": "service-udp-not-run", "service": (LAB, "udp", 10161), "expect": "not_rescanned"},
    {"id": "service-untouched", "service": (LAB, "tcp", 2222), "expect": "same"},
]


def build_pair(tmp: Path) -> tuple[Store, Store]:
    """Write the planted old and new runs under `tmp`. The fixture is copied,
    never modified."""
    shutil.copytree(FIXTURE, tmp / "old")
    old = Store(tmp / "old")
    _build_old(old)
    shutil.copytree(tmp / "old", tmp / "new")
    new = Store(tmp / "new")
    _build_new(new)
    return old, new


def states_of(result: dict, case: dict) -> dict[str, list[dict]]:
    """Every row of the diff that matches a planted case, by state."""
    hits: dict[str, list[dict]] = {}
    if "service" in case:
        for state, rows in result["services"].items():
            for r in rows:
                if (r["host"], r["proto"], r["port"]) == case["service"]:
                    hits.setdefault(state, []).append(r)
        return hits
    for state, rows in result["findings"].items():
        for r in rows:
            if (r["host"], r["port"]) == (case["host"], case["port"]) \
                    and re.search(case["title"], r["title"]):
                hits.setdefault(state, []).append(r)
    return hits


def judge(result: dict, case: dict) -> str:
    """Empty when the case was classified as planted, else what went wrong."""
    hits = states_of(result, case)
    if set(hits) != {case["expect"]}:
        return f"want {case['expect']}, got {sorted(hits) or 'nothing'}"
    row = hits[case["expect"]][0]
    if "reason" in case and case["reason"] not in row.get("reason", ""):
        return f"reason {row.get('reason')!r} does not mention {case['reason']!r}"
    if "change" in case and case["change"] not in row.get("changes", {}):
        return f"changes {sorted(row.get('changes', {}))} lack {case['change']!r}"
    return ""


def run() -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="extscan-diff-eval-"))
    try:
        old, new = build_pair(tmp)
        result = diff_runs(old, new)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    wrong = {c["id"]: why for c in PLANTED if (why := judge(result, c))}
    # Nothing that was only relabelled or not re-checked may be reported fixed.
    false_gone = [r["title"] for r in result["findings"]["gone"]
                  if r["source"].startswith(("nuclei", "nmap-udp", "analyst"))
                  and r["host"] == LAB and r["port"] != 3306]     # 3306 really closed
    return {
        "planted": len(PLANTED), "correct": len(PLANTED) - len(wrong), "wrong": wrong,
        "accuracy": (len(PLANTED) - len(wrong)) / len(PLANTED),
        "false_gone": false_gone, "counts": result["counts"],
        "passed": not wrong and not false_gone,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = run()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"planted transitions  {result['correct']} of {result['planted']} classified "
              f"correctly ({result['accuracy']:.0%})")
        for case, why in result["wrong"].items():
            print(f"  wrong: {case}: {why}")
        print(f"wrongly 'gone'       {len(result['false_gone'])}")
        for title in result["false_gone"]:
            print(f"  {title}")
        for kind, counts in result["counts"].items():
            print(f"{kind:<20} " + ", ".join(f"{v} {k}" for k, v in counts.items()))
        print("PASS" if result["passed"] else "FAIL")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
