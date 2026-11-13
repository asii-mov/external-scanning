"""Score a run directory against a ground-truth file.

Works on any run of the lab: the committed fixture (no scanners needed) or a
fresh one, so the same scorecard tracks detection and cost over time.

    uv run python -m evals.score                       # tests/fixtures/lab-run
    uv run python -m evals.score runs/<run-id>         # a lab run you just made
    uv run python -m evals.score runs/<run-id> --json

What it measures:

* recall         planted issues found, at the expected severity, review flag
                 and confidence
* honesty        an expected item that is missing must be explained by a
                 recorded coverage gap for the stage it needs. Missing with no
                 gap is the failure this tool exists to prevent.
* review noise   share of the manual review queue that is nothing but
                 info-level nmap script output. Some of that belongs there
                 (a page title, the allowed methods); the threshold is a
                 ceiling so housekeeping scripts do not creep back in. The
                 queue is the handover to a person, and filler costs them.
* duplication    findings per distinct issue
* cost           wall-clock per stage and per external tool, from run.json
                 and commands.jsonl

By default the nmap and nuclei findings are rebuilt from the run's raw/
output with the current parsers (see `replay`); `--stored` scores
the stored findings exactly as the run left them.

Exit status is 1 when a threshold in the expected file is missed.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from extscan.models import Finding
from extscan.store import Store
from extscan.tools import nmap, nuclei
from extscan.triage import triage

ROOT = Path(__file__).parent
FIXTURE = ROOT.parent / "tests" / "fixtures" / "lab-run"
LAB = ROOT / "expected" / "lab.json"


def _matches(f: Finding, want: dict) -> bool:
    if "port" in want and f.port != want["port"]:
        return False
    if "ports" in want and f.port not in want["ports"]:
        return False
    if "source" in want and not f.source.startswith(want["source"]):
        return False
    return "title" not in want or re.search(want["title"], f.title) is not None


def _stage_seconds(meta: dict) -> dict[str, float]:
    """Seconds each stage took, read off the completion timestamps."""
    out: dict[str, float] = {}
    previous = meta.get("created")
    stages = sorted(meta.get("stages", {}).items(), key=lambda kv: kv[1].get("completed", 0))
    for name, detail in stages:
        done = detail.get("completed")
        if previous is not None and done is not None and done >= previous:
            out[name] = round(done - previous, 1)
        previous = done or previous
    return out


def replay(store: Store) -> list[Finding]:
    """The run's findings with the nmap and nuclei ones rebuilt from raw/.

    A stored finding is what the code of the day made of the tool output.
    Parsing the captured XML and JSONL again puts today's parsers in front of
    real scanner output, with no scanner. Findings from extscan's own probes
    cannot be rebuilt offline and are kept as stored.
    """
    rebuilt: list[Finding] = []
    for xml in sorted(store.raw.glob("nmap-*.xml")):
        kind = "udp" if xml.name.startswith("nmap-udp") else "tcp"
        text, _ = nmap.salvage_partial_xml(xml.read_text(errors="replace"))
        rebuilt += nmap.parse_xml(text, source=f"nmap-{kind}")[2]
    for jsonl in sorted(store.raw.glob("nuclei*.jsonl")):     # one file per batch
        rebuilt += nuclei.parse_jsonl(jsonl.read_text(errors="replace"))[0]
    kept = [f for f in store.findings() if not f.source.startswith(("nmap-", "nuclei"))]
    return list({f.id: f for f in kept + rebuilt}.values())


def score(run_dir: str | Path, expected_path: str | Path = LAB,
          replay_raw: bool = True) -> dict:
    store = Store(run_dir)
    expected = json.loads(Path(expected_path).read_text())
    findings = replay(store) if replay_raw else store.findings()
    gap_stages = {d.stage for d in store.degradations()}

    found, missed, not_assessed, wrong = [], [], [], []
    for want in expected["must_find"]:
        hits = [f for f in findings if _matches(f, want)]
        if not hits:
            if want.get("needs") in gap_stages:
                not_assessed.append(f"{want['id']} (gap recorded for {want['needs']})")
            else:
                missed.append(want["id"])
            continue
        found.append(want["id"])
        if not any(f.severity == want["severity"] for f in hits):
            wrong.append(f"{want['id']}: severity {sorted({f.severity for f in hits})}, "
                         f"want {want['severity']}")
        if want.get("review") and not any(f.review_required for f in hits):
            wrong.append(f"{want['id']}: not flagged for review")
        if "confidence" in want and not any(f.confidence == want["confidence"] for f in hits):
            wrong.append(f"{want['id']}: confidence is not {want['confidence']}")

    assessed = len(found) + len(missed)
    triaged = triage(findings, store.services())
    queue = triaged.review_queue
    source = {f.id: f.source for f in findings}
    noise = [item for item in queue if item.severity == "info"
             and all(source[i].startswith("nmap-") for i in item.finding_ids)]
    distinct = triaged.stats.get("distinct_issues") or len(findings) or 1
    leads = store.leads()

    tools: dict[str, float] = {}
    for cmd in store.commands():
        if cmd.get("argv") and cmd.get("returncode") is not None:
            tool = Path(cmd["argv"][0]).name
            tools[tool] = round(tools.get(tool, 0.0) + float(cmd.get("duration") or 0), 1)

    result = {
        "run": str(run_dir),
        "recall": round(len(found) / assessed, 3) if assessed else 0.0,
        "found": len(found), "missed": missed, "not_assessed": not_assessed,
        "wrong": wrong,
        "known_false_positives": sorted({
            fp["id"] for fp in expected.get("known_false_positives", [])
            if any(_matches(f, fp) for f in findings)}),
        "known_misses": [m["id"] for m in expected.get("known_misses", [])
                         if not any(_matches(f, m) for f in findings)],
        "findings": len(findings),
        "duplication": round(len(findings) / distinct, 2),
        "review_queue": len(queue),
        "review_noise": round(len(noise) / len(queue), 3) if queue else 0.0,
        "open_leads": sum(1 for ld in leads if ld.status == "open"),
        "coverage_gaps": sorted(gap_stages),
        "stage_seconds": _stage_seconds(store.meta()),
        "tool_seconds": tools,
    }

    limits = expected.get("thresholds", {})
    failures = list(wrong)
    if result["recall"] < limits.get("recall", 1.0):
        failures.append(f"recall {result['recall']:.0%}: missed {', '.join(missed)} "
                        "with no coverage gap to explain it")
    if result["review_noise"] > limits.get("max_review_noise", 1.0):
        failures.append(f"review noise {result['review_noise']:.0%} is over "
                        f"{limits['max_review_noise']:.0%}")
    if result["duplication"] > limits.get("max_duplication", 99):
        failures.append(f"duplication {result['duplication']} is over "
                        f"{limits['max_duplication']}")
    if result["open_leads"] > limits.get("max_open_leads", 10**6):
        failures.append(f"{result['open_leads']} lead(s) left open")
    result["failures"] = failures
    result["passed"] = not failures
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run", nargs="?", default=str(FIXTURE), help="run directory")
    ap.add_argument("--expected", default=str(LAB))
    ap.add_argument("--stored", action="store_true",
                    help="score the findings as stored, without re-parsing raw/")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    r = score(args.run, args.expected, replay_raw=not args.stored)
    if args.json:
        print(json.dumps(r, indent=2))
        return 0 if r["passed"] else 1

    print(f"run              {r['run']}")
    print(f"recall           {r['recall']:.0%}  ({r['found']} found, {len(r['missed'])} missed, "
          f"{len(r['not_assessed'])} not assessed)")
    for label in ("missed", "not_assessed", "wrong"):
        for item in r[label]:
            print(f"  {label.replace('_', ' ')}: {item}")
    print(f"findings         {r['findings']}  ({r['duplication']} per distinct issue)")
    print(f"review queue     {r['review_queue']}  ({r['review_noise']:.0%} info-level nmap scripts)")
    print(f"open leads       {r['open_leads']}")
    print(f"coverage gaps    {', '.join(r['coverage_gaps']) or 'none'}")
    print(f"known FPs seen   {', '.join(r['known_false_positives']) or 'none'}")
    print(f"known misses     {', '.join(r['known_misses']) or 'none'}")
    print(f"stage seconds    {r['stage_seconds']}")
    print(f"tool seconds     {r['tool_seconds']}")
    for item in r["failures"]:
        print(f"FAIL: {item}")
    print("PASS" if r["passed"] else "FAIL")
    return 0 if r["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
