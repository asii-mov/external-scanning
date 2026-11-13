"""Stage the run directories the skill eval cases refer to.

    uv run python -m evals.skill.stage [DEST]      # default: runs/

Writes two runs from the committed lab fixture, so no scanner is needed:

* `lab`         the fixture as captured (root, TCP and UDP, nuclei)
* `lab-no-udp`  the same run as an unprivileged user would have left it: no
                UDP services or findings, and the coverage gap that says so
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from extscan.pipeline import UDP_NEEDS_ROOT
from extscan.resilience import Degradation
from extscan.store import LEGACY_DIR, Store

FIXTURE = Path(__file__).parents[2] / "tests" / "fixtures" / "lab-run"


def stage(dest: Path) -> list[Path]:
    made = []
    for name in ("lab", "lab-no-udp"):
        target = dest / name
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(FIXTURE, target)
        made.append(target)

    store = Store(dest / "lab-no-udp")
    udp = [s for s in store.services() if s.proto == "udp"]
    store.replace_services(s for s in store.services() if s.proto != "udp")
    store.replace_findings(
        f for f in store.findings()
        if not f.source.startswith("nmap-udp") and (f.port, f.proto) not in
        {(s.port, "udp") for s in udp})
    store.replace_leads(ld for ld in store.leads() if ld.kind != "snmp_walk")
    store.add_degradation(Degradation(
        stage="discover:udp", component="nmap", reason=UDP_NEEDS_ROOT,
        impact="No UDP scanning was performed. SNMP, IPMI, NTP, mDNS and other UDP "
               "exposure is NOT covered by this report. Absence of UDP findings here "
               "means the check never ran.",
        severity="serious", recoverable=True,
        remedy="Re-run as root: `sudo extscan discover <run> --udp-only`",
    ))
    for stale in ("report.md", "report.json"):
        (store.path / stale).unlink(missing_ok=True)
    # The first write moved the fixture's JSON state (which still lists UDP)
    # into legacy-json/. An agent reading the directory must not find it.
    shutil.rmtree(store.path / LEGACY_DIR, ignore_errors=True)
    store.close()
    return made


if __name__ == "__main__":
    for path in stage(Path(sys.argv[1] if len(sys.argv) > 1 else "runs")):
        print(path)
