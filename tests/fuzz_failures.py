"""Property-based fuzzing of tool failure states against the real pipeline.

Hypothesis generates a ToolFailure for each external tool: how it exits (any
code, any signal, or a hang past its timeout), what it writes to its output
file (nothing, intact, truncated, random bytes, or byte flips), and what it
prints. Fake executables on PATH act that out, the real stages run, and every
run is checked against the README's promise that reduced coverage never
looks like a clean result.

Opt-in, because it needs Hypothesis and takes a few minutes:

    uv run --with hypothesis python -m unittest tests.fuzz_failures -v

FUZZ_EXAMPLES=500 raises the example count per property.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import signal
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from unittest import mock

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from extscan import pipeline
from extscan.models import Service
from extscan.policy import Policy
from extscan.resilience import RunAborted
from extscan.runner import Runner
from extscan.scope import Scope
from extscan.store import Store
from extscan.tools import nmap, nuclei, snmp, sslscan

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLES = int(os.environ.get("FUZZ_EXAMPLES", "60"))
TOOL_TIMEOUT = 2

STOP_SIGNALS = {signal.SIGSTOP, signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU}

FAKE_TOOL = f"""#!{sys.executable} -I
import json, os, sys, time
tool = os.path.basename(sys.argv[0])
sc = json.load(open(os.environ["FUZZ_SCENARIO"]))[tool]
args = sys.argv[1:]
if tool == "nmap":
    out = args[args.index("-oA") + 1] + ".xml"
elif tool == "nuclei":
    out = args[args.index("-output") + 1]
else:
    out = next(a for a in args if a.startswith("--xml=")).split("=", 1)[1]
if sc["output"] is not None:
    open(out, "wb").write(bytes.fromhex(sc["output"]))
sys.stdout.write(sc["stdout"])
sys.stderr.write(sc["stderr"])
sys.stdout.flush()
kind, value = sc["exit"]
if kind == "hang":
    time.sleep(60)
if kind == "signal":
    os.kill(os.getpid(), value)
    time.sleep(0.2)
sys.exit(value if kind == "code" else 0)
"""


@dataclass(frozen=True)
class ToolFailure:
    exit: tuple[str, int]
    output: str | None
    stdout: str
    stderr: str


def outputs(fixture: bytes):
    return st.one_of(
        st.none(),
        st.just(fixture),
        st.integers(0, len(fixture) - 1).map(lambda n: fixture[:n]),
        st.binary(max_size=2048),
        st.lists(st.tuples(st.integers(0, len(fixture) - 1), st.integers(0, 255)),
                 min_size=1, max_size=8).map(lambda flips: _flip(fixture, flips)),
    )


def _flip(data: bytes, flips) -> bytes:
    out = bytearray(data)
    for i, b in flips:
        out[i] = b
    return bytes(out)


def failures(fixture: bytes, can_hang: bool = True):
    signals = [s for s in range(1, 65)
               if s not in {32, 33} and (can_hang or s not in STOP_SIGNALS)]
    exits = [st.tuples(st.just("code"), st.integers(0, 255)),
             st.tuples(st.just("signal"), st.sampled_from(signals))]
    if can_hang:
        exits.append(st.just(("hang", 0)))
    return st.builds(
        ToolFailure,
        exit=st.one_of(*exits),
        output=outputs(fixture).map(lambda b: None if b is None else b.hex()),
        stdout=st.text(max_size=200),
        stderr=st.text(max_size=200),
    )


def finished_nmap_doc(hexdata: str | None) -> bool:
    """Independent oracle: did nmap leave a complete, well-formed document?

    Decoded leniently, as nmap output is: a bad byte inside a comment or a
    value does not lose a host, a missing closing tag does.
    """
    if hexdata is None:
        return False
    try:
        root = ET.fromstring(bytes.fromhex(hexdata).decode(errors="replace"))  # noqa: S314
    except ET.ParseError:
        return False
    return root.tag == "nmaprun" and root.find("runstats/finished") is not None


class _Harness:
    def __init__(self, targets: list[str]):
        self.tmp = Path(tempfile.mkdtemp())
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for tool in ("nmap", "nuclei", "sslscan"):
            path = self.bin / tool
            path.write_text(FAKE_TOOL)
            path.chmod(0o755)
        sp = self.tmp / "scope.json"
        sp.write_text(json.dumps({
            "engagement": "fuzz", "client": "c",
            "authorization": {"reference": "FUZZ", "authorized_by": "x"},
            "targets": targets, "allow_private": True,
        }))
        self.scope = Scope.load(sp)
        self.store = Store.create(self.tmp / "runs", "fuzz", run_id="r")
        self.store.write_meta({"run_id": "r"})
        self.policy = Policy()
        self.policy.nmap.timeout_sec = TOOL_TIMEOUT
        self.policy.nuclei.timeout_sec = TOOL_TIMEOUT
        self.policy.http.timeout_sec = 1

    def env(self, scenario: dict[str, ToolFailure]):
        path = self.tmp / "scenario.json"
        path.write_text(json.dumps({k: asdict(v) for k, v in scenario.items()}))
        return mock.patch.dict(os.environ, {"PATH": str(self.bin),
                                            "FUZZ_SCENARIO": str(path)})

    def command(self, stage_prefix: str) -> dict:
        lines = (self.store.path / "commands.jsonl").read_text().splitlines()
        return next(r for r in map(json.loads, reversed(lines))
                    if r["stage"].startswith(stage_prefix))

    def gap_stages(self) -> set[str]:
        return {d.stage for d in self.store.degradations()}

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def _ok(record: dict) -> bool:
    return record["returncode"] == 0 and not record["timed_out"]


FUZZ = settings(max_examples=EXAMPLES, deadline=None, derandomize=False,
                suppress_health_check=[HealthCheck.too_slow])


class FuzzDiscovery(unittest.TestCase):
    @FUZZ
    @given(failures((FIXTURES / "nmap-tcp.xml").read_bytes()))
    def test_unfinished_nmap_output_is_always_a_gap(self, failure: ToolFailure):
        h = _Harness(["203.0.113.10/31", "203.0.113.12/32", "198.51.100.99/32"])
        try:
            with h.env({"nmap": failure}), contextlib.redirect_stdout(io.StringIO()):
                try:
                    pipeline.discover(h.store, h.scope, h.policy, Runner(h.store),
                                      udp=False)
                except RunAborted:
                    return
            if not finished_nmap_doc(failure.output):
                self.assertIn("discover:tcp", h.gap_stages(),
                              "unfinished nmap output left no coverage gap")
            h.store.services()
            pipeline.make_report(h.store, h.scope)
            report = (h.store.path / "report.md").read_text()
            for d in h.store.degradations():
                self.assertIn(d.impact[:60], report, "gap missing from report")
        finally:
            h.close()


class FuzzProbe(unittest.TestCase):
    web = Service(host="127.0.0.1", port=9, proto="tcp", name="http", tunnel="ssl")

    @FUZZ
    @given(failures((FIXTURES / "nuclei.jsonl").read_bytes()),
           failures((FIXTURES / "sslscan.xml").read_bytes(), can_hang=False))
    def test_failed_tool_is_a_gap_and_service_stays_unprobed(self, nuc, ssl):
        h = _Harness(["127.0.0.1/32"])
        try:
            h.store.save_services([self.web])
            with h.env({"nuclei": nuc, "sslscan": ssl}), \
                    contextlib.redirect_stdout(io.StringIO()):
                pipeline.probe(h.store, h.scope, h.policy, Runner(h.store),
                               only=["nuclei", "sslscan"])
            probed = h.store.services()[0].probed_by
            for tool in ("nuclei", "sslscan"):
                gap = f"probe:{tool}" in h.gap_stages()
                self.assertNotEqual(tool in probed, gap,
                                    f"{tool} must be either checked or a gap, never both or neither")
                if not _ok(h.command(f"probe:{tool}")):
                    self.assertTrue(gap, f"failed {tool} left no gap")
        finally:
            h.close()


class FuzzParsers(unittest.TestCase):
    """Target-controlled bytes reach these parsers.

    ValueError is their documented contract for garbage, and the pipeline
    turns it into a coverage gap. Anything else escaping is a bug.
    """

    @FUZZ
    @given(outputs((FIXTURES / "nmap-tcp.xml").read_bytes()).filter(lambda b: b is not None))
    def test_nmap_salvage_and_parse(self, data: bytes):
        text, _ = nmap.salvage_partial_xml(data.decode(errors="replace"))
        if text:
            with contextlib.suppress(ValueError):
                nmap.parse_xml(text)

    @FUZZ
    @given(outputs((FIXTURES / "nuclei.jsonl").read_bytes()).filter(lambda b: b is not None))
    def test_nuclei_jsonl(self, data: bytes):
        with contextlib.suppress(ValueError):
            nuclei.parse_jsonl(data.decode(errors="replace"))

    @FUZZ
    @given(outputs((FIXTURES / "sslscan.xml").read_bytes()).filter(lambda b: b is not None))
    def test_sslscan_xml(self, data: bytes):
        with contextlib.suppress(ValueError):
            sslscan.parse_xml(data.decode(errors="replace"))

    @FUZZ
    @given(st.binary(max_size=512))
    def test_snmp_reply(self, data: bytes):
        snmp._parse_reply(data)


if __name__ == "__main__":
    unittest.main()
