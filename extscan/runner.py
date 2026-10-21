"""Audited subprocess execution.

Every external command the pipeline runs goes through here so that:

* it is executed as an argv list, never through a shell. Hostnames, URLs and
  paths in these commands frequently originate in scanner output, i.e. from
  the target. `shell=True` anywhere in this file would turn a hostile HTTP
  header into command execution on the auditor's own box;
* it lands in commands.jsonl with its exit code, duration and output paths,
  so the report can show exactly what was run and the client can reproduce it;
* --dry-run can print the plan without sending a packet.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass

from .models import CommandRecord
from .store import Store


class ToolMissing(Exception):
    def __init__(self, tool: str):
        super().__init__(
            f"required tool {tool!r} not found on PATH. Run `extscan doctor` "
            "for install hints."
        )
        self.tool = tool


@dataclass
class Result:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    skipped: bool = False          # true when dry-run
    stdout_path: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise ToolMissing(tool)
    return path


class Runner:
    def __init__(self, store: Store, dry_run: bool = False, verbose: bool = False):
        self.store = store
        self.dry_run = dry_run
        self.verbose = verbose

    def run(
        self,
        argv: list[str],
        *,
        stage: str = "",
        timeout: int = 600,
        stdout_name: str | None = None,
        check: bool = False,
        input_text: str | None = None,
    ) -> Result:
        argv = [str(a) for a in argv]
        if self.verbose or self.dry_run:
            print(f"  $ {' '.join(argv)}", flush=True)

        if self.dry_run:
            self.store.log_command(CommandRecord(
                argv=argv, started=time.time(), duration=0.0, returncode=None,
                stage=stage, error="dry-run: not executed",
            ))
            return Result(argv, None, "", "", 0.0, skipped=True)

        started = time.time()
        timed_out = False
        error = ""
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                input=input_text,
                shell=False,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc = None
            out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            error = f"timed out after {timeout}s"
        except FileNotFoundError:
            raise ToolMissing(argv[0]) from None
        except OSError as exc:
            rc, out, err = None, "", str(exc)
            error = f"exec failed: {exc}"

        duration = time.time() - started

        # Persist output. Large tool dumps belong on disk, not in memory or in
        # an agent's context window.
        out_path = err_path = ""
        if stdout_name:
            base = stdout_name
            if out:
                out_path = str(self.store.write_raw(f"{base}.stdout", out))
            if err:
                err_path = str(self.store.write_raw(f"{base}.stderr", err))

        self.store.log_command(CommandRecord(
            argv=argv, started=started, duration=duration, returncode=rc,
            stdout_path=out_path, stderr_path=err_path, stage=stage,
            timed_out=timed_out, error=error,
        ))

        result = Result(argv, rc, out, err, duration, timed_out=timed_out, stdout_path=out_path)
        if check and not result.ok:
            raise RuntimeError(
                f"command failed ({rc}{', timed out' if timed_out else ''}): "
                f"{' '.join(argv)}\n{err.strip()[:800]}"
            )
        return result

    def tool_version(self, tool: str, *args: str) -> str:
        """Best-effort version string for the report appendix."""
        if not have(tool):
            return "not installed"
        try:
            proc = subprocess.run(
                [tool, *(args or ("--version",))],
                capture_output=True, text=True, errors="replace", timeout=20, shell=False,
            )
        except Exception as exc:
            return f"unknown ({exc})"
        text = (proc.stdout or proc.stderr or "").strip()
        return text.splitlines()[0][:200] if text else "unknown"


# Install hints shown by `extscan doctor`. Kept here so the runner is the one
# place that knows about external binaries.
TOOL_HINTS: dict[str, dict[str, str]] = {
    "nmap": {
        "purpose": "TCP/UDP port and service discovery (required)",
        "debian": "sudo apt install nmap",
        "macos": "brew install nmap",
    },
    "nuclei": {
        "purpose": "templated web/service vulnerability checks (required for web probes)",
        "debian": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "macos": "brew install nuclei",
    },
    "httpx": {
        "purpose": "fast HTTP fingerprinting before nuclei (optional)",
        "debian": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "macos": "brew install httpx",
    },
    "testssl.sh": {
        "purpose": "detailed TLS configuration audit (optional)",
        "debian": "git clone --depth 1 https://github.com/testssl/testssl.sh",
        "macos": "brew install testssl",
    },
    "snmpwalk": {
        "purpose": "richer SNMP enumeration after a community-string hit (optional; "
                   "extscan has a built-in SNMP GET that needs no external tool)",
        "debian": "sudo apt install snmp",
        "macos": "brew install net-snmp",
    },
}


def doctor() -> dict:
    """Report which external tools are available."""
    rows = {}
    for tool, info in TOOL_HINTS.items():
        present = have(tool)
        rows[tool] = {
            "present": present,
            "path": shutil.which(tool) or "",
            "purpose": info["purpose"],
            "install_debian": info.get("debian", ""),
            "install_macos": info.get("macos", ""),
        }
    rows["_notes"] = {
        "nmap_privileges": (
            "UDP scans (-sU), SYN scans (-sS) and OS detection need root. Either "
            "run extscan with sudo, or grant nmap CAP_NET_RAW: "
            "sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)"
        ),
    }
    return rows
