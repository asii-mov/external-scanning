"""Run directory: the single source of truth for an engagement.

Every stage reads and writes here, which is what lets a human or an agent step
in between stages, inspect the JSON, and change course. Nothing is held only in
memory, so a run survives a dropped SSH session.

    runs/<run-id>/
        run.json         metadata, scope summary, policy, stages completed
        hosts.json       discovered hosts
        services.json    open ports with service detail
        findings.json    everything destined for the report
        leads.json       follow-ups, open and resolved
        commands.jsonl   audit trail of every command executed
        raw/             verbatim tool output (nmap XML, nuclei JSONL, bodies)
        report.md        rendered report
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
from pathlib import Path

from .models import CommandRecord, Finding, Host, Lead, Service
from .resilience import Degradation

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-.")
    return (s or "run")[:40]


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.raw = self.path / "raw"

    @classmethod
    def create(cls, runs_dir: str | Path, engagement: str, run_id: str | None = None) -> Store:
        runs_dir = Path(runs_dir)
        if run_id is None:
            run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{_slug(engagement)}"
        if not RUN_ID_RE.match(run_id):
            raise ValueError(f"invalid run id {run_id!r}")
        store = cls(runs_dir / run_id)
        store.raw.mkdir(parents=True, exist_ok=True)
        return store

    @classmethod
    def open(cls, runs_dir: str | Path, run_id: str) -> Store:
        """Open an existing run. `latest` resolves to the newest run directory."""
        runs_dir = Path(runs_dir)
        if run_id in ("latest", "last"):
            candidates = sorted(
                (p for p in runs_dir.glob("*") if (p / "run.json").exists()),
                key=lambda p: (p / "run.json").stat().st_mtime,
            )
            if not candidates:
                raise FileNotFoundError(f"no runs found under {runs_dir}")
            return cls(candidates[-1])
        if not RUN_ID_RE.match(run_id):
            raise ValueError(f"invalid run id {run_id!r}")
        store = cls(runs_dir / run_id)
        if not (store.path / "run.json").exists():
            raise FileNotFoundError(f"no such run: {store.path}")
        return store

    @property
    def run_id(self) -> str:
        return self.path.name

    def _read(self, name: str, default):
        p = self.path / name
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            return default

    def _write(self, name: str, data) -> None:
        """Atomic write: a killed scan must not leave truncated state behind."""
        self.path.mkdir(parents=True, exist_ok=True)
        tmp = self.path / f".{name}.tmp"
        tmp.write_text(json.dumps(data, indent=2, sort_keys=False, default=str))
        tmp.replace(self.path / name)

    def meta(self) -> dict:
        return self._read("run.json", {})

    def write_meta(self, meta: dict) -> None:
        self._write("run.json", meta)

    def update_meta(self, **fields) -> dict:
        meta = self.meta()
        meta.update(fields)
        self.write_meta(meta)
        return meta

    def mark_stage(self, stage: str, **detail) -> None:
        meta = self.meta()
        stages = meta.setdefault("stages", {})
        stages[stage] = {"completed": time.time(), **detail}
        self.write_meta(meta)

    def stage_done(self, stage: str) -> bool:
        return stage in self.meta().get("stages", {})

    def hosts(self) -> list[Host]:
        return [Host.from_dict(d) for d in self._read("hosts.json", [])]

    def save_hosts(self, hosts: Iterable[Host]) -> None:
        merged: dict[str, Host] = {h.ip: h for h in self.hosts()}
        for h in hosts:
            existing = merged.get(h.ip)
            if existing:
                existing.hostnames = sorted(set(existing.hostnames) | set(h.hostnames))
                existing.state = h.state or existing.state
                existing.os_guess = h.os_guess or existing.os_guess
            else:
                merged[h.ip] = h
        self._write("hosts.json", [h.to_dict() for h in merged.values()])

    def services(self) -> list[Service]:
        return [Service.from_dict(d) for d in self._read("services.json", [])]

    def save_services(self, services: Iterable[Service]) -> None:
        merged: dict[str, Service] = {s.id: s for s in self.services()}
        for s in services:
            prev = merged.get(s.id)
            if prev:
                s.probed_by = sorted(set(prev.probed_by) | set(s.probed_by))
                s.scripts = {**prev.scripts, **s.scripts}
            merged[s.id] = s
        order = {"tcp": 0, "udp": 1}
        self._write(
            "services.json",
            [s.to_dict() for s in sorted(merged.values(),
                                         key=lambda x: (x.host, order.get(x.proto, 9), x.port))],
        )

    def mark_probed(self, service_id: str, probe: str) -> None:
        services = self.services()
        for s in services:
            if s.id == service_id and probe not in s.probed_by:
                s.probed_by.append(probe)
        self._write("services.json", [s.to_dict() for s in services])

    def findings(self) -> list[Finding]:
        return [Finding.from_dict(d) for d in self._read("findings.json", [])]

    def add_findings(self, findings: Iterable[Finding]) -> int:
        existing = {f.id: f for f in self.findings()}
        added = 0
        for f in findings:
            if f.id not in existing:
                existing[f.id] = f
                added += 1
        self._write("findings.json", [f.to_dict() for f in existing.values()])
        return added

    def replace_findings(self, findings: Iterable[Finding]) -> None:
        self._write("findings.json", [f.to_dict() for f in findings])

    def leads(self, status: str | None = None) -> list[Lead]:
        leads = [Lead.from_dict(d) for d in self._read("leads.json", [])]
        return [ld for ld in leads if status is None or ld.status == status]

    def add_leads(self, leads: Iterable[Lead], max_total: int = 10_000) -> int:
        existing = {ld.id: ld for ld in self.leads()}
        added = 0
        for ld in leads:
            if ld.id in existing:
                continue
            if len(existing) >= max_total:
                break
            existing[ld.id] = ld
            added += 1
        self._write("leads.json", [ld.to_dict() for ld in existing.values()])
        return added

    def update_lead(self, lead_id: str, **fields) -> Lead | None:
        leads = self.leads()
        hit = None
        for ld in leads:
            if ld.id == lead_id:
                for k, v in fields.items():
                    setattr(ld, k, v)
                hit = ld
        self._write("leads.json", [ld.to_dict() for ld in leads])
        return hit

    def degradations(self) -> list[Degradation]:
        return [Degradation.from_dict(d) for d in self._read("degradations.json", [])]

    def add_degradation(self, deg: Degradation) -> None:
        existing = self.degradations()
        key = (deg.stage, deg.component, deg.reason)
        if any((d.stage, d.component, d.reason) == key for d in existing):
            return
        existing.append(deg)
        self._write("degradations.json", [d.to_dict() for d in existing])

    def checkpoint(self, stage: str, key: str) -> None:
        data = self._read("checkpoints.json", {})
        data.setdefault(stage, [])
        if key not in data[stage]:
            data[stage].append(key)
        self._write("checkpoints.json", data)

    def checkpoints(self, stage: str) -> set[str]:
        return set(self._read("checkpoints.json", {}).get(stage, []))

    def is_done(self, stage: str, key: str) -> bool:
        return key in self.checkpoints(stage)

    def clear_checkpoints(self, stage: str | None = None) -> None:
        if stage is None:
            self._write("checkpoints.json", {})
            return
        data = self._read("checkpoints.json", {})
        data.pop(stage, None)
        self._write("checkpoints.json", data)

    def log_command(self, rec: CommandRecord) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        with (self.path / "commands.jsonl").open("a") as fh:
            fh.write(json.dumps(rec.to_dict()) + "\n")

    def commands(self) -> list[dict]:
        p = self.path / "commands.jsonl"
        if not p.exists():
            return []
        out = []
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def raw_path(self, name: str) -> Path:
        """Map an arbitrary label (often target-derived) to a safe filename."""
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
        safe = re.sub(r"\.{2,}", ".", safe).lstrip("._-") or "artifact"
        self.raw.mkdir(parents=True, exist_ok=True)
        return self.raw / safe[:200]

    def write_raw(self, name: str, content: str | bytes) -> Path:
        p = self.raw_path(name)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
        return p

    def counts(self) -> dict:
        findings = self.findings()
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "hosts": len(self.hosts()),
            "services": len(self.services()),
            "findings": len(findings),
            "findings_by_severity": by_sev,
            "review_required": sum(1 for f in findings if f.review_required),
            "leads_open": len(self.leads("open")),
            "leads_total": len(self.leads()),
            "degradations": len(self.degradations()),
        }
