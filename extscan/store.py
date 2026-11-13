"""Run directory: the single source of truth for an engagement.

Every stage reads and writes here, which is what lets a human or an agent step
in between stages, look at the state, and change course. Nothing is held only
in memory, so a run survives a dropped SSH session.

    runs/<run-id>/
        run.json         metadata, scope summary, policy, stages completed
        state.db         SQLite: hosts, services, findings, leads, coverage
                         gaps, checkpoints, batch figures, screenshot records
        commands.jsonl   audit trail of every command executed
        raw/             verbatim tool output (nmap XML, nuclei JSONL, bodies)
        report.md        rendered report

State is read through the CLI (`extscan hosts|services|findings|leads|gaps|
status <run> --json`) or written out as plain JSON files with `extscan export
<run>`. Each record is one row holding the record as JSON, next to the
columns it is looked up by, so `sqlite3 state.db` shows the same fields.

Why a database: a mutation is one small transaction (insert a finding, update
one lead) instead of a rewrite of a whole JSON file, and a killed process
leaves either the state before the call or the state after it. The rollback
journal is used, never WAL: part of a run can be done as root (`sudo extscan
discover <run> --udp-only`), and WAL's `-wal`/`-shm` files would be left
root-owned and lock the user out.

Threads: one connection per Store, guarded by a re-entrant lock. Any method
may be called from any thread. Another process (or another Store on the same
directory) is kept out by SQLite's file lock for the length of a write.

Runs written before the database existed keep their state in JSON files
(`hosts.json`, `findings.json`, ...). They are read as they are, and reading
writes nothing. The first write to such a run imports the JSON into
`state.db` in one transaction and then moves the JSON files into
`legacy-json/`, so no stale file is left looking like live state.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from .models import CommandRecord, Finding, Host, Lead, Service
from .resilience import Degradation

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

STATE_DB = "state.db"
LEGACY_DIR = "legacy-json"
EXPORT_DIR = "export"
SCHEMA_VERSION = 1

# The JSON layout: what old runs hold, and what `export` writes.
STATE_FILES = {
    "hosts": "hosts.json",
    "services": "services.json",
    "findings": "findings.json",
    "leads": "leads.json",
    "degradations": "degradations.json",
    "checkpoints": "checkpoints.json",
    "batches": "batches.json",
    "screenshots": "screenshots.json",
}

_SCHEMA = (
    "CREATE TABLE schema_info (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
    # `seq` is insertion order, which is the order reports list records in.
    "CREATE TABLE hosts (seq INTEGER PRIMARY KEY, ip TEXT NOT NULL UNIQUE, data TEXT NOT NULL)",
    "CREATE TABLE services (id TEXT PRIMARY KEY, host TEXT NOT NULL, proto TEXT NOT NULL, "
    "port INTEGER NOT NULL, data TEXT NOT NULL) WITHOUT ROWID",
    "CREATE TABLE findings (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, "
    "data TEXT NOT NULL)",
    "CREATE TABLE leads (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, "
    "status TEXT NOT NULL, data TEXT NOT NULL)",
    "CREATE INDEX leads_status ON leads (status)",
    "CREATE TABLE degradations (seq INTEGER PRIMARY KEY, stage TEXT NOT NULL, "
    "component TEXT NOT NULL, reason TEXT NOT NULL, data TEXT NOT NULL, "
    "UNIQUE (stage, component, reason))",
    "CREATE TABLE checkpoints (seq INTEGER PRIMARY KEY, stage TEXT NOT NULL, "
    "key TEXT NOT NULL, UNIQUE (stage, key))",
    "CREATE TABLE batch_stats (seq INTEGER PRIMARY KEY, stage TEXT NOT NULL, "
    "key TEXT NOT NULL, data TEXT NOT NULL, UNIQUE (stage, key))",
    "CREATE TABLE screenshots (seq INTEGER PRIMARY KEY, data TEXT NOT NULL)",
)

_SERVICE_ORDER = ("host, CASE proto WHEN 'tcp' THEN 0 WHEN 'udp' THEN 1 ELSE 9 END, "
                  "port, proto")


def _slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-.")
    return (s or "run")[:40]


def _dump(data) -> str:
    return json.dumps(data, default=str)


def _service_id(d: dict) -> str:
    return f"{d['host']}/{d['proto']}/{d['port']}"


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.raw = self.path / "raw"
        self.db_path = self.path / STATE_DB
        self._lock = threading.RLock()          # the connection and run.json
        self._log_lock = threading.Lock()       # commands.jsonl
        self._db: sqlite3.Connection | None = None
        self._depth = 0                         # open transaction nesting
        self._swept = False                     # legacy JSON already moved aside
        # Decoded coverage gaps, valid while `_gaps_version` is the
        # database's data_version (which moves when anyone else commits).
        self._gaps: list[tuple[int, Degradation]] | None = None
        self._gaps_version = -1

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close()

    def close(self) -> None:
        """Close the database connection. The Store stays usable: the next
        call opens it again."""
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
                self._gaps = None

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

    @property
    def layout(self) -> str:
        """`sqlite`, `legacy-json` (an old run nothing has written to since),
        or `empty`."""
        if self._connect() is not None:
            return "sqlite"
        if any((self.path / name).exists() for name in STATE_FILES.values()):
            return "legacy-json"
        return "empty"

    # --- files ---------------------------------------------------------------

    def _read(self, name: str, default):
        p = self.path / name
        if not p.exists():
            return default
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError:
            return default
        return data if isinstance(data, type(default)) else default

    def _write(self, name: str, data) -> None:
        """Atomic write: a killed scan must not leave truncated state behind."""
        self.path.mkdir(parents=True, exist_ok=True)
        tmp = self.path / f".{name}.tmp"
        tmp.write_text(json.dumps(data, indent=2, sort_keys=False, default=str))
        self._hand_over(tmp)
        tmp.replace(self.path / name)

    def _hand_over(self, path: Path) -> None:
        """Give a file root has just created to the run directory's owner.

        `sudo extscan discover <run> --udp-only` works inside a run the
        normal user owns. Whatever it creates there has to stay writable by
        that user, or every later unprivileged stage fails.
        """
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return
        with contextlib.suppress(OSError):
            owner = self.path.stat()
            if (owner.st_uid, owner.st_gid) != (0, 0):
                os.chown(path, owner.st_uid, owner.st_gid)

    # --- database ------------------------------------------------------------

    def _connect(self, create: bool = False) -> sqlite3.Connection | None:
        """The connection, or None when there is no database and `create` is
        false: reading never creates anything in a run directory."""
        with self._lock:
            if self._db is None:
                if not self.db_path.exists():
                    if not create:
                        return None
                    self.path.mkdir(parents=True, exist_ok=True)
                # Autocommit: every transaction below is opened explicitly.
                db = sqlite3.connect(self.db_path, timeout=60.0, isolation_level=None,
                                     check_same_thread=False)
                try:
                    db.execute("PRAGMA journal_mode = DELETE")     # never WAL, see above
                    db.execute("PRAGMA synchronous = FULL")
                    ready = _initialised(db)
                    if not ready and create:
                        self._initialise(db)
                        ready = True
                except sqlite3.OperationalError as exc:
                    db.close()
                    self._raise_if_not_writable(exc)
                    raise
                except BaseException:
                    db.close()
                    raise
                if not ready:
                    # A file something died while creating. Nothing is in it,
                    # so an old run's JSON is still the state.
                    db.close()
                    return None
                self._db = db
            if create and not self._swept:
                self._move_legacy_aside()
            return self._db

    def _initialise(self, db: sqlite3.Connection) -> None:
        """Create the tables and, in the same transaction, import the JSON
        state of an old run. A crash leaves no tables, and the next writer
        starts again from the JSON files, which are still in place."""
        db.execute("BEGIN IMMEDIATE")
        try:
            if not _initialised(db):        # another process may have got there first
                for statement in _SCHEMA:
                    db.execute(statement)
                db.execute("INSERT INTO schema_info VALUES ('version', ?)",
                           (str(SCHEMA_VERSION),))
                self._import_legacy(db)
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
        self._hand_over(self.db_path)

    def _import_legacy(self, db: sqlite3.Connection) -> None:
        imported = [name for name in STATE_FILES.values() if (self.path / name).exists()]
        if not imported:
            return
        # Through the dataclasses, so a record written before a field existed
        # is stored with today's defaults, exactly as reading it would give.
        def load(collection: str, cls) -> list[dict]:
            return [cls.from_dict(d).to_dict()
                    for d in self._read(STATE_FILES[collection], [])]

        _put_hosts(db, load("hosts", Host))
        _put_services(db, load("services", Service))
        _put_findings(db, load("findings", Finding))
        _put_leads(db, load("leads", Lead))
        _put_degradations(db, load("degradations", Degradation))
        for stage, keys in self._read(STATE_FILES["checkpoints"], {}).items():
            db.executemany("INSERT OR IGNORE INTO checkpoints (stage, key) VALUES (?, ?)",
                           [(stage, key) for key in keys])
        for stage, batches in self._read(STATE_FILES["batches"], {}).items():
            db.executemany(
                "INSERT OR REPLACE INTO batch_stats (stage, key, data) VALUES (?, ?, ?)",
                [(stage, key, _dump(stats)) for key, stats in batches.items()])
        _put_screenshots(db, self._read(STATE_FILES["screenshots"], []))
        db.execute("INSERT INTO schema_info VALUES ('imported_from', ?)",
                   (_dump(imported),))

    def _move_legacy_aside(self) -> None:
        """Once the database holds the state, JSON state files in the run
        directory are stale. Move them out of the way, keeping them."""
        self._swept = True
        stale = [self.path / name for name in STATE_FILES.values()
                 if (self.path / name).exists()]
        if not stale:
            return
        aside = self.path / LEGACY_DIR
        aside.mkdir(exist_ok=True)
        self._hand_over(aside)
        for src in stale:
            dst, n = aside / src.name, 0
            while dst.exists():
                n += 1
                dst = aside / f"{src.name}.{n}"
            src.replace(dst)

    def _raise_if_not_writable(self, exc: Exception) -> None:
        """Say what to chown when the database cannot be written, which is
        what a database left root-owned by a sudo run looks like."""
        text = str(exc).lower()
        if "readonly" not in text and "unable to open" not in text:
            return
        try:
            owner = f"uid {self.db_path.stat().st_uid}"
        except OSError:
            owner = "another user"
        raise PermissionError(
            f"cannot write {self.db_path} (owned by {owner}). If part of this run was "
            f"done with sudo, give the run directory back to your user: "
            f"sudo chown -R \"$(id -u):$(id -g)\" {self.path}") from exc

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """One write transaction. Nested uses join the outer one."""
        with self._lock:
            db = self._connect(create=True)
            if self._depth:
                self._depth += 1
                try:
                    yield db
                finally:
                    self._depth -= 1
                return
            try:
                db.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                self._raise_if_not_writable(exc)
                raise
            self._depth = 1
            try:
                yield db
            except BaseException as exc:
                self._gaps = None
                db.execute("ROLLBACK")
                if isinstance(exc, sqlite3.OperationalError):
                    self._raise_if_not_writable(exc)
                raise
            else:
                try:
                    db.execute("COMMIT")
                except BaseException:
                    self._gaps = None
                    with contextlib.suppress(sqlite3.Error):
                        db.execute("ROLLBACK")
                    raise
            finally:
                self._depth = 0

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """Make several mutations one commit: all of them land, or none.

            with store.transaction():
                store.add_findings(findings)
                store.mark_probed(service_id, probe)

        Other threads wait at their next Store call until it ends, so keep
        the body short and do no network or subprocess work inside it.
        """
        with self._tx():
            yield

    def _rows(self, sql: str, args: tuple = ()) -> list[tuple] | None:
        """Query rows, or None when this run has no database (yet)."""
        with self._lock:
            db = self._connect()
            return None if db is None else db.execute(sql, args).fetchall()

    def _records(self, table: str, where: str = "", args: tuple = (),
                 order: str = "seq") -> list[dict]:
        rows = self._rows(f"SELECT data FROM {table} {where} ORDER BY {order}", args)  # noqa: S608
        if rows is None:
            return self._read(STATE_FILES[table], [])
        return [json.loads(r[0]) for r in rows]

    # --- run.json ------------------------------------------------------------

    def meta(self) -> dict:
        return self._read("run.json", {})

    def write_meta(self, meta: dict) -> None:
        with self._lock:
            self._write("run.json", meta)

    def update_meta(self, **fields) -> dict:
        with self._lock:
            meta = self.meta()
            meta.update(fields)
            self.write_meta(meta)
            return meta

    def mark_stage(self, stage: str, **detail) -> None:
        with self._lock:
            meta = self.meta()
            stages = meta.setdefault("stages", {})
            stages[stage] = {"completed": time.time(), **detail}
            self.write_meta(meta)

    def stage_done(self, stage: str) -> bool:
        return stage in self.meta().get("stages", {})

    # --- hosts ---------------------------------------------------------------

    def hosts(self) -> list[Host]:
        return [Host.from_dict(d) for d in self._records("hosts")]

    def save_hosts(self, hosts: Iterable[Host]) -> None:
        hosts = list(hosts)
        if not hosts:
            return
        with self._tx() as db:
            for h in hosts:
                row = db.execute("SELECT data FROM hosts WHERE ip = ?", (h.ip,)).fetchone()
                if row is None:
                    db.execute("INSERT INTO hosts (ip, data) VALUES (?, ?)",
                               (h.ip, _dump(h.to_dict())))
                    continue
                existing = Host.from_dict(json.loads(row[0]))
                existing.hostnames = sorted(set(existing.hostnames) | set(h.hostnames))
                existing.state = h.state or existing.state
                existing.os_guess = h.os_guess or existing.os_guess
                db.execute("UPDATE hosts SET data = ? WHERE ip = ?",
                           (_dump(existing.to_dict()), h.ip))

    def replace_hosts(self, hosts: Iterable[Host]) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM hosts")
            _put_hosts(db, [h.to_dict() for h in hosts])

    def tag_hosts(self, tags: dict[str, str], checked: set[str]) -> None:
        """Set `Host.network` from the enrich stage's range lookup.

        `tags` maps ip -> network for the hosts that matched. `checked` names
        the networks that were looked up this time: a host carrying one of
        those and no longer matching loses its tag, while a tag from a
        network that could not be looked up is left as it was.
        """
        with self._tx() as db:
            for h in self.hosts():
                if h.ip in tags:
                    network = tags[h.ip]
                elif h.network in checked:
                    network = ""
                else:
                    continue
                if network != h.network:
                    h.network = network
                    db.execute("UPDATE hosts SET data = ? WHERE ip = ?",
                               (_dump(h.to_dict()), h.ip))

    # --- services ------------------------------------------------------------

    def services(self) -> list[Service]:
        return [Service.from_dict(d) for d in self._records("services", order=_SERVICE_ORDER)]

    def service_ids(self) -> set[str]:
        rows = self._rows("SELECT id FROM services")
        if rows is None:
            return {_service_id(d) for d in self._read(STATE_FILES["services"], [])}
        return {r[0] for r in rows}

    def save_services(self, services: Iterable[Service]) -> None:
        """Add or replace services. A service already on record keeps its
        `probed_by` and its script output, merged with the new record's."""
        services = list(services)
        if not services:
            return
        with self._tx() as db:
            for s in services:
                row = db.execute("SELECT data FROM services WHERE id = ?", (s.id,)).fetchone()
                if row is not None:
                    prev = json.loads(row[0])
                    s.probed_by = sorted(set(prev.get("probed_by", [])) | set(s.probed_by))
                    s.scripts = {**prev.get("scripts", {}), **s.scripts}
                db.execute("INSERT OR REPLACE INTO services VALUES (?, ?, ?, ?, ?)",
                           (s.id, s.host, s.proto, s.port, _dump(s.to_dict())))

    def replace_services(self, services: Iterable[Service]) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM services")
            _put_services(db, [s.to_dict() for s in services])

    def mark_probed(self, service_id: str, probe: str) -> None:
        self.mark_probed_many([(service_id, probe)])

    def mark_probed_many(self, pairs: Iterable[tuple[str, str]]) -> None:
        """Record (service id, probe) pairs in one transaction."""
        wanted: dict[str, list[str]] = {}
        for service_id, probe in pairs:
            wanted.setdefault(service_id, []).append(probe)
        if not wanted:
            return
        with self._tx() as db:
            for service_id, probes in wanted.items():
                row = db.execute("SELECT data FROM services WHERE id = ?",
                                 (service_id,)).fetchone()
                if row is None:
                    continue
                data = json.loads(row[0])
                probed = data.setdefault("probed_by", [])
                new = [p for p in dict.fromkeys(probes) if p not in probed]
                if new:
                    probed += new
                    db.execute("UPDATE services SET data = ? WHERE id = ?",
                               (_dump(data), service_id))

    # --- findings ------------------------------------------------------------

    def findings(self) -> list[Finding]:
        return [Finding.from_dict(d) for d in self._records("findings")]

    def add_findings(self, findings: Iterable[Finding]) -> int:
        """Add the findings whose id is not on record yet. Returns how many."""
        findings = list(findings)
        if not findings:
            return 0
        added = 0
        with self._tx() as db:
            for f in findings:
                added += db.execute("INSERT OR IGNORE INTO findings (id, data) VALUES (?, ?)",
                                    (f.id, _dump(f.to_dict()))).rowcount
        return added

    def replace_findings(self, findings: Iterable[Finding]) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM findings")
            _put_findings(db, [f.to_dict() for f in findings])

    # --- leads ---------------------------------------------------------------

    def leads(self, status: str | None = None) -> list[Lead]:
        if status is None or self._connect() is None:
            leads = [Lead.from_dict(d) for d in self._records("leads")]
            return [ld for ld in leads if status is None or ld.status == status]
        return [Lead.from_dict(d)
                for d in self._records("leads", "WHERE status = ?", (status,))]

    def add_leads(self, leads: Iterable[Lead], max_total: int = 10_000) -> int:
        leads = list(leads)
        if not leads:
            return 0
        added = 0
        with self._tx() as db:
            total = db.execute("SELECT COUNT(*) FROM leads").fetchone()[0]
            for ld in leads:
                if db.execute("SELECT 1 FROM leads WHERE id = ?", (ld.id,)).fetchone():
                    continue
                if total >= max_total:
                    break
                db.execute("INSERT INTO leads (id, status, data) VALUES (?, ?, ?)",
                           (ld.id, ld.status, _dump(ld.to_dict())))
                total += 1
                added += 1
        return added

    def replace_leads(self, leads: Iterable[Lead]) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM leads")
            _put_leads(db, [ld.to_dict() for ld in leads])

    def update_lead(self, lead_id: str, **fields) -> Lead | None:
        with self._tx() as db:
            row = db.execute("SELECT data FROM leads WHERE id = ?", (lead_id,)).fetchone()
            if row is None:
                return None
            lead = Lead.from_dict(json.loads(row[0]))
            for k, v in fields.items():
                setattr(lead, k, v)
            db.execute("UPDATE leads SET id = ?, status = ?, data = ? WHERE id = ?",
                       (lead.id, lead.status, _dump(lead.to_dict()), lead_id))
            return lead

    # --- coverage gaps -------------------------------------------------------

    def _gap_rows(self) -> list[tuple[int, Degradation]] | None:
        """Every gap with its row number, decoded once and kept until the
        database changes. Clearing gaps is a Python predicate over all of
        them, called after every batch and probe, so decoding each time
        would cost more than the write. Callers must not change the objects.
        """
        with self._lock:
            db = self._connect()
            if db is None:
                return None
            version = db.execute("PRAGMA data_version").fetchone()[0]
            if self._gaps is None or version != self._gaps_version:
                self._gaps = [
                    (seq, Degradation.from_dict(json.loads(data))) for seq, data in
                    db.execute("SELECT seq, data FROM degradations ORDER BY seq")]
                self._gaps_version = version
            return self._gaps

    def degradations(self) -> list[Degradation]:
        with self._lock:
            rows = self._gap_rows()
            if rows is None:
                return [Degradation.from_dict(d)
                        for d in self._read(STATE_FILES["degradations"], [])]
            return [Degradation.from_dict(d.to_dict()) for _, d in rows]

    def add_degradation(self, deg: Degradation) -> None:
        """Record a gap, unless one with the same stage, component and
        reason is already on record."""
        with self._tx() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO degradations (stage, component, reason, data) "
                "VALUES (?, ?, ?, ?)",
                (deg.stage, deg.component, deg.reason, _dump(deg.to_dict())))
            if cur.rowcount and self._gaps is not None:
                # Keep the decoded list in step rather than decode it all again.
                self._gaps.append((cur.lastrowid, Degradation.from_dict(deg.to_dict())))

    def replace_degradations(self, gaps: Iterable[Degradation]) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM degradations")
            _put_degradations(db, [d.to_dict() for d in gaps])
            self._gaps = None

    def remove_degradations(self, match: Callable[[Degradation], bool]) -> None:
        """Drop recorded gaps that later work has covered."""
        with self._lock:
            rows = self._gap_rows()
            if rows is None:
                # An old run: only import it if there is something to drop.
                if not any(match(d) for d in self.degradations()):
                    return
            elif not any(match(d) for _, d in rows):
                return
            with self._tx() as db:
                rows = self._gap_rows() or []
                doomed = {seq for seq, d in rows if match(d)}
                db.executemany("DELETE FROM degradations WHERE seq = ?",
                               [(seq,) for seq in doomed])
                self._gaps = [(seq, d) for seq, d in rows if seq not in doomed]

    # --- checkpoints ---------------------------------------------------------

    def checkpoint(self, stage: str, key: str) -> None:
        with self._tx() as db:
            db.execute("INSERT OR IGNORE INTO checkpoints (stage, key) VALUES (?, ?)",
                       (stage, key))

    def checkpoints(self, stage: str) -> set[str]:
        rows = self._rows("SELECT key FROM checkpoints WHERE stage = ?", (stage,))
        if rows is None:
            return set(self._read(STATE_FILES["checkpoints"], {}).get(stage, []))
        return {r[0] for r in rows}

    def all_checkpoints(self) -> dict[str, list[str]]:
        """Every stage's checkpoint keys, in the order they were recorded."""
        rows = self._rows("SELECT stage, key FROM checkpoints ORDER BY seq")
        if rows is None:
            return {stage: list(keys)
                    for stage, keys in self._read(STATE_FILES["checkpoints"], {}).items()}
        out: dict[str, list[str]] = {}
        for stage, key in rows:
            out.setdefault(stage, []).append(key)
        return out

    def is_done(self, stage: str, key: str) -> bool:
        return key in self.checkpoints(stage)

    def clear_checkpoints(self, stage: str | None = None) -> None:
        with self._tx() as db:
            if stage is None:
                db.execute("DELETE FROM checkpoints")
            else:
                db.execute("DELETE FROM checkpoints WHERE stage = ?", (stage,))

    # What each discovery batch measured (addresses asked and up, open ports
    # a sweep found, unconfirmed UDP ports), kept so a resumed run still has
    # the figures for the batches it skips.

    def batch_stats(self, stage: str) -> dict[str, dict]:
        rows = self._rows("SELECT key, data FROM batch_stats WHERE stage = ? ORDER BY seq",
                          (stage,))
        if rows is None:
            return dict(self._read(STATE_FILES["batches"], {}).get(stage, {}))
        return {key: json.loads(data) for key, data in rows}

    def all_batch_stats(self) -> dict[str, dict[str, dict]]:
        rows = self._rows("SELECT stage, key, data FROM batch_stats ORDER BY seq")
        if rows is None:
            return self._read(STATE_FILES["batches"], {})
        out: dict[str, dict[str, dict]] = {}
        for stage, key, data in rows:
            out.setdefault(stage, {})[key] = json.loads(data)
        return out

    def save_batch_stats(self, stage: str, key: str, stats: dict | None) -> None:
        """Record one batch's figures; None forgets them."""
        if stats is None and key not in self.batch_stats(stage):
            return
        with self._tx() as db:
            if stats is None:
                db.execute("DELETE FROM batch_stats WHERE stage = ? AND key = ?", (stage, key))
            else:
                # Not INSERT OR REPLACE: a batch scanned again keeps its place.
                db.execute(
                    "INSERT INTO batch_stats (stage, key, data) VALUES (?, ?, ?) "
                    "ON CONFLICT (stage, key) DO UPDATE SET data = excluded.data",
                    (stage, key, _dump(stats)))

    def keep_batch_stats(self, stage: str, keys: Iterable[str]) -> None:
        """Forget every batch of `stage` that is not in `keys`."""
        wanted = set(keys)
        extra = [key for key in self.batch_stats(stage) if key not in wanted]
        if not extra:
            return
        with self._tx() as db:
            db.executemany("DELETE FROM batch_stats WHERE stage = ? AND key = ?",
                           [(stage, key) for key in extra])

    # --- screenshot records (extscan/screenshots.py owns their meaning) ------

    def screenshots(self) -> list[dict]:
        return self._records("screenshots")

    def save_screenshots(self, shots: Iterable[dict]) -> None:
        """Replace the list of screenshot records."""
        with self._tx() as db:
            db.execute("DELETE FROM screenshots")
            _put_screenshots(db, list(shots))

    # --- audit trail and raw output ------------------------------------------

    def log_command(self, rec: CommandRecord) -> None:
        """Append to commands.jsonl. One write per line, under a lock, so
        lines from worker threads never interleave."""
        line = (json.dumps(rec.to_dict()) + "\n").encode()
        with self._log_lock:
            self.path.mkdir(parents=True, exist_ok=True)
            path = self.path / "commands.jsonl"
            new = not path.exists()
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
            if new:
                self._hand_over(path)

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

    # --- everything at once --------------------------------------------------

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

    def export(self, out_dir: str | Path | None = None) -> list[Path]:
        """Write the state as plain JSON files, the layout runs had before
        the database: one file per collection, plus copies of run.json and
        commands.jsonl. The result opens as a (read-only, old-layout) run.

        Never into the run directory itself: files with those names there
        would look like live state.
        """
        out = Path(out_dir) if out_dir is not None else self.path / EXPORT_DIR
        if out.resolve() == self.path.resolve():
            raise ValueError(
                f"refusing to export into the run directory itself ({self.path}): "
                "the JSON files would look like live state. Choose another --out.")
        with self._lock:
            data = {
                "hosts": [h.to_dict() for h in self.hosts()],
                "services": [s.to_dict() for s in self.services()],
                "findings": [f.to_dict() for f in self.findings()],
                "leads": [ld.to_dict() for ld in self.leads()],
                "degradations": [d.to_dict() for d in self.degradations()],
                "checkpoints": self.all_checkpoints(),
                "batches": self.all_batch_stats(),
                "screenshots": self.screenshots(),
            }
        out.mkdir(parents=True, exist_ok=True)
        written = []
        for collection, name in STATE_FILES.items():
            (out / name).write_text(json.dumps(data[collection], indent=2, default=str))
            written.append(out / name)
        for name in ("run.json", "commands.jsonl"):
            if (self.path / name).exists():
                shutil.copyfile(self.path / name, out / name)
                written.append(out / name)
        return written


def _initialised(db: sqlite3.Connection) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' "
                      "AND name = 'schema_info'").fetchone() is not None


# Bulk loaders, shared by the legacy import and the replace_* methods. Where
# a list repeats a key, the first occurrence keeps its place and the last one
# supplies the record, as a dict built from the list would.

def _unique(rows: list[dict], key: Callable[[dict], object]) -> list[dict]:
    return list({key(d): d for d in rows}.values())


def _put_hosts(db: sqlite3.Connection, rows: list[dict]) -> None:
    db.executemany("INSERT INTO hosts (ip, data) VALUES (?, ?)",
                   [(d["ip"], _dump(d)) for d in _unique(rows, lambda d: d["ip"])])


def _put_services(db: sqlite3.Connection, rows: list[dict]) -> None:
    db.executemany("INSERT INTO services VALUES (?, ?, ?, ?, ?)",
                   [(_service_id(d), d["host"], d["proto"], d["port"], _dump(d))
                    for d in _unique(rows, _service_id)])


def _put_findings(db: sqlite3.Connection, rows: list[dict]) -> None:
    db.executemany("INSERT INTO findings (id, data) VALUES (?, ?)",
                   [(d["id"], _dump(d)) for d in _unique(rows, lambda d: d["id"])])


def _put_leads(db: sqlite3.Connection, rows: list[dict]) -> None:
    db.executemany("INSERT INTO leads (id, status, data) VALUES (?, ?, ?)",
                   [(d["id"], d.get("status", "open"), _dump(d))
                    for d in _unique(rows, lambda d: d["id"])])


def _put_degradations(db: sqlite3.Connection, rows: list[dict]) -> None:
    db.executemany(
        "INSERT OR IGNORE INTO degradations (stage, component, reason, data) "
        "VALUES (?, ?, ?, ?)",
        [(d["stage"], d["component"], d["reason"], _dump(d)) for d in rows])


def _put_screenshots(db: sqlite3.Connection, rows: list[dict]) -> None:
    db.executemany("INSERT INTO screenshots (data) VALUES (?)", [(_dump(d),) for d in rows])
