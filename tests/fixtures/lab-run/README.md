# Lab run fixture

A complete extscan run against the local lab (`tests/lab.py`), captured so
reporting work can happen without running any scanner.

## How it was made

```bash
bash scripts/capture-lab-run.sh
```

That script scans the lab in a fresh `ubuntu:24.04` container, as root, with
the tools pinned by `scripts/cloud-setup.sh`. It then copies the run here
and rewrites absolute paths to `runs/<run-id>/...`. Running as root means
UDP was scanned, so the run has no coverage gaps. Tool versions are in
`versions.txt`. The container's nmap is Ubuntu's 7.94SVN.

Run `20261023-090822-extscan-local-lab` (2026-10-23):

- 9 services: 8 TCP, plus SNMP on 10161/udp.
- 168 findings: 5 critical, 19 high, 14 medium, 8 low, 122 info.
- 42 items in the manual review queue, and no coverage gaps.

## What's here

| File | Contents |
|---|---|
| `run.json` | run metadata, stage timestamps, policy |
| `hosts.json`, `services.json` | discovery inventory |
| `findings.json`, `leads.json` | every finding and follow-up, with evidence |
| `degradations.json` | coverage gaps (empty for this run) |
| `commands.jsonl` | every command run, with exit codes and timings |
| `report.md`, `report.json` | the rendered report |
| `run.log` | console output of the scan |
| `raw/` | nmap TCP and UDP XML, nuclei JSONL, sslscan XML, parsed OpenAPI specs |

All data is the lab's. The `acme.example` addresses and the `.env` secrets
are fixed placeholders from `tests/targetapp.py`. Raw tool output is not
redacted, the same as in a real run directory.

`tests/test_lab_run_fixture.py` re-renders the report from this state, so a
schema change that breaks it fails the suite. Regenerate it with the
command above after changes that alter scan output.
