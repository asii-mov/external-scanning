# Where things are

A map of this repo and its working notes, for any agent picking up the work.
`CLAUDE.md` has the setup, commands and rules. This file says where to look.

## Plans and open work

| What | Where |
|---|---|
| Near-term tasks and known unfixed gaps (the `Open` section) | `todo.md` |
| Longer-term feature ideas, prioritised, with the catch for each | `docs/ROADMAP.md` |

## Claude's local notes

Claude Code keeps per-project memory outside the repo, at
`~/.claude/projects/-home-asiimov-projects2-cybersecurity-tooling-external-external-scanning/memory/`.
It exists only on the original workstation. Cloud sessions and other
machines don't have it.

- `MEMORY.md` is the index, loaded into each local session.
- `extscan-open-issues.md` records which gaps were fixed and when. Open
  ones are copied into `todo.md`.
- `nuclei-killed-by-edr.md` records why nuclei was SIGKILLed on that machine
  (an EDR agent, since removed).

You don't need these notes to find open work. `todo.md` is the source of
truth.

## Documentation

| What | Where |
|---|---|
| What extscan does, safety properties, failure handling | `README.md` |
| Local lab: ports, expected findings, UDP, troubleshooting | `docs/LAB.md` |
| Claude Code skill for driving extscan on an engagement | `.claude/skills/extscan/SKILL.md` |

## Code

| What | Where |
|---|---|
| CLI entry point | `extscan/cli.py` |
| Stages: discover, probe, chase, report | `extscan/pipeline.py` |
| Per-service probes (one function per service family) | `extscan/probes.py` |
| Tool adapters (nmap, nuclei, sslscan, SNMP, IIS, subdomains) | `extscan/tools/` |
| Defaults, profiles, excluded NSE scripts and nuclei tags | `extscan/policy.py` |
| Scope loading and per-request scope checks | `extscan/scope.py` |
| Run directory state (`runs/<run-id>/`) | `extscan/store.py` |
| Retries, circuit breaker, coverage gaps (`Degradation`) | `extscan/resilience.py` |
| Report rendering (`report.md`, `report.json`) | `extscan/report.py` |
| Obsidian vault: the pentest narrative, host and finding notes | `extscan/vault.py` |
| Web screenshots (optional Playwright), per-request scope guard | `extscan/screenshots.py` |
| Redaction applied to every rendered report | `extscan/redact.py` |
| Optional model-assisted analysis | `extscan/llm/` |

## Tests and test data

| What | Where |
|---|---|
| Unit and integration tests | `tests/test_*.py` |
| Failed and missing tools must be gaps, never clean passes | `tests/test_coverage_gaps.py` |
| Safety properties (no DoS, no credential testing, screenshots in scope) | `tests/test_safety_invariants.py` |
| Vault links, ordering, redaction, hostile text, screenshot stage | `tests/test_vault.py` |
| Failure-state fuzzer (opt-in, several minutes) | `tests/fuzz_failures.py` |
| Minimized fuzzer counterexamples, replayed every fuzz run | `tests/fuzz_corpus.json` |
| Captured scanner output for parser tests | `tests/fixtures/*.xml`, `tests/fixtures/*.jsonl` |
| A complete lab run, for reporting work without scanners | `tests/fixtures/lab-run/` |
| Local lab server (9 exposed services on 127.0.0.2) | `tests/lab.py` |
| Deliberately exposed web target used by the lab and tests | `tests/targetapp.py` |

## Config and scripts

| What | Where |
|---|---|
| Scope and policy templates | `examples/` |
| Lab scope and policy | `examples/lab/` |
| Provision a fresh Linux box (cloud, CI) | `scripts/cloud-setup.sh` |
| Regenerate `tests/fixtures/lab-run` (needs Docker) | `scripts/capture-lab-run.sh` |
| CI: lint, plus tests on Python 3.10 to 3.13 | `.github/workflows/tests.yml` |
| Dependencies, the 7-day resolution window, ruff config | `pyproject.toml` |

## Not in the repo

- `runs/` holds scan output. It's gitignored, because real runs carry
  client data.
- `/scope*.json` and `/policy*.json` at the repo root are gitignored for the
  same reason. Only the `examples/` templates belong in git.
- `.claude/hooks/state/` is local state for the continual-learning hook.
  It's untracked.
