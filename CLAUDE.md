# extscan

External attack-surface scanner for authorised assessments. `README.md` is
the full description. This file is what a fresh session needs to work here.

`AGENTS.md` maps where everything lives: plans, docs, code, test data and
Claude's local notes.

@AGENTS.md

## Setup

```bash
bash scripts/cloud-setup.sh   # nmap, sslscan, uv, pinned nuclei + templates, uv sync
```

Idempotent. On a machine that already has the tools, `uv sync` is enough.
Screenshots need `uv sync --extra screenshots && uv run playwright install
chromium`; without them the browser scope test skips.

## Commands

```bash
uv run python -m unittest discover -s tests -t .    # ~800 tests, ~50s, no network
uv run ruff check .
uv run python -m evals.local                        # detection, false positives, request counts (~1s)
uv run python -m evals.score [runs/<id>]            # scorecard for a lab run (default: the fixture)
uv run python -m evals.bench                        # bookkeeping and SNMP budgets
uv run python -m evals.discovery                    # one-phase against two-phase discovery, fake nmap
uv run python -m evals.diff                         # planted run-to-run transitions
uv run python -m unittest tests.fuzz_failures -v    # fuzzer, several minutes
FUZZ_EXAMPLES=1 uv run python -m unittest tests.fuzz_failures   # corpus replay only, ~1 min
uv run python -m tests.lab                          # lab on 127.0.0.2, Ctrl-C to stop
uv run extscan run --scope examples/lab/scope.json --policy examples/lab/policy.json
```

A full lab scan takes about 8 minutes with nuclei, or 70 seconds with
`extscan probe --skip-nuclei` (recorded as a nuclei coverage gap). Without root it is TCP only, which is expected.

## Data in the repo

- `tests/fixtures/` holds captured scanner output for the parser tests.
- `tests/fixtures/lab-run/` is a complete lab run (real nmap TCP and UDP,
  nuclei, sslscan, run as root): state files, `report.md`, raw tool output.
  Use it to work on reporting without running scanners. Regenerate it with
  `bash scripts/capture-lab-run.sh`, which needs Docker.
- `tests/fuzz_corpus.json` holds minimized fuzzer counterexamples, replayed
  on every fuzz run. When the fuzzer finds a new failure, pin it there and
  as a unit test in `tests/test_coverage_gaps.py`.

## Rules

- Only scan the lab (`127.0.0.2`) or targets in a scope file the user
  provides. Never point extscan at anything else, including from a cloud
  environment, where the traffic leaves from shared infrastructure.
- Reduced coverage must never look clean. A failed or missing tool is a
  `Degradation`, and the service stays unmarked so `resume` retries it.
- No credential testing and no disruptive checks. The excluded nuclei tags
  and NSE scripts in `extscan/policy.py` are safety properties with tests in
  `tests/test_safety_invariants.py`.
- Stdlib only at runtime. Dev tools (ruff, pytest, hypothesis) go in the
  `dev` dependency group.
- `--dry-run` sends nothing in any stage, and marks nothing as done
  (checkpoints, stage records, probed services, leads). A stage that talks
  to the network in-process has to check `runner.dry_run`.
- A change to a probe, a parser or the skill is checked against `evals/`
  (`evals/README.md`). A new check gets a `must_find` line; a false positive
  gets a clean target that reproduces it.
- Tests never reach the internet. `tests/__init__.py` sets
  `EXTSCAN_OFFLINE=1`, which disables the `enrich` stage's feed downloads;
  a test that exercises enrich uses local files.
- A request to a name (virtual hosts) connects to the in-scope IP and sends
  the name as Host header and SNI (`net.request_at`). Never let a name's DNS
  decide where a connection goes.
- Run state goes through `Store` (`extscan/store.py`, SQLite, no WAL
  because root and the user both write a run). Never read or write state
  files by path; `tests/fixtures/lab-run` stays in the old JSON layout on
  purpose, as the legacy-compatibility test.
- Targets come from the scope file only. Anything a policy file can set
  that reaches a scanner's command line is checked in `extscan/policy.py`
  (`check_nmap_extra_args`, `check_nuclei_extra_args`); a new pass-through
  setting needs the same check and a test in `tests/test_failsafes.py`.
- No quiet fallbacks. A setting that cannot be read, a file that is damaged
  or a model that did not answer is an error or a `Degradation`, never a
  default. Do not catch an exception to return an empty result unless the
  caller records why.
- A new report section is a value in `report.build_context`, a line in
  `extscan/templates/report.md` and a row in `docs/REPORT_TEMPLATE.md`
  (a test compares the last two). Do not write report text straight from
  Python.
- A new policy key, scope key, command, flag or environment variable gets a
  row in `docs/CONFIGURATION.md`; `tests/test_docs.py` fails without one. A
  setting that is accepted has to do something, or be refused when set.
- Model providers go through the `anthropic` SDK's own client classes
  (`extscan/llm/providers.py`). Credentials come from the environment and
  never from a policy file.
- Open work is in `todo.md` and `docs/ROADMAP.md`.
