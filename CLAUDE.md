# extscan

External attack-surface scanner for authorised assessments. `README.md` is
the full description. This file is what a fresh session needs to work here.

## Setup

```bash
bash scripts/cloud-setup.sh   # nmap, sslscan, uv, pinned nuclei + templates, uv sync
```

Idempotent. On a machine that already has the tools, `uv sync` is enough.

## Commands

```bash
uv run python -m unittest discover -s tests -t .    # ~390 tests, ~6s, no network
uv run ruff check .
uv run python -m unittest tests.fuzz_failures -v    # fuzzer, several minutes
FUZZ_EXAMPLES=1 uv run python -m unittest tests.fuzz_failures   # corpus replay only, ~1 min
uv run python -m tests.lab                          # lab on 127.0.0.2, Ctrl-C to stop
uv run extscan run --scope examples/lab/scope.json --policy examples/lab/policy.json
```

A full lab scan takes about 8 minutes with nuclei, or 70 seconds with
`extscan probe --skip-nuclei`. Without root it is TCP only, which is expected.

## Data in the repo

- `tests/fixtures/` holds captured scanner output for the parser tests.
- `tests/fixtures/lab-run/` is a complete lab run with real nmap and nuclei:
  state files, `report.md`, raw tool output. Use it to work on reporting
  without running scanners. Its README says how it was made.
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
- Open work is in `todo.md` and `docs/ROADMAP.md`.
