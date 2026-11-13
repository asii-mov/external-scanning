# Evals

Tests say the code does what it did yesterday. These say how good the tool
is: what it finds, what it wrongly reports, what it costs, and whether an
agent driving it behaves. All of them run offline or on loopback.

| Eval | Question | Run | Needs |
|---|---|---|---|
| `local.py` | Are the planted issues found, do clean targets stay clean, and how many requests did that take? | `uv run python -m evals.local` | nothing |
| `score.py` | How does a lab run score against ground truth: recall, honesty about gaps, review-queue noise, time per stage? | `uv run python -m evals.score [runs/<id>]` | a lab run, or the committed fixture by default |
| `bench.py` | Is extscan's own bookkeeping and SNMP checking inside budget? | `uv run python -m evals.bench` | nothing |
| `discovery.py` | Does two-phase discovery find the same services as one-phase, for how many fewer nmap runs and fingerprint attempts? | `uv run python -m evals.discovery` | nothing (fake nmap) |
| `diff.py` | Are planted changes between two runs classified correctly, "not re-checked" included? | `uv run python -m evals.diff` | nothing |
| `skill/evals.json` | Does an agent using the skill ask for authorisation, report gaps, refuse off-scope work? | see below | a model |

`tests/test_evals.py` runs the first three on every test run and fails when a
threshold is missed; `tests/test_discovery_accuracy.py` and
`tests/test_diff.py` run the discovery and diff evals. It also parses every `extscan` command in the skill
against the real CLI, so the skill cannot name a flag that does not exist.

## Ground truth

`expected/local.json` and `expected/lab.json` list what must be found
(`must_find`), the false positives already known (`known_false_positives`),
what the lab cannot exercise yet (`known_misses`) and the thresholds.

A `must_find` item can name the stage it `needs`. If that stage has a
recorded coverage gap, the item counts as not assessed. If it is missing
with no gap, the eval fails: that is a check that silently did not happen.

## Scoring a fresh lab run

```bash
uv run python -m tests.lab                                  # terminal 1
uv run extscan run --scope examples/lab/scope.json --policy examples/lab/policy.json
uv run python -m evals.score runs/<run-id>
```

Compare `stage seconds` and `tool seconds` with the last run to see whether a
change made scanning faster or slower. `score.py` re-parses the run's raw
nmap and nuclei output with the current parsers; `--stored` scores
the findings as the run left them.

## Skill cases

`skill/evals.json` holds prompts with the expectations a grader checks
against the transcript: no scope file, summarising a run that skipped UDP,
an off-scope host named in a spec, a request to test credentials, an
interrupted run, a request to bypass extscan, an all-ports scan, and
pressure to overstate a finding.

```bash
uv run python -m evals.skill.stage <scratch>/runs    # the run directories the cases use
```

Then run the cases with the `skill-creator` skill, or by hand in a scratch
copy of the repo. Nothing in them needs a packet to leave the machine.

## Adding to them

- A new probe or chase handler: plant its issue in `tests/targetapp.py` (or
  the lab), add a `must_find` line, and check `evals.local` still shows no
  false positives on the clean targets.
- A false positive seen on an engagement: reproduce its shape as a clean
  target in `local.py`, watch the eval fail, then fix the probe.
- A mistake an agent made: add a case to `skill/evals.json` with the prompt
  that led to it.
- Raise a request or time budget only with a reason. Each request in
  `local.py` is a request against a client's host on a real engagement.
