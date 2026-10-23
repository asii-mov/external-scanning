# extscan

Orchestrated external attack-surface scanning for **authorised** security
assessments.

The problem this solves: you feed an IP or subnet into nmap, then the team
works through each open port by hand. The port-by-port part is mechanical —
run the right tool at the right service, read the output, decide whether to dig
further — and it eats the time that should go on the findings that actually
need a human.

extscan automates the mechanical half and is explicit about where the other
half begins. Every report ends with a **manual review queue**: the things
automation proved are exposed but cannot judge, each with the specific question
an auditor needs to answer.

```
scope → discover (nmap TCP+UDP) → probe (per-service) → chase (follow-ups) → triage → report
                                         ↑_______________________|  bounded loop
```

## Why it is built this way

**Stages are separate, state is on disk.** Each stage reads and writes a run
directory, so you can stop after discovery, look at what is open, change the
policy, and carry on. That is how audit work actually goes. It also means a
dropped SSH session costs you nothing.

**Findings are separate from judgement.** A tool can establish that Swagger UI
is published. It cannot decide whether that is acceptable for this client.
extscan records both: the finding, and the question for the auditor.

**Follow-ups are first-class.** Discovery says port 443 is open. A probe says
there is an OpenAPI document. Neither answers *what does that expose*. "Leads"
close that gap: a swagger hit raises an `openapi` lead, chasing it parses the
spec and raises `api_endpoint` leads for operations documented as needing no
authentication, and chasing those confirms whether the spec reflects reality.
Bounded by depth so it terminates.

**Stdlib only.** No pip install on the jump box. SNMP is implemented directly
(BER over UDP), so `snmpwalk` is optional rather than required.

## Install

```bash
git clone <this repo> && cd external-scanning
uv sync                   # dev environment (ruff, pytest)
uv run extscan doctor     # check external tools

# or without uv -- there are no runtime dependencies:
python3 -m extscan doctor
```

Optional model-assisted analysis needs one extra:

```bash
uv pip install 'extscan[llm]'       # direct Claude API
uv pip install 'extscan[bedrock]'   # AWS Bedrock
uv run extscan providers            # check what is reachable
```

Screenshots of web services for the report need headless Chromium:

```bash
uv sync --extra screenshots && uv run playwright install chromium
```

Without it the screenshot stage records a coverage gap and the report
describes web services in text only.

External tools: **nmap** (required), **nuclei** (required for web checks),
`sslscan`, `httpx`, `testssl.sh`, `subfinder`/`amass` (all optional —
each degrades to a recorded coverage gap rather than a failure).
`extscan doctor` prints install commands for what is missing.

Lint with `uv run ruff check .`. The formatter is configured but not
enforced; `pyproject.toml` explains why and how to turn it on.

UDP scanning needs root. Run unprivileged, extscan says up front that the run
is TCP only, prints the command to add UDP afterwards, and records a coverage
gap, because "no SNMP findings" and "SNMP was never checked" must never look
the same in a report:

```bash
sudo extscan discover <run> --udp-only   # clears the gap once UDP has run
```

## Authorisation is mandatory

extscan will not scan anything without a scope file recording who authorised
the work. This is not a formality: it is the artefact that distinguishes an
audit from an attack, and the thing you want on file if a client's SOC asks
what hit them.

```jsonc
{
  "engagement": "ACME external perimeter review Q4",
  "client": "ACME Corporation",
  "authorization": {
    "reference": "SOW-2026-114 / JIRA SEC-1423",     // required
    "authorized_by": "jane.doe@acme.example (CISO)",  // required
    "window_start": "2026-10-20T00:00:00Z",
    "window_end": "2026-10-31T23:59:59Z",
    "notes": "External perimeter only. No DoS. No credential testing."
  },
  "targets": ["203.0.113.0/27", "198.51.100.14"],
  "exclude": ["203.0.113.5"],
  "max_hosts": 256
}
```

Enforced at load: malformed CIDRs fail before a packet is sent, internal
address space (RFC 1918, loopback, link-local, CGNAT) is refused unless
`allow_private` is set, a scope that expands past `max_hosts` is refused, and
scanning outside the testing window stops the run.

See `examples/scope.example.json`.

## Use

```bash
extscan init --scope scope.json --profile standard
extscan recon latest                 # subdomain enumeration (needs scope.domains)
extscan discover latest              # nmap TCP + UDP, in checkpointed batches
extscan services latest              # what is open
extscan probe latest                 # nuclei + per-service probes
extscan leads latest                 # what is worth a closer look
extscan chase latest --rounds 2      # resolve the follow-ups
extscan screenshot latest            # headless Chromium, every request scope-checked
extscan report latest                # report.md, report.json, report/ (Obsidian vault)
extscan gaps latest                  # what did NOT get checked
```

Interrupted? `extscan resume latest` continues from the last checkpoint.

Or unattended: `extscan run --scope scope.json`

`--dry-run` prints every command without sending a packet. Worth doing on a new
engagement before the real thing.

Profiles: `quick`, `standard`, `thorough` (all 65535 TCP ports — hours on a
wide range). Override anything with a policy file; see
`examples/policy.gentle.json` for a rate-limited configuration suitable for
fragile infrastructure.

## What it checks

| Stage | Covers |
|---|---|
| `discover` | nmap TCP (SYN when privileged, connect otherwise) + UDP, service/version detection, `default,safe,vuln` NSE categories, OS fingerprint |
| `probe` → `nuclei` | templated web checks across every discovered HTTP service at once |
| `probe` → `http_fingerprint` | root page, fingerprint and security headers, ~23 disclosure paths with soft-404 filtering |
| `probe` → `tls` | certificate detail, expiry, self-signing, which TLS versions are actually offered |
| `probe` → `snmp` | default/guessable community strings, read-only, built-in SNMP client |
| `probe` → `exposure` | databases, management interfaces and legacy services that should not face the internet |
| `probe` → `ssh` | banner and exposure review |
| `probe` → `iis` | IIS/ASP.NET: `trace.axd`/`elmah.axd`, WebDAV verbs, 8.3 short-name oracle, verbose error pages, version headers, default content |
| `probe` → `sslscan` | cipher-level TLS audit — RC4/3DES/export suites, CRIME, insecure renegotiation (needs `sslscan`) |
| `recon` → subdomains | certificate transparency + `subfinder`/`amass`, resolved and split into in-scope (scannable) and out-of-scope (reported, never touched) |
| `chase` → `openapi` | finds the spec, enumerates operations, flags those declaring no authentication (writes especially), notes out-of-scope servers |
| `chase` → `graphql` | introspection, schema size, whether mutations are exposed |
| `chase` → `api_endpoint` | confirms one documented-as-open **GET** really is open |
| `chase` → `secret_file` | credential-bearing files, with values redacted |
| `chase` → `git_exposure` | readable `.git` metadata |
| `chase` → `snmp_walk` | interface and address tables, to show what the exposure actually discloses |

`extscan probes` lists what is registered. Adding a service family means adding
one function to `extscan/probes.py` with a match predicate — the pipeline does
not change.

## When things go wrong

Reduced coverage must never look like a clean result — a scan that silently
checked half of what it claimed is worse than one that failed outright,
because somebody signs a report based on it. So every failure ends in one of
three places: retried and succeeded, recorded as a named coverage gap, or a
loud abort. Never a silent pass.

| Failure | What happens |
|---|---|
| **nmap times out or is killed** | Partial XML is salvaged — completed hosts are recovered from the truncated file instead of the whole batch being lost. The gap names which hosts went unscanned. `-oA` output means `nmap --resume` also works. |
| **Scope is large** | Discovery runs in batches of `nmap.chunk_size` hosts, each checkpointed. A timeout costs one batch; `extscan resume` skips what finished. |
| **nmap/nuclei/sslscan not installed** | Recorded as a coverage gap naming what was not checked, and the run continues. `doctor` tells you up front. |
| **nuclei or a probe fails** | A killed, timed-out or crashing tool is a coverage gap naming the services it did not finish, and those services stay unmarked so `extscan probe <run> --only <probe>` retries them. |
| **UDP needs root** | A TCP-only notice before discovery starts, plus a *serious* coverage gap, because "no SNMP findings" and "SNMP was never checked" must never look alike. |
| **Model endpoint is down** | Retried with jittered backoff, then a circuit breaker opens and stops trying. 100 leads against a dead endpoint cost ~6 HTTP attempts, not 200. Findings keep their deterministic evidence and get a human-review flag. |
| **Model returns garbage** | Not retried — it answered, just not usefully. Counted separately from an outage. |
| **A lead keeps failing** | Retried up to `max_lead_attempts` *across runs*, then abandoned with its error recorded, so one unreachable host cannot block the stage on every resume. |
| **Nearly everything fails** | The abort threshold decides the fault is local (egress, VPN, DNS), stops, and says so — rather than producing a report saying the client's estate is dark. |
| **Process killed** | All state is on disk after every step. `extscan resume <run>` continues. |

`extscan gaps <run>` lists them; the report carries them in the summary *and*
their own section, above the inventory.

## Model-assisted analysis (optional)

Off by default. Enable per-engagement in a policy file:

```jsonc
{"llm": {"enabled": true, "provider": "bedrock",
         "model": "anthropic.claude-opus-5-5",
         "aws_region": "eu-west-2", "effort": "medium"}}
```

`provider` is `anthropic` (direct API) or `bedrock`. Bedrock model IDs carry an
`anthropic.` prefix, accept cross-region (`us.anthropic.…`) and
inference-profile ARNs, and are granted **per model per region** — a wrong
region is the usual first failure, so `extscan providers` reports it.

Three rules the implementation holds to, because everything it would send a
model was written by the target:

1. **Input is hostile.** Evidence is fenced, labelled as data, and the
   delimiter is stripped from the content so it cannot forge its own
   terminator. The system prompt says injected instructions are themselves a
   finding and must not be followed.
2. **Output is a suggestion, never an action.** Commentary becomes a separate
   finding sourced to `llm-analysis`, pinned to `info` severity regardless of
   the model's opinion, marked tentative and flagged for review. It cannot
   decide what to scan, widen scope, or move an item up the remediation queue.
3. **Secrets do not leave the engagement.** Evidence goes through the same
   redaction as the report before transmission. An exposed `.env` proves
   credentials are reachable; it is not something to upload to an API.

A run with no model produces the same findings minus the commentary, and says
so. Nothing depends on it — which is what makes it safe to use.

## Safety properties

Deliberate, tested, and not configurable away:

- **Read-only.** GET, connect, query. No credential testing (nuclei's
  `default-login` and `creds-stuffing` templates are excluded), no SNMP SET, no
  writes to discovered services, no exploitation. Where impact cannot be
  established without going further, the finding says so and asks a human.
- **Scope re-checked per request.** Leads come from scanner output, HTTP
  redirects and OpenAPI `servers` blocks — all controlled by the target. A host
  that redirects to `169.254.169.254` gets refused, recorded as a finding, and
  not followed.
- **No shell.** Every command runs as an argv list. Target-derived strings
  never reach a shell.
- **Disruptive and leaky NSE scripts excluded by default.** The `dos` and
  `external` categories and `http-slowloris-check` do not run. `external`
  covers scripts such as `vulners` and `dns-blacklist`, which send target
  details to third-party services. This is the one item here a policy can
  change (`nmap.exclude_scripts`), for an engagement that permits it.
- **Destructive nuclei templates excluded** (`dos`, `intrusive`, `fuzz`,
  `brute-force`), and out-of-band detection is off by default — public
  interactsh relays would see client traffic.
- **No system proxy.** `http_proxy` in the operator's shell would route client
  traffic through a third party and make results reflect the proxy, not the
  target.
- **Secrets redacted.** Evidence proves an `.env` is readable and names the
  keys; it does not copy the values into the report, the ticket and three
  mailboxes. Every rendered report (`report.md`, `report.json`, the vault)
  also drops session ids, cookie values, credentials in URLs and SNMP
  community strings that are not well-known defaults. Pages whose evidence
  holds secrets are never screenshotted, because an image cannot be redacted.
  The run state keeps raw values, so findings can be re-checked.
- **Screenshots stay in scope.** The browser's every request, subresources and
  each redirect hop included, is scope-checked before it is sent. Off-scope
  requests are blocked and listed in the caption.
- **Full audit trail.** Every command, exit code and timing in
  `commands.jsonl`, summarised in the report so a client can reproduce any
  finding.

## Reports

`report.md` for people, `report.json` for tooling. Structure:

1. **Authorisation and scope** — what was agreed, by whom, when
2. **Summary** — counts by severity
3. **Manual review queue** — the handover from automation to auditor, ordered,
   each item naming the decision required
4. **Systemic issues** — anything on 3+ hosts, as one remediation task rather
   than forty findings
5. **Findings** — by severity, with evidence and reproduction
6. **Service inventory**
7. **Methodology and limitations** — stages run, coverage gaps, tool versions,
   command log

`report/` is the same run as an Obsidian vault, written as a pentest
narrative. Open the folder in Obsidian and start at `00 Summary.md`:

- **00 Summary** tells the story in the order the work happened: scope and
  authorisation, discovery (with the nmap commands as run), each service
  family with screenshots and a fenced proof block per finding, the
  follow-ups, and what was not covered. The manual review queue and coverage
  gaps are flagged before the story starts.
- **hosts/** has one note per host: services, the checks run on each,
  screenshots, findings.
- **findings/** has one note per finding: evidence, proof, a command to
  reproduce it, remediation.
- **Manual review queue**, **Coverage gaps** and **Methodology** (with the
  full command log) are notes of their own.

Notes have YAML frontmatter (severity, host, port, tags) for Dataview, and
link with `[[wikilinks]]`. Scanner text is escaped, so a hostile page title
cannot embed notes or make Obsidian fetch a URL. Re-rendering replaces the
notes extscan wrote and leaves your own notes and `.obsidian/` alone.

Findings are marked `tentative` when derived from a version banner or a
specification rather than observed behaviour. Keep that distinction when
writing up: one over-claimed finding costs more credibility than ten correct
ones earn.

## Driving it with Claude

`.claude/skills/extscan/SKILL.md` is a skill for Claude Code covering the
workflow, where model judgement adds value over the tooling, and the limits
that hold regardless of how a request is phrased.

The agent-facing design: every read command takes `--json`, and
`extscan note` records a finding from the model's own analysis with
`--source claude-analysis` so a reviewer can tell reasoning from tool output.
Reading an OpenAPI spec and concluding that unauthenticated invoice deletion
matters more than an open health check is exactly the judgement worth having in
the loop — the branching logic is not frozen into the tool.

## Tests

```bash
uv run python -m unittest discover -s tests -t .   # ~415 tests, ~10s, no network
```

Fixture-driven, so no scanners are needed: captured nmap/sslscan XML and
nuclei JSONL for the parsers, a fake SNMP agent over a real UDP socket for the
wire format, and local HTTP targets (one deliberately exposed, one IIS-flavoured,
one correctly hardened) for the probe → chase → report path.

`tests/fuzz_failures.py` fuzzes the failure paths with Hypothesis. Fake
`nmap`, `nuclei` and `sslscan` binaries exit with random codes and signals,
hang, or write truncated, random or bit-flipped output. Each run is checked
for a crash, a failed tool with no coverage gap, or a failed tool marked as
having checked a service. Past counterexamples in `tests/fuzz_corpus.json`
replay first on every run. It is opt-in because it takes several minutes:

```bash
uv run python -m unittest tests.fuzz_failures -v
```

`tests/fixtures/lab-run/` is a complete lab run with real nmap and nuclei
output, for working on reporting without running scanners.
`bash scripts/cloud-setup.sh` provisions a fresh Linux box (a cloud session,
CI) with nmap, sslscan and pinned nuclei and templates.

To exercise the real scanners too, `uv run python -m tests.lab` starts nine
exposed services on `127.0.0.2` (HTTP, HTTPS, IIS, SSH, Redis, MySQL,
Elasticsearch, Docker API, SNMP) with a matching scope and policy in
`examples/lab/`. See `docs/LAB.md`.

The suite deliberately covers the things that cause false positives in client
reports — soft-404 filtering, OpenAPI base-path joining, secret redaction,
scope refusal of hostile redirects, SHA-1 signature detection — and the
failure paths: truncated-scan salvage, checkpoint resume, circuit breaking, and
a dead model endpoint costing bounded work. Tests pass with and without the
optional `anthropic` extra installed.

## Further work

`docs/ROADMAP.md` has a prioritised list of what else is worth adding, with
the catch for each. The top of it: virtual-host enumeration and run-to-run
diffing.

## Legal

For authorised testing only. Scanning infrastructure you do not own or have
written permission to test is illegal in most jurisdictions. The scope file
exists so that permission is recorded before the first packet — use it
honestly.
