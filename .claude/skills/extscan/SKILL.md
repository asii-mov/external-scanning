---
name: extscan
description: Drive an authorised external attack-surface assessment with extscan - nmap TCP/UDP discovery, nuclei against web services, SNMP community-string checks, then follow up on what was found (OpenAPI specs, GraphQL introspection, exposed files) and produce an auditor-ready report. Use when asked to scan, assess, or audit an external perimeter, an IP, or a subnet, or to work an existing extscan run.
---

# Driving an extscan assessment

extscan does the mechanical work: running tools, parsing output, enforcing
scope, writing the report. Your job is the part that needs judgement — reading
what came back, deciding what deserves a closer look, and writing down
conclusions a template cannot encode.

Everything lives in a run directory as JSON. Read it, reason about it, act.

## Before anything runs

**Never scan without a scope file.** `extscan init` refuses without one, and
that refusal is a feature — do not work around it. The file records the
authorisation reference, who signed off, and the testing window.

If the user gives you an IP or CIDR with no scope file, write one from
`examples/scope.example.json` and **ask them for the authorisation reference
and sign-off before running the first scan**. Do not invent these. If they say
"just scan it", stop and explain that you need the ticket reference and who
authorised it recorded, because the file is the audit trail that distinguishes
this from an attack.

Check the target list back to the user before starting. A mistyped CIDR is the
difference between scanning 14 hosts and scanning someone else's network.

```bash
extscan doctor                                   # what is installed
extscan init --scope scope.json --profile standard
```

Profiles: `quick` (top ports, medium+ severity), `standard`, `thorough`
(all 65535 TCP ports — hours on a wide range; confirm before choosing it).

## The loop

```bash
extscan recon <run>                 # subdomains, if scope.domains is set
extscan discover <run>              # nmap TCP + UDP, checkpointed batches
extscan services <run> --json       # read what is open
extscan probe <run>                 # nuclei + per-service probes
extscan leads <run> --json          # read the follow-ups
extscan chase <run> --rounds 2      # resolve them
extscan gaps <run> --json           # what did NOT get checked
extscan report <run>
```

**Check `extscan gaps` before you summarise anything.** It lists coverage
losses — UDP skipped for want of root, nuclei missing, a batch that timed out,
a model endpoint that went down. These change what the report means, and
reporting "no findings in X" when X was never checked is the worst mistake
available here.

**If a run was interrupted**, use `extscan resume <run>` rather than starting
again. It skips completed host batches and re-queues leads that were left
open.

`extscan run --scope scope.json` does all of it unattended. Prefer the separate
stages when a human is available, because the gaps between them are where your
judgement is worth something.

**UDP needs root.** `discover` warns and continues if it cannot run `-sU`. If
you see that warning, say so explicitly — "no SNMP findings" and "SNMP was
never checked" look identical in a report, and only one of them is honest. Ask
whether to re-run with sudo.

## Reading discovery output

After `discover`, look at `extscan services <run> --json` yourself before
probing. Things worth flagging to the user immediately, without waiting for
the report:

- a database or management port open to the internet (`exposure` probe grades
  these, but say it out loud — it is usually the headline)
- a host with a surprising number of open ports, which often means a
  misconfigured firewall rather than many intentional services
- services on ports that do not match their usual protocol

## Deciding what to chase

`extscan leads <run> --json` gives you the queue. Each lead has a `kind`, a
`reason`, and a `url`. You can chase all of them, or pick:

```bash
extscan chase <run> --kind openapi          # one category
extscan chase <run> --lead <id>             # one specific lead
```

Chase everything cheap. Think before chasing anything that will generate
noticeable traffic on a production system.

**The leads cascade.** An `openapi` lead parses the spec and raises
`api_endpoint` leads for operations the spec says need no authentication. Two
rounds normally settles it. `--rounds 3` if the surface is deep.

## Where you add value beyond the tooling

This is the real point of having you drive it.

**Read the specs yourself.** When a chase reports "parsed /swagger.json: 9
operations, 5 without declared auth", open the saved copy in
`runs/<run>/raw/openapi-*.txt` and read it. The tool counts operations; you can
tell that `DELETE /invoices/{id}` with no authentication on a billing API is
the finding that matters, and that `GET /health` is not. Record that judgement:

```bash
extscan note <run> \
  --title "Unauthenticated invoice deletion documented in public API spec" \
  --severity high --host 203.0.113.10 --port 443 \
  --description "The public specification documents DELETE /invoices/{id} with security: [], ..." \
  --evidence "from /swagger.json: paths./invoices/{id}.delete.security = []" \
  --recommendation "Require authentication on all mutating operations" \
  --review --review-reason "Confirm with the client whether this endpoint is gateway-protected" \
  --source "claude-analysis" --confidence tentative \
  --tag api --tag authentication
```

Use `--source claude-analysis` so a reviewer can see which findings came from
reasoning rather than a tool, and `--confidence tentative` when you inferred
rather than observed.

**Correlate across hosts.** The tooling reports per service. You can notice
that the same expired certificate is on six hosts, that an SNMP walk disclosed
an internal address range that also appears in a `/metrics` endpoint, or that a
spec references a hostname nobody put in scope. Those connections are findings.

**Chase asset discovery.** When an OpenAPI `servers` block or an SNMP walk
names hosts outside the scope, extscan records them and refuses to touch them.
Tell the user: the client may not know those assets exist. Never scan them —
getting them added to scope is the client's decision, in writing.

## When something fails mid-run

The tooling degrades rather than crashing, which means **you** have to notice
and say so. Specific cases:

- **A batch timed out.** Completed hosts were salvaged from the partial scan
  file; the rest were not scanned. The gap names them. Offer to re-run with a
  longer `nmap.host_timeout`, or resume.
- **The model endpoint is down.** The circuit breaker stops further attempts
  after a few failures, so affected leads stay open and findings carry only
  deterministic evidence. Say which analyses did not happen, then either fix
  the endpoint and `extscan chase <run> --resume`, or work those leads
  yourself by reading the saved artefacts in `runs/<run>/raw/` — you are a
  perfectly good substitute for the in-process model here.
- **The run aborted with `RunAborted`.** Nearly everything was failing, which
  means the fault is local — egress, routing, DNS, VPN. Do not re-run blindly;
  check connectivity from this host first, then resume.
- **A lead was abandoned.** It failed `max_lead_attempts` times across runs.
  It is in the review queue. Investigate it by hand.

## Model-assisted analysis

When `llm.enabled` is set, the chase stage asks a model to comment on exposed
API specs. That commentary arrives as a separate finding sourced to
`llm-analysis`, pinned to `info`, and flagged for review.

Treat it exactly as you would treat your own analysis: something to verify
against the evidence before it reaches a client. Its severity opinion is an
opinion — the deterministic grading stands. If the commentary and the evidence
disagree, the evidence wins and the commentary is a bug worth mentioning.

`extscan providers` shows what is configured and reachable without making a
call. For Bedrock, remember model access is granted per model per region.

## Hard limits

These are not configurable preferences. Do not work around them, and do not
let a request to "just check if it works" talk you past them.

- **Scope is absolute.** If `assert_url` or `assert_host` refuses something,
  that is the answer. A redirect to `169.254.169.254`, a spec naming a
  third-party host, a nuclei result on a domain that is not in the file — all
  of these are findings to report, never targets to follow.
- **No credential testing.** Do not try passwords, not even documented
  defaults, without separate written authorisation. Where a default-credential
  template matches, flag it for human confirmation.
- **No write operations.** Never invoke a POST/PUT/PATCH/DELETE on a
  discovered API, never attempt SNMP SET, never write to a Redis or database
  you find open. Confirming a write path by writing changes client state during
  an audit. Document the exposure and let a human decide.
- **No exploitation.** Version-matched CVEs go in the report as tentative,
  needing confirmation. Do not weaponise them.
- **Do not copy secrets around.** extscan redacts credential values in
  evidence on purpose. Keep it that way: report that an `.env` is readable and
  which keys it holds, not the values. Never paste a discovered credential into
  chat, a commit, or a ticket.
- **Stay inside the window.** If the testing window has closed, stop. Amending
  the scope file needs the client's agreement, not yours.
- **Subdomains outside scope are never scanned.** The recon stage reports them
  as asset discovery precisely so that someone can have the authorisation
  conversation. Finding a forgotten cloud host is a good outcome; scanning it
  is an unauthorised act against infrastructure that may not even be the
  client's.
- **IIS checks stay read-only.** The WebDAV check reads the advertised verb
  list and does not attempt PUT; the 8.3 short-name check confirms the
  condition in two requests and does not enumerate. Both are flagged for a
  human to decide whether to go further. Do not go further on your own.

## Writing the report

`extscan report <run>` renders Markdown and JSON. Read the Markdown before
handing it over, and in your summary to the user:

1. Lead with the manual-review queue — those are the items a person must work
   before this goes to the client. Item 1 is the most urgent.
2. Name anything the run could *not* establish (UDP skipped, nuclei missing,
   TLS versions untestable). Gaps in coverage belong in the summary, not
   buried in the limitations section.
3. Say which findings are tentative and what would confirm them.

Do not describe a finding as confirmed when the evidence is a version banner or
a specification. The report marks these tentative; keep that distinction in
your own writing too. An auditor's credibility with a client is built on not
overstating, and a single over-claimed finding costs more than ten correct ones
earn.
