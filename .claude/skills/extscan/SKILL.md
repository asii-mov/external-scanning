---
name: extscan
description: Drive an authorised external attack-surface assessment with extscan - nmap TCP/UDP discovery, nuclei against web services, SNMP community-string checks, then follow up on what was found (OpenAPI specs, GraphQL introspection, exposed files) and produce an auditor-ready report. Use when asked to scan, assess, or audit an external perimeter, an IP, or a subnet, or to work an existing extscan run.
---

# Driving an extscan assessment

extscan does the mechanical work: running tools, parsing output, enforcing
scope, writing the report. Your job is the part that needs judgement — reading
what came back, deciding what deserves a closer look, and writing down
conclusions a template cannot encode.

Everything lives in a run directory. State is in a database (`state.db`),
so read it through the CLI, not from files: `extscan status`, `hosts`,
`services`, `findings`, `leads` and `gaps`, each with `--json`. `extscan
export <run>` writes plain JSON copies if you need files; a copy is never
the live state. Raw tool output is in `runs/<run>/raw/`.

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
extscan --dry-run discover latest                # the nmap commands, nothing sent
```

`--dry-run` works on every stage and sends nothing: it prints the commands,
probes and leads that would run. Use it on a new engagement before the real
thing. `latest` stands for the newest run wherever a run id is expected.

Picking up a run someone else started? `extscan status <run>` shows which
stages finished and the counts, and `extscan gaps <run>` what was lost.

On a scope with more hosts than one batch (32), discovery runs in two
phases on its own: a port sweep of every address, then version detection
only on hosts that had an open port. Nothing to configure.

Profiles: `quick` (top ports, medium+ severity), `standard`, `thorough`
(all 65535 TCP ports — hours on a wide range; confirm before choosing it).

`--tcp-ports` on `init` or `run` picks the TCP range on its own, whatever the
profile: `all` (1-65535, confirm before choosing it on a wide range), `top`
(the standard list), `quick` (25 common ports) or a literal list such as
`22,80,8000-8100`.

## The loop

```bash
extscan recon <run>                 # subdomains + DNS checks, if scope.domains is set
extscan discover <run>              # nmap TCP + UDP, checkpointed batches
extscan services <run> --json       # read what is open
extscan probe <run>                 # nuclei + per-service probes
extscan leads <run> --json          # read the follow-ups
extscan chase <run> --rounds 2      # resolve them
extscan screenshot <run>            # web services, for the report (optional extra)
extscan enrich <run>                # KEV and EPSS ranking, CDN tags (public feeds, no client data)
extscan gaps <run> --json           # what did NOT get checked
extscan report <run>
```

`--json` goes before or after the subcommand.

Nuclei is most of the wall-clock (minutes per web service at the default
rate limit). When you need a first look quickly, `extscan probe <run>
--skip-nuclei` runs everything else and records nuclei as a coverage gap;
`extscan probe <run> --only nuclei` clears it later. Don't raise
`nuclei.rate_limit` or nmap timing to save time without asking: how hard to
push a client's hosts is agreed with the client.

**Check `extscan gaps` before you summarise anything.** It lists coverage
losses — UDP skipped for want of root, nuclei missing, a batch that timed out,
a model endpoint that went down. These change what the report means, and
reporting "no findings in X" when X was never checked is the worst mistake
available here.

**If a run was interrupted**, use `extscan resume <run>` rather than starting
again. It skips completed host batches, nuclei batches and per-service
probes, and re-queues leads that were left open.

`nmap.parallel` in the policy runs several discovery batches at once
(default 1). It multiplies the momentary load on the client's network by
the same number, so raise it only when the client has agreed to the rate.

`extscan run --scope scope.json` does all of it unattended. Prefer the separate
stages when a human is available, because the gaps between them are where your
judgement is worth something.

**UDP needs root.** `discover` warns and continues if it cannot run `-sU`. If
you see that warning, say so explicitly — "no SNMP findings" and "SNMP was
never checked" look identical in a report, and only one of them is honest. Ask
whether to re-run with sudo. If a stage after the sudo pass says it cannot
write `state.db`, run the `chown` command it prints.

## Reading findings without drowning in them

`findings --json` returns every finding with its full evidence, which on a
real run is hundreds of kilobytes. Read in two steps instead:

```bash
extscan findings <run> --severity medium     # one line each: severity, target, title, id
extscan findings <run> --review-only         # the manual review queue's raw material
extscan show <run> --finding <id>            # one finding in full, evidence included
```

Use `--json` on `hosts`, `services`, `leads`, `gaps` and `status`, which
stay small.

## What the gaps are telling you

`extscan gaps` now reports several conditions that used to pass silently.
Each changes what you may claim:

- **"N of M addresses did not answer host discovery."** Those addresses
  were never port-scanned. Many will be unused, but a host that drops ping
  looks the same. On a small scope, offer `nmap.skip_host_discovery`; on a
  large one, say how many addresses the results do not cover.
- **nmap gave up on ports, or timed a host out.** Ports on the named hosts
  may have been missed. Offer a re-run with higher `nmap.max_retries` or
  `nmap.host_timeout`, or slower timing.
- **UDP ports were `open|filtered`.** nmap got no answer, so the port may be
  open or silently dropped. Never write "SNMP is exposed" from that state
  alone; the SNMP check's own result is the evidence.
- **"Path checks not trustworthy" on a web service.** A WAF or rate limit
  cut the checks short. Findings made before the block stand; absence of
  findings on that service means nothing. Slow down
  (`http.inter_request_delay`) or ask the client to allow-list the scanner,
  then `extscan probe <run> --only http_fingerprint`.
- **An `enrich` gap.** Findings are not ranked by known exploitation, so a
  missing KEV flag or EPSS score means nothing until it clears.

## Findings that need a particular reading

- **Virtual host findings (`extscan:vhost`).** A name tied to an in-scope
  address returned a different site from the one seen by address. That
  application has had none of the other checks. Report it; do not add the
  name to scope and do not point any tool at it. Getting it tested is a
  scope decision for the client.
- **A host tagged with a network (Cloudflare, CloudFront, Fastly, Google).**
  Its open ports and TLS setup may belong to a shared edge, not the client's
  server. Say so before attributing them to the client.
- **KEV and EPSS.** `KEV` means the CVE is in CISA's catalogue of
  vulnerabilities exploited in the wild, and it moves the item up the review
  queue. It does not confirm the finding: a version-matched CVE stays
  tentative however widely it is exploited.

## Comparing with the last assessment

```bash
extscan diff <old-run> <new-run>     # writes diff.md and diff.json into the new run
```

Five states. **Not re-checked** means still open as far as anyone knows:
the new run did not look (the host left scope, discovery or the check had a
gap, the stage never ran), and each item gives the reason. Only **gone**
means the new run looked and did not find it. Never tell a client something
was fixed from a "not re-checked" line.

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

When you settle a lead yourself (you read the saved spec, or the user says
to leave it), close it so it stops showing as open work:

```bash
extscan resolve <run> --lead <id> --status done --note "what you concluded"
```

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
  the endpoint and run `extscan chase <run>` again (leads still open are
  retried), or work those leads
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
- **Do not copy secrets around.** Evidence keeps credential values so a human
  reviewer can judge whether they are live, expired or placeholders. Leave
  that judgement to them: don't try discovered credentials, and never paste
  them into a commit, a ticket or anywhere outside the run directory and
  report.
- **Stay inside the window.** If the testing window has closed, stop. Amending
  the scope file needs the client's agreement, not yours.
- **Subdomains outside scope are never scanned.** The recon stage reports them
  as asset discovery precisely so that someone can have the authorisation
  conversation. Finding a forgotten cloud host is a good outcome; scanning it
  is an unauthorised act against infrastructure that may not even be the
  client's.
- **Takeover candidates are report-only.** recon flags dangling CNAME, MX and
  NS records from DNS alone, and discover does the same for the names of
  in-scope hosts. Don't register the domain, create the bucket or
  otherwise claim the resource to prove it. The client confirms.
- **IIS checks stay read-only.** The WebDAV check reads the advertised verb
  list and does not attempt PUT; the 8.3 short-name check confirms the
  condition in two requests and does not enumerate. Both are flagged for a
  human to decide whether to go further. Do not go further on your own.

## Writing the report

`extscan report <run>` renders Markdown, JSON and `report/`, an Obsidian
vault that tells the run as a pentest narrative (`report/00 Summary.md` is
the entry point), with screenshots if `extscan screenshot <run>` ran. Read
the summary note before handing it over. In your summary to the user:

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
