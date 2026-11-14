# extscan

extscan scans the internet-facing side of a network you are authorised to
test, and hands a person the parts a tool cannot judge.

Most of an external assessment is mechanical. You give nmap a range, then
work through each open port: run the right tool at it, read the output,
decide whether to dig further. That takes most of the time, and it leaves
less for the findings that need someone to think.

extscan does the port-by-port part. It also says where its part stops: every
report has a manual review queue, a list of things the scan proved are
exposed and could not decide about, each with the question a reviewer has to
answer.

```
scope → discover (nmap TCP+UDP) → probe (per-service) → chase (follow-ups) → enrich → analyse → triage → report
                                         ↑_______________________|  bounded loop
```

`analyse` is the model-written notes stage. It does nothing unless a policy
file turns a model on.

`tests/fixtures/lab-run/report.md` is a complete report from a scan of the
bundled lab, if you want to see the output before installing anything.

Every setting, command and flag is listed in `docs/CONFIGURATION.md`. This
file gets you to a first scan, then explains what the tool does and why.

## Contents

- [Quick start](#quick-start)
- [Scanning a real target](#scanning-a-real-target)
- [The scope file](#the-scope-file)
- [Running stage by stage](#running-stage-by-stage)
- [Profiles and policy files](#profiles-and-policy-files)
- [Optional extras](#optional-extras): UDP, screenshots, more tools
- [Reports](#reports)
- [Model-written notes](#model-written-notes)
- Reference: [what it checks](#what-it-checks),
  [when things go wrong](#when-things-go-wrong),
  [safety properties](#safety-properties),
  [how it is put together](#how-it-is-put-together)
- [Driving it with Claude](#driving-it-with-claude)

## Quick start

You need:

- Linux or macOS, with Python 3.10 or later
- [uv](https://docs.astral.sh/uv/)
- `nmap` and `nuclei` on `PATH`

extscan itself has no runtime dependencies beyond the standard library.

```bash
git clone git@github.com:asii-mov/external-scanning.git && cd external-scanning
uv sync
uv run extscan doctor     # lists the scanners it found, with install commands for the rest
```

On a fresh Ubuntu or Debian box, `bash scripts/cloud-setup.sh` installs
nmap, sslscan, uv and a pinned nuclei with its templates, then runs
`uv sync`.

The commands in this file are written as `extscan ...`. Either put `uv run`
in front of each one, or activate the environment once per shell:

```bash
source .venv/bin/activate
```

### Try it on the lab

The repo includes a lab: nine deliberately exposed services on `127.0.0.2`
(HTTP, HTTPS, IIS, SSH, Redis, MySQL, Elasticsearch, Docker API, SNMP), and
a scope file that authorises only that address. Use it to see a full run and
a report before pointing the tool at anything real.

On macOS, add the address first: `sudo ifconfig lo0 alias 127.0.0.2 up`.

```bash
uv run python -m tests.lab       # terminal 1: the lab, Ctrl-C to stop
```

```bash
# terminal 2
extscan run --scope examples/lab/scope.json --policy examples/lab/policy.json
extscan findings latest          # what it found
extscan gaps latest              # what it could not check
```

The scan takes about 8 minutes, nearly all of it nuclei. When it finishes:

- The report is `runs/<run-id>/report.md`. Start at the manual review queue.
  `latest` in any command means the newest run.
- The run exits with code 3 and lists a coverage gap for UDP. That is
  expected: UDP scanning needs root, and extscan reports what it skipped
  instead of passing quietly. [Optional extras](#optional-extras) shows how
  to add the UDP pass.

`docs/LAB.md` lists what each lab service should produce, and has
troubleshooting for the lab.

## Scanning a real target

1. Copy the scope template and fill it in. extscan scans nothing without a
   scope file that names the targets and who authorised the test.
   [The scope file](#the-scope-file) explains each part.

   ```bash
   cp examples/scope.example.json scope.json
   ```

2. Run the scan.

   ```bash
   extscan run --scope scope.json
   ```

3. Read the results.

   ```bash
   extscan status latest       # stages done, counts
   extscan findings latest     # findings by severity
   extscan gaps latest         # what did not get checked
   ```

   The report is `runs/<run-id>/report.md`. [Reports](#reports) describes
   its sections and the Obsidian vault written beside it.

If the run is interrupted (Ctrl-C, a dropped SSH session, a reboot),
`extscan resume latest` carries on from the last checkpoint.

`run` and `resume` finish by listing the coverage gaps. The exit code
carries the same information, for a scheduler or a CI job:

| Exit code | Meaning |
|---|---|
| 0 | Finished, with no serious coverage gap. Warnings are printed |
| 3 | Finished and wrote the report, with at least one serious coverage gap. Read `extscan gaps` |
| 2 | Refused or misconfigured: scope, policy, report template, damaged run state |
| 1 | Aborted. Nearly everything failed, which points at this machine's network |
| 130 | Interrupted. State is on disk; use `extscan resume` |

An unprivileged run has no UDP pass. That is a serious gap, so it exits 3.

## The scope file

extscan scans nothing without a scope file that says what may be touched and
who agreed to it. If someone's SOC asks what hit them, this is the record
you point to.

```jsonc
{
  "engagement": "ACME external perimeter review",
  "client": "ACME Corporation",
  "authorization": {
    "reference": "SOW-2026-114 / JIRA SEC-1423",     // required
    "authorized_by": "jane.doe@acme.example (CISO)",  // required
    "window_start": "2026-11-01T00:00:00Z",
    "window_end": "2027-12-31T23:59:59Z",
    "notes": "External perimeter only. No DoS. No credential testing."
  },
  "targets": ["203.0.113.0/27", "198.51.100.14"],
  "exclude": ["203.0.113.5"],
  "max_hosts": 256
}
```

`targets` are the only addresses that get scanned. The other keys are
`allow_hostnames`, `domains` and `allow_private`; `docs/CONFIGURATION.md`
describes each, and `examples/scope.example.json` is a template to copy.

What is checked when the file is loaded:

- A malformed address or range fails before a packet is sent.
- Internal address space (RFC 1918, loopback, link-local, CGNAT) is refused
  unless `allow_private` is set.
- A scope that expands to more than `max_hosts` hosts is refused.
- A window that is not a valid date is refused.
- A key the file format does not have is refused. `"exlude"` read as "no
  exclusions" would scan the host you meant to leave out. Keys starting with
  `//` are comments.

The testing window is checked at the start of each stage, and again before
every nmap batch, nuclei batch and follow-up, so a long stage stops when the
window closes.

The file is re-read on every command, which means an exclusion added halfway
through takes effect. When it differs from what the run was created with,
extscan prints what changed (targets added, exclusions removed, a new
window), stores that in the run and shows it in the report.

## Running stage by stage

`extscan run` does everything in one go. Each stage is also a command of its
own, so you can stop after discovery, look at what is open, change the
policy and carry on:

```bash
extscan init --scope scope.json --profile standard
extscan recon latest                 # subdomains and DNS checks (needs scope.domains)
extscan discover latest              # nmap TCP + UDP, in checkpointed batches
extscan services latest              # what is open
extscan probe latest                 # nuclei + per-service probes
extscan leads latest                 # what is worth a closer look
extscan chase latest --rounds 2      # resolve the follow-ups
extscan screenshot latest            # headless Chromium, every request scope-checked
extscan enrich latest                # KEV and EPSS ranking, CDN tagging (public feeds only)
extscan analyse latest               # model-written notes, only if llm.enabled is set
extscan report latest                # report.md, report.json, report/ (Obsidian vault)
extscan gaps latest                  # what did NOT get checked
extscan diff <old-run> latest        # what changed since the last scan
```

The commands that read a run (`status`, `hosts`, `services`, `findings`,
`leads`, `gaps`) take `--json`. `extscan --help` lists every command, and
`docs/CONFIGURATION.md` has every flag.

## Profiles and policy files

A profile sets how thorough the scan is: `quick`, `standard` or `thorough`.
`thorough` scans all 65535 TCP ports and takes hours on a wide range.

To pick the TCP ports alone, pass `--tcp-ports` to `init` or `run`: `all`
(1-65535), `top` (the standard list), `quick` (25 common ports), or a list
such as `22,80,8000-8100`.

Everything else is changed with a policy file (`--policy FILE`), a JSON file
that overrides the profile's defaults: rates, timeouts, ports, which checks
run, the model, the report template. `examples/policy.gentle.json` is a
rate-limited one for fragile infrastructure. `docs/CONFIGURATION.md` has
every key with its default.

A key or section extscan does not recognise is an error, so a typo cannot
leave a default in force unnoticed.

Be careful with `nmap.parallel` (default 1). It runs that many nmap batches
at once and multiplies the traffic the network sees by the same number, so
agree the rate before raising it.

## Optional extras

None of these is needed for a first run. Without one, extscan records a
coverage gap that says what was not checked, and carries on.

### UDP scanning

UDP scanning needs root. An unprivileged run says at the start that it is
TCP only, prints the command that adds UDP later, and records a coverage
gap. A report with no SNMP findings and a report where SNMP was never
checked have to look different.

```bash
sudo .venv/bin/extscan discover <run> --udp-only   # clears the gap once UDP has run
```

### Screenshots

Screenshots for the report need headless Chromium:

```bash
uv sync --extra screenshots && uv run playwright install chromium
```

Without it, the screenshot stage records a coverage gap and the report
describes web services in text.

### More scanners

nmap is required, and nuclei is required for the templated web checks.
`sslscan`, `testssl.sh`, `subfinder` and `amass` are optional and each adds
checks: cipher-level TLS audits, and more subdomain sources for `recon`.
`snmpwalk` is not required, because extscan has its own SNMP client.
`extscan doctor` shows which are installed and prints install commands for
the rest.

### A model

A model can write a note on each finding that matters. It is off by default
and needs one extra package; see [Model-written notes](#model-written-notes).

## Reports

`extscan report` writes `report.md` for people, `report.json` for tooling
and `report/`, an Obsidian vault.

`report.md` has these sections by default:

1. Authorisation and scope: what was agreed, by whom, when.
2. Summary: counts by severity, and a warning if there are coverage gaps.
3. Manual review queue: the items a person has to decide, in order, each
   with its question.
4. Notes for the security team: where to look next. It lists follow-ups the
   scanner did not finish, assets it saw outside the scope file and left
   alone, findings inferred from a version or a specification, and notes
   written by an analyst or a model. `report.json` has the same data as
   `security_notes`.
5. Systemic issues: anything on three or more hosts, as one task.
6. Findings: by severity, with evidence.
7. Service inventory.
8. Coverage gaps: what was not checked, why, and the remedy.
9. Methodology and limitations: stages run, tool versions, command log.

Findings are marked `tentative` when they come from a version banner or a
specification and not from behaviour the scanner saw. Keep the distinction
when you write up. An over-claimed finding is hard to walk back.

### Changing the layout

The layout of `report.md` is itself a Markdown file,
`extscan/templates/report.md`. To change the sections, their order, the
headings or how one finding is laid out, edit a copy:

```bash
extscan template --out our-report.md      # copy the built-in template
extscan template --check our-report.md    # test the edited copy, no scan needed
extscan report latest --template our-report.md
```

To use it on every run, put `{"report": {"template": "our-report.md"}}` in
the policy. `docs/REPORT_TEMPLATE.md` lists every value a template can use.

The coverage gaps and the review queue can be moved and retitled, and a
template that leaves either out is refused. A template with a mistake in it
is refused before a scan starts.

### The Obsidian vault

`report/` holds the same run as linked notes, written in the order the work
happened. Open the folder in Obsidian and start at `00 Summary.md`.

- `00 Summary` covers scope and authorisation, discovery (with the nmap
  commands as run), each service family with screenshots and a proof block
  per finding, the follow-ups, and what was not covered. The review queue
  and coverage gaps are flagged at the top.
- `hosts/` has one note per host: its services, the checks run on each,
  screenshots and findings.
- `findings/` has one note per finding: evidence, proof, a command to
  reproduce it and the remediation.
- The review queue, the coverage gaps and the methodology (with the full
  command log) are notes of their own.

Notes have YAML frontmatter (severity, host, port, tags) for Dataview and
link to each other with `[[wikilinks]]`. Scanner text is escaped, so a
hostile page title cannot embed a note or make Obsidian fetch a URL.
Re-rendering replaces the notes extscan wrote and leaves your own notes and
`.obsidian/` alone. The template does not apply to the vault.

## Model-written notes

Off by default. Install the extra for your provider:

```bash
uv pip install 'extscan[llm]'       # Anthropic API
uv pip install 'extscan[bedrock]'   # AWS Bedrock
uv pip install 'extscan[azure]'     # Azure (Claude in Microsoft Foundry)
extscan providers                   # check what is usable
```

Then turn a model on in a policy file:

```jsonc
// Anthropic API. Credentials: ANTHROPIC_API_KEY, or an `ant auth login` profile.
{"llm": {"enabled": true, "provider": "anthropic", "model": "claude-opus-5-5"}}

// AWS Bedrock. Credentials: the usual AWS chain (role, profile, environment).
{"llm": {"enabled": true, "provider": "bedrock",
         "model": "anthropic.claude-opus-5-5",
         "aws_region": "eu-west-2", "effort": "medium"}}

// Azure (Claude in Microsoft Foundry). `model` is your deployment name.
// Credentials: ANTHROPIC_FOUNDRY_API_KEY, or Entra ID when no key is set.
{"llm": {"enabled": true, "provider": "azure",
         "azure_resource": "my-foundry-resource", "model": "claude-opus-5-5"}}
```

`examples/policy.direct-api.json`, `examples/policy.with-bedrock.json` and
`examples/policy.with-azure.json` are starting points. `extscan providers
--policy FILE` says what is missing before you scan. A policy file never
holds a credential, because the policy is copied into every run directory.

The model is used in two places. In `chase` it comments on an exposed API
specification. In `analyse` it writes one note for each finding at or above
`llm.analyse_findings_above` (default `medium`; `off` skips the stage), up
to `llm.max_findings` per run (default 40). The report lists the notes under
"Notes for the security team". A finding that should have had a note and
did not is recorded as a coverage gap.

Provider details:

- Bedrock model ids carry an `anthropic.` prefix. Cross-region ids
  (`us.anthropic.…`) and inference-profile ARNs work too. Access is granted
  per model per region, and a wrong region is the usual first failure, so
  `extscan providers` checks for it.
- On Azure, set `llm.azure_resource` to the Foundry resource name, which is
  the first label of `https://<resource>.services.ai.azure.com`. For a
  private endpoint set `llm.base_url` instead. `llm.azure_auth` is `auto`
  (the API key if `ANTHROPIC_FOUNDRY_API_KEY` is set, otherwise Entra ID),
  `api_key` or `entra`. Entra ID goes through `azure-identity`'s default
  credential chain: managed identity, workload identity or `az login`.
- `llm.enabled: true` with no provider is an error, and so is a provider
  name extscan does not know.

Everything sent to the model was written by the system being scanned. The
code holds to three rules because of that:

1. The input is treated as hostile. Evidence is fenced and labelled as data,
   and the delimiter is stripped from the content so it cannot close its own
   fence. The system prompt says that instructions found in the evidence are
   a finding to report and must not be followed.
2. The output changes nothing. A note becomes a separate finding with the
   source `llm-analysis`. It is always `info` severity whatever the model
   thought, marked tentative and flagged for review. The model cannot choose
   what is scanned, widen the scope or move anything up the queue.
3. Secrets stay here. Evidence is redacted before it is sent. An exposed
   `.env` shows that credentials are reachable, and that is no reason to
   upload them to an API. This is the only redaction in extscan; reports
   keep evidence as captured.

A run without a model produces the same findings without the notes, and the
report says so.

## What it checks

| Stage | Covers |
|---|---|
| `discover` | nmap TCP (SYN when privileged, connect otherwise) and UDP, service and version detection, the `default,safe,vuln` NSE categories, OS fingerprint |
| `discover` on large scopes | When the scope has more hosts than `nmap.chunk_size`, discovery runs in two phases: a port sweep of every address with no version detection, then the full scan on the hosts that had an open port, on the union of those ports. On a sparse /24 the lab eval goes from 8 nmap runs to 2 for the same services. `nmap.sweep` is `auto`, `always` or `never` |
| `discover` → host discovery | Wider than nmap's default, which unprivileged is a connect to ports 80 and 443 only. extscan sends ICMP echo and timestamp, SYN to 22 common ports, and ACK and UDP probes (`nmap.discovery_probes`). Unprivileged runs send the SYN probes only |
| `discover` → dns | The host names nmap reported for each live in-scope address, checked one by one for dangling CNAME and MX records. Names under no scope domain are listed in one info finding, so a reviewer can add the domains and get the zone checks. Skip with `dns.skip: ["host-names"]` |
| `probe` → `web_identify` | Open TCP ports nmap could not name (`unknown`, `tcpwrapped`, or guessed from its port table) get one TLS handshake and one GET, so an application on an odd port still gets the web checks |
| `probe` → `nuclei` | Templated web checks across every HTTP service, in batches of `nuclei.batch_size`, each checkpointed. A re-run covers only the services not yet done; `--force` repeats all |
| `probe` → `http_fingerprint` | Root page, fingerprint and security headers, and 22 disclosure paths. Each answer is compared with the server's answer for a path that cannot exist, which filters soft 404s |
| `probe` → `http_fingerprint` (edge) | Names the CDN or WAF in front of a service from its headers and cookies. Notices being throttled or blocked: a 429, a challenge header, a run of dropped requests, one block page for every path. Blocked path checks are recorded as a coverage gap |
| `probe` → `vhosts` | Requests `/` once for each name tied to the address (reverse DNS, in-scope names from recon, certificate SANs), sending the name as Host header and SNI to the in-scope IP. A name counts only if its page differs from both the by-address page and the page for a name that cannot exist. Reported for review, because the application behind the name was not otherwise tested |
| `probe` → `tls` | Certificate detail, expiry, self-signing, which TLS versions are offered |
| `probe` → `snmp` | Default and guessable community strings, read-only, with the built-in SNMP client |
| `probe` → `exposure` | Databases, management interfaces and legacy services that should not face the internet |
| `probe` → `ssh` | Banner and exposure review |
| `probe` → `iis` | IIS and ASP.NET: `trace.axd` and `elmah.axd`, WebDAV verbs, the 8.3 short-name oracle, verbose error pages, version headers, default content |
| `probe` → `sslscan` | Cipher-level TLS audit: RC4, 3DES and export suites, CRIME, insecure renegotiation. Needs `sslscan` |
| `recon` → subdomains | Certificate transparency plus `subfinder` or `amass`. Names are resolved and split into in-scope (scannable) and out-of-scope (reported, never touched) |
| `recon` → dns | Per scope domain, with the built-in DNS client: zone transfer (AXFR) against each nameserver, NSEC zone walking (NSEC3 is recognised, not cracked), and takeover candidates from dangling CNAME, MX and NS records and lame delegations. Report only. The policy's `dns` section tunes or skips checks. `dns.subzones: true` also transfers and walks each delegated sub-zone, up to `dns.max_subzones` |
| `chase` → `openapi` | Finds the spec, lists its operations, flags the ones declaring no authentication (writes especially), notes servers outside scope |
| `chase` → `graphql` | Introspection, schema size, whether mutations are exposed |
| `chase` → `api_endpoint` | Confirms that one GET documented as open is open |
| `chase` → `secret_file` | Credential-bearing files, with the values shown for review |
| `chase` → `git_exposure` | Readable `.git` metadata |
| `chase` → `snmp_walk` | Interface and address tables, to show what the exposure discloses |
| `enrich` | Downloads the CISA KEV catalogue and FIRST's EPSS scores (cached for a day; nothing about the targets is sent) and attaches them to findings that carry a CVE. A KEV-listed finding moves up the review queue, above unlisted findings one severity level higher. Also tags addresses inside Cloudflare, CloudFront, Fastly and Google ranges, where port results describe a shared edge. `enrich.enabled: false` or `EXTSCAN_OFFLINE=1` turns it off |
| `analyse` | With a model enabled, one written note per finding at or above `llm.analyse_findings_above`. See "Model-written notes" |
| `diff` | Compares two runs: new, changed, gone and not re-checked. A finding missing from the new run counts as gone only if the new run looked. If the host left scope, the check had a gap or the stage never ran, it is "not re-checked", with the reason |

`extscan probes` lists the registered probes.

## When things go wrong

A scan that checked half of what it claimed and said nothing is worse than
one that failed, because somebody acts on the report. So a failure ends one
of three ways: it is retried and works, it is recorded as a named coverage
gap, or the run stops with a message.

| Failure | What happens |
|---|---|
| nmap times out or is killed | The partial XML is salvaged: hosts nmap finished are recovered from the truncated file. The gap names the hosts that went unscanned. Output is written with `-oA`, so `nmap --resume` also works |
| A stage after `sudo ... --udp-only` cannot write | extscan hands files it creates as root back to the run directory's owner. If something is still root-owned, it stops and prints the `chown` to run |
| The scope is large | Discovery runs in batches of `nmap.chunk_size` hosts, each checkpointed. A timeout costs one batch, and `extscan resume` skips what finished |
| nmap, nuclei or sslscan is not installed | A coverage gap naming what was not checked. The run continues. `doctor` tells you beforehand |
| nuclei or a probe fails | A killed, timed-out or crashing tool is a coverage gap naming the services it did not finish. Those services stay unmarked, so `extscan probe <run> --only <probe>` retries them |
| nuclei output has lines that cannot be read | The results that could be read are kept. The rest is a gap naming the batch and the file under `raw/` |
| Addresses do not answer host discovery | Counted, and recorded as one gap per pass ("412 of 1024 addresses did not answer"), because they were never port-scanned. `nmap.skip_host_discovery` scans them anyway |
| nmap gives up on a port or times a host out | nmap says so only in its text output. extscan reads it and records a gap naming the hosts and the setting to change |
| A UDP port is `open\|filtered` | Kept in the inventory so the SNMP check still tries it, and recorded as unconfirmed. nmap got no answer, so the port may be open or the packet may have been dropped |
| An SNMP request cannot be sent (no route, a local firewall) | The check is recorded as not run. Only a timeout or a closed port counts as "no SNMP" |
| A WAF or rate limit blocks the path checks | A gap naming the service. Findings made before the block are kept, and the next `probe` retries the service |
| A KEV or EPSS feed cannot be fetched | A gap saying findings are not ranked by exploitation. An older cached copy is used if there is one |
| UDP needs root | A TCP-only notice before discovery starts, and a serious coverage gap |
| A lead keeps failing | Retried up to `max_lead_attempts` times across runs, then abandoned with its error recorded. One unreachable host cannot block the stage on every resume |
| Nearly everything fails | The run stops and says the fault is probably local (egress, VPN, DNS). The alternative is a report claiming the whole range is dark |
| The saved policy or `run.json` cannot be read | The command stops and says so. Falling back to the default policy would drop the run's rate limits |
| The report template has a mistake | `run` and `init` refuse before scanning. `report` fails and leaves the previous `report.md` in place |
| The model endpoint is down | Retried with backoff, then extscan stops calling it. 100 leads against a dead endpoint cost about 6 HTTP attempts, not 200. Findings keep their evidence |
| The model returns something unusable | Not retried, and counted separately from an outage |
| A model note could not be written | One gap for the `analyse` stage, naming the findings without a note and the cause: endpoint down, a refusal, a reply cut off at `llm.max_tokens`, or more findings than `llm.max_findings` |
| The process is killed | Every change is its own database transaction, and results are stored as each batch and each probe finishes. `extscan resume <run>` does what is left |

`extscan gaps <run>` lists the gaps. The report mentions them in its summary
and gives them their own section.

## Safety properties

These are deliberate and tested. Where a policy file can change one, the
entry says so.

- extscan is read-only. It sends GETs, connects and queries. It tests no
  credentials (nuclei's `default-login` and `creds-stuffing` templates are
  excluded), sends no SNMP SET, writes nothing to a discovered service and
  exploits nothing. Where impact cannot be shown without going further, the
  finding says so and asks a person.
- Scope is checked again on every request. Leads come from scanner output,
  HTTP redirects and OpenAPI `servers` blocks, all of which the target
  controls. A host that redirects to `169.254.169.254` is refused, recorded
  as a finding and not followed.
- nuclei follows no redirects. Left alone it follows them to any host, so
  it runs with `-disable-redirects` and requests only the in-scope URLs it
  was given. Templates that match only after a redirect will not fire.
  `nuclei.follow_redirects: true` turns following back on, for a range where
  you know every redirect target is yours.
- A policy file cannot add targets. `nmap.extra_args` accepts timing and
  verbosity flags and nothing else. A bare address, `-iL`, `--script`,
  `--exclude`, decoys, spoofing and output flags are refused.
  `nuclei.extra_args` refuses flags that add targets, set a proxy, upload
  results, run code or bring back excluded templates.
- Excluded hosts never reach nmap. nmap gets the expanded host list with the
  exclusions already removed, whatever `nmap.chunk_size` is.
- A name in `allow_hostnames` is checked where it points. It may resolve
  outside `targets`, which is the reason the setting exists. It is refused
  when it resolves to an excluded address, or to internal address space
  (including the cloud metadata address) while `allow_private` is false.
  The check and the connection are separate DNS lookups, so use IP targets
  where you can.
- No command goes through a shell. Each runs as an argv list, so a string
  that came from a target cannot become shell syntax.
- NSE scripts that disrupt or leak are excluded: the `dos` and `external`
  categories and `http-slowloris-check`. `external` covers scripts such as
  `vulners` and `dns-blacklist`, which send target details to third-party
  services. A policy can change the list (`nmap.exclude_scripts`).
- Destructive nuclei templates are excluded (`dos`, `intrusive`, `fuzz`,
  `brute-force`), and out-of-band detection is off, because a public
  interactsh relay would see the traffic. A policy can change both
  (`nuclei.allow_intrusive`, `nuclei.interactsh`). Do that only for work
  that explicitly allows it.
- The system proxy is ignored. `http_proxy` in the operator's shell would
  send the traffic through a third party and make the results describe the
  proxy. `http.use_system_proxy` turns it on.
- Secrets are shown, for a person to judge. Evidence keeps the values it
  found (an `.env`'s keys and values, cookies, community strings), and the
  pages holding them are screenshotted, so a reviewer can tell a live
  credential from an expired one or a placeholder. Treat reports as working
  documents and sanitise them before they go anywhere else.
- DNS queries stay on the scope's domains. `Scope.assert_dns_name` in
  `extscan/scope.py` gates every query: the name has to be a `domains` entry
  or sit under one. Zone transfers and NSEC walks go only to the zone's own
  nameservers. A CNAME, MX or NS target outside the zone is checked for
  existence with an A query through the resolver, and nothing more: extscan
  does not contact it, send it HTTP or try to claim it. Only opcode QUERY is
  sent.
- A host's name does not open its zone. The one exception to the rule above
  is a host name nmap reported for an in-scope address. The resolver is
  asked for its A and MX records only, so the zone's nameservers are never
  looked up, asked for a transfer or walked.
- Screenshots stay in scope. Every request the browser makes, including
  subresources and each redirect hop, is scope-checked before it is sent.
  Blocked requests are listed in the caption.
- There is an audit trail. Every command, exit code and timing is in
  `commands.jsonl` and summarised in the report, so a finding can be
  reproduced.

## How it is put together

Each stage reads and writes a run directory, and nothing else carries state.
You can stop after discovery, look at what is open, change the policy and
carry on. A dropped SSH session costs nothing.

The state is a SQLite database, `runs/<run-id>/state.db` (standard library,
one transaction per change). Beside it are `run.json`, the command log
`commands.jsonl` and the raw tool output in `raw/`. Read the state with the
CLI (`extscan hosts`, `services`, `findings`, `leads`, `gaps` or `status`,
with `--json`) or write plain JSON copies with `extscan export <run>`. Runs
made before the database existed still open, render and diff. The first
write converts them and keeps the old files in `legacy-json/`.

A finding and the judgement about it are kept apart. A tool can show that
Swagger UI is published. Whether that is acceptable here is a person's call.
extscan records the finding and the question.

Follow-ups are tracked as "leads". Discovery says port 443 is open, and a
probe says there is an OpenAPI document, but neither says what that
document exposes. So a swagger hit raises an `openapi` lead. Chasing it
parses the spec and raises `api_endpoint` leads for operations documented as
needing no authentication. Chasing those checks whether the spec matches
what the server does. The depth is capped, so the loop ends.

There are no runtime dependencies beyond the standard library, so there is
nothing to pip install on a jump box. SNMP is implemented in the tool (BER
over UDP), and `snmpwalk` is not needed.

## Driving it with Claude

`.claude/skills/extscan/SKILL.md` is a skill for Claude Code. It covers the
workflow, where a model's judgement helps, and the limits that hold however
a request is phrased.

Two things make the tool usable by an agent. Every read command takes
`--json`. And `extscan note` records a finding from the model's own analysis
with `--source claude-analysis`, so a reviewer can tell reasoning from tool
output. An agent that reads an OpenAPI spec and concludes that
unauthenticated invoice deletion matters more than an open health check can
write that down where the reviewer will see it.

## Further work

`docs/ROADMAP.md` is a prioritised list of what else is worth adding, with
the catch for each. `reports/External scanning gap analysis.md` rates a
longer list and names two safety questions to settle first.

## Legal

For authorised testing only. Scanning systems you do not own, or do not have
written permission to test, is illegal in most jurisdictions. Record that
permission in the scope file before the first packet.
