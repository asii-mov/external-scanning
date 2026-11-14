# Configuration reference

Every setting extscan reads, in one place: the scope file, the policy file,
the command line, environment variables and exit codes. `README.md` explains
what the tool does and why; this file is for looking something up.

A test (`tests/test_docs.py`) compares this file with the code, so a setting
added without a row here fails the suite.

- [Scope file](#scope-file)
- [Policy file](#policy-file)
- [Commands](#commands)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)

## Scope file

It says what may be touched. `--scope FILE` on `init` and `run`; later
commands re-read the same path, or the one given with `--scope`. The file is
one of two things.

A plain list of targets, one per line: an address, a CIDR range, or a range
such as `12.1.1.1-100` (the last octet) or `12.1.1.1-12.1.2.20`, both ends
included. `#` starts a comment. It records no authorisation, so the report
says none was recorded, and the person running the scan is trusted to list
only ranges they may test. Every other setting keeps its default: internal
address space and more than 1024 hosts are refused. A range of more than
65536 addresses has to be written as CIDR blocks. `examples/targets.example.txt`
is a template.

JSON, when the run should record who agreed to it, or needs exclusions, a
testing window, host names, domains or a different `max_hosts`. A file whose
first character is `{` is read as JSON. `examples/scope.example.json` is a
template. The rest of this section describes the JSON keys.

An unknown key is an error. A key whose name starts with `//` is a comment.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `engagement` | no | `unnamed engagement` | Name of the piece of work. Used in the report title and the run id |
| `client` | no | empty | Who the systems belong to. Shown in the report header |
| `authorization` | yes | | The sign-off. See the next table |
| `targets` | yes | | IPv4 or IPv6 addresses, CIDR ranges, and ranges such as `12.1.1.1-100`. These are the only things that get scanned |
| `exclude` | no | `[]` | Addresses and ranges inside `targets` to leave alone, written the same way. Removed before nmap sees the list |
| `allow_hostnames` | no | `[]` | Host names that HTTP requests may be sent to by name. A name is refused if it resolves to an excluded address, or to internal address space while `allow_private` is false |
| `domains` | no | `[]` | Domains whose names may be enumerated and whose DNS may be queried (`recon`). A name found this way is scanned only if its address is inside `targets` |
| `max_hosts` | no | `1024` | The scope is refused if it expands to more hosts than this |
| `allow_private` | no | `false` | Allow internal address space as a target: RFC 1918, loopback, link-local, CGNAT, IPv6 unique-local and link-local |

`authorization`:

| Key | Required | Default | Meaning |
|---|---|---|---|
| `authorization.reference` | yes | | Ticket, contract or change number |
| `authorization.authorized_by` | yes | | The person who signed off |
| `authorization.window_start` | no | empty | Earliest time scanning may run, ISO 8601 such as `2026-11-01T00:00:00Z`. No zone means UTC |
| `authorization.window_end` | no | empty | Latest time scanning may run. Checked at the start of each stage and before every nmap batch, nuclei batch and follow-up |
| `authorization.notes` | no | empty | Constraints, contacts. Shown in the report |

With neither window key set, there is no time limit.

## Policy file

JSON. It says how hard to push and what is off the table. `--policy FILE` on
`init` and `run`. The policy is copied into the run, so later commands use
the same one unless `--policy` is given again.

Start from a profile (`--profile`, or `"profile"` in the file) and override
only what you need. An unknown key or section is an error.

Examples: `examples/policy.gentle.json` (rate-limited),
`examples/policy.direct-api.json`, `examples/policy.with-bedrock.json`,
`examples/policy.with-azure.json`.

### Profiles

| Profile | What it changes from `standard` |
|---|---|
| `quick` | 25 common TCP ports, 6 UDP ports, NSE `default,safe` only, version intensity 5, nuclei `medium` and above at 30 requests a second, lead depth 2 |
| `standard` | The defaults in the tables below |
| `thorough` | All 65535 TCP ports, version intensity 9, host timeout 90 minutes, nmap timeout 6 hours, nuclei at 80 requests a second with a 3 hour timeout, lead depth 4 |

### Top level

| Key | Default | Meaning |
|---|---|---|
| `profile` | `standard` | `quick`, `standard` or `thorough` |
| `max_workers` | `8` | Per-service probes run at once |
| `max_lead_depth` | `3` | How many follow-ups deep the chase goes. A lead deeper than this stays open and is listed in the report |
| `max_leads_per_run` | `500` | Leads stored per run. Further ones are dropped |
| `max_lead_attempts` | `3` | Attempts at one lead, counted across runs, before it is abandoned and recorded as a gap |
| `stop_on_tool_error` | `false` | Not implemented. Must stay `false`; `true` is refused. A failed tool is a coverage gap and the run carries on |

### `nmap`

| Key | Default | Meaning |
|---|---|---|
| `nmap.tcp_ports` | 1-1024 plus about 60 common service ports | TCP ports, as an nmap port list. `--tcp-ports` on `init` and `run` sets it |
| `nmap.udp_ports` | 19 common UDP ports | UDP ports, as an nmap port list |
| `nmap.timing` | `-T4` | nmap timing template, `-T0` to `-T5` |
| `nmap.version_intensity` | `7` | `--version-intensity`. The UDP pass caps it at 5 |
| `nmap.host_timeout` | `30m` | `--host-timeout`: nmap gives up on one host after this |
| `nmap.max_retries` | `2` | `--max-retries` per port |
| `nmap.min_rate` | `0` | `--min-rate` in packets a second. 0 leaves it to nmap |
| `nmap.scripts` | `default,safe,vuln` | NSE categories or scripts for the TCP pass. The UDP pass runs `default,safe`. Empty runs none |
| `nmap.exclude_scripts` | `dos`, `external`, `http-slowloris-check` | NSE categories or scripts that never run, whatever `scripts` selects |
| `nmap.skip_host_discovery` | `false` | `-Pn`: port-scan every address, including ones that do not answer discovery |
| `nmap.do_udp` | `true` | Run the UDP pass. It needs root |
| `nmap.extra_args` | `[]` | Extra nmap flags. Timing and verbosity flags only; see below |
| `nmap.timeout_sec` | `7200` | Wall-clock limit for one nmap run |
| `nmap.chunk_size` | `32` | Hosts per batch. Each batch is checkpointed. At least 1 |
| `nmap.discovery_probes` | ICMP echo and timestamp, SYN to 22 ports, ACK to 80 and 443, UDP to 53 and 161 | Host-discovery flags. Unprivileged runs send the `-PS` ones only |
| `nmap.sweep` | `auto` | Two-phase discovery: `auto` (when the scope is larger than `chunk_size`), `always` or `never` |
| `nmap.sweep_chunk_size` | `256` | Hosts per batch in the sweep phase |
| `nmap.parallel` | `1` | nmap batches run at once. It multiplies the traffic the network sees |

`nmap.extra_args` accepts these and nothing else: `-n`, `-R`, `-v`, `-vv`,
`-d`, `-6`, `-r`, `-T0` to `-T5`, `--reason`, `--traceroute`,
`--version-light`, `--version-all`, `--defeat-rst-ratelimit`,
`--defeat-icmp-ratelimit`, `--unprivileged`, `--privileged`, and, with a
number or a time as the value, `--max-rate`, `--min-rate`,
`--max-parallelism`, `--min-parallelism`, `--scan-delay`, `--max-scan-delay`,
`--min-rtt-timeout`, `--max-rtt-timeout`, `--initial-rtt-timeout`,
`--max-hostgroup`, `--min-hostgroup`, `--ttl`, `--data-length`,
`--source-port`, `-g`, `--script-timeout`, `--max-os-tries`, `--stats-every`.
Anything else is refused, because it could add targets, spoof a source,
select scripts past `exclude_scripts` or move the output the parser reads.

### `nuclei`

| Key | Default | Meaning |
|---|---|---|
| `nuclei.batch_size` | `25` | Web services per nuclei run. Each run is checkpointed |
| `nuclei.severities` | all five | Template severities to run |
| `nuclei.exclude_tags` | `dos`, `intrusive`, `fuzz`, `brute-force`, `default-login`, `default-logins`, `creds-stuffing` | Template tags that never run |
| `nuclei.include_tags` | `[]` | Run only templates with these tags (`-tags`). Empty means no restriction |
| `nuclei.rate_limit` | `50` | Requests a second |
| `nuclei.concurrency` | `15` | Templates run at once |
| `nuclei.retries` | `1` | Retries per request |
| `nuclei.request_timeout` | `10` | Seconds per request |
| `nuclei.templates` | `[]` | Template paths or directories (`-t`). Empty uses nuclei's installed set |
| `nuclei.extra_args` | `[]` | Extra nuclei flags. Flags that add targets, set a proxy or resolver, upload results, run code, follow redirects, re-include excluded templates or move the output are refused |
| `nuclei.timeout_sec` | `3600` | Wall-clock limit for one nuclei run |
| `nuclei.allow_intrusive` | `false` | `true` drops `exclude_tags`, so intrusive, fuzzing and credential templates run. Only for work that explicitly permits it |
| `nuclei.interactsh` | `false` | Out-of-band detection. Off because a public relay would see the traffic |
| `nuclei.interactsh_server` | empty | Your own interactsh server, used when `interactsh` is `true` |
| `nuclei.follow_redirects` | `false` | `false` runs nuclei with `-disable-redirects`, so it requests only the in-scope URLs it was given. `true` lets it follow redirects to any host |

### `http`

Settings for extscan's own HTTP requests (fingerprinting, path checks,
virtual hosts, follow-ups).

| Key | Default | Meaning |
|---|---|---|
| `http.timeout_sec` | `12` | Seconds per request |
| `http.max_redirects` | `3` | Redirects followed. Every hop is scope-checked |
| `http.max_body_bytes` | `2000000` | Response bytes read |
| `http.user_agent` | `extscan/0.1 (authorised security assessment)` | User-Agent header |
| `http.verify_tls` | `false` | Verify certificates. Off so that a service with a bad certificate is still examined; the certificate is reported separately |
| `http.path_checks` | `true` | Request the disclosure paths |
| `http.paths` | 22 paths such as `/.env`, `/.git/config`, `/swagger.json`, `/actuator` | The disclosure paths |
| `http.inter_request_delay` | `0.0` | Seconds to wait between requests to one service |
| `http.use_system_proxy` | `false` | Use `http_proxy` and friends from the environment |
| `http.max_vhosts` | `25` | Names tried per web service by the virtual-host check. 0 turns it off |

### `snmp`

| Key | Default | Meaning |
|---|---|---|
| `snmp.communities` | 11 common strings, `public` and `private` first | Community strings tried, read-only |
| `snmp.timeout_sec` | `2.0` | Seconds to wait for a reply |
| `snmp.retries` | `1` | Re-sends per request |
| `snmp.versions` | `[1, 2]` | SNMP versions tried. 2 means v2c |
| `snmp.walk_on_hit` | `true` | When a community works, raise a follow-up that walks the interface and address tables |

### `sslscan`

| Key | Default | Meaning |
|---|---|---|
| `sslscan.timeout_sec` | `300` | Wall-clock limit for one sslscan run |

### `recon`

| Key | Default | Meaning |
|---|---|---|
| `recon.sources` | `crt.sh`, `subfinder` | Where subdomain names come from. `crt.sh`, `subfinder` or `amass` (passive mode) |
| `recon.resolve_timeout` | `5.0` | Seconds to resolve one name |
| `recon.max_names` | `2000` | Names kept per domain |
| `recon.allow_bruteforce` | `false` | Not implemented. Must stay `false`; `true` is refused. Recon uses passive sources only |

### `dns`

| Key | Default | Meaning |
|---|---|---|
| `dns.resolvers` | `[]` | Resolvers as `ip` or `ip:port`. Empty uses the system's. An internal address is never queried |
| `dns.port` | `53` | Port of the authoritative servers |
| `dns.timeout_sec` | `3.0` | Seconds per query |
| `dns.retries` | `1` | Re-sends per query |
| `dns.query_interval_sec` | `0.02` | Pause between queries |
| `dns.skip` | `[]` | Checks to leave out: `axfr`, `nsec-walk`, `takeover`, `host-names` |
| `dns.max_names` | `2000` | Names checked per domain |
| `dns.max_walk_steps` | `5000` | Steps in one NSEC walk |
| `dns.max_axfr_records` | `200000` | Records read from one zone transfer |
| `dns.subzones` | `false` | Also transfer and walk each delegated sub-zone |
| `dns.max_subzones` | `20` | Sub-zones audited per domain |

### `screenshots`

| Key | Default | Meaning |
|---|---|---|
| `screenshots.enabled` | `true` | Run the screenshot stage. It needs the `screenshots` extra |
| `screenshots.timeout_sec` | `20` | Seconds per page |
| `screenshots.max_pages` | `60` | Pages captured per run |
| `screenshots.width` | `1280` | Viewport width |
| `screenshots.height` | `800` | Viewport height |

### `enrich`

| Key | Default | Meaning |
|---|---|---|
| `enrich.enabled` | `true` | Download the feeds below and rank findings by them |
| `enrich.kev_url` | CISA's KEV JSON | Where the Known Exploited Vulnerabilities catalogue comes from |
| `enrich.epss_url` | The current EPSS CSV | Where EPSS scores come from |
| `enrich.tag_networks` | `true` | Tag hosts that sit in published CDN and cloud ranges |
| `enrich.range_urls` | Cloudflare, CloudFront, Fastly, Google, Google Cloud | Provider name to a list of URLs that publish its ranges |
| `enrich.timeout_sec` | `30` | Seconds per download |
| `enrich.cache_dir` | empty | Where downloads are cached. Empty means `.feed-cache` beside the run directories |
| `enrich.cache_max_age_hours` | `24.0` | Age after which a cached feed is fetched again |

### `llm`

Off unless `enabled` is `true`. Credentials come from the environment, never
from this file.

| Key | Default | Meaning |
|---|---|---|
| `llm.enabled` | `false` | Use a model |
| `llm.provider` | `none` | `anthropic`, `bedrock` or `azure`. Required when `enabled` is `true` |
| `llm.model` | the provider's default | Model id. `claude-opus-5-5` on the Anthropic API, `anthropic.claude-opus-5-5` on Bedrock, your deployment name on Azure |
| `llm.effort` | `medium` | `low`, `medium`, `high`, `xhigh` or `max` |
| `llm.max_tokens` | `8000` | Output limit per reply. The model's thinking counts against it, so a low value cuts the reply off |
| `llm.timeout_sec` | `120` | Seconds per request |
| `llm.aws_region` | empty | Bedrock region. Falls back to `AWS_REGION`, then `AWS_DEFAULT_REGION` |
| `llm.aws_profile` | empty | AWS credential profile for Bedrock |
| `llm.base_url` | empty | Endpoint override. On Azure it replaces `azure_resource` |
| `llm.azure_resource` | empty | Foundry resource name, the first label of `https://<resource>.services.ai.azure.com` |
| `llm.azure_auth` | `auto` | `api_key`, `entra`, or `auto`: the key when `ANTHROPIC_FOUNDRY_API_KEY` is set, otherwise Entra ID |
| `llm.max_input_chars` | `40000` | Evidence characters sent per request. Longer evidence is truncated and the note says so |
| `llm.sdk_retries` | `0` | Retries inside the SDK. 0 because extscan does the retrying |
| `llm.retry_attempts` | `3` | Attempts per request |
| `llm.retry_base_delay` | `2.0` | First backoff in seconds; it doubles |
| `llm.retry_budget_sec` | `90` | Total seconds spent retrying one request |
| `llm.circuit_failure_threshold` | `3` | Consecutive failures before extscan stops calling the model |
| `llm.circuit_cooldown_sec` | `120` | Seconds before it tries again |
| `llm.analyse_openapi` | `true` | In `chase`, ask for a note on each exposed API specification |
| `llm.analyse_findings_above` | `medium` | In `analyse`, ask for a note on each finding at or above this severity. `off` asks for none |
| `llm.max_findings` | `40` | Findings the `analyse` stage asks about per run. The rest are recorded as a gap |

### `report`

| Key | Default | Meaning |
|---|---|---|
| `report.template` | empty | Path of a report template. Empty uses `extscan/templates/report.md`. See `docs/REPORT_TEMPLATE.md` |

## Commands

`extscan <command> [options]`. `<run>` is a run id or `latest`.

Global options, accepted before or after the command:

| Option | Meaning |
|---|---|
| `--runs-dir` | Where run directories live. Default `runs` |
| `--json` | Machine-readable output |
| `--verbose` | Print every command as it is run |
| `--dry-run` | Print what would run. Sends nothing and marks nothing as done |
| `--no-llm` | Do not use a model, even if the policy enables one |
| `--version` | Print the version |

Every command that takes `<run>` also accepts these:

| Option | Meaning |
|---|---|
| `--scope` | Use this scope file for this command instead of the one the run was created with |
| `--policy` | Use this policy file instead of the one saved in the run |
| `--profile` | Profile to start from when `--policy` is given |

Setting up and running:

| Command | Options | What it does |
|---|---|---|
| `doctor` | | Check which external tools are installed. Exits 1 if nmap is missing |
| `probes` | | List the per-service probes |
| `providers` | `--policy`, `--profile` | Show which model providers are usable, without calling one |
| `template` | `--out`, `--force`, `--check` | Print the built-in report template. `--out FILE` writes a copy (`--force` to overwrite), `--check FILE` tests an edited one |
| `init` | `--scope` (required), `--policy`, `--profile`, `--tcp-ports`, `--id`, `--template` | Create a run. `--tcp-ports` is `all`, `top`, `quick` or a list such as `22,80,8000-8100`. `--id` names the run |
| `run` | `--scope` (required), `--policy`, `--profile`, `--tcp-ports`, `--id`, `--rounds`, `--template` | `init`, then every stage, then the report |
| `resume` | `--rounds`, `--template` | Carry on an interrupted run, skipping what finished |

Stages:

| Command | Options | What it does |
|---|---|---|
| `recon` | | Subdomains and DNS checks for the scope's `domains` |
| `discover` | `--tcp-only`, `--udp-only`, `--resume` | nmap discovery. `--resume` skips batches already done |
| `probe` | `--only`, `--force`, `--skip-nuclei` | nuclei and the per-service probes. `--only NAME` (repeatable) restricts to one probe, `--force` repeats finished ones, `--skip-nuclei` leaves nuclei out and records a gap |
| `chase` | `--lead`, `--kind`, `--rounds` | Resolve follow-ups. `--lead ID` and `--kind KIND` (both repeatable) pick which. `--rounds` is how many times new leads are re-queued, default 2 |
| `screenshot` | `--force`, `--list` | Capture web pages. `--force` recaptures, `--list` shows what is on record and captures nothing |
| `enrich` | | Rank findings by KEV and EPSS, tag CDN hosts |
| `analyse` | | Model-written notes on findings. Exits 2 when `llm.enabled` is false |
| `report` | `--template` | Write `report.md`, `report.json` and the `report/` vault |

Reading and recording:

| Command | Options | What it does |
|---|---|---|
| `status` | | Stages done, counts, warnings |
| `hosts` | | Hosts found |
| `services` | `--web-only` | Open services |
| `findings` | `--severity`, `--review-only` | Findings. `--severity` is the minimum to show |
| `show` | `--finding` (required) | One finding in full |
| `leads` | `--status` | Follow-ups: `open` (default), `done`, `skipped`, `failed` or `all` |
| `gaps` | | Coverage gaps: what was not checked, and why |
| `diff` | `old`, `new`, `--no-write` | Compare two runs. Writes `diff.md` and `diff.json` into the newer one unless `--no-write` |
| `export` | `--out` | Write the run's state as JSON files. Default `<run>/export` |
| `note` | `--title` (required), `--severity`, `--host`, `--port`, `--proto`, `--description`, `--evidence`, `--recommendation`, `--reference`, `--tag`, `--source`, `--confidence`, `--review`, `--review-reason` | Record a finding from your own analysis. `--source` says who concluded it (default `analyst`), `--confidence` is `firm` or `tentative`, `--review` puts it in the review queue. `--reference` and `--tag` repeat |
| `resolve` | `--lead` (required), `--status`, `--note` | Close a follow-up by hand: `done` (default), `open`, `skipped` or `failed` |

## Environment variables

| Variable | Meaning |
|---|---|
| `EXTSCAN_OFFLINE` | Set to anything to turn the `enrich` downloads off. The tests set it |
| `ANTHROPIC_API_KEY` | Anthropic API key. `ANTHROPIC_AUTH_TOKEN` or an `ant auth login` profile also work |
| `ANTHROPIC_AUTH_TOKEN` | Anthropic API bearer token, instead of a key |
| `AWS_REGION` | Bedrock region when `llm.aws_region` is empty |
| `AWS_DEFAULT_REGION` | Used when `AWS_REGION` is also unset. Other AWS credential variables work as usual |
| `ANTHROPIC_FOUNDRY_API_KEY` | Azure Foundry API key |
| `ANTHROPIC_FOUNDRY_RESOURCE` | Foundry resource name when `llm.azure_resource` is empty |
| `ANTHROPIC_FOUNDRY_BASE_URL` | Foundry endpoint when `llm.base_url` is empty. It wins over a resource name |

`http_proxy` and the other proxy variables are ignored unless
`http.use_system_proxy` is `true`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Done. For `run` and `resume`: no serious coverage gap |
| `1` | Aborted because nearly everything failed, which points at this machine's network. Also `doctor` without nmap, `show` or `resolve` with an unknown id, `analyse` when no model could be reached |
| `2` | Refused or misconfigured: scope, policy, report template, damaged run state, a file not found |
| `3` | `run` or `resume` finished and wrote the report, with at least one serious coverage gap |
| `130` | Interrupted. State is on disk; `extscan resume <run>` |
