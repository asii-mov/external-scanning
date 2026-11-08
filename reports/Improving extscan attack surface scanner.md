# Fix extscan's broken promises, then chase the edge

extscan's biggest weakness is not missing coverage. Several confirmed defects break the three rules the project is built on, and they should be fixed before any new feature. Setting `allow_intrusive: true` in a policy file drops every nuclei exclusion, credential templates included, although the README calls "no credential testing" not configurable away (`extscan/tools/nuclei.py:39-40`). Setting `chunk_size: 0` stops the exclude list reaching nmap, so excluded hosts get scanned (`extscan/tools/nmap.py:28-32`, `:319-320`). Network failures in probes and chase are recorded as info findings or finished leads, not as coverage gaps, so a VPN drop mid-scan produces a clean-looking report that `resume` will not retry. Nuclei's default skipping of hosts after 30 errors goes unrecorded. Unknown top-level policy keys are silently ignored, so `examples/policy.gentle.json` runs with 8 workers, not 3 (`extscan/policy.py:279-281`). Once those are fixed, the threat data points to one coverage priority: find edge appliances (VPNs, firewalls, gateways), identify product and version, and map them to CISA's Known Exploited Vulnerabilities (KEV) catalog. Exploitation of internet-facing software is now the top initial-access vector in both Verizon's and Mandiant's 2026 data, at about a third of breaches. On reporting, a stable finding key comes first, because run diffing, KEV/EPSS ranking, dispute records and SIEM exports all depend on it. extscan's first-class coverage-gap accounting has no equivalent in any open-source recon framework surveyed. It is the tool's differentiator and worth protecting before anything is added.

## The plan: eleven rule fixes ahead of any new feature

The table is the recommended order. Tier (a) items break a rule written in `CLAUDE.md` or `README.md`. Tier (b) items add coverage, ranked by threat data and how safely each can be detected. Tier (c) items improve reporting and integration. The effort labels are my own estimates: S is under a day, M is a few days, L is a week or more. Each tier (a) fix fits the project's existing pattern of a unit test in `tests/test_coverage_gaps.py` or `tests/test_safety_invariants.py`, plus a fuzz-corpus entry where the fuzzer can reach it.

| # | Item | Where | Effort |
|---|---|---|---|
| **A1** | `allow_intrusive` removes credential and DoS exclusions; `extra_args`, `templates`, `include_tags` and `nmap.scripts` are unvalidated | `extscan/tools/nuclei.py:39-49`, `extscan/tools/nmap.py:55-67` | S |
| **A2** | Exclude list never reaches nmap when `chunk_size <= 0` | `extscan/tools/nmap.py:28-32`, `:319-320`; `extscan/policy.py:267-278` | S |
| **A3** | Probe and chase network failures become info findings or "done" leads, with no `Degradation` and no retry | `extscan/probes.py:97-104`, `:263-264`, `:318-325`; `extscan/chase.py:653-664`; `extscan/pipeline.py:404-410`, `:468-517` | M |
| **A4** | Nuclei drops hosts after 30 errors (`-mhe` default) and exits cleanly; no `-nmhe`, nothing parsed | `extscan/tools/nuclei.py:25-50` | S |
| **A5** | Checkpoints keyed by chunk index, so resume after a scope or `chunk_size` change skips unscanned hosts | `extscan/pipeline.py:98-101`, `:136` | S |
| **A6** | Top-level policy keys other than three are silently ignored (`max_workers`, `max_lead_attempts`, typos) | `extscan/policy.py:279-281` | S |
| **A7** | `allow_hostnames` trusts DNS at connect time | `extscan/scope.py:198-209`, `extscan/tools/net.py:91-106` | M |
| **A8** | Testing window checked only at stage start | `extscan/pipeline.py:178`, `:98-170` | S |
| **A9** | Silent losses: over-depth leads stay open, leads past 500 dropped, corrupt `findings.json` read as empty, dead `CircuitOpen` branch | `extscan/pipeline.py:446`, `:477-491`; `extscan/store.py:76-83`, `:173-184` | S |
| **A10** | Default NSE selection admits `vuln` scripts that are also `intrusive`/`exploit` (suspected) | `extscan/tools/nmap.py:35-38`, `extscan/policy.py:45-52` | S |
| **A11** | Scope hygiene: `_INTERNAL_NETS` gaps, IPv6 /64 hangs at load, unresolved `source_path`, browser non-HTTP egress (suspected) | `extscan/scope.py:33-45`, `:136`, `:157-179`; `extscan/screenshots.py:147`, `:221-229` | M |
| **B1** | Bump nuclei pin 3.4.10 → 3.11.x (2026 template-engine CVE fixes) | `scripts/cloud-setup.sh:12-17` | S |
| **B2** | Edge-appliance inventory with product, version and KEV mapping | new probe + report section | L |
| **B3** | Remote-access and management-interface posture (RDP NLA, SSH auth methods, BMC/IPMI, BOD 23-02 language) | `extscan/probes.py:428-521` | M |
| **B4** | ssh-audit and testssl.sh as optional tools with safety-pinned argv; SNI and hostname match in the TLS probe | `extscan/probes.py:505-521`, `extscan/tools/net.py:151`, `:224` | M |
| **B5** | Takeover confirmation fingerprints; email posture (SPF, DMARC, MTA-STS) | `extscan/tools/dns.py` | M |
| **B6** | Read-only DevOps and AI-endpoint checks; WAF/CDN detection as a coverage gap; web fingerprint pack | `extscan/probes.py` | M |
| **C1** | Stable `issue_key` independent of title wording; cross-source merge | `extscan/models.py:131-133` | S |
| **C2** | `extscan diff`, plus a suppress/dispute record that survives re-rendering | `extscan/cli.py`, `extscan/store.py:156-164` | M |
| **C3** | KEV/EPSS enrichment, CVSS with version label, indicative BOD 26-04 tier | `extscan/models.py:110-133` | M |
| **C4** | Exports: OCSF 2002, DefectDojo generic, SARIF; leads in `report.json` | `extscan/report.py:323-336` | M |
| **C5** | Audit trail: log HTTP/DNS/SNMP requests, hash manifest, source IP, effective policy per stage | `extscan/runner.py:431-435`, `extscan/cli.py:52-62` | M |

The rest of this report gives the evidence for each row and the constraints that shape the fix.

## (a) Eleven confirmed or suspected defects break extscan's own rules

The codebase audit read the code at commit `aedf542` and ran offline Python checks that sent no packets. Items marked CONFIRMED were verified that way. SUSPECTED items were inferred from the code and knowledge of the external tool, and need a test before acting. The coordinator independently re-read A1, A6 and the nuclei pin and confirmed them. I spot-checked A2, A3's `http_fingerprint` path and A7's `contains()` against the current tree, and they match.

### "No credential testing" can be configured away in one line

The README promises that no credential testing is "not configurable away" (`README.md:250-257`). The nuclei argv builder contradicts it: `if not p.allow_intrusive and p.exclude_tags:` means **one `allow_intrusive: true` drops the whole exclude list, including `default-login`, `default-logins`, `brute-force`, `creds-stuffing` and `dos`** (`extscan/tools/nuclei.py:39-40`, CONFIRMED). The same builder passes `include_tags`, `templates` and `extra_args` through unvalidated, and nmap does the same with `extra_args` and `scripts`. A policy file can therefore add `-tags default-login` or `--script brute` (`extscan/tools/nuclei.py:41-49`, `extscan/tools/nmap.py:55-67`, CONFIRMED). The safety tests check the strings in the built-in profiles only. They do not check the argv that a `Policy.from_dict` overlay produces (`tests/test_safety_invariants.py:100-138`).

The fix is to split the exclusions into two sets. Credential and DoS tags are appended unconditionally. Only a narrower "intrusive" set is controlled by `allow_intrusive`. `extra_args`, `templates`, `include_tags` and `nmap.scripts` should be validated against a deny-list (`-tags`/`-t` naming credential tags, `--script` naming `brute` or `dos`). The safety invariants then belong on the effective argv for any loaded policy, not on the default strings. AWS's testing policy gives the outside justification: "Tools with DoS capability must be able to disable that capability," and login and API request flooding is prohibited ([AWS Penetration Testing](https://aws.amazon.com/security/penetration-testing/)).

A10 is related but SUSPECTED. The default NSE expression is `(default or safe or vuln) and not (dos or external or http-slowloris-check)` (`extscan/tools/nmap.py:35-38`, `extscan/policy.py:45-52`). It does not exclude `intrusive`, `exploit`, `brute` or `malware`. From NSE metadata (nmap was not installed, so this is unverified), `vuln` scripts that are also intrusive or exploit include `http-vuln-cve2014-3704`, whose documented behaviour injects an admin user, along with `http-shellshock` and `smb-vuln-cve-2017-7494`. Run `nmap --script-help "vuln and (intrusive or exploit)"` first. If the list is non-empty, add those categories to `exclude_scripts` or switch the selection to `vuln and safe`. The current safety test only asserts that the substrings are absent from `policy.nmap.scripts` (`tests/test_safety_invariants.py:134-138`). That would miss this.

### Scope is enforced per request, except in four places

The per-request scope checks are strong: off-scope redirects are refused, the DNS scope gate allows QUERY only, and a host name never unlocks its zone. Four paths get around them.

First, **`chunk_size <= 0` makes `chunk_targets` return `[scope.targets]`**. `_targets_for` then sees a non-None list and never calls `nmap_target_args()`, so `--exclude` is never passed (`extscan/tools/nmap.py:28-32`, `:319-320`, CONFIRMED offline with a /29 and one excluded host). `parse_xml` drops the excluded host's results afterwards, but the packets have already gone out. Policy loading accepts `chunk_size: 0` (`extscan/policy.py:267-278`). Reject values below 1 and always pass `--exclude`.

Second, **`Scope.contains` returns True for any name in `allow_hostnames` without resolving it**, and urllib resolves at connect time (`extscan/scope.py:198-209`, `extscan/tools/net.py:91-106`, CONFIRMED). A listed name that resolves or is rebound to an out-of-scope or internal address gets fetched. This contradicts recon's own rule that a name is scannable only if all its addresses are in targets (`extscan/tools/subdomains.py:187`), and the example scope ships `allow_hostnames`. Resolve the name, require every address to be in scope and not excluded or internal, then connect to the pinned IP with the name in the Host header and SNI.

Third, **the testing window is checked once per stage** (`extscan/pipeline.py:178`). A discover stage can run many chunks, each allowed 7,200 s (21,600 s on `thorough`), well past `window_end` (`extscan/policy.py:56`, `:246`, CONFIRMED). Check the window before each chunk, probe job and lead. Cap each subprocess timeout at `window_end − now`, and record a `Degradation` for work cut off by the window.

Fourth, the smaller hygiene items. `_INTERNAL_NETS` omits `0.0.0.0/8`, multicast, `240.0.0.0/4`, `::ffff:0:0/96`, `64:ff9b::/96` and `2002::/16`, so `is_internal_address("::ffff:127.0.0.1")` returns False (`extscan/scope.py:33-45`, CONFIRMED). An IPv6 /64 target hangs `Scope.validate` because it iterates every address before comparing with `max_hosts` (`extscan/scope.py:157-179`, CONFIRMED). `source_path` is stored unresolved, so a later stage run from another directory can load a different `scope.json` (`extscan/scope.py:136`, `extscan/cli.py:39-49`, CONFIRMED). `net.hosts()` drops network and broadcast addresses that `contains()` treats as in scope (`extscan/scope.py:171-179`). The screenshot guard sees only requests routed through Playwright's `context.route`. WebSocket, WebRTC/STUN and DNS prefetch may bypass it (`extscan/screenshots.py:147`, `:221-229`). That last item is SUSPECTED and untested, because Chromium is not installed and the browser scope test skipped. Routing all browser egress through a local scope-enforcing proxy would close it regardless.

### "Reduced coverage must never look clean" fails on ordinary network errors

This is the most consequential category, because it fails silently. **`http_fingerprint` turns a connection failure into an info finding ("did not answer cleanly") and returns normally**, so the pipeline marks the service probed and records no gap. Path checks `continue` on `status == 0`, and a TLS handshake failure is also just an info finding (`extscan/probes.py:97-104`, `:263-264`, `:318-325`; `extscan/pipeline.py:404-410`, CONFIRMED). Chase handlers return notes such as "no response: …", `chase()` catches every exception into a "handler error" note, and the pipeline marks any lead with a note `done` or `failed` without a `Degradation` (`extscan/chase.py:359-360`, `:443-444`, `:520-521`, `:653-664`; `extscan/pipeline.py:468-517`). The `retry`/`max_lead_attempts`/abandon path is therefore effectively unreachable for network failures, and no test covers "no response". The vault hides these leads because it lists only `status != "done"` (`extscan/vault.py:662-721`). The probe stage also has no `AbortThreshold`, although discover and chase do (`extscan/pipeline.py:96`, `:438`).

The fix: have probes and handlers return an explicit failure status. Record a `Degradation`, leave the service or lead unmarked so `resume` retries it, and add an abort threshold to probe. The existing fuzzer targets tool-process failures, not HTTP-level ones, so it would not have caught this (`tests/fuzz_failures.py`). Extending it to inject `status == 0` responses is the natural regression guard.

**Nuclei's host skipping is the same leak in an external tool.** Its default `-max-host-error 30` drops a host after 30 errors, and v3.10.0 added a hosterrors cache under which "hosts that consistently time out are skipped" ([nuclei README](https://github.com/projectdiscovery/nuclei/blob/dev/README.md), [nuclei releases](https://github.com/projectdiscovery/nuclei/releases)). extscan passes no `-mhe` or `-nmhe` and parses only JSONL results (`extscan/tools/nuclei.py:25-50`). A rate-limiting host can silently get partial template coverage. Either pass `-nmhe` and accept slower scans, or set a known `-mhe`, run with `-stats-json`, and turn skipped hosts into a `Degradation`. The scan-time cost of `-nmhe` is unmeasured.

Smaller silent losses round this out. Leads deeper than `max_lead_depth` stay `open` forever with no gap. Leads past `max_leads_per_run` (500) are dropped by `add_leads` (`extscan/pipeline.py:446`, `extscan/store.py:173-184`). `Store._read` returns `[]` on `JSONDecodeError`, so a corrupted `findings.json` reads as "no findings" and the next write overwrites it (`extscan/store.py:76-83`, `:156-164`). The `except CircuitOpen` branch that would record a serious LLM gap is dead, because `LLMClient.analyse` swallows the exception (`extscan/pipeline.py:477-491`, `extscan/llm/__init__.py:160-162`). Its remedy text also points at a `chase --resume` flag that does not exist (`extscan/cli.py:563-570`). It is SUSPECTED that if nmap fails to start, a stale `raw/nmap-<label>.xml` from an earlier attempt is parsed and checkpointed as success (`extscan/tools/nmap.py:336-355`, `extscan/runner.py:417-419`).

### Resume and policy loading undermine what the README endorses

The README says to "change the policy, and carry on," and `_scope_for` accepts that scope can change mid-engagement (`README.md:24-27`). But **checkpoints are keyed `chunk-{index:04d}`, not by which hosts the chunk held** (`extscan/pipeline.py:98-101`, `:136`, CONFIRMED). Suppose chunks 1-2 complete at `chunk_size` 16 and the run resumes at 32. Chunks 1-2 now hold hosts 1-64, and hosts 33-64 are skipped with no gap. Key checkpoints by a hash of the sorted host list.

**`Policy.from_dict` copies only `max_lead_depth`, `max_leads_per_run` and `stop_on_tool_error` from the top level**, while section keys are validated strictly (`extscan/policy.py:279-281`, CONFIRMED). So `"max_workers": 3` in `examples/policy.gentle.json` is ignored, the loaded value stays 8, and a typo like `max_wrokers` passes silently. `max_lead_attempts` cannot be loaded at all (`extscan/policy.py:228`). `stop_on_tool_error` is loaded but never read (`extscan/policy.py:227`). Raise on unknown top-level keys, as the sections already do. Two related issues: `_policy_for` suppresses `ValueError`/`KeyError` and falls back to profile defaults, and a `--policy` override on a later stage is never written to `run.json`, so the report's methodology shows the init-time policy (`extscan/cli.py:52-62`).

### Accuracy defects that erode trust in the report

These don't break a stated rule, but an auditor will notice them.

`/actuator/heapdump` (critical) can never be a hit. The actuator branch requires JSON, and a heap dump is binary HPROF (`extscan/probes.py:177-178`, `:245-246`).

GraphQL introspection is reported as enabled whenever the body contains `"data"` or `"__schema"`, which includes `{"data":null,"errors":[…]}` (`extscan/chase.py:362-403`).

`chase_api_endpoint` confirms any 2xx JSON as an unauthenticated API endpoint, including `200 {"error":"unauthorized"}` (`extscan/chase.py:504-562`).

The soft-404 fallback matches substrings with no random-path baseline (`extscan/probes.py:225-228`, `:249`).

TFTP sits in the TCP exposure table rather than the UDP one (`extscan/probes.py:430`, `:461-471`).

`X-Frame-Options` is flagged missing even when CSP `frame-ancestors` is set (`extscan/probes.py:77`, `:145`).

NSE output reading "State: VULNERABLE" maps to info with no review flag unless the script is one of 15 named entries (`extscan/tools/nmap.py:217-273`). This one comes close to the coverage rule: a real vulnerability that is under-rated looks clean in a severity-sorted report. At minimum, any `vuln`-category output containing `VULNERABLE` should be medium and `review_required`.

## (b) Edge appliances are where a third of breaches start, and extscan cannot name them

### The threat data converges on internet-facing edge software

**Exploiting vulnerabilities became the top initial-access vector in the 2026 Verizon DBIR for the first time, at 31%, up from 20%.** Credential abuse fell to 13% as the first vector but appears somewhere in 39% of breaches ([watchTowr](https://watchtowr.com/resources/verizon-dbir-2026-vulnerability-exploitation/), [SecurityInfoWatch](https://www.securityinfowatch.com/cybersecurity/news/55378754/verizon-dbir-vulnerability-exploitation-surpasses-stolen-credentials-as-top-breach-entry-point)). One secondary source gives 36%. **Mandiant's M-Trends 2026 puts exploits at 32%, the top vector for the sixth straight year.** It estimates the mean time to exploit at −7 days, meaning exploitation before a patch exists ([Google Cloud M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)). The products being exploited are edge products. In the 2025 DBIR, edge devices and VPNs made up 22% of exploitation breaches, up from 3% ([Tenable](https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025)). Some blogs misattribute that figure to the 2026 report. M-Trends 2025's four most exploited CVEs were all in PAN-OS GlobalProtect, Ivanti Connect Secure, Ivanti Policy Secure and Fortinet FortiClient EMS ([GreyNoise citing M-Trends](https://www.greynoise.io/blog/2026-greynoise-state-of-the-edge-report-where-attacks-concentrate-defenses-fall-short)). VulnCheck found network edge devices were the most targeted technology in 2025, and 28.96% of KEVs were exploited on or before disclosure day ([VulnCheck 2026 report](https://wwv.vulncheck.com/hubfs/Research/2026-StateofExploitation.pdf?hsLang=en); summary only, PDF not fetched). GreyNoise logged 16.7 million sessions against GlobalProtect in H2 2025, more than 3.5 times Cisco and Fortinet combined ([GreyNoise](https://www.greynoise.io/blog/2026-greynoise-state-of-the-edge-report-where-attacks-concentrate-defenses-fall-short)). Patching lags: **only 26% of KEV vulnerabilities were fully remediated, with a median of 43 days** ([watchTowr](https://watchtowr.com/resources/verizon-dbir-2026-vulnerability-exploitation/)).

A scanner cannot beat a −7-day mean time to exploit. What it can do is produce an accurate inventory ("Ivanti Connect Secure 22.x on 203.0.113.10"), so the client can act the day an advisory drops. A grep of `extscan/` finds **no Fortinet, Ivanti, Citrix, Palo Alto or SonicWall logic, and no KEV mapping**. RDP and SMB get only a port-number finding. This is the largest gap between extscan's coverage and current threats.

### B1–B2: refresh nuclei, then build an edge inventory on data already collected

**B1 should go first because it is cheap and fixes security bugs.** `scripts/cloud-setup.sh:12` pins nuclei 3.4.10 with templates 10.2.7. Current releases are nuclei v3.11.1 and templates v10.5.1. Nuclei v3.8.0 (April 2026) fixed CVE-2026-41646 (JS `require` ignored `allow-local-file-access`) and CVE-2026-41645 (expressions could evaluate non-template content) ([nuclei releases](https://github.com/projectdiscovery/nuclei/releases)). Both matter for a tool that feeds target-controlled content to nuclei. Re-capture `tests/fixtures/lab-run` after the bump. Three related cleanups: `doctor` hints say `nuclei@latest` and `amass@master`, contrary to the pinning (`extscan/runner.py:466-496`); the setup script hard-codes `linux_amd64`; and v3.11.0 requires custom `javascript:` templates to be signed, which matters only if extscan ships its own.

**B2, the edge inventory, is mostly aggregation, not new probing.** The templates repo has 1,496 KEV-tagged templates, 3,587 CVE templates and 1,365 `panel` templates ([nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)). nmap CPEs are already parsed into `Service.cpe` but used only by the IIS matcher (`extscan/tools/nmap.py:207`, `extscan/tools/iis.py:78`). The work has three parts:

- A product-identification probe using login-page markers, cookies, redirect paths and default certificate subjects for FortiGate SSL-VPN, GlobalProtect, Ivanti Connect Secure, NetScaler Gateway, SonicWall SMA, Cisco ASA/FTD, Check Point and F5 BIG-IP.
- Version extraction where public research exists. Fox-IT's NetScaler triage tool reads the build from the gzip timestamp of a static language resource ([fox-it/citrix-netscaler-triage](https://www.github.com/fox-it/citrix-netscaler-triage)). No comparably documented remote method was found for FortiGate or Ivanti.
- An "edge inventory" report section joining product and version to a cached KEV JSON.

The specific URL path markers come from general knowledge, not from gathered sources. Check each against vendor documentation or the nuclei templates before coding. Microsoft Defender EASM labels a CVE match "Potential" when the version is hidden ([MS Learn](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-dashboards)). extscan already has the equivalent in `confidence="tentative"` and `review_required`, and every version-inferred CVE match should use them. ssh-audit removed version-based CVE mapping in v3.3.0 as "wildly inaccurate" ([ssh-audit](https://github.com/jtesta/ssh-audit)). Verifying templates should outrank version guesses, and that is also why the `vulners` NSE script should stay excluded.

### B3: remote-access and management surfaces, without touching a credential

Credential-based entry is the other main route. Sophos found "external remote services" with valid accounts in 56% of its 2024 IR/MDR cases ([Sophos](https://www.sophos.com/en-gb/press/press-releases/2025/04/sophos-report-56-sophos-ir-and-mdr-cases-adversaries-logged-instead)). extscan must not test credentials, but it can describe the login surface. Useful checks:

- RDP: whether NLA/CredSSP is enforced (nmap `rdp-enum-encryption`).
- SSH: whether the server offers `password` authentication (`ssh-auth-methods`, pre-auth, no guessing).
- SSH host-key reuse across hosts.
- VPN login pages: whether they redirect to SAML/SSO (a hint that MFA is in place) or show a local form.

CISA BOD 23-02 requires federal agencies to remove internet-exposed management interfaces (routers, firewalls, VPN concentrators, load balancers, out-of-band server management), or put them behind a separate enforcement point, within 14 days ([CISA BOD 23-02](https://www.cisa.gov/news-events/directives/binding-operational-directive-23-02)). That is ready-made remediation text for BMC/iLO/iDRAC and IPMI (623/udp) findings.

Two structural fixes belong here. The `exposure` probe keys purely on port number, so Redis on 6380 is silent and a web app on 3389 is called "RDP" (`extscan/probes.py:428-502`). Key it on the nmap service name, with the port as a fallback. Several ports in `TCP_TOP` are discovered but have no probe or exposure row (`extscan/policy.py:16`): 4786 Smart Install, 8009 AJP, 5985/5986 WinRM, 8500 Consul, 9092 Kafka and 15672 RabbitMQ. The same applies to SMTP 25/587, IKE 500/4500, and ICS 502/102/47808.

### B4: specialist TLS and SSH audits, pinned to safe argv

The SSH probe only echoes nmap's banner (`extscan/probes.py:505-521`). **ssh-audit** is MIT-licensed, has "no dependencies", outputs JSON and audits KEX, host-key, cipher and MAC algorithms. It includes a Terrapin (CVE-2023-48795) test and warns about KEX without post-quantum protection ([ssh-audit](https://github.com/jtesta/ssh-audit)). Two of its defaults need care: a connection-rate test runs unless `--skip-rate-test` is passed, and the DHEat DoS test runs only with `--dheat`. Call it as an optional subprocess with fixed argv `-j --skip-rate-test`, record a `Degradation` when it is missing, and add a safety invariant asserting `--dheat` never appears.

**testssl.sh** should become the primary TLS audit, with sslscan as fallback. It covers ROBOT, Ticketbleed, DROWN, LOGJAM, SWEET32 and others, STARTTLS for 13 protocols including SMTP, IMAP, LDAP, PostgreSQL and MySQL, and an SSL Labs-style rating. It needs only bash and openssl ([testssl.sh](https://testssl.sh/)). Keep `--phone-out` off, because it contacts third-party OCSP, CRL and compromised-key services. The built-in TLS probe has its own gaps:

- It sends no SNI (`server_hostname=None`, `extscan/tools/net.py:224`), so SNI-selected certificates are invisible.
- `TlsInfo.hostname_matches` is declared but never set (`extscan/tools/net.py:151`).
- It has no "expires soon" warning (`extscan/probes.py:346-355`).
- STARTTLS mail ports get no TLS inspection at all (`extscan/tools/net.py:220-233`).

Fixing SNI ties into roadmap item 2, virtual-host enumeration. It must keep the roadmap's catch: a name that resolves elsewhere is out of scope even if an in-scope IP serves it.

### B5: dangling-DNS confirmation and email posture

The DNS side of takeover detection is done. The roadmap's remaining step is provider fingerprint matching, and it has real-world urgency: a longitudinal study found **20,904 hijacked dangling records** hosting malicious content across 12 cloud platforms ([arXiv 2403.19368](https://arxiv.org/abs/2403.19368)). Vendor can-i-take-over-xyz's CI-verified `fingerprints.json` as data, then make one GET to the in-scope name to look for the "unclaimed" marker ([can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)). The data's licence was not checked. Detection is fine, but claiming the resource is not: AWS prohibits "S3 bucket takeover and subdomain takeover" outright ([AWS Penetration Testing](https://aws.amazon.com/security/penetration-testing/)).

Email posture (roadmap item 7) will produce findings on most engagements. EasyDMARC found 52.2% of the top 1.8 million domains have no DMARC record, and only 7.7% use `p=reject` ([EasyDMARC](https://easydmarc.com/blog/?p=52716)). The stdlib DNS client in `extscan/tools/dns.py` can already do SPF (gating each include on DNS scope, per the roadmap's catch), DMARC, MTA-STS, TLS-RPT and common-selector DKIM lookups.

### B6: smaller additions that fit stdlib and read-only

Read-only checks for DevOps and AI services: Kubernetes `/version` and anonymous `/api`, Docker registry `/v2/_catalog`, Ollama `/api/tags`, OpenAI-compatible `/v1/models`, and anonymous Prometheus/Grafana. GreyNoise counted 91,403 malicious sessions targeting AI/LLM infrastructure in H2 2025 ([GreyNoise](https://www.greynoise.io/blog/2026-greynoise-state-of-the-edge-report-where-attacks-concentrate-defenses-fall-short)).

WAF/CDN detection, framed as a coverage signal rather than a finding. Vendor provider ranges in the style of cdncheck ([cdncheck](https://github.com/projectdiscovery/cdncheck)), add block-page and 429 heuristics, and record a `Degradation` ("results behind a WAF may be incomplete"). This is the coverage rule applied to a cause no surveyed tool accounts for.

A web fingerprint pack:

- A favicon mmh3 hash. Pure-Python MurmurHash3 is small. That it matches Shodan's convention is unverified.
- A matcher over the Wappalyzer-format JSON that enthec/webappanalyzer maintains since Wappalyzer went closed ([enthec/webappanalyzer](https://github.com/enthec/webappanalyzer)). Licence unchecked.
- Body simhash grouping, so the vault can say "these 14 services serve the same default page".

The HTTP probe checks only the presence of four security headers, and only on TLS services (`extscan/probes.py:73-78`, `:144-155`). It needs cookie flags, CORS, HSTS quality and plain-HTTP coverage.

IPv6 is broken: the nmap argv never adds `-6` (`extscan/tools/nmap.py:41-69`, CONFIRMED offline). Fix it together with the /64 hang in A11.

### What not to build, even though competitors do

The open-source frameworks surveyed optimise for breadth and leave safety to the operator. reconFTW chains password spraying, sqlmap and commix ([reconFTW](https://github.com/six2dez/reconftw)). BBOT 3.0 added lightfuzz with OOB SSRF ([BBOT 3.0](https://blog.blacklanternsecurity.com/p/bbot-30)). Several popular options send target data to third parties: nuclei `-ai` and `-dashboard` (ProjectDiscovery cloud), naabu `-passive` (Shodan InternetDB), the nmap `vulners` script, trufflehog's default live verification of found secrets, and testssl `--phone-out` ([nuclei README](https://github.com/projectdiscovery/nuclei/blob/dev/README.md), [naabu](https://github.com/projectdiscovery/naabu), [trufflehog](https://github.com/trufflesecurity/trufflehog)). Each should be blocked by a safety-invariant test, as interactsh already is.

Cloud bucket brute-forcing (cloud_enum, S3Scanner), ffuf-style wordlists, alterx permutations and automatic ASN expansion all widen scope or volume beyond the signed scope file. At most, ASN or WHOIS pivots belong in the report as "possibly related assets; ask the client", the way Defender EASM uses a "Candidate" state ([MS Learn](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/what-is-discovery)). JA4S and JA4X fingerprints are under the FoxIO License 1.1, which requires an OEM licence for commercial services ([ja4plus](https://pypi.org/project/ja4plus/)), so an audit firm should prefer favicon and certificate-SPKI reuse.

Two ideas are worth borrowing as metadata rather than features. BBOT's `passive/active/loud/invasive` module flags could become a probe attribute, with a test asserting no `invasive` probe is registered. BBOT's seeds-versus-targets "scope distance" could become a provenance field per asset ([BBOT scanning docs](https://www.blacklanternsecurity.com/bbot/Stable/scanning/)).

## (c) A stable finding key unlocks diffing, KEV ranking and every export

### C1–C2: identity first, then diff and disputes

`Finding.id` hashes host, port, protocol, **title** and source (`extscan/models.py:131-133`), and titles embed volatile data such as page titles and operation counts (`extscan/probes.py:120`, `extscan/chase.py:229`). As a result, a reworded title reads as one issue resolved and another new, and the same Redis exposure becomes three findings: the `redis-info` NSE high, the exposure probe's "Redis reachable" critical, and a nuclei template (`extscan/tools/nmap.py:230`, `extscan/probes.py:450`). The TLS probe and sslscan also double-report deprecated protocols and expired or self-signed certificates (`extscan/tools/sslscan.py:238-247`). Add an `issue_key` built from host, port, protocol and a check identifier (a nuclei template ID, NSE script ID or probe check name), and merge sources that share it. SARIF calls the same idea `partialFingerprints`, a "stable value" for tracking a result over time ([OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)).

With that in place, `extscan diff` (roadmap item 5) can follow ScanCannon's coarse model: host:port new or gone, plus version changes ([ScanCannon](https://github.com/johnnyxmas/ScanCannon)). It should add one state that no surveyed tool has: **"not re-observed: coverage gap"**, distinct from "resolved". A finding whose check failed on the retest must stay open. That is extscan's coverage rule applied to remediation tracking. Commercially, change tracking is a headline feature: Defender EASM has an inventory-changes dashboard ([MS Learn](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-dashboards)), and ProjectDiscovery keeps drift monitoring in its paid cloud tier rather than the open-source CLIs ([PDCP](https://docs.projectdiscovery.io/cloud/introduction)).

Findings are add-only (`extscan/store.py:156-164`), and `resolve` applies only to leads. Add `extscan suppress|dispute <issue_key> --reason --evidence`, stored outside the regenerated report. That gives auditors the section the PCI ASV Program Guide requires under "Exceptions, False Positives, or Compensating Controls" ([ASV Program Guide v4.0r2, unofficial copy](https://www.scribd.com/document/686715606/ASV-Program-Guide-v4-0r2)). It also lets the review queue record the auditor's decision, reviewer and date.

### C3: rank by exploitation evidence, not static severity

Severity is a static per-check string, with no CVSS, EPSS, KEV or CWE fields (`extscan/models.py:15`, `:110-133`). The current prioritisation model layers exploitation evidence on top of severity:

- **KEV.** CISA's catalog is "the authoritative source of vulnerabilities that have been exploited in the wild," with a ransomware-use flag and a JSON feed ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).
- **EPSS.** EPSS v4 (March 2025) publishes a daily 30-day exploitation probability and percentile for every CVE ([FIRST EPSS](https://www.first.org/epss/)).
- **BOD 26-04.** CISA's directive, reportedly issued 10 June 2026, replaces BOD 22-01 and 19-02. It sets remediation tiers from four variables (internet-exposed, KEV-listed, automatable, technical impact) instead of CVSS ([CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-bod-26-04-risk-based-vulnerability-re/)). The primary text was not fetched, so treat the exact 3/14/60-day tiers as unverified. Everything extscan reports is internet-exposed by definition, so an "indicative BOD 26-04 tier" column needs only KEV status plus CISA Vulnrichment's automatable and impact values.
- **CVSS.** Where shown, it must carry its version and nomenclature label, for example `CVSS-B 9.3` ([FIRST CVSS v4.0](https://www.first.org/cvss/v4-0/specification-document)).

Three constraints shape this. First, enrichment needs network access to cisa.gov and FIRST. Prefer whole-catalogue downloads, cached and dated, over per-CVE queries, so nothing engagement-specific leaves the box. Record the snapshot date in `report.json`, and record a `Degradation` ("exploitability enrichment not performed") when the fetch fails. Second, the nuclei JSONL CVE field (`info.classification.cve-id`) is unverified; check it against `tests/fixtures/nuclei.jsonl`. Third, most extscan findings are misconfigurations without CVEs. For those, SSVC-style decision points (exploitation, automatable, technical impact) give one consistent priority language across CVE and non-CVE findings ([CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)).

A labelled "PCI ASV-style pre-check (not an ASV scan)" is a cheap add-on: per host, PASS, FAIL (CVSS ≥ 4.0 or an automatic-fail class such as an internet-reachable database) or INCOMPLETE when any `Degradation` is open. That last state mirrors the ASV rule that scan interference must be recorded as a failure ([ASV Program Guide, unofficial copy](https://www.scribd.com/document/686715606/ASV-Program-Guide-v4-0r2)). The guide's reported CVSS-version precedence (NVD v3.1 first) comes from a paywalled snippet and is unverified.

### C4: exports in the formats clients already ingest

The best integration targets are:

1. **OCSF Vulnerability Finding**, `class_uid` 2002, schema 1.9.0. Its `status_id` (New, In Progress, Suppressed, Resolved) maps directly onto the diff and dispute states ([OCSF schema](https://schema.ocsf.io/classes/vulnerability_finding)). AWS Security Hub and Security Lake ingest OCSF ([AWS](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ocsf.md)).
2. **DefectDojo Generic Findings import.** DefectDojo already parses Nmap, Nuclei, sslscan and SARIF natively ([DefectDojo parsers](https://docs.defectdojo.com/supported_tools/parsers/file/generic/)). The generic import keeps extscan's own findings, review questions and coverage gaps, which the raw-tool parsers would lose.
3. **SARIF**, as a secondary format with `baselineState` for diffing.

All three are plain JSON, so they fit stdlib. `report.json` also omits leads entirely (`extscan/report.py:323-336`), so unresolved follow-up work is invisible to any consumer. Add them.

### C5: an audit trail that matches the README's promise

The README says every command, exit code and timing is in `commands.jsonl` "so a client can reproduce any finding" (`README.md:295-297`). In fact only subprocesses are logged: HTTP requests from probes and chase, DNS queries and SNMP packets are not (`extscan/runner.py:431-435`). Treat this as a documentation promise to fix. Log every outbound request with timestamp, destination and the scope decision. Add:

- A SHA-256 manifest of raw outputs and reports.
- The scanning host's source IP and egress ASN, recorded at run start. AWS forwards abuse reports to testers ([AWS](https://aws.amazon.com/security/penetration-testing/)).
- A hash of the authorisation document in `scope.json`.
- The effective policy per stage, written to `run.json`.

Make the User-Agent configurable with an engagement reference and contact. It is currently hard-coded `extscan/0.1` while `__version__` is 0.2.0 (`extscan/policy.py:110`, `extscan/__init__.py:3`).

Methodology tags are cheap and auditor-friendly. Pin them to versions: WSTG test IDs in version-qualified form (`WSTG-v42-INFO-02`), as OWASP recommends ([OWASP WSTG](https://github.com/owasp/wstg)), and ATT&CK T1595/T1590/T1596 at content v20.1, whose TA0043 now has 12 techniques ([MITRE ATT&CK TA0043](https://attack.mitre.org/tactics/TA0043/)). Then add a "methodology coverage" table listing which phases ran, which were partial, and which were excluded by design, such as credential testing and DoS.

Finally, cut the noise. The lab run (1 host, 9 services) produced **168 findings, 42 review items and a 4,601-line `report.md`**. Every `http-*` NSE script with output is flagged `review_required`, which floods the queue with items like `http-date` and `http-useragent-tester` (`extscan/tools/nmap.py:262-270`, `tests/fixtures/lab-run/report.md:64-77`). Demote these to an appendix.

## Engineering debt that will surface on the first large estate

extscan is sized for a few hundred hosts (`max_hosts` defaults to 1024, `extscan/scope.py:106`), and several costs grow badly beyond that. **Nuclei re-runs against every web service on every `probe` or `resume`, even when all are already marked done.** A single timeout marks all of them unprobed, so the longest stage starts again from zero (`extscan/pipeline.py:332-366`). Chunk and checkpoint nuclei the way nmap is. The store rewrites whole JSON files on every mutation, `mark_probed` runs in a loop, and a fixed `.<name>.tmp` filename races when two processes touch one run, for example a user `probe` while `sudo discover` runs (`extscan/store.py:85-90`, `extscan/pipeline.py:408-410`). Batching writes, or moving to `sqlite3`, which is stdlib, fixes both. The probe pool has no per-host cap and no global rate limiter (`extscan/pipeline.py:380`, `extscan/probes.py:252-262`). urllib's timeout applies per socket operation, so a tarpit can pin workers indefinitely (`extscan/tools/net.py:106-107`, SUSPECTED). `Runner` drops partial stdout on timeout because `TimeoutExpired.stdout` is bytes (`extscan/runner.py:409-414`). `Store.open("latest")` picks the most recently modified run, not the newest (`extscan/store.py:57-64`). No benchmark exists beyond the one-host lab, so any timing for a large estate is extrapolation.

On the test side, the suite now has **485 tests, not the ~415 the docs claim**. Two lab tests fail in any environment with `HTTPS_PROXY` set, because plain `urlopen` honours the proxy and urllib's `no_proxy` matching ignores CIDR entries (`tests/test_lab.py:48-60`). Use a `ProxyHandler({})` opener, as `extscan/tools/net.py:75-80` already does. CI runs no fuzzer, coverage, type check or packaging step (`.github/workflows/tests.yml`). A coverage report alone would have flagged the dead `CircuitOpen` branch and the unread `stop_on_tool_error`. The open `todo.md` item (unprivileged TCP, then `sudo` UDP) also has a likely answer from code. JSON state survives via tmp-plus-replace, but root-owned leftover `.tmp` files and raw artefacts such as nmap `-oA` output and `dns-axfr-*.txt` cannot be overwritten by a later unprivileged pass (`extscan/store.py:262-268`, `extscan/tools/dns.py:753`). This is SUSPECTED and needs the real-host test the todo describes.

For the optional LLM layer, research supports keeping it conservative. A 2025 paper hijacked an AI pentest agent through content in scanned responses in **100% of 14 attack variants** ([arXiv 2508.21669](https://arxiv.org/abs/2508.21669v1)). The best rigorous result for LLM false-positive filtering removed about a third of false positives, and that was on SAST, not external scanning ([arXiv 2506.16899](https://arxiv.org/abs/2506.16899v1)). Any LLM triage should only demote findings to review, never delete them. It needs injection tests equivalent to the vault's hostile-text tests. Roadmap item 11's closed action allow-list is the right design.

## Conclusion

The surveyed open-source frameworks (BBOT, reconFTW, Osmedeus, Sn1per) and the commercial EASM platforms all win on breadth. None of them documents anything like extscan's rule that reduced coverage must never look clean. That rule is the reason a client can sign off on an extscan report, and the defects in tier (a) mean it currently holds only when tools fail as processes, not when the network fails, nuclei skips a host, or a policy file sets one flag. Fixing tier (a) is mostly small, test-first work. It should come before any new coverage, because every new probe added on top inherits the same silent-failure paths.

After that, the threat data favours depth over breadth. The products attackers exploit most, VPNs and firewalls, are few and well fingerprinted by templates extscan already runs, so the missing piece is aggregation into an edge inventory joined to KEV. A stable issue key is the one reporting change everything else depends on: diffing, disputes, BOD 26-04 tiers, OCSF and DefectDojo export. Its most distinctive output would be the diff state no surveyed tool offers, "not re-observed: coverage gap". That extends extscan's founding rule from a single run to remediation tracking, where an auditor needs it most.
