# extscan codebase audit: what it does, where it is weak, what to improve

Scope of this note: the internal view only (code, docs, tests at commit `aedf542`, 2026-11-08). Every claim cites a repo-relative `file:line`. "CONFIRMED" means verified by reading the code and, where marked, by running an offline Python check (no packets sent; scratch script `verify1.py` in the session scratchpad). "SUSPECTED" means inferred from code plus general knowledge of the external tool, not executed. No scanner was run and the lab was not started.

## 1. What the pipeline does end to end, and which services have probes

### Takeaway
extscan is a staged, disk-backed orchestrator: `init → recon → discover (nmap TCP+UDP, chunked) → probe (nuclei + 7 built-in probes) → chase (8 lead handlers) → screenshot → report (md/json/Obsidian vault)`. Depth exists for HTTP disclosure paths, OpenAPI/GraphQL, IIS, TLS, SNMP and DNS takeover/AXFR. Most other internet-facing protocols (SSH crypto, SMTP/STARTTLS, RDP, VPN/edge appliances, databases, SMB, FTP, DNS resolver behaviour, email auth records, IPv6) get only an nmap port/banner line plus a port-number "exposure" finding.

### Cited Findings
**Stages and orchestration**
- `run_all` order: doctor → recon (only if `scope.domains`) → discover → probe → chase → screenshot → report — [extscan/pipeline.py:629-639](extscan/pipeline.py)
- `init_run` checks the testing window and writes `run.json` with the scope summary and full policy — [extscan/pipeline.py:38-53](extscan/pipeline.py)
- Discover runs one nmap pass per kind in sequential chunks of `nmap.chunk_size` hosts (default 32), checkpointing each chunk, salvaging truncated XML, with an `AbortThreshold` at 100% failure — [extscan/pipeline.py:75-172](extscan/pipeline.py), [extscan/policy.py:57](extscan/policy.py), [extscan/tools/nmap.py:276-324](extscan/tools/nmap.py)
- TCP argv: `-sS` as root else `-sT`, `-sV --version-intensity 7`, `--script (default or safe or vuln) and not (dos or external or http-slowloris-check)`, `-T4`, `--open`, `-oA`, `-O` as root — [extscan/tools/nmap.py:41-69](extscan/tools/nmap.py), [extscan/policy.py:38-57](extscan/policy.py)
- UDP argv: `-sU -sV` (intensity ≤5) over 19 default ports, `default,safe` scripts; unprivileged runs record a "serious" coverage gap and print a `sudo .../extscan discover <run> --udp-only` command — [extscan/tools/nmap.py:72-85](extscan/tools/nmap.py), [extscan/policy.py:23](extscan/policy.py), [extscan/pipeline.py:184-210](extscan/pipeline.py), [extscan/runner.py:506-514](extscan/runner.py)
- After nmap, host names nmap reported for in-scope live hosts get CNAME/MX dangling-record checks — [extscan/pipeline.py:217-232](extscan/pipeline.py)
- Recon: crt.sh + subfinder (amass optional) passive enumeration, getaddrinfo resolution, split into in-scope (all addresses in targets) vs out-of-scope (reported, never touched); then per-domain DNS audit — [extscan/pipeline.py:235-289](extscan/pipeline.py), [extscan/tools/subdomains.py:157-197](extscan/tools/subdomains.py), [extscan/policy.py:154](extscan/policy.py)
- DNS checks implemented with a built-in stdlib DNS client: AXFR, NSEC walk (NSEC3 recognised, not cracked), dangling CNAME/MX/NS and lame delegation, host-name checks; sub-zones opt-in — [extscan/tools/dns.py:738-965](extscan/tools/dns.py), [extscan/policy.py:160-176](extscan/policy.py)
- Probe: nuclei once over all HTTP services, then a `ThreadPoolExecutor(max_workers=8)` over every (probe, service) pair from the registry — [extscan/pipeline.py:319-414](extscan/pipeline.py)
- Chase: up to `rounds` (default 2) passes over open leads with depth ≤ `max_lead_depth` (3), each wrapped in `retry` — [extscan/pipeline.py:421-525](extscan/pipeline.py)
- Screenshot: Playwright Chromium, root page of every TCP web service plus pages behind medium+ findings, every request scope-checked in a route guard — [extscan/screenshots.py:83-111](extscan/screenshots.py), [extscan/screenshots.py:156-245](extscan/screenshots.py)
- Report: triage → `report.md`, `report.json`, and an Obsidian vault in `report/` — [extscan/pipeline.py:603-626](extscan/pipeline.py)
- LLM (optional, off by default): only `analyse_openapi` is wired in, called from the OpenAPI chase handler — [extscan/chase.py:324-335](extscan/chase.py), [extscan/llm/analyst.py:128-155](extscan/llm/analyst.py)

**Built-in probe registry (7 probes)** — [extscan/probes.py:89-542](extscan/probes.py)
- `http_fingerprint` (all HTTP): root GET, title, 8 version-disclosing headers, 4 security headers (HSTS, CSP, XCTO, XFO) only on TLS services, body hints → leads, plus 22 disclosure paths with per-path soft-404 heuristics — [extscan/probes.py:73-169](extscan/probes.py), [extscan/probes.py:172-307](extscan/probes.py), [extscan/policy.py:79-102](extscan/policy.py)
- `tls` (TLS TCP): cert subject/issuer/validity/SANs via `openssl x509`, expired, self-signed (subject==issuer), TLS 1.0-1.3 support, legacy-version finding; untested versions become a `tls_detail` lead for testssl.sh — [extscan/probes.py:310-403](extscan/probes.py), [extscan/tools/net.py:212-298](extscan/tools/net.py)
- `snmp` (UDP 161/10161 or name snmp): v1/v2c GET with 11 community strings, built-in BER client — [extscan/probes.py:406-425](extscan/probes.py), [extscan/policy.py:118-127](extscan/policy.py)
- `exposure` (port-number table): 30 TCP ports and 7 UDP ports mapped to fixed severities — [extscan/probes.py:428-502](extscan/probes.py)
- `ssh` (port 22 or name ssh): records nmap's product/version only, info severity, review flag — [extscan/probes.py:505-521](extscan/probes.py)
- `iis` (IIS-looking HTTP): trace.axd/elmah.axd, WebDAV verbs via OPTIONS, 8.3 short-name oracle (2 requests), verbose errors, default content — [extscan/tools/iis.py:68-334](extscan/tools/iis.py)
- `sslscan` (TLS TCP): RC4/3DES/export, <128-bit, compression, insecure renegotiation, heartbleed, expired/self-signed/SHA-1/MD5 signature, key <2048 — [extscan/tools/sslscan.py:71-286](extscan/tools/sslscan.py)

**Chase handlers (8)** — [extscan/chase.py:641-650](extscan/chase.py)
- `openapi` (find spec, count ops, flag no-auth ops and writes, spawn `api_endpoint` leads for parameter-free GETs), `graphql` (one introspection POST), `git_exposure` (`/.git/config`, `/.git/HEAD` only), `web_paths`, `secret_file`, `api_endpoint` (GET only), `snmp_walk` (3 subtrees, 25 rows each), `tls_detail` (testssl.sh `--protocols`, output pasted as info) — [extscan/chase.py:132-638](extscan/chase.py)

**nmap NSE output → findings**: only 15 script IDs have a severity mapping (heartbleed, ms17-010, ftp-anon, nfs-showmount, smb-enum-shares, rdp-ntlm-info, snmp-*, mongodb/redis/memcached-info, elasticsearch); every other script output becomes an `info` finding — [extscan/tools/nmap.py:217-273](extscan/tools/nmap.py)

**Protocols/services with no dedicated probe (only nmap banner + possibly the port-table finding)**
- SSH: no KEX/cipher/MAC/host-key audit, no Terrapin (CVE-2023-48795) check, no auth-method listing; the probe only echoes nmap's banner — [extscan/probes.py:505-521](extscan/probes.py). nmap's `ssh2-enum-algos` (safe category) may run, but its output is unparsed and lands as an info finding — [extscan/tools/nmap.py:261-272](extscan/tools/nmap.py)
- SMTP/IMAP/POP3 STARTTLS: not in the TLS probe (it does an implicit-TLS `wrap_socket` only); port 25/587 not in the exposure table; no open-relay or VRFY/EXPN check — [extscan/tools/net.py:220-233](extscan/tools/net.py), [extscan/probes.py:428-459](extscan/probes.py)
- RDP, SMB, MSSQL, MySQL, Postgres, Oracle, VNC, Redis, MongoDB, Elasticsearch, Kubernetes, Docker: port-number finding only (no NLA, signing, SMBv1, anonymous-access or unauthenticated-read checks beyond what NSE happens to emit) — [extscan/probes.py:428-459](extscan/probes.py). The roadmap lists these as tier-2 item 10 — [docs/ROADMAP.md:162-178](docs/ROADMAP.md)
- VPN/edge appliances (Fortinet, Ivanti/Pulse, Citrix, Palo Alto GlobalProtect, Cisco ASA), IKE (500/4500 udp), OpenVPN, WinRM (5985/5986), LDAP/CLDAP, Kerberos, ICS (Modbus 502, S7 102, BACnet 47808), Cisco Smart Install 4786, AJP 8009, Java RMI 1099, etcd 2379, Consul 8500, ZooKeeper, Kafka, RabbitMQ: none in the exposure table, so absent from findings unless nuclei/NSE says something. Some of these ports are in `TCP_TOP` (4786, 8009, 5985, 5986, 8500, 9092, 15672) so they are discovered but get no probe — [extscan/policy.py:16](extscan/policy.py), [extscan/probes.py:428-471](extscan/probes.py)
- DNS service on in-scope hosts: no open-resolver/recursion check, no version.bind, no amplification check; DNS work is zone-centric only — [extscan/tools/dns.py:965](extscan/tools/dns.py), [extscan/policy.py:160-176](extscan/policy.py)
- Email posture (SPF/DKIM/DMARC/MTA-STS), CAA, DNSSEC validation: not implemented (roadmap item 7) — [docs/ROADMAP.md:105-115](docs/ROADMAP.md)
- HTTP headers: no cookie-flag (Secure/HttpOnly/SameSite), CORS, Referrer-Policy, Permissions-Policy, HSTS max-age/includeSubDomains, or CSP quality analysis; security headers checked only on TLS services and only for presence — [extscan/probes.py:73-78](extscan/probes.py), [extscan/probes.py:144-155](extscan/probes.py)
- HTTP methods / 403-bypass: not implemented (roadmap item 3) — [docs/ROADMAP.md:46-56](docs/ROADMAP.md)
- Virtual hosts / SNI: every service is addressed by IP (`base_url` uses `self.host`), and TLS inspection sends no SNI (`server_hostname=None`), so name-based vhosts and SNI-selected certs are invisible (roadmap item 2) — [extscan/models.py:92-100](extscan/models.py), [extscan/tools/net.py:224](extscan/tools/net.py), [docs/ROADMAP.md:33-44](docs/ROADMAP.md)
- Cloud storage / subdomain-takeover HTTP fingerprinting: DNS-only today; HTTP "unclaimed" fingerprint matching is listed as left-to-do — [docs/ROADMAP.md:86-103](docs/ROADMAP.md)
- IPv6: nmap argv never adds `-6` (CONFIRMED offline: argv for a `2001:db8::/120` scope has no `-6`), so IPv6 targets cannot be scanned correctly — [extscan/tools/nmap.py:41-69](extscan/tools/nmap.py)
- TLS probe computes no "expires soon" warning, and `TlsInfo.hostname_matches` is declared but never set anywhere — [extscan/probes.py:346-355](extscan/probes.py), [extscan/tools/net.py:151](extscan/tools/net.py)
- SNMP: v1/v2c only; no SNMPv3 engine-ID discovery (a read-only, unauthenticated info leak) — [extscan/policy.py:126](extscan/policy.py)

### Inferences
- The "service family" depth is concentrated on web/API exposure; the highest-volume real external findings in typical estates (SSH/TLS crypto hygiene, SMTP, RDP/SMB posture, edge appliances with KEV-listed CVEs) are covered only by nuclei's generic templates or NSE side output, both of which extscan maps to `info` unless named in a small table.
- The registry pattern ([extscan/probes.py:50-58](extscan/probes.py)) makes adding probes cheap, but `exposure` keys purely on port number, so a Redis on 6380 is silent and a web app on 3389 is called "RDP".

### Gaps
- Could not inspect what nuclei templates actually fire against each service type (nuclei not installed here); the lab-run fixture shows 48 nuclei findings for 5 web services — [tests/fixtures/lab-run/findings.json](tests/fixtures/lab-run/findings.json).
- Vault internals (1,024 lines) were skimmed, not audited line by line.

## 2. Open work already listed in todo.md and docs/ROADMAP.md

### Takeaway
`todo.md` has a single open item (verify the unprivileged-then-sudo UDP flow and root-owned files). The roadmap has 15 prioritised items in three tiers; items 1 (screenshots) and the DNS half of 6 are done. The roadmap puts vhost/SNI enumeration and run diffing at the top of what remains.

### Cited Findings
- todo.md "Open": test the TCP-as-user then `sudo .../extscan discover <run> --udp-only` flow on a real host; only a dry-run unit test covers the UDP pass clearing the gap; check whether sudo leaves root-owned files later stages cannot overwrite — [todo.md:61-69](todo.md)
- todo.md "Improve reporting" (vault, screenshots, narrative ordering, proof blocks, auditor view, tests) is all ticked done — [todo.md:1-59](todo.md)
- Roadmap tier 1 (highest value for effort) — [docs/ROADMAP.md:15-79](docs/ROADMAP.md):
  1. Screenshots — done. Catch: heavy Chromium dependency; keep images out of JSON.
  2. Virtual-host and SNI enumeration from cert SANs, subdomains, rDNS. Catch: a name resolving elsewhere is out of scope even if served by an in-scope IP; findings must say which name produced which response.
  3. HTTP method and auth-bypass checks (TRACE, OPTIONS, path-case/`X-Original-URL` 403→200). Catch: shades into exploitation; restrict to GET/OPTIONS/TRACE/HEAD and header variations.
  4. Certificate inventory and expiry tracking across the estate (shared certs, CAs, 30-day expiry). Catch: "none worth mentioning"; cheapest item.
  5. `extscan diff <old> <new>`. Catch: finding IDs hash host/port/title, so a reworded title reads as resolved+new.
- Tier 2 — [docs/ROADMAP.md:82-178](docs/ROADMAP.md):
  6. Cloud asset correlation: DNS side done; left: provider takeover fingerprints + one HTTP request; names from sub-zone AXFR/walk not yet fed into the takeover check. Catch: claiming a resource is not read-only.
  7. Email posture (SPF/DKIM/DMARC/MTA-STS) as new `CHECKS` rows in `dns.py`. Catch: SPF include-following and the 10-lookup limit, each include gated by DNS scope.
  8. Authenticated scanning. Catch: changes the risk profile; needs its own authorisation field.
  9. Rate-limit/WAF detection as coverage gaps. Catch: false positives on slow servers.
  10. Protocol probes: SMB, RDP, FTP/SFTP, DB banners, Kubernetes, Docker. Catch: temptation to authenticate.
- Tier 3 — [docs/ROADMAP.md:181-246](docs/ROADMAP.md): 11 agent-driven adaptive probing (closed allow-list action space; prompt-injection steering risk), 12 continuous monitoring (standing authorisation, hard stop on lapse), 13 cross-engagement findings DB (client data separation, retention), 14 report formats DOCX/ticketing (timebox), 15 distributed scanning (complexity).
- Deliberately not planned: exploitation/PoC, credential brute force/spraying, DoS, default active subdomain brute force, anything out of scope — [docs/ROADMAP.md:250-265](docs/ROADMAP.md)
- README "Further work" names vhost enumeration and diffing as the top of the list — [README.md:391-395](README.md)

### Inferences
- The roadmap is feature-centric. The correctness issues in section 3 (checkpoint keying, exclude bypass, network failures not becoming gaps) are not on any list and arguably outrank tier-1 features, since they break the project's own "reduced coverage must never look clean" rule ([CLAUDE.md](CLAUDE.md), [extscan/resilience.py:1-24](extscan/resilience.py)).
- Severity enrichment (CVSS/EPSS/KEV), SARIF/CSV export and finding suppression appear nowhere in todo or roadmap (see section 5).

### Gaps
- `docs/ROADMAP.md` gives no effort estimates or dates; ordering is explicitly "a recommendation, not a plan" — [docs/ROADMAP.md:8-10](docs/ROADMAP.md).
- The local memory notes referenced in AGENTS.md (`extscan-open-issues.md`) are not in the repo, so any open issue recorded only there was not visible — [AGENTS.md](AGENTS.md).

## 3. Correctness and robustness risks (bugs, scope bypasses, resume edge cases)

### Takeaway
Several confirmed defects break the tool's two core promises: (a) authorisation boundaries (excludes dropped when chunking is off; `allow_hostnames` trusts DNS; window checked only at stage start) and (b) "reduced coverage never looks clean" (network failures in probes/chase are recorded as info findings or "done" leads, not gaps; checkpoints keyed by chunk index silently skip hosts after a policy/scope change). There are also policy-loading bugs that make `policy.gentle.json` less gentle than it claims.

### Cited Findings
**Scope / authorisation**
- CONFIRMED (offline): `chunk_size <= 0` makes `chunk_targets` return `[scope.targets]`; because `targets` is then non-None, `_targets_for` skips `nmap_target_args()` and the `--exclude` list is never passed to nmap. Excluded hosts receive packets (results are dropped afterwards by `parse_xml`'s `scope.contains`, but the traffic was sent). Offline check: argv for `203.0.113.0/29` with exclude `.5` and chunk_size 0 has no `--exclude` — [extscan/tools/nmap.py:28-32](extscan/tools/nmap.py), [extscan/tools/nmap.py:319-320](extscan/tools/nmap.py), [extscan/scope.py:184-189](extscan/scope.py). Nothing rejects `chunk_size: 0` in policy loading — [extscan/policy.py:267-278](extscan/policy.py)
- CONFIRMED (code): `Scope.contains` returns True for any name in `allow_hostnames` with no resolution check, and `net.fetch` lets urllib resolve at connect time. A listed hostname that resolves (or is rebound) to an out-of-scope or internal address gets fetched. The example scope ships `allow_hostnames` — [extscan/scope.py:198-209](extscan/scope.py), [extscan/tools/net.py:91-106](extscan/tools/net.py), [examples/scope.example.json](examples/scope.example.json). This contradicts the recon rule that a name is scannable only if *all* its addresses are in targets — [extscan/tools/subdomains.py:187](extscan/tools/subdomains.py)
- CONFIRMED (code): the testing window is checked once per stage (`assert_window` at the top of discover/recon/probe/chase/screenshot) and never inside loops. A discover stage over many chunks (each allowed `timeout_sec` 7200 s, 21600 s on `thorough`) can run long past `window_end` — [extscan/pipeline.py:178](extscan/pipeline.py), [extscan/pipeline.py:98-170](extscan/pipeline.py), [extscan/policy.py:56](extscan/policy.py), [extscan/policy.py:246](extscan/policy.py). The safety test only checks that each stage calls it — [tests/test_safety_invariants.py:420](tests/test_safety_invariants.py)
- CONFIRMED (offline): `Scope.validate` calls `host_count()`, which iterates every address before comparing with `max_hosts`. An IPv6 `/64` target hangs at load (still iterating after 3 s in the offline check) instead of failing fast — [extscan/scope.py:157-179](extscan/scope.py)
- CONFIRMED (offline): `_INTERNAL_NETS` omits `0.0.0.0/8` (0.0.0.0 reaches localhost on Linux), multicast `224.0.0.0/4`, reserved `240.0.0.0/4`, IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96` and 6to4 `2002::/16`; `is_internal_address("0.0.0.1")` and `("::ffff:127.0.0.1")` both return False. Only matters if such a range is typed into targets, but the guard exists precisely to catch typos — [extscan/scope.py:33-45](extscan/scope.py)
- CONFIRMED (code): `net.hosts()` drops network/broadcast addresses, so chunked nmap never scans `.0`/`.255` of a /24 even though `contains()` treats them as in scope (inconsistent coverage; offline check shows `203.0.113.0` and `.7` absent from the /29 chunk) — [extscan/scope.py:171-179](extscan/scope.py), [extscan/tools/nmap.py:321-324](extscan/tools/nmap.py)
- CONFIRMED (code): `source_path` is stored as given (`str(Path(path))`, not resolved), and later stages reload the scope from that path. Running a later stage from another working directory fails, or loads a different `scope.json` that happens to sit there — [extscan/scope.py:136](extscan/scope.py), [extscan/cli.py:39-49](extscan/cli.py)
- SUSPECTED: screenshot scope guard covers only requests that pass through Playwright's `context.route`. WebSocket connections, WebRTC/STUN (UDP) and DNS prefetch/preconnect are not routed, and Chromium is launched with no restricting flags or proxy, so a hostile page could make the browser contact off-scope hosts — [extscan/screenshots.py:147](extscan/screenshots.py), [extscan/screenshots.py:221-229](extscan/screenshots.py)

**Coverage gaps that look clean**
- CONFIRMED (code): `http_fingerprint` turns a connection error into an `info` finding ("did not answer cleanly") and returns normally, so the pipeline marks the service probed and records no Degradation; path checks silently `continue` on `status == 0`; a TLS handshake failure is likewise an info finding. A VPN drop mid-probe produces a report with no coverage gaps for those services, and `resume` will not retry them — [extscan/probes.py:97-104](extscan/probes.py), [extscan/probes.py:263-264](extscan/probes.py), [extscan/probes.py:318-325](extscan/probes.py), [extscan/pipeline.py:404-410](extscan/pipeline.py). There is also no `AbortThreshold` in the probe stage (only in discover and chase) — [extscan/pipeline.py:96](extscan/pipeline.py), [extscan/pipeline.py:438](extscan/pipeline.py)
- CONFIRMED (code): chase handlers return a `ChaseResult` with a note on network failure ("no response: …", "no machine-readable spec found") and `chase()` catches every exception into a "handler error" note. The pipeline marks any lead with a non-empty note `done` (or `failed` for handler errors) and records no Degradation. So the `retry`/`max_lead_attempts`/abandon path (and its gap) is effectively unreachable for ordinary network failures — [extscan/chase.py:359-360](extscan/chase.py), [extscan/chase.py:443-444](extscan/chase.py), [extscan/chase.py:520-521](extscan/chase.py), [extscan/chase.py:653-664](extscan/chase.py), [extscan/pipeline.py:468-517](extscan/pipeline.py). No test asserts behaviour for "no response" — grep of `tests/` for "no response"/"handler error" finds nothing.
- CONFIRMED (code): the `except CircuitOpen` branch in `chase_leads` (which records a serious LLM gap) is dead. `LLMClient.analyse` swallows `CircuitOpen` and returns None, and `chase()` would catch it anyway. A dead model shows up as per-lead "unavailable" findings, never as a Degradation — [extscan/pipeline.py:477-491](extscan/pipeline.py), [extscan/llm/__init__.py:160-162](extscan/llm/__init__.py), [extscan/llm/analyst.py:145-149](extscan/llm/analyst.py)
- CONFIRMED (code): leads with `depth > max_lead_depth` are filtered out of the chase loop and stay `open` forever with no gap; new leads beyond `max_leads_per_run` (500) are dropped silently by `add_leads` (no gap) — [extscan/pipeline.py:446](extscan/pipeline.py), [extscan/store.py:173-184](extscan/store.py)
- CONFIRMED (code): `Store._read` returns the default (`[]`/`{}`) on `JSONDecodeError`. A corrupted `findings.json` reads as "no findings", and the next `add_findings` overwrites it with only the new ones: silent data loss — [extscan/store.py:76-83](extscan/store.py), [extscan/store.py:156-164](extscan/store.py)

**Resume / checkpoint edge cases**
- CONFIRMED (code): checkpoints are keyed `chunk-{index:04d}`, independent of which hosts the chunk held. Changing `nmap.chunk_size`, the scope's `exclude`, or targets between runs, which README and `_scope_for` explicitly endorse ("change the policy, and carry on"; "scope can legitimately change mid-engagement"), shifts host→chunk mapping. Resume then skips chunks that were never scanned, with no gap. Example: chunk_size 16 completes chunks 1-2 (hosts 1-32), resume with 32 skips chunks 1-2 = hosts 1-64 — [extscan/pipeline.py:98-101](extscan/pipeline.py), [extscan/pipeline.py:136](extscan/pipeline.py), [extscan/tools/nmap.py:312-324](extscan/tools/nmap.py), [README.md:24-27](README.md), [extscan/cli.py:39-49](extscan/cli.py)
- SUSPECTED: `_read_xml` reads `raw/nmap-<label>.xml` after every run. If nmap fails to start (OSError path in `Runner.run`, rc None) a stale XML from an earlier attempt with the same label is parsed and checkpointed as success — [extscan/tools/nmap.py:336-355](extscan/tools/nmap.py), [extscan/runner.py:417-419](extscan/runner.py)
- CONFIRMED (code): nuclei re-runs against *all* web services on every `probe`/`resume`, even when all are already marked `nuclei`; the `unchecked` list is used only for the `--skip-nuclei` gap. On a large estate every `extscan resume` repeats the longest stage — [extscan/pipeline.py:332-366](extscan/pipeline.py)
- CONFIRMED (code): `Runner.run` keeps timeout output only if `exc.stdout` is `str`; CPython's `TimeoutExpired.stdout` is bytes even with `text=True`, so partial stdout is dropped on timeout (nmap and nuclei write files, so impact is limited to stdout-only tools such as testssl) — [extscan/runner.py:409-414](extscan/runner.py)
- todo.md root-owned-files question, from code: JSON state is written via tmp+`replace`, so a later unprivileged rename over root-owned files works in a user-owned dir. Risks are (a) a root-owned leftover `.<name>.tmp` after a crash, which the user cannot open for writing, and (b) raw artefacts the root pass writes (nmap `-oA` files, DNS `dns-axfr-*.txt` via `write_raw`) that a later unprivileged pass rewriting the same name cannot overwrite — [extscan/store.py:85-90](extscan/store.py), [extscan/store.py:262-268](extscan/store.py), [extscan/tools/dns.py:753](extscan/tools/dns.py) (SUSPECTED; untested, per todo)
- CONFIRMED (code): `Store.open("latest")` picks the run whose `run.json` was *modified* most recently, not the newest run; touching an old run (even `report`) changes what `latest` means — [extscan/store.py:57-64](extscan/store.py)

**Policy loading**
- CONFIRMED (offline): `Policy.from_dict` copies only `max_lead_depth`, `max_leads_per_run` and `stop_on_tool_error` from top-level keys and silently ignores all other top-level keys. `examples/policy.gentle.json` sets `"max_workers": 3`, but the loaded policy has `max_workers == 8`; a typo such as `max_wrokers` is also accepted silently — [extscan/policy.py:279-281](extscan/policy.py), [examples/policy.gentle.json](examples/policy.gentle.json). `max_lead_attempts` is likewise not loadable — [extscan/policy.py:228](extscan/policy.py)
- CONFIRMED (code): `stop_on_tool_error` is defined and loaded but never read; `analyse_findings_above` and `analyst.analyse_finding` are defined but never used — [extscan/policy.py:227](extscan/policy.py), [extscan/policy.py:210](extscan/policy.py), [extscan/llm/analyst.py:169](extscan/llm/analyst.py)
- CONFIRMED (code): `_policy_for` suppresses `ValueError`/`KeyError` when re-loading the saved policy and silently falls back to profile defaults; a `--policy` override on a later stage is never written back to `run.json`, so the report's methodology shows the init-time policy — [extscan/cli.py:52-62](extscan/cli.py), [extscan/pipeline.py:38-53](extscan/pipeline.py)

**Detection accuracy (false positives/negatives)**
- CONFIRMED (code): `/actuator/heapdump` (critical) can never be a hit. The `/actuator*` branch requires a JSON content type or a body starting with `{`, but a heap dump is binary HPROF (`application/octet-stream`). The critical path is missed unless nuclei catches it — [extscan/probes.py:177-178](extscan/probes.py), [extscan/probes.py:245-246](extscan/probes.py)
- CONFIRMED (code): GraphQL chase reports "introspection enabled" (medium) whenever the body contains `"data"` or `"__schema"`. A server with introspection disabled that returns `{"data":null,"errors":[...]}`, or an error message quoting `"__schema"`, yields a medium finding with 0 types — [extscan/chase.py:362-403](extscan/chase.py)
- CONFIRMED (code): `chase_api_endpoint` treats any 2xx JSON as confirmed open (`_looks_like_app_error` returns False for JSON), so a `200 {"error":"unauthorized"}` becomes a medium/high "unauthenticated API endpoint confirmed" — [extscan/chase.py:504-562](extscan/chase.py)
- CONFIRMED (code): generic soft-404 fallback is substring matching ("not found"/"404") with no random-path baseline comparison; `/config.json` passes on any JSON containing `{` — [extscan/probes.py:225-228](extscan/probes.py), [extscan/probes.py:249](extscan/probes.py)
- CONFIRMED (code): TFTP (69) is in the **TCP** exposure table and absent from the UDP table; TFTP runs on UDP — [extscan/probes.py:430](extscan/probes.py), [extscan/probes.py:461-471](extscan/probes.py)
- CONFIRMED (code): nmap `vuln`-category output (for example "State: VULNERABLE" from ssl-poodle, ssl-dh-params, smb-vuln-*, http-vuln-*) maps to `info` with no review flag unless the script ID is in the 15-entry table, so real vulnerabilities are under-rated — [extscan/tools/nmap.py:217-273](extscan/tools/nmap.py)
- CONFIRMED (code): `X-Frame-Options` is flagged missing even when CSP `frame-ancestors` is set (the comment says "unless", the code does not check) — [extscan/probes.py:77](extscan/probes.py), [extscan/probes.py:145](extscan/probes.py)
- CONFIRMED (code): the OpenAPI raw filename uses `abs(hash(spec_url))`, which changes per process because of hash randomisation, so reruns write duplicate artefacts — [extscan/chase.py:138-139](extscan/chase.py)
- SUSPECTED: `subdomains.resolve` relies on `socket.setdefaulttimeout`, which does not bound `getaddrinfo`, and changes a process-global default — [extscan/tools/subdomains.py:144-151](extscan/tools/subdomains.py)
- SUSPECTED: urllib's timeout is per socket operation, not a total deadline, so a tarpit server trickling bytes can hold a probe worker far beyond `timeout_sec` — [extscan/tools/net.py:106-107](extscan/tools/net.py)

### Inferences
- The most important fixes are: key checkpoints by a hash of the chunk's host list; always pass `--exclude` (or filter `scope.targets` through `hosts()`); turn `status==0` network errors in probes and chase into Degradations, leaving services and leads unmarked; reject unknown top-level policy keys; re-check the window per chunk and per lead; and resolve and IP-check `allow_hostnames` per request (or pin the resolved IP).
- Each of these fits the project's existing pattern (a fuzz-corpus entry plus a unit test in `tests/test_coverage_gaps.py`, as CLAUDE.md requires).

### Gaps
- The fuzzer (`tests/fuzz_failures.py`) was not run (several minutes, opt-in); it targets tool-process failures, not network-level HTTP failures, so it would not catch the probe/chase gap issues — [tests/fuzz_failures.py](tests/fuzz_failures.py).
- The screenshot WebSocket/WebRTC bypass was not tested (needs Playwright and Chromium, which are not installed; the browser scope test skipped).

## 4. Performance and scale

### Takeaway
extscan is designed for "a few hundred hosts": `max_hosts` defaults to 1024, nmap chunks run one at a time, nuclei is a single unchunked invocation, the JSON store rewrites whole files on every mutation, and screenshots and chase are sequential. A /16 is possible only by raising `max_hosts`, and it would take a very long time, re-run nuclei on every resume, and degrade quadratically in the store.

### Cited Findings
- Default `max_hosts` is 1024 (README example uses 256); scopes above it are refused — [extscan/scope.py:106](extscan/scope.py), [extscan/scope.py:157-162](extscan/scope.py)
- nmap: one process at a time, 32 hosts per chunk, each chunk `-sV` intensity 7 + default/safe/vuln NSE + `-O` across `TCP_TOP` (1-1024 plus ~60 ports), timeout 7200 s per chunk. A /16 is 2,048 sequential chunks. There is no fast pre-sweep (masscan/naabu) and no `--max-rate` default (only `min_rate`, default 0, and `extra_args`) — [extscan/pipeline.py:98-170](extscan/pipeline.py), [extscan/tools/nmap.py:41-69](extscan/tools/nmap.py), [extscan/policy.py:16](extscan/policy.py), [extscan/policy.py:37-57](extscan/policy.py)
- nuclei: one invocation over every web URL, `timeout_sec` 3600 (10800 on thorough), `rate_limit` 50, `concurrency` 15. A timeout marks *all* web services unprobed, and the next run starts nuclei over from zero — [extscan/pipeline.py:343-366](extscan/pipeline.py), [extscan/policy.py:60-76](extscan/policy.py), [extscan/tools/nuclei.py:221-235](extscan/tools/nuclei.py)
- Probes: `ThreadPoolExecutor(max_workers=8)` over all (probe, service) jobs, with no per-host concurrency cap, so several workers can hit one host's services at once. `inter_request_delay` applies only within one service's sequential path loop; there is no global token-bucket rate limiter — [extscan/pipeline.py:380](extscan/pipeline.py), [extscan/probes.py:252-262](extscan/probes.py)
- Store: every `add_findings`, `mark_probed`, `update_lead`, `add_degradation` and `checkpoint` re-reads and rewrites the whole JSON file. `mark_probed` runs in a loop over all jobs, so the cost is O(jobs × services) file rewrites. There is no locking for concurrent processes, and a fixed tmp filename `.<name>.tmp` races if two extscan processes touch one run (for example user `probe` while `sudo discover` runs) — [extscan/store.py:85-90](extscan/store.py), [extscan/store.py:146-151](extscan/store.py), [extscan/pipeline.py:408-410](extscan/pipeline.py)
- Chase is strictly sequential, one lead at a time, up to 500 leads × 2 rounds, with a 12 s per-request timeout — [extscan/pipeline.py:451-517](extscan/pipeline.py), [extscan/policy.py:107](extscan/policy.py), [extscan/policy.py:226](extscan/policy.py)
- Screenshots are sequential. `plan` always includes every root page regardless of `max_pages` (`max(limit, len(roots))`), and each capture can take `timeout_sec` (20 s) plus a networkidle settle loop — [extscan/screenshots.py:110-111](extscan/screenshots.py), [extscan/screenshots.py:226-237](extscan/screenshots.py), [extscan/screenshots.py:242-256](extscan/screenshots.py)
- Recon resolves up to 2,000 names sequentially with getaddrinfo — [extscan/tools/subdomains.py:185-192](extscan/tools/subdomains.py)
- The `Runner` captures all stdout in memory (`capture_output=True`) — [extscan/runner.py:399-408](extscan/runner.py)
- Lab-scale data point: a full lab scan is ~8 min with nuclei, ~70 s with `--skip-nuclei` (one host, 9 services) — [CLAUDE.md](CLAUDE.md)
- Report volume: the lab run (1 host, 9 services) produced 168 findings, 42 review items and a 4,601-line `report.md` — [tests/fixtures/lab-run/report.md:19-35](tests/fixtures/lab-run/report.md), [tests/fixtures/lab-run/README.md](tests/fixtures/lab-run/README.md)

### Inferences
- Cheapest scale wins: chunk and checkpoint nuclei like nmap; skip nuclei for already-marked services; run 2-4 nmap chunks concurrently; add a host-discovery/port pre-sweep before `-sV`/NSE; batch store writes (one write per stage or per completed job, or SQLite); add per-host concurrency and a global request rate limiter for the HTTP probes.
- Without a total-deadline HTTP client and per-host caps, a handful of tarpit hosts can pin all 8 workers.

### Gaps
- No benchmark exists for >1 host; any timing for a /16 is extrapolation, not measurement.

## 5. Reporting and output

### Takeaway
Outputs are `report.md` (severity-grouped with review queue, systemic issues, inventory, gaps, methodology), `report.json` (same data, no leads), and an Obsidian vault narrative. There is no CVSS/EPSS/KEV scoring, no run diffing, no SARIF/CSV/HTML/DOCX export, no cross-source deduplication beyond title normalisation, and no way to suppress or accept findings. NSE noise floods the review queue.

### Cited Findings
- `report.md` sections: Authorisation, Scope, Summary, Manual review queue, Systemic issues, Findings by severity, Service inventory, Host detail, Coverage gaps, Methodology (tool versions, command log) — [extscan/report.py:73-307](extscan/report.py)
- `report.json` keys: engagement, run (full `run.json`), stats, review_queue, systemic, hosts, services, findings, coverage_gaps; **leads are not included** (and `report.md` has no lead section) — [extscan/report.py:323-336](extscan/report.py). The vault lists unresolved leads (`status != "done"`), but leads marked `done` after a network failure are hidden — [extscan/vault.py:662-721](extscan/vault.py)
- Severity is a static per-check string; `SEVERITIES = info..critical`; no CVSS vector, EPSS, CISA KEV or CWE fields on `Finding` — [extscan/models.py:15](extscan/models.py), [extscan/models.py:110-133](extscan/models.py). nmap CPEs are parsed into `Service.cpe` but used only by the IIS matcher (no CVE lookup; `vulners` is excluded as `external`) — [extscan/tools/nmap.py:207](extscan/tools/nmap.py), [extscan/tools/iis.py:78](extscan/tools/iis.py), [extscan/policy.py:46-52](extscan/policy.py)
- Dedup: `Finding.id = sha256(host, port, proto, title, source)`, so the same issue from nmap NSE, the exposure probe and nuclei becomes three findings (for example `redis-info` high + "Redis reachable" critical + a nuclei Redis template). The TLS probe and sslscan both report deprecated protocols, expired and self-signed certs under different titles — [extscan/models.py:131-133](extscan/models.py), [extscan/tools/nmap.py:230](extscan/tools/nmap.py), [extscan/probes.py:450](extscan/probes.py), [extscan/probes.py:346-387](extscan/probes.py), [extscan/tools/sslscan.py:104](extscan/tools/sslscan.py), [extscan/tools/sslscan.py:238-247](extscan/tools/sslscan.py)
- Titles embed volatile data (page title, op counts), so IDs churn across runs. The roadmap's diff item names this catch — [extscan/probes.py:120](extscan/probes.py), [extscan/chase.py:229](extscan/chase.py), [docs/ROADMAP.md:68-79](docs/ROADMAP.md)
- Systemic grouping: same `source|normalised title` on ≥3 hosts — [extscan/triage.py:78-133](extscan/triage.py)
- Review-queue noise: every `http-*` NSE script with output is `review_required` at info, so the lab review queue has 12+ items like `http-date`, `http-useragent-tester`, `http-mobileversion-checker` — [extscan/tools/nmap.py:262-270](extscan/tools/nmap.py), [tests/fixtures/lab-run/report.md:64-77](tests/fixtures/lab-run/report.md)
- Findings are add-only within a run (`add_findings` never removes or updates), so `probe --force` after remediation keeps the old finding, and changed titles add duplicates — [extscan/store.py:156-164](extscan/store.py)
- No `diff`, `export`, finding-suppress/accept or false-positive command exists. `resolve` applies to leads only — [extscan/cli.py:490-670](extscan/cli.py), [extscan/cli.py:347-355](extscan/cli.py)
- Audit trail: `commands.jsonl` records subprocesses only. HTTP requests from probes and chase, DNS queries and SNMP packets are not logged there, though README says "Every command, exit code and timing in `commands.jsonl` … so a client can reproduce any finding". Evidence strings carry request lines instead — [extscan/runner.py:431-435](extscan/runner.py), [README.md:295-297](README.md)
- Reports deliberately keep secrets unredacted; only LLM input is redacted — [README.md:242-245](README.md), [README.md:275-280](README.md)

### Inferences
- High-leverage, low-cost additions: (1) a stable `issue_key`/fingerprint independent of title wording, to enable `extscan diff` and cross-run tracking; (2) cross-source merge of findings for the same host:port and issue; (3) KEV/EPSS enrichment keyed on nuclei CVE IDs (nuclei JSONL carries `info.classification.cve-id`, which extscan does not currently read; SUSPECTED field name, verify against `tests/fixtures/nuclei.jsonl`); (4) SARIF/CSV export from `report.json`; (5) demote `http-*` NSE info output out of the review queue; (6) a suppression file (accepted-risk/FP) that survives re-rendering.

### Gaps
- Did not check whether the vault's per-finding notes contain anything `report.json` lacks.
- No information on what format clients require (DOCX is mentioned only as roadmap item 14).

## 6. Testing and engineering

### Takeaway
The suite is broad (485 tests in ~23 s) and lint is clean, but 2 lab tests fail in any environment with `HTTPS_PROXY` set, because they use plain `urlopen`. Documentation undercounts tests (says ~415). CI covers Python 3.10-3.13 and ruff, but not the fuzzer, real scanners, coverage measurement, type checking or packaging. Test gaps line up with the bugs in section 3.

### Cited Findings
- Ran `uv run python -m unittest discover -s tests -t .`: **Ran 485 tests in 22.7 s, FAILED (errors=2, skipped=1)**. The failures are `tests.test_lab.TestLab.test_https_serves_spec_pointing_at_lab_address` and `test_idle_tls_client_does_not_block_others`, both `URLError: [Errno 104] Connection reset by peer`. Re-running `tests.test_lab` with `HTTPS_PROXY`/`https_proxy` unset: 5 tests OK. Cause: the tests use `urllib.request.urlopen`, which honours env proxies, and urllib's `no_proxy` matching does not understand CIDR entries such as `127.0.0.0/8`, so 127.0.0.3 went through the proxy — [tests/test_lab.py:48-60](tests/test_lab.py). The skip is the Chromium screenshot scope test — [tests/test_safety_invariants.py:342](tests/test_safety_invariants.py)
- Ran `uv run ruff check .`: "All checks passed!". uv warned that `UV_NATIVE_TLS` is deprecated (environmental).
- Docs say "~415 tests, ~10s" — [CLAUDE.md](CLAUDE.md), [README.md:355](README.md); actual is 485.
- Test counts per file: test_new_tools 60, test_llm 50, test_resilience 45, test_dns 45, test_parsers 40, test_pipeline_e2e 39, test_coverage_gaps 36, test_safety_invariants 34, test_probes_and_chase 32, test_scope 28, test_vault 24, test_triage 21, test_snmp 19, test_lab 5, test_cli_ports 5, test_lab_run_fixture 2 (count of `def test`) — [tests/](tests/)
- CI: `ruff check` plus unittest on 3.10-3.13 plus a CLI smoke test (`--version`, `probes`, `providers`, `doctor || true`). No fuzz run, no nmap/nuclei install, no coverage, no mypy/pyright, no wheel build, no dependency audit — [.github/workflows/tests.yml](.github/workflows/tests.yml)
- Packaging: setuptools, zero runtime deps, extras `llm`, `bedrock`, `screenshots`, `all`; dev group ruff/pytest/hypothesis; `exclude-newer = "7 days"` supply-chain window; license "Proprietary" — [pyproject.toml](pyproject.toml)
- Version drift: `__version__ = "0.2.0"` but the default User-Agent is hard-coded `extscan/0.1` — [extscan/__init__.py:3](extscan/__init__.py), [extscan/policy.py:110](extscan/policy.py)
- `cloud-setup.sh` pins nuclei 3.4.10 and templates 10.2.7 with SHA-256 checks, but hard-codes `linux_amd64` (no arm64) — [scripts/cloud-setup.sh:12-17](scripts/cloud-setup.sh), [scripts/cloud-setup.sh:36](scripts/cloud-setup.sh). `doctor` hints use `nuclei@latest` and `amass@master`, contrary to that pinning — [extscan/runner.py:466-496](extscan/runner.py)
- Untested behaviours (no test found by grep, and each corresponds to a section-3 defect): `chunk_size<=0` exclude handling; checkpoint validity after a chunk_size/scope change; HTTP/TLS network failure → gap; chase "no response" → gap; unknown top-level policy keys; IPv6 nmap argv; `/actuator/heapdump` binary hit; GraphQL disabled-introspection error bodies.

### Inferences
- Make `test_lab` proxy-proof (build an opener with `ProxyHandler({})`, as `net._opener` already does at [extscan/tools/net.py:75-80](extscan/tools/net.py)). Otherwise the suite fails in every proxied CI or cloud environment.
- A coverage report (pytest-cov is not in the dev group) would have flagged the dead `CircuitOpen` branch and the unused `stop_on_tool_error`.

### Gaps
- Did not run the opt-in Hypothesis fuzzer or measure line coverage (no coverage tool in the dev group).

## 7. Safety properties: are they complete?

### Takeaway
The read-only and no-credential-testing guarantees are enforced for the default profiles only. A policy file can switch them off: `allow_intrusive` drops *all* nuclei exclusions including default-login; `extra_args`/`templates`/`scripts` are unconstrained; and nmap's default selection `(default or safe or vuln) and not (dos or external or slowloris)` admits NSE scripts that are also tagged `intrusive`/`exploit`. The safety tests check strings in the default profiles, not the effective script set or overrides.

### Cited Findings
- nuclei default `-exclude-tags`: dos, intrusive, fuzz, brute-force, default-login, default-logins, creds-stuffing; `-no-interactsh`; `-disable-update-check` — [extscan/policy.py:63-65](extscan/policy.py), [extscan/tools/nuclei.py:25-50](extscan/tools/nuclei.py)
- CONFIRMED (code): `if not p.allow_intrusive and p.exclude_tags:` means `allow_intrusive: true` removes the entire exclude list, credential templates included. README calls "no credential testing" "not configurable away" — [extscan/tools/nuclei.py:39-40](extscan/tools/nuclei.py), [README.md:250-257](README.md)
- CONFIRMED (code): `nuclei.extra_args`, `nuclei.templates`, `nuclei.include_tags`, `nmap.extra_args` and `nmap.scripts` are passed through unvalidated, so a policy file can add `-tags default-login`, `--script brute`, etc. The `brute`, `intrusive`, `exploit` and `malware` NSE categories are not in `exclude_scripts` — [extscan/tools/nuclei.py:41-49](extscan/tools/nuclei.py), [extscan/tools/nmap.py:55-67](extscan/tools/nmap.py), [extscan/policy.py:51-55](extscan/policy.py)
- CONFIRMED (code) + SUSPECTED (NSE metadata): the default selection includes the whole `vuln` category minus only dos/external/slowloris. NSE scripts in `vuln` that are also `intrusive`/`exploit` would run. From nmap's script metadata (not verified here, nmap not installed), examples include `http-vuln-cve2014-3704` (Drupalgeddon; its documented behaviour is to inject an admin user), `http-shellshock` and `smb-vuln-cve-2017-7494`. Verify with `nmap --script-help "vuln and (intrusive or exploit)"` — [extscan/tools/nmap.py:35-38](extscan/tools/nmap.py), [extscan/policy.py:45-52](extscan/policy.py)
- The safety test for NSE only asserts the substring "exploit"/"dos"/"brute"/"malware" is absent from `policy.nmap.scripts` in built-in profiles. It does not evaluate the effective category expression — [tests/test_safety_invariants.py:134-138](tests/test_safety_invariants.py)
- The nuclei safety tests cover the built-in profiles only, not `Policy.from_dict` overlays — [tests/test_safety_invariants.py:100-130](tests/test_safety_invariants.py)
- GraphQL introspection is a POST (tested to contain no mutation) and IIS uses OPTIONS. README's "Read-only. GET, connect, query" is accurate in spirit, but the POST exception is not stated there — [extscan/chase.py:342-357](extscan/chase.py), [tests/test_safety_invariants.py:183-200](tests/test_safety_invariants.py), [README.md:254-257](README.md)
- SNMP community list includes `private` and `write` (GET-only; tests assert no SET PDU) — [extscan/policy.py:120-123](extscan/policy.py), [tests/test_safety_invariants.py:165-178](tests/test_safety_invariants.py)
- What is well covered: no shell, no eval, scope check on fetch/TLS/SNMP, off-scope redirect refusal including POST, DNS scope gate and QUERY-only opcode, a host name never unlocking its zone, the browser test (skipped without Chromium), the window check in every stage — [tests/test_safety_invariants.py:51-431](tests/test_safety_invariants.py)
- Scope-related safety gaps from section 3: the exclude list is dropped when `chunk_size<=0`; `allow_hostnames` trusts DNS; the window is checked only at stage start; screenshot WebSocket/WebRTC (SUSPECTED).

### Inferences
- Make safety invariants properties of the *effective* argv: always append the credential/dos exclusions even under `allow_intrusive` (split "intrusive" from "credential" opt-ins); add `intrusive`, `exploit`, `brute` and `malware` to the default NSE exclusion expression, or allow-list `vuln and safe`; validate `extra_args` against a deny list (`--script`, `-tags`, `-t`); and test `Policy.from_dict` overlays as well as built-in profiles.

### Gaps
- Could not enumerate the effective NSE script set or the nuclei template set (neither tool installed); the script names above come from prior knowledge of NSE metadata.

## 8. Usability: CLI, docs, skill

### Takeaway
The CLI is complete for a staged workflow and agent-friendly (`--json` everywhere, `note`, `resolve`, `gaps`), but it lacks diff/export/suppress, target overrides, and rate controls on the command line. Some remediation text and docs are stale or point at flags that do not exist.

### Cited Findings
- Subcommands: doctor, probes, providers, init, recon, discover (`--tcp-only/--udp-only/--resume`), probe (`--only/--force/--skip-nuclei`), leads, chase (`--lead/--kind/--rounds`), screenshot, report, gaps, resume, status, services, findings, show, note, resolve, run — [extscan/cli.py:490-670](extscan/cli.py)
- CONFIRMED: the CircuitOpen gap remedy says `extscan chase <run> --resume`, but `chase` has no `--resume` flag (the branch is dead anyway) — [extscan/pipeline.py:487-488](extscan/pipeline.py), [extscan/cli.py:563-570](extscan/cli.py)
- `resume` re-runs discover/probe/chase/screenshot/report but never `recon`, and always re-runs nuclei (section 3) — [extscan/cli.py:387-418](extscan/cli.py)
- `note --host` is not scope-checked (an analyst can record a finding for any host) — [extscan/cli.py:324-344](extscan/cli.py)
- `doctor` returns non-zero only when nmap is missing; `run` calls `doctor()` but ignores the result — [extscan/cli.py:115-116](extscan/cli.py), [extscan/pipeline.py:631](extscan/pipeline.py)
- No CLI flags for rate (`--max-rate`), workers, excludes or ad-hoc targets; everything goes through policy/scope JSON, where unknown top-level keys are silently ignored (section 3) — [extscan/cli.py:528-560](extscan/cli.py), [extscan/policy.py:279-281](extscan/policy.py)
- Stale docs: test count (~415 vs 485); README "Model endpoint is down → … a circuit breaker opens", but at pipeline level no gap is recorded — [README.md:207](README.md), [extscan/pipeline.py:477-491](extscan/pipeline.py)
- SKILL.md (232 lines) covers before-run checks, the loop, reading discovery, chase choices, where model judgement adds value, mid-run failures, LLM, hard limits and report writing. Its hard limits say "Stay inside the window", which the tool itself only half-enforces — [.claude/skills/extscan/SKILL.md:175-212](.claude/skills/extscan/SKILL.md)
- AGENTS.md points at local memory notes that exist only on the original workstation — [AGENTS.md](AGENTS.md)

### Inferences
- Quick usability wins: `extscan diff`, `extscan export --format sarif|csv`, `extscan suppress <finding-id> --reason`, policy validation (`extscan policy check`), recording per-stage effective policy in `run.json`, resolving and recording the absolute scope path at init, and a `--max-rate`/`--workers` CLI override.

### Gaps
- The CLI was not exercised end to end (no scanning permitted); usability claims come from reading argparse definitions and docs.
