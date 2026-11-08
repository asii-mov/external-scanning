# Open-source external attack-surface and recon tooling (late 2026) benchmarked against extscan

Method note: versions below come from `git ls-remote --tags` on each public repo, and "last commit" dates come from the HEAD commit of each repo's default branch, read from a shallow clone on 2026-11-08. A recent commit can be a dependency bump, so it shows the repo is alive, not that features are being added. Feature descriptions come from the READMEs, docs and release notes linked inline. No tool was run against any target.

Baseline (from the repo's `README.md` and `docs/ROADMAP.md`):
- **What extscan already does:** nmap TCP/UDP with `default,safe,vuln` NSE and `external` excluded; nuclei over HTTP services with `dos,intrusive,fuzz,brute-force` excluded and no interactsh; built-in TLS cert/version probe; sslscan; built-in SNMP; IIS checks; an SSH banner-only probe; about 23 disclosure paths; CT and subfinder/amass subdomains split into in-scope and out-of-scope; DNS AXFR, NSEC walk and dangling-CNAME/MX/NS checks; chase of OpenAPI, GraphQL, secret files and `.git`; Playwright screenshots; report.md, report.json and an Obsidian vault; Degradation coverage gaps and resume.
- **What the code has no trace of:** grep of `extscan/` finds no favicon hashing, tech fingerprinting (Wappalyzer), CDN/WAF detection, JARM, vhost probing, run diffing, ssh-audit, crawling, or robots/sitemap parsing. testssl.sh appears only as a fallback in `chase.py`.
- **Roadmap items still open:** vhost/SNI (2), HTTP method checks (3), cert inventory (4), diff (5), takeover fingerprint matching (6 "Left"), email posture (7), WAF/rate-limit detection (9), and more protocol probes (10).

## Key Question 1: ProjectDiscovery stack — what each tool does that extscan lacks, current versions, 2025-2026 changes

### Takeaway
The ProjectDiscovery stack is very actively maintained. Every repo checked had commits in the past two weeks. Its main advantage over extscan is web-layer fingerprinting: tech detection, favicon mmh3, JARM, CDN/WAF tagging, near-duplicate and page-type classification, and crawling. Two findings bear directly on extscan:
- **The pinned nuclei is old.** extscan pins nuclei **v3.4.10** and templates **v10.2.7** (`scripts/cloud-setup.sh`). Current is nuclei v3.11.1 and templates v10.5.1. Nuclei v3.8.0 fixed two 2026 CVEs in the template engine.
- **Nuclei can silently skip hosts.** Its default `-max-host-error 30` drops a host after 30 errors. extscan's nuclei argv neither disables this nor surfaces it, which is a coverage-gap leak.

### Cited Findings
**Versions and activity**
- Latest tags: nuclei v3.11.1, httpx v1.12.0, naabu v2.7.0, katana v1.8.0, dnsx v1.3.1, subfinder v2.17.0, tlsx v1.4.4, asnmap v1.2.0, cdncheck v1.4.0, uncover v1.2.1, alterx v0.1.0, nuclei-templates v10.5.1, cvemap v2.0.2. All had HEAD commits between 2026-10-25 and 2026-11-08. — [nuclei](https://github.com/projectdiscovery/nuclei), [httpx](https://github.com/projectdiscovery/httpx), [naabu](https://github.com/projectdiscovery/naabu), [katana](https://github.com/projectdiscovery/katana), [cdncheck](https://github.com/projectdiscovery/cdncheck), [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)

**Nuclei 2025-2026 release history** — [nuclei releases](https://github.com/projectdiscovery/nuclei/releases)
- **v3.6.0 (4 Dec 2025):** resume file at a flag-set path, direct fuzzing of OpenAPI/Swagger from a URL, JS multi-port support.
- **v3.7.0 (Jan 2026):** `cdp-endpoint` for headless; RSYNC module.
- **v3.8.0 (18 Apr 2026):**
  - Fixed CVE-2026-41646 (JS `require` ignored `allow-local-file-access`) and CVE-2026-41645 (expressions could evaluate non-template content).
  - Added PDF report export, honeypot detection, and a resume-state refactor.
- **v3.9.0 (Jun 2026):** impacket integration plus WMI/TSCH/SCMR/DCOM JS helpers.
- **v3.10.0 (30 Jun 2026):** opt-in capability gating; per-host HTTP client pooling. "Hosts that consistently time out are skipped via the hosterrors cache."
- **v3.11.0 (6 Jul 2026), breaking:** custom `javascript:` templates must be digitally signed (`nuclei -sign`). Unsigned ones are skipped at load and in workflows. Official templates are pre-signed.
- **v3.11.1 (8 Aug 2026):** `-max-time` soft termination, TLS metadata for HTTP, SMB and MySQL/MSSQL JS fingerprinting, DNSSEC record types.

**Nuclei flags relevant to extscan**
- Nuclei's flags include:
  - `-mhe, -max-host-error int` ("max errors for a host before skipping from scan (default 30)"), `-te/-track-error` and `-nmhe/-no-mhe`.
  - `-as, -automatic-scan` ("automatic web scan using wappalyzer technology detection to tags mapping").
  - `-ai, -prompt` ("generate and run template using ai prompt").
  - `-pd/-dashboard` (upload results to the ProjectDiscovery Cloud Platform, PDCP).
  - `-resume`, `-stats-json`, `-hps` (HTTP status capture).

  — [nuclei README](https://github.com/projectdiscovery/nuclei/blob/dev/README.md)
- **The `-ai` flag runs in the cloud.** It generates and runs a template from a natural-language prompt through ProjectDiscovery's cloud. Over 40k templates had been created with the earlier AI Template Editor. PD recommends reviewing AI output. — [PD blog](https://projectdiscovery.io/blog/reinventing-custom-detections-and-vulnerability-management); [PDCP editor FAQ](https://docs.projectdiscovery.io/cloud/editor/faq)

**nuclei-templates content**
- 11,997 files: http 9,281, cloud 659, file 436, network 259, code 251, dast 240, **workflows 205**, javascript 92, ssl 38, dns 23.
- 3,587 `cve` tags and 1,496 unique KEV templates (`-tags kev,vkev`).
- 1,365 `panel`, 1,141 `exposure` and 3,265 `discovery` tags.
- Severity spread: info 4,353, high 2,552, medium 2,457, critical 1,555.

  — [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)

**httpx** — [httpx README](https://github.com/projectdiscovery/httpx)
- **Fingerprinting:** `-td` tech detection (Wappalyzer dataset) and `-cff` custom fingerprints.
- **Hashing:** `-favicon` (mmh3 of `/favicon.ico`); `-hash` (md5/mmh3/simhash/sha*); `-jarm`.
- **Network data:** `-cdn` CDN/WAF detection (on by default) and `-asn`.
- **TLS and vhosts:** `-tls-grab`, `-vhost`, `-sni`, `-tlsi` (JA3 impersonation, experimental).
- **Screenshots:** `-ss`.
- **Triage filters:** `-fd/-filter-duplicates` drops near-duplicate responses. `-kb/-knowledge-base` and `-fpt/-filter-page-type` classify pages (e.g. login, captcha, parked) using a downloadable or local `-ptm` model.
- **Storage:** `-rdb` result databases (MongoDB, Postgres, MySQL).

**katana** — [katana README](https://github.com/projectdiscovery/katana)
- **Crawl modes:** standard (Go HTTP, no JS rendering) or `-headless`.
- **Endpoint sources:** `-jc` JS endpoint parsing, `-jsl` jsluice (memory-heavy), `-kf` robots.txt/sitemap.xml.
- **Forms:** `-fx` extracts forms. `-aff` auto form fill is experimental and **off by default**.
- **Scope and limits:**
  - Field scope `rdn`/`fqdn`/`dn` with `-cs/-cos` regex in/out-of-scope rules.
  - `-d` depth (default 3).
  - `-fsu` collapses look-alike URLs.
- **Newer features:** `-pcs` simhash/tfidf similarity, `-kb` page classification, recorded login flows `-rf`, auto-login `-al`, captcha solving `-csp capsolver`, per-host rate limit with backoff on 429/503 `-hrl`.

**naabu** — [naabu README](https://github.com/projectdiscovery/naabu)
- **Scan types:** SYN, CONNECT and UDP.
- **Targets:** IPs/CIDRs/hosts/**ASNs**.
- **CDN handling:** `-exclude-cdn` limits detected CDN/WAF IPs to ports 80 and 443.
- **Passive ports:** `-passive` reads open ports from Shodan InternetDB.
- **Service detection:** `-sV` uses nmap-service-probes from a local nmap. `-nmap-cli` hands results to nmap.
- **Operations:** `-resume`; `-shard`/`-seed` for splitting work.

**cdncheck** — [cdncheck README](https://github.com/projectdiscovery/cdncheck)
- Classifies IPs and DNS names as CDN, cloud or WAF.
- **WAF providers:** cloudflare, incapsula, sucuri, akamai. **CDNs:** cloudfront, fastly, google, leaseweb. **Cloud:** aws, google, oracle.
- **Data:** ranges are compiled from `provider.yaml` (URLs, ASNs, CIDRs) into `sources_data.json`. CNAME and Wappalyzer-based mappings live in `other.go`.
- **Output:** JSONL; also usable as a Go library.

**PDCP (ProjectDiscovery Cloud Platform)** — [PDCP intro](https://docs.projectdiscovery.io/cloud/introduction)
- Commercial service with a free tier.
- Features: asset discovery, continuous monitoring of "new hosts, endpoints, and configuration drift," automated retest and regression of fixes.
- Diffing and continuous monitoring sit in this commercial tier rather than in the OSS CLIs.

### Inferences
**Upgrade and coverage-gap items in extscan's nuclei integration**
- **The nuclei pin is behind on security fixes.** extscan's pin (nuclei 3.4.10 / templates 10.2.7) predates the v3.8.0 template-engine CVE fixes and v3.10.0 capability gating. For a tool that feeds target-controlled content to nuclei, bumping the pin is the cheapest security win. Re-capture lab fixtures afterwards.
- **v3.11.0 JS template signing** only matters if extscan ever ships custom `javascript:` templates. It would need a signing key and the `-sign` workflow.
- **Host skipping is a coverage gap extscan doesn't record.** Nuclei's default `-mhe 30`, plus v3.10.0's hosterrors cache, means nuclei drops a flaky or rate-limiting host partway through and still exits 0. extscan's argv builder (`extscan/tools/nuclei.py`) passes no `-mhe`/`-nmhe` and parses only JSONL results. Two fixes:
  - Run with `-stats-json` and/or a known `-mhe`, and parse which hosts were skipped into a Degradation.
  - Or pass `-nmhe`, accepting slower scans.
  This is the most directly actionable finding against the project rule "reduced coverage must never look clean."
- **`-as` automatic scan** (Wappalyzer-to-tags) would reduce noise and runtime versus running the full template set. Running the full set is more conservative for an audit, so it is a trade-off, not a clear win.
- **Avoid cloud features.** `-ai`, `-dashboard` and PDCP upload send target data to a third party. They conflict with extscan's rules (no third-party relays, secrets stay in the engagement). Policy should keep them unreachable, like interactsh.

**Capabilities extscan lacks, by fit**
- **Good fit for stdlib-only:**
  - Favicon mmh3 hash: MurmurHash3 x86_32 is small in pure Python. Shodan convention is mmh3 of the base64-encoded favicon with newlines every 76 chars; this convention is from general knowledge and not verified in a source this session.
  - Body simhash or near-duplicate grouping.
  - CDN/WAF IP-range tagging, by vendoring cdncheck's provider data or similar published cloud ranges.
- **Heavier:** tech fingerprinting via a Wappalyzer-format JSON. JARM needs raw ClientHello crafting.
- **Unsafe as-is for an audit tool:** katana-style crawling. It would need a strict depth cap, GET-only and no form fill.

### Gaps
- The `-ai` flag's ship date and data handling are not documented in what I fetched.
- No primary source on whether PDCP's free tier includes diffing.
- No per-release changelog checked for httpx/katana, so dates for `-kb`, `-fpt`, `-fd` and `-tlsi` are unknown. They appear in current READMEs.
- Not verified: which templates the nuclei `technologies`/`tech` tags contain, or the count of `takeover` templates (only top-10 tag counts were visible).
- asnmap, uncover, alterx, dnsx and tlsx were not read in detail beyond their versions and activity.

## Key Question 2: Frameworks — BBOT, Amass, reNgine, Osmedeus, reconFTW, ax, Sn1per, ScanCannon, masscan, RustScan, ZMap

### Takeaway
The frameworks split into four groups:
- **Event-graph engines** (BBOT, Amass v5): modules or plugins emit typed events or assets into a graph, with explicit scope distance.
- **Workflow orchestrators** (Osmedeus v5, reconFTW, reNgine, Sn1per): YAML/bash pipelines over many external tools, with scheduling, notifications and distributed workers.
- **Fast port-scanner front-ends** (masscan/RustScan/ZMap, wrapped by ScanCannon).
- **Fleet tooling** (ax): spreads the work over cloud VMs.

Almost all are bug-bounty-shaped: breadth, passive OSINT, mass fuzzing, cloud fleets. The patterns worth taking for an auditor tool:
- run-to-run diff (reconFTW DIFF, ScanCannon scan-diff, Amass `track`, reNgine)
- BBOT's targets-vs-seeds and scope-distance model
- BBOT's safe/passive/active/loud/invasive module flags
- a "hotlist" or risk-ranked asset list (reconFTW)
- output sinks (SQLite/JSONL/SIEM)

### Cited Findings
**BBOT (Black Lantern Security)**
- **Architecture:** Spiderfoot-style recursion. 100+ modules each consume an event type and emit new events, which go to all other modules. Example: `portscan` consumes `DNS_NAME` and emits `OPEN_TCP_PORT`; `sslcert` consumes `OPEN_TCP_PORT` and emits `DNS_NAME`. — [BBOT how it works](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works/)
- **Scope model:** — [BBOT scanning docs](https://www.blacklanternsecurity.com/bbot/Stable/scanning/)
  - Targets (`-t`) define what is in scope. `-b/--blacklist` "takes ultimate precedence" and accepts regex.
  - Seeds (`-s`) start discovery. Out-of-scope items found via seeds are reported but "active modules won't touch it."
  - "Scope distance" counts hops from scope: 0 is in scope, and resolution reaches distance 2 by default. `scope.report_distance` controls what is displayed. `--strict-scope` excludes children of targets.
- **Module flags:** safe (100), passive "never connects to target systems" (68), active (52), loud (21), invasive "intrusive or potentially destructive" (7). Every module is either active or passive. — [BBOT scanning docs](https://www.blacklanternsecurity.com/bbot/Stable/scanning/)
- **Output modules:** — [BBOT output docs](https://www.blacklanternsecurity.com/bbot/Stable/scanning/output/)
  - On by default: CSV/TXT/JSON.
  - Chat: Discord/Slack/Teams (FINDING events filtered by `min_severity`).
  - Messaging and search: Webhook, Kafka, RabbitMQ, NATS, ZeroMQ, Elasticsearch, Splunk HEC.
  - Databases: MongoDB, SQLite, Postgres, MySQL, Neo4j.
  - Reports: Asset Inventory CSV, Web Report (Markdown), Nmap XML.
  - No built-in scan-to-scan diff is documented.
- **BBOT 3.0 (8 Jul 2026):** — [BBOT 3.0 blog](https://blog.blacklanternsecurity.com/p/bbot-30); [3.0 breaking changes](https://www.blacklanternsecurity.com/bbot/Stable/migration/3.0_breaking_changes/)
  - Rust BlastDNS ("15x faster than ... dnspython") and BlastHTTP, which replaced httpx.
  - `--whitelist` removed; targets now define scope and seeds drive discovery.
  - ASNs accepted as targets via the free ASNDB API.
  - New Mongo/Elastic/Kafka/RabbitMQ/NATS/ZeroMQ outputs, with `siem_friendly` on by default.
  - Lightfuzz overhaul with an OOB SSRF submodule.
  - wappalyzer, wpscan, smuggler and others removed.
  - "BBOT Server" and an Enterprise ASM offering are described as upcoming.
- **Activity:** latest stable tag v3.0.2. The `stable` branch HEAD is 2026-08-24 and `dev` is 2026-11-05. — [bbot repo](https://github.com/blacklanternsecurity/bbot)

**OWASP Amass v5**
- **Structure:** `amass engine` fills an Open Asset Model (OAM) database. `amass subs` presents discovered subdomains. `amass track` "identif[ies] newly discovered assets" over time. `amass assoc` walks the graph with SPARQL-like triples. — [Amass OAM docs](https://owasp-amass.github.io/docs/open_asset_model); [oam-tools](https://www.github.com/owasp-amass/oam-tools)
- **Asset DB:** "long-term tracking", with a PostgreSQL backend shown.
- **Data model:** OAM asset types include FQDN, IPAddress, Netblock, Service and TLSCertificate, plus relation types. Data sources are configured in `datasources.yaml` with credentials. The docs reference Docker image `owaspamass/amass:5.0.0`. — [Amass docs](https://owasp-amass.github.io/docs/)
- **Activity:** latest tag v5.1.3, HEAD 2026-10-25. — [amass repo](https://github.com/owasp-amass/amass)
- Source quality: most of the subcommand detail came from search snippets of the official docs and the oam-tools repo, not a full v5 reference page.

**reconFTW**
- **Versions:** bash v4.1 is the stable release. A Go rewrite, v5.0.0-beta.1, is an opt-in pre-release. HEAD 2026-10-29.
- **Coverage:** chains about 80 tools across OSINT, subdomains, hosts, web and vulns. These include cdncheck, wafw00f, nmap+vulners, naabu, katana, jsluice, favirecon, ffuf, shortscan, nuclei (incl. DAST), testssl, trufflehog/gitleaks/noseyparker and cloud_enum/S3Scanner. It also includes **brutespray/brutus password spraying and sqlmap/commix**, which are exploitation-grade.
- **Scope:** `-i` in-scope list, `-x` out-of-scope list, and an `INSCOPE` `.scope` file.
- **Change tracking:**
  - **DIFF:** re-run and show only new findings.
  - **`--incremental`:** scan only what is new.
  - **`--monitor`:** cycles with alert suppression by fingerprint.
  - **`--quick-rescan`:** skip heavy modules when nothing is new.
  - **`hotlist.txt`:** ranks the riskiest assets.
  - Checkpoint resume.
- **Fleet and reporting:**
  - Ax fleet via `-v`.
  - `report.json`/`index.html` output and Faraday export.
  - Notify to Slack/Discord/Telegram.
  - The AI report (`reconftw_ai`) has `AI_REDACT` and `AI_STRICT` modes.

  — [reconFTW](https://github.com/six2dez/reconftw)

**Osmedeus**
- **Version:** v5.1.2 (tags), HEAD 2026-11-06.
- **Workflows:** declarative YAML workflows (modules and flows) with hooks, conditional branching and module exclusion. Runners: host, Docker and SSH. Step types: bash, parallel, foreach, http, **llm, agent** (Claude Code, Codex, OpenCode and Gemini via ACP), SARIF.
- **Scale-out:** Redis master-worker queue with dedup; cloud workers on DO/AWS/GCP/Linode/Azure with cost controls.
- **Scheduling and UI:** cron, file-watch and event triggers; API server with an embedded dashboard; `osmedeus assets --json`.
- **Diff reports between runs are listed as not implemented** on its own roadmap.

  — [Osmedeus](https://github.com/j3ssie/osmedeus)

**reNgine**
- **Architecture:** Django + Celery + Postgres on Docker Compose, with YAML scan engines.
- **Features:**
  - Scheduled and periodic scans with Slack/Discord/Telegram alerts.
  - Subscans on individual assets.
  - Tracking of new and removed subdomains and endpoints.
  - Branded PDF reports.
  - GPT or local-LLM vulnerability write-ups.
- **Latest release:** 2.2.0 (BountyHub for HackerOne sync).
- **Maintenance:** README calls it a spare-time passion project. **HEAD is 2025-11-16 (about a year without commits)**, so treat it as slowing or possibly stale.

  — [reNgine](https://github.com/yogeshojha/rengine)

**Axiom / ax**
- `pry0cc/axiom` HEAD is 2024-09-30, so the original is stale. reconFTW now refers to "Ax (formerly Axiom)". `attacksurge/ax` is active, with HEAD 2026-07-13. — [pry0cc/axiom](https://github.com/pry0cc/axiom); [attacksurge/ax](https://github.com/attacksurge/ax); [reconFTW](https://github.com/six2dez/reconftw)

**Sn1per**
- **Licensing:** the Community edition is "source-available" under a custom EULA, so it is not OSI open source. Professional costs $984/yr per seat; Enterprise is quote-based.
- **Modes:** normal, stealth, airstrike, nuke (incl. brute force), discover, port, web, massweb and vulnscan (OpenVAS).
- **Features:**
  - Workspaces.
  - Scheduled daily/weekly/monthly scans; marketing claims day-over-day comparison.
  - CSV/Excel/PDF and a JSON API.
  - An MCP server (beta, Oct 2026) with scope enforcement and an audit log.
- **Activity:** HEAD 2026-10-27.

  — [Sn1per](https://github.com/1N3/Sn1per)

**ScanCannon v1.9**
- **Pipeline:** masscan sweep, then nmap service/version only on responders. Supports ASN/prefix expansion via whois/RADB with an interactive selection.
- **Change tracking:** "projects with scan-diff" reports new and gone host:port, with timestamped snapshots. Checkpoint skip of completed ranges.
- **Probes and hints:** API detection, cert SAN harvesting, CVE hints via nmap `vulners`, and UDP 53/161/500.
- **Output:** `report.html` + `findings.csv`.
- **Licence and warnings:** CC BY-NC 3.0. It warns that high masscan rates can cause DoS.
- **Activity:** HEAD 2026-07-20.

  — [ScanCannon](https://github.com/johnnyxmas/ScanCannon)

**Raw port scanners**
- masscan HEAD 2026-10-05; RustScan tag 2.4.1, HEAD 2026-11-04; ZMap tag v4.4.0, HEAD 2026-11-06. All maintained. — [masscan](https://github.com/robertdavidgraham/masscan); [RustScan](https://github.com/RustScan/RustScan); [zmap](https://github.com/zmap/zmap)

### Inferences
**Patterns that fit extscan's design**
- **Diffing:** ScanCannon's simple model is the closest fit for extscan's roadmap item 5: new and gone host:port plus changed versions, from timestamped snapshots. reconFTW and Amass add "new findings only" and asset-graph tracking. Both ScanCannon and reconFTW diff on coarse keys (host:port, fingerprints), which supports the roadmap's suggestion to diff on a coarser key than the finding title.
- **Scope distance:** extscan already splits in-scope from out-of-scope subdomains (report, never touch). This is the same idea as BBOT's seeds-vs-targets and scope distance. Adopting the vocabulary would make reports clearer: record a distance or provenance per asset, plus a `report_distance`-style setting.
- **Module safety flags:** BBOT's `passive/active/loud/invasive` flags are a cleaner, testable way to express extscan's safety rules per probe. `tests/test_safety_invariants.py` could assert that no `invasive` probe is registered.
- **Prioritisation:** reconFTW's `hotlist.txt` is similar to extscan's manual review queue, but ranked by asset rather than by finding. A per-host risk rollup in the vault could borrow it.
- **Output sinks:** BBOT's are useful in principle. A stdlib-friendly subset is SQLite (`sqlite3` is stdlib), JSONL and a webhook. These would support roadmap items 12 and 13.

**Poor fits for extscan**
- Fleet scale-out (ax, Osmedeus workers).
- masscan/ZMap-speed scanning. Its DoS risk is flagged by ScanCannon itself.
- reconFTW's spraying, sqlmap and commix stages.
- BBOT's lightfuzz.
- Automatic ASN expansion. It widens scope beyond the signed scope file. At most, report ASN and netblock ownership as "possible additional estate" for the scoping conversation.

**Maintenance cautions**
- reNgine (no commits for about a year) and pry0cc/axiom (stale since 2024) are risky to depend on or copy.
- Sn1per's licence is not open source.

### Gaps
- No primary doc fetched for Amass v5 `track` internals or its scope config keys (domains, cidrs, asns, blacklist).
- No data on BBOT scan-to-scan diff beyond the announced "BBOT Server".
- reconFTW v5 beta's unfinished areas are not listed on the README.
- No reliable comparative performance numbers for masscan vs RustScan vs ZMap vs naabu were sought; not needed for an nmap-centric audit tool.

## Key Question 3: Specialist tools for extscan's gaps

### Takeaway
The highest-value specialist additions are:
- **ssh-audit:** Python, MIT, "no dependencies", JSON output and policy audits. It turns extscan's banner-only SSH probe into an algorithm audit. Its default connection-rate test must be disabled.
- **testssl.sh:** much broader than sslscan. It covers the named TLS vulns, STARTTLS for 13 protocols and SSL Labs-style rating. Its `--phone-out` revocation checks are off unless requested.
- **Takeover fingerprints:** from can-i-take-over-xyz or nuclei takeover templates, to finish roadmap item 6.
- **Secret-pattern rules:** gitleaks or trufflehog *without* verification, run over already-captured bodies.

Fits to avoid or gate:
- cloud bucket brute-forcing (cloud_enum/S3Scanner)
- ffuf/feroxbuster wordlist brute force
- trufflehog's live verification, which sends found secrets to providers
- nmap `vulners` and naabu `-passive`, which send target data to third parties

### Cited Findings
**SSH: ssh-audit** — [ssh-audit](https://github.com/jtesta/ssh-audit)
- **Checks:** audits KEX, host-key, cipher and MAC algorithms with security status; covers OpenSSH/Dropbear/libssh history.
- **Policy features:** built-in and custom policies (`-L`, `-P`, `-M`; exit code 0 on pass); built-in hardening guides.
- **Specific tests and warnings:** Terrapin CVE-2023-48795 test (v3.1.0+); warnings for KEX without post-quantum protection.
- **Output:** JSON (`-j`).
- **Version-based CVE mapping was *removed* in v3.3.0** as "wildly inaccurate".
- **DoS behaviour:** DHEat DoS (CVE-2002-20001) runs only with `--dheat N`. A **connection rate test runs by default**; skip it with `--skip-rate-test`.
- **Release and licence:** v3.9.0 (2026-07-04), HEAD 2026-11-07. MIT; "no dependencies"; Python 3.10–3.14.

**TLS: testssl.sh** — [testssl.sh site](https://testssl.sh/); [testssl.sh repo](https://github.com/testssl/testssl.sh)
- **Vulnerabilities checked:** Heartbleed, CCS, Ticketbleed, ROBOT, Opossum, STARTTLS injection, secure renegotiation, CRIME, BREACH, POODLE, TLS_FALLBACK_SCSV, SWEET32, BEAST, LUCKY13, Winshock, FREAK, LOGJAM, DROWN, RC4.
- **Protocol and cipher checks:** client simulations, forward secrecy, HTTP/2 ALPN and QUIC/HTTP3.
- **Certificate checks:**
  - Trust against 5 root stores.
  - OCSP stapling and Must-Staple, CT and CAA.
  - Revocation and compromised-key checks, **only via `--phone-out`**.
- **HTTP header checks:** HSTS/HPKP and BIG-IP cookie decoding.
- **Rating and STARTTLS:**
  - SSL Labs-style rating.
  - STARTTLS for FTP, SMTP, LMTP, POP3, IMAP, XMPP, XMPP-server, Telnet, LDAP, NNTP, Sieve, PostgreSQL and MySQL.
- **Output and requirements:** flat and pretty JSON, CSV, HTML. Needs only bash and openssl.
- **Licence:** GPL-2.0, and asks for credit when offered as a service.
- **Release status:** stable 3.2.5 reported released 4 Nov 2026; dev branch 3.3dev, with 3.4 planned as the next stable. The site's own pages are inconsistent about which 3.2.x is current.
- **sslscan:** still maintained (tag 2.2.3, HEAD 2026-11-07). The repo was not read in detail, so no feature-by-feature comparison to testssl.sh was sourced. — [sslscan](https://github.com/rbsec/sslscan)

**Subdomain takeover**
- **can-i-take-over-xyz:** lists services with Vulnerable / Not vulnerable / Edge case status. Fingerprints are a page string/regex or `NXDOMAIN`, with CI verification of fingerprints, and an auto-generated `fingerprints.json`. — [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- **subjack:** tag v3.1.0, HEAD 2026-10-20, so it appears revived. — [subjack](https://github.com/haccer/subjack)
- **Other tools:** reconFTW uses nuclei and dnstake for takeovers. — [reconFTW](https://github.com/six2dez/reconftw)

**Cloud bucket and storage enumeration**
- **cloud_enum:**
  - Brute-forces keyword mutations with DNS and HTTP against S3, Azure storage/blob/DB/VMs/web apps and GCP buckets/Firebase/App Engine/Functions.
  - Defaults to 1.1.1.1 as resolver.
  - Its author says it is not actively used, only bug-fixed, and plans to move the functionality into nuclei templates.
  - HEAD 2026-10-04; MIT.

  — [cloud_enum](https://github.com/initstring/cloud_enum)
- **S3Scanner:** tag v3.1.1, HEAD 2026-07-13. — [S3Scanner](https://github.com/sa7mon/S3Scanner)

**Screenshots**
- **gowitness 3.x:** — [gowitness](https://github.com/sensepost/gowitness)
  - Uses headless Chrome (chromedp/go-rod) and takes Nmap and Nessus XML as input.
  - Saves request and console logs, headers and cookies.
  - Writes SQLite/JSONL/CSV, with a web viewer and API.
  - Credits wappalyzergo and goimagehash. Their exact use isn't documented on the page, but presumably they power tech detection and perceptual-hash grouping.
  - Tag 3.2.2, HEAD 2026-10-11.
- **EyeWitness:** last tag 20230525.1, HEAD 2026-01-05. — [EyeWitness](https://github.com/RedSiege/EyeWitness)
- **aquatone:** HEAD 2019-05-19, last tag v1.7.0-beta.2, so **unmaintained**. — [aquatone](https://github.com/michenriksen/aquatone)

**Tech fingerprinting**
- **Wappalyzer went closed/private in 2023.** Sources disagree on the date: May vs August 2023.
- **enthec/webappanalyzer** says it is a continuation that keeps the same JSON format.

  — [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer); [dev.to post (promotional)](https://dev.to/nexgendata/wappalyzer-paywalled-itself-in-2023-heres-the-oss-powered-replacement-3i01)
- **Other implementations:**
  - webanalyze: tag v0.4.6, HEAD 2026-09-19. — [webanalyze](https://github.com/rverton/webanalyze)
  - wappalyzergo: tag v0.3.9, HEAD 2026-11-08. — [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)
  - BBOT 3.0 removed its wappalyzer module. — [BBOT 3.0 blog](https://blog.blacklanternsecurity.com/p/bbot-30)

**Content discovery**
- ffuf: tag v2.3.0, HEAD 2026-09-26. feroxbuster: tag v2.13.1, HEAD 2026-11-07. Both are actively maintained. — [ffuf](https://github.com/ffuf/ffuf); [feroxbuster](https://github.com/epi052/feroxbuster)
- reconFTW uses ffuf and `shortscan`. The IIS 8.3 short-name oracle that extscan already checks is the same class. — [reconFTW](https://github.com/six2dez/reconftw)

**Secrets**
- **trufflehog:**
  - "Over 800 secret types". By default it **verifies by logging in to the provider** to confirm liveness; `--no-verification` disables this.
  - `analyze` enumerates a credential's permissions.
  - Sources include git, filesystem and stdin.
  - Output: JSON and SARIF.
  - **AGPL-3.0**. Tag v3.99.8, HEAD 2026-11-05.

  — [trufflehog](https://github.com/trufflesecurity/trufflehog)
- **gitleaks:** tag v8.30.1, HEAD 2026-10-23. — [gitleaks](https://github.com/gitleaks/gitleaks)

**CVE mapping**
- **nmap-vulners:** tag v2.0.2, HEAD 2026-11-02, so maintained. It queries the vulners.com service, which is why extscan excludes the `external` NSE category, including `vulners`. — [nmap-vulners](https://github.com/vulnersCom/nmap-vulners); extscan `README.md` (Safety properties)
- **Other tools that use it:** ScanCannon (`-V`) and reconFTW both use `vulners` for CVE hints. — [ScanCannon](https://github.com/johnnyxmas/ScanCannon); [reconFTW](https://github.com/six2dez/reconftw)
- **Nuclei templates:** 3,587 `cve`-tagged and 1,496 KEV templates. — [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- **cvemap:** tag v2.0.2, HEAD 2026-10-26. — [cvemap](https://github.com/projectdiscovery/cvemap)

**WAF detection**
- reconFTW uses `wafw00f` plus `cdncheck`. — [reconFTW](https://github.com/six2dez/reconftw)
- naabu `-exclude-cdn` and httpx `-cdn` are on by default in httpx. — [naabu](https://github.com/projectdiscovery/naabu); [httpx](https://github.com/projectdiscovery/httpx)

### Inferences
**Worth adopting**
- **ssh-audit as an optional SSH probe:**
  - Call it like sslscan, as an optional external tool with a Degradation when missing.
  - Fixed argv: `-j --skip-rate-test`, never `--dheat`.
  - Add a safety-invariant test asserting `--dheat` never appears and `--skip-rate-test` always does.
  - It is Python and MIT, so it could even be vendored, but calling it as a subprocess keeps extscan's dependency story clean.
  - Its removal of version-based CVE mapping is a useful signal: version-to-CVE guessing is noisy, so prefer nuclei CVE templates (which verify) over vulners-style version hints.
- **testssl.sh as the primary cipher audit, with sslscan as fallback:**
  - Gains ROBOT, Ticketbleed, Opossum, DROWN, LOGJAM etc. and STARTTLS on mail, LDAP and DB ports.
  - Its rating gives auditors a single headline grade.
  - Keep `--phone-out` off: it contacts OCSP/CRL and compromised-key services, which are third-party, consistent with the policy on the `external` category.
  - Its JSON output is easy to parse.
- **Takeover fingerprint matching:** vendor `fingerprints.json` from can-i-take-over-xyz as data, refreshed at release. Match dangling or live CNAME targets, then make one GET to an in-scope name to check the marker. This finishes roadmap item 6's "Left" item without a new runtime dependency. The licence of that data was not checked.
- **Secret detection on captured content:** port a subset of gitleaks' regex rules into extscan's chase of exposed files, JS and responses, with no verification. trufflehog's default verification sends discovered credentials to third-party APIs. That conflicts directly with extscan's "secrets do not leave the engagement" rule, and AGPL is a licence concern for vendoring. If used at all: `--no-verification`, run on saved bodies via `filesystem`.

**Avoid or gate**
- **cloud_enum / S3Scanner:** keyword-mutation brute force against provider namespaces. The buckets found may not belong to the client and are not in the scope file's IPs. Not a fit by default; at most a scope-file-authorised, opt-in mode. A safer variant is checking only bucket hostnames already referenced by in-scope DNS, CNAMEs or page content.
- **ffuf / feroxbuster:** loud by design. extscan's ~23-path list plus nuclei `exposure`/`panel` templates covers the high-yield part. A small curated list at a low rate may be acceptable under a `loud` flag, never by default.
- **Screenshot tools:** gowitness's perceptual-hash grouping and Nmap-XML input match extscan's contact-sheet goal. extscan already has Playwright with per-request scope checks, which gowitness lacks according to its README. The idea to borrow is grouping near-identical screenshots, not the tool.

### Gaps
- No feature-by-feature primary comparison of sslscan 2.2.x vs testssl.sh: the sslscan README was not fetched.
- gitleaks rule count and licence not fetched. MIT is from memory and not verified this session.
- The licence of can-i-take-over-xyz `fingerprints.json` was not checked.
- ssh-audit's "connection rate test" behaviour (how many connections, how disruptive) is not described on the page.
- onesixtyone and other SNMP tools were not researched. extscan's built-in SNMP client already covers community checks.
- S3Scanner features not read.
- EyeWitness feature set not read.
- No current source on the nuclei takeover template count.

## Key Question 4: Which patterns fit a stdlib-only, safety-first, auditor-focused tool?

### Takeaway
Good fits are features that are deterministic, low-traffic, read-only, and keep data inside the engagement. Most can be stdlib Python or an optional external tool that degrades to a coverage gap. Poor fits are breadth-maximising bug-bounty features: brute force, fleets, passive third-party lookups that leak target data, fuzzing, credential verification, and auto scope expansion.

### Cited Findings
- **Data that leaves the engagement:** several tools' defaults or optional flags send target data off-box — nuclei `-ai`/`-dashboard` (PDCP), naabu `-passive` (Shodan InternetDB), nmap `vulners` (vulners.com), trufflehog default verification (provider APIs), testssl `--phone-out`, BBOT ASN targets (ASNDB API), cloud_enum's default resolver 1.1.1.1. — [nuclei README](https://github.com/projectdiscovery/nuclei/blob/dev/README.md); [naabu](https://github.com/projectdiscovery/naabu); [nmap-vulners](https://github.com/vulnersCom/nmap-vulners); [trufflehog](https://github.com/trufflesecurity/trufflehog); [testssl.sh](https://testssl.sh/); [BBOT 3.0 blog](https://blog.blacklanternsecurity.com/p/bbot-30); [cloud_enum](https://github.com/initstring/cloud_enum)
- **Intrusive stages in mainstream recon frameworks:**
  - reconFTW: brutespray/brutus password spraying, sqlmap, commix.
  - Sn1per: nuke mode with brute force.
  - BBOT: lightfuzz with OOB SSRF.
  - ScanCannon: warns masscan can DoS targets.

  — [reconFTW](https://github.com/six2dez/reconftw); [Sn1per](https://github.com/1N3/Sn1per); [BBOT 3.0 blog](https://blog.blacklanternsecurity.com/p/bbot-30); [ScanCannon](https://github.com/johnnyxmas/ScanCannon)
- **Diff and monitoring:** offered by reconFTW (DIFF, incremental, monitor), ScanCannon (scan-diff), Amass (`track`), reNgine and PDCP (commercial). Missing from Osmedeus (roadmap "not implemented") and not documented for BBOT OSS. — sources as above

### Inferences

#### Feature comparison matrix (extscan vs leading tools)
| Capability | extscan today | Who does it well | Fit for extscan |
|---|---|---|---|
| Port discovery | nmap TCP/UDP, checkpointed batches, salvage partial XML | naabu (SYN/UDP, `-exclude-cdn`, passive), RustScan/masscan/ZMap (speed), ScanCannon (masscan→nmap) | Keep nmap. Borrow naabu's CDN-aware port limiting as policy. Skip mass-speed scanners |
| Service/version + CVE hints | nmap -sV + NSE default,safe,vuln; `external` (vulners) excluded | nmap vulners, nuclei CVE/KEV templates (3,587 / 1,496) | Keep excluding vulners by default. Lean on nuclei CVE/KEV, which verifies rather than guessing from versions (cf. ssh-audit dropping version-based CVE mapping) |
| Web tech fingerprinting | Root page, headers, server banner | httpx `-td`, wappalyzergo, webanalyze, enthec/webappanalyzer JSON, nuclei `-as` | **Adopt.** Stdlib matcher over Wappalyzer-format JSON, or run nuclei tech templates already present |
| Favicon hash | None | httpx `-favicon` (mmh3) | **Adopt.** Pure-Python mmh3; useful for spotting default appliances and pivoting |
| JARM / TLS fingerprint | None | httpx `-jarm` | Low priority; needs raw ClientHello crafting |
| CDN/WAF detection | None (roadmap 9) | cdncheck, httpx `-cdn`, wafw00f | **Adopt as a coverage-gap signal.** Vendored ranges, plus block-page and 429 heuristics → Degradation "results behind WAF/CDN may be incomplete" |
| Near-duplicate/page-type triage | Screenshots only | httpx `-fd`, `-fpt`/`-kb`; katana `-pcs`; gowitness image hashing | **Adopt.** Simhash of body + perceptual grouping in the vault: "these 14 services serve the same default page" |
| Virtual hosts / SNI | None (roadmap 2) | httpx `-vhost`, `-sni`; BBOT vhost; reconFTW VhostFinder | Adopt (already planned) with scope gating per name |
| Crawling / JS endpoints | OpenAPI/GraphQL chase, ~23 paths | katana (`-jc`, `-kf`, `-fx`), jsluice, BBOT spider preset | Partial: robots.txt + sitemap.xml + same-origin JS endpoint regex, depth 1, GET-only; no form fill |
| Content discovery | ~23 curated paths with soft-404 filter | ffuf, feroxbuster | Gate behind a "loud" flag only |
| TLS audit | Built-in cert/version + sslscan; testssl.sh fallback | testssl.sh (vulns, STARTTLS x13, rating) | **Promote testssl.sh** to primary optional tool; no `--phone-out` |
| SSH audit | Banner + version | ssh-audit (algorithms, policies, Terrapin, JSON) | **Adopt** as optional tool with `--skip-rate-test`, never `--dheat` |
| Subdomain enumeration | CT + subfinder/amass, in/out-of-scope split | subfinder, amass v5, BBOT, alterx permutations | Mostly covered. Permutations (alterx) = active brute force → keep off by default |
| Takeover | Dangling CNAME/MX/NS from DNS | can-i-take-over-xyz fingerprints, nuclei takeover templates, subjack | **Adopt** fingerprint data → one GET to in-scope name |
| Cloud assets | Provider-suffix tagging of dangling CNAMEs | cloud_enum, S3Scanner | Only for hostnames already referenced by in-scope assets; no name brute force |
| Secrets in exposed content | Shows `.env`/secret files raw | gitleaks rules, trufflehog | Port regex rules, no verification |
| Scope model | Scope file + per-request checks, out-of-scope reported not touched | BBOT targets/seeds/blacklist/scope distance | Already strong. Add a scope-distance/provenance field per asset |
| Module safety classes | Policy exclusions + safety tests | BBOT flags safe/passive/active/loud/invasive | **Adopt** as metadata on each probe, enforced in tests |
| Run diff / monitoring | None (roadmap 5, 12) | ScanCannon scan-diff, reconFTW DIFF/monitor, Amass track, reNgine | **Adopt** ScanCannon-style host:port + version + finding-key diff over report.json |
| Output sinks | report.md, report.json, Obsidian vault | BBOT (SQLite/Postgres/Neo4j/Elastic/Splunk/webhook), gowitness SQLite, Sn1per PDF/CSV | SQLite (stdlib) + JSONL; maybe SARIF-like export |
| Distributed / fleet | None (roadmap 15) | ax, Osmedeus workers, reconFTW `-v` | Not a fit |
| AI | Optional, hostile-input fenced, info-only, redacted | reconFTW_ai (redact/strict), Osmedeus agent steps, nuclei `-ai` (cloud), Sn1per MCP | extscan's design is already more conservative. Sn1per's MCP "scope enforcement + audit log" mirrors roadmap 11 |
| Coverage-gap accounting | First-class Degradation | Rare. No surveyed tool documents an equivalent | extscan's differentiator. Extend to nuclei `-mhe` host skipping |

#### Prioritised adoption list
1. **Nuclei hygiene:**
   - Bump the pin from 3.4.10 to ≥3.8.0 (ideally 3.11.x) for the 2026 CVE fixes.
   - Handle `-max-host-error` skipping as a Degradation, via `-nmhe` or by parsing stats.
   - Keep `-ai`/`-dashboard` blocked by policy tests.
2. **Run diff:** coarse keys (host, port, proto, service name/version, finding template-id) over two `report.json` files. Patterned on ScanCannon and reconFTW.
3. **Web fingerprint pack:** favicon mmh3, tech detection from Wappalyzer-format JSON (or nuclei tech templates), body simhash dedupe and page-type grouping in the vault.
4. **WAF/CDN detection as coverage gaps:** vendored provider ranges plus response heuristics.
5. **ssh-audit and testssl.sh** as optional external tools with safety-pinned argv.
6. **Takeover fingerprints** from can-i-take-over-xyz to finish roadmap item 6.
7. **Secret regex rules** (gitleaks-derived) over captured content, never verified.
8. **BBOT-style probe safety flags and scope distance**, enforced in `tests/test_safety_invariants.py`.
9. **Light crawl:** robots/sitemap/JS endpoint extraction, depth-bounded, GET-only, scope-checked per URL.

Why extscan should not become BBOT or reconFTW: its value is that a signed report is trustworthy — scope enforced per request, nothing leaves the engagement, and gaps are explicit. Every surveyed framework optimises for coverage breadth and leaves those guarantees to the operator.

### Gaps
- **Not verified in sources:**
  - That a pure-Python mmh3 matches Shodan's favicon hash convention.
  - The exact effect of nuclei's `-nmhe` on scan time.
- **No measurements:**
  - False-positive rates of cdncheck or wafw00f.
  - Template-level detail of nuclei's tech detection versus Wappalyzer fingerprints.
- **Licences not checked:** enthec/webappanalyzer fingerprint data, can-i-take-over-xyz data and the gitleaks rules. Vendoring any of them needs a licence check.
