# Closing extscan's blind spots without breaking its rules

extscan is strongest where comparable tools are weakest: evidence, scope guarding and honest coverage gaps. Its biggest shortfalls are in enrichment and context. It has no KEV or EPSS ranking, and its protocol checks mostly flag a port without proving anything. It does no DNS-layer, email or IPv6 work, and it never looks past a web service's root page. It has no memory of findings between runs. The best value-for-effort ideas are mostly passive or single-request. They are: KEV and EPSS enrichment, an edge-device inventory, a small DNS client for mail and zone posture, handshake-level proof for databases and remote-access services, read-only web misconfiguration checks, and a persistent accepted-risk and finding-lifecycle file. Two safety questions about the current tool come first and should be settled before any new feature: the NSE `vuln` category, and the quick profile's nuclei severity filter. Most research claims below come from tool READMEs and vendor docs. Where a claim rests on practitioner background that the researchers could not verify, this report says so. Each idea is marked safe (fits the rules as written), needs care (fits with stated constraints) or conflict (breaks a rule and should not be automated). Ideas already in `docs/ROADMAP.md` or `todo.md` are marked "planned". Nothing here is implementation detail.

## Two safety findings about the current tool, before any new features

**NSE `vuln` category.** The default nmap script selection is `default,safe,vuln`. The exclusion list removes only `dos`, `external` and `http-slowloris-check` (`extscan/policy.py`). The code comment itself says `dos` scripts "sit in `vuln`". The `intrusive` and `exploit` categories are not excluded, and neither are `auth` or `brute`. nmap's own `smtp-open-relay` is categorised `discovery, intrusive, external` ([nsedoc](https://nmap.org/nsedoc/scripts/smtp-open-relay.html)), and `ipmi-cipher-zero` is `vuln, safe` ([nsedoc](https://nmap.org/nsedoc/scripts/ipmi-cipher-zero.html)). Both show that categories overlap in ways that make "safe" an unreliable label. The research notes also suggest, from unverified background, that some RDP and SMB `vuln` scripts send crafted packets. Nobody has actually listed which scripts the combined selection resolves to. The cheap fix is to run `nmap --script-help "default or safe or vuln"` and diff the result against an allow-list. Then either add `intrusive` and `exploit` to the exclusions or pin an explicit script list, and add a test in `tests/test_safety_invariants.py`. The notes rate this the most important process item for the network domain, and it is a safety property of the shipped tool, not a feature request.

**Quick profile drops info-level detections.** The quick profile sets nuclei severities to medium, high and critical (`extscan/policy.py`, `for_profile`) and narrows nmap scripts to `default,safe`. Nuclei's panel and technology-detection templates are mostly info-level: the `panel` tag alone covers about 1,365 templates ([nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)). A quick run can therefore report no admin panels and no technology fingerprints, and the report reads as clean. This contradicts the rule that reduced coverage must never look clean. The notes said both quick and standard filter to medium and above. The code shows only quick does: the default severity list includes info. The fix is either to record the severity filter as a `Degradation` whenever it is narrower than the default, or to run a separate info-level pass restricted to panel, tech and exposure tags. The standard profile needs no change.

## Asset discovery and recon: the scope list is never questioned

extscan takes a signed scope and enumerates inside it. Leading tools also ask what else the client owns, and they attach an evidence trail to each answer. Censys describes a discovery trail explaining why an asset was attributed to an organisation ([Censys](https://censys.com/?p=1361), secondary). Every idea in this area produces candidates for client confirmation and must never feed the scanner automatically. extscan already treats out-of-scope subdomains this way, so the pattern exists.

| Idea | Status | Label | Value / effort |
|---|---|---|---|
| Wildcard-DNS detection before accepting resolved names (dnsx has it: [dnsx](https://github.com/projectdiscovery/dnsx)) | new | safe | Medium-high / low. Also a coverage-honesty fix |
| Passive port cross-check against Shodan InternetDB per scope IP; ports seen there but not by nmap become a gap, not a finding | new | needs care: sends client IPs to a third party, so gate behind a policy flag and log it; InternetDB is free for non-commercial use only ([InternetDB](https://internetdb.shodan.io/)) | High / low |
| Takeover check incl. dangling NS and MX, with a vendored fingerprint list | planned (#6) | safe if report-only; claiming a resource is a conflict ([can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)) | High / low-medium |
| Reverse-DNS (PTR) sweep of in-scope CIDRs; stdlib `gethostbyaddr` suffices; feeds vhost enumeration | new, supports planned #2 | safe | Medium-high / low |
| AAAA lookup for in-scope names, scan the v6 addresses, diff open ports v4 against v6 | new | needs care: v6 addresses found by DNS may be unlisted, so require them in scope or an explicit flag | Medium-high / low. Whether `scope.py` handles IPv6 is unchecked |
| ASN and netblock attribution (asnmap needs a PD Cloud token: [asnmap](https://github.com/projectdiscovery/asnmap)) to list candidate ranges | new | safe as a candidate list, never auto-scoped | High for scope completeness / medium |
| Certificate pivot: other hosts sharing a scope cert or Subject O | new, extends planned #4 | safe | High / low-medium |
| CDN/cloud/WAF tagging from published ranges ([cdncheck](https://github.com/projectdiscovery/cdncheck)); skip port-scanning CDN edges | new | safe | Medium-high / low |
| Wayback and URLScan URL harvest feeding the existing `chase` stage | new | safe; archived does not mean exposed | Medium-high / low |
| Cloud bucket permutation from the client name (cloud_enum: [cloud_enum](https://github.com/initstring/cloud_enum)) | new | needs care: guesses also hit strangers' buckets, so keep list-only, report only with ownership evidence, never download | Medium-high / medium |
| GitHub code search for client domains | new | needs care: it will find live secrets and personal data; hand them to a human and never run trufflehog's verification | Medium-high / medium |
| Origin-IP discovery behind a CDN | new | needs care: connecting to a candidate IP may be out of scope | Medium / medium |
| Favicon-hash and reverse-WHOIS pivots | new | safe but noisy | Medium / medium |
| Cloudlist (cloud accounts via client credentials) | new | **conflict** with no credentials; also relates to planned #8 | defer |
| Default active subdomain brute force | listed as deliberately not planned | conflict with the stated default | none |

The reasoning behind the first row: nmap can miss a port through filtering, rate limits or the quick profile, and a dataset that disagrees is cheap evidence of reduced coverage. The notes caution that dataset results go stale and can describe a different tenant after IP churn, so they are leads and never proof. The origin-discovery and favicon-pivot claims come from HackTricks-style write-ups and vendor blogs, which the notes call secondary. No effectiveness numbers were found for either.

## Web and API checks: the root page is as far as extscan looks

The scanner fetches a root page, 22 fixed disclosure paths and a handful of chase handlers (OpenAPI, GraphQL introspection, one unauthenticated API GET). APIs referenced only from JavaScript bundles are invisible. The notes treat bounded crawling with JS analysis as the largest functional gap. Most other ideas are single requests.

| Idea | Status | Label | Value / effort |
|---|---|---|---|
| KEV and EPSS enrichment of every CVE-bearing finding, sorting the review queue KEV first, then EPSS, then CVSS | new | safe: bulk-download the feeds once per run and store the fetch date; never send hostnames. KEV is published as JSON and CSV ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)); EPSS predicts 30-day exploitation ([DefectDojo EPSS/KEV](https://docs.defectdojo.com/triage_findings/epss_kev/), secondary) | High / low-medium |
| Edge-device and admin-panel signature inventory (login portals, Exchange, Jenkins, Grafana, Tomcat Manager) reported as "reachable, owner and MFA?" without submitting any form | new | safe; 401 and 403 count as present. Paths are practitioner knowledge, to be checked against nuclei's exposed-panels templates | High / low |
| CORS reflection, `null` origin and credentials (three GETs; [PortSwigger](https://portswigger.net/web-security/cors)) | new | safe; flag only when credentials are allowed or sensitive data returns | High on APIs / low |
| Cookie flags, HSTS and CSP quality, missing HTTP-to-HTTPS redirect, security headers on plain-HTTP services (currently TLS only) | new | safe; restrict cookie severity to session-like names | Medium / low |
| OIDC, OAuth and JWKS metadata reads; flag advertised `none`/HS256 algorithms, missing S256 PKCE, and private-key members in JWKS (critical) | new | safe for GETs; forging or replaying tokens is a conflict | Medium-high / low |
| More spec and doc paths: WSDL, Postman collections, Swagger variants, OData `$metadata` | new | safe | Medium / low |
| Verbose-error and debug-console detection from harmless malformed GETs (Werkzeug console, Laravel Ignition, Symfony profiler) | new | safe-to-needs care: no injection payloads | High / low |
| Technology inventory from headers, cookies, favicon hash and JARM; optional httpx ([httpx](https://docs.projectdiscovery.io/opensource/httpx/usage)) | new | safe | Medium / low-medium |
| Passive WAF/CDN detection, with challenge pages recorded as a `Degradation` | planned (#9) | safe; wafw00f's second stage sends malicious-looking requests, so needs care ([wafw00f](https://github.com/EnableSecurity/wafw00f)) | High / medium |
| GraphQL beyond introspection: "Did you mean" suggestion leakage, IDE exposure, a two-alias batching probe, GET support | new | safe at tiny scale; scaled batching or deep nesting is a conflict | Medium / low |
| Bounded crawl (depth 2, about 200 pages, low rate, same host) plus JS endpoint, secret and source-map extraction | new | needs care; never use form auto-fill ([katana flags](https://docs.projectdiscovery.io/opensource/katana/usage)) | High / medium |
| Open-redirect `Location` check; cache-header analysis | new | needs care: use a unique cache-buster | Medium / medium |
| HTTP method checks and auth-bypass header variants | planned (#3) | safe for GET, OPTIONS, TRACE, HEAD; PUT or DELETE is a conflict | Medium-high |
| Request smuggling probes | new | **conflict**: PortSwigger says the timing test can disrupt other users ([PortSwigger](https://portswigger.net/web-security/request-smuggling/finding)); at most a passive hint plus a manual-review item | none |
| Live secret verification (trufflehog's default) | new | **conflict**: it sends found credentials to the provider ([trufflehog](https://github.com/trufflesecurity/trufflehog)); use `--no-verification` or regexes and let the human judge | none |
| Form auto-fill, password-reset poisoning, GraphQL mutations, SSRF out-of-band callbacks, rate-limit bursts | new | **conflict** (writes or disruption) | none |

The API picture is bounded by the OWASP API Top 10 ([OWASP](https://api-security.owasp.org/editions/2023/en/0x11-t10)). Broken object- and function-level authorisation (API1, API3, API5, API6) needs sessions or writes and cannot be tested within the rules. The automatable part is inventory (API9) and misconfiguration (API8). For the logic-heavy categories the best extscan can do is raise a manual-review prompt. The WSTG test IDs in the notes were not verified, so none are cited here.

## Network, edge-device and email services: flag-by-port becomes proof

extscan's `SENSITIVE_TCP` table marks databases and remote-access ports critical by number alone. The ROADMAP lists protocol probes (#10) and email posture (#7), but the probes are not built, and the SMTP, DNS and IKE paths have no probe at all.

**Edge devices.** The case for an edge inventory is strong. CISA's KEV grew by 245 entries, or 20%, in 2025, to 1,484 ([SecurityWeek](https://www.securityweek.com/cisa-kev-catalog-expanded-20-in-2025-topping-1480-entries/), secondary). Reported 2025 entries include Citrix NetScaler, Fortinet, Cisco ASA, Ivanti and SonicWall products. Per-vendor counts conflict between aggregators, so none are quoted here. Nuclei ships 454 CISA-KEV templates and 1,449 VulnCheck-KEV templates ([nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)). A detection-only `-tags kev` pass reported in a "KEV-tagged hits" section is high value and low effort. It needs care because some KEV templates are exploit-adjacent: the CitrixBleed 2 check triggers a memory over-read, so the evidence could contain live session tokens. Run such templates only behind a per-template allow-list. Anything that sends exploit payloads is a conflict.

Two limits belong in the report text. First, external scanning cannot show that a patched edge device is uncompromised. CISA's Cisco directive requires core dumps for compromise detection ([CISA ED 25-03](https://www.cisa.gov/news-events/directives/ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices)), so extscan should state this as a limitation instead of implying a clean result. Second, version-to-CVE mapping from banners is unreliable. ssh-audit removed it in v3.3.0 because it was "wildly inaccurate" ([ssh-audit](https://github.com/jtesta/ssh-audit)), so any mapping should be marked tentative. Hash-based Fortinet build fingerprinting is possible ([DIVD](https://vintage.divd.nl/2022/12/26/dissecting-fortigate-images-for-fun-and-no-profit)), but it needs a maintained hash table.

| Idea | Status | Label | Value / effort |
|---|---|---|---|
| ssh-audit as an optional adapter: `-j --skip-rate-test`, with `--dheat` banned by a safety test ([ssh-audit](https://github.com/jtesta/ssh-audit)) | new | safe | High / low-medium |
| Parse `rdp-enum-encryption` (NLA not required, weak encryption) ([nsedoc](https://nmap.org/nsedoc/scripts/rdp-enum-encryption.html)) and SMB signing and SMBv1 results | new, part of planned #10 | safe; the SMB script categories are unverified background | High / low |
| Unauthenticated-access proof: Redis PING, Elasticsearch `/_cat` counts, Docker `/version`, kubelet `/pods`, ZooKeeper `ruok`; pre-auth banners for MySQL, Postgres, MSSQL | new, part of planned #10 | safe to needs care: count or name items, never fetch documents; categories unverified | High / medium |
| SMTP probe: banner, EHLO, STARTTLS and cert, AUTH-before-TLS, VRFY capability advertised | new | safe | High / low |
| TLS audit on STARTTLS ports (SMTP, IMAP, POP3); extscan today calls only sslscan though README lists testssl.sh as optional | new | safe; Heartbleed-class checks send crafted packets, so toggle them | Medium / medium |
| MX, SPF, DMARC, MTA-STS, TLS-RPT, DANE, CAA, DNSSEC, `security.txt` via a small hand-written DNS client or `dig` | planned (#7) for mail, new for the rest | safe; the stdlib cannot query TXT, so this dependency decision is most of the cost | High / medium |
| Open-recursion and AXFR checks on in-scope name servers | new | safe-to-needs care: gate AXFR on the NS IPs being in scope; no amplification measurement | Medium / low |
| IKE main-mode vendor and transform fingerprint ([ike-scan](https://github.com/royhills/ike-scan)) | new | safe | High for VPN estates / medium |
| Single-packet amplification factor (request versus response bytes) for NTP, SSDP, mDNS, memcached | new | safe at one probe per host | Medium / low |
| SMTP open-relay test, RCPT-only with no DATA | new | needs care: reviewed custom code, never the stock script | Medium / medium |
| WinRM (5985/5986), AJP 8009, Smart Install 4786 and other ports missing from the table | new | safe; the port list is unverified background | Medium / low |
| Scan-accuracy handling: UDP `open\|filtered` as a gap, tarpit ceilings, scanner egress IP recorded | new | safe | Medium / low-medium |
| IKE Aggressive-Mode PSK hash capture, IPMI RAKP hash retrieval, SIP extension enumeration and RabbitMQ default guest login | new | **conflict** (credential testing); report the exposure and leave the manual step to a human | none |

The scan-accuracy row matters for the project's core rule. Treating UDP `open|filtered` as neither open nor closed, and recording it as a gap with a service-specific retry, follows the principle directly. The nmap rate-limit details in the notes are uncited background.

## Workflow, prioritisation and reporting: strong evidence, no memory

The open-source tools split into recon orchestrators (BBOT, reNgine) and finding managers (DefectDojo, Faraday, Greenbone). extscan has the evidence and gap honesty the managers lack, and none of the lifecycle state they have. Greenbone models overrides, tickets and a Fixed-verified status set by a clean rescan ([Greenbone](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html)). DefectDojo auto-marks findings that match earlier false-positive triage ([DefectDojo](https://docs.defectdojo.com/triage_findings/)). Diffing without that state would re-raise every known false positive each quarter, so lifecycle should come before, or with, planned run diffing (#5).

| Idea | Status | Label | Value / effort |
|---|---|---|---|
| Persistent per-client `accepted.json`: fingerprint, reason, approver, expiry; suppressed items stay in an appendix so nothing disappears silently | new | safe | High / medium |
| Run diff with New, Gone, Same, Changed and a fifth "not re-checked" state tied to the coverage-gap model, so a failed tool never reads as fixed | planned (#5), the fifth state is new | safe | High / medium |
| `retest` mode that re-runs the exact check behind each prior finding and records fixed, partially fixed, still open or could not retest | new | safe; must re-check the authorisation window | High / medium |
| Evidence manifest: SHA-256 of raw tool output, UTC timestamps, scanner source IP | new | safe | Medium / low |
| SARIF and DefectDojo generic-import JSON plus CSV export; the DefectDojo schema was not fetched, so check it first | new, adjacent to planned #14 | safe | Medium-high / low |
| Deterministic executive summary, severity rubric and document-control block, remediation roadmap grouped by fix action | new | safe | Medium-high / low-medium |
| Per-target criticality, owner and environment fields in the scope file feeding priority and routing | new | safe | Medium / low |
| Stop file, automatic stop at `window_end`, back-off on 429s and resets | new, back-off overlaps planned #9 | safe | Medium / low |
| Scanner identity header and a one-page SOC scan notice, as a policy option because attribution lets a WAF block the scan | new | safe | Medium / low |
| Slack or Teams webhook with counts and IDs only, never evidence | new | needs care | Low-medium / low |
| Opt-in client-facing render with reviewer sign-off per finding | new | needs care: a separate optional output, not a fix. extscan deliberately leaves secrets unredacted in working reports so a human can judge whether they are live, expired or examples | Medium / medium |
| Scheduling and continuous monitoring | planned (#12) | needs a standing-authorisation model | Medium |
| Findings database across engagements | planned (#13) | needs care: client separation and retention | Medium |
| DOCX or PDF output | planned (#14) | safe; timebox it | Low-medium |
| Authenticated scanning | planned (#8) | **conflict** with no credential testing | defer |
| Agentic probe selection | planned (#11) | needs care: a closed allow-list enforced in code | defer |
| Anything labelled PCI ASV compliant | new | **conflict**: ASV reports are a regulated product only ASVs may issue ([Sikich](https://www.sikich.com/insight/vulnerability-scanning-scope-asv-program-guide-sampling/), secondary) | none |

On LLM use, the evidence base is thin: the notes found one preprint arguing AI security tools can be hijacked by prompt injection from target content ([arXiv 2508.21669 summary](https://www.emergentmind.com/papers/2508.21669)) and otherwise vendor claims and secondary roundups. The existing design matches that caution: model output is pinned to info, hostile text is fenced, and evidence is redacted before it is sent to the provider. That redaction stays. One small addition is a report line recording whether evidence left the environment. Low-risk model uses are drafting executive-summary prose and clustering reworded titles for diffing, each labelled as a draft for human review.

## Where to start

Three batches fall out of the value-and-effort ratings. The first is the two safety audits above, plus KEV and EPSS enrichment, the nuclei KEV pass behind an allow-list, wildcard detection, the SMTP probe, the ssh-audit adapter and parsing of the RDP and SMB script output already available. These are small, mostly offline or single-request, and fix the most misleading outputs. The second batch is the DNS client (which unlocks planned #7 plus CAA, DNSSEC, AXFR and open recursion), handshake proof for databases and orchestration APIs, the web misconfiguration set, finding lifecycle with diffing and retest, and the evidence manifest and export formats. The third is the larger or riskier work: the bounded crawl with JS analysis, bucket and GitHub lookups, origin discovery, IPv6 parity and scheduling.

Several of the notes' headline items rest on unverified material. Per-product edge paths, nmap script categories for SMB, RDP, NTP and DNS, and the extended port list are practitioner background. The notes also could not retrieve CREST, NCSC CHECK or the PCI ASV primary text, or FIRST's EPSS pages, and found no benchmarks of LLM triage accuracy or of ASM tools against each other. Validate each against nsedoc or the vendor source before building.

## Conclusion

The research changes the framing of "what is missing". The largest gap is not another scanner. It is context and memory: whether a CVE is being exploited, whether a finding is new or already accepted, and whether a missing result means a clean target or a blocked probe. Nearly every high-value idea adds that context from public feeds or single read-only requests, so most fit the existing rules without strain. The recurring conflict cases (hash capture, secret verification, bucket claiming, mutations, smuggling) share one pattern. Each can be replaced by reporting the exposed condition and leaving the confirming step to a human, which is what the tool's human-in-the-loop design already assumes.

The sharpest finding is that the tool's own safeguards need the same scrutiny it applies to targets. An NSE selection that excludes only `dos`, and a quick profile that can omit panel detection without saying so, are the places where coverage or safety could be misrepresented today. Auditing those costs less than any feature above.
