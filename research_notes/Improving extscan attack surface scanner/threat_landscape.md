# Threat landscape and EASM coverage: what an external scanner most needs (2024-2026)

Scope note: research done 2026-11-08 by web search and fetch only. No scanning tools were run. Many headline
figures were reached through secondary coverage because the primary PDFs (Verizon DBIR, M-Trends, VulnCheck) were
not fetched in full; where that is the case it is said. extscan's current coverage was checked by grepping the repo
(see Inferences in section 1 and the prioritised list in section 3).

## 1. Initial access trends: how much starts at the internet edge?

### Takeaway
Exploiting internet-facing software is now the most common way breaches start in both Verizon's and Mandiant's
2026 data, at roughly a third of cases (DBIR 2026: 31%; M-Trends 2026: 32%). Edge devices are what's being exploited:
VPNs, firewalls, gateways, file-transfer apps and enterprise apps like SAP, Oracle EBS and SharePoint. Credential abuse
against exposed remote services (VPN and RDP with valid accounts) is the other big route. The two together
argue that the scanner's most valuable job is to identify *which* edge product and version is exposed and whether it
appears in the KEV catalog, and to flag exposed remote-access and management interfaces.

### Cited Findings
**Verizon DBIR**
- DBIR 2025 (breaches Nov 2023 to Oct 2024; 22,052 incidents, 12,195 confirmed breaches): credential abuse 22%,
  vulnerability exploitation 20% (up 34% year on year), phishing 16% as initial access vectors —
  [Qualys summary](https://blog.qualys.com/qualys-insights/2025/04/22/the-verizon-2025-data-breach-investigations-report-dbir-six-trends-you-cant-ignore);
  [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/verizon-dbir-jump-vulnerability/)
- DBIR 2025: edge devices and VPNs were 22% of vulnerability-exploitation breaches, up from 3% the year before
  (about eight-fold). Only 54% of edge-device vulnerabilities were fully remediated, median 32 days. Median time to
  mass exploitation was 0 days —
  [Tenable](https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025);
  [CPO Magazine](https://www.cpomagazine.com/cyber-security/2025-verizon-dbir-cyber-attacks-increasingly-driven-by-vulnerability-exploitation-vpns-and-edge-devices-heavily-targeted/);
  [GovInfoSecurity](https://www.govinfosecurity.com/verizon-reports-surge-in-breaches-tied-to-edge-devices-a-28061)
- DBIR 2025: 70% of espionage-motivated breaches started with vulnerability exploitation —
  [Qualys summary](https://blog.qualys.com/qualys-insights/2025/04/22/the-verizon-2025-data-breach-investigations-report-dbir-six-trends-you-cant-ignore)
- DBIR 2026 (data period from Nov 2024; about 22,000 breaches): vulnerability exploitation is the #1 initial access
  vector for the first time, at 31% (up 55% from 20%). Credential abuse fell to 13% as the first vector but appears
  somewhere in the attack chain in 39% of breaches —
  [watchTowr](https://watchtowr.com/resources/verizon-dbir-2026-vulnerability-exploitation/);
  [SecurityInfoWatch](https://www.securityinfowatch.com/cybersecurity/news/55378754/verizon-dbir-vulnerability-exploitation-surpasses-stolen-credentials-as-top-breach-entry-point);
  [Push Security review](https://pushsecurity.com/blog/verizon-dbir-2026-review). One secondary source gives 36%
  rather than 31%, which conflicts with the others; 31% is the consensus figure.
- DBIR 2026: only 26% of CISA KEV vulnerabilities were fully remediated (down from 38%), and the median time to patch
  rose to 43 days —
  [watchTowr](https://watchtowr.com/resources/verizon-dbir-2026-vulnerability-exploitation/);
  [TechRepublic](https://www.techrepublic.com/article/news-verizon-dbir-vulnerability-exploitation-2026/).
  (The SC World article was blocked (403); figures from secondary coverage.)
- Some 2026 blogs attribute the "3% to 22% edge" figure to the 2026 DBIR. It was published in the 2025 DBIR (2024
  data) —
  [Cybelesoft](https://blog.cybelesoft.com/dbir-2026-edge-device-exploitation/) vs
  [Tenable 2025](https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025).
  I found no 2026-specific edge-device share.

**Mandiant M-Trends**
- M-Trends 2025 (2024 investigations): exploits 33% (5th year as top vector, down from 38%), stolen credentials 16%
  (2nd for the first time, driven by infostealers), email phishing 14% —
  [Google Cloud blog](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/);
  [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/vulnerability-credential-initial)
- M-Trends 2025: the four most frequently exploited vulnerabilities were all in edge devices: PAN-OS GlobalProtect,
  Ivanti Connect Secure, Ivanti Policy Secure and Fortinet FortiClient EMS —
  [GreyNoise citing M-Trends](https://www.greynoise.io/blog/2026-greynoise-state-of-the-edge-report-where-attacks-concentrate-defenses-fall-short)
- M-Trends 2026 (2025 investigations, over 500,000 hours): exploits 32% (6th straight year on top), voice phishing 11%,
  prior compromise 10%, email phishing 6%. Prior compromise was the top vector in ransomware (30%, up from 15%). Global
  median dwell time was 14 days. Mean time to exploit was estimated at -7 days (exploited before a patch exists).
  Hand-off from initial-access broker to the next group fell from more than 8 hours (2022) to 22 seconds (2025) —
  [Google Cloud M-Trends 2026 blog](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)
- M-Trends 2026: SecurityWeek lists stolen credentials at 9%. The most abused CVEs included SAP NetWeaver
  CVE-2025-31324, Oracle EBS CVE-2025-61882 and SharePoint CVE-2025-53770 —
  [SecurityWeek](https://www.securityweek.com/m-trends-2026-initial-access-handoff-shrinks-from-hours-to-22-seconds/);
  [SC World](https://www.scworld.com/brief/attack-handoff-times-plummet-exploits-remain-leading-attack-vector)
- M-Trends 2026 names VPNs and routers as targets of UNC6201/UNC5807 and a Dell RecoverPoint zero-day; BRICKSTORM
  dwell time was nearly 400 days —
  [Google Cloud M-Trends 2026 blog](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)

**Google Threat Intelligence Group (zero-days)**
- 2024: 75 zero-days exploited, 33 (44%) in enterprise technology. 20 of those were in security and networking
  products (over 60% of enterprise zero-days), mostly edge appliances (VPNs, gateways, firewalls) —
  [GTIG 2024 zero-day review](https://cloud.google.com/blog/topics/threat-intelligence/2024-zero-day-trends/);
  [CSO Online](https://www.csoonline.com/article/3973769/enterprise-specific-zero-day-exploits-on-the-rise-google-warns.html)
- 2025 (published 5 Mar 2026): 90 zero-days exploited (up from 78). 48% (43) targeted enterprise technology, of which
  21 were in security and networking products. 14 hit edge devices, which GTIG says is likely an undercount because
  edge devices lack EDR —
  [GTIG 2025 zero-day review](https://cloud.google.com/blog/topics/threat-intelligence/2025-zero-day-review/);
  [SecurityWeek](https://www.securityweek.com/google-half-of-2025s-90-exploited-zero-days-aimed-at-enterprises/amp/);
  [Security Affairs](https://securityaffairs.com/188993/security/google-gtig-90-zero-day-flaws-exploited-in-2025-as-enterprise-targets-grow.html)

**CISA KEV and VulnCheck**
- KEV grew by 245 entries in 2025 (about +20%) to 1,484. 2024 added 185-187 (sources differ). 24 of the 2025 additions
  were flagged as ransomware-used. 94 of the 2025 additions were CVEs from 2024 or earlier. Microsoft led with 39 —
  [SecurityWeek](https://www.securityweek.com/cisa-kev-catalog-expanded-20-in-2025-topping-1480-entries/);
  [Cyble](https://cyble.com/blog/cisa-kev-2025-exploited-vulnerabilities-growth/). Per-vendor counts for Cisco (8),
  Fortinet (8) and Ivanti (7) come from a single blog —
  [Stackademic](https://blog.stackademic.com/cisas-kev-catalog-in-2025-what-exploited-vulnerabilities-reveal-about-the-modern-threat-landscape-f02ef11b62e2)
- VulnCheck 1H 2025: 432 CVEs newly exploited in the wild. 32.1% were exploited on or before the day the CVE was
  published (23.6% in 2024). Network edge devices were the second category by count (77 KEVs) after CMS (86, mostly
  WordPress plugins). Cisco, Fortinet, SonicWall, D-Link and Ivanti were among the most-targeted edge vendors —
  [VulnCheck blog](https://www.vulncheck.com/blog/state-of-exploitation-1h-2025)
- VulnCheck full-year 2025: 28.96% of KEVs were exploited on or before the CVE's publication day. Network edge devices
  (firewalls, VPNs, proxies) were the most targeted technologies —
  [VulnCheck 2026 State of Exploitation PDF](https://wwv.vulncheck.com/hubfs/Research/2026-StateofExploitation.pdf?hsLang=en)
  (via search summary; PDF not fetched)

**GreyNoise / Rapid7 / Sophos**
- GreyNoise 2026 State of the Edge (H2 2025, 162 days): 2.97 billion malicious sessions from 3.8 million source IPs.
  Palo Alto GlobalProtect drew 16.7M sessions, more than 3.5x Cisco and Fortinet combined. 52% of RCE attempts came from
  IPs with no prior history. Pre-2015 CVEs still generated 7.3M sessions (about 4x the 2023-2024 CVEs combined). A
  credential-spraying botnet grew from 2,000 to 300,000 IPs (73% residential) in 72 days. 91,403 sessions targeted
  AI/LLM infrastructure —
  [GreyNoise blog](https://www.greynoise.io/blog/2026-greynoise-state-of-the-edge-report-where-attacks-concentrate-defenses-fall-short)
- GreyNoise 2025 Mass Internet Exploitation Report (2024 data): several CVEs were exploited before they were added to
  KEV, and the most exploited vulnerability of 2024 was in home routers (botnets). About 28-30% of the KEV entries
  GreyNoise tracks are used by ransomware (figures vary by summary) —
  [GreyNoise](https://greynoise.io/blog/2025-mass-internet-exploitation-report)
- Rapid7 2024 Attack Intelligence Report: 36% of the widely exploited vulnerabilities it tracked were in network edge
  technology, and 60% of those were zero-days. Mass-compromise events from edge exploitation nearly doubled in 2023 —
  [Rapid7 press release](https://www.rapid7.com/about/press-releases/rapid7-releases-2024-attack-intelligence-report/);
  [BankInfoSecurity](https://www.bankinfosecurity.com/attacks-surge-against-edge-infrastructure-devices-a-25525).
  I found no Rapid7 "2025 Attack Intelligence Report".
- Sophos Active Adversary 2025 (over 400 IR/MDR cases, 2024): "external remote services" with valid accounts was the
  leading initial access technique (56% of cases; includes VPNs and firewalls). Root causes were compromised
  credentials 41%, exploited vulnerabilities 21.79% and brute force 21.07% —
  [Sophos press release](https://www.sophos.com/en-gb/press/press-releases/2025/04/sophos-report-56-sophos-ir-and-mdr-cases-adversaries-logged-instead).
  An "RDP abused in 84% of cases" figure appears only in secondary coverage
  ([techeconomy.ng](https://techeconomy.ng/in-56-of-sophos-ir-and-mdr-cases-adversaries-logged-in-instead-of-breaking-in/)).
- CISA BOD 23-02 (June 2023) requires federal agencies to remove internet-exposed networked management interfaces
  (routers, switches, firewalls, VPN concentrators, proxies, load balancers, out-of-band server management) or put them
  behind a separate zero-trust enforcement point, within 14 days of discovery. CISA recommends all organisations adopt
  it —
  [CISA BOD 23-02](https://www.cisa.gov/news-events/directives/binding-operational-directive-23-02);
  [Implementation guidance](https://cisa.gov/news-events/directives/binding-operational-directive-23-02-implementation-guidance)

### Inferences
- Roughly one third of intrusions start with exploitation (DBIR 2026 31%, M-Trends 2026 32%). In the 2024 data, about a
  fifth to a quarter of exploitation cases were edge devices (DBIR 2025 22%). In threat-intel telemetry, edge devices
  dominate exploitation (VulnCheck, GTIG, GreyNoise). For an external scanner, "identify the edge product, its version,
  and whether that version is in KEV" is the single highest-value capability.
- Exploitation often comes on or before disclosure day (29-32% of KEVs) and the mean time to exploit is negative. A
  scanner cannot out-race attackers on zero-days, but it *can* produce an accurate inventory ("you run Ivanti Connect
  Secure 22.x on 203.0.113.10") so the client can act the day an advisory drops. That makes the edge-product inventory
  and run diffing (ROADMAP item 5) more valuable than more CVE templates.
- Credential-based entry (Sophos 56% external remote services; DBIR credential abuse in 39% of chains) means exposed
  login surfaces matter even though extscan does no credential testing. Inventorying VPN portals, RDP, SSH, Citrix
  gateways, OWA/Exchange and SSO login pages, and whether MFA or pre-auth controls are visible (for example RDP NLA), is
  in scope and non-intrusive.
- Pre-2015 CVEs still drive heavy traffic (GreyNoise). Old, unpatched services such as Shellshock CGI, PHP-CGI and
  legacy SMB are worth keeping in the default checks.
- Repo check (grep of `extscan/`): there is **no** edge-appliance identification (no Fortinet, Ivanti, Citrix, Palo Alto
  or SonicWall logic), **no** KEV or EPSS mapping, and RDP/SMB are only flagged as "port open, high". This is the
  biggest gap between extscan's coverage and the threat data.

### Gaps
- Could not fetch the full DBIR 2026 or M-Trends 2026 PDFs. The DBIR 2026 edge-device share and named top CVEs, and
  M-Trends 2026's top-exploited CVE ranking, are unconfirmed. SC World's DBIR 2026 page returned 403.
- No primary-source per-vendor KEV counts for 2025 (Fortinet, Ivanti, Cisco from a single blog).
- No reliable 2025-2026 statistic for "share of breaches via exposed RDP/SSH" specifically. Sophos's category is
  broader (external remote services).
- File-transfer apps (MOVEit 2023, Cleo CVE-2024-50623/CVE-2024-55956 in Dec 2024) were not specifically researched
  here. Their mass-exploitation history is well known, but I have no fresh 2025-2026 statistic to cite.

## 2. What commercial EASM / exposure tools detect and how they present it

### Takeaway
Commercial EASM products share one pattern: seed-based recursive discovery (domains, IP blocks, ASNs, WHOIS orgs,
certificates) with an explicit attribution-confidence state per asset. On top of that sits a catalogue of named
"risk rules" grouped into categories (insecure versions/CVEs, unsafe protocols and exposed databases, admin
interfaces, IoT/OT, certificate hygiene, web weaknesses). Findings are prioritised High/Medium/Low with a separate
"potential/unconfirmed" label when the version can't be seen, a KEV view, and inventory-change dashboards with
alerting. extscan already does the finding side for a fixed scope. What it lacks is the KEV lens, the
confirmed-vs-potential distinction applied to version-inferred CVEs, and change tracking.

### Cited Findings
**Microsoft Defender EASM (docs updated 2026)**
- Discovery starts from seeds (domains, IP blocks, hosts, email contacts, ASNs, WHOIS orgs) and recurses through WHOIS
  (same registrant/email/name server), DNS (hosts, shared IP blocks, MX), SSL certificates (other hosts sharing a
  cert) and ASN records —
  [MS Learn: What is discovery](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/what-is-discovery)
- Attribution is expressed as asset states: Approved Inventory, Dependency (third-party infrastructure supporting
  owned assets), Monitor Only, Candidate (weak connection, needs manual review), and Requires Investigation (set by
  internal confidence scores). Confidence falls with each recursion level —
  [MS Learn: What is discovery](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/what-is-discovery)
- Eight dashboards: Overview, Inventory changes (added/removed per 7 or 30 days; assets pruned automatically after 30-60
  days unseen), Attack surface summary, Security posture, GDPR, OWASP Top 10, CWE Top 25, and CISA Known Exploits —
  [MS Learn: dashboards](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-dashboards)
- Priorities are High/Medium/Low. "High" covers new, frequently exploited or low-skill-exploitable CVEs. "Low" covers
  deprecated tech, upcoming expiry and best-practice violations. Insights are labelled **"Potential"** when the service
  is detected but its version is hidden, so manual confirmation is needed. Users can mark CVE observations as
  non-applicable (for example backported patches). New insights trigger push notifications —
  [MS Learn: dashboards](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-dashboards)
- Other detections: "sensitive services", SSL and domain expiry (bucketed from expired to >90 days), SHA-1/MD5
  signature algorithms, IP reputation (e.g. DDoS involvement), domain EPP status codes (missing
  `clientUpdateProhibited` means hijack risk), registrar consolidation, open ports found by TCP SYN scans (databases,
  DNS, IoT, routers), login and PII forms served over HTTP, and web-component-to-CVE matching refreshed daily —
  [MS Learn: dashboards](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-dashboards)

**Palo Alto Cortex Xpanse**
- "Attack Surface Rules" (more than 800 by mid-2024) in categories: insecure versions/configurations, unsafe protocols
  and services (Telnet, FTP, exposed databases, unintentionally exposed admin interfaces), exposed IoT/embedded/OT,
  certificate and crypto hygiene, and common web-app weaknesses. Examples: "Insecure Jenkins Server", "SAP Employee
  Self-Service Portal", "Schneider Electric Modicon MC80 PLC". Severity is High/Medium. Rules that are High and not
  noisy, or Medium but uncommon and significant, are enabled by default. OT/IoT rules are enabled because they are
  actionable when accidentally exposed —
  [Palo Alto Networks blog, June 2024](https://www.paloaltonetworks.com/blog/security-operations/enhancing-critical-risk-detection-with-cortex-xpanse-attack-surface-rules.md)
- Third-party comparisons describe Xpanse attribution as ML/algorithmic —
  [IONIX comparison (competitor)](https://www.ionix.io/writing-center/top-5-cortex-xpanse-alternatives-for-external-attack-surface-management-in-2026/)
  (vendor-adjacent, low confidence)

**Censys**
- ASM "risk fingerprints" are added continuously (an Aug 2026 changelog adds 2 ASM risk fingerprints, which may be
  disabled by default). Censys Assistant (LLM) generates custom attack-surface reports. An Elasticsearch/Kibana
  connector can trigger host rescans and pull IP event history —
  [Censys changelog, 17 Aug 2026](https://docs.censys.com/changelog/august-17-2026)
- Sept 2024: more than 5,000 CVE risks added to the ASM risk library; new CVEs appear in ASM within 24 hours of NVD
  cataloguing —
  [Censys release notes Sept 2024](https://community.censys.com/product-updates/censys-release-notes-for-september-23-2024-183)

**runZero**
- March 2025 platform expansion added "Internet Exposures": detecting internal assets inadvertently exposed to the
  internet (e.g. RDP, OT) using "inside-out" correlation of fingerprints. Fingerprinting identifies services by
  behaviour, not banners —
  [Help Net Security, Mar 2025](https://www.helpnetsecurity.com/2025/03/27/runzero-exposure-detection-management/);
  [runZero press](https://www.runzero.com/newsroom/exposure-management/)
- runZero became a CVE Numbering Authority in Dec 2025 —
  [BusinessWire Dec 2025](https://www.businesswire.com/news/home/20251210559188/en). An Accenture acquisition of
  runZero (June 2026) is reported by a single blog only — unverified
  ([guptadeepak.com](https://guptadeepak.com/tools/top-10-attack-surface-management-tools-2026/)).

**Category-level**
- CrowdStrike's former Falcon Surface is now inside Falcon Exposure Management. Censys is often the discovery data layer
  feeding other EASM platforms —
  [guptadeepak.com roundup](https://guptadeepak.com/tools/top-10-attack-surface-management-tools-2026/)
  (secondary, low confidence)

### Inferences
- Features extscan could copy without giving up its auditor framing:
  1. **KEV/known-exploited view.** Defender EASM gives it a whole dashboard. For extscan, a `kev: true` flag and a
     report section listing services whose detected product/version maps to a KEV entry (offline KEV JSON shipped or
     fetched at `doctor` time; stdlib only).
  2. **"Potential" vs confirmed.** Defender's split matches extscan's existing `confidence="tentative"` and
     `review_required` fields. Version-inferred CVE matches should always be tentative and land in the manual review
     queue, never be presented as confirmed.
  3. **Asset attribution states.** Recon already reports names resolving outside scope. Labelling recon-discovered
     assets Candidate / Dependency / Out-of-scope, rather than just "outside scope", matches industry vocabulary.
  4. **Inventory-change view.** Run diffing (ROADMAP item 5) is the open-source equivalent of the
     inventory-changes dashboard and alerting.
  5. **Domain hygiene.** Domain and certificate expiry and registrar lock status are cheap and passive. Certificate
     expiry is ROADMAP item 4. Registrar lock needs WHOIS/RDAP lookups, which are passive and out-of-band.
- Discovery-from-seeds (WHOIS org pivots, ASN expansion) is the core EASM differentiator, but it conflicts with
  extscan's "only scan what the scope file lists" rule. It is safe only as a *reporting* step ("these assets look
  related; ask the client"), never as a scan-target expander.

### Gaps
- No primary documentation retrieved for Rapid7 Surface Command, Tenable ASM, or Shodan Monitor. The search returned
  only generic EASM pages. Their 2025-2026 headline features are not covered here.
- No primary source for how Censys or Xpanse compute attribution confidence or risk scores. Third-party claims such as
  ">95% attribution accuracy" are unverified.

## 3. Safe, non-intrusive detection techniques and a prioritised list for extscan

### Takeaway
The highest-value additions, ranked by threat data and how safely they can be checked:
1. Edge-appliance identification and version fingerprinting, mapped to KEV.
2. Exposed remote-access and management-interface inventory (BOD 23-02 categories).
3. Dangling-DNS takeover confirmation via provider fingerprints.
4. Email posture.
5. Exposed DevOps/data services (largely done).
6. TLS/HTTP fingerprints (JA4X/JA4S, favicon) as correlation and attribution aids.

All can be done with ordinary GETs, TLS handshakes and DNS queries.

### Cited Findings
**Edge-appliance version fingerprinting (no exploit, static assets only)**
- Citrix NetScaler: Fox-IT's public triage tool fingerprints the build over HTTP from the gzip header timestamp of a
  static language resource that ships with each build, mapped to firmware versions —
  [fox-it/citrix-netscaler-triage](https://www.github.com/fox-it/citrix-netscaler-triage). Community tools add
  Content-Length, ETag correlation and login-page hash mapping, and note that some hardened appliances put static files
  behind authentication, so remote detection fails —
  [cybrdude/citrixscan](https://github.com/cybrdude/citrixscan) (third-party, unverified accuracy). BinaryEdge
  implemented the same gzip-timestamp method —
  [BinaryEdge docs](https://docs.sand.binaryedge.io/SEv2/modules/netscaler/)
- FortiGate and Ivanti: no comparably documented remote static-asset version method found. Identification is
  typically by login-page strings and cookies (GlobalProtect, Pulse/Ivanti, FortiGate, AnyConnect, NetScaler) —
  [search results; tessl skill page](https://tessl.io/registry/skills/github/elementalsouls/Claude-BugHunter/enterprise-vpn-attack)
  (low-quality source; see Gaps).
- Defender EASM matches observed web components and versions to CVEs, and labels hidden-version cases "Potential" —
  [MS Learn](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-dashboards)

**TLS/HTTP fingerprinting**
- JA4+ family: JA4 (TLS client), JA4S (TLS server response), JA4X (how the X.509 certificate was generated), JA4H
  (HTTP client), among others. JA4S combined with JA4 raises fidelity from "library" to "application/malware family".
  Published C2 examples include Sliver (JA4/JA4S) and Cobalt Strike (JA4H/JA4X) —
  [APNIC blog (FoxIO)](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/);
  [FoxIO Medium](https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637)
- Licensing: JA4 (client) is BSD-3. JA4S, JA4H, JA4X and the other JA4+ methods are under the FoxIO License 1.1, which
  allows internal/research use but requires an OEM licence for commercial products or services sold to customers —
  [ja4plus on PyPI](https://pypi.org/project/ja4plus/);
  [netring docs](https://docs.rs/crate/netring/latest/source/docs/FINGERPRINTS.md)

**Subdomain takeover / dangling DNS**
- A longitudinal study across 12 cloud platforms found 20,904 hijacked dangling records hosting malicious content
  (75% blackhat SEO), with the first evidence of real-world exploitation —
  [arXiv 2403.19368 (2024)](https://arxiv.org/abs/2403.19368)
- DVAHunter measured 89,015,946 subdomains of Tranco top-1M domains across 45 CDNs for dangling-resource abuse —
  [arXiv 2409.01887 (2024)](https://arxiv.org/html/2409.01887v1)
- Industry: SentinelOne reports more than 1,250 subdomain-takeover-risk alerts to clients in a year from deprovisioned
  cloud resources and frames takeovers as a supply-chain risk —
  [SentinelOne](https://www.sentinelone.com/blog/re-assessing-risk-subdomain-takeovers-as-supply-chain-attacks/).
  Infoblox's "Hazy Hawk" (May 2025) hijacked abandoned cloud resources behind dangling CNAMEs at scale (via secondary
  coverage) —
  [Cyber Security News](https://cybersecuritynews.com/dangling-dns-attack-let-hackers-gain-control/amp/)

**Exposed DevOps and data services**
- Shadowserver found 381,645 Kubernetes API servers returning 200 OK (of more than 450,000 seen on 443/6443). A 200
  does not mean fully open. Cyble's count of more than 900,000 clusters was mostly 403s, and only 799 accepted
  unauthenticated requests. These figures are from ~2022, before the research window —
  [SecurityWeek](https://www.securityweek.com/over-380000-kubernetes-api-servers-exposed-internet-shadowserver);
  [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-900-000-kubernetes-instances-found-exposed-online/amp)
- Xpanse ships rules for exposed databases, admin interfaces and "Insecure Jenkins" —
  [Palo Alto Networks](https://www.paloaltonetworks.com/blog/security-operations/enhancing-critical-risk-detection-with-cortex-xpanse-attack-surface-rules.md)
- GreyNoise saw 91,403 malicious sessions targeting AI/LLM infrastructure in H2 2025, so exposed model-serving
  endpoints (e.g. Ollama, inference APIs) are an emerging class —
  [GreyNoise](https://www.greynoise.io/blog/2026-greynoise-state-of-the-edge-report-where-attacks-concentrate-defenses-fall-short)

**Email posture**
- EasyDMARC 2025 (top 1.8M domains): 52.2% have no DMARC, and only 7.7% use p=reject —
  [EasyDMARC](https://easydmarc.com/blog/?p=52716). Red Sift (Dec 2025, 73.3M domains): about 2.5% p=reject and 83.9% no
  DMARC (secondary summary) —
  [AutoSPF](https://autospf.com/blog/dmarc-adoption-benchmarks-by-industry-protection-gaps-and-sector-comparison/).
  Denominators differ between studies, so reject rates range from 2.5% to about 20%.

### Inferences — prioritised list for extscan (P1 highest)
Each item is tagged with whether it is already done in the repo (from grep), the threat-data justification, and how to
detect it non-intrusively.

- **P1. Edge-appliance identification + version-to-KEV mapping.** *Not present.* Justification: DBIR, M-Trends, GTIG,
  VulnCheck and GreyNoise all put edge devices at the top of exploitation. Safe detection:
  - Identify the product from login-page title/body markers, cookies, redirect paths and TLS certificate CN/issuer
    defaults: Fortinet SSL-VPN (`/remote/login`), Palo Alto GlobalProtect (`/global-protect/login.esp`), Ivanti
    Connect Secure (`/dana-na/`), Citrix NetScaler Gateway (`/vpn/index.html`, `/logon/LogonPoint/`), SonicWall SMA,
    Cisco ASA/FTD AnyConnect (`/+CSCOE+/logon.html`), Check Point, F5 BIG-IP (`/tmui/` exposure is itself a finding).
  - Version from static asset hashes, ETags, gzip timestamps (Fox-IT method) or version strings in JS/CSS query
    parameters, where public research exists.
  - Map product and version to a locally cached KEV JSON. Report hidden-version matches as "Potential" (tentative +
    manual review), as Defender EASM does.
  - Many nuclei templates already exist for these (tech-detect and version-detect templates). The new work is
    aggregation, KEV mapping and an "edge inventory" report section, not new probes.
  - Path markers above are from general knowledge, not sources gathered here; verify each before coding.
- **P1. Exposed management interfaces (BOD 23-02 categories).** *Partially present* (ports flagged by number).
  Detect the management plane of routers, firewalls and load balancers, and BMC/out-of-band interfaces (iDRAC, iLO,
  IPMI on 623/udp), from the HTTP title/cert and UDP responses. Report each against BOD 23-02's "remove or put behind a
  separate enforcement point" language. That language is ready-made, citable remediation text for auditors.
- **P1. Remote-access surface detail (RDP/SSH/VPN), without credentials.** *Partial* (`rdp-ntlm-info` NSE, port
  flags). Justification: Sophos 56% external remote services; DBIR credential abuse in 39% of chains. Safe checks:
  RDP NLA/CredSSP enforcement and TLS cert (nmap `rdp-enum-encryption`), SSH auth methods offered (does the server
  allow `password`?) via nmap `ssh-auth-methods` (pre-auth, no guessing), SSH host-key reuse across hosts, and whether
  VPN login pages show SAML/SSO redirects (an MFA hint) vs a local form. This overlaps ROADMAP item 10.
- **P2. Subdomain-takeover confirmation.** *DNS side done* (ROADMAP item 6 "Left"). Add the provider-fingerprint
  HTTP check (one GET to the in-scope name, matching known "unclaimed" markers, as in the can-i-take-over-xyz project).
  Never claim the resource. Academic data (20,904 observed hijacks) supports raising severity when the fingerprint
  matches.
- **P2. Email security posture.** *Not present* (ROADMAP item 7). The data (more than half of domains lack DMARC, and
  under 10% enforce reject) means this check will produce findings on most engagements. Add MTA-STS
  (`_mta-sts` TXT + HTTPS policy fetch), TLS-RPT, BIMI optional, DKIM selector probing only for common selectors
  (passive DNS).
- **P2. KEV-aware severity across all version detections** (nmap `-sV`, nuclei tech-detect). Raise severity and add a
  "known exploited" tag. This is the cheapest high-impact change and reuses data already collected.
- **P3. Exposed DevOps/data services.** *Largely present* (Docker 2375/2376, Redis, Elasticsearch, kubelet 10250 in
  `probes.py` and nmap scripts). Worth adding: unauthenticated read-only checks for the Kubernetes API (`/version`,
  `/api` anonymous), the Docker registry `/v2/_catalog`, Jenkins `/script` reachability (GET only), exposed AI
  inference endpoints (Ollama `/api/tags`, OpenAI-compatible `/v1/models`) given GreyNoise's AI-targeting data, and
  Prometheus/Grafana anonymous.
- **P3. Fingerprints for attribution and correlation.** Favicon mmh3 hash, JA4X certificate fingerprints, and
  certificate/SSH-host-key reuse. These group hosts running the same appliance or deployment and find shared keys.
  Licensing matters: JA4X/JA4S are FoxIO License 1.1, so extscan used commercially by an audit firm may need an OEM
  licence. Favicon hashing and certificate-SPKI reuse have no such encumbrance.
- **P3. Domain hygiene.** Registrar lock (EPP status via RDAP), domain expiry, certificate expiry (ROADMAP item 4),
  SHA-1 certificates. All passive.
- **P4. DNS posture: DNSSEC, open resolvers, IPv6.** DNSSEC presence/validation and open-resolver checks (a single
  recursive query for a benign name to an in-scope DNS server) are safe and standard. IPv6: scan AAAA-resolved
  addresses only when the scope lists IPv6 targets, because firewall rules often differ between v4 and v6 (inference;
  not sourced here).

### Gaps
- No primary research found on remote, non-intrusive version fingerprinting for FortiGate or Ivanti Connect Secure.
  Only Citrix has a well-documented public method (Fox-IT). The product path markers listed in P1 are from general
  knowledge and need verification against vendor docs or nuclei templates.
- JARM: not researched in depth. I did not confirm Salesforce JARM's current maintenance status or a head-to-head
  JARM vs JA4S comparison.
- Favicon-hash usage statistics, open-resolver counts, DNSSEC adoption and IPv6 exposure statistics for 2024-2026 were
  not found in this pass.
- No 2025 Shadowserver figures for exposed Redis, Elasticsearch or Docker were retrieved. The Kubernetes figures are
  from ~2022.

## 4. AI/LLMs in recon and triage (2025-2026): what works, what's risky

### Takeaway
Agentic tools showed in 2025 that they can find real, validated web vulnerabilities at scale: XBOW topped HackerOne's
US leaderboard. What made it work was a deterministic *validator* layer, not trust in model output. LLM false-positive
filtering cuts noise substantially in benchmarks, but rigorous studies show more modest gains (about a third of
false positives removed with no lost true positives). The main risk is indirect prompt injection from scanned content:
a 2025 paper hijacked an AI pentest agent 100% of the time across 14 variants. extscan's planned closed action
allow-list (ROADMAP item 11) is the right design.

### Cited Findings
- XBOW, an autonomous AI pentester, reached #1 on HackerOne's US leaderboard in June 2025, submitting about 1,060 reports
  from Feb to June 2025 (counts vary by source). It uses automated "validators" that independently confirm each finding
  before reporting. Its developers acknowledge that some false positives remain, especially business-logic bugs that
  are hard to validate automatically —
  [XBOW blog](https://xbow.com/blog/top-1-how-xbow-did-it/);
  [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/ai-based-pen-tester-top-bug-hunter-hackerone)
- "Cybersecurity AI: Hacking the AI Hackers via Prompt Injection" (arXiv 2508.21669, Aug 2025): malicious content in a
  scanned target's responses hijacked the CAI pentest agent, reaching shell on the tester's machine. It succeeded in
  100% of 14 attack variants in under 20 seconds. The authors propose layered defences —
  [arXiv 2508.21669](https://arxiv.org/abs/2508.21669v1)
- Indirect prompt injection is LLM01 in OWASP Top 10 for LLM Apps 2025. Unit 42 (Mar 2026) reports in-the-wild indirect
  injection with 22 payload techniques (secondary summary) —
  [startupdefense.io summary](https://www.startupdefense.io/blog/indirect-prompt-injection-attacks)
- LLM false-positive filtering: a June 2025 study (OWASP Benchmark plus a real project) found the best single LLM
  removed 33.85% of false positives without missing true weaknesses, and an ensemble 38.46% —
  [arXiv 2506.16899](https://arxiv.org/abs/2506.16899v1). Multi-agent and hybrid pipelines report larger cuts
  (QASecClaw: 88.6% FP reduction with a 3.1% recall loss) —
  [arXiv 2605.01885](https://arxiv.org/pdf/2605.01885). ZeroFalse finds reasoning models with CWE-specific prompts are
  the most reliable —
  [arXiv 2510.02534](https://arxiv.org/html/2510.02534v1). A 2026 comparison concludes results vary heavily with agent
  design, model, vulnerability class and cost —
  [arXiv 2601.22952](https://arxiv.org/pdf/2601.22952). These studies are all SAST, not external scanning.
- Vendors are adding LLM report generation to EASM (Censys Assistant, Aug 2026) —
  [Censys changelog](https://docs.censys.com/changelog/august-17-2026)
- Attackers' AI use: M-Trends 2026 documents malware querying LLMs mid-execution (PROMPTFLUX, PROMPTSTEAL) but says
  2025 was not the year breaches resulted directly from AI —
  [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026). GreyNoise saw 91,403
  sessions targeting AI infrastructure —
  [GreyNoise](https://www.greynoise.io/blog/2026-greynoise-state-of-the-edge-report-where-attacks-concentrate-defenses-fall-short)

### Inferences
- What works for extscan: use the LLM for *triage and explanation* of deterministic evidence: summarising,
  de-duplicating, suggesting the manual-review question, and ranking edge/KEV findings. Each LLM verdict should be
  checked by a deterministic re-request (XBOW's validator pattern). It should never be the sole basis for marking a
  finding false-positive, because extscan's rule is that reduced coverage must never look clean.
- What's risky: every banner, HTML page, OpenAPI description and certificate field extscan collects is
  attacker-controllable text. The 100% hijack rate in arXiv 2508.21669 means scanned content must be treated as data:
  delimited, never able to choose URLs or commands, with the action space a closed allow-list enforced in code
  (consistent with ROADMAP item 11's stated catch). The vault already has "hostile text" tests; the LLM layer should
  have equivalent injection tests.
- LLM false-positive filtering of nuclei output is plausible, but no external-scanning benchmark exists. If added, it
  should only *demote to review*, never delete.

### Gaps
- No published benchmark found for LLM triage of DAST/EASM findings (nuclei-style). All rigorous FP-reduction evidence
  is from SAST.
- No independent (non-vendor) evaluation of agentic pentest tools' false-positive rates on external perimeters was
  found. XBOW's figures are self-reported plus HackerOne acceptance.
