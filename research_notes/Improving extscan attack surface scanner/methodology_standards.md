# Methodology, compliance and reporting standards for an auditor-focused external assessment tool (as of Nov 2026)

Context from the repo, read briefly (README.md, extscan/report.py, tests/fixtures/lab-run/report.md):
- extscan already records an authorisation reference, who authorised the work, the testing window and constraints. It puts scope at the top of `report.md`, gives a severity count table, a manual review queue, explicit coverage gaps (`Degradation`), and logs each command with timings to `commands.jsonl`.
- `report.json` comes from `render_json` in `extscan/report.py`. Severity is a five-level label (Critical, High, Medium, Low, Informational). The sample report shows no CVSS vector, EPSS or KEV fields.

Source-quality note: the following could not be fetched directly: PCI SSC PDFs, DefectDojo field docs, the PTES, OSSTMM and CREST pages, and the Azure and GCP policy pages. Claims about them rely on secondary sources, which are flagged where used.

## 1. Testing methodologies (NIST SP 800-115, PTES, OWASP WSTG, OSSTMM, CREST, MITRE ATT&CK TA0043)

### Takeaway
NIST SP 800-115 is still the 2008 final, never revised. OWASP WSTG's last stable release is 4.2, with v5 still in development, and WSTG asks for version-qualified test IDs. MITRE ATT&CK TA0043 Reconnaissance is at content v20.1 and has 12 techniques. extscan should tag each check and finding with a methodology reference, such as a WSTG-v42 ID and an ATT&CK technique ID, and record which methodology phases ran and which did not.

### Cited Findings
- NIST SP 800-115, "Technical Guide to Information Security Testing and Assessment," was published September 2008 (final 09/30/08). It is still listed as Final, with no withdrawal or revision noted, and it superseded SP 800-42. Its scope: help organisations "plan and conduct technical information security tests and examinations, analyze findings, and develop mitigation strategies." — [NIST CSRC SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)
- A search found no SP 800-115 revision draft as of late 2026. A secondary training site says it was "published in 2008 and never replaced." — [rolling-thunder-security (secondary)](https://rolling-thunder-security.pages.dev/extras/nist_sp_800_115)
- OWASP WSTG: the GitHub repo says the project is "currently working on release version 5.0," and the last stable release is 4.2. Identifiers can change between versions, so the project recommends version-qualified test IDs such as `WSTG-v42-INFO-02`. — [OWASP WSTG GitHub](https://github.com/owasp/wstg), [releases](https://github.com/OWASP/wstg/releases)
- MITRE ATT&CK TA0043 Reconnaissance (ATT&CK content v20.1) lists 12 techniques: T1595 Active Scanning, T1592 Gather Victim Host Information, T1589 Gather Victim Identity Information, T1590 Gather Victim Network Information, T1591 Gather Victim Org Information, T1598 Phishing for Information, T1682 Query Public AI Services, T1597 Search Closed Sources, T1596 Search Open Technical Databases, T1593 Search Open Websites/Domains, T1681 Search Threat Vendor Data, and T1594 Search Victim-Owned Websites. — [MITRE ATT&CK TA0043](https://attack.mitre.org/tactics/TA0043/)
  - Note: T1681 and T1682 are recent additions, not present in older ATT&CK versions. Any mapping should pin the ATT&CK version.

### Inferences
- extscan's stages correspond mainly to ATT&CK T1595 (Active Scanning: scanning IP blocks, vulnerability scanning, wordlist scanning). Its subdomain enumeration corresponds to T1590/T1596 (DNS and passive DNS, certificate transparency in Search Open Technical Databases). A per-stage ATT&CK mapping in `report.json` would let blue teams correlate their detections with extscan traffic.
- The web-facing probes match WSTG-INFO (information gathering: fingerprinting, enumerating applications, reviewing webserver metafiles), WSTG-CONF (configuration: admin interfaces, backup and unreferenced files, HTTP methods, HSTS), and WSTG-CRYP (weak TLS). Tag each extscan finding and check with `WSTG-v42-XXXX-NN`, and leave the version in the ID so a later WSTG v5 can be mapped without ambiguity.
- A "methodology coverage" table in the report would complement the existing coverage-gaps section. It would list which phases of the claimed methodology were performed, which were partial, and which were out of scope by design, such as credential testing and DoS.
- NIST SP 800-115's three technique families are review, target identification and analysis, and target vulnerability validation. extscan covers target identification and analysis, plus limited validation. Its policy of not testing credentials means the report should say plainly that password cracking and credential testing were out of scope. That wording comes from my own knowledge of the document; the CSRC abstract page does not list the families.

### Gaps
- I did not retrieve the primary PTES, OSSTMM v3 or CREST methodology pages, so I cannot cite their phase lists or reporting requirements. PTES (pentest-standard.org) has not been updated in years, but that is unverified here. CREST's "Defensible Penetration Test" and its accreditation requirements were not checked.
- There was no confirmed WSTG v5 release date as of Nov 2026.
- I did not obtain the full SP 800-115 text on rules of engagement and data handling (Appendix B, "Rules of Engagement Template," from my own knowledge, not verified).

## 2. PCI DSS v4.0.1 external scanning and the ASV Program Guide

### Takeaway
PCI DSS v4.0.1 Requirement 11.3.2 needs a passing ASV external scan at least every three months. Requirement 11.3.2.1 adds a scan after any significant change. Under the ASV Program Guide (v4.0 r2, Dec 2022, the latest version found), any component with a CVSS score of 4.0 or higher, or with one of several "automatic failure" conditions, fails the scan. Disputes, compensating controls and false positives go in a dedicated report section. extscan cannot be an ASV scan, since only a PCI SSC-listed ASV can produce one. It could emit an "ASV-style pre-check" summary to help clients prepare.

### Cited Findings
- 11.3.2 requires external scans "at least once every three months" by a PCI SSC Approved Scanning Vendor, with a passing result. Vulnerabilities are resolved, and rescans are performed as needed to meet the ASV Program Guide's passing-scan criteria. — [Halo Security blog (secondary)](https://blog.halosecurity.com/quarterly-pci-scans-building-a-cadence/); [Cloudaware v4.0.1 11.3.2 mapping](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/11/03/02/)
- 11.3.2.1 requires an external scan after any significant change, with vulnerabilities scored CVSS 4.0 or higher resolved and rescans as needed. These scans are in addition to the quarterly scans. — [WithPCI 11.3.2.1 (secondary)](https://withpci.pages.dev/requirements/11/11.3/11.3.2.1)
- ASVs must use the official report templates defined in the ASV Program Guide, and an ASV scan alone does not make an entity PCI DSS compliant. — [PCI SSC FAQ](https://pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/I-have-had-an-external-vulnerability-scan-completed-by-an-ASV-does-this-mean-I-am-PCI-DSS-compliant)
- The latest ASV Program Guide found is v4.0 Revision 2, dated December 2022. The only copy retrieved was an unofficial Scribd upload, and its text has an inconsistent "PCI DSS version 2.0" reference, so treat it with caution. — [Scribd copy of ASV Program Guide v4.0r2](https://www.scribd.com/document/686715606/ASV-Program-Guide-v4-0r2); see also the [PCI SSC ASV Resource Guide v12](https://www.pcisecuritystandards.org/wp-content/uploads/2024/07/PCI_SSC_ASV_Resource_Guide_v12.pdf)
- Pass/fail: a component fails if any vulnerability has a CVSS base score of 4.0 or higher. Tenable's PCI plugin also lists automatic failures for unsupported operating systems, internet-reachable database servers and default accounts. — [Tenable plugin 33929](https://tenable.com/plugins/nessus/33929); [Foregenix (secondary)](https://www.foregenix.com/blog/pci-dss-v4.0-asv-scanning-guide-for-compliance)
- A vendor says the guide's score precedence is NVD CVSS v3.1, then v3.0, then v2.0, then an ASV-calculated v3.1 score, using the first one available rather than the highest. The source was paywalled when fetched, so this is a search snippet only and unverified. CVSS v4.0 does not appear in the ASV precedence according to this source. — [Praetorian docs (snippet only)](https://docs.praetorian.com/articles/5035916-pci-asv-cvss-scoring-engine-and-passfail-gate)
- The guide says a non-compliant component "must be considered non-compliant and marked as an automatic failure by the ASV." A scan customer "may dispute the results of an ASV scan by stating they have compensating controls in place," and the ASV's conclusion "must be documented in the scan report under 'Exceptions, False Positives, or Compensating Controls'." — [ASV Program Guide (Scribd copy)](https://www.scribd.com/document/686715606/ASV-Program-Guide-v4-0r2); older official editions are at [v3.0](https://www.carson-saint.com/wp-content/uploads/2019/11/ASV_Program_Guide_v3.0.pdf) and [v2](https://www.pci-dss.gr/media/2000/asv_program_guide_v2.pdf)
- Scan interference: if interference, such as an IPS blocking the scanner, prevents completion, "the ASV must record the ASV scan result as a failure" (v4.0 r2 text). — same Scribd copy
- A secondary source says automatic-failure conditions "generally can't be disputed away." — [Secusy ASV blog (secondary)](https://secusyasv.com/asv-scan-failed/)
- On DoS: the PCI SSC FAQ covers how an identified DoS vulnerability affects an ASV pass. The page was not fetched. — [PCI SSC FAQ on DoS](https://www.pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/How-would-an-identified-Denial-of-Service-DoS-vulnerability-affect-a-company-s-ability-to-pass-a-PCI-DSS-vulnerability-scan-from-an-Approved-Scanning-Vendor-ASV)

### Inferences
- The ASV approach has four parts that map onto extscan:
  1. Per-component pass/fail with a CVSS 4.0 or higher threshold.
  2. Automatic-fail classes regardless of score, such as databases reachable from the internet and unsupported operating systems.
  3. An "interference means fail" rule. This matches extscan's rule that reduced coverage must never look clean.
  4. A section for exceptions, false positives and compensating controls with recorded justification.
- extscan could add a clearly labelled "PCI ASV-style pre-check (not an ASV scan)" table: per host, PASS/FAIL/INCOMPLETE. A host with an open `Degradation` would be INCOMPLETE, never PASS, mirroring the ASV interference rule.
- The PCI pre-check must use NVD CVSS v3.x base scores, per the reported precedence, not CVSS v4.0. extscan therefore needs to store the scoring version alongside each score.
- A disputes or false-positive workflow (`extscan dispute <finding-id> --reason ... --evidence ...`) would give auditors the ASV-style "Exceptions, False Positives, or Compensating Controls" section, and would persist across `resume` and retests.
- Scope attestation: in ASV practice the scan customer attests to scope completeness. extscan's scope file already records `authorized_by`. Adding a customer statement that the scope includes all internet-facing in-scope components, with a timestamp, would mirror that.

### Gaps
- I could not fetch the official ASV Program Guide v4.0 r2 PDF from the PCI SSC document library. I did not confirm the exact list of automatic-failure categories (Praetorian mentions nine), the exact CVSS version precedence, or whether PCI SSC has issued a newer revision that addresses CVSS v4.0. I also did not confirm the ASV scan report template sections, such as Attestation of Scan Compliance, ASV Scan Report Summary and Vulnerability Details.
- I could not verify the ASV rule on dispute evidence retention.

## 3. Risk prioritisation: CVSS v4.0, EPSS v4, CISA KEV, SSVC, BOD 26-04

### Takeaway
Modern prioritisation layers exploitation evidence on top of severity. This means KEV membership, EPSS probability and percentile, and SSVC-style decision points (exploitation, automatable, technical impact, exposure). CISA's BOD 26-04 (10 June 2026) replaced BOD 22-01 and 19-02, moving from CVSS-driven deadlines to a model built on four variables: internet-exposed, KEV, automatable and technical impact. Everything extscan finds is internet-exposed by definition. Showing KEV, EPSS and automatable/impact data per CVE would therefore map findings directly onto current US federal remediation tiers. CVSS v4.0 scores must carry their nomenclature label (CVSS-B, BT, BE or BTE).

### Cited Findings
- CVSS v4.0 was published 2023-11-01; the current specification document is revision v1.2 (2024-06-18). Score labels are CVSS-B (Base), CVSS-BT (Base+Threat), CVSS-BE (Base+Environmental) and CVSS-BTE. "This nomenclature should be used wherever a numerical CVSS value is displayed or communicated." — [FIRST CVSS v4.0 spec](https://www.first.org/cvss/v4-0/specification-document)
- CVSS v4.0 metric groups are Base, Threat, Environmental and Supplemental (Supplemental does not change the score). Exploit Maturity (E) values are Not Defined (X; defaults to worst case, equal to Attacked), Attacked (A), Proof-of-Concept (P) and Unreported (U). The qualitative scale is None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0 (optional to use). The spec encourages consumers to add Threat and Environmental metrics for a more complete risk input. — [FIRST CVSS v4.0 spec](https://www.first.org/cvss/v4-0/specification-document)
- EPSS v4 was released 17 March 2025. — [FIRST EPSS (via search; corroborated by Empirical Security)](https://www.first.org/epss/), [Introducing EPSS v4](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- EPSS "publishes a 0–1 probability (with ranking percentiles) every day for every CVE," estimating the probability that a CVE will be exploited in the wild in the next 30 days. The API is at `https://api.first.org/epss/`. FIRST's "Using EPSS" page covers combining EPSS with CVSS and KEV. — [FIRST EPSS](https://www.first.org/epss/)
- The CISA KEV catalog is "the authoritative source of vulnerabilities that have been exploited in the wild." Each entry shows CVE ID, vendor/product, name, description, CWE, "Known To Be Used in Ransomware Campaigns?", "Forensic triage required per BOD 26-04?", Date Added, Due Date, Action (required action) and notes. Feeds:
  - JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - CSV: `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`
  - JSON schema: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json`
  — [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- BOD 26-04, "Prioritizing Security Updates Based on Risk," was issued 10 June 2026 and supersedes BOD 22-01 and BOD 19-02. It evaluates four variables per vulnerability and asset: internet-exposed, KEV-listed, automatable, and technical impact (total or partial control). These give 16 profiles mapped to tiers:
  - 3 calendar days for the highest-risk combinations. All four factors present also requires forensic triage.
  - 14 days for KEV-listed vulnerabilities without the worst combination.
  - 60 days for lower-risk combinations.
  - Deferral to the next scheduled upgrade when none of the four apply.

  Compensating mitigations that remove public exposure count as equivalent to patching. CISA supplies KEV, automatable and impact answers through Vulnrichment. CVSS is no longer the proxy for deadlines. The directive binds FCEB agencies, and contractors are expected to match. — [CSA Research Note on BOD 26-04](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-bod-26-04-risk-based-vulnerability-re/); primary: [CISA BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk), [implementation guidance](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk) (primary pages not fetched; details from the CSA note and corroborated by [CIQ](https://ciq.com/blog/bod-26-04-federal-vulnerability-remediation))
- CISA's SSVC decision points are Exploitation, Technical Impact, Automatable, Mission Prevalence and Public Well-being Impact. The outcomes:
  - Track: remediate within standard timelines.
  - Track*: monitor closely.
  - Attend: supervisory action; remediate sooner than standard.
  - Act: leadership involved; remediate as soon as possible.

  CISA's SSVC calculator exports PDF or JSON. — [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
- Commercial tools have added BOD 26-04 workflows, for example "Operationalize CISA BOD 26-04 with Tenable One" and Wiz automation. — [OffSeq summary of Tenable post](https://radar.offseq.com/threat/operationalize-cisa-bod-26-04-with-tenable-one-056b4548b221437a), [Security Arsenal on Wiz](https://securityarsenal.com/blog/cisa-bod-26-04-automating-kev-remediation-and-forensic-triage-with-wiz)

### Inferences
- Recommended ranking for extscan:
  1. KEV-listed, with the ransomware flag surfaced.
  2. EPSS percentile, for example top 10% or a probability threshold the client chooses.
  3. CVSS-BT, with Exploit Maturity filled from KEV, EPSS or exploit references.
  4. Severity label for non-CVE findings.

  Keep the manual review queue order, but annotate each item with the evidence that drove its rank.
- Map findings to the BOD 26-04 profile. For an external scan, "internet-exposed" is always true and needs no inference. The tool can mark "KEV: yes/no" and pull "automatable" and "technical impact" from CISA Vulnrichment ADP data in CVE records. That gives a "BOD 26-04 tier (indicative)" column, useful to US federal and contractor clients.
- Store `cvss_version`, `cvss_vector` and the nomenclature label (for example `CVSS-B 9.3` or `CVSS:3.1 8.1`) for each finding. The ASV pre-check needs v3.x while modern prioritisation uses v4.0.
- KEV and EPSS lookups need network access to cisa.gov and api.first.org. They should be cached and dated, and the snapshot date and EPSS model version should be recorded in `report.json`, since EPSS changes daily and KEV grows. Failure to fetch must be a `Degradation` ("exploitability enrichment not performed"). That follows the repo rule that reduced coverage never looks clean.
- Most extscan findings are misconfigurations or exposures without CVEs, such as an exposed .env file or the Redis service in the lab report. For these, SSVC-style decision points (exploitation: none/PoC/active; automatable: yes/no; technical impact: partial/total) can be applied directly by rule or by the auditor. That gives a consistent priority language for CVE and non-CVE findings.

### Gaps
- I did not fetch BOD 26-04 primary text to confirm the exact tier table, the 16 profiles or the effective dates.
- I did not retrieve FIRST's "Using EPSS" guidance text or EPSS v4 model details. The "1,600+ variables" claim appears only in low-quality blogs.
- I did not check how major scanners (Nessus VPR, Qualys TruRisk, Rapid7) display KEV and EPSS in their UI, beyond the existence of BOD 26-04 integrations.
- I did not verify SSVC's latest version on CERT/CC's SSVC docs site (certcc.github.io/SSVC), including the "Deployer" tree and the "Exposure" decision point.

## 4. Machine-readable output standards (SARIF, OCSF, CycloneDX/VEX, DefectDojo, OpenVAS/Nessus)

### Takeaway
The best integration targets are OCSF Vulnerability Finding (class_uid 2002, schema 1.9.0) for SIEM and data lake ingestion (AWS Security Lake and Security Hub use OCSF), and a DefectDojo-compatible import. DefectDojo already parses Nmap, Nuclei, sslscan, OpenVAS and SARIF natively, plus a Generic Findings format. SARIF 2.1.0 is built for static analysis but can address any URI-addressable artifact and has fingerprints and baselineState for diffing. It is a reasonable secondary output. CycloneDX/VEX has little fit for an external scanner, which does not produce SBOMs.

### Cited Findings
- OCSF Vulnerability Finding: class_uid 2002, category 2 (Findings), schema version 1.9.0. type_uid values are 200201 Create, 200202 Update and 200203 Close.
  - Required: `finding_info`, `vulnerabilities` (array), `severity_id` (0–6, 99), `activity_id`, `time`, `metadata`.
  - Recommended: `resources`, `status_id` (1 New, 2 In Progress, 3 Suppressed, 4 Resolved), `observables`, `confidence_id`.
  - Aggregation: `count`, `start_time`, `end_time`.

  — [OCSF schema: Vulnerability Finding](https://schema.ocsf.io/classes/vulnerability_finding)
- The OCSF Vulnerability Details object includes `cve`, `cwe` and `advisory` (mutually exclusive: just one must be present), `is_exploit_available`, `exploit_last_seen_time`, `exploit_ref_url`, `is_fix_available`, `fix_coverage_id`, `remediation`, `first_seen_time`, `last_seen_time`, `references`, `severity`, `title`, `desc` and `vendor_name`. There is no dedicated KEV attribute in this object. CVSS and EPSS live in the CVE object, which was not checked. — [OCSF Vulnerability object 1.9.0](https://schema.ocsf.io/1.9.0/objects/vulnerability)
- AWS Security Hub supports findings in OCSF schema 1.6, and Security Lake maps to Vulnerability Finding, Compliance Finding and Detection Finding classes. — [AWS Security Hub OCSF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ocsf.md), [Amazon Security Lake OCSF](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html)
- SARIF 2.1.0 plus Errata 01 is an OASIS Standard (errata version 28 Aug 2023; original 27 Mar 2020). It is defined as "a standard format for the output of static analysis tools," but "SARIF can represent results detected in any URI-addressable artifact." It includes `webRequest`/`webResponse` objects, property bags, `fingerprints`/`partialFingerprints` (stable IDs for tracking a result over time) and `baselineState` for comparing a run against a baseline. — [OASIS SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- DefectDojo's parser list includes Nuclei, Nmap, SARIF, OpenVAS, Sslscan and Tenable, but no separate "Nessus" entry, plus a Generic Findings Import. — [DefectDojo parsers](https://docs.defectdojo.com/supported_tools/parsers/file/generic/)

### Inferences
- Priority order for new outputs:
  1. OCSF 2002 JSON (one event per finding, `status_id` for retest state, `first_seen_time`/`last_seen_time` across runs) for SIEM, data lake and Security Hub users.
  2. DefectDojo Generic Findings JSON. Alternatively, rely on DefectDojo's native Nuclei, Nmap and sslscan parsers by shipping extscan's raw tool outputs in a predictable layout. Generic import keeps extscan's own findings, review-queue questions and coverage gaps, which raw tool parsers would lose.
  3. SARIF, mainly for GitHub/GitLab code-scanning-style dashboards and baseline diffing. Use `partialFingerprints` such as host+port+check-id for stable de-duplication. It is a poor fit for network assets but not prohibited by the spec.
- OpenVAS or Nessus XML emulation is low value and high effort. Both formats are vendor-specific. DefectDojo and most platforms ingest raw Nmap and Nuclei output directly.
- CycloneDX/VEX: extscan does not produce an SBOM. VEX statements ("not_affected" with a justification) are conceptually similar to extscan's dispute and false-positive records, but no standard consumer expects VEX from a network scanner.
- Whatever the format, every finding needs a stable ID that survives across runs (deterministic from host, port, protocol and check). That is the prerequisite for retest status, diffing and platform de-duplication.

### Gaps
- I could not retrieve DefectDojo's Generic Findings Import field list (the page content was truncated). I did not confirm whether it accepts `cvssv4`, `epss_score`, `epss_percentile`, `known_exploited` or `ransomware_used`.
- I did not check the OCSF CVE object fields (cvss array, epss object) or whether OCSF 1.9 has added a KEV flag.
- I did not research CycloneDX 1.6/1.7 vulnerability or VEX schema details, or the OpenVAS and Nessus `.nessus` XML structure.

## 5. Evidence and chain-of-custody practice

### Takeaway
I found few authoritative sources specific to chain of custody for pentest evidence in the time available. The relevant standards point the same way: per-finding timestamps and stable IDs (OCSF, SARIF), raw-output integrity, interference recording (ASV), and dated enrichment snapshots. BOD 26-04's forensic-triage emphasis on preserving evidence before patching also highlights why scan timestamps and raw evidence matter.

### Cited Findings
- OCSF findings carry `time`, `start_time`/`end_time`, `first_seen_time`/`last_seen_time` and `metadata` (producer, schema version), which supports provenance of each finding. — [OCSF Vulnerability Finding](https://schema.ocsf.io/classes/vulnerability_finding), [OCSF Vulnerability object](https://schema.ocsf.io/1.9.0/objects/vulnerability)
- SARIF fingerprints are a "stable value" that lets a result management system identify a result over time. Baselines (the result set of one run) are compared with later runs via `baselineState`. — [OASIS SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- The ASV Program Guide requires interference that prevents scan completion to be recorded as a failure, and requires ASV conclusions on disputes to be documented in the report. — [ASV Program Guide v4.0r2 (Scribd copy)](https://www.scribd.com/document/686715606/ASV-Program-Guide-v4-0r2)
- CISA's BOD 26-04 implementation guidance reportedly separates rapid evidence preservation from patching, because patching changes files, logs and timestamps. — [CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-bod-26-04-risk-based-vulnerability-re/) (secondary)
- AWS forwards abuse reports about your testing to you. You answer with approved use-case language and a contact point. — [AWS Penetration Testing policy](https://aws.amazon.com/security/penetration-testing/)

### Inferences
- Suggested features, each grounded in the needs above:
  - A per-run manifest with a SHA-256 of every raw tool output file, `report.md` and `report.json`, ideally hash-chained or signed. The tool already logs `commands.jsonl` with timings.
  - Source IP, egress ASN and hostname of the scanning host recorded at run start. A client SOC answering "what hit us" needs it, and AWS and other providers forward abuse reports to the tester.
  - A hash, or a stored copy, of the authorisation letter or SOW in the run directory, linked from `scope.json` (`authorization.document_sha256`).
  - Tool versions, nuclei template version and commit, and the policy profile in `report.json`. That makes repeatability verifiable. The report already shows "extscan 0.1.0, profile quick".
  - A run diff (`extscan diff <runA> <runB>`) with New, Unchanged and Resolved (or "Not re-observed: coverage gap") states keyed by stable finding IDs. Map these to OCSF `status_id` and SARIF `baselineState`.
  - Retest mode: rerun only the checks behind specific findings and record "verified fixed at <timestamp> by <check>" evidence. A finding that cannot be retested because the tool failed must stay open, not resolved, consistent with the repo rule.
- Evidence redaction: the repo's vault keeps unredacted evidence. The report should mark which artefacts contain live secrets, such as the .env contents in the lab report, and support a redacted export for wider distribution.

### Gaps
- I found no specific standard such as ISO/IEC 27037 (digital evidence) or CREST guidance on pentest evidence retention or chain of custody. ISO/IEC 27037 is relevant from my own knowledge but was not verified.
- I did not verify NIST SP 800-115's data-handling recommendations (secure storage, transmission and destruction of assessment data).

## 6. Responsible and safe scanning practice (rate limits, windows, identification, third-party hosting)

### Takeaway
Cloud provider policies permit customers to test their own resources without pre-approval, within strict rules: no DoS or flooding, no Route 53 zone walking, no subdomain or S3 takeover on AWS, and a 24-hour duty to report AWS service vulnerabilities. This means extscan needs a per-target hosting-provider classifier and policy notes, rate-limit enforcement, and testing-window enforcement. The repo already has a testing window in the scope file.

### Cited Findings
- AWS, as of 2026: customers may test these services without prior approval: EC2, WAF, NAT Gateways, ELB, RDS, Aurora, CloudFront, API Gateway, AppSync, Lambda and Lambda@Edge, Lightsail, Elastic Beanstalk, ECS/Fargate, OpenSearch, FSx, Transit Gateway, Bedrock AgentCore and Global Accelerator. Other services need AWS Support or account-team engagement. — [AWS Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- AWS prohibits:
  - DNS zone walking via Route 53 Hosted Zones, and DNS hijacking or pharming via Route 53.
  - DoS/DDoS and simulated DoS.
  - Port, protocol and request flooding, including login and API request flooding.
  - S3 bucket takeover and subdomain takeover.
  - Outbound pentesting from API Gateway or Bedrock AgentCore.

  "Tools with DoS capability must be able to disable that capability." Banner grabbing is allowed. Vulnerabilities in AWS services must be reported to AWS Security within 24 hours of completing testing. Simulated events, such as red teaming or C2, need a form with at least two weeks' notice. — [AWS Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- Azure: no pre-approval since 2017, but testing must follow Microsoft's Cloud Unified Penetration Testing Rules of Engagement (no DoS, no testing of Azure's own infrastructure). Sources disagree on whether notification is optional. Google Cloud: no notification or approval needed for your own projects. The Acceptable Use Policy applies, and activity affecting other customers can lead to suspension. — [7A Security (secondary, Aug 2026)](https://7asecurity.com/blog/2026/08/cloud-penetration-testing/), [Blaze Information Security (secondary)](https://www.blazeinfosec.com/post/cloud-penetration-testing-buyers-guide/)
- PCI SSC has an FAQ on how DoS vulnerabilities affect ASV pass/fail. It is relevant because the ASV programme expects scans to avoid disruption. — [PCI SSC FAQ](https://www.pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/How-would-an-identified-Denial-of-Service-DoS-vulnerability-affect-a-company-s-ability-to-pass-a-PCI-DSS-vulnerability-scan-from-an-Approved-Scanning-Vendor-ASV) (not fetched)

### Inferences
- Add hosting-provider attribution per target, from published cloud IP ranges and ASN or reverse DNS. Annotate the report: "Target 203.0.113.5 is in AWS EC2 range; AWS policy permits testing; report AWS-service vulnerabilities within 24 h." Flag targets in providers whose policy needs pre-approval or bans the testing. Third-party SaaS and CDN assets, such as Cloudflare, Akamai or Salesforce-hosted, where the client cannot authorise testing, should go to the manual review queue as "authorisation from the platform owner needed."
- Subdomain-takeover checks: AWS explicitly prohibits performing S3 bucket or subdomain takeover. Detecting a dangling CNAME is fine; claiming it is not. This belongs in `extscan/policy.py`'s excluded nuclei tags or as a safety invariant test, if not already there.
- AWS requires DoS-capable tools to be able to disable that capability. extscan's excluded nuclei tags and NSE scripts are exactly that control. Cite the policy in the README and safety tests as the external justification.
- Make rate limits explicit and recorded: packets per second and requests per second per host in policy, and printed in the report's methodology section. AWS prohibits "request flooding," and clients want proof of throttling.
- Enforce the testing window at runtime, refusing to start or continue outside `window_start`/`window_end`. Record any pause or resume.
- Scanner identification: a configurable User-Agent containing the engagement reference and a contact, an optional reverse-DNS or scan-notice page on the source IP, and the source IP in the report. This lets SOCs and cloud abuse desks route complaints. That last point is common industry practice and is not cited from a standard here.

### Gaps
- I did not fetch the primary Microsoft Cloud Penetration Testing Rules of Engagement or the Google Cloud AUP and security-testing pages, so the Azure and GCP details are secondary.
- I did not research Cloudflare, Akamai, Fastly or major SaaS (Salesforce, Shopify, Atlassian) testing policies.
- I found no standard that mandates a scanner User-Agent or reverse-DNS convention. RFC 9116 (security.txt) is relevant for contact discovery but was not checked.

## 7. Reporting best practice (executive summary, risk ratings, remediation, retest status)

### Takeaway
I gathered limited primary material on pentest report structure in this pass. The standards found imply a report that pins the score source and version (CVSS nomenclature), shows exploitation context (KEV, EPSS), includes an exceptions, false-positive and compensating-controls section (ASV), tracks lifecycle and retest state (OCSF `status_id`, SARIF `baselineState`), and states methodology version references (WSTG-v42 IDs, ATT&CK version).

### Cited Findings
- ASV reports must use official templates, and disputes and compensating controls are documented under "Exceptions, False Positives, or Compensating Controls." — [PCI SSC FAQ](https://pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/I-have-had-an-external-vulnerability-scan-completed-by-an-ASV-does-this-mean-I-am-PCI-DSS-compliant), [ASV Program Guide v4.0r2 (Scribd copy)](https://www.scribd.com/document/686715606/ASV-Program-Guide-v4-0r2)
- CVSS numerical values must be shown with the B/BT/BE/BTE nomenclature. The qualitative rating scale is optional. — [FIRST CVSS v4.0](https://www.first.org/cvss/v4-0/specification-document)
- OCSF finding lifecycle states: New, In Progress, Suppressed, Resolved. — [OCSF Vulnerability Finding](https://schema.ocsf.io/classes/vulnerability_finding)
- WSTG recommends version-qualified test identifiers. — [OWASP WSTG](https://github.com/owasp/wstg)
- Remediation framing for US federal clients is now driven by BOD 26-04 tiers (3, 14 or 60 days, or deferral), not CVSS. — [CSA note on BOD 26-04](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-bod-26-04-risk-based-vulnerability-re/)

### Inferences
- Gaps in extscan's current report relative to these standards, based on the sample `report.md`:
  1. No per-finding CVSS vector or version, and no KEV or EPSS.
  2. No exceptions, false-positives or accepted-risk section.
  3. No retest or lifecycle status per finding.
  4. No methodology references (WSTG, ATT&CK, NIST 800-115) per finding.
  5. No scanner source IP or rate-limit statement.
  6. The executive summary is a severity count table plus coverage-gap warning. It could add a three-sentence business-risk narrative and a "top 5 actions" list ranked by KEV, EPSS and exposure.
- A retest report should show each original finding with its status (Open, Fixed (verified), Fixed (not verifiable: coverage gap), Risk accepted, False positive), with the evidence and timestamp of the retest check.
- The manual review queue maps naturally to "auditor judgement" fields. Recording the auditor's decision, reviewer and date per item would make the report auditable end to end.

### Gaps
- I did not retrieve CREST, PTES or SANS reporting guidance, or published sample reports, to cite canonical section lists such as executive summary, scope, methodology, findings, remediation and appendices.
- I found no authoritative standard defining retest-status vocabulary for pentest reports. OCSF `status_id` is the closest machine-readable equivalent.
