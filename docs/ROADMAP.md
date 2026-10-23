# What else is worth adding

A prioritised list, written from the point of view of "what would save the
audit team the most time per engagement, or stop the most reports going out
wrong". Each entry notes the work involved and the catch, because several of
these look cheaper than they are.

Ordering is a recommendation, not a plan — your engagement mix should decide.
If most of your work is cloud-hosted estates, tier 2's cloud asset
correlation jumps above everything in tier 1.

---

## Tier 1 — highest value for the effort

### 1. Screenshotting every web service (done: `extscan screenshot`)
**Why:** the single biggest time saver in the manual phase. An auditor
triaging forty web services currently opens forty browser tabs. A contact
sheet answers "which of these are default installs, which are real apps,
which are printer admin panels" in about ten seconds.
**How:** Chromium via Playwright or `gowitness`, one image per service, a
thumbnail grid in the report.
**Catch:** headless Chromium is a heavy dependency and the first thing a
hardened jump box will not have. Make it an optional extra like the LLM layer,
and keep the grid out of the JSON report (base64 images bloat it).

### 2. Virtual-host and SNI enumeration
**Why:** one IP commonly serves a dozen sites, and scanning by IP finds only
the default vhost. This is the most frequent cause of "the scan missed the
application entirely". The TLS certificate SANs we already collect are a free
source of candidate hostnames.
**How:** collect names from cert SANs (already parsed), the subdomain stage,
and reverse DNS; re-request each service with each `Host` header; report
distinct responses.
**Catch:** needs scope care — a hostname resolving elsewhere is out of scope
even if it is served by an in-scope IP. The existing `assert_url` guard covers
the fetch, but the finding needs to say which name produced which response.

### 3. HTTP method and auth-bypass checks
**Why:** cheap, high-yield, and entirely read-only in the safe subset. `TRACE`
enabled, `OPTIONS` disclosing unexpected verbs, and 403s that become 200s with
a path-case change or a `X-Original-URL` header are common real findings.
**How:** per-service, a small matrix of requests against an already-known
403/401 path.
**Catch:** the full technique shades into exploitation. Restrict to GET/OPTIONS
/TRACE/HEAD and header variations; never `PUT`, never a verb that writes.

### 4. Certificate inventory and expiry tracking
**Why:** we already parse every certificate. Aggregating them across the
estate turns a pile of per-host findings into one useful table: what expires
in the next 30 days, which certs are shared across hosts (and therefore which
private key compromise is widest), which CAs are in use.
**How:** a report section built from data already collected. Mostly reporting
work.
**Catch:** none worth mentioning. This is the cheapest item on the list.

### 5. Diffing against a previous run
**Why:** external perimeters are re-tested quarterly. "What changed since
last time" is the question the client actually asks, and currently answering
it means comparing two PDFs by hand. A new open port on a host that was
previously clean is more interesting than a finding that has been there for
two years.
**How:** `extscan diff <old-run> <new-run>` over the existing JSON — new/closed
services, new/resolved findings, changed versions. The run directory format
already supports it.
**Catch:** finding IDs are derived from host/port/title, so a reworded title
reads as "resolved + new". Either keep title wording stable or diff on a
coarser key.

---

## Tier 2 — substantial value, more work

### 6. Cloud asset correlation
**Why:** the subdomain stage already finds names resolving outside scope, and
the most valuable version of that finding is "this points at an S3 bucket /
Azure blob / GitHub Pages site that is unclaimed". Dangling-record takeover is
a critical finding that costs nothing to check once you know where the record
points.
**How:** resolve CNAME chains, match against a fingerprint list of provider
takeover signatures, then one HTTP request to check for the unclaimed marker.
**Catch:** claiming a bucket to prove the finding is **not** read-only and not
authorised. Report the condition and let the client confirm.

### 7. Email security posture (SPF, DKIM, DMARC, MTA-STS)
**Why:** routinely in scope for an external review, entirely passive, and the
findings are unambiguous: no DMARC, `~all` instead of `-all`, missing MTA-STS.
Clients act on these because the fix is a DNS record.
**How:** DNS TXT lookups per domain, plus parsing. No new dependency if we
keep to `getaddrinfo`-adjacent stdlib resolution — though TXT records need a
real resolver, so this probably means a minimal DNS client or `dnspython` as
an optional extra.
**Catch:** the stdlib cannot query TXT records. That dependency decision is
the whole cost of this item.

### 8. Authenticated scanning support
**Why:** the biggest category we currently refuse. Plenty of external
engagements include credentials for a portal, and "here is what an
authenticated attacker sees" is where the serious findings live.
**How:** a credential store in the scope file (referencing a secrets manager,
not inline), session acquisition per application, and nuclei's auth support.
**Catch:** this changes the project's risk profile substantially. Every safety
property that currently holds because we never authenticate would need
re-examining, and a bug could lock out a client's user or modify data. Treat
as a separate mode with its own authorisation field in the scope file.

### 9. Rate-limit and WAF detection
**Why:** a WAF silently dropping requests makes every other result unreliable,
and right now we would report "no findings" for a service behind one. Knowing
we were blocked is as important as any finding.
**How:** watch for response-time cliffs, 429s, challenge pages and
block-page fingerprints; raise a coverage gap (the mechanism already exists)
rather than a finding.
**Catch:** needs care to avoid false positives on slow-but-honest servers.

### 10. Protocol-specific probes we do not cover
**Why:** each is a real external exposure we currently only report as "port
open".
- **SMB** — signing not required, SMBv1 enabled, null-session share listing
- **RDP** — NLA not enforced, certificate detail, BlueKeep-era version checks
- **FTP/SFTP** — anonymous access, banner, TLS support
- **Databases** — pre-auth banner detail for MSSQL/MySQL/Postgres/Oracle
- **Kubernetes** — anonymous access to the API server, kubelet read-only port
- **Docker** — unauthenticated socket, registry catalogue listing
**How:** one probe module each, same registry pattern as the existing ones.
**Catch:** mostly the temptation to authenticate. Null-session SMB listing is
read-only and fine; a credential guess is not.

---

## Tier 3 — valuable but larger projects

### 11. Agent-driven adaptive probing
**Why:** the deepest use of the model layer. Instead of a fixed probe
registry, let the model propose the next check from what has been found,
within a safety envelope it cannot widen.
**How:** a constrained action space (the model may only select from registered
read-only probes and in-scope targets), with every selection logged.
**Catch:** this is the point where prompt injection in a response body could
start steering the scan. The action space must be a closed allow-list enforced
in code — never a URL or command the model supplies. Worth doing carefully,
not quickly.

### 12. Continuous monitoring mode
**Why:** turns a quarterly engagement into a service. Re-run on a schedule,
alert on what changed, track remediation over time.
**How:** builds directly on run diffing (item 5) plus scheduling and a
notification sink.
**Catch:** authorisation windows. The scope file's testing window is currently
enforced per run; continuous operation needs a standing authorisation model
and a hard stop when it lapses.

### 13. Findings database across engagements
**Why:** enables "this client's TLS posture over four quarters", per-client
remediation SLAs, and cross-client benchmarking ("your exposure is typical for
your sector"), which is genuinely saleable.
**How:** SQLite or Postgres behind the existing store interface.
**Catch:** client data separation becomes a real design problem rather than a
directory boundary. Also a retention and deletion obligation you may not want.

### 14. Report output formats
**Why:** the Markdown and JSON are for us; clients want their template. DOCX
with the firm's branding, or a direct push into their ticketing system.
**How:** a renderer per format from the existing JSON. The report is already
cleanly separated from collection.
**Catch:** none technically — it is the kind of work that expands to fill
whatever time you give it. Timebox it.

### 15. Distributed scanning
**Why:** large engagements and geo-distributed perimeters. Also lets you see
what differs between source regions, which catches geo-filtering and
split-horizon DNS.
**How:** the run store is already the coordination point; workers claim
chunks (the checkpoint mechanism is the right primitive).
**Catch:** significant complexity for a benefit most engagements will not
need. Only worth it if scan duration is actually your bottleneck.

---

## Deliberately not planned

- **Exploitation or proof-of-concept execution.** The read-only property is
  what makes this safe to point at production, and it is load-bearing for
  every other safety claim in the project.
- **Credential brute-forcing or spraying.** Locks out client accounts and
  needs separate authorisation that a scanner should not assume it has.
- **DoS or stress testing.** Excluded from the nuclei template set on purpose.
- **Active subdomain brute-forcing by default.** Heavy DNS traffic for names
  that passive sources mostly already have. The policy flag exists; the
  default stays off.
- **Scanning anything the scope file does not authorise**, however
  interesting it looks. This is the one item on the list that is not a
  trade-off.
