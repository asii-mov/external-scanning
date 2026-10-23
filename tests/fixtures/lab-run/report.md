# External attack surface assessment: extscan local lab

**Client:** Local workstation (operator-owned)  
**Report generated:** 2026-10-23 09:18:41 UTC  
**Run id:** `20261023-090822-extscan-local-lab`  
**Tooling:** extscan 0.1.0, profile `quick`

## Authorisation

- **Reference:** LOCAL-LAB
- **Authorised by:** operator (owns this host)
- **Testing window:** 2026-01-01T00:00:00Z to 2027-12-31T23:59:59Z
- **Constraints:** Loopback-only test lab started by `python -m tests.lab`. Nothing here leaves the machine.

### Scope

- `127.0.0.2/32`

## Summary

1 of 1 responding host(s) produced findings across 9 open service(s) (8 TCP, 1 UDP, 5 speaking HTTP).

| Severity | Findings |
|---|---|
| Critical | 5 |
| High | 19 |
| Medium | 14 |
| Low | 8 |
| Informational | 122 |
| **Total** | **168** |

42 item(s) require manual review before this report is issued; 97 distinct issue(s) were identified, of which 0 appear across three or more hosts.

## Manual review queue

Automated checks establish that something is exposed; they cannot decide whether it is acceptable for this client. Each item below names the specific question an auditor needs to answer. Work top to bottom.

| # | Severity | Item | Target | An auditor must decide |
|---|---|---|---|---|
| 1 | Critical | Credential-bearing file readable at http://127.0.0.2:8080/.env _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Confirm these are live production credentials and drive the rotation. This is usually the highest-priority item in a report. |
| 2 | Critical | Docker API (plaintext) reachable from the internet on 127.0.0.2:2375/tcp | `127.0.0.2:2375/tcp` | Confirm whether Docker API (plaintext) on this host is intentional and, if so, whether authentication and patch level are adequate. Do not test credentials without explicit written approval. |
| 3 | Critical | Elasticsearch reachable from the internet on 127.0.0.2:9200/tcp | `127.0.0.2:9200/tcp` | Confirm whether Elasticsearch on this host is intentional and, if so, whether authentication and patch level are adequate. Do not test credentials without explicit written approval. |
| 4 | Critical | Redis reachable from the internet on 127.0.0.2:6379/tcp | `127.0.0.2:6379/tcp` | Confirm whether Redis on this host is intentional and, if so, whether authentication and patch level are adequate. Do not test credentials without explicit written approval. |
| 5 | High | MySQL reachable from the internet on 127.0.0.2:3306/tcp | `127.0.0.2:3306/tcp` | Confirm whether MySQL on this host is intentional and, if so, whether authentication and patch level are adequate. Do not test credentials without explicit written approval. |
| 6 | High | Unauthenticated API endpoint confirmed reachable: http://127.0.0.2:8080/api/admin/users _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Check whether the returned data is sensitive, and whether other endpoints from the same spec behave the same way. Do not enumerate records beyond what proves the finding. |
| 7 | High | 5 API operation(s) declare no authentication, including 2 that modify data | `127.0.0.2:8080/tcp` | extscan did not call these endpoints -- invoking undocumented write operations on a live system risks changing client data. An auditor should confirm, on the read-only endpoints first, whether the lack of declared authentication is real. |
| 8 | High | Exposed /.env on 127.0.0.2:8080 _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Confirm what this actually discloses for this client and whether the exposure is already known/accepted. |
| 9 | High | Exposed diagnostic handler /elmah.axd on 127.0.0.2:8081 | `127.0.0.2:8081/tcp` | Check what the handler is currently exposing. If it has been serving other users' session identifiers or credentials, this is an incident to raise with the client now, not a finding to file. |
| 10 | High | Exposed diagnostic handler /trace.axd on 127.0.0.2:8081 | `127.0.0.2:8081/tcp` | Check what the handler is currently exposing. If it has been serving other users' session identifiers or credentials, this is an incident to raise with the client now, not a finding to file. |
| 11 | High | WebDAV appears enabled on 127.0.0.2:8081 with write verbs (COPY, DELETE, MKCOL, MOVE, PUT) | `127.0.0.2:8081/tcp` | extscan read the advertised verb list only -- it did not attempt PUT or DELETE, because writing to a client's server is a change rather than a test. An auditor should confirm whether the write verbs are genuinely usable, with explicit written approval for that step. |
| 12 | Medium | Exposed API specification: ACME Billing API (9 operations) | `127.0.0.2:8080/tcp` | An auditor must decide whether publishing this spec is intended. If the API is public by design this may be acceptable; the operations listed below still need review. |
| 13 | Medium | GraphQL introspection enabled at http://127.0.0.2:8080/graphql _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Review the schema for fields that should not be reachable by unauthenticated callers and for mutations that change data. |
| 14 | Medium | Exposed /graphql on 127.0.0.2:8080 _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Confirm what this actually discloses for this client and whether the exposure is already known/accepted. |
| 15 | Medium | Exposed /metrics on 127.0.0.2:8080 _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Confirm what this actually discloses for this client and whether the exposure is already known/accepted. |
| 16 | Medium | Exposed /swagger.json on 127.0.0.2:8080 _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Confirm what this actually discloses for this client and whether the exposure is already known/accepted. |
| 17 | Medium | IIS 8.3 short-name enumeration possible on 127.0.0.2:8081 | `127.0.0.2:8081/tcp` | extscan confirmed the condition with two requests and did not enumerate. Deciding whether to run a full enumeration -- thousands of requests against a production site -- is the auditor's call. |
| 18 | Low | Self-signed TLS certificate on 127.0.0.2:8443 | `127.0.0.2:8443/tcp` | Decide whether this endpoint is user-facing (a real problem) or an internal appliance interface (often accepted). |
| 19 | Informational | API specification references hosts outside the engagement scope | `127.0.0.2:8080/tcp` | Confirm with the client whether these hosts belong to them and should be added to scope for a future assessment. |
| 20 | Informational | GraphQL API Detection | `127.0.0.2:8080/tcp` | GraphQL endpoint. Check introspection and whether mutations are exposed. |
| 21 | Informational | API exposes 4 operation(s) on sensitive-looking resources | `127.0.0.2:8080/tcp` | Decide which of these warrant authenticated testing under a separate, explicitly scoped engagement. |
| 22 | Informational | Content review: http://127.0.0.2:9200/?pretty _(+6 related, listed below)_ | `127.0.0.2:9200/tcp` | An auditor should judge whether the content disclosed here matters for this client. |
| 23 | Informational | Default IIS content at /iisstart.htm on 127.0.0.2:8081 | `127.0.0.2:8081/tcp` | A default install page often means an unmaintained or forgotten site. Establish who owns it. |
| 24 | Informational | HTTP service: ACME Billing — API Console on 127.0.0.2:8080 _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | An auditor should confirm whether this application is intended to be internet-facing, and who owns it. |
| 25 | Informational | HTTP service: Intranet on 127.0.0.2:8081 | `127.0.0.2:8081/tcp` | An auditor should confirm whether this application is intended to be internet-facing, and who owns it. |
| 26 | Informational | HTTP service: untitled on 127.0.0.2:9200 _(+1 related, listed below)_ | `127.0.0.2:9200/tcp` | An auditor should confirm whether this application is intended to be internet-facing, and who owns it. |
| 27 | Informational | SSH service on 127.0.0.2:2222 | `127.0.0.2:2222/tcp` | Confirm key-only authentication and whether exposure to the whole internet is required. Banner-based version checks are indicative only; distributions backport fixes without changing the banner. |
| 28 | Informational | http-comments-displayer on 127.0.0.2:8080/tcp _(+3 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 29 | Informational | http-date on 127.0.0.2:8080/tcp _(+2 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 30 | Informational | http-fetch on 127.0.0.2:8080/tcp _(+3 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 31 | Informational | http-headers on 127.0.0.2:8080/tcp _(+3 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 32 | Informational | http-malware-host on 127.0.0.2:8080/tcp _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 33 | Informational | http-methods on 127.0.0.2:8081/tcp | `127.0.0.2:8081/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 34 | Informational | http-mobileversion-checker on 127.0.0.2:8080/tcp _(+3 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 35 | Informational | http-referer-checker on 127.0.0.2:8080/tcp _(+3 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 36 | Informational | http-robots.txt on 127.0.0.2:8080/tcp _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 37 | Informational | http-security-headers on 127.0.0.2:8443/tcp | `127.0.0.2:8443/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 38 | Informational | http-title on 127.0.0.2:8080/tcp _(+3 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 39 | Informational | http-useragent-tester on 127.0.0.2:8080/tcp _(+3 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 40 | Informational | http-vuln-cve2017-1001000 on 127.0.0.2:8080/tcp _(+1 related, listed below)_ | `127.0.0.2:8080/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 41 | Informational | http-webdav-scan on 127.0.0.2:8081/tcp | `127.0.0.2:8081/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |
| 42 | Informational | ssl-cert on 127.0.0.2:8443/tcp | `127.0.0.2:8443/tcp` | Script output is informational; an auditor should judge whether what it exposes matters for this client. |

Where one queue entry covers several instances:

- **#1** (2 instances):
  - Credential-bearing file readable at http://127.0.0.2:8080/.env
  - Credential-bearing file readable at https://127.0.0.2:8443/.env
- **#6** (2 instances):
  - Unauthenticated API endpoint confirmed reachable: http://127.0.0.2:8080/api/admin/users
  - Unauthenticated API endpoint confirmed reachable: http://127.0.0.2:8080/api/health
- **#8** (2 instances):
  - Exposed /.env on 127.0.0.2:8080
  - Exposed /.env on 127.0.0.2:8443
- **#13** (2 instances):
  - GraphQL introspection enabled at http://127.0.0.2:8080/graphql
  - GraphQL introspection enabled at https://127.0.0.2:8443/graphql
- **#14** (2 instances):
  - Exposed /graphql on 127.0.0.2:8080
  - Exposed /graphql on 127.0.0.2:8443
- **#15** (2 instances):
  - Exposed /metrics on 127.0.0.2:8080
  - Exposed /metrics on 127.0.0.2:8443
- **#16** (2 instances):
  - Exposed /swagger.json on 127.0.0.2:8080
  - Exposed /swagger.json on 127.0.0.2:8443
- **#22** (7 instances):
  - Content review: http://127.0.0.2:8080/metrics
  - Content review: http://127.0.0.2:8080/robots.txt
  - Content review: http://127.0.0.2:8081/elmah.axd
  - Content review: http://127.0.0.2:8081/trace.axd
  - Content review: http://127.0.0.2:9200/?pretty
  - Content review: https://127.0.0.2:8443/metrics
  - Content review: https://127.0.0.2:8443/robots.txt
- **#24** (2 instances):
  - HTTP service: ACME Billing — API Console on 127.0.0.2:8080
  - HTTP service: ACME Billing — API Console on 127.0.0.2:8443
- **#26** (2 instances):
  - HTTP service: untitled on 127.0.0.2:2375
  - HTTP service: untitled on 127.0.0.2:9200
- **#28** (4 instances):
  - http-comments-displayer on 127.0.0.2:8080/tcp
  - http-comments-displayer on 127.0.0.2:8081/tcp
  - http-comments-displayer on 127.0.0.2:8443/tcp
  - http-comments-displayer on 127.0.0.2:9200/tcp
- **#29** (3 instances):
  - http-date on 127.0.0.2:8080/tcp
  - http-date on 127.0.0.2:8081/tcp
  - http-date on 127.0.0.2:8443/tcp
- **#30** (4 instances):
  - http-fetch on 127.0.0.2:8080/tcp
  - http-fetch on 127.0.0.2:8081/tcp
  - http-fetch on 127.0.0.2:8443/tcp
  - http-fetch on 127.0.0.2:9200/tcp
- **#31** (4 instances):
  - http-headers on 127.0.0.2:8080/tcp
  - http-headers on 127.0.0.2:8081/tcp
  - http-headers on 127.0.0.2:8443/tcp
  - http-headers on 127.0.0.2:9200/tcp
- **#32** (2 instances):
  - http-malware-host on 127.0.0.2:8080/tcp
  - http-malware-host on 127.0.0.2:8443/tcp
- **#34** (4 instances):
  - http-mobileversion-checker on 127.0.0.2:8080/tcp
  - http-mobileversion-checker on 127.0.0.2:8081/tcp
  - http-mobileversion-checker on 127.0.0.2:8443/tcp
  - http-mobileversion-checker on 127.0.0.2:9200/tcp
- **#35** (4 instances):
  - http-referer-checker on 127.0.0.2:8080/tcp
  - http-referer-checker on 127.0.0.2:8081/tcp
  - http-referer-checker on 127.0.0.2:8443/tcp
  - http-referer-checker on 127.0.0.2:9200/tcp
- **#36** (2 instances):
  - http-robots.txt on 127.0.0.2:8080/tcp
  - http-robots.txt on 127.0.0.2:8443/tcp
- **#38** (4 instances):
  - http-title on 127.0.0.2:8080/tcp
  - http-title on 127.0.0.2:8081/tcp
  - http-title on 127.0.0.2:8443/tcp
  - http-title on 127.0.0.2:9200/tcp
- **#39** (4 instances):
  - http-useragent-tester on 127.0.0.2:8080/tcp
  - http-useragent-tester on 127.0.0.2:8081/tcp
  - http-useragent-tester on 127.0.0.2:8443/tcp
  - http-useragent-tester on 127.0.0.2:9200/tcp
- **#40** (2 instances):
  - http-vuln-cve2017-1001000 on 127.0.0.2:8080/tcp
  - http-vuln-cve2017-1001000 on 127.0.0.2:8443/tcp

## Findings

### Critical (5)

#### 1. Docker API (plaintext) reachable from the internet on 127.0.0.2:2375/tcp

- **Severity:** Critical
- **Affected:** `127.0.0.2:2375/tcp`
- **Detected by:** `extscan:exposure`
- **Finding id:** `eae7d9dc54db`
- **Tags:** `exposure`, `docker`

An unauthenticated Docker socket is container-host takeover. Detected as `docker` (Docker remote API).

> **Requires manual review.** Confirm whether Docker API (plaintext) on this host is intentional and, if so, whether authentication and patch level are adequate. Do not test credentials without explicit written approval.

**Evidence**

```text
127.0.0.2:2375/tcp open; service=docker; product=Docker remote API; version=
```

**Recommendation**

Restrict this port to known management sources at the perimeter, or move access behind a VPN/bastion. If the service must be public, confirm authentication is enforced and the build is current.

#### 2. Redis reachable from the internet on 127.0.0.2:6379/tcp

- **Severity:** Critical
- **Affected:** `127.0.0.2:6379/tcp`
- **Detected by:** `extscan:exposure`
- **Finding id:** `fb14769a080f`
- **Tags:** `exposure`, `redis`

Redis is unauthenticated by default and allows file writes. Detected as `redis` (Redis key-value store 5.0.7).

> **Requires manual review.** Confirm whether Redis on this host is intentional and, if so, whether authentication and patch level are adequate. Do not test credentials without explicit written approval.

**Evidence**

```text
127.0.0.2:6379/tcp open; service=redis; product=Redis key-value store; version=5.0.7
```

**Recommendation**

Restrict this port to known management sources at the perimeter, or move access behind a VPN/bastion. If the service must be public, confirm authentication is enforced and the build is current.

#### 3. Credential-bearing file readable at http://127.0.0.2:8080/.env

- **Severity:** Critical
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:secret_file`
- **Finding id:** `7aeab74d6f71`
- **Tags:** `secrets`, `information-disclosure`

The file is served to unauthenticated clients and contains 4 key(s) whose names indicate secrets. Values are redacted here deliberately: the finding is that they are reachable, and the report should not become another copy of the client's credentials.

> **Requires manual review.** Confirm these are live production credentials and drive the rotation. This is usually the highest-priority item in a report.

**Evidence**

```text
GET http://127.0.0.2:8080/.env -> 200  length: 305
secret-like keys present: AWS_ACCESS_KEY_ID, JWT_SIGNING_SECRET, SMTP_PASSWORD, STRIPE_SECRET_KEY

APP_ENV=production
DATABASE_URL=<redacted, 80 chars>
STRIPE_SECRET_KEY=<redacted, 32 chars>
JWT_SIGNING_SECRET=<redacted, 32 chars>
AWS_ACCESS_KEY_ID=<redacted, 25 chars>
SMTP_PASSWORD=<redacted, 18 chars>
DEBUG=false
```

**Recommendation**

Remove the file from the web root, block the path, and rotate every credential it contained -- treat them as compromised.

#### 4. Credential-bearing file readable at https://127.0.0.2:8443/.env

- **Severity:** Critical
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:secret_file`
- **Finding id:** `0440b29a93bf`
- **Tags:** `secrets`, `information-disclosure`

The file is served to unauthenticated clients and contains 4 key(s) whose names indicate secrets. Values are redacted here deliberately: the finding is that they are reachable, and the report should not become another copy of the client's credentials.

> **Requires manual review.** Confirm these are live production credentials and drive the rotation. This is usually the highest-priority item in a report.

**Evidence**

```text
GET https://127.0.0.2:8443/.env -> 200  length: 305
secret-like keys present: AWS_ACCESS_KEY_ID, JWT_SIGNING_SECRET, SMTP_PASSWORD, STRIPE_SECRET_KEY

APP_ENV=production
DATABASE_URL=<redacted, 80 chars>
STRIPE_SECRET_KEY=<redacted, 32 chars>
JWT_SIGNING_SECRET=<redacted, 32 chars>
AWS_ACCESS_KEY_ID=<redacted, 25 chars>
SMTP_PASSWORD=<redacted, 18 chars>
DEBUG=false
```

**Recommendation**

Remove the file from the web root, block the path, and rotate every credential it contained -- treat them as compromised.

#### 5. Elasticsearch reachable from the internet on 127.0.0.2:9200/tcp

- **Severity:** Critical
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `extscan:exposure`
- **Finding id:** `b624d7a6d80c`
- **Tags:** `exposure`, `elasticsearch`

Elasticsearch has no authentication by default. Detected as `http` (Elasticsearch REST API 6.8.0 name: es-node-1; cluster: billing-logs; Lucene 7.7.0).

> **Requires manual review.** Confirm whether Elasticsearch on this host is intentional and, if so, whether authentication and patch level are adequate. Do not test credentials without explicit written approval.

**Evidence**

```text
127.0.0.2:9200/tcp open; service=http; product=Elasticsearch REST API; version=6.8.0
```

**Recommendation**

Restrict this port to known management sources at the perimeter, or move access behind a VPN/bastion. If the service must be public, confirm authentication is enforced and the build is current.

### High (19)

#### 6. MySQL reachable from the internet on 127.0.0.2:3306/tcp

- **Severity:** High
- **Affected:** `127.0.0.2:3306/tcp`
- **Detected by:** `extscan:exposure`
- **Finding id:** `7f7984487ff6`
- **Tags:** `exposure`, `mysql`

Database engine exposed directly to the internet. Detected as `mysql` (MySQL 5.7.33-log).

> **Requires manual review.** Confirm whether MySQL on this host is intentional and, if so, whether authentication and patch level are adequate. Do not test credentials without explicit written approval.

**Evidence**

```text
127.0.0.2:3306/tcp open; service=mysql; product=MySQL; version=5.7.33-log
```

**Recommendation**

Restrict this port to known management sources at the perimeter, or move access behind a VPN/bastion. If the service must be public, confirm authentication is enforced and the build is current.

#### 7. 5 API operation(s) declare no authentication, including 2 that modify data

- **Severity:** High  (tentative -- needs confirmation)
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:openapi`
- **Finding id:** `2fd00072e735`
- **Tags:** `openapi`, `api`, `authentication`, `owasp-api`

These operations carry no security requirement in the specification, either explicitly (`security: []`) or because none was ever declared and there is no global requirement. The specification is a statement of intent, not proof: the gateway in front of the API may enforce auth regardless, and an operation may be protected in code but undocumented.

> **Requires manual review.** extscan did not call these endpoints -- invoking undocumented write operations on a live system risks changing client data. An auditor should confirm, on the read-only endpoints first, whether the lack of declared authentication is real.

**Evidence**

```text
unauthenticated operations (5):
  GET    /health
  POST   /invoices
  DELETE /invoices/{id}
  GET    /admin/users
  GET    /internal/debug/config

write operations with no declared auth (2):
  POST   /invoices
  DELETE /invoices/{id}
```

**Recommendation**

Declare and enforce authentication on every operation that is not deliberately public; verify enforcement at the gateway.

#### 8. Exposed /.env on 127.0.0.2:8080

- **Severity:** High
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `bbc7ddd50a11`
- **Tags:** `http`, `path-check`, `/.env`

An environment file is readable; these normally hold database credentials and API keys.

> **Requires manual review.** Confirm what this actually discloses for this client and whether the exposure is already known/accepted.

**Evidence**

```text
GET http://127.0.0.2:8080/.env -> 200 OK
content-type: text/plain
length: 305

APP_ENV=production
DATABASE_URL=<redacted, 80 chars>
STRIPE_SECRET_KEY=<redacted, 32 chars>
JWT_SIGNING_SECRET=<redacted, 32 chars>
AWS_ACCESS_KEY_ID=<redacted, 25 chars>
SMTP_PASSWORD=<redacted, 18 chars>
DEBUG=false
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 9. Unauthenticated API endpoint confirmed reachable: http://127.0.0.2:8080/api/admin/users

- **Severity:** High
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:api`
- **Finding id:** `821b41c80756`
- **Tags:** `api`, `authentication`, `owasp-api`

The endpoint returned data without credentials, confirming the specification's lack of a security requirement reflects reality. The path suggests administrative or credential-bearing functionality, which raises the impact.

> **Requires manual review.** Check whether the returned data is sensitive, and whether other endpoints from the same spec behave the same way. Do not enumerate records beyond what proves the finding.

**Evidence**

```text
GET http://127.0.0.2:8080/api/admin/users -> 200 OK
content-type: application/json  length: 110

[{"id":1,"email":"jane.doe@acme.example","role":"admin"},{"id":2,"email":"bob@acme.example","role":"billing"}]
```

**Recommendation**

Require authentication on this endpoint.

#### 10. Exposed diagnostic handler /elmah.axd on 127.0.0.2:8081

- **Severity:** High
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:iis`
- **Finding id:** `64bc3599776f`
- **Tags:** `iis`, `aspnet`, `handler`, `information-disclosure`

ELMAH error log viewer. Exposes unhandled-exception detail, stack traces, connection strings and often full request bodies.

> **Requires manual review.** Check what the handler is currently exposing. If it has been serving other users' session identifiers or credentials, this is an incident to raise with the client now, not a finding to file.

**Evidence**

```text
GET http://127.0.0.2:8081/elmah.axd -> 200
content-type: text/html
length: 52

<html><title>Error Log</title>ELMAH error log</html>
```

**Recommendation**

Remove the handler registration from web.config in production; do not rely on obscurity or on IP filtering alone.

#### 11. Exposed diagnostic handler /trace.axd on 127.0.0.2:8081

- **Severity:** High
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:iis`
- **Finding id:** `9ab90f0ad511`
- **Tags:** `iis`, `aspnet`, `handler`, `information-disclosure`

ASP.NET trace viewer. Serves the most recent requests to the application including headers, cookies, session state and form values -- an unauthenticated feed of other users' session identifiers.

> **Requires manual review.** Check what the handler is currently exposing. If it has been serving other users' session identifiers or credentials, this is an incident to raise with the client now, not a finding to file.

**Evidence**

```text
GET http://127.0.0.2:8081/trace.axd -> 200
content-type: text/html
length: 212

<html><head><title>Application Trace</title></head><body><h1>Application Trace</h1><p>Requests to this Application</p><table><tr><td>/Account/Login</td><td>ASP.NET_SessionId=abc123</td></tr></table></body></html>
```

**Recommendation**

Remove the handler registration from web.config in production; do not rely on obscurity or on IP filtering alone.

#### 12. WebDAV appears enabled on 127.0.0.2:8081 with write verbs (COPY, DELETE, MKCOL, MOVE, PUT)

- **Severity:** High  (tentative -- needs confirmation)
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:iis`
- **Finding id:** `568b4976bc80`
- **Tags:** `iis`, `webdav`

The server advertises WebDAV methods. WebDAV widens the HTTP surface well beyond GET/POST and has a long history of authentication bypass and upload issues. Where write verbs are advertised, the risk is remote file placement -- which on IIS can mean code execution.

> **Requires manual review.** extscan read the advertised verb list only -- it did not attempt PUT or DELETE, because writing to a client's server is a change rather than a test. An auditor should confirm whether the write verbs are genuinely usable, with explicit written approval for that step.

**Evidence**

```text
OPTIONS http://127.0.0.2:8081 -> 200
Allow/Public: OPTIONS, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK, PUT 
DAV: 1, 2
```

**Recommendation**

Remove the WebDAV module if the application does not use it; otherwise require authentication and disable write verbs.

#### 13. 5 API operation(s) declare no authentication, including 2 that modify data

- **Severity:** High  (tentative -- needs confirmation)
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:openapi`
- **Finding id:** `05d0fc4ccf4f`
- **Tags:** `openapi`, `api`, `authentication`, `owasp-api`

These operations carry no security requirement in the specification, either explicitly (`security: []`) or because none was ever declared and there is no global requirement. The specification is a statement of intent, not proof: the gateway in front of the API may enforce auth regardless, and an operation may be protected in code but undocumented.

> **Requires manual review.** extscan did not call these endpoints -- invoking undocumented write operations on a live system risks changing client data. An auditor should confirm, on the read-only endpoints first, whether the lack of declared authentication is real.

**Evidence**

```text
unauthenticated operations (5):
  GET    /health
  POST   /invoices
  DELETE /invoices/{id}
  GET    /admin/users
  GET    /internal/debug/config

write operations with no declared auth (2):
  POST   /invoices
  DELETE /invoices/{id}
```

**Recommendation**

Declare and enforce authentication on every operation that is not deliberately public; verify enforcement at the gateway.

#### 14. Exposed /.env on 127.0.0.2:8443

- **Severity:** High
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `f78278c13c50`
- **Tags:** `http`, `path-check`, `/.env`

An environment file is readable; these normally hold database credentials and API keys.

> **Requires manual review.** Confirm what this actually discloses for this client and whether the exposure is already known/accepted.

**Evidence**

```text
GET https://127.0.0.2:8443/.env -> 200 OK
content-type: text/plain
length: 305

APP_ENV=production
DATABASE_URL=<redacted, 80 chars>
STRIPE_SECRET_KEY=<redacted, 32 chars>
JWT_SIGNING_SECRET=<redacted, 32 chars>
AWS_ACCESS_KEY_ID=<redacted, 25 chars>
SMTP_PASSWORD=<redacted, 18 chars>
DEBUG=false
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 15. Unauthenticated API endpoint confirmed reachable: http://127.0.0.2:8080/api/admin/users

- **Severity:** High
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:api`
- **Finding id:** `b50fadd9f8e9`
- **Tags:** `api`, `authentication`, `owasp-api`

The endpoint returned data without credentials, confirming the specification's lack of a security requirement reflects reality. The path suggests administrative or credential-bearing functionality, which raises the impact.

> **Requires manual review.** Check whether the returned data is sensitive, and whether other endpoints from the same spec behave the same way. Do not enumerate records beyond what proves the finding.

**Evidence**

```text
GET http://127.0.0.2:8080/api/admin/users -> 200 OK
content-type: application/json  length: 110

[{"id":1,"email":"jane.doe@acme.example","role":"admin"},{"id":2,"email":"bob@acme.example","role":"billing"}]
```

**Recommendation**

Require authentication on this endpoint.

#### 16. Redis Server - Unauthenticated Access

- **Severity:** High
- **Affected:** `127.0.0.2:6379/tcp`
- **Detected by:** `nuclei:exposed-redis`
- **Finding id:** `759c3c5eb831`
- **Tags:** `nuclei`, `network`, `redis`, `unauth`, `exposure`, `tcp`

Redis server without any required authentication was discovered.

**Evidence**

```text
matched-at: 127.0.0.2:6379
--- request ---
info
quit

--- response ---
$64
# Server
redis_version:5.0.7
redis_mode:standalone
os:Linux
```

**References**

- https://redis.io/topics/security

#### 17. redis-info on 127.0.0.2:6379/tcp

- **Severity:** High
- **Affected:** `127.0.0.2:6379/tcp`
- **Detected by:** `nmap-tcp:redis-info`
- **Finding id:** `afbd982af2ff`
- **Tags:** `nmap-script`, `redis-info`

Redis responded to an unauthenticated query.

**Evidence**

```text
Version: 5.0.7
  Operating System: Linux
```

#### 18. Codeigniter - .env File Discovery

- **Severity:** High
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:codeigniter-env`
- **Finding id:** `a01966da7e22`
- **Tags:** `nuclei`, `config`, `exposure`, `codeigniter`

Codeigniter .env file was discovered.

**Evidence**

```text
matched-at: http://127.0.0.2:8080/.env
--- request ---
GET /.env HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 305
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:13:23 GMT
Server: nginx/1.18.0
X-Powered-By: Express

APP_ENV=production
DATABASE_URL=postgres://billing:NOT-A-REAL-PASSWORD@db-prod-01.corp.acme.example:5432/billing
STRIPE_SECRET_KEY=fake-stripe-value-for-tests-only
JWT_SIGNING_SECRET=fake-jwt-signing-value-for-tests
AWS_ACCESS_KEY_ID=fake-aws-key-id-for-tests
SMTP_PASSWORD=fake-smtp-password
DEBUG=false
```

#### 19. Generic Env File Disclosure

- **Severity:** High
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:generic-env`
- **Finding id:** `720530f438aa`
- **Tags:** `nuclei`, `config`, `exposure`, `env`

A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

**Evidence**

```text
matched-at: http://127.0.0.2:8080/.env
--- request ---
GET /.env HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 305
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:14:47 GMT
Server: nginx/1.18.0
X-Powered-By: Express

APP_ENV=production
DATABASE_URL=postgres://billing:NOT-A-REAL-PASSWORD@db-prod-01.corp.acme.example:5432/billing
STRIPE_SECRET_KEY=fake-stripe-value-for-tests-only
JWT_SIGNING_SECRET=fake-jwt-signing-value-for-tests
AWS_ACCESS_KEY_ID=fake-aws-key-id-for-tests
SMTP_PASSWORD=fake-smtp-password
DEBUG=false
```

#### 20. Laravel - Sensitive Information Disclosure

- **Severity:** High
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:laravel-env`
- **Finding id:** `b07ffc54fc88`
- **Tags:** `nuclei`, `config`, `exposure`, `laravel`

A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.

**Evidence**

```text
matched-at: http://127.0.0.2:8080/.env
--- request ---
GET /.env HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (Knoppix; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 305
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:13:26 GMT
Server: nginx/1.18.0
X-Powered-By: Express

APP_ENV=production
DATABASE_URL=postgres://billing:NOT-A-REAL-PASSWORD@db-prod-01.corp.acme.example:5432/billing
STRIPE_SECRET_KEY=fake-stripe-value-for-tests-only
JWT_SIGNING_SECRET=fake-jwt-signing-value-for-tests
AWS_ACCESS_KEY_ID=fake-aws-key-id-for-tests
SMTP_PASSWORD=fake-smtp-password
DEBUG=false
```

**References**

- https://laravel.com/docs/master/configuration#environment-configuration
- https://stackoverflow.com/questions/38331397/how-to-protect-env-file-in-laravel

#### 21. Codeigniter - .env File Discovery

- **Severity:** High
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:codeigniter-env`
- **Finding id:** `09f0d6147a4b`
- **Tags:** `nuclei`, `config`, `exposure`, `codeigniter`

Codeigniter .env file was discovered.

**Evidence**

```text
matched-at: https://127.0.0.2:8443/.env
--- request ---
GET /.env HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (Debian; Linux i686; rv:123.0) Gecko/20100101 Firefox/123.0
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 305
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:13:23 GMT
Server: nginx/1.18.0
X-Powered-By: Express

APP_ENV=production
DATABASE_URL=postgres://billing:NOT-A-REAL-PASSWORD@db-prod-01.corp.acme.example:5432/billing
STRIPE_SECRET_KEY=fake-stripe-value-for-tests-only
JWT_SIGNING_SECRET=fake-jwt-signing-value-for-tests
AWS_ACCESS_KEY_ID=fake-aws-key-id-for-tests
SMTP_PASSWORD=fake-smtp-password
DEBUG=false
```

#### 22. Generic Env File Disclosure

- **Severity:** High
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:generic-env`
- **Finding id:** `98fae4c1fe73`
- **Tags:** `nuclei`, `config`, `exposure`, `env`

A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

**Evidence**

```text
matched-at: https://127.0.0.2:8443/.env
--- request ---
GET /.env HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (Mac OS X 13_2) AppleWebKit/537.36 (KHTML, like Gecko) Edge/119.0 Safari/537.36
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 305
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:14:47 GMT
Server: nginx/1.18.0
X-Powered-By: Express

APP_ENV=production
DATABASE_URL=postgres://billing:NOT-A-REAL-PASSWORD@db-prod-01.corp.acme.example:5432/billing
STRIPE_SECRET_KEY=fake-stripe-value-for-tests-only
JWT_SIGNING_SECRET=fake-jwt-signing-value-for-tests
AWS_ACCESS_KEY_ID=fake-aws-key-id-for-tests
SMTP_PASSWORD=fake-smtp-password
DEBUG=false
```

#### 23. Laravel - Sensitive Information Disclosure

- **Severity:** High
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:laravel-env`
- **Finding id:** `3ec8c11e44e0`
- **Tags:** `nuclei`, `config`, `exposure`, `laravel`

A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.

**Evidence**

```text
matched-at: https://127.0.0.2:8443/.env
--- request ---
GET /.env HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (Mac OS X 13_2) AppleWebKit/537.36 (KHTML, like Gecko) Safari/111.0 Safari/537.36
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 305
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:13:26 GMT
Server: nginx/1.18.0
X-Powered-By: Express

APP_ENV=production
DATABASE_URL=postgres://billing:NOT-A-REAL-PASSWORD@db-prod-01.corp.acme.example:5432/billing
STRIPE_SECRET_KEY=fake-stripe-value-for-tests-only
JWT_SIGNING_SECRET=fake-jwt-signing-value-for-tests
AWS_ACCESS_KEY_ID=fake-aws-key-id-for-tests
SMTP_PASSWORD=fake-smtp-password
DEBUG=false
```

**References**

- https://laravel.com/docs/master/configuration#environment-configuration
- https://stackoverflow.com/questions/38331397/how-to-protect-env-file-in-laravel

#### 24. SNMP readable with default community string `public`

- **Severity:** High
- **Affected:** `127.0.0.2:10161/udp`
- **Detected by:** `extscan:snmp`
- **Finding id:** `3e9c24efcb24`
- **Tags:** `snmp`, `default-credentials`, `community:public`

The SNMP agent on 127.0.0.2:10161/udp answered an unauthenticated query using the community string `public` (v1). SNMP read access typically discloses the device model and firmware, interface and routing tables, ARP caches and internal addressing -- a map of the internal network, served to the internet.

**Evidence**

```text
sysDescr: Linux lab-router 4.19.0 #1 SMP x86_64
version: v1
sysName: Linux lab-router 4.19.0 #1 SMP x86_64
sysLocation: Linux lab-router 4.19.0 #1 SMP x86_64
sysContact: Linux lab-router 4.19.0 #1 SMP x86_64
sysObjectID: Linux lab-router 4.19.0 #1 SMP x86_64
sysUpTime: Linux lab-router 4.19.0 #1 SMP x86_64
```

**Recommendation**

Restrict UDP/161 to management networks at the perimeter; replace guessable community strings; prefer SNMPv3 with authPriv. If SNMP is not in use, disable the agent.

**References**

- https://www.cisa.gov/news-events/alerts/2017/06/05/simple-network-management-protocol-snmp-vulnerabilities

### Medium (14)

#### 25. Exposed /graphql on 127.0.0.2:8080

- **Severity:** Medium
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `2086ab0283ec`
- **Tags:** `http`, `path-check`, `/graphql`

A GraphQL endpoint is reachable.

> **Requires manual review.** Confirm what this actually discloses for this client and whether the exposure is already known/accepted.

**Evidence**

```text
GET http://127.0.0.2:8080/graphql -> 400 Bad Request
content-type: application/json
length: 52

{"errors":[{"message":"Must provide query string"}]}
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 26. Exposed /metrics on 127.0.0.2:8080

- **Severity:** Medium
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `6835ff87c381`
- **Tags:** `http`, `path-check`, `/metrics`

A metrics endpoint exposes internal topology.

> **Requires manual review.** Confirm what this actually discloses for this client and whether the exposure is already known/accepted.

**Evidence**

```text
GET http://127.0.0.2:8080/metrics -> 200 OK
content-type: text/plain
length: 143

# HELP http_requests_total Total requests
# TYPE http_requests_total counter
http_requests_total{instance="db-prod-01.corp.acme.example"} 4821
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 27. Exposed /swagger.json on 127.0.0.2:8080

- **Severity:** Medium
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `2de132b14e68`
- **Tags:** `http`, `path-check`, `/swagger.json`

An OpenAPI/Swagger document is public.

> **Requires manual review.** Confirm what this actually discloses for this client and whether the exposure is already known/accepted.

**Evidence**

```text
GET http://127.0.0.2:8080/swagger.json -> 200 OK
content-type: application/json
length: 889

{"openapi": "3.0.1", "info": {"title": "ACME Billing API", "version": "2.4.1"}, "servers": [{"url": "http://127.0.0.2:8080/api"}, {"url": "https://internal-billing.corp.acme.example/api"}], "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}, "security": [{"bearerAuth": []}], "paths": {"/health": {"get": {"summary": "Liveness", "security": []}}, "/invoices": {"get": {"summary": "List invoices"}, "post": {"summary": "Create invoice", "security": []}}, "/invoices/{id}": {"delete": {"summary": "Delete invoice", "security": []}, "get": {"summary": "Get invoice"}}, "/admin/users": {"get": {"summary": "List all users", "security": []}, "post": {"summary": "Create user", "operationId": "createUserAdmin"}}, "/internal/debug/config": {"get": {"summary": "Dump config", "security": []}}, "/payments/token": {"post": {"summary": "Issue payment token"}}}}
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 28. Exposed API specification: ACME Billing API (9 operations)

- **Severity:** Medium
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:openapi`
- **Finding id:** `ad2827bbe444`
- **Tags:** `openapi`, `api`, `information-disclosure`

A complete machine-readable description of this API is published at http://127.0.0.2:8080/swagger.json. It documents 9 operations across 6 paths, which hands an attacker the full attack surface including parameter names and types.

> **Requires manual review.** An auditor must decide whether publishing this spec is intended. If the API is public by design this may be acceptable; the operations listed below still need review.

**Evidence**

```text
spec: http://127.0.0.2:8080/swagger.json
API: ACME Billing API v2.4.1 (spec format 3.0.1)
paths: 6, operations: 9
declared security schemes: bearerAuth
global security requirement: yes
servers: http://127.0.0.2:8080/api, https://internal-billing.corp.acme.example/api
```

**Recommendation**

Serve the specification only to authenticated consumers, or publish a redacted version covering only public endpoints.

**References**

- https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/

#### 29. GraphQL introspection enabled at http://127.0.0.2:8080/graphql

- **Severity:** Medium
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:graphql`
- **Finding id:** `2fc8cb4d7192`
- **Tags:** `graphql`, `information-disclosure`

Introspection returns the full schema: 3 types and 8 fields, with mutations exposed via `Mutation`. This gives an attacker the complete API surface, including fields that no client UI references.

> **Requires manual review.** Review the schema for fields that should not be reachable by unauthenticated callers and for mutations that change data.

**Evidence**

```text
POST http://127.0.0.2:8080/graphql -> 200
types: Query, Mutation, User
```

**Recommendation**

Disable introspection in production and apply query depth/complexity limits.

**References**

- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

#### 30. Unauthenticated API endpoint confirmed reachable: http://127.0.0.2:8080/api/health

- **Severity:** Medium
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:api`
- **Finding id:** `0e9564c8cefd`
- **Tags:** `api`, `authentication`, `owasp-api`

The endpoint returned data without credentials, confirming the specification's lack of a security requirement reflects reality. Impact depends on what the response contains.

> **Requires manual review.** Check whether the returned data is sensitive, and whether other endpoints from the same spec behave the same way. Do not enumerate records beyond what proves the finding.

**Evidence**

```text
GET http://127.0.0.2:8080/api/health -> 200 OK
content-type: application/json  length: 31

{"status":"ok","build":"2.4.1"}
```

**Recommendation**

Require authentication on this endpoint.

#### 31. IIS 8.3 short-name enumeration possible on 127.0.0.2:8081

- **Severity:** Medium
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:iis`
- **Finding id:** `32cc81cfbb16`
- **Tags:** `iis`, `shortname`, `information-disclosure`

The server distinguishes matching from non-matching 8.3 short-name wildcards by status code, which allows an attacker to enumerate file and directory names character by character without any directory listing. Names recovered this way routinely include backup copies, admin pages and configuration files that were never linked.

> **Requires manual review.** extscan confirmed the condition with two requests and did not enumerate. Deciding whether to run a full enumeration -- thousands of requests against a production site -- is the auditor's call.

**Evidence**

```text
GET http://127.0.0.2:8081/*~1*/.aspx -> 404
GET http://127.0.0.2:8081/zzqq9xv*~1*/.aspx -> 400
A 404/400 split is the documented indicator.
```

**Recommendation**

Disable 8.3 name generation (`fsutil 8dot3name set 1`) and strip existing short names from the web root.

**References**

- https://owasp.org/www-project-web-security-testing-guide/

#### 32. Exposed /graphql on 127.0.0.2:8443

- **Severity:** Medium
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `5905961c175a`
- **Tags:** `http`, `path-check`, `/graphql`

A GraphQL endpoint is reachable.

> **Requires manual review.** Confirm what this actually discloses for this client and whether the exposure is already known/accepted.

**Evidence**

```text
GET https://127.0.0.2:8443/graphql -> 400 Bad Request
content-type: application/json
length: 52

{"errors":[{"message":"Must provide query string"}]}
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 33. Exposed /metrics on 127.0.0.2:8443

- **Severity:** Medium
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `5766856bec70`
- **Tags:** `http`, `path-check`, `/metrics`

A metrics endpoint exposes internal topology.

> **Requires manual review.** Confirm what this actually discloses for this client and whether the exposure is already known/accepted.

**Evidence**

```text
GET https://127.0.0.2:8443/metrics -> 200 OK
content-type: text/plain
length: 143

# HELP http_requests_total Total requests
# TYPE http_requests_total counter
http_requests_total{instance="db-prod-01.corp.acme.example"} 4821
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 34. Exposed /swagger.json on 127.0.0.2:8443

- **Severity:** Medium
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `f736eab823ac`
- **Tags:** `http`, `path-check`, `/swagger.json`

An OpenAPI/Swagger document is public.

> **Requires manual review.** Confirm what this actually discloses for this client and whether the exposure is already known/accepted.

**Evidence**

```text
GET https://127.0.0.2:8443/swagger.json -> 200 OK
content-type: application/json
length: 889

{"openapi": "3.0.1", "info": {"title": "ACME Billing API", "version": "2.4.1"}, "servers": [{"url": "http://127.0.0.2:8080/api"}, {"url": "https://internal-billing.corp.acme.example/api"}], "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}, "security": [{"bearerAuth": []}], "paths": {"/health": {"get": {"summary": "Liveness", "security": []}}, "/invoices": {"get": {"summary": "List invoices"}, "post": {"summary": "Create invoice", "security": []}}, "/invoices/{id}": {"delete": {"summary": "Delete invoice", "security": []}, "get": {"summary": "Get invoice"}}, "/admin/users": {"get": {"summary": "List all users", "security": []}, "post": {"summary": "Create user", "operationId": "createUserAdmin"}}, "/internal/debug/config": {"get": {"summary": "Dump config", "security": []}}, "/payments/token": {"post": {"summary": "Issue payment token"}}}}
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 35. Exposed API specification: ACME Billing API (9 operations)

- **Severity:** Medium
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:openapi`
- **Finding id:** `f3334fd69242`
- **Tags:** `openapi`, `api`, `information-disclosure`

A complete machine-readable description of this API is published at https://127.0.0.2:8443/swagger.json. It documents 9 operations across 6 paths, which hands an attacker the full attack surface including parameter names and types.

> **Requires manual review.** An auditor must decide whether publishing this spec is intended. If the API is public by design this may be acceptable; the operations listed below still need review.

**Evidence**

```text
spec: https://127.0.0.2:8443/swagger.json
API: ACME Billing API v2.4.1 (spec format 3.0.1)
paths: 6, operations: 9
declared security schemes: bearerAuth
global security requirement: yes
servers: http://127.0.0.2:8080/api, https://internal-billing.corp.acme.example/api
```

**Recommendation**

Serve the specification only to authenticated consumers, or publish a redacted version covering only public endpoints.

**References**

- https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/

#### 36. GraphQL introspection enabled at https://127.0.0.2:8443/graphql

- **Severity:** Medium
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:graphql`
- **Finding id:** `3484af4fec04`
- **Tags:** `graphql`, `information-disclosure`

Introspection returns the full schema: 3 types and 8 fields, with mutations exposed via `Mutation`. This gives an attacker the complete API surface, including fields that no client UI references.

> **Requires manual review.** Review the schema for fields that should not be reachable by unauthenticated callers and for mutations that change data.

**Evidence**

```text
POST https://127.0.0.2:8443/graphql -> 200
types: Query, Mutation, User
```

**Recommendation**

Disable introspection in production and apply query depth/complexity limits.

**References**

- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

#### 37. Unauthenticated API endpoint confirmed reachable: http://127.0.0.2:8080/api/health

- **Severity:** Medium
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:api`
- **Finding id:** `46a60a5ff437`
- **Tags:** `api`, `authentication`, `owasp-api`

The endpoint returned data without credentials, confirming the specification's lack of a security requirement reflects reality. Impact depends on what the response contains.

> **Requires manual review.** Check whether the returned data is sensitive, and whether other endpoints from the same spec behave the same way. Do not enumerate records beyond what proves the finding.

**Evidence**

```text
GET http://127.0.0.2:8080/api/health -> 200 OK
content-type: application/json  length: 31

{"status":"ok","build":"2.4.1"}
```

**Recommendation**

Require authentication on this endpoint.

#### 38. Verbose ASP.NET error page on 127.0.0.2:8081

- **Severity:** Medium
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:iis`
- **Finding id:** `e61f859c26a2`
- **Tags:** `iis`, `aspnet`, `information-disclosure`

The application returns framework error detail to unauthenticated clients. These pages typically disclose the .NET version, physical paths on disk, source file names and line numbers, and sometimes connection strings. The page names .NET 4.0.30319.

**Evidence**

```text
GET http://127.0.0.2:8081/extscan_nonexistent_%27.aspx -> 500
matched markers: server error in, [httpexception, stack trace:, microsoft .net framework version, system.web., at system.

<html><head><title>Server Error in '/' Application</title></head><body><h2>Runtime Error</h2><p>[HttpException (0x80004005)]</p><pre>Stack Trace:
   at System.Web.HttpRequest.ValidateInput()</pre>Microsoft .NET Framework Version:4.0.30319</body></html>
```

**Recommendation**

Set `<customErrors mode="On">` and `<httpErrors existingResponse="Replace">`, and never ship debug builds to production.

### Low (8)

#### 39. Self-signed TLS certificate on 127.0.0.2:8443

- **Severity:** Low
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:tls`
- **Finding id:** `842585abd751`
- **Tags:** `tls`, `certificate`

Subject and issuer match, so the certificate is self-signed and provides no identity assurance against interception.

> **Requires manual review.** Decide whether this endpoint is user-facing (a real problem) or an internal appliance interface (often accepted).

**Evidence**

```text
subject: CN = billing.lab.invalid, O = extscan lab
issuer: CN = billing.lab.invalid, O = extscan lab
```

**Recommendation**

Use a certificate from a CA the clients trust.

#### 40. Version-disclosing HTTP headers on 127.0.0.2:8080

- **Severity:** Low
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `0977a65c6fe4`
- **Tags:** `http`, `information-disclosure`

The server returns headers naming the product and version, which lets an attacker select exploits without probing.

**Evidence**

```text
server: nginx/1.18.0
x-powered-by: Express
```

**Recommendation**

Suppress or genericise Server/X-Powered-By and similar headers.

#### 41. IIS/ASP.NET version disclosure on 127.0.0.2:8081

- **Severity:** Low
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:iis`
- **Finding id:** `c148a4e4f3fa`
- **Tags:** `iis`, `aspnet`, `information-disclosure`

Response headers name the web server and framework versions, which lets an attacker select exploits for the exact build without probing for them. On Windows estates this also narrows down the patch level of the host itself.

**Evidence**

```text
server: Microsoft-IIS/8.5
x-aspnet-version: 4.0.30319
x-aspnetmvc-version: 5.2
x-powered-by: ASP.NET
```

**Recommendation**

Remove or genericise these headers (`removeServerHeader` in requestFiltering, and `enableVersionHeader=false` in httpRuntime for ASP.NET).

#### 42. Version-disclosing HTTP headers on 127.0.0.2:8081

- **Severity:** Low
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `cfe18069330d`
- **Tags:** `http`, `information-disclosure`

The server returns headers naming the product and version, which lets an attacker select exploits without probing.

**Evidence**

```text
server: Microsoft-IIS/8.5
x-powered-by: ASP.NET
x-aspnet-version: 4.0.30319
x-aspnetmvc-version: 5.2
```

**Recommendation**

Suppress or genericise Server/X-Powered-By and similar headers.

#### 43. Missing HTTP security headers on 127.0.0.2:8443

- **Severity:** Low
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `3b9f6244a263`
- **Tags:** `http`, `headers`

Response headers that harden browser behaviour are absent.

**Evidence**

```text
strict-transport-security: HSTS not set; downgrade to cleartext is not prevented.
content-security-policy: No CSP; no in-browser mitigation for injected content.
x-content-type-options: Missing nosniff.
x-frame-options: No framing restriction (unless CSP frame-ancestors is set).
```

**Recommendation**

Add HSTS, CSP, X-Content-Type-Options and a framing policy.

#### 44. Self Signed SSL Certificate

- **Severity:** Low
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:self-signed-ssl`
- **Finding id:** `6259b4e15eb6`
- **Tags:** `nuclei`, `ssl`, `tls`, `self-signed`

self-signed certificates are public key certificates that are not issued by a certificate authority. These self-signed
certificates are easy to make and do not cost money. However, they do not provide any trust value.

**Evidence**

```text
matched-at: 127.0.0.2:8443
```

**Recommendation**

Purchase or generate a proper SSL certificate for this service.

**References**

- https://www.rapid7.com/db/vulnerabilities/ssl-self-signed-certificate/

#### 45. Version-disclosing HTTP headers on 127.0.0.2:8443

- **Severity:** Low
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `524471e42801`
- **Tags:** `http`, `information-disclosure`

The server returns headers naming the product and version, which lets an attacker select exploits without probing.

**Evidence**

```text
server: nginx/1.18.0
x-powered-by: Express
```

**Recommendation**

Suppress or genericise Server/X-Powered-By and similar headers.

#### 46. ElasticSearch Information Disclosure

- **Severity:** Low
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nuclei:elasticsearch`
- **Finding id:** `6e23fe0d24ce`
- **Tags:** `nuclei`, `elastic`, `unauth`, `elasticsearch`, `misconfig`

Internal information is exposed in elasticsearch to external users.

**Evidence**

```text
matched-at: http://127.0.0.2:9200/?pretty
extracted: 6.8.0
--- request ---
GET /?pretty HTTP/1.1
Host: 127.0.0.2:9200
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.0 200 OK
Connection: close
Content-Length: 247
Content-Type: application/json; charset=UTF-8

{
  "name" : "es-node-1",
  "cluster_name" : "billing-logs",
  "cluster_uuid" : "lab-cluster-uuid",
  "version" : {
    "number" : "6.8.0",
    "build_flavor" : "default",
    "lucene_version" : "7.7.0"
  },
  "tagline" : "You Know, for Search"
}
```

### Informational (122)

#### 47. SSH service on 127.0.0.2:2222

- **Severity:** Informational
- **Affected:** `127.0.0.2:2222/tcp`
- **Detected by:** `extscan:ssh`
- **Finding id:** `410bdadf2834`
- **Tags:** `ssh`

SSH is reachable and identifies as `OpenSSH 7.4`.

> **Requires manual review.** Confirm key-only authentication and whether exposure to the whole internet is required. Banner-based version checks are indicative only; distributions backport fixes without changing the banner.

**Evidence**

```text
product=OpenSSH version=7.4 extrainfo=protocol 2.0
```

#### 48. HTTP service: untitled on 127.0.0.2:2375

- **Severity:** Informational
- **Affected:** `127.0.0.2:2375/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `465960dfad55`
- **Tags:** `http`, `fingerprint`

An HTTP service is reachable at http://127.0.0.2:2375.

> **Requires manual review.** An auditor should confirm whether this application is intended to be internet-facing, and who owns it.

**Evidence**

```text
GET http://127.0.0.2:2375 -> 404 Not Found
```

#### 49. API exposes 4 operation(s) on sensitive-looking resources

- **Severity:** Informational  (tentative -- needs confirmation)
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:openapi`
- **Finding id:** `e117402b5e09`
- **Tags:** `openapi`, `api`, `triage-hint`

Operation paths or names suggest administrative or data-bearing functionality. This is a naming heuristic, not a vulnerability.

> **Requires manual review.** Decide which of these warrant authenticated testing under a separate, explicitly scoped engagement.

**Evidence**

```text
GET    /admin/users
  POST   /admin/users
  GET    /internal/debug/config
  POST   /payments/token
```

#### 50. API specification references hosts outside the engagement scope

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:openapi`
- **Finding id:** `7bd547645ee2`
- **Tags:** `openapi`, `scope`, `asset-discovery`

The spec names servers that are not in scope. These were not touched. They may be additional assets the client has not listed, which is worth raising.

> **Requires manual review.** Confirm with the client whether these hosts belong to them and should be added to scope for a future assessment.

**Evidence**

```text
https://internal-billing.corp.acme.example/api
```

#### 51. Content review: http://127.0.0.2:8080/metrics

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:web_paths`
- **Finding id:** `c20446759bb4`
- **Tags:** `http`, `content-review`

Retrieved for context. /metrics responded 200; establish what it exposes.

> **Requires manual review.** An auditor should judge whether the content disclosed here matters for this client.

**Evidence**

```text
GET http://127.0.0.2:8080/metrics -> 200 OK
content-type: text/plain  length: 143

# HELP http_requests_total Total requests
# TYPE http_requests_total counter
http_requests_total{instance="db-prod-01.corp.acme.example"} 4821
```

#### 52. Content review: http://127.0.0.2:8080/robots.txt

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:web_paths`
- **Finding id:** `dc7d7881bb28`
- **Tags:** `http`, `content-review`

Retrieved for context. /robots.txt responded 200; establish what it exposes.

> **Requires manual review.** An auditor should judge whether the content disclosed here matters for this client.

**Evidence**

```text
GET http://127.0.0.2:8080/robots.txt -> 200 OK
content-type: text/plain  length: 51

User-agent: *
Disallow: /admin
Disallow: /internal
```

#### 53. GraphQL API Detection

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:graphql-detect`
- **Finding id:** `010215d669d7`
- **Tags:** `nuclei`, `tech`, `graphql`

nuclei template `graphql-detect` matched.

> **Requires manual review.** GraphQL endpoint. Check introspection and whether mutations are exposed.

**Evidence**

```text
matched-at: http://127.0.0.2:8080/graphql
--- request ---
POST /graphql HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15
Content-Length: 67
Accept: */*
Accept-Language: en
Content-Type: application/json
Accept-Encoding: gzip

{"query":"query IntrospectionQuery{__schema {queryType { name }}}"}
--- response ---
HTTP/1.1 200 OK
Content-Length: 445
Content-Type: application/json
Date: Fri, 23 Oct 2026 09:14:07 GMT
Server: nginx/1.18.0
X-Powered-By: Express

{"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "types": [{"name": "Query", "kind": "OBJECT", "fields": [{"name": "invoices"}, {"name": "users"}, {"name": "internalAuditLog"}]}, {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "deleteInvoice"}, {"name": "promoteUserToAdmin"}]}, {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}, {"name": "email"}, {"name": "passwordHash"}]}]}}}
```

#### 54. HTTP service: ACME Billing — API Console on 127.0.0.2:8080

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `fc77dfeb9f7c`
- **Tags:** `http`, `fingerprint`

An HTTP service is reachable at http://127.0.0.2:8080. It identifies itself as `nginx/1.18.0`.

> **Requires manual review.** An auditor should confirm whether this application is intended to be internet-facing, and who owns it.

**Evidence**

```text
GET http://127.0.0.2:8080 -> 200 OK
title: ACME Billing — API Console
server: nginx/1.18.0
x-powered-by: Express
```

#### 55. http-comments-displayer on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-comments-displayer`
- **Finding id:** `7bd668b1f10d`
- **Tags:** `nmap-script`, `http-comments-displayer`

nmap script `http-comments-displayer` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Couldn't find any comments.
```

#### 56. http-date on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-date`
- **Finding id:** `999aa5c69a62`
- **Tags:** `nmap-script`, `http-date`

nmap script `http-date` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Fri, 23 Oct 2026 09:09:15 GMT; -1s from local time.
```

#### 57. http-fetch on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-fetch`
- **Finding id:** `bf1c85a0e39e`
- **Tags:** `nmap-script`, `http-fetch`

nmap script `http-fetch` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Please enter the complete path of the directory to save data in.
```

#### 58. http-headers on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-headers`
- **Finding id:** `3115070e5f30`
- **Tags:** `nmap-script`, `http-headers`

nmap script `http-headers` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Server: nginx/1.18.0
  Date: Fri, 23 Oct 2026 09:09:18 GMT
  Content-Type: text/html; charset=utf-8
  Content-Length: 273
  X-Powered-By: Express
  
  (Request type: GET)
```

#### 59. http-malware-host on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-malware-host`
- **Finding id:** `27001df5ce0b`
- **Tags:** `nmap-script`, `http-malware-host`

nmap script `http-malware-host` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
false
```

#### 60. http-mobileversion-checker on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-mobileversion-checker`
- **Finding id:** `456418dd5dc8`
- **Tags:** `nmap-script`, `http-mobileversion-checker`

nmap script `http-mobileversion-checker` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
No mobile version detected.
```

#### 61. http-referer-checker on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-referer-checker`
- **Finding id:** `c3b649788351`
- **Tags:** `nmap-script`, `http-referer-checker`

nmap script `http-referer-checker` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Couldn't find any cross-domain scripts.
```

#### 62. http-robots.txt on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-robots.txt`
- **Finding id:** `9d3ff990dda9`
- **Tags:** `nmap-script`, `http-robots.txt`

nmap script `http-robots.txt` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
2 disallowed entries 
/admin /internal
```

#### 63. http-title on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-title`
- **Finding id:** `6afbe40fbe14`
- **Tags:** `nmap-script`, `http-title`

HTTP page title.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
ACME Billing &mdash; API Console
```

#### 64. http-useragent-tester on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-useragent-tester`
- **Finding id:** `bb958a637980`
- **Tags:** `nmap-script`, `http-useragent-tester`

nmap script `http-useragent-tester` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Status for browser useragent: 200
  Allowed User Agents: 
    Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
    libwww
    lwp-trivial
    libcurl-agent/1.0
    PHP/
    Python-urllib/2.5
    GT::WWW
    Snoopy
    MFC_Tear_Sample
    HTTP::Lite
    PHPCrawl
    URI::Fetch
    Zend_Http_Client
    http client
    PECL::HTTP
    Wget/1.13.4 (linux-gnu)
    WWW-Mechanize/1.34
```

#### 65. http-vuln-cve2017-1001000 on 127.0.0.2:8080/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nmap-tcp:http-vuln-cve2017-1001000`
- **Finding id:** `8fb68f0730ef`
- **Tags:** `nmap-script`, `http-vuln-cve2017-1001000`

nmap script `http-vuln-cve2017-1001000` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
ERROR: Script execution failed (use -d to debug)
```

#### 66. Content review: http://127.0.0.2:8081/elmah.axd

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:web_paths`
- **Finding id:** `d2200ae371b9`
- **Tags:** `http`, `content-review`

Retrieved for context. /elmah.axd is serving content; establish what it discloses.

> **Requires manual review.** An auditor should judge whether the content disclosed here matters for this client.

**Evidence**

```text
GET http://127.0.0.2:8081/elmah.axd -> 200 OK
content-type: text/html  length: 52

<html><title>Error Log</title>ELMAH error log</html>
```

#### 67. Content review: http://127.0.0.2:8081/trace.axd

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:web_paths`
- **Finding id:** `3ead2d6871fd`
- **Tags:** `http`, `content-review`

Retrieved for context. /trace.axd is serving content; establish what it discloses.

> **Requires manual review.** An auditor should judge whether the content disclosed here matters for this client.

**Evidence**

```text
GET http://127.0.0.2:8081/trace.axd -> 200 OK
content-type: text/html  length: 212

<html><head><title>Application Trace</title></head><body><h1>Application Trace</h1><p>Requests to this Application</p><table><tr><td>/Account/Login</td><td>ASP.NET_SessionId=abc123</td></tr></table></body></html>
```

#### 68. Default IIS content at /iisstart.htm on 127.0.0.2:8081

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:iis`
- **Finding id:** `3e13cf5a37e5`
- **Tags:** `iis`, `default-content`

The default IIS landing page is present, which usually means a site was provisioned and never configured.

> **Requires manual review.** A default install page often means an unmaintained or forgotten site. Establish who owns it.

**Evidence**

```text
GET http://127.0.0.2:8081/iisstart.htm -> 200, 31 bytes
```

#### 69. HTTP service: Intranet on 127.0.0.2:8081

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `ad8ddbb7c29d`
- **Tags:** `http`, `fingerprint`

An HTTP service is reachable at http://127.0.0.2:8081. It identifies itself as `Microsoft-IIS/8.5`.

> **Requires manual review.** An auditor should confirm whether this application is intended to be internet-facing, and who owns it.

**Evidence**

```text
GET http://127.0.0.2:8081 -> 200 OK
title: Intranet
server: Microsoft-IIS/8.5
x-powered-by: ASP.NET
x-aspnet-version: 4.0.30319
x-aspnetmvc-version: 5.2
```

#### 70. http-comments-displayer on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-comments-displayer`
- **Finding id:** `bd0179f4745d`
- **Tags:** `nmap-script`, `http-comments-displayer`

nmap script `http-comments-displayer` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Couldn't find any comments.
```

#### 71. http-date on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-date`
- **Finding id:** `b9b8b90a5523`
- **Tags:** `nmap-script`, `http-date`

nmap script `http-date` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Fri, 23 Oct 2026 09:09:18 GMT; 0s from local time.
```

#### 72. http-fetch on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-fetch`
- **Finding id:** `af8eb2e52f69`
- **Tags:** `nmap-script`, `http-fetch`

nmap script `http-fetch` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Please enter the complete path of the directory to save data in.
```

#### 73. http-headers on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-headers`
- **Finding id:** `e2bf8c0cd7c4`
- **Tags:** `nmap-script`, `http-headers`

nmap script `http-headers` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Server: Microsoft-IIS/8.5
  Date: Fri, 23 Oct 2026 09:09:19 GMT
  Content-Type: text/html
  Content-Length: 36
  X-AspNet-Version: 4.0.30319
  X-AspNetMvc-Version: 5.2
  X-Powered-By: ASP.NET
  
  (Request type: GET)
```

#### 74. http-methods on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-methods`
- **Finding id:** `26a6d4379f3c`
- **Tags:** `nmap-script`, `http-methods`

nmap script `http-methods` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Potentially risky methods: COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
```

#### 75. http-mobileversion-checker on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-mobileversion-checker`
- **Finding id:** `00dc6b7d98c1`
- **Tags:** `nmap-script`, `http-mobileversion-checker`

nmap script `http-mobileversion-checker` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
No mobile version detected.
```

#### 76. http-referer-checker on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-referer-checker`
- **Finding id:** `d84a77f639d2`
- **Tags:** `nmap-script`, `http-referer-checker`

nmap script `http-referer-checker` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Couldn't find any cross-domain scripts.
```

#### 77. http-title on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-title`
- **Finding id:** `440ddfdaae28`
- **Tags:** `nmap-script`, `http-title`

HTTP page title.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Intranet
```

#### 78. http-useragent-tester on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-useragent-tester`
- **Finding id:** `7cf161b04c82`
- **Tags:** `nmap-script`, `http-useragent-tester`

nmap script `http-useragent-tester` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Status for browser useragent: 200
  Allowed User Agents: 
    Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
    libwww
    lwp-trivial
    libcurl-agent/1.0
    PHP/
    Python-urllib/2.5
    GT::WWW
    Snoopy
    MFC_Tear_Sample
    HTTP::Lite
    PHPCrawl
    URI::Fetch
    Zend_Http_Client
    http client
    PECL::HTTP
    Wget/1.13.4 (linux-gnu)
    WWW-Mechanize/1.34
```

#### 79. http-webdav-scan on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:http-webdav-scan`
- **Finding id:** `5a3568ccde5b`
- **Tags:** `nmap-script`, `http-webdav-scan`

nmap script `http-webdav-scan` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Allowed Methods: OPTIONS, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK, PUT
  WebDAV type: Unknown
  Server Type: Microsoft-IIS/8.5
  Server Date: Fri, 23 Oct 2026 09:09:18 GMT
```

#### 80. API exposes 4 operation(s) on sensitive-looking resources

- **Severity:** Informational  (tentative -- needs confirmation)
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:openapi`
- **Finding id:** `0dde7b1a5a7e`
- **Tags:** `openapi`, `api`, `triage-hint`

Operation paths or names suggest administrative or data-bearing functionality. This is a naming heuristic, not a vulnerability.

> **Requires manual review.** Decide which of these warrant authenticated testing under a separate, explicitly scoped engagement.

**Evidence**

```text
GET    /admin/users
  POST   /admin/users
  GET    /internal/debug/config
  POST   /payments/token
```

#### 81. API specification references hosts outside the engagement scope

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:openapi`
- **Finding id:** `1fc4210c90e9`
- **Tags:** `openapi`, `scope`, `asset-discovery`

The spec names servers that are not in scope. These were not touched. They may be additional assets the client has not listed, which is worth raising.

> **Requires manual review.** Confirm with the client whether these hosts belong to them and should be added to scope for a future assessment.

**Evidence**

```text
https://internal-billing.corp.acme.example/api
```

#### 82. Content review: https://127.0.0.2:8443/metrics

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:web_paths`
- **Finding id:** `5da318c92303`
- **Tags:** `http`, `content-review`

Retrieved for context. /metrics responded 200; establish what it exposes.

> **Requires manual review.** An auditor should judge whether the content disclosed here matters for this client.

**Evidence**

```text
GET https://127.0.0.2:8443/metrics -> 200 OK
content-type: text/plain  length: 143

# HELP http_requests_total Total requests
# TYPE http_requests_total counter
http_requests_total{instance="db-prod-01.corp.acme.example"} 4821
```

#### 83. Content review: https://127.0.0.2:8443/robots.txt

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:web_paths`
- **Finding id:** `2006df9ca89f`
- **Tags:** `http`, `content-review`

Retrieved for context. /robots.txt responded 200; establish what it exposes.

> **Requires manual review.** An auditor should judge whether the content disclosed here matters for this client.

**Evidence**

```text
GET https://127.0.0.2:8443/robots.txt -> 200 OK
content-type: text/plain  length: 51

User-agent: *
Disallow: /admin
Disallow: /internal
```

#### 84. GraphQL API Detection

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:graphql-detect`
- **Finding id:** `ef8db41de2b0`
- **Tags:** `nuclei`, `tech`, `graphql`

nuclei template `graphql-detect` matched.

> **Requires manual review.** GraphQL endpoint. Check introspection and whether mutations are exposed.

**Evidence**

```text
matched-at: https://127.0.0.2:8443/graphql
--- request ---
POST /graphql HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.6 Safari/605.1.15
Content-Length: 67
Accept: */*
Accept-Language: en
Content-Type: application/json
Accept-Encoding: gzip

{"query":"query IntrospectionQuery{__schema {queryType { name }}}"}
--- response ---
HTTP/1.1 200 OK
Content-Length: 445
Content-Type: application/json
Date: Fri, 23 Oct 2026 09:14:07 GMT
Server: nginx/1.18.0
X-Powered-By: Express

{"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "types": [{"name": "Query", "kind": "OBJECT", "fields": [{"name": "invoices"}, {"name": "users"}, {"name": "internalAuditLog"}]}, {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "deleteInvoice"}, {"name": "promoteUserToAdmin"}]}, {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}, {"name": "email"}, {"name": "passwordHash"}]}]}}}
```

#### 85. HTTP service: ACME Billing — API Console on 127.0.0.2:8443

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `e9db3117311f`
- **Tags:** `http`, `fingerprint`

An HTTP service is reachable at https://127.0.0.2:8443. It identifies itself as `nginx/1.18.0`.

> **Requires manual review.** An auditor should confirm whether this application is intended to be internet-facing, and who owns it.

**Evidence**

```text
GET https://127.0.0.2:8443 -> 200 OK
title: ACME Billing — API Console
server: nginx/1.18.0
x-powered-by: Express
```

#### 86. http-comments-displayer on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-comments-displayer`
- **Finding id:** `f75eef45bb60`
- **Tags:** `nmap-script`, `http-comments-displayer`

nmap script `http-comments-displayer` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Couldn't find any comments.
```

#### 87. http-date on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-date`
- **Finding id:** `c5f0447aef62`
- **Tags:** `nmap-script`, `http-date`

nmap script `http-date` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Fri, 23 Oct 2026 09:09:15 GMT; -2s from local time.
```

#### 88. http-fetch on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-fetch`
- **Finding id:** `5e81b56c6f40`
- **Tags:** `nmap-script`, `http-fetch`

nmap script `http-fetch` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Please enter the complete path of the directory to save data in.
```

#### 89. http-headers on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-headers`
- **Finding id:** `6950621fa840`
- **Tags:** `nmap-script`, `http-headers`

nmap script `http-headers` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Server: nginx/1.18.0
  Date: Fri, 23 Oct 2026 09:09:20 GMT
  Content-Type: text/html; charset=utf-8
  Content-Length: 273
  X-Powered-By: Express
  
  (Request type: GET)
```

#### 90. http-malware-host on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-malware-host`
- **Finding id:** `deb7d92516b8`
- **Tags:** `nmap-script`, `http-malware-host`

nmap script `http-malware-host` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
false
```

#### 91. http-mobileversion-checker on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-mobileversion-checker`
- **Finding id:** `61379b324c56`
- **Tags:** `nmap-script`, `http-mobileversion-checker`

nmap script `http-mobileversion-checker` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
No mobile version detected.
```

#### 92. http-referer-checker on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-referer-checker`
- **Finding id:** `3e6786b86d44`
- **Tags:** `nmap-script`, `http-referer-checker`

nmap script `http-referer-checker` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Couldn't find any cross-domain scripts.
```

#### 93. http-robots.txt on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-robots.txt`
- **Finding id:** `a09f64d9f84f`
- **Tags:** `nmap-script`, `http-robots.txt`

nmap script `http-robots.txt` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
2 disallowed entries 
/admin /internal
```

#### 94. http-security-headers on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-security-headers`
- **Finding id:** `af6425bcac3c`
- **Tags:** `nmap-script`, `http-security-headers`

nmap script `http-security-headers` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Strict_Transport_Security: 
    HSTS not configured in HTTPS Server
```

#### 95. http-title on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-title`
- **Finding id:** `57ec10684b96`
- **Tags:** `nmap-script`, `http-title`

HTTP page title.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
ACME Billing &mdash; API Console
```

#### 96. http-useragent-tester on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-useragent-tester`
- **Finding id:** `b6345a25d856`
- **Tags:** `nmap-script`, `http-useragent-tester`

nmap script `http-useragent-tester` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Status for browser useragent: 200
  Allowed User Agents: 
    Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
    libwww
    lwp-trivial
    libcurl-agent/1.0
    PHP/
    Python-urllib/2.5
    GT::WWW
    Snoopy
    MFC_Tear_Sample
    HTTP::Lite
    PHPCrawl
    URI::Fetch
    Zend_Http_Client
    http client
    PECL::HTTP
    Wget/1.13.4 (linux-gnu)
    WWW-Mechanize/1.34
```

#### 97. http-vuln-cve2017-1001000 on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:http-vuln-cve2017-1001000`
- **Finding id:** `9ae10dad9354`
- **Tags:** `nmap-script`, `http-vuln-cve2017-1001000`

nmap script `http-vuln-cve2017-1001000` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
ERROR: Script execution failed (use -d to debug)
```

#### 98. ssl-cert on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:ssl-cert`
- **Finding id:** `8576848c7b06`
- **Tags:** `nmap-script`, `ssl-cert`

TLS certificate details.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Subject: commonName=billing.lab.invalid/organizationName=extscan lab
Subject Alternative Name: IP Address:127.0.0.2, DNS:billing.lab.invalid
Not valid before: 2026-10-23T09:08:18
Not valid after:  2026-11-22T09:08:18
```

#### 99. Content review: http://127.0.0.2:9200/?pretty

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `extscan:web_paths`
- **Finding id:** `808fcb3d29df`
- **Tags:** `http`, `content-review`

Retrieved for context. Elasticsearch/Kibana exposure; check whether indices are readable.

> **Requires manual review.** An auditor should judge whether the content disclosed here matters for this client.

**Evidence**

```text
GET http://127.0.0.2:9200/?pretty -> 200 OK
content-type: application/json  length: 247

{
  "name" : "es-node-1",
  "cluster_name" : "billing-logs",
  "cluster_uuid" : "lab-cluster-uuid",
  "version" : {
    "number" : "6.8.0",
    "build_flavor" : "default",
    "lucene_version" : "7.7.0"
  },
  "tagline" : "You Know, for Search"
}
```

#### 100. HTTP service: untitled on 127.0.0.2:9200

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `extscan:http`
- **Finding id:** `054ee41a0018`
- **Tags:** `http`, `fingerprint`

An HTTP service is reachable at http://127.0.0.2:9200.

> **Requires manual review.** An auditor should confirm whether this application is intended to be internet-facing, and who owns it.

**Evidence**

```text
GET http://127.0.0.2:9200 -> 200 OK
```

#### 101. http-comments-displayer on 127.0.0.2:9200/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nmap-tcp:http-comments-displayer`
- **Finding id:** `44f7d439e226`
- **Tags:** `nmap-script`, `http-comments-displayer`

nmap script `http-comments-displayer` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Couldn't find any comments.
```

#### 102. http-fetch on 127.0.0.2:9200/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nmap-tcp:http-fetch`
- **Finding id:** `07d76b84dd57`
- **Tags:** `nmap-script`, `http-fetch`

nmap script `http-fetch` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Please enter the complete path of the directory to save data in.
```

#### 103. http-headers on 127.0.0.2:9200/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nmap-tcp:http-headers`
- **Finding id:** `20b9d74d1e82`
- **Tags:** `nmap-script`, `http-headers`

nmap script `http-headers` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
content-type: application/json; charset=UTF-8
  Content-Length: 247
  
  (Request type: GET)
```

#### 104. http-mobileversion-checker on 127.0.0.2:9200/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nmap-tcp:http-mobileversion-checker`
- **Finding id:** `35b33b3d778b`
- **Tags:** `nmap-script`, `http-mobileversion-checker`

nmap script `http-mobileversion-checker` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
No mobile version detected.
```

#### 105. http-referer-checker on 127.0.0.2:9200/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nmap-tcp:http-referer-checker`
- **Finding id:** `55c15174df88`
- **Tags:** `nmap-script`, `http-referer-checker`

nmap script `http-referer-checker` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Couldn't find any cross-domain scripts.
```

#### 106. http-title on 127.0.0.2:9200/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nmap-tcp:http-title`
- **Finding id:** `1e79b0c99b89`
- **Tags:** `nmap-script`, `http-title`

HTTP page title.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Site doesn't have a title (application/json; charset=UTF-8).
```

#### 107. http-useragent-tester on 127.0.0.2:9200/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nmap-tcp:http-useragent-tester`
- **Finding id:** `c4d4d95e843f`
- **Tags:** `nmap-script`, `http-useragent-tester`

nmap script `http-useragent-tester` output.

> **Requires manual review.** Script output is informational; an auditor should judge whether what it exposes matters for this client.

**Evidence**

```text
Status for browser useragent: 200
  Allowed User Agents: 
    Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
    libwww
    lwp-trivial
    libcurl-agent/1.0
    PHP/
    Python-urllib/2.5
    GT::WWW
    Snoopy
    MFC_Tear_Sample
    HTTP::Lite
    PHPCrawl
    URI::Fetch
    Zend_Http_Client
    http client
    PECL::HTTP
    Wget/1.13.4 (linux-gnu)
    WWW-Mechanize/1.34
```

#### 108. Redis Require Authentication - Detect

- **Severity:** Informational
- **Affected:** `:2375/tcp`
- **Detected by:** `nuclei:redis-require-auth`
- **Finding id:** `2918dce784bd`
- **Tags:** `nuclei`, `js`, `redis`, `network`, `enum`

IsAuthenticated checks if the redis server requires authentication

**Evidence**

```text
matched-at: 127.0.0.2:2375
--- request ---
const redis = require('nuclei/redis');
const isAuthenticated = redis.IsAuthenticated(Host, Port);
Export(isAuthenticated);
--- response ---
true
```

**References**

- https://docs.projectdiscovery.io/templates/protocols/javascript/modules/redis#isauthenticated

#### 109. Redis Require Authentication - Detect

- **Severity:** Informational
- **Affected:** `:9200/tcp`
- **Detected by:** `nuclei:redis-require-auth`
- **Finding id:** `0b6a81264866`
- **Tags:** `nuclei`, `js`, `redis`, `network`, `enum`

IsAuthenticated checks if the redis server requires authentication

**Evidence**

```text
matched-at: 127.0.0.2:9200
--- request ---
const redis = require('nuclei/redis');
const isAuthenticated = redis.IsAuthenticated(Host, Port);
Export(isAuthenticated);
--- response ---
true
```

**References**

- https://docs.projectdiscovery.io/templates/protocols/javascript/modules/redis#isauthenticated

#### 110. nmap host script: clock-skew

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-tcp:clock-skew`
- **Finding id:** `e465740defee`
- **Tags:** `nmap-script`, `clock-skew`

Host-level nmap script `clock-skew` returned output.

**Evidence**

```text
mean: -1s, deviation: 1s, median: -1s
```

#### 111. nmap host script: fcrdns

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-tcp:fcrdns`
- **Finding id:** `d5e387256f55`
- **Tags:** `nmap-script`, `fcrdns`

Host-level nmap script `fcrdns` returned output.

**Evidence**

```text
FAIL (No PTR record)
```

#### 112. nmap host script: fcrdns

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-udp:fcrdns`
- **Finding id:** `2a50cf384ee3`
- **Tags:** `nmap-script`, `fcrdns`

Host-level nmap script `fcrdns` returned output.

**Evidence**

```text
FAIL (No PTR record)
```

#### 113. nmap host script: ipidseq

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-tcp:ipidseq`
- **Finding id:** `5240e0203a5d`
- **Tags:** `nmap-script`, `ipidseq`

Host-level nmap script `ipidseq` returned output.

**Evidence**

```text
All zeros
```

#### 114. nmap host script: path-mtu

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-tcp:path-mtu`
- **Finding id:** `d862223ce1a2`
- **Tags:** `nmap-script`, `path-mtu`

Host-level nmap script `path-mtu` returned output.

**Evidence**

```text
ERROR: Script execution failed (use -d to debug)
```

#### 115. nmap host script: port-states

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-tcp:port-states`
- **Finding id:** `553eca54e8e7`
- **Tags:** `nmap-script`, `port-states`

Host-level nmap script `port-states` returned output.

**Evidence**

```text
tcp: 
    open: 2222,2375,3306,6379,8080-8081,8443,9200
```

#### 116. nmap host script: port-states

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-udp:port-states`
- **Finding id:** `67cdf0dc342c`
- **Tags:** `nmap-script`, `port-states`

Host-level nmap script `port-states` returned output.

**Evidence**

```text
udp: 
    open: 10161
```

#### 117. nmap host script: qscan

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-tcp:qscan`
- **Finding id:** `5144d825624c`
- **Tags:** `nmap-script`, `qscan`

Host-level nmap script `qscan` returned output.

**Evidence**

```text
PORT  FAMILY  MEAN (us)  STDDEV  LOSS (%)
2222  0       55.80      6.55    0.0%
2375  0       54.90      4.53    0.0%
3306  0       55.50      2.27    0.0%
6379  0       56.60      3.37    0.0%
8080  0       57.30      3.50    0.0%
8081  0       56.30      4.27    0.0%
8443  0       57.00      1.63    0.0%
9200  0       57.60      2.67    0.0%
```

#### 118. nmap host script: unusual-port

- **Severity:** Informational
- **Affected:** `127.0.0.2`
- **Detected by:** `nmap-udp:unusual-port`
- **Finding id:** `b75287b4205f`
- **Tags:** `nmap-script`, `unusual-port`

Host-level nmap script `unusual-port` returned output.

**Evidence**

```text
WARNING: this script depends on Nmap's service/version detection (-sV)
```

#### 119. banner on 127.0.0.2:2222/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:2222/tcp`
- **Detected by:** `nmap-tcp:banner`
- **Finding id:** `3d4f8a161074`
- **Tags:** `nmap-script`, `banner`

nmap script `banner` output.

**Evidence**

```text
SSH-2.0-OpenSSH_7.4
```

#### 120. unusual-port on 127.0.0.2:2222/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:2222/tcp`
- **Detected by:** `nmap-tcp:unusual-port`
- **Finding id:** `4e0d03176154`
- **Tags:** `nmap-script`, `unusual-port`

nmap script `unusual-port` output.

**Evidence**

```text
ssh unexpected on port tcp/2222
```

#### 121. Composer Config - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:2375/tcp`
- **Detected by:** `nuclei:composer-config`
- **Finding id:** `f45bd0c48a5f`
- **Tags:** `nuclei`, `config`, `exposure`

Composer configuration file detected.

**Evidence**

```text
matched-at: http://127.0.0.2:2375/composer.json
matcher: composer.lock
--- request ---
GET /composer.json HTTP/1.1
Host: 127.0.0.2:2375
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; sv-SE) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.0 404 Not Found
Connection: close
Content-Length: 29
Content-Type: application/json
Date: Fri, 23 Oct 2026 09:16:37 GMT

{"message":"page not found"}
```

**References**

- https://getcomposer.org/

#### 122. HTTP Missing Security Headers

- **Severity:** Informational
- **Affected:** `127.0.0.2:2375/tcp`
- **Detected by:** `nuclei:http-missing-security-headers`
- **Finding id:** `e3685b98616a`
- **Tags:** `nuclei`, `misconfig`, `headers`, `generic`

This template searches for missing HTTP security headers. The impact of these missing headers can vary.

**Evidence**

```text
matched-at: http://127.0.0.2:2375
matcher: x-content-type-options
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:2375
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.0 404 Not Found
Connection: close
Content-Length: 29
Content-Type: application/json
Date: Fri, 23 Oct 2026 09:17:02 GMT

{"message":"page not found"}
```

#### 123. MySQL - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:3306/tcp`
- **Detected by:** `nuclei:mysql-detect`
- **Finding id:** `0c196504965a`
- **Tags:** `nuclei`, `network`, `mysql`, `db`, `detect`, `detection`, `tcp`

MySQL instance was detected.

**Evidence**

```text
matched-at: 127.0.0.2:3306
--- request ---


--- response ---
N   
5.7.33-log *   abcdefgh ��! ��          ijklmnopqrst mysql_native_password 
```

#### 124. MySQL - Password Vulnerability

- **Severity:** Informational
- **Affected:** `127.0.0.2:3306/tcp`
- **Detected by:** `nuclei:mysql-native-password`
- **Finding id:** `b51d50f8db5a`
- **Tags:** `nuclei`, `network`, `mysql`, `db`, `misconfig`, `tcp`

MySQL database queries with enabled native password support are susceptible to password brute-force attacks.

**Evidence**

```text
matched-at: 127.0.0.2:3306
--- response ---
N   
5.7.33-log *   abcdefgh ��! ��          ijklmnopqrst mysql_native_password 
```

**References**

- https://github.com/Tinram/MySQL-Brute

#### 125. MySQL Info - Enumeration

- **Severity:** Informational
- **Affected:** `127.0.0.2:3306/tcp`
- **Detected by:** `nuclei:mysql-info`
- **Finding id:** `cbe3eb8647ac`
- **Tags:** `nuclei`, `js`, `mssql`, `network`, `enum`

Connects to a MySQL server and prints information such as the protocol and version numbers

**Evidence**

```text
matched-at: 127.0.0.2:3306
extracted: Version: 5.7.33-log, Transport: tcp
--- request ---
var m = require("nuclei/mysql");
var c = m.MySQLClient();
var response = c.FingerprintMySQL(Host, Port);
Export(response);
--- response ---
{
  "Host": "127.0.0.2",
  "IP": "invalid IP",
  "Port": 0,
  "Protocol": "mysql",
  "TLS": false,
  "Transport": "tcp",
  "Version": "5.7.33-log",
  "Debug": {
    "PacketType": "handshake",
    "ErrorMessage": "",
    "ErrorCode": 0
  },
  "Raw": "{\"packetType\":\"handshake\",\"errorMsg\":\"\",\"errorCode\":0}"
}
```

**References**

- https://nmap.org/nsedoc/scripts/mysql-info.html

#### 126. banner on 127.0.0.2:3306/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:3306/tcp`
- **Detected by:** `nmap-tcp:banner`
- **Finding id:** `bef723b23fb4`
- **Tags:** `nmap-script`, `banner`

nmap script `banner` output.

**Evidence**

```text
N\x00\x00\x00\x0A5.7.33-log\x00*\x00\x00\x00abcdefgh\x00\xFF...
```

#### 127. mysql-info on 127.0.0.2:3306/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:3306/tcp`
- **Detected by:** `nmap-tcp:mysql-info`
- **Finding id:** `c42aca4c5469`
- **Tags:** `nmap-script`, `mysql-info`

nmap script `mysql-info` output.

**Evidence**

```text
Protocol: 10
  Version: 5.7.33-log
  Thread ID: 42
  Capabilities flags: 63487
  Some Capabilities: Speaks41ProtocolNew, LongColumnFlag, SupportsLoadDataLocal, Speaks41ProtocolOld, LongPassword, DontAllowDatabaseTableColumn, ConnectWithDatabase, SupportsTransactions, IgnoreSigpipes, ODBCClient, SupportsCompression, InteractiveClient, Support41Auth, IgnoreSpaceBeforeParenthesis, FoundRows, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
  Status: Autocommit
  Salt: abcdefghijklmnopqrst
  Auth Plugin Name: mysql_native_password
```

#### 128. Redis Require Authentication - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:6379/tcp`
- **Detected by:** `nuclei:redis-require-auth`
- **Finding id:** `fcb39868739d`
- **Tags:** `nuclei`, `js`, `redis`, `network`, `enum`

IsAuthenticated checks if the redis server requires authentication

**Evidence**

```text
matched-at: 127.0.0.2:6379
--- request ---
const redis = require('nuclei/redis');
const isAuthenticated = redis.IsAuthenticated(Host, Port);
Export(isAuthenticated);
--- response ---
true
```

**References**

- https://docs.projectdiscovery.io/templates/protocols/javascript/modules/redis#isauthenticated

#### 129. /actuator present but access-controlled on 127.0.0.2:8080

- **Severity:** Informational  (tentative -- needs confirmation)
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `6bd6e3604165`
- **Tags:** `http`, `path-check`, `protected`

http://127.0.0.2:8080/actuator returned 401, so the path exists but is protected. Worth noting: the protection is the only thing standing between the internet and this resource.

**Evidence**

```text
GET http://127.0.0.2:8080/actuator -> 401 Unauthorized
```

#### 130. API endpoint enforces authentication despite spec: http://127.0.0.2:8080/api/internal/debug/config

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:api`
- **Finding id:** `ff044622e223`
- **Tags:** `api`, `documentation`

The specification declared no security requirement, but the endpoint returned 403. Enforcement is happening somewhere other than the spec -- worth reporting as a documentation defect rather than an access-control one.

**Evidence**

```text
GET http://127.0.0.2:8080/api/internal/debug/config -> 403 Forbidden
```

#### 131. Exposed /robots.txt on 127.0.0.2:8080

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `93c23ea1fdc3`
- **Tags:** `http`, `path-check`, `/robots.txt`

robots.txt lists paths the owner would rather not have indexed, which is a useful map.

**Evidence**

```text
GET http://127.0.0.2:8080/robots.txt -> 200 OK
content-type: text/plain
length: 51

User-agent: *
Disallow: /admin
Disallow: /internal
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 132. HTTP Missing Security Headers

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:http-missing-security-headers`
- **Finding id:** `4cd04228c942`
- **Tags:** `nuclei`, `misconfig`, `headers`, `generic`

This template searches for missing HTTP security headers. The impact of these missing headers can vary.

**Evidence**

```text
matched-at: http://127.0.0.2:8080
matcher: strict-transport-security
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 273
Content-Type: text/html; charset=utf-8
Date: Fri, 23 Oct 2026 09:17:02 GMT
Server: nginx/1.18.0
X-Powered-By: Express

<!doctype html>
<html><head><title>ACME Billing &mdash; API Console</title></head>
<body>
<div id="swagger-ui"></div>
<script src="/static/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/swagger.json", dom_id: '#swagger-ui' });
</script>
</body></html>
```

#### 133. Nginx version detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:nginx-version`
- **Finding id:** `1fa03fa2300a`
- **Tags:** `nuclei`, `tech`, `nginx`

Some nginx servers have the version on the response header. Useful when you need to find specific CVEs on your targets.

**Evidence**

```text
matched-at: http://127.0.0.2:8080
extracted: nginx/1.18.0
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (ZZ; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 273
Content-Type: text/html; charset=utf-8
Date: Fri, 23 Oct 2026 09:17:59 GMT
Server: nginx/1.18.0
X-Powered-By: Express

<!doctype html>
<html><head><title>ACME Billing &mdash; API Console</title></head>
<body>
<div id="swagger-ui"></div>
<script src="/static/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/swagger.json", dom_id: '#swagger-ui' });
</script>
</body></html>
```

#### 134. WAF Detection

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:waf-detect`
- **Finding id:** `7112eb8043c8`
- **Tags:** `nuclei`, `waf`, `tech`, `misc`

A web application firewall was detected.

**Evidence**

```text
matched-at: http://127.0.0.2:8080
matcher: nginxgeneric
--- request ---
POST / HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Connection: close
Content-Length: 27
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

_=<script>alert(1)</script>
--- response ---
HTTP/1.1 405 Method Not Allowed
Content-Length: 30
Content-Type: application/json
Date: Fri, 23 Oct 2026 09:14:21 GMT
Server: nginx/1.18.0
X-Powered-By: Express

{"error":"method not allowed"}
```

**References**

- https://github.com/Ekultek/WhatWaf

#### 135. Wappalyzer Technology Detection

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:tech-detect`
- **Finding id:** `d3488bb27e56`
- **Tags:** `nuclei`, `tech`

nuclei template `tech-detect` matched.

**Evidence**

```text
matched-at: http://127.0.0.2:8080
matcher: express
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (Knoppix; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 273
Content-Type: text/html; charset=utf-8
Date: Fri, 23 Oct 2026 09:18:32 GMT
Server: nginx/1.18.0
X-Powered-By: Express

<!doctype html>
<html><head><title>ACME Billing &mdash; API Console</title></head>
<body>
<div id="swagger-ui"></div>
<script src="/static/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/swagger.json", dom_id: '#swagger-ui' });
</script>
</body></html>
```

#### 136. robots.txt endpoint prober

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:robots-txt-endpoint`
- **Finding id:** `8420f8597110`
- **Tags:** `nuclei`, `miscellaneous`, `misc`, `generic`

nuclei template `robots-txt-endpoint` matched.

**Evidence**

```text
matched-at: http://127.0.0.2:8080/robots.txt
--- request ---
GET /robots.txt HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (Ubuntu; Linux i686; rv:132.0) Gecko/20100101 Firefox/132.0
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 51
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:18:21 GMT
Server: nginx/1.18.0
X-Powered-By: Express

User-agent: *
Disallow: /admin
Disallow: /internal
```

#### 137. robots.txt file

- **Severity:** Informational
- **Affected:** `127.0.0.2:8080/tcp`
- **Detected by:** `nuclei:robots-txt`
- **Finding id:** `2458daefe313`
- **Tags:** `nuclei`, `miscellaneous`, `misc`, `generic`

nuclei template `robots-txt` matched.

**Evidence**

```text
matched-at: http://127.0.0.2:8080/robots.txt
--- request ---
GET /robots.txt HTTP/1.1
Host: 127.0.0.2:8080
User-Agent: Mozilla/5.0 (SS; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 51
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:16:19 GMT
Server: nginx/1.18.0
X-Powered-By: Express

User-agent: *
Disallow: /admin
Disallow: /internal
```

#### 138. Allowed Options Method

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nuclei:options-method`
- **Finding id:** `8170d4160ad7`
- **Tags:** `nuclei`, `miscellaneous`, `misc`, `generic`

nuclei template `options-method` matched.

**Evidence**

```text
matched-at: http://127.0.0.2:8081
extracted: OPTIONS, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK, PUT
--- request ---
OPTIONS / HTTP/1.1
Host: 127.0.0.2:8081
User-Agent: Mozilla/5.0 (Knoppix; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Allow: OPTIONS, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK, PUT
Content-Type: text/html
Date: Fri, 23 Oct 2026 09:18:17 GMT
Dav: 1, 2
Server: Microsoft-IIS/8.5
X-Aspnet-Version: 4.0.30319
X-Aspnetmvc-Version: 5.2
X-Powered-By: ASP.NET
Content-Length: 0
```

#### 139. AspNet Version Disclosure - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nuclei:aspnet-version-detect`
- **Finding id:** `acfad0ff5321`
- **Tags:** `nuclei`, `tech`, `detect`, `aspnet`

Detects version disclosed via 'X-AspNet-Version' header.

**Evidence**

```text
matched-at: http://127.0.0.2:8081
extracted: 4.0.30319
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8081
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 36
Content-Type: text/html
Date: Fri, 23 Oct 2026 09:16:29 GMT
Server: Microsoft-IIS/8.5
X-Aspnet-Version: 4.0.30319
X-Aspnetmvc-Version: 5.2
X-Powered-By: ASP.NET

<html><title>Intranet</title></html>
```

#### 140. AspNetMvc Version - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nuclei:aspnetmvc-version-disclosure`
- **Finding id:** `1b006e2a7b0f`
- **Tags:** `nuclei`, `aspnetmvc`, `tech`, `detect`

Detects version disclosed via 'X-AspNetMvc-Version' header.

**Evidence**

```text
matched-at: http://127.0.0.2:8081
extracted: 5.2
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8081
User-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 36
Content-Type: text/html
Date: Fri, 23 Oct 2026 09:17:29 GMT
Server: Microsoft-IIS/8.5
X-Aspnet-Version: 4.0.30319
X-Aspnetmvc-Version: 5.2
X-Powered-By: ASP.NET

<html><title>Intranet</title></html>
```

#### 141. HTTP Missing Security Headers

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nuclei:http-missing-security-headers`
- **Finding id:** `641ec58957ef`
- **Tags:** `nuclei`, `misconfig`, `headers`, `generic`

This template searches for missing HTTP security headers. The impact of these missing headers can vary.

**Evidence**

```text
matched-at: http://127.0.0.2:8081
matcher: clear-site-data
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8081
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 36
Content-Type: text/html
Date: Fri, 23 Oct 2026 09:17:02 GMT
Server: Microsoft-IIS/8.5
X-Aspnet-Version: 4.0.30319
X-Aspnetmvc-Version: 5.2
X-Powered-By: ASP.NET

<html><title>Intranet</title></html>
```

#### 142. IIS - Short Name Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nuclei:iis-shortname`
- **Finding id:** `67d7759e5bbe`
- **Tags:** `nuclei`, `iis`, `edb`, `fuzzing`

A website running via IIS on an old .net framework contains a get request vulnerability. Using the the tilde character "~" in the request, an attacker can locate short names of files and folders not normally visible.

**Evidence**

```text
matched-at: http://127.0.0.2:8081/*~1*/a.aspx
--- request ---
GET /*~1*/a.aspx HTTP/1.1
Host: 127.0.0.2:8081
User-Agent: Mozilla/5.0 (SS; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Connection: close
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Origin: http://127.0.0.2:8081
Accept-Encoding: gzip


--- response ---
HTTP/1.1 404 Not Found
Content-Type: text/html
Date: Fri, 23 Oct 2026 09:13:38 GMT
Server: Microsoft-IIS/8.5
X-Aspnet-Version: 4.0.30319
X-Aspnetmvc-Version: 5.2
X-Powered-By: ASP.NET
Content-Length: 0
```

**References**

- https://github.com/lijiejie/IIS_shortname_Scanner
- https://www.exploit-db.com/exploits/19525
- http://soroush.secproject.com/blog/2012/06/microsoft-iis-tilde-character-vulnerabilityfeature-short-filefolder-name-disclosure/

#### 143. Microsoft IIS version detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nuclei:microsoft-iis-version`
- **Finding id:** `72e75805a3c7`
- **Tags:** `nuclei`, `tech`, `microsoft`, `iis`

Some Microsoft IIS servers have the version on the response header. Useful when you need to find specific CVEs on your targets.

**Evidence**

```text
matched-at: http://127.0.0.2:8081
extracted: Microsoft-IIS/8.5
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8081
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 36
Content-Type: text/html
Date: Fri, 23 Oct 2026 09:16:53 GMT
Server: Microsoft-IIS/8.5
X-Aspnet-Version: 4.0.30319
X-Aspnetmvc-Version: 5.2
X-Powered-By: ASP.NET

<html><title>Intranet</title></html>
```

#### 144. Wappalyzer Technology Detection

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nuclei:tech-detect`
- **Finding id:** `06473c3fb5e2`
- **Tags:** `nuclei`, `tech`

nuclei template `tech-detect` matched.

**Evidence**

```text
matched-at: http://127.0.0.2:8081
matcher: ms-iis
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 36
Content-Type: text/html
Date: Fri, 23 Oct 2026 09:18:32 GMT
Server: Microsoft-IIS/8.5
X-Aspnet-Version: 4.0.30319
X-Aspnetmvc-Version: 5.2
X-Powered-By: ASP.NET

<html><title>Intranet</title></html>
```

#### 145. unusual-port on 127.0.0.2:8081/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8081/tcp`
- **Detected by:** `nmap-tcp:unusual-port`
- **Finding id:** `e03b8d150e35`
- **Tags:** `nmap-script`, `unusual-port`

nmap script `unusual-port` output.

**Evidence**

```text
http unexpected on port tcp/8081
```

#### 146. /actuator present but access-controlled on 127.0.0.2:8443

- **Severity:** Informational  (tentative -- needs confirmation)
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `5e9032886a6b`
- **Tags:** `http`, `path-check`, `protected`

https://127.0.0.2:8443/actuator returned 401, so the path exists but is protected. Worth noting: the protection is the only thing standing between the internet and this resource.

**Evidence**

```text
GET https://127.0.0.2:8443/actuator -> 401 Unauthorized
```

#### 147. API endpoint enforces authentication despite spec: http://127.0.0.2:8080/api/internal/debug/config

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:api`
- **Finding id:** `ec2d26b395de`
- **Tags:** `api`, `documentation`

The specification declared no security requirement, but the endpoint returned 403. Enforcement is happening somewhere other than the spec -- worth reporting as a documentation defect rather than an access-control one.

**Evidence**

```text
GET http://127.0.0.2:8080/api/internal/debug/config -> 403 Forbidden
```

#### 148. Detect SSL Certificate Issuer

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:ssl-issuer`
- **Finding id:** `dc22c6b07c6a`
- **Tags:** `nuclei`, `ssl`, `tls`

Extract the issuer's organization from the target's certificate. Issuers are entities which sign and distribute certificates.

**Evidence**

```text
matched-at: 127.0.0.2:8443
extracted: extscan lab
```

#### 149. Exposed /robots.txt on 127.0.0.2:8443

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:paths`
- **Finding id:** `8d2813a89ad5`
- **Tags:** `http`, `path-check`, `/robots.txt`

robots.txt lists paths the owner would rather not have indexed, which is a useful map.

**Evidence**

```text
GET https://127.0.0.2:8443/robots.txt -> 200 OK
content-type: text/plain
length: 51

User-agent: *
Disallow: /admin
Disallow: /internal
```

**Recommendation**

Remove the file from the document root or block the path at the edge; rotate anything it disclosed.

#### 150. Grat2 C2 JARM - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:grat-c2-jarm`
- **Finding id:** `84d32e4311cc`
- **Tags:** `nuclei`, `c2`, `jarm`, `network`, `ir`, `osint`, `cti`, `shad0w`, `tcp`

GRAT2 is a Command and Control (C2) tool written in python3 and the client in .NET 4.5. The main idea came from Georgios Koumettou who initiated the project.

**Evidence**

```text
matched-at: 127.0.0.2:8443
--- request ---
2E
```

**References**

- https://github.com/cedowens/C2-JARM
- https://github.com/r3nhat/GRAT2

#### 151. HTTP Missing Security Headers

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:http-missing-security-headers`
- **Finding id:** `a833dbc478bb`
- **Tags:** `nuclei`, `misconfig`, `headers`, `generic`

This template searches for missing HTTP security headers. The impact of these missing headers can vary.

**Evidence**

```text
matched-at: https://127.0.0.2:8443
matcher: strict-transport-security
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (ZZ; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 273
Content-Type: text/html; charset=utf-8
Date: Fri, 23 Oct 2026 09:17:02 GMT
Server: nginx/1.18.0
X-Powered-By: Express

<!doctype html>
<html><head><title>ACME Billing &mdash; API Console</title></head>
<body>
<div id="swagger-ui"></div>
<script src="/static/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/swagger.json", dom_id: '#swagger-ui' });
</script>
</body></html>
```

#### 152. MacC2 JARM - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:mac-c2-jarm`
- **Finding id:** `a40fdd41077b`
- **Tags:** `nuclei`, `jarm`, `network`, `c2`, `ir`, `osint`, `cti`, `macc2`, `tcp`

MacC2 is a macOS post exploitation tool written in python that uses Objective C calls or python libraries as opposed to command line executions. The client is written in python2, which though deprecated is still being shipped with base Big Sur installs. It is possible down the road that Apple will remove python2 (or python altogether) from base macOS installs but as of Nov 2020 this is not the case. Apple plans to eventually remove scripting runtimes from base macOS installs, but it is unknown when that will happen since Big Sur includes python.

**Evidence**

```text
matched-at: 127.0.0.2:8443
--- request ---
2E
```

**References**

- https://github.com/cedowens/C2-JARM
- https://github.com/cedowens/MacC2

#### 153. Mythic C2 JARM - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:mythic-c2-jarm`
- **Finding id:** `bc67d623b53b`
- **Tags:** `nuclei`, `jarm`, `network`, `c2`, `ir`, `osint`, `cti`, `mythic`, `tcp`

A cross-platform, post-exploit, red teaming framework built with python3, docker, docker-compose, and a web browser UI.
It's designed to provide a collaborative and user friendly interface for operators, managers, and reporting throughout red teaming.

**Evidence**

```text
matched-at: 127.0.0.2:8443
--- request ---
2E
```

**References**

- https://github.com/cedowens/C2-JARM
- https://www.socinvestigation.com/shodan-filters-to-hunt-adversaries-infrastructure-and-c2/

#### 154. Nginx version detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:nginx-version`
- **Finding id:** `275857b8131a`
- **Tags:** `nuclei`, `tech`, `nginx`

Some nginx servers have the version on the response header. Useful when you need to find specific CVEs on your targets.

**Evidence**

```text
matched-at: https://127.0.0.2:8443
extracted: nginx/1.18.0
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 273
Content-Type: text/html; charset=utf-8
Date: Fri, 23 Oct 2026 09:17:59 GMT
Server: nginx/1.18.0
X-Powered-By: Express

<!doctype html>
<html><head><title>ACME Billing &mdash; API Console</title></head>
<body>
<div id="swagger-ui"></div>
<script src="/static/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/swagger.json", dom_id: '#swagger-ui' });
</script>
</body></html>
```

#### 155. SILENTTRINITY C2 JARM - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:silenttrinity-c2-jarm`
- **Finding id:** `85aa10ae7f18`
- **Tags:** `nuclei`, `jarm`, `network`, `c2`, `ir`, `osint`, `cti`, `silenttrinity`, `tcp`

SILENTTRINITY is modern, asynchronous, multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. It's the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET API's, a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell.

**Evidence**

```text
matched-at: 127.0.0.2:8443
--- request ---
2E
```

**References**

- https://github.com/cedowens/C2-JARM
- https://github.com/byt3bl33d3r/SILENTTRINITY

#### 156. SSL DNS Names

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:ssl-dns-names`
- **Finding id:** `b4c82266de11`
- **Tags:** `nuclei`, `ssl`, `tls`

Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.

**Evidence**

```text
matched-at: 127.0.0.2:8443
extracted: billing.lab.invalid
```

#### 157. Shad0w C2 JARM - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:shad0w-c2-jarm`
- **Finding id:** `ecd97496d837`
- **Tags:** `nuclei`, `jarm`, `network`, `c2`, `ir`, `osint`, `cti`, `shad0w`, `tcp`

SHAD0W is a modular C2 framework designed to successfully operate on mature environments.

**Evidence**

```text
matched-at: 127.0.0.2:8443
--- request ---
2E
```

**References**

- https://github.com/cedowens/C2-JARM
- https://github.com/bats3c/shad0w

#### 158. TLS Version - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:tls-version`
- **Finding id:** `cd2063de4285`
- **Tags:** `nuclei`, `ssl`, `tls`

TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.
It is important to detect the TLS version in order to ensure secure communication between two computers or servers.

**Evidence**

```text
matched-at: 127.0.0.2:8443
extracted: tls12
```

#### 159. TLS endpoint 127.0.0.2:8443 (TLSv1.3)

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `extscan:tls`
- **Finding id:** `87146bc6dfd9`
- **Tags:** `tls`, `fingerprint`

TLS configuration as observed.

**Evidence**

```text
negotiated: TLSv1.3  cipher: TLS_AES_256_GCM_SHA384 (256 bit)
subject: CN = billing.lab.invalid, O = extscan lab
issuer: CN = billing.lab.invalid, O = extscan lab
validity: Oct 23 09:08:18 2026 GMT .. Nov 22 09:08:18 2026 GMT
SANs: 127.0.0.2, billing.lab.invalid
protocols: TLSv1.0=no, TLSv1.1=no, TLSv1.2=yes, TLSv1.3=yes
```

#### 160. Wappalyzer Technology Detection

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:tech-detect`
- **Finding id:** `1b2221bc42f0`
- **Tags:** `nuclei`, `tech`

nuclei template `tech-detect` matched.

**Evidence**

```text
matched-at: https://127.0.0.2:8443
matcher: express
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 273
Content-Type: text/html; charset=utf-8
Date: Fri, 23 Oct 2026 09:18:32 GMT
Server: nginx/1.18.0
X-Powered-By: Express

<!doctype html>
<html><head><title>ACME Billing &mdash; API Console</title></head>
<body>
<div id="swagger-ui"></div>
<script src="/static/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/swagger.json", dom_id: '#swagger-ui' });
</script>
</body></html>
```

#### 161. robots.txt endpoint prober

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:robots-txt-endpoint`
- **Finding id:** `160d4175f9fb`
- **Tags:** `nuclei`, `miscellaneous`, `misc`, `generic`

nuclei template `robots-txt-endpoint` matched.

**Evidence**

```text
matched-at: https://127.0.0.2:8443/robots.txt
--- request ---
GET /robots.txt HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (SS; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 51
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:18:21 GMT
Server: nginx/1.18.0
X-Powered-By: Express

User-agent: *
Disallow: /admin
Disallow: /internal
```

#### 162. robots.txt file

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nuclei:robots-txt`
- **Finding id:** `60951840101f`
- **Tags:** `nuclei`, `miscellaneous`, `misc`, `generic`

nuclei template `robots-txt` matched.

**Evidence**

```text
matched-at: https://127.0.0.2:8443/robots.txt
--- request ---
GET /robots.txt HTTP/1.1
Host: 127.0.0.2:8443
User-Agent: Mozilla/5.0 (ZZ; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.1 200 OK
Content-Length: 51
Content-Type: text/plain
Date: Fri, 23 Oct 2026 09:16:19 GMT
Server: nginx/1.18.0
X-Powered-By: Express

User-agent: *
Disallow: /admin
Disallow: /internal
```

#### 163. ssl-date on 127.0.0.2:8443/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:8443/tcp`
- **Detected by:** `nmap-tcp:ssl-date`
- **Finding id:** `0978c162a948`
- **Tags:** `nmap-script`, `ssl-date`

TLS server clock/date.

**Evidence**

```text
TLS randomness does not represent time
```

#### 164. Composer Config - Detect

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nuclei:composer-config`
- **Finding id:** `de38db6cebd7`
- **Tags:** `nuclei`, `config`, `exposure`

Composer configuration file detected.

**Evidence**

```text
matched-at: http://127.0.0.2:9200/composer.json
matcher: composer.lock
--- request ---
GET /composer.json HTTP/1.1
Host: 127.0.0.2:9200
User-Agent: Mozilla/5.0 (ZZ; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.0 404 Not Found
Connection: close
Content-Length: 35
Content-Type: application/json; charset=UTF-8

{
  "message" : "page not found"
}
```

**References**

- https://getcomposer.org/

#### 165. FingerprintHub Technology Fingerprint

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nuclei:fingerprinthub-web-fingerprints`
- **Finding id:** `49bae7745563`
- **Tags:** `nuclei`, `tech`

FingerprintHub Technology Fingerprint tests run in nuclei.

**Evidence**

```text
matched-at: http://127.0.0.2:9200
matcher: elasticsearch
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:9200
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.0 200 OK
Connection: close
Content-Length: 247
Content-Type: application/json; charset=UTF-8

{
  "name" : "es-node-1",
  "cluster_name" : "billing-logs",
  "cluster_uuid" : "lab-cluster-uuid",
  "version" : {
    "number" : "6.8.0",
    "build_flavor" : "default",
    "lucene_version" : "7.7.0"
  },
  "tagline" : "You Know, for Search"
}
```

**References**

- https://github.com/0x727/FingerprintHub

#### 166. HTTP Missing Security Headers

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nuclei:http-missing-security-headers`
- **Finding id:** `2fe9e8c251b4`
- **Tags:** `nuclei`, `misconfig`, `headers`, `generic`

This template searches for missing HTTP security headers. The impact of these missing headers can vary.

**Evidence**

```text
matched-at: http://127.0.0.2:9200
matcher: strict-transport-security
--- request ---
GET / HTTP/1.1
Host: 127.0.0.2:9200
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip


--- response ---
HTTP/1.0 200 OK
Connection: close
Content-Length: 247
Content-Type: application/json; charset=UTF-8

{
  "name" : "es-node-1",
  "cluster_name" : "billing-logs",
  "cluster_uuid" : "lab-cluster-uuid",
  "version" : {
    "number" : "6.8.0",
    "build_flavor" : "default",
    "lucene_version" : "7.7.0"
  },
  "tagline" : "You Know, for Search"
}
```

#### 167. unusual-port on 127.0.0.2:9200/tcp

- **Severity:** Informational
- **Affected:** `127.0.0.2:9200/tcp`
- **Detected by:** `nmap-tcp:unusual-port`
- **Finding id:** `486e9a8295fd`
- **Tags:** `nmap-script`, `unusual-port`

nmap script `unusual-port` output.

**Evidence**

```text
http unexpected on port tcp/9200
```

#### 168. fingerprint-strings on 127.0.0.2:10161/udp

- **Severity:** Informational
- **Affected:** `127.0.0.2:10161/udp`
- **Detected by:** `nmap-udp:fingerprint-strings`
- **Finding id:** `4617422b85a5`
- **Tags:** `nmap-script`, `fingerprint-strings`

nmap script `fingerprint-strings` output.

**Evidence**

```text
SNMPv1public: 
    public
    0301
    %Linux lab-router 4.19.0 #1 SMP x86_64
```

## Service inventory

| Host | Port | Proto | Service | Product / version | Probes run |
|---|---|---|---|---|---|
| `127.0.0.2` | 2222 | tcp | ssh | OpenSSH 7.4 protocol 2.0 | ssh |
| `127.0.0.2` | 2375 | tcp | docker | Docker remote API | nuclei, http_fingerprint, exposure |
| `127.0.0.2` | 3306 | tcp | mysql | MySQL 5.7.33-log | exposure |
| `127.0.0.2` | 6379 | tcp | redis | Redis key-value store 5.0.7 | exposure |
| `127.0.0.2` | 8080 | tcp | http | nginx 1.18.0 | nuclei, http_fingerprint |
| `127.0.0.2` | 8081 | tcp | http | Microsoft IIS httpd 8.5 | nuclei, http_fingerprint, iis |
| `127.0.0.2` | 8443 | tcp | http | nginx 1.18.0 | nuclei, http_fingerprint, tls, sslscan |
| `127.0.0.2` | 9200 | tcp | http | Elasticsearch REST API 6.8.0 name: es-node-1; cluster: billing-logs; Lucene 7.7.0 | nuclei, http_fingerprint, exposure |
| `127.0.0.2` | 10161 | udp | snmpdtls | - | snmp |

### Host detail

| Host | Hostnames | OS guess |
|---|---|---|
| `127.0.0.2` | - | Linux 5.0 - 5.7 (100%) |

## Methodology and limitations

Stages completed:

- `discover` at 2026-10-23 09:12:00 UTC
- `probe` at 2026-10-23 09:18:40 UTC
- `chase` at 2026-10-23 09:18:41 UTC
- `report` — **not run**

Limitations that apply to this report:

- All checks were read-only. No credentials were tested, no data was modified, and no exploitation was attempted. Findings marked *tentative* are version-derived or specification-derived and need confirmation.
- Services behind a WAF, rate limiter or geo-filter may be under-reported.
- UDP results are less reliable than TCP by nature: silence is ambiguous.
- Absence of a finding is not evidence of absence of a vulnerability.

### Tool versions

- `nmap`: Nmap version 7.94SVN ( https://nmap.org )
- `nuclei`: [[34mINF[0m] Nuclei Engine Version: v3.4.10
- `openssl`: OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)

### Command log

4 command(s) were executed. Full argv, exit codes and timings are in `commands.jsonl` in the run directory.

```text
[2026-10-23 09:08:22 UTC] rc=0 89.3s  nmap -sS -sV --version-intensity 5 --script (default or safe) and not (dos or external or http-slowloris-check) -p 2222,2375,3306,6379,8080,8081,8443,9200 -T4 --max-retries 2 --host-timeout 30m --open -oA runs/20261023-090822-extscan-local-lab/raw/nmap-tcp-0001 -Pn -O 127.0.0.2
[2026-10-23 09:09:51 UTC] rc=0 128.1s  nmap -sU -sV --version-intensity 5 -p 10161 -T4 --max-retries 2 --host-timeout 30m --open -oA runs/20261023-090822-extscan-local-lab/raw/nmap-udp-0001 --script (default or safe) and not (dos or external or http-slowloris-check) -Pn 127.0.0.2
[2026-10-23 09:12:00 UTC] rc=0 400.6s  nuclei -list runs/20261023-090822-extscan-local-lab/raw/nuclei-targets.txt -jsonl -output runs/20261023-090822-extscan-local-lab/raw/nuclei.jsonl -severity info,low,medium,high,critical -rate-limit 150 -c 15 -retries 1 -timeout 10 -silent -no-color -disable-update-check -exclude-tags dos,intrusive,fuzz,brute-force,default-login,default-logins,creds-stuffing -no-interactsh
[2026-10-23 09:18:40 UTC] rc=0 0.2s  sslscan --no-colour --show-certificate --xml=runs/20261023-090822-extscan-local-lab/raw/sslscan-127.0.0.2-8443.xml 127.0.0.2:8443
```

