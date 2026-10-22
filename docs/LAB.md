# Local test lab

The unit tests feed probes pre-built `Service` objects, so they never exercise
real nmap discovery, real nuclei, or service identification. The lab covers
that gap. It is a set of deliberately exposed listeners on a dedicated loopback
address, so you can run the whole pipeline end to end on a workstation without
touching a network you don't own.

Everything is stdlib Python and reuses the handlers the test suite already
uses (`tests/targetapp.py`, the IIS handler in `tests/test_new_tools.py`, the
SNMP agent in `tests/test_snmp.py`). One extra dependency: `openssl` on `PATH`,
which generates the self-signed certificate at startup.

## Quick start

```bash
# terminal 1: start the lab (Ctrl-C to stop)
uv run python -m tests.lab

# terminal 2: scan it
uv run extscan run --scope examples/lab/scope.json --policy examples/lab/policy.json
uv run extscan findings latest
uv run extscan gaps latest
```

A full run takes about 8 minutes, nearly all of it nuclei. With
`--skip-nuclei` on `probe`, or nuclei missing, it takes about 70 seconds.
The report lands in `runs/<id>/report.md`,
which is gitignored like any other run.

## What is listening

Everything binds `127.0.0.2`. Linux routes all of `127.0.0.0/8` to `lo`, so no
setup is needed there. The scope is that single address, so nothing else
running on your machine shows up in the results.

| Port | Imitates | nmap identifies it as | What extscan should report |
|---|---|---|---|
| 2222/tcp | OpenSSH 7.4 banner | `ssh OpenSSH 7.4` | SSH exposure review, vulners candidates |
| 2375/tcp | Docker remote API, no auth | `docker Docker remote API` | **critical** Docker API (plaintext) exposure |
| 3306/tcp | MySQL 5.7.33 handshake | `mysql MySQL 5.7.33-log` | **high** database exposed |
| 6379/tcp | Redis 5.0.7, no `requirepass` | `redis Redis key-value store 5.0.7` | **critical** Redis exposure, `redis-info` |
| 8080/tcp | Billing app (`targetapp.py`) | `http nginx 1.18.0` | `.env` with redacted secrets, Swagger spec with unauthenticated writes, GraphQL introspection, `/metrics`, soft-404 handling, a confirmed-open `/api/admin/users` |
| 8081/tcp | IIS 8.5 / ASP.NET | `http Microsoft IIS httpd 8.5` | `trace.axd`, `elmah.axd`, WebDAV write verbs, 8.3 short-name oracle, verbose error page |
| 8443/tcp | Billing app over TLS | `ssl/http nginx 1.18.0` | Same as 8080, plus a self-signed certificate |
| 9200/tcp | Elasticsearch 6.8.0 | `http Elasticsearch REST API 6.8.0` | **critical** Elasticsearch exposure |
| 10161/udp | SNMP agent, community `public` | `snmp` (needs a UDP scan) | **SNMP readable with `public`**, interface walk |

On the last full run with nuclei working, this produced 5 critical, 20 high,
14 medium and 8 low findings, with 42 items in the manual review queue.
nuclei flags "Apache RocketMQ Broker - Unauthenticated Access" on 2375 and
9200. That's a false positive caused by the lab's fake listeners, which
answer the template's raw TCP probe. A real Docker or Elasticsearch
wouldn't.

The 8443 copy of the billing app serves the same OpenAPI document as 8080, and
its `servers` entry points at `http://127.0.0.2:8080/api`. That's deliberate:
its `api_endpoint` follow-ups land on 8080, which exercises extscan following a
spec's `servers` block, still within scope. The second `servers` entry,
`internal-billing.corp.acme.example`, shows up as an out-of-scope reference
and is never requested.

## UDP and SNMP

nmap needs root for `-sU`. Run unprivileged, extscan prints this before
discovery starts, and records a **serious** coverage gap:

```
Not running as root: this run is TCP only.
  Re-run as root to add UDP: sudo extscan discover <run> --udp-only
```

Run that command to cover SNMP, then re-run the later stages as yourself.
The UDP pass clears the gap:

```bash
sudo .venv/bin/extscan discover <run> --udp-only
uv run extscan probe latest && uv run extscan chase latest && uv run extscan report latest
```

Use the venv's `extscan` under sudo. root's `PATH` usually has neither `uv`
nor the project's entry point.

The SNMP probe matches port 10161 (SNMP over TLS's registered port), so the
lab doesn't need root to bind 161. You can check the agent directly without
nmap:

```bash
uv run python -c "from extscan.policy import Policy; from extscan.tools import snmp; \
print(snmp.check_community_strings('127.0.0.2', Policy(), port=10161)[2])"
# ['public']
```

## The lab policy

`examples/lab/policy.json` narrows the standard settings to what a loopback
target needs:

- **Ports**: only the lab's, so discovery takes about a minute instead of
  sweeping `TCP_TOP`.
- **Scripts**: `default,safe`, minus the `nmap.exclude_scripts` default that
  every policy gets (`dos`, `external`, `http-slowloris-check`). No `vuln`
  category, which keeps the run short. Add it back to test the production
  script set.

`examples/lab/scope.json` sets `allow_private: true` (loopback is refused
otherwise) and a wide testing window. Don't copy either setting into a real
engagement scope.

## Things the lab surfaced

Building the lab turned up four problems, all fixed since:

- **`http-slowloris-check` ran by default.** NSE puts it in `vuln,safe`, not
  `dos`. It holds connections open against servers that don't time out
  partial requests, and stretched the lab's TCP stage from 1 minute to 10.
- **`vulners` and `dns-blacklist` ran by default.** Both are in `external`
  and send target details to third parties. All three are now excluded by
  `nmap.exclude_scripts`.
- **nuclei tested default credentials.** Once nuclei could run, the
  default policy loaded 274 `default-login` templates, which submit
  passwords to discovered services. `default-login`, `default-logins` and
  `creds-stuffing` are now in `nuclei.exclude_tags`.
- **A nuclei crash looked like a clean result.** A killed nuclei is now a
  serious coverage gap, and the web services stay unmarked so
  `extscan probe <run> --only nuclei` retries them.

## Troubleshooting

**`OSError: [Errno 98] Address already in use`**: a lab is already running,
or something else holds one of the ports on `127.0.0.2`. `ss -ltnup | grep
127.0.0.2` shows what. You can also bind a different loopback address with
`--host 127.0.0.5`, then change `targets` in a copy of the scope to match.

**macOS**: only `127.0.0.1` is configured on `lo0` by default. Add the alias
first with `sudo ifconfig lo0 alias 127.0.0.2 up`.

**Gap `nuclei killed by SIGKILL`**: something outside extscan killed nuclei.
Check with `nuclei -u http://127.0.0.2:8080 -t ~/nuclei-templates/http/`.
On the workstation where the lab was built, an EDR agent (Elastic Defend)
killed nuclei about 0.9s into loading the `http/` or `javascript/`
templates, whatever the target, including inside Docker. Uninstalling the
agent fixed it. A reinstall or a venv won't help, because the EDR judges
the process, not how it was installed. Until the cause is gone, extscan's
own probes still run, and the report says the nuclei findings are missing.

**A port shows as `tcpwrapped` or `?`**: nmap identifies these listeners by
exact byte patterns, so changing a handler's headers or JSON layout can break
identification. Check with `nmap -sT -sV -Pn -p <port> 127.0.0.2`, and compare
the `SF-Port` fingerprint against the `match` lines in
`/usr/share/nmap/nmap-service-probes`.

## Tests

`tests/test_lab.py` starts the lab on `127.0.0.3`, so it doesn't collide with
a lab you have running. It checks that every listener answers as expected,
including that an idle TLS client can't stall the HTTPS port. It runs as part
of the normal suite.
