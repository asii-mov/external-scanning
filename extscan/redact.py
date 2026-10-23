"""Redaction for everything that leaves the run directory as a report.

Run state (`findings.json`, `raw/`) keeps what the tools returned, so a
finding can be re-checked. Reports are copied into tickets and mailboxes, so
they prove a credential is exposed without carrying it:

- secret-looking `KEY=value` lines keep the key and lose the value, whatever
  produced them (nuclei captures full response bodies);
- credentials embedded in URLs, cookie values and session ids are dropped;
- SNMP community strings that are not well-known defaults are credentials
  the client chose, so they are redacted everywhere they appear. Defaults
  such as `public` stay visible, because naming them is the finding.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable

from .models import Finding, Lead
from .tools.snmp import WELL_KNOWN

# `KEY=value` or `key: value` at the start of a line, where some `_`/`-`/`.`
# separated part of the key names a secret. Matching parts rather than
# substrings keeps `content-security-policy` (sec-URI-ty) visible.
_KV_RE = re.compile(r"(?m)^([A-Za-z0-9_.\-]{1,80})[ \t]*[=:][ \t]*(\S.*)$")
_SECRET_PARTS = {"key", "token", "secret", "pass", "passwd", "password", "pwd", "credential",
                 "credentials", "dsn", "uri", "url", "conn", "auth", "apikey", "privatekey"}
_SECRET_SUFFIXES = ("apikey", "accesskey", "secretkey", "privatekey", "authtoken",
                    "accesstoken", "secret", "password", "passwd")
_URL_CRED_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9+.\-]*://[^:/\s@]+:)[^@/\s]{3,}(@)")
_COOKIE_RE = re.compile(r"(?im)^((?:set-)?cookie:\s*[^=;\s]+=)[^;\r\n]+")
_SESSION_RE = re.compile(
    r"(?i)\b((?:asp\.net_)?session_?id|jsessionid|phpsessid|connect\.sid)=([^;&\s<\"']{4,})")
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/\-]{12,}={0,2}")


def secret_communities(findings: Iterable[Finding], leads: Iterable[Lead] = ()) -> set[str]:
    """Community strings that worked and are not published defaults."""
    found: set[str] = set()
    for f in findings:
        for tag in f.tags:
            if tag.startswith("community:"):
                found.add(tag.split(":", 1)[1])
    for ld in leads:
        if ld.kind == "snmp_walk" and ld.params.get("community"):
            found.add(str(ld.params["community"]))
    return {c for c in found if c and c.lower() not in WELL_KNOWN}


def _is_secret_key(key: str) -> bool:
    parts = [p for p in re.split(r"[_.\-]+", key.lower()) if p]
    if len(parts) == 1 and parts[0] in ("url", "uri", "auth"):
        return False          # a bare `url:` line in evidence is where we fetched from
    return any(p in _SECRET_PARTS or p.endswith(_SECRET_SUFFIXES) for p in parts)


def redact_text(text: str, communities: Iterable[str] = ()) -> str:
    if not text:
        return text

    def kv(m: re.Match) -> str:
        key, value = m.group(1), m.group(2).strip()
        if value.startswith("<redacted") or not _is_secret_key(key):
            return m.group(0)
        return f"{key}=<redacted, {len(value)} chars>"

    out = _KV_RE.sub(kv, text)
    out = _URL_CRED_RE.sub(r"\1<redacted>\2", out)
    out = _COOKIE_RE.sub(r"\1<redacted>", out)
    out = _BEARER_RE.sub(r"\1<redacted>", out)
    out = _SESSION_RE.sub(r"\1=<redacted>", out)
    # Longest first, so a community that contains another is replaced whole.
    for c in sorted(set(communities), key=len, reverse=True):
        out = out.replace(c, f"<redacted community, {len(c)} chars>")
    return out


def scrub_finding(f: Finding, communities: Iterable[str] = ()) -> Finding:
    communities = list(communities)

    def r(s: str) -> str:
        return redact_text(s, communities)

    tags = []
    for t in f.tags:
        if t.startswith("community:") and t.split(":", 1)[1] in communities:
            tags.append("community:<redacted>")
        else:
            tags.append(t)
    return dataclasses.replace(
        f, title=r(f.title), description=r(f.description), evidence=r(f.evidence),
        review_reason=r(f.review_reason), recommendation=r(f.recommendation), tags=tags,
    )


def scrub_lead(ld: Lead, communities: Iterable[str] = ()) -> Lead:
    communities = list(communities)
    params = {k: ("<redacted>" if k == "community" and str(v) in communities else v)
              for k, v in ld.params.items()}
    return dataclasses.replace(
        ld, note=redact_text(ld.note, communities), reason=redact_text(ld.reason, communities),
        url=redact_text(ld.url, communities), params=params,
    )
