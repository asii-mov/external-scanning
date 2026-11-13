"""Find web services that nmap could not name.

`Service.is_http` trusts nmap's service name or a short list of ports. An
application on an odd port that nmap labels `unknown` or `tcpwrapped` (its
probes got nothing they recognised) therefore gets no HTTP probe, no nuclei
and no screenshot, and nothing says so.

For each such TCP service this asks the cheapest possible question: a TLS
handshake, then one `GET /` (inside TLS if the handshake worked, in the clear
otherwise). A service that answers HTTP is relabelled the way nmap would have
labelled it, so everything downstream treats it as a web service in the same
`probe` run. Services nmap did identify (SSH, databases, mail) are left alone:
a GET sent to those is noise in the client's logs and tells us nothing.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from extscan.models import WEB_IDENTIFY_KEY, Service
from extscan.policy import Policy
from extscan.resilience import Degradation
from extscan.scope import Scope
from extscan.store import Store
from extscan.tools import net

# Recorded in `Service.probed_by`, like a probe name, so a second run does not
# ask again. `extscan probe --only web_identify` runs this step alone.
MARK = "web_identify"
STAGE = f"probe:{MARK}"

_UNNAMED = {"", "unknown", "tcpwrapped"}


def needs_identifying(svc: Service) -> bool:
    """Open TCP, not already web, and nmap did not say what it is."""
    if svc.proto != "tcp" or svc.state != "open" or svc.is_http:
        return False
    name = svc.name.strip().lower()
    return name in _UNNAMED or name.endswith("?")


class NotReached(Exception):
    """The port could not be asked at all, which is a gap, not a 'no'."""


def identify(svc: Service, scope: Scope, policy: Policy) -> tuple[str, net.Response | None]:
    """What the port speaks: "https", "http", "tls" (TLS, not HTTP) or "none".

    At most two connections. Raises `NotReached` when the port refuses the
    connection or the address is out of scope: nmap saw it open, so no answer
    here means we do not know, and the caller records that.
    """
    over_tls = net.request_at(svc.host, svc.port, scope, policy.http, tls=True)
    if over_tls.failed_at in ("scope", "connect"):
        raise NotReached(over_tls.error)
    if over_tls.status:
        return "https", over_tls
    if over_tls.failed_at == "http":
        return "tls", None            # handshake fine, but no HTTP inside it

    plain = net.request_at(svc.host, svc.port, scope, policy.http, tls=False)
    if plain.failed_at in ("scope", "connect"):
        raise NotReached(plain.error)
    return ("http", plain) if plain.status else ("none", None)


def _banner(text: str) -> str:
    return "".join(c for c in text if c.isprintable())[:100].strip()


def apply(svc: Service, verdict: str, resp: net.Response | None) -> None:
    """Relabel a service in place, the way nmap reports the same thing."""
    if verdict == "none":
        return
    was = _banner(svc.name) or "no service name"
    svc.scripts[WEB_IDENTIFY_KEY] = verdict
    svc.tunnel = "ssl" if verdict in ("https", "tls") else ""
    if verdict in ("http", "https"):
        svc.name = "http"
        if resp is not None and not svc.product:
            svc.product = _banner(resp.headers.get("server", ""))
    note = f"identified by extscan (nmap reported {was})"
    svc.extrainfo = f"{svc.extrainfo}; {note}" if svc.extrainfo else note


def run(store: Store, scope: Scope, policy: Policy, services: list[Service], *,
        dry_run: bool = False, only: list[str] | None = None,
        force: bool = False) -> dict:
    """Identify unnamed services, updating `services` in place and on disk.

    Called at the top of the probe stage, before nuclei and the per-service
    probes choose their targets.
    """
    if only is not None and MARK not in only:
        return {"identified": 0}
    todo = [s for s in services if needs_identifying(s) and (force or MARK not in s.probed_by)]
    if not todo:
        return {"identified": 0}

    if dry_run:
        for svc in todo:
            print(f"  [dry-run] would try TLS then GET / on {svc.id} "
                  f"(nmap: {svc.name or 'no service name'})")
        return {"identified": 0, "planned": len(todo), "dry_run": True}

    print(f"→ identifying {len(todo)} service(s) nmap could not name")
    done: list[Service] = []
    identified = 0
    with ThreadPoolExecutor(max_workers=max(1, policy.max_workers)) as pool:
        futures = {pool.submit(identify, svc, scope, policy): svc for svc in todo}
        for fut in as_completed(futures):
            svc = futures[fut]
            prefix = f"{svc.id}: "
            store.remove_degradations(
                lambda d, prefix=prefix: d.stage == STAGE and d.reason.startswith(prefix))
            try:
                verdict, resp = fut.result()
            except Exception as exc:
                deg = Degradation(
                    stage=STAGE, component=MARK,
                    reason=f"{prefix}{type(exc).__name__}: {exc}"[:300],
                    impact=f"nmap could not name the service on {svc.id} and extscan "
                           "could not ask it either, so if it is a web application it "
                           "has had no HTTP checks, no nuclei and no screenshot.",
                    hosts=[svc.host],
                    remedy=f"Check the port by hand, then `extscan probe <run> --only {MARK}`.",
                )
                store.add_degradation(deg)
                print(f"  ! {deg.reason}")
                print(f"    {deg.impact}")
                continue
            apply(svc, verdict, resp)
            if MARK not in svc.probed_by:
                svc.probed_by.append(MARK)
            done.append(svc)
            if verdict != "none":
                identified += 1
                print(f"  {svc.id}: {verdict}")

    if done:
        store.save_services(done)
    return {"identified": identified, "asked": len(todo)}
