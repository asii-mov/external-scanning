# TODO

## Improve reporting

Make the report read as a pentest narrative, not a findings dump. It should
tell the story in the order the work happened: "We scanned 203.0.113.0/27
and found 3 web services (screenshots below). Port 161/udp answered to the
community string `public`:" followed by the proof block, and so on.

Done: `extscan report` writes `runs/<run-id>/report/` (see `extscan/vault.py`),
and `extscan screenshot` captures web services (`extscan/screenshots.py`).
The notes below are kept as the spec it was built to.

### What existed before

- Each scan already gets its own folder, `runs/<run-id>/`, holding
  `report.md`, `report.json`, raw tool output in `raw/`, and the command
  log in `commands.jsonl`.
- `extscan/report.py` (`render_markdown`) writes one flat `report.md`,
  grouped by severity.
- Screenshots didn't exist. They were item 1 in `docs/ROADMAP.md`.

### Wanted

- [x] **Obsidian vault per scan.** Write `runs/<run-id>/report/` as a
      folder of linked notes, which opens directly as an Obsidian vault:
  - `00 Summary.md` is the narrative and the entry point.
  - Each host gets a note (`hosts/203.0.113.10.md`) listing its services
    and findings.
  - Each finding gets a note (`findings/<id>.md`) with evidence,
    reproduction and remediation.
  - Coverage gaps and the manual review queue each get a note.
  - Use `[[wikilinks]]` between notes, YAML frontmatter (severity, host,
    port, tags) so Dataview queries work, and `attachments/` for images.
- [x] **Screenshots of every web service**, embedded in the narrative and
      host notes (`![[attachments/203.0.113.10-443.png]]`).
  - Use headless Chromium (Playwright) or `gowitness`, as an optional extra
    like `extscan[llm]`. A missing browser is a coverage gap, not a failure.
  - Capture the root page plus pages that produced findings (Swagger UI,
    admin panels). Pages holding secrets (`.env`, `trace.axd`) are not
    captured: an image cannot be redacted.
  - Every capture goes through `scope.assert_url`, like any other request.
    Follow no redirects off scope.
  - Keep images out of `report.json`.
- [x] **Narrative ordering.** Build the story from stage timestamps in
      `run.json` and `commands.jsonl`: scope and authorisation, discovery
      (what was open), each service family in turn, follow-ups (chase), then
      what was not covered.
- [x] **Proof blocks.** Each finding in the narrative carries a fenced proof
      excerpt:
  - SNMP: the community string that worked and the `sysDescr` it returned.
  - HTTP: the request line and response status, with headers trimmed.
  - Secrets: key names only. Values stay redacted, as the current report
    already does.
  - Non-default SNMP community strings are credentials. Redact them like
    secrets, and keep known defaults such as `public` visible.
- [x] **Keep the auditor view.** The manual review queue and coverage gaps
      stay near the top. The narrative must not bury "this was never checked".
- [x] **Tests.** Render a vault from the lab (`tests/lab.py`) run fixtures,
      check that every wikilink resolves to a note, and check that every
      finding and gap appears.
