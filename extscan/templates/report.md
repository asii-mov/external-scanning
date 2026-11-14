<!--#
  The layout of report.md. Copy this file, edit the copy, and point extscan
  at it with `--template FILE` or `"report": {"template": "FILE"}` in the
  policy. `extscan template --check FILE` tests a copy without a scan.

  You can reorder sections, retitle or delete headings, add your own text,
  and change how one finding is laid out. docs/REPORT_TEMPLATE.md lists
  every name that can go between {{ and }}.

  Two sections have to stay somewhere in the file: {{coverage_gaps}} and
  {{review_queue}}. Notes like this one never reach the report.
-->
# External attack surface assessment: {{engagement}}

**Client:** {{client}}  
**Report generated:** {{generated}}  
**Run id:** `{{run_id}}`  
**Tooling:** extscan {{version}}, profile `{{profile}}`

## Authorisation

{{authorisation}}

### Scope

{{scope}}

## Summary

{{summary}}

## Manual review queue

{{review_queue}}

## Notes for the security team

{{security_notes}}

<!-- if systemic -->
## Systemic issues

{{systemic}}

<!-- end -->
## Findings

<!-- if not findings -->
_No findings were recorded._

<!-- end -->
<!-- each group in severities -->
### {{group.label}} ({{group.count}})

<!-- each finding in group.findings -->
#### {{finding.number}}. {{finding.title}}

- **Severity:** {{finding.severity_label}}<!-- if finding.tentative -->  (tentative -- needs confirmation)<!-- end -->
- **Affected:** `{{finding.target}}`
- **Detected by:** `{{finding.source}}`
- **Finding id:** `{{finding.id}}`
<!-- if finding.tags -->
- **Tags:** {{finding.tags}}
<!-- end -->
<!-- if finding.exploitation -->
{{finding.exploitation}}
<!-- end -->

<!-- if finding.description -->
{{finding.description}}

<!-- end -->
<!-- if finding.review_required -->
> **Requires manual review.** {{finding.review_reason}}

<!-- end -->
<!-- if finding.evidence -->
**Evidence**

{{finding.evidence}}

<!-- end -->
<!-- if finding.recommendation -->
**Recommendation**

{{finding.recommendation}}

<!-- end -->
<!-- if finding.references -->
**References**

{{finding.references}}

<!-- end -->
<!-- end -->
<!-- end -->
## Service inventory

{{inventory}}

<!-- if host_detail -->
### Host detail

{{host_detail}}

<!-- end -->
<!-- if coverage_gaps -->
## Coverage gaps

{{coverage_gaps}}

<!-- end -->
## Methodology and limitations

{{methodology}}

<!-- if tool_versions -->
### Tool versions

{{tool_versions}}

<!-- end -->
<!-- if command_log -->
### Command log

{{command_log}}
<!-- end -->
