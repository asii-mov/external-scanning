# Changing the report layout

`report.md` is built from a Markdown template. The built-in one is
`extscan/templates/report.md`. To change the layout, edit a copy:

```bash
extscan template --out our-report.md          # write a copy of the built-in template
$EDITOR our-report.md
extscan template --check our-report.md        # test it without running a scan
extscan report latest --template our-report.md
```

To use it on every run, name it in the policy file. The path is stored with
the run, so `extscan report` and `extscan resume` keep using it:

```json
{"report": {"template": "our-report.md"}}
```

`--template` on `run`, `init`, `resume` and `report` overrides the policy.
The report's methodology section says which template produced it, with a
hash of the file.

The template controls `report.md` only. `report.json` and the Obsidian vault
in `report/` keep their fixed structure.

## What you can change

- The order of sections, and their headings.
- Which sections appear, apart from the two listed under "What has to stay".
- Your own text anywhere: a confidentiality notice, a contact, a ticket link.
- How one finding is laid out, and whether findings are grouped by severity.

## The three constructs

```markdown
{{summary}}                      a value

<!-- if systemic -->             kept only when the value is not empty
## Systemic issues
{{systemic}}
<!-- end -->

<!-- if not findings -->         kept only when the value is empty
No findings.
<!-- end -->

<!-- each f in findings -->      repeated for every item of a list
- {{f.title}} ({{f.target}})
<!-- end -->

<!--# a note for whoever edits the template; it never reaches the report -->
```

An `if`, `each` or `end` line that stands alone leaves no blank line behind.
Runs of blank lines are collapsed to one, except inside code fences.

Text from a scan is inserted as it is and is never read as template syntax,
so a page title containing `{{...}}` stays literal.

## What has to stay

`{{coverage_gaps}}` and `{{review_queue}}` must appear somewhere. Move them
and retitle them freely. A template without them is refused, because the
report would then read as a clean result when checks did not run or a
decision is still open.

## Mistakes are errors

A name that does not exist, an unclosed block or a missing required section
stops with a message that gives the file and line. `extscan run` and
`extscan init` check the template before anything is scanned. If
`extscan report` fails on a template, the previous `report.md` is left as it
was.

## Values

One line each:

| Name | What it holds |
|---|---|
| `{{engagement}}` | The engagement name from the scope file |
| `{{client}}` | The client name from the scope file, or `n/a` |
| `{{generated}}` | When the report was rendered, in UTC |
| `{{run_id}}` | The run id |
| `{{version}}` | The extscan version that created the run |
| `{{profile}}` | The scan profile: quick, standard or thorough |
| `{{findings_total}}` | Number of findings |
| `{{gap_count}}` | Number of coverage gaps |

Ready-made sections. Each is Markdown without a heading, so the heading is
yours to write. The ones marked "may be empty" are worth wrapping in an `if`:

| Name | What it holds |
|---|---|
| `{{authorisation}}` | Reference, who authorised, testing window, constraints |
| `{{scope}}` | Targets and exclusions |
| `{{summary}}` | Counts by severity, and a warning when there are coverage gaps |
| `{{review_queue}}` | Required. The items a person has to decide, in order, each with its question |
| `{{security_notes}}` | Where to look next: follow-ups the scanner did not finish, assets seen outside the scope file, findings inferred from a version or a specification, analyst and model notes |
| `{{systemic}}` | Issues on three or more hosts. May be empty |
| `{{inventory}}` | Table of open services and the checks run on each |
| `{{host_detail}}` | Host names, OS guess, CDN or cloud network. May be empty |
| `{{coverage_gaps}}` | Required. What was not checked, why, and the remedy. Empty when there are no gaps |
| `{{methodology}}` | Stages run, warnings, limitations, data feeds, model use, the template used |
| `{{tool_versions}}` | Versions of nmap, nuclei and openssl. May be empty |
| `{{command_log}}` | The first 60 commands run, in a code block. May be empty |

## Lists

`findings` is every finding, most severe first. `severities` is the same
findings grouped: one item per severity that has findings, most severe
first. Use one or the other:

```markdown
<!-- each group in severities -->
### {{group.label}} ({{group.count}})
<!-- each finding in group.findings -->
#### {{finding.number}}. {{finding.title}}
<!-- end -->
<!-- end -->
```

The names `group`, `finding` and `f` above are yours to choose; the field
names are fixed.

Fields of a severity group:

| Name | What it holds |
|---|---|
| `{{group.key}}` | `critical`, `high`, `medium`, `low` or `info` |
| `{{group.label}}` | `Critical`, `High`, `Medium`, `Low` or `Informational` |
| `{{group.count}}` | Number of findings at this severity |

`group.findings` is the list of findings at that severity.

Fields of a finding:

| Name | What it holds |
|---|---|
| `{{finding.number}}` | Position in the report, counting from 1 |
| `{{finding.id}}` | Stable id, as used by `extscan show --finding` |
| `{{finding.title}}` | Title |
| `{{finding.severity}}` | `critical`, `high`, `medium`, `low` or `info` |
| `{{finding.severity_label}}` | The same, as shown to readers |
| `{{finding.confidence}}` | `firm` or `tentative` |
| `{{finding.tentative}}` | Set when the finding is inferred, not observed. For `if` |
| `{{finding.target}}` | `host:port/proto`, or the host |
| `{{finding.host}}` | Host address |
| `{{finding.port}}` | Port, or empty |
| `{{finding.proto}}` | `tcp` or `udp` |
| `{{finding.source}}` | The tool or check that raised it |
| `{{finding.tags}}` | Tags, formatted as code. May be empty |
| `{{finding.exploitation}}` | CVE, KEV and EPSS lines as a list. May be empty |
| `{{finding.description}}` | Description. May be empty |
| `{{finding.review_required}}` | Set when a person has to judge it. For `if` |
| `{{finding.review_reason}}` | The question for the reviewer. May be empty |
| `{{finding.evidence}}` | Evidence in a code block. May be empty |
| `{{finding.recommendation}}` | Recommendation. May be empty |
| `{{finding.references}}` | References as a list. May be empty |
