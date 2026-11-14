"""A small template language for the Markdown report.

The report's layout lives in a Markdown file (`extscan/templates/report.md`
by default) so a team can reorder sections, rename headings, add its own
boilerplate or change how one finding is laid out, without touching Python.

Three constructs, all of which read as plain Markdown in an editor:

    {{name}}  {{finding.title}}        a value, by dotted name

    <!-- if name -->  ...  <!-- end -->          kept when the value is not empty
    <!-- if not name -->  ...  <!-- end -->      kept when it is empty

    <!-- each finding in findings -->  ...  <!-- end -->     once per item

    <!--# a note to whoever edits the template; never reaches the report -->

Values are substituted once and never re-read as template text, so a page
title containing `{{...}}` or an HTML comment stays literal text.

Mistakes are errors, not blanks. A name the report does not provide, an
unclosed block or a stray `end` raises `TemplateError`, and `check` finds
them before a scan starts rather than after it has finished.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


class TemplateError(ValueError):
    """The report template is malformed, or asks for something that does not exist."""


_NAME = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
_TOKEN_RE = re.compile(
    r"\{\{\s*(?P<var>[^{}]*?)\s*\}\}"
    r"|<!--#(?P<note>.*?)-->"
    r"|<!--\s*(?P<kw>if|each|end)\b(?P<arg>.*?)-->",
    re.S,
)
_NAME_RE = re.compile(_NAME)
_IF_RE = re.compile(rf"\s*(?P<neg>not\s+)?(?P<name>{_NAME})\s*")
_EACH_RE = re.compile(rf"\s*(?P<item>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+(?P<name>{_NAME})\s*")


@dataclass
class _Text:
    text: str


@dataclass
class _Var:
    name: str
    line: int


@dataclass
class _If:
    name: str
    negate: bool
    line: int
    body: list = field(default_factory=list)


@dataclass
class _Each:
    item: str
    name: str
    line: int
    body: list = field(default_factory=list)


def _own_line(text: str, start: int, end: int) -> tuple[int, int]:
    """Widen a control tag to its whole line when nothing else is on it, so
    the tag leaves no blank line behind."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    if text[line_start:start].strip() or text[end:line_end].strip():
        return start, end
    return line_start, min(line_end + 1, len(text))


def parse(text: str, source: str = "template") -> list:
    """Parse template text into nodes. Raises TemplateError on bad syntax."""
    root: list = []
    stack: list[tuple[list, _If | _Each | None]] = [(root, None)]
    pos = 0
    for m in _TOKEN_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        start, end = m.start(), m.end()
        if m.group("var") is None:
            start, end = _own_line(text, start, end)
        if start > pos:
            stack[-1][0].append(_Text(text[pos:start]))
        pos = max(pos, end)

        if m.group("var") is not None:
            name = m.group("var")
            if not _NAME_RE.fullmatch(name):
                raise TemplateError(f"{source}:{line}: {m.group(0)!r} is not a name such "
                                    "as {{summary}} or {{finding.title}}")
            stack[-1][0].append(_Var(name, line))
        elif m.group("note") is not None:
            continue
        elif m.group("kw") == "if":
            parsed = _IF_RE.fullmatch(m.group("arg"))
            if not parsed:
                raise TemplateError(f"{source}:{line}: write `<!-- if name -->` or "
                                    "`<!-- if not name -->`")
            node = _If(parsed.group("name"), bool(parsed.group("neg")), line)
            stack[-1][0].append(node)
            stack.append((node.body, node))
        elif m.group("kw") == "each":
            parsed = _EACH_RE.fullmatch(m.group("arg"))
            if not parsed:
                raise TemplateError(f"{source}:{line}: write `<!-- each item in list -->`")
            node = _Each(parsed.group("item"), parsed.group("name"), line)
            stack[-1][0].append(node)
            stack.append((node.body, node))
        else:
            if m.group("arg").strip():
                raise TemplateError(f"{source}:{line}: `<!-- end -->` takes no argument")
            if len(stack) == 1:
                raise TemplateError(f"{source}:{line}: `<!-- end -->` closes nothing")
            stack.pop()
    if len(stack) > 1:
        opened = stack[-1][1]
        kind = "if" if isinstance(opened, _If) else "each"
        where = opened.line if opened is not None else 0
        raise TemplateError(f"{source}:{where}: `<!-- {kind} ... -->` is never closed "
                            "with `<!-- end -->`")
    if pos < len(text):
        root.append(_Text(text[pos:]))
    return root


def names(nodes: list) -> set[str]:
    """Every dotted name the template refers to."""
    out: set[str] = set()
    for node in nodes:
        if isinstance(node, _Var):
            out.add(node.name)
        elif isinstance(node, (_If, _Each)):
            out.add(node.name)
            out |= names(node.body)
    return out


def _lookup(name: str, scopes: list[dict], line: int, source: str):
    head, *rest = name.split(".")
    for scope in reversed(scopes):
        if head in scope:
            value = scope[head]
            break
    else:
        known = sorted({k for s in scopes for k in s})
        raise TemplateError(f"{source}:{line}: the report has no value named {head!r}. "
                            f"Available here: {', '.join(known)}")
    for part in rest:
        if not isinstance(value, dict) or part not in value:
            fields = sorted(value) if isinstance(value, dict) else []
            raise TemplateError(
                f"{source}:{line}: {name!r} does not exist"
                + (f". Fields: {', '.join(fields)}" if fields else ""))
        value = value[part]
    return value


def _show(value) -> str:
    if value is None or value is False:
        return ""
    if value is True:
        return "yes"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _render(nodes: list, scopes: list[dict], out: list[str], checking: bool,
            source: str) -> None:
    for node in nodes:
        if isinstance(node, _Text):
            out.append(node.text)
        elif isinstance(node, _Var):
            value = _lookup(node.name, scopes, node.line, source)
            if isinstance(value, dict):
                raise TemplateError(f"{source}:{node.line}: {node.name!r} is a group of "
                                    f"fields ({', '.join(sorted(value))}); name one of them")
            out.append(_show(value))
        elif isinstance(node, _If):
            value = _lookup(node.name, scopes, node.line, source)
            if checking or bool(value) != node.negate:
                _render(node.body, scopes, out, checking, source)
        else:
            value = _lookup(node.name, scopes, node.line, source)
            if not isinstance(value, list):
                raise TemplateError(f"{source}:{node.line}: {node.name!r} is not a list, "
                                    "so `each` cannot repeat over it")
            for item in value:
                _render(node.body, [*scopes, {node.item: item}], out, checking, source)


def _squeeze(text: str) -> str:
    """Collapse runs of blank lines left by empty sections. Fenced blocks
    (evidence, command logs) are left exactly as they are."""
    out: list[str] = []
    fenced = False
    blank = 0
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if not fenced and not line.strip():
            blank += 1
            if blank > 1:
                continue
        else:
            blank = 0
        out.append(line)
    return "\n".join(out).strip("\n") + "\n"


def render(nodes: list, context: dict, source: str = "template") -> str:
    out: list[str] = []
    _render(nodes, [context], out, False, source)
    return _squeeze("".join(out))


def check(nodes: list, sample: dict, source: str = "template") -> None:
    """Walk every branch of the template against `sample`, a context whose
    lists each hold one item. Raises TemplateError for any name that the
    report would not be able to fill in."""
    _render(nodes, [sample], [], True, source)
