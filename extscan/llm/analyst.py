"""Where model output becomes a finding -- and where it is kept in its place.

Everything here follows the same pattern:

* the deterministic finding is produced first and stands on its own;
* the model's commentary is attached as a *separate* finding, sourced to
  `llm-analysis`, marked tentative and flagged for review;
* the model's severity opinion never overrides the probe's grading. It is
  reported as an opinion, and only ever as a reason for a human to look.

So a run with no model loses commentary and loses nothing else. That is the
property that makes the feature safe to depend on, because it is the property
that means nothing depends on it.
"""

from __future__ import annotations

from extscan.models import Finding

from .base import Analysis

# A visible marker on every model-derived finding. An auditor skimming a report
# must be able to tell at a glance which sentences a machine wrote about
# attacker-supplied input.
LLM_SOURCE = "llm-analysis"


def _provenance(analysis: Analysis) -> str:
    return (f"Written by {analysis.model or 'a language model'} via "
            f"{analysis.provider or 'an API'}"
            + (", from truncated evidence" if analysis.input_truncated else "")
            + ".")


def analysis_to_finding(
    analysis: Analysis,
    *,
    host: str,
    port: int | None,
    proto: str = "tcp",
    subject: str,
    deterministic_severity: str,
    tags: list[str] | None = None,
) -> Finding:
    """Turn a model's assessment into a clearly-labelled, review-flagged finding.

    Severity is pinned to `info` regardless of what the model thought. Its
    opinion is reported inside the text, where a human weighs it, rather than
    driving the report's own risk ordering -- a model that is wrong about
    severity should not be able to move an item up the remediation queue.
    """
    opinion = analysis.severity_opinion or "no opinion"
    disagrees = (analysis.severity_opinion
                 and analysis.severity_opinion != deterministic_severity)

    body = [analysis.summary.strip()] if analysis.summary else []
    if analysis.reasoning:
        body.append(f"**Reasoning given:** {analysis.reasoning.strip()}")
    body.append(
        f"**Model's severity opinion:** {opinion} "
        f"(the scanner graded the underlying finding `{deterministic_severity}`"
        + ("; the two disagree, which is itself worth a look" if disagrees else "")
        + ")."
    )
    if analysis.suggested_followups:
        body.append("**Further read-only checks it suggested:**\n"
                    + "\n".join(f"- {item}" for item in analysis.suggested_followups))

    questions = analysis.questions_for_auditor or [
        "Confirm whether this commentary matches the evidence."
    ]

    return Finding(
        title=f"Model analysis: {subject}",
        severity="info",
        host=host, port=port, proto=proto,
        source=LLM_SOURCE,
        description="\n\n".join(body),
        evidence=_provenance(analysis),
        review_required=True,
        review_reason=(
            "Machine-written commentary on attacker-supplied input, not an "
            "observation. Verify it against the evidence before any of it reaches "
            "the client. Questions it raised: "
            + "; ".join(questions)
        ),
        confidence="tentative",
        tags=[*(tags or []), "llm", "needs-verification"],
    )


def unavailable_finding(*, host: str, port: int | None, subject: str,
                        reason: str, proto: str = "tcp") -> Finding:
    """Record that analysis was wanted here and could not be done.

    The point of writing this down: a report where the model worked for forty
    findings and silently failed on the forty-first is a report that quietly
    under-describes one thing. Naming the omission turns it into a review item.
    """
    return Finding(
        title=f"Model analysis unavailable: {subject}",
        severity="info",
        host=host, port=port, proto=proto,
        source=LLM_SOURCE,
        description=(
            "Model-assisted analysis was configured for this item but could not be "
            "completed, so this finding carries only its deterministic evidence. "
            "That evidence is unaffected; what is missing is the commentary."
        ),
        evidence=f"reason: {reason}",
        review_required=True,
        review_reason="Read this item's evidence by hand -- the assisted pass that "
                      "would normally summarise it did not run.",
        confidence="firm",
        tags=["llm", "coverage-gap"],
    )


# ---------------------------------------------------------------------------
# Analyses
# ---------------------------------------------------------------------------

OPENAPI_QUESTION = """\
An external scan found this API specification published without authentication.

Assess what it discloses about the client's attack surface. Concentrate on:
- operations that appear to need no authentication, especially ones that modify \
state, and which of those would matter most if genuinely open;
- parameters or schemas that hint at sensitive data or administrative reach;
- whether the surface suggests internal-only functionality has been exposed.

The scanner already enumerated the operations deterministically and did not \
call any of them. Do not assume the specification reflects enforcement: a \
gateway in front of the API may require authentication that the spec omits."""


def analyse_openapi(client, *, host: str, port: int | None, spec_url: str,
                    spec_text: str, operation_summary: str,
                    deterministic_severity: str) -> Finding | None:
    """Model commentary on an exposed OpenAPI document.

    Returns None when no model is available, which the caller treats as "the
    deterministic finding is the whole answer here".
    """
    if client is None:
        return None
    analysis = client.analyse(
        OPENAPI_QUESTION,
        spec_text,
        context={"spec_url": spec_url, "host": host, "port": port,
                 "scanner_enumeration": operation_summary,
                 "scanner_severity": deterministic_severity},
    )
    if analysis is None:
        return unavailable_finding(
            host=host, port=port, subject=f"API specification at {spec_url}",
            reason=client.stats.last_error or "model unavailable",
        )
    return analysis_to_finding(
        analysis, host=host, port=port,
        subject=f"API specification at {spec_url}",
        deterministic_severity=deterministic_severity,
        tags=["openapi", "api"],
    )


FINDING_QUESTION = """\
Assess this single finding from an external scan: what it actually means for \
the client, and how much it matters relative to a typical external exposure.

Say explicitly what the evidence establishes versus what it only suggests, and \
what a human would need to check to settle the difference. If it looks like a \
false positive or a non-issue, say so -- that is a useful answer."""


def analyse_finding(client, finding: Finding) -> Finding | None:
    """Model commentary on one deterministic finding."""
    if client is None:
        return None
    analysis = client.analyse(
        FINDING_QUESTION,
        f"{finding.title}\n\n{finding.description}\n\n{finding.evidence}",
        context={"host": finding.host, "port": finding.port,
                 "detected_by": finding.source,
                 "scanner_severity": finding.severity,
                 "scanner_confidence": finding.confidence},
    )
    if analysis is None:
        return None            # the finding already stands; no need to annotate
    return analysis_to_finding(
        analysis, host=finding.host, port=finding.port, proto=finding.proto,
        subject=finding.title,
        deterministic_severity=finding.severity,
        tags=[*finding.tags[:4]],
    )
