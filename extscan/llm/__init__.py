"""Model-assisted analysis, with the failure path as the designed path.

`LLMClient.analyse` never raises for an outage. It returns `None`, records why,
and the caller carries on with deterministic findings plus a human-review flag.
That is the whole contract, and it is what makes the model optional rather than
load-bearing: a run with the endpoint down produces the same findings as a run
without the feature configured, minus the commentary, and says so in the report.

What happens when the model is unreachable, in order:

1. Transient failures (timeout, 429, 5xx) are retried with jittered backoff
   inside a time budget.
2. After `circuit_failure_threshold` consecutive failures the circuit opens and
   further calls return immediately. Without this, a dead endpoint turns a
   300-lead chase into 300 sequential timeouts.
3. The chase loop sees the open circuit, stops asking, records a coverage gap
   naming what went unanalysed, and leaves those leads open so a later
   `extscan resume` can finish them.
4. The report carries the gap in its own section, so nobody mistakes "no model
   commentary" for "nothing worth commenting on".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from extscan.resilience import CircuitBreaker, CircuitOpen, RetryPolicy, retry

from .base import (
    SYSTEM_PROMPT,
    Analysis,
    LLMBadOutput,
    LLMRefused,
    LLMUnavailable,
    Provider,
    build_prompt,
    parse_analysis,
    sanitise_evidence,
)
from .providers import (
    AnthropicAPIProvider,
    AzureFoundryProvider,
    BedrockProvider,
    build_provider,
    classify_sdk_error,
    describe_providers,
)
from .redact import SYSTEM_NOTE, IPRedactor, RedactionError

__all__ = [
    "Analysis",
    "AnthropicAPIProvider",
    "AzureFoundryProvider",
    "BedrockProvider",
    "IPRedactor",
    "LLMBadOutput",
    "LLMClient",
    "LLMRefused",
    "LLMStats",
    "LLMUnavailable",
    "Provider",
    "build_client",
    "describe_providers",
]


@dataclass
class LLMStats:
    """What the model layer did, for the run metadata and the report appendix."""

    requested: int = 0
    succeeded: int = 0
    failed: int = 0
    refused: int = 0
    bad_output: int = 0
    skipped_circuit_open: int = 0
    truncated_inputs: int = 0
    total_seconds: float = 0.0
    last_error: str = ""
    circuit_trips: int = 0
    model: str = ""
    provider: str = ""
    ip_redaction: bool = False
    redacted_addresses: int = 0

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "model": self.model,
            "ip_redaction": self.ip_redaction,
            "redacted_addresses": self.redacted_addresses,
            "requested": self.requested, "succeeded": self.succeeded,
            "failed": self.failed, "refused": self.refused,
            "bad_output": self.bad_output,
            "skipped_circuit_open": self.skipped_circuit_open,
            "truncated_inputs": self.truncated_inputs,
            "total_seconds": round(self.total_seconds, 1),
            "circuit_trips": self.circuit_trips,
            "last_error": self.last_error,
        }

    @property
    def degraded(self) -> bool:
        """True if any requested analysis did not happen."""
        return bool(self.failed or self.refused or self.bad_output
                    or self.skipped_circuit_open)


@dataclass
class LLMClient:
    """A provider wrapped in retries, a circuit breaker and accounting."""

    provider: Provider
    max_tokens: int = 8000
    effort: str = "medium"
    timeout: float = 120.0
    max_input_chars: int = 40_000
    # Pseudonymise IP addresses on the way out and restore them in the reply
    # (extscan/llm/redact.py). One redactor per client, so every request in a
    # run sees the same mapping.
    redact_ips: bool = True
    redactor: IPRedactor | None = None
    stats: LLMStats = field(default_factory=LLMStats)
    breaker: CircuitBreaker = field(default_factory=lambda: CircuitBreaker(
        name="llm", failure_threshold=3, cooldown=120.0))
    retry_policy: RetryPolicy = field(default_factory=lambda: RetryPolicy(
        attempts=3, base_delay=2.0, max_delay=20.0, total_budget=90.0))

    def __post_init__(self) -> None:
        self.stats.provider = self.provider.name
        self.stats.model = getattr(self.provider, "model", "")
        self.stats.ip_redaction = self.redact_ips
        if self.redact_ips and self.redactor is None:
            self.redactor = IPRedactor()

    @property
    def healthy(self) -> bool:
        return self.breaker.allows()

    def describe(self) -> dict:
        return {**self.provider.describe(), "circuit": self.breaker.state,
                "stats": self.stats.to_dict()}

    def analyse(self, question: str, evidence: str,
                context: dict | None = None) -> Analysis | None:
        """Ask the model about one piece of evidence.

        Returns None whenever an answer could not be obtained, for any reason.
        Callers must handle None by proceeding deterministically -- never by
        skipping the check or retrying here.
        """
        self.stats.requested += 1

        if not self.breaker.allows():
            self.stats.skipped_circuit_open += 1
            return None

        system = SYSTEM_PROMPT
        if self.redact_ips:
            # Every part, not just the evidence: the trusted context carries
            # the host and URLs too. Before truncation, so a cut cannot leave
            # the first octets of a real address that no pattern matches.
            # Fail closed: text that could not be redacted is not sent.
            try:
                question = self.redactor.redact(question)
                evidence = self.redactor.redact(evidence or "")
                if context:
                    context = {k: self.redactor.redact(v) if isinstance(v, str) else v
                               for k, v in context.items()}
            except RedactionError as exc:
                self.stats.failed += 1
                self.stats.last_error = str(exc)[:300]
                return None
            system = SYSTEM_PROMPT + SYSTEM_NOTE
        safe_evidence, truncated = sanitise_evidence(evidence, self.max_input_chars)
        if truncated:
            self.stats.truncated_inputs += 1
        prompt = build_prompt(question, safe_evidence, context)

        started = time.monotonic()
        try:
            text, model_id = self.breaker.call(
                lambda: retry(
                    lambda: self.provider.complete(
                        system, prompt,
                        max_tokens=self.max_tokens,
                        effort=self.effort,
                        timeout=self.timeout,
                    ),
                    self.retry_policy,
                )
            )
        except CircuitOpen:
            self.stats.skipped_circuit_open += 1
            return None
        except LLMRefused as exc:
            self.stats.refused += 1
            self.stats.last_error = str(exc)[:300]
            return None
        except LLMUnavailable as exc:
            self.stats.failed += 1
            self.stats.last_error = str(exc)[:300]
            return None
        except Exception as exc:
            self.stats.failed += 1
            self.stats.last_error = f"{type(exc).__name__}: {exc}"[:300]
            return None
        finally:
            self.stats.total_seconds += time.monotonic() - started
            self.stats.circuit_trips = self.breaker.trips
            if self.redactor is not None:
                self.stats.redacted_addresses = self.redactor.replaced

        if getattr(self.provider, "last_stop_reason", "") == "max_tokens":
            # Thinking and the answer share max_tokens, so a low limit ends
            # the reply mid-answer. Named for what it is: the fix is a
            # setting, not a retry.
            self.stats.bad_output += 1
            self.stats.last_error = (
                f"the reply was cut off at llm.max_tokens ({self.max_tokens}); "
                "raise llm.max_tokens or lower llm.effort")
            return None
        if self.redact_ips:
            text = self.redactor.restore(text)
        try:
            analysis = parse_analysis(text)
        except LLMBadOutput as exc:
            self.stats.bad_output += 1
            self.stats.last_error = str(exc)[:300]
            return None

        analysis.model = model_id
        analysis.provider = self.provider.name
        analysis.input_truncated = truncated
        self.stats.succeeded += 1
        return analysis


def build_client(policy, *, redact_ips: bool | None = None) -> LLMClient | None:
    """Build a client from an LLMPolicy, or None when analysis is disabled.

    `redact_ips` overrides `policy.redact_ips` (the `--no-redact-ips` flag).

    Raises LLMUnavailable (or ValueError for a provider name that does not
    exist) when analysis is enabled but cannot work. The CLI turns that into
    a recorded coverage gap and carries on without a model, so a
    misconfigured model never stops a scan and never goes unmentioned.
    """
    provider = build_provider(policy)
    if provider is None:
        return None

    usable, reason = provider.available()
    if not usable:
        raise LLMUnavailable(reason)

    return LLMClient(
        provider=provider,
        max_tokens=policy.max_tokens,
        effort=policy.effort,
        timeout=float(policy.timeout_sec),
        max_input_chars=policy.max_input_chars,
        redact_ips=policy.redact_ips if redact_ips is None else redact_ips,
        breaker=CircuitBreaker(name=f"llm:{provider.name}",
                               failure_threshold=policy.circuit_failure_threshold,
                               cooldown=float(policy.circuit_cooldown_sec)),
        retry_policy=RetryPolicy(attempts=policy.retry_attempts,
                                 base_delay=policy.retry_base_delay,
                                 max_delay=20.0,
                                 total_budget=float(policy.retry_budget_sec)),
    )


def _register_classifier() -> None:
    from extscan import resilience

    original = resilience.classify

    def classify(exc: BaseException) -> str:
        module = type(exc).__module__ or ""
        if module.startswith("anthropic"):
            verdict = classify_sdk_error(exc)
            if verdict != "unknown":
                return verdict
        return original(exc)

    resilience.classify = classify


_register_classifier()
