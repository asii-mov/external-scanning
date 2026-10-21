"""Failure handling: retries, circuit breaking, and honest degradation.

The governing rule for a scanner is that **reduced coverage must never look
like a clean result**. A scan that silently checked half of what it claimed is
worse than one that failed outright, because somebody signs a report based on
it. So every failure here ends in one of three places:

1. it is retried and succeeds;
2. it is retried, fails, and is recorded as a `Degradation` that appears in the
   report as a named coverage gap; or
3. it aborts the stage loudly.

Never a silent pass.

The three mechanisms:

* `retry` -- exponential backoff with jitter, for transient faults.
* `CircuitBreaker` -- after enough consecutive failures, stop trying. Without
  this, an LLM endpoint that is down turns a 300-lead chase into 300 sequential
  timeouts, and the run never finishes.
* `AbortThreshold` -- if nearly everything is failing, the problem is local
  (network down, VPN dropped, egress blocked). Stop and say so rather than
  grinding out a report full of "host did not respond".
"""

from __future__ import annotations

import random
import socket
import ssl
import time
import urllib.error
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, TypeVar

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

class PermanentError(Exception):
    """A failure that retrying cannot fix (bad credentials, 400, bad config)."""


class TransientError(Exception):
    """A failure worth retrying (timeout, 503, connection reset)."""


class CircuitOpen(Exception):
    """Raised instead of calling through a circuit that has tripped."""


class RunAborted(Exception):
    """Raised when the abort threshold decides the environment is broken."""


# HTTP status codes worth retrying. 429 and 5xx are the provider telling us to
# come back; everything else in the 4xx range is our own mistake.
RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 507, 509, 529}

_TRANSIENT_EXCEPTIONS = (
    TimeoutError,
    ConnectionError,
    ConnectionResetError,
    ConnectionAbortedError,
    socket.gaierror,
    socket.herror,
    ssl.SSLWantReadError,
    ssl.SSLWantWriteError,
    TransientError,
)

# Substrings in an error message that indicate a transient condition, for
# libraries that raise generic exceptions.
_TRANSIENT_MARKERS = (
    "timed out", "timeout", "connection reset", "broken pipe",
    "temporarily unavailable", "try again", "too many requests",
    "service unavailable", "bad gateway", "gateway timeout",
    "throttl", "rate limit", "overloaded", "capacity",
    "connection refused", "eof occurred",
)


def classify(exc: BaseException) -> str:
    """Return "transient", "permanent" or "unknown" for an exception."""
    if isinstance(exc, PermanentError):
        return "permanent"
    if isinstance(exc, _TRANSIENT_EXCEPTIONS):
        return "transient"
    if isinstance(exc, urllib.error.HTTPError):
        return "transient" if exc.code in RETRYABLE_STATUS else "permanent"
    if isinstance(exc, urllib.error.URLError):
        return "transient"
    if isinstance(exc, ssl.SSLError):
        # A handshake failure against one target is permanent for that target;
        # it is not a reason to retry the whole operation.
        return "permanent"
    message = str(exc).lower()
    if any(marker in message for marker in _TRANSIENT_MARKERS):
        return "transient"
    return "unknown"


def is_retryable(exc: BaseException, retry_unknown: bool = False) -> bool:
    verdict = classify(exc)
    return verdict == "transient" or (retry_unknown and verdict == "unknown")


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------

@dataclass
class RetryPolicy:
    attempts: int = 3                  # total tries, not retries
    base_delay: float = 1.0
    max_delay: float = 30.0
    multiplier: float = 2.0
    jitter: float = 0.3               # +/- this fraction, to avoid lockstep
    retry_unknown: bool = False       # be conservative by default
    total_budget: float = 120.0       # give up after this much wall clock

    def delay_for(self, attempt: int) -> float:
        """Backoff for `attempt` (1-based), with jitter."""
        raw = min(self.base_delay * (self.multiplier ** (attempt - 1)), self.max_delay)
        if self.jitter:
            spread = raw * self.jitter
            raw += random.uniform(-spread, spread)  # noqa: S311 - jitter, not crypto
        return max(0.0, raw)


def retry(
    fn: Callable[[], T],
    policy: RetryPolicy | None = None,
    *,
    on_retry: Callable[[int, BaseException, float], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Call `fn`, retrying transient failures with exponential backoff.

    Re-raises the last exception when attempts or the time budget run out, so
    the caller still has to decide what a final failure means.
    """
    policy = policy or RetryPolicy()
    started = time.monotonic()
    last: BaseException | None = None

    for attempt in range(1, max(1, policy.attempts) + 1):
        try:
            return fn()
        except BaseException as exc:
            last = exc
            if not is_retryable(exc, policy.retry_unknown):
                raise
            if attempt >= policy.attempts:
                break
            delay = policy.delay_for(attempt)
            elapsed = time.monotonic() - started
            if elapsed + delay > policy.total_budget:
                break
            if on_retry:
                on_retry(attempt, exc, delay)
            sleep(delay)

    assert last is not None
    raise last


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

@dataclass
class CircuitBreaker:
    """Stop calling a dependency that is clearly down.

    Three states. Closed: calls pass through. Open: calls raise `CircuitOpen`
    immediately, which is what keeps a dead LLM endpoint from turning every
    remaining lead into a timeout. Half-open: after `cooldown`, one probe call
    is allowed; success closes the circuit, failure re-opens it.
    """

    name: str = "dependency"
    failure_threshold: int = 4
    cooldown: float = 60.0
    success_threshold: int = 1        # successes in half-open needed to close

    _failures: int = field(default=0, init=False)
    _successes: int = field(default=0, init=False)
    _opened_at: float | None = field(default=None, init=False)
    _trip_count: int = field(default=0, init=False)

    @property
    def state(self) -> str:
        if self._opened_at is None:
            return "closed"
        if time.monotonic() - self._opened_at >= self.cooldown:
            return "half-open"
        return "open"

    @property
    def trips(self) -> int:
        return self._trip_count

    def allows(self) -> bool:
        return self.state != "open"

    def record_success(self) -> None:
        if self.state == "half-open":
            self._successes += 1
            if self._successes >= self.success_threshold:
                self.reset()
            return
        self._failures = 0

    def record_failure(self) -> None:
        if self.state == "half-open":
            # The probe failed; serve another cooldown.
            self._opened_at = time.monotonic()
            self._successes = 0
            return
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = time.monotonic()
            self._trip_count += 1
            self._successes = 0

    def reset(self) -> None:
        self._failures = 0
        self._successes = 0
        self._opened_at = None

    def call(self, fn: Callable[[], T]) -> T:
        if not self.allows():
            waited = time.monotonic() - (self._opened_at or 0)
            raise CircuitOpen(
                f"{self.name} circuit is open after {self._failures} consecutive "
                f"failures ({waited:.0f}s into a {self.cooldown:.0f}s cooldown)"
            )
        try:
            result = fn()
        except BaseException as exc:
            # Only count failures the dependency is responsible for. A caller
            # bug should not trip the breaker.
            if classify(exc) != "permanent":
                self.record_failure()
            raise
        self.record_success()
        return result


# ---------------------------------------------------------------------------
# Abort threshold
# ---------------------------------------------------------------------------

@dataclass
class AbortThreshold:
    """Detect "the problem is us", not the targets.

    If the first `min_samples` operations nearly all fail, something local is
    broken -- egress blocked, VPN dropped, wrong interface. Carrying on
    produces a report that says the client's estate is dark when it is not.
    """

    min_samples: int = 12
    failure_ratio: float = 0.95
    _total: int = field(default=0, init=False)
    _failed: int = field(default=0, init=False)

    def record(self, ok: bool) -> None:
        self._total += 1
        if not ok:
            self._failed += 1

    @property
    def ratio(self) -> float:
        return self._failed / self._total if self._total else 0.0

    def should_abort(self) -> bool:
        return self._total >= self.min_samples and self.ratio >= self.failure_ratio

    def check(self, context: str = "") -> None:
        if self.should_abort():
            raise RunAborted(
                f"{self._failed} of {self._total} operations failed"
                + (f" during {context}" if context else "")
                + ". That rate means the fault is local rather than at the "
                "targets -- check egress, routing and DNS from this host, then "
                "resume the run. State is on disk; nothing is lost."
            )


# ---------------------------------------------------------------------------
# Degradation records
# ---------------------------------------------------------------------------

@dataclass
class Degradation:
    """A recorded loss of coverage, destined for the report.

    `impact` is the important field, and it is written for the person reading
    the report rather than the person debugging the tool: not "nuclei exited
    1" but "web vulnerability checks did not run against these 14 services".
    """

    stage: str
    component: str
    reason: str
    impact: str
    severity: str = "warning"          # warning | serious
    hosts: list[str] = field(default_factory=list)
    recoverable: bool = True
    remedy: str = ""
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Degradation:
        return cls(**d)
