"""Provider implementations: the Anthropic API directly, and AWS Bedrock.

Both go through the official `anthropic` SDK, which is an optional install
(`pip install 'extscan[llm]'` or `'extscan[bedrock]'`). The SDK being absent is
reported as unavailability like any other outage, so a core install with no
extras behaves exactly as if the endpoint were unreachable -- deterministic
findings, a recorded coverage gap, no crash.

Retries are turned off at the SDK level (`max_retries=0`) on purpose. The
backoff, the time budget and the circuit breaker live in extscan.resilience, so
there is one place that decides how hard to try and one set of numbers in the
degradation records. Two independent retry layers would multiply the wall
clock and misreport the attempt count.
"""

from __future__ import annotations

import os

from .base import LLMRefused, LLMUnavailable, Provider

# Defaults. Bedrock model ids carry an `anthropic.` prefix; the first-party API
# ids do not. Both are overridable in policy, because which models an account
# can reach -- especially on Bedrock, where access is granted per model and per
# region -- is deployment-specific.
DEFAULT_API_MODEL = "claude-opus-5-5"
DEFAULT_BEDROCK_MODEL = "anthropic.claude-opus-5-5"


def _import_sdk():
    try:
        import anthropic
    except ImportError as exc:                 # pragma: no cover - env-dependent
        raise LLMUnavailable(
            "the `anthropic` package is not installed. Model-assisted analysis "
            "is optional; install it with `pip install 'extscan[llm]'` (or "
            "'extscan[bedrock]' for AWS Bedrock), or run with llm.enabled=false "
            "for fully deterministic scanning."
        ) from exc
    return anthropic


def classify_sdk_error(exc: BaseException) -> str:
    """Map SDK exception types onto the resilience classifier's vocabulary.

    Registered with extscan.resilience so a 429 from the SDK is retried and a
    401 is not.
    """
    name = type(exc).__name__
    if name in ("RateLimitError", "APIConnectionError", "APITimeoutError",
                "InternalServerError", "APIConnectionTimeoutError"):
        return "transient"
    if name in ("AuthenticationError", "PermissionDeniedError", "NotFoundError",
                "BadRequestError", "UnprocessableEntityError"):
        return "permanent"
    if name == "APIStatusError":
        status = getattr(exc, "status_code", None)
        if isinstance(status, int):
            return "transient" if status == 429 or status >= 500 else "permanent"
    return "unknown"


class _AnthropicSDKProvider(Provider):
    """Shared request logic for both the direct API and Bedrock."""

    def __init__(self, model: str, max_retries: int = 0):
        self.model = model
        self.max_retries = max_retries
        self._client = None

    def _build_client(self):                   # pragma: no cover - overridden
        raise NotImplementedError

    def _client_or_raise(self):
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def complete(self, system: str, user: str, *, max_tokens: int,
                 effort: str, timeout: float) -> tuple[str, str]:
        anthropic = _import_sdk()
        client = self._client_or_raise()

        try:
            # No `thinking` parameter and no `budget_tokens`: on current models
            # thinking is always on and a budget is rejected outright. Depth is
            # controlled by effort, which defaults to medium on Opus 5.5 -- set
            # explicitly here because this task is short and well-specified.
            response = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                output_config={"effort": effort},
                messages=[{"role": "user", "content": user}],
                timeout=timeout,
            )
        except anthropic.AuthenticationError as exc:
            raise LLMUnavailable(f"model authentication failed: {exc}") from exc
        except anthropic.PermissionDeniedError as exc:
            raise LLMUnavailable(
                f"the credentials are valid but lack access to {self.model!r}: {exc}"
            ) from exc
        except anthropic.NotFoundError as exc:
            raise LLMUnavailable(
                f"model {self.model!r} was not found by this provider. Check the id "
                "and, on Bedrock, that the model is enabled in this region: "
                f"{exc}"
            ) from exc
        except anthropic.BadRequestError as exc:
            # A 400 is our bug (bad parameter, oversized request), not an outage.
            raise LLMUnavailable(f"the model rejected the request: {exc}") from exc

        # A safety classifier may decline; stop_reason must be checked before
        # reading content, which may be empty.
        if getattr(response, "stop_reason", None) == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) or "unspecified"
            raise LLMRefused(
                f"the model declined to analyse this evidence (category: {category}). "
                "The finding stands on its deterministic evidence; an auditor should "
                "review it by hand."
            )

        text = "".join(
            block.text for block in (response.content or [])
            if getattr(block, "type", None) == "text"
        )
        return text, getattr(response, "model", self.model)


class AnthropicAPIProvider(_AnthropicSDKProvider):
    """The first-party Claude API."""

    name = "anthropic"

    def __init__(self, model: str = DEFAULT_API_MODEL, api_key: str | None = None,
                 base_url: str | None = None, max_retries: int = 0):
        super().__init__(model or DEFAULT_API_MODEL, max_retries)
        self.api_key = api_key
        self.base_url = base_url

    def available(self) -> tuple[bool, str]:
        """Report every problem, not just the first.

        An operator fixing this on a locked-down box should learn in one run
        that the SDK is missing *and* that the region is wrong, rather than
        discovering the second problem after solving the first.
        """
        problems: list[str] = []
        notes: list[str] = []
        try:
            _import_sdk()
        except LLMUnavailable as exc:
            problems.append(str(exc))

        # An unset ANTHROPIC_API_KEY does not mean there are no credentials: the
        # SDK also resolves ANTHROPIC_AUTH_TOKEN and an `ant auth login` profile
        # on disk. So this is a note, not a problem.
        if not (self.api_key or os.environ.get("ANTHROPIC_API_KEY")
                or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            notes.append("no ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN set; the SDK "
                         "will try a stored credential profile (`ant auth status`)")
        if problems:
            return False, " | ".join(problems + notes)
        return True, " | ".join([f"configured for model {self.model}", *notes])

    def _build_client(self):
        anthropic = _import_sdk()
        kwargs: dict = {"max_retries": self.max_retries}
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return anthropic.Anthropic(**kwargs)


class BedrockProvider(_AnthropicSDKProvider):
    """Claude on AWS Bedrock.

    Uses the SDK's Bedrock client, which handles SigV4 signing and the normal
    AWS credential chain (instance role, profile, environment), so no AWS
    secrets are handled here. Region matters: Bedrock model access is granted
    per model per region, and the common first failure is a model that is
    enabled in one region and not another.
    """

    name = "bedrock"

    def __init__(self, model: str = DEFAULT_BEDROCK_MODEL,
                 region: str | None = None, profile: str | None = None,
                 max_retries: int = 0):
        super().__init__(model or DEFAULT_BEDROCK_MODEL, max_retries)
        self.region = region or os.environ.get("AWS_REGION") \
            or os.environ.get("AWS_DEFAULT_REGION") or ""
        self.profile = profile

    def available(self) -> tuple[bool, str]:
        """Report every problem at once (see AnthropicAPIProvider.available).

        Configuration is checked even when the SDK is absent, because a missing
        region is worth knowing about on the same run as a missing package.
        """
        problems: list[str] = []
        notes: list[str] = []

        try:
            anthropic = _import_sdk()
        except LLMUnavailable as exc:
            problems.append(str(exc))
        else:
            if not self._client_class(anthropic):
                problems.append("this `anthropic` build exposes no Bedrock client; "
                                "install `pip install 'extscan[bedrock]'`")

        if not self.region:
            problems.append("no AWS region configured. Set llm.aws_region in the "
                            "policy file, or AWS_REGION in the environment: Bedrock "
                            "model access is granted per model per region.")
        if not self.model.startswith(("anthropic.", "us.anthropic.", "eu.anthropic.",
                                      "apac.anthropic.", "arn:")):
            notes.append(f"model {self.model!r} does not look like a Bedrock id "
                         "(expected an `anthropic.` prefix, a cross-region prefix "
                         "such as `us.anthropic.`, or an inference-profile ARN)")

        if problems:
            return False, " | ".join(problems + notes)
        return True, " | ".join([f"configured for {self.model} in {self.region}",
                                 *notes])

    @staticmethod
    def _client_class(anthropic):
        """Prefer the Mantle (Messages-API) client, fall back to the legacy one.

        Which of these a given SDK build ships varies, and an audit box often
        has whatever version was approved months ago. Probing beats pinning.
        """
        for attr in ("AnthropicBedrockMantle", "AnthropicBedrock"):
            client = getattr(anthropic, attr, None)
            if client is not None:
                return client
        return None

    def _build_client(self):
        anthropic = _import_sdk()
        client_class = self._client_class(anthropic)
        if client_class is None:
            raise LLMUnavailable(
                "this `anthropic` build exposes no Bedrock client; install "
                "`pip install 'extscan[bedrock]'`"
            )
        kwargs: dict = {"aws_region": self.region, "max_retries": self.max_retries}
        if self.profile:
            kwargs["aws_profile"] = self.profile
        try:
            return client_class(**kwargs)
        except TypeError:
            # Older builds take neither aws_profile nor max_retries.
            return client_class(aws_region=self.region)


def build_provider(policy) -> Provider | None:
    """Construct the provider named by an LLMPolicy, or None when disabled."""
    name = (policy.provider or "none").lower()
    if not policy.enabled or name in ("none", "", "off", "disabled"):
        return None
    if name in ("anthropic", "api", "claude"):
        return AnthropicAPIProvider(
            model=policy.model or DEFAULT_API_MODEL,
            base_url=policy.base_url or None,
            max_retries=policy.sdk_retries,
        )
    if name in ("bedrock", "aws", "aws-bedrock"):
        return BedrockProvider(
            model=policy.model or DEFAULT_BEDROCK_MODEL,
            region=policy.aws_region or None,
            profile=policy.aws_profile or None,
            max_retries=policy.sdk_retries,
        )
    raise ValueError(
        f"unknown llm.provider {policy.provider!r}; expected 'anthropic', "
        "'bedrock' or 'none'"
    )


def describe_providers(policy) -> list[dict]:
    """Availability of every provider, for `extscan providers`."""
    rows = []
    for provider in (
        AnthropicAPIProvider(model=policy.model or DEFAULT_API_MODEL),
        BedrockProvider(model=(policy.model if policy.provider == "bedrock"
                               else DEFAULT_BEDROCK_MODEL),
                        region=policy.aws_region or None),
    ):
        rows.append(provider.describe())
    return rows
