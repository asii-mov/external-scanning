"""Provider implementations: the Anthropic API directly, AWS Bedrock, and
Azure (Claude in Microsoft Foundry).

All three go through the official `anthropic` SDK, which is an optional install
(`pip install 'extscan[llm]'`, `'extscan[bedrock]'` or `'extscan[azure]'`). The
SDK being absent is
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

DEFAULT_API_MODEL = "claude-opus-5-5"
DEFAULT_BEDROCK_MODEL = "anthropic.claude-opus-5-5"
# On Foundry the model is a deployment name, which by default is the model id.
DEFAULT_AZURE_MODEL = "claude-opus-5-5"
# The Entra ID scope for Foundry, as given in the SDK's Foundry notes.
AZURE_TOKEN_SCOPE = "https://ai.azure.com/.default"  # noqa: S105 (a scope, not a secret)


def _import_sdk():
    try:
        import anthropic
    except ImportError as exc:
        raise LLMUnavailable(
            "the `anthropic` package is not installed. Model-assisted analysis "
            "is optional; install it with `pip install 'extscan[llm]'` (or "
            "'extscan[bedrock]' for AWS Bedrock, 'extscan[azure]' for Azure), or "
            "run with llm.enabled=false for fully deterministic scanning."
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
    """Shared request logic for the direct API, Bedrock and Azure."""

    def __init__(self, model: str, max_retries: int = 0):
        self.model = model
        self.max_retries = max_retries
        self._client = None
        # Why the last reply ended. The client reads it to tell a reply cut
        # off at max_tokens from one that is merely not JSON.
        self.last_stop_reason = ""

    def _build_client(self):
        raise NotImplementedError

    def _client_or_raise(self):
        if self._client is None:
            anthropic = _import_sdk()
            try:
                self._client = self._build_client()
            except LLMUnavailable:
                raise
            except (anthropic.AnthropicError, ValueError, TypeError) as exc:
                # Missing credentials or a bad endpoint: configuration, so
                # not something a retry can fix.
                raise LLMUnavailable(
                    f"the {self.name} client could not be set up: {exc}") from exc
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
            raise LLMUnavailable(f"the model rejected the request: {exc}") from exc

        self.last_stop_reason = str(getattr(response, "stop_reason", "") or "")

        # A safety classifier may decline; stop_reason must be checked before
        # reading content, which may be empty.
        if self.last_stop_reason == "refusal":
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
        except TypeError as exc:
            # Never retried with fewer arguments: dropping aws_profile would
            # sign requests with a different account's credentials, and
            # dropping max_retries would add a second retry layer.
            raise LLMUnavailable(
                f"this `anthropic` build's {client_class.__name__} does not accept "
                f"the configured options ({exc}). Upgrade the package, or set "
                "AWS_PROFILE in the environment instead of llm.aws_profile."
            ) from exc


class AzureFoundryProvider(_AnthropicSDKProvider):
    """Claude on Azure, through Microsoft Foundry.

    Uses the SDK's Foundry client. The endpoint is either a Foundry resource
    name (https://<resource>.services.ai.azure.com/anthropic/) or a full base
    URL, never both. Sign-in is an API key from ANTHROPIC_FOUNDRY_API_KEY, or
    Entra ID through `azure-identity`'s default credential chain (managed
    identity, workload identity, `az login`). No secret is read from the
    policy file, because the policy is copied into every run directory.
    """

    name = "azure"

    def __init__(self, model: str = DEFAULT_AZURE_MODEL, resource: str | None = None,
                 base_url: str | None = None, auth: str = "auto", max_retries: int = 0):
        super().__init__(model or DEFAULT_AZURE_MODEL, max_retries)
        self.base_url = base_url or os.environ.get("ANTHROPIC_FOUNDRY_BASE_URL") or ""
        # An explicit base URL wins; the SDK refuses to be given both.
        self.resource = "" if self.base_url else (
            resource or os.environ.get("ANTHROPIC_FOUNDRY_RESOURCE") or "")
        self.auth = (auth or "auto").lower()

    def _auth_mode(self) -> str:
        if self.auth != "auto":
            return self.auth
        return "api_key" if os.environ.get("ANTHROPIC_FOUNDRY_API_KEY") else "entra"

    @staticmethod
    def _token_provider():
        try:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        except ImportError as exc:
            raise LLMUnavailable(
                "Entra ID sign-in needs the `azure-identity` package: "
                "`pip install 'extscan[azure]'`, or set ANTHROPIC_FOUNDRY_API_KEY "
                "to use an API key."
            ) from exc
        return get_bearer_token_provider(DefaultAzureCredential(), AZURE_TOKEN_SCOPE)

    def available(self) -> tuple[bool, str]:
        """Report every problem at once (see AnthropicAPIProvider.available)."""
        problems: list[str] = []
        try:
            anthropic = _import_sdk()
        except LLMUnavailable as exc:
            problems.append(str(exc))
        else:
            if getattr(anthropic, "AnthropicFoundry", None) is None:
                problems.append("this `anthropic` build has no Foundry client; upgrade "
                                "it with `pip install -U 'extscan[azure]'`")

        if not (self.resource or self.base_url):
            problems.append("no Azure endpoint configured. Set llm.azure_resource (the "
                            "Foundry resource name) or llm.base_url in the policy file, "
                            "or ANTHROPIC_FOUNDRY_RESOURCE in the environment.")
        mode = self._auth_mode()
        if mode == "api_key" and not os.environ.get("ANTHROPIC_FOUNDRY_API_KEY"):
            problems.append("llm.azure_auth is api_key but ANTHROPIC_FOUNDRY_API_KEY is "
                            "not set")
        elif mode == "entra":
            try:
                import azure.identity  # noqa: F401
            except ImportError:
                problems.append(
                    "no ANTHROPIC_FOUNDRY_API_KEY is set, and Entra ID sign-in needs "
                    "`azure-identity` (`pip install 'extscan[azure]'`)"
                    if self.auth == "auto" else
                    "Entra ID sign-in needs `azure-identity` "
                    "(`pip install 'extscan[azure]'`)")
        elif mode not in ("api_key", "entra"):
            problems.append(f"llm.azure_auth {self.auth!r} is not auto, api_key or entra")

        if problems:
            return False, " | ".join(problems)
        where = self.base_url or f"resource {self.resource}"
        how = "an API key" if mode == "api_key" else "Entra ID"
        return True, f"configured for deployment {self.model} at {where}, using {how}"

    def _build_client(self):
        anthropic = _import_sdk()
        client_class = getattr(anthropic, "AnthropicFoundry", None)
        if client_class is None:
            raise LLMUnavailable("this `anthropic` build has no Foundry client; upgrade "
                                 "it with `pip install -U 'extscan[azure]'`")
        kwargs: dict = {"max_retries": self.max_retries}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        else:
            kwargs["resource"] = self.resource
        if self._auth_mode() == "entra":
            kwargs["azure_ad_token_provider"] = self._token_provider()
        # With an API key the SDK reads ANTHROPIC_FOUNDRY_API_KEY itself.
        return client_class(**kwargs)


AZURE_NAMES = ("azure", "foundry", "azure-foundry", "microsoft-foundry")


def build_provider(policy) -> Provider | None:
    """Construct the provider named by an LLMPolicy, or None when disabled."""
    name = (policy.provider or "none").lower()
    if not policy.enabled:
        return None
    if name in ("none", "", "off", "disabled"):
        # Enabled with nowhere to send to is a mistake, not a way of turning
        # it off: saying nothing would look like the model had no comment.
        raise ValueError(
            "llm.enabled is true but llm.provider is not set; use 'anthropic', "
            "'bedrock' or 'azure', or set llm.enabled to false")
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
    if name in AZURE_NAMES:
        return AzureFoundryProvider(
            model=policy.model or DEFAULT_AZURE_MODEL,
            resource=policy.azure_resource or None,
            base_url=policy.base_url or None,
            auth=policy.azure_auth,
            max_retries=policy.sdk_retries,
        )
    raise ValueError(
        f"unknown llm.provider {policy.provider!r}; expected 'anthropic', "
        "'bedrock' or 'azure'"
    )


def describe_providers(policy) -> list[dict]:
    """Availability of every provider, for `extscan providers`."""
    chosen = (policy.provider or "").lower()

    def model_for(names: tuple[str, ...], default: str) -> str:
        return policy.model if chosen in names and policy.model else default

    rows = []
    for provider in (
        AnthropicAPIProvider(model=model_for(("anthropic", "api", "claude"),
                                             DEFAULT_API_MODEL)),
        BedrockProvider(model=model_for(("bedrock", "aws", "aws-bedrock"),
                                        DEFAULT_BEDROCK_MODEL),
                        region=policy.aws_region or None),
        AzureFoundryProvider(model=model_for(AZURE_NAMES, DEFAULT_AZURE_MODEL),
                             resource=policy.azure_resource or None,
                             base_url=(policy.base_url or None) if chosen in AZURE_NAMES
                             else None,
                             auth=policy.azure_auth),
    ):
        rows.append(provider.describe())
    return rows
