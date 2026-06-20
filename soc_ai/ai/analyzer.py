"""Universal LLM analyzer for the AI Log Analysis module.

Sends each :class:`AggregatedLog` window to any OpenAI-compatible LLM
API (Groq, DeepSeek, OpenAI, OpenRouter, Together, or a custom endpoint)
and parses the JSON response into an :class:`AIVerdict`.

Why this design?
----------------
Almost every modern LLM provider — Groq, DeepSeek, OpenRouter, Together,
OpenAI, Anyscale, Fireworks, Mistral, vLLM, Ollama (with `openai`
compatibility shim), etc. — exposes the **same** Chat Completions API
contract. The only things that differ are:

    1. The base URL (e.g. ``https://api.groq.com/openai/v1``)
    2. The API key
    3. The model name

So instead of writing a separate analyzer class per provider, this
module exposes a single :class:`LLMAnalyzer` that takes those three
inputs and uses the official ``openai`` Python SDK under the hood.

Configuration
-------------
All configuration lives in ``.env``. The active provider is selected
by ``LLM_PROVIDER``. For each provider ``P`` the analyzer reads:

    - ``P_API_KEY``   (required)
    - ``P_BASE_URL``  (optional, falls back to a sensible default)
    - ``P_MODEL``     (optional, falls back to a sensible default)

The supported providers and their defaults are listed in
:data:`PROVIDER_DEFAULTS`. To add a brand-new provider, just set
``LLM_PROVIDER=custom`` and fill in ``LLM_API_KEY``, ``LLM_BASE_URL``,
``LLM_MODEL``.

Switching providers
-------------------
To switch from Groq to DeepSeek, edit ``.env``:

    LLM_PROVIDER=deepseek
    DEEPSEEK_API_KEY=sk-xxxxxxxxxxxx
    DEEPSEEK_MODEL=deepseek-chat   # optional

Then re-run the pipeline. No code changes required.

Robustness
----------
Every failure path (API error, timeout, malformed JSON, schema
validation) produces an :class:`AIVerdict.fallback` so the pipeline
never aborts mid-run.
"""

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI
from openai import (
    APIError,
    APIConnectionError,
    APITimeoutError,
    RateLimitError,
    AuthenticationError,
)

from soc_ai.aggregation.schemas import AggregatedLog
from soc_ai.ai.context_loader import ContextLoader
from soc_ai.ai.schemas import AIVerdict, VALID_CATEGORIES, VALID_SEVERITIES


load_dotenv()


# ── Public constants ────────────────────────────────────────────────────

# Registry of known OpenAI-compatible providers. Each entry maps a
# provider name to:
#   - env_prefix : the prefix used to look up API_KEY / BASE_URL / MODEL
#                  in environment variables (e.g. "GROQ" -> GROQ_API_KEY)
#   - base_url   : default base URL if the env var is not set
#   - model      : default model name if the env var is not set
#
# To add a new built-in provider, just add an entry here — no other
# code changes are required. The "custom" entry lets the user point at
# any OpenAI-compatible endpoint via LLM_API_KEY / LLM_BASE_URL / LLM_MODEL.
PROVIDER_DEFAULTS: Dict[str, Dict[str, str]] = {
    "groq": {
        "env_prefix": "GROQ",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
    },
    "deepseek": {
        "env_prefix": "DEEPSEEK",
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
    },
    "openrouter": {
        "env_prefix": "OPENROUTER",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "meta-llama/llama-3.3-70b-instruct:free",
    },
    "together": {
        "env_prefix": "TOGETHER",
        "base_url": "https://api.together.xyz/v1",
        "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo-Free",
    },
    "openai": {
        "env_prefix": "OPENAI",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    },
    "custom": {
        "env_prefix": "LLM",
        "base_url": "",   # must be supplied via env
        "model": "",      # must be supplied via env
    },
}

DEFAULT_TEMPERATURE: float = 0.2
DEFAULT_MAX_TOKENS: int = 1024
DEFAULT_TIMEOUT_SECONDS: float = 30.0


# ── Analyzer ────────────────────────────────────────────────────────────

class LLMAnalyzer:
    """
    Analyze :class:`AggregatedLog` windows using any OpenAI-compatible LLM API.

    The analyzer is reusable across multiple windows; the OpenAI client is
    created once and shared. Each call to :meth:`analyze` produces exactly
    one :class:`AIVerdict`.

    Provider selection priority
    ---------------------------
    1. Explicit ``provider`` argument to ``__init__``.
    2. ``LLM_PROVIDER`` environment variable.
    3. Default: ``"groq"``.

    For the chosen provider ``P`` (with env prefix ``PREFIX``), the
    analyzer reads:

        - ``PREFIX_API_KEY``   (required — raises if missing)
        - ``PREFIX_BASE_URL``  (optional — falls back to provider default)
        - ``PREFIX_MODEL``     (optional — falls back to provider default)

    These can all be overridden by passing the corresponding kwargs to
    ``__init__`` (useful for tests or for one-off runs against a
    different endpoint without editing ``.env``).

    Usage
    -----
    >>> analyzer = LLMAnalyzer()                   # reads .env
    >>> verdict = analyzer.analyze(aggregated_log)  # one window -> one verdict

    Or, to analyze a batch:

    >>> verdicts = analyzer.analyze_batch([agg1, agg2, agg3])

    Or, to override the provider at construction time:

    >>> analyzer = LLMAnalyzer(provider="deepseek")
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        context_loader: Optional[ContextLoader] = None,
        client: Optional[OpenAI] = None,
    ) -> None:
        """
        Parameters
        ----------
        provider : str, optional
            Provider name. Must be a key of :data:`PROVIDER_DEFAULTS`
            (``groq``, ``deepseek``, ``openrouter``, ``together``,
            ``openai``, ``custom``). Defaults to ``LLM_PROVIDER`` env
            var, or ``"groq"`` if neither is set.
        api_key : str, optional
            Override the API key. Defaults to ``<PREFIX>_API_KEY`` env var.
        base_url : str, optional
            Override the base URL. Defaults to ``<PREFIX>_BASE_URL`` env
            var, then to the provider default.
        model : str, optional
            Override the model name. Defaults to ``<PREFIX>_MODEL`` env
            var, then to the provider default.
        temperature : float, optional
            Sampling temperature. Defaults to ``LLM_TEMPERATURE`` env var
            (0.2 if unset).
        max_tokens : int, optional
            Max completion tokens. Defaults to ``LLM_MAX_TOKENS`` env var
            (1024 if unset).
        timeout_seconds : float, optional
            Per-request timeout. Defaults to ``LLM_TIMEOUT_SECONDS`` env
            var (30.0 if unset).
        context_loader : ContextLoader, optional
            Loader for the Markdown context files. Defaults to a new
            :class:`ContextLoader`.
        client : OpenAI, optional
            Pre-built OpenAI client (mostly for testing). When ``None``,
            a new client is constructed from ``api_key`` and ``base_url``.
        """
        # ── Resolve provider ──────────────────────────────────────────
        self.provider = (provider or os.getenv("LLM_PROVIDER") or "groq").strip().lower()
        if self.provider not in PROVIDER_DEFAULTS:
            raise ValueError(
                f"Unknown LLM_PROVIDER={self.provider!r}. "
                f"Supported: {sorted(PROVIDER_DEFAULTS)}"
            )
        config = PROVIDER_DEFAULTS[self.provider]
        prefix = config["env_prefix"]

        # ── Resolve API key ───────────────────────────────────────────
        self.api_key = api_key or os.getenv(f"{prefix}_API_KEY")
        if not self.api_key:
            raise ValueError(
                f"Missing {prefix}_API_KEY for provider {self.provider!r}. "
                f"Please set it in .env or pass api_key explicitly."
            )

        # ── Resolve base URL ──────────────────────────────────────────
        self.base_url = (
            base_url
            or os.getenv(f"{prefix}_BASE_URL")
            or config["base_url"]
        )
        if not self.base_url:
            raise ValueError(
                f"Missing base URL for provider {self.provider!r}. "
                f"Set {prefix}_BASE_URL in .env or pass base_url explicitly."
            )

        # ── Resolve model ─────────────────────────────────────────────
        self.model = (
            model
            or os.getenv(f"{prefix}_MODEL")
            or config["model"]
        )
        if not self.model:
            raise ValueError(
                f"Missing model name for provider {self.provider!r}. "
                f"Set {prefix}_MODEL in .env or pass model explicitly."
            )

        # ── Resolve inference parameters ──────────────────────────────
        self.temperature = float(
            temperature if temperature is not None
            else os.getenv("LLM_TEMPERATURE", DEFAULT_TEMPERATURE)
        )
        self.max_tokens = int(
            max_tokens if max_tokens is not None
            else os.getenv("LLM_MAX_TOKENS", DEFAULT_MAX_TOKENS)
        )
        self.timeout_seconds = float(
            timeout_seconds if timeout_seconds is not None
            else os.getenv("LLM_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        )

        # ── Context loader ────────────────────────────────────────────
        self.context_loader = context_loader or ContextLoader()

        # ── OpenAI client (shared across all analyze() calls) ─────────
        self.client = client or OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.timeout_seconds,
        )

        # Cache the loaded context so we don't re-read files per window.
        # Re-load with :meth:`reload_context` after editing the Markdown files.
        self._cached_context: Optional[str] = None

    # ── Public API ────────────────────────────────────────────────────

    def analyze(self, aggregated: AggregatedLog) -> AIVerdict:
        """
        Analyze one :class:`AggregatedLog` window and return its verdict.

        On any failure (API error, timeout, malformed JSON, schema
        validation), an :class:`AIVerdict.fallback` is returned so the
        pipeline can continue. The original error message is preserved
        in the fallback's ``summary`` for audit.

        Parameters
        ----------
        aggregated : AggregatedLog
            The 5-minute window to analyze.

        Returns
        -------
        AIVerdict
            Either the model's verdict (parsed and validated) or a
            fallback verdict describing the failure.
        """
        analyzed_at = datetime.now(timezone.utc).isoformat()

        try:
            system_prompt = self._get_system_prompt()
            user_prompt = self._build_user_prompt(aggregated)

            response = self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )

            response_text = response.choices[0].message.content or ""
            tokens_used = (
                getattr(response.usage, "total_tokens", None)
                if response.usage else None
            )

            return self._parse_response(
                response_text=response_text,
                tokens_used=tokens_used,
                analyzed_at=analyzed_at,
            )

        except APITimeoutError as exc:
            return AIVerdict.fallback(
                error_message=f"LLM API timeout after {self.timeout_seconds}s: {exc}",
                model=self.model,
                analyzed_at=analyzed_at,
            )
        except RateLimitError as exc:
            return AIVerdict.fallback(
                error_message=f"LLM rate limit exceeded: {exc}",
                model=self.model,
                analyzed_at=analyzed_at,
            )
        except AuthenticationError as exc:
            return AIVerdict.fallback(
                error_message=f"LLM authentication failed (check API key): {exc}",
                model=self.model,
                analyzed_at=analyzed_at,
            )
        except APIConnectionError as exc:
            return AIVerdict.fallback(
                error_message=f"LLM connection error (check base_url / network): {exc}",
                model=self.model,
                analyzed_at=analyzed_at,
            )
        except APIError as exc:
            return AIVerdict.fallback(
                error_message=f"LLM API error: {exc}",
                model=self.model,
                analyzed_at=analyzed_at,
            )
        except Exception as exc:  # noqa: BLE001 — we never want a crash here
            return AIVerdict.fallback(
                error_message=f"Unexpected analyzer error: {type(exc).__name__}: {exc}",
                model=self.model,
                analyzed_at=analyzed_at,
            )

    def analyze_batch(self, windows: List[AggregatedLog]) -> List[AIVerdict]:
        """
        Analyze multiple windows sequentially.

        No concurrency is used — most free tiers rate-limit per minute,
        so sequential calls with fallback on rate-limit errors are safer.
        For higher throughput, wrap :meth:`analyze` in your own throttled
        thread pool.

        Parameters
        ----------
        windows : list[AggregatedLog]
            Aggregated windows to analyze, in order.

        Returns
        -------
        list[AIVerdict]
            One verdict per input window, in the same order.
        """
        return [self.analyze(w) for w in windows]

    def reload_context(self) -> None:
        """Force the next :meth:`analyze` call to re-read context files."""
        self._cached_context = None

    def describe(self) -> Dict[str, Any]:
        """
        Return a dict describing the active configuration.

        Useful for logging at pipeline startup so the user can verify
        which provider / model / endpoint is being used.
        """
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout_seconds": self.timeout_seconds,
            "api_key_set": bool(self.api_key),
        }

    # ── Prompt building ───────────────────────────────────────────────

    def _get_system_prompt(self) -> str:
        """
        Build (and cache) the system prompt.

        The system prompt has two parts:

          1. An instruction block telling the model what role it plays
             and what output format to use.
          2. The concatenated Markdown context (environment, policy,
             asset criticality, benign patterns, response playbooks,
             output schema).
        """
        if self._cached_context is None:
            self._cached_context = self.context_loader.load()

        instruction = (
            "You are a senior SOC analyst reviewing a 5-minute batch "
            "of FortiGate firewall logs. Your job is to decide whether "
            "this batch requires an alert, and to produce a structured "
            "JSON verdict.\n\n"
            "OUTPUT CONTRACT — read this carefully:\n"
            "1. Output exactly ONE JSON object.\n"
            "2. Use ONLY the fields listed in `06_output_schema.md`.\n"
            "3. Do NOT output any markdown, code fences, or commentary "
            "outside the JSON object.\n"
            "4. If the evidence is below threshold, set "
            "`should_alert=false` and choose a normal or low-signal "
            "category.\n"
            "5. Use `confidence` (0-100) to express how sure you are "
            "of the verdict.\n"
            "6. Use `dedup_key` as a stable string (e.g. "
            "`auth_brute_force:<src_ip>:<dst_ip>:<port>`).\n"
            "7. Apply the detection policy strictly. Do not escalate "
            "without evidence.\n"
        )

        return f"{instruction}\n\n--- SOC CONTEXT ---{self._cached_context}\n--- END SOC CONTEXT ---"

    def _build_user_prompt(self, aggregated: AggregatedLog) -> str:
        """
        Build the user prompt containing the aggregated window data.

        The window is serialised to a compact JSON object containing:

          - window_start, window_end, log_source
          - event_count, unique_log_count, malicious_ip_count
          - logs: list of every EnrichedLog in the window (each with
            its dedup metadata and AbuseIPDB enrichments)
        """
        window_dict = aggregated.to_dict()
        window_json = json.dumps(window_dict, ensure_ascii=False, indent=2)

        return (
            "Analyze the following 5-minute aggregated window of "
            "FortiGate logs and produce your JSON verdict.\n\n"
            f"Window data:\n```json\n{window_json}\n```\n\n"
            "Return ONLY the JSON verdict object."
        )

    # ── Response parsing ──────────────────────────────────────────────

    def _parse_response(
        self,
        response_text: str,
        tokens_used: Optional[int],
        analyzed_at: str,
    ) -> AIVerdict:
        """
        Parse the model's response text into an :class:`AIVerdict`.

        Handles three failure modes:

          1. Empty response -> fallback with "Empty response from model".
          2. JSON wrapped in markdown code fences -> strip fences first.
          3. JSON missing required fields or with invalid enum values
             -> fallback listing the specific validation error.
        """
        if not response_text or not response_text.strip():
            return AIVerdict.fallback(
                error_message="Empty response from model",
                model=self.model,
                analyzed_at=analyzed_at,
            )

        # Strip markdown code fences if present (```json ... ```)
        cleaned = _strip_code_fences(response_text)

        # Parse JSON
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            return AIVerdict.fallback(
                error_message=f"Malformed JSON in model response: {exc}",
                model=self.model,
                analyzed_at=analyzed_at,
            )

        if not isinstance(data, dict):
            return AIVerdict.fallback(
                error_message=f"Model response is not a JSON object: {type(data).__name__}",
                model=self.model,
                analyzed_at=analyzed_at,
            )

        # Validate required fields and enums
        try:
            return self._build_verdict(
                data=data,
                tokens_used=tokens_used,
                analyzed_at=analyzed_at,
            )
        except ValueError as exc:
            return AIVerdict.fallback(
                error_message=f"Schema validation failed: {exc}",
                model=self.model,
                analyzed_at=analyzed_at,
            )

    def _build_verdict(
        self,
        data: Dict[str, Any],
        tokens_used: Optional[int],
        analyzed_at: str,
    ) -> AIVerdict:
        """
        Construct and validate an :class:`AIVerdict` from a parsed dict.

        Raises :class:`ValueError` on any schema violation so the
        caller can convert it to a fallback verdict.
        """
        # Required string/bool fields
        should_alert = _require_bool(data, "should_alert")
        severity = _require_str(data, "severity")
        confidence = _require_int(data, "confidence")
        category = _require_str(data, "category")
        title = _require_str(data, "title")
        summary = _require_str(data, "summary")
        reasoning = _require_str(data, "reasoning")
        dedup_key = _require_str(data, "dedup_key")

        # Optional list field (default to empty list if missing)
        recommended_actions_raw = data.get("recommended_actions", [])
        if not isinstance(recommended_actions_raw, list):
            # Some models occasionally return a single string — accept it.
            if isinstance(recommended_actions_raw, str):
                recommended_actions = [recommended_actions_raw]
            else:
                raise ValueError(
                    f"Field 'recommended_actions' must be a list, got "
                    f"{type(recommended_actions_raw).__name__}"
                )
        else:
            recommended_actions = [str(a) for a in recommended_actions_raw]

        # Validate enums
        if severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Field 'severity' must be one of {VALID_SEVERITIES}, "
                f"got {severity!r}"
            )

        if category not in VALID_CATEGORIES:
            # Don't hard-fail on unknown categories — accept but warn.
            # The model may emit a slightly-off label that still carries
            # useful information. The fallback path is for genuinely
            # broken responses, not borderline labels.
            pass

        # Validate confidence range
        if not (0 <= confidence <= 100):
            raise ValueError(
                f"Field 'confidence' must be 0-100, got {confidence}"
            )

        return AIVerdict(
            should_alert=should_alert,
            severity=severity,
            confidence=confidence,
            category=category,
            title=title,
            summary=summary,
            reasoning=reasoning,
            recommended_actions=recommended_actions,
            dedup_key=dedup_key,
            model=self.model,
            analyzed_at=analyzed_at,
            tokens_used=tokens_used,
        )


# ── Internal helpers ────────────────────────────────────────────────────

_CODE_FENCE_RE = re.compile(
    r"^```(?:json)?\s*\n(.*?)\n```\s*$",
    re.DOTALL | re.IGNORECASE,
)


def _strip_code_fences(text: str) -> str:
    """
    Strip leading/trailing markdown code fences if present.

    The model occasionally wraps its JSON in `````json ... ````` despite
    being told not to. This helper removes that wrapper so ``json.loads``
    can parse the inner content.
    """
    stripped = text.strip()
    match = _CODE_FENCE_RE.match(stripped)
    if match:
        return match.group(1).strip()
    return stripped


def _require_bool(data: Dict[str, Any], field: str) -> bool:
    """Extract a required bool field, raising ValueError if missing/wrong type."""
    if field not in data:
        raise ValueError(f"Missing required field: {field!r}")
    value = data[field]
    if not isinstance(value, bool):
        raise ValueError(
            f"Field {field!r} must be a bool, got {type(value).__name__}"
        )
    return value


def _require_int(data: Dict[str, Any], field: str) -> int:
    """Extract a required int field, raising ValueError if missing/wrong type."""
    if field not in data:
        raise ValueError(f"Missing required field: {field!r}")
    value = data[field]
    # Accept ints only — NOT bools (bool is a subclass of int in Python)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"Field {field!r} must be an int, got {type(value).__name__}"
        )
    return value


def _require_str(data: Dict[str, Any], field: str) -> str:
    """Extract a required string field, raising ValueError if missing/wrong type."""
    if field not in data:
        raise ValueError(f"Missing required field: {field!r}")
    value = data[field]
    if not isinstance(value, str):
        raise ValueError(
            f"Field {field!r} must be a string, got {type(value).__name__}"
        )
    return value