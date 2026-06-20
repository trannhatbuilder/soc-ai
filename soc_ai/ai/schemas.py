"""Data models for the AI Log Analysis module.

Two dataclasses are defined here:

  - :class:`AIVerdict`   — the structured result returned by the Groq
    model for a single aggregated window. The first nine fields
    (``should_alert`` .. ``dedup_key``) follow exactly the contract in
    ``soc_ai/ai/context/06_output_schema.md`` so the model output can
    be parsed without translation. Three additional provenance fields
    (``model``, ``analyzed_at``, ``tokens_used``) are added by this
    module for audit and cost tracking and are NOT part of the model
    output contract.
  - :class:`AnalyzedLog` — a container that wraps an
    :class:`AggregatedLog` (the input window, unchanged) together with
    its :class:`AIVerdict` (the AI's analysis of that window).

``AnalyzedLog`` deliberately does NOT inherit from :class:`AggregatedLog`
because it represents the *combination* of "a window" and "an AI
verdict", not a single enriched log. Inheritance would force every
``AggregatedLog`` field to be redeclared and would blur the boundary
between "what happened" (the window) and "what the AI thinks about it"
(the verdict). Composition keeps the two concerns cleanly separated
and makes the JSONL output easy to read.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from soc_ai.aggregation.schemas import AggregatedLog


# ── Severity vocabulary ─────────────────────────────────────────────────
#
# Per ``06_output_schema.md`` the model only emits these four values.
# ``info`` is intentionally NOT included — when the model decides
# there is no alert, it still picks one of these four severities to
# indicate how serious the (non-alerting) activity would have been.
VALID_SEVERITIES = ("low", "medium", "high", "critical")


# ── Category vocabulary ─────────────────────────────────────────────────
#
# Open list — the model may emit any of these evidence-based
# categories (per ``06_output_schema.md`` and the detection policy).
# The fallback category ``analysis_failed`` is internal-only: it is
# produced by :meth:`AIVerdict.fallback` and never by the model
# itself, but is exposed here so downstream stages can filter on it.
VALID_CATEGORIES = (
    # WAF / web
    "auth_abuse",
    "web_attack",
    "business_abuse",
    "waf_block_rate_anomaly",
    "possible_ddos",
    # VPC / network
    "exposed_service",
    "lateral_movement",
    "reconnaissance",
    # FortiGate-specific (added for the current implementation)
    "malicious_ip_activity",
    "ips_anomaly",
    # Normal / benign
    "internal_db_access_pattern",
    "normal_east_west_app_db_traffic",
    "expected_internal_service_connectivity",
    "normal_internal_to_external_traffic",
    "expected_vpn_activity",
    "expected_application_traffic",
    "internet_scan_noise",
    # Operational
    "telemetry_gap",
    # Internal-only (fallback, never produced by the model)
    "analysis_failed",
)


@dataclass
class AIVerdict:
    """
    Structured result of analyzing one :class:`AggregatedLog` window.

    The first nine fields are the model's output contract
    (see ``soc_ai/ai/context/06_output_schema.md``). The remaining
    three fields (``model``, ``analyzed_at``, ``tokens_used``) are
    added by this module for audit and cost tracking.

    When the model call fails, :meth:`AIVerdict.fallback` produces an
    instance whose ``should_alert`` is ``False`` and whose
    ``category`` is ``"analysis_failed"`` so the pipeline can continue
    without crashing and so downstream stages can identify failed
    analyses without parsing free-text.

    Fields (model output contract)
    ------------------------------
    should_alert : bool
        ``True`` if the AI judges this window to require immediate
        SOC attention. ``False`` otherwise (including the fallback
        verdict).
    severity : str
        One of ``"low"``, ``"medium"``, ``"high"``, ``"critical"``.
        Always ``"low"`` for the fallback verdict (the model contract
        does not include ``"info"``).
    confidence : int
        Integer 0..100 indicating how confident the model is in its
        verdict. ``0`` for the fallback verdict.
    category : str
        Evidence-based category (see :data:`VALID_CATEGORIES`).
        ``"analysis_failed"`` for the fallback verdict.
    title : str
        Concise, specific headline for the window (surfaced in
        Telegram alerts).
    summary : str
        1–3 sentence description of the evidence and scope.
    reasoning : str
        The AI's chain-of-thought explaining why the activity is
        normal, low-signal, or malicious. Stored for audit.
    recommended_actions : list[str]
        Short operational steps proportional to confidence and
        evidence. Surfaced as a bulleted list in Telegram alerts.
    dedup_key : str
        Stable string based on issue type and primary entities.
        Allows the alert-detection stage to deduplicate alerts across
        consecutive windows that describe the same underlying issue.

    Fields (audit / provenance, added by this module)
    -------------------------------------------------
    model : str
        Identifier of the model that produced this verdict
        (e.g. ``"llama-3.3-70b-versatile"``).
    analyzed_at : str
        ISO 8601 timestamp marking when the AI analysis ran.
    tokens_used : int, optional
        Total token usage (prompt + completion) reported by Groq,
        or ``None`` when not available (e.g. on API failure).
    """

    # ── Model output contract (9 fields) ─────────────────────────────
    should_alert: bool
    severity: str
    confidence: int
    category: str
    title: str
    summary: str
    reasoning: str
    recommended_actions: List[str] = field(default_factory=list)
    dedup_key: str = ""

    # ── Provenance / audit (3 fields, added by this module) ─────────
    model: str = ""
    analyzed_at: str = ""
    tokens_used: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise to a plain dict suitable for JSONL output.

        The nine model-output fields are emitted first (in the order
        defined by ``06_output_schema.md``) so the JSONL output is
        easy to eyeball, followed by the three audit fields.
        """
        return {
            "should_alert": self.should_alert,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "title": self.title,
            "summary": self.summary,
            "reasoning": self.reasoning,
            "recommended_actions": list(self.recommended_actions),
            "dedup_key": self.dedup_key,
            "model": self.model,
            "analyzed_at": self.analyzed_at,
            "tokens_used": self.tokens_used,
        }

    @classmethod
    def fallback(
        cls,
        error_message: str,
        model: str = "",
        analyzed_at: str = "",
    ) -> "AIVerdict":
        """
        Build a neutral :class:`AIVerdict` for when the AI call fails.

        The fallback verdict has ``should_alert=False``,
        ``severity="low"`` (the lowest severity permitted by the
        model contract), ``confidence=0``, and
        ``category="analysis_failed"`` so it never triggers a
        spurious alert and downstream stages can identify failed
        analyses by category.

        Parameters
        ----------
        error_message : str
            Description of the failure (e.g. "Groq API timeout after
            30s", "Malformed JSON in model response").
        model : str, optional
            Model identifier that was attempted, if known.
        analyzed_at : str, optional
            ISO 8601 timestamp of when the failure occurred.

        Returns
        -------
        AIVerdict
            A neutral, non-alerting verdict carrying the error message.
        """
        return cls(
            should_alert=False,
            severity="low",
            confidence=0,
            category="analysis_failed",
            title="AI Analysis Failed",
            summary=f"AI analysis failed for this window: {error_message}",
            reasoning=(
                f"The AI analysis stage could not produce a verdict "
                f"for this window. Reason: {error_message}. The "
                f"window has been preserved for manual review; no "
                f"alert was raised as a safety default."
            ),
            recommended_actions=[
                "Manually review the window's logs",
                "Check the AI analyzer logs for the failure cause",
                "Re-run the analysis pipeline once the issue is resolved",
            ],
            dedup_key=f"analysis_failed:{error_message[:80]}",
            model=model,
            analyzed_at=analyzed_at,
            tokens_used=None,
        )


@dataclass
class AnalyzedLog:
    """
    A :class:`AggregatedLog` window paired with its :class:`AIVerdict`.

    One :class:`AnalyzedLog` corresponds to one output line in the
    ``analyzed_*.jsonl`` file. The downstream alert-detection stage
    reads this line and decides whether to fire a Telegram alert
    based primarily on ``verdict.should_alert`` (and optionally on
    ``verdict.severity`` / ``verdict.confidence``).

    Fields
    ------
    aggregated : AggregatedLog
        The original 5-minute window (unchanged). Kept verbatim so
        SOC analysts can always cross-reference the AI verdict with
        the underlying logs.
    verdict : AIVerdict
        The AI's analysis of ``aggregated``.
    """

    aggregated: AggregatedLog
    verdict: AIVerdict

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise to a plain dict suitable for JSONL output.

        The original aggregated window is preserved under the
        ``"aggregated"`` key and the AI verdict is preserved under
        the ``"verdict"`` key, so the structure is self-documenting.
        """
        return {
            "aggregated": self.aggregated.to_dict(),
            "verdict": self.verdict.to_dict(),
        }