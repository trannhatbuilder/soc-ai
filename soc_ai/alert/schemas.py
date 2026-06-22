"""Data models for the Alert Detection module.

Two event types are produced by the alert detector:

  - :class:`AlertEvent`   — fired when an :class:`AnalyzedLog` window
    has ``verdict.should_alert == True``.  Carries the full AI verdict
    (severity, title, summary, recommended_actions, etc.) so the
    downstream Telegram module can format a rich notification.
  - :class:`HeartbeatEvent` — fired when **1 hour** has elapsed with
    no alerts.  Serves as a "system alive" monitoring message so SOC
    operators know the pipeline is still running and simply has not
    detected any threats worth alerting on.

Both event types share a common ``event_type`` discriminator so the
Telegram sender can dispatch to the right message template without
parsing the full structure.

Design principles
-----------------
  - Composition over inheritance: ``AlertEvent`` wraps an
    :class:`AnalyzedLog` reference (the window + verdict), it does
    NOT inherit from it.  This keeps "what happened" (the analysis)
    cleanly separated from "what we do about it" (the alert).
  - ``HeartbeatEvent`` is deliberately minimal — it only carries
    timing and pipeline-health metadata.  No verdict or log data is
    attached because there is nothing noteworthy to report.
  - Both types serialise to a flat dict suitable for JSONL output.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from soc_ai.ai.schemas import AIVerdict
from soc_ai.aggregation.schemas import AggregatedLog


# ── Event type constants ─────────────────────────────────────────────────

EVENT_TYPE_ALERT = "alert"
EVENT_TYPE_HEARTBEAT = "heartbeat"


# ── Alert Event ──────────────────────────────────────────────────────────

@dataclass
class AlertEvent:
    """
    An alert-worthy event detected from an :class:`AnalyzedLog`.

    Created when ``verdict.should_alert == True``.  The downstream
    Telegram module reads the ``verdict`` fields to compose the alert
    message: title, severity, summary, recommended actions, etc.

    Fields
    ------
    event_type : str
        Always ``"alert"``.  Used by the Telegram sender to dispatch
        to the correct message template.
    detected_at : str
        ISO 8601 timestamp marking when this alert was *detected*
        (i.e. when the alert detector processed the window), not when
        the original log event occurred.
    window_start : str
        ISO 8601 start of the 5-minute window that triggered the alert.
    window_end : str
        ISO 8601 end of the 5-minute window.
    log_source : str
        Log source (e.g. ``"fortigate"``).
    event_count : int
        Total number of raw events in the alerting window.
    malicious_ip_count : int
        Number of distinct malicious IPs in the window.
    verdict : AIVerdict
        The AI verdict that triggered this alert.  All nine model-output
        fields are available here: should_alert, severity, confidence,
        category, title, summary, reasoning, recommended_actions,
        dedup_key.
    """

    event_type: str = EVENT_TYPE_ALERT
    detected_at: str = ""

    # ── Window metadata (from AggregatedLog) ─────────────────────────
    window_start: str = ""
    window_end: str = ""
    log_source: str = ""
    event_count: int = 0
    malicious_ip_count: int = 0

    # ── AI verdict (from AIVerdict) ──────────────────────────────────
    verdict: Optional[AIVerdict] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise to a plain dict suitable for JSONL output.

        The verdict is flattened into a ``"verdict"`` sub-dict so the
        Telegram sender can access every field it needs.
        """
        result: Dict[str, Any] = {
            "event_type": self.event_type,
            "detected_at": self.detected_at,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "log_source": self.log_source,
            "event_count": self.event_count,
            "malicious_ip_count": self.malicious_ip_count,
        }
        if self.verdict is not None:
            result["verdict"] = self.verdict.to_dict()
        else:
            result["verdict"] = None
        return result

    @classmethod
    def from_analyzed_log(
        cls,
        aggregated: AggregatedLog,
        verdict: AIVerdict,
        detected_at: str,
    ) -> "AlertEvent":
        """
        Build an :class:`AlertEvent` from an :class:`AnalyzedLog`.

        This is the primary factory used by the alert detector.
        Window metadata is pulled from the aggregated log; the verdict
        is carried over verbatim.

        Parameters
        ----------
        aggregated : AggregatedLog
            The 5-minute window that triggered the alert.
        verdict : AIVerdict
            The AI's verdict for this window (``should_alert == True``).
        detected_at : str
            ISO 8601 timestamp of when the alert was detected.

        Returns
        -------
        AlertEvent
        """
        return cls(
            event_type=EVENT_TYPE_ALERT,
            detected_at=detected_at,
            window_start=aggregated.window_start,
            window_end=aggregated.window_end,
            log_source=aggregated.log_source,
            event_count=aggregated.event_count,
            malicious_ip_count=aggregated.malicious_ip_count,
            verdict=verdict,
        )


# ── Heartbeat Event ──────────────────────────────────────────────────────

@dataclass
class HeartbeatEvent:
    """
    A monitoring "heartbeat" event sent when no alerts have been
    detected for **1 hour**.

    The purpose is twofold:

      1. **Liveness**: SOC operators know the pipeline is still running.
      2. **Gap detection**: If the heartbeat does NOT arrive within the
         expected interval, something is wrong with the pipeline itself.

    Fields
    ------
    event_type : str
        Always ``"heartbeat"``.
    generated_at : str
        ISO 8601 timestamp of when this heartbeat was generated.
    last_alert_at : str or None
        ISO 8601 timestamp of the most recent alert, if any.
        ``None`` when no alert has ever been recorded.
    hours_since_last_alert : float
        Number of hours elapsed since the last alert.  Always ``>= 1.0``
        because the heartbeat is only generated after 1 hour of silence.
    windows_processed : int
        Total number of analyzed windows processed by the detector
        since the last alert (useful for pipeline-health monitoring).
    total_events_processed : int
        Total number of raw events (sum of event_count) across all
        windows processed since the last alert.
    """

    event_type: str = EVENT_TYPE_HEARTBEAT
    generated_at: str = ""
    last_alert_at: Optional[str] = None
    hours_since_last_alert: float = 0.0
    windows_processed: int = 0
    total_events_processed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict suitable for JSONL output."""
        return {
            "event_type": self.event_type,
            "generated_at": self.generated_at,
            "last_alert_at": self.last_alert_at,
            "hours_since_last_alert": self.hours_since_last_alert,
            "windows_processed": self.windows_processed,
            "total_events_processed": self.total_events_processed,
        }