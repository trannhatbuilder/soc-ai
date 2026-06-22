"""Data models for the Telegram Notification module.

Two message types are defined, one per event type produced by the
Alert Detection module:

  - :class:`AlertMessage` — formatted for :class:`AlertEvent`.  Includes
    severity emoji, title, summary, recommended actions, window
    metadata, and AI confidence.  Designed to be immediately actionable
    for SOC analysts.
  - :class:`HeartbeatMessage` — formatted for :class:`HeartbeatEvent`.
  Minimal "system alive" message with pipeline-health stats so
  operators know the SOC-AI pipeline is running and no threats were
  detected in the past hour.

Both message types expose a ``text`` property that returns the
Telegram-ready plain-text (with basic markdown) and a ``parse_mode``
property indicating whether Telegram MarkdownV2 or plain text is used.

Design principles
-----------------
  - Human-readable: messages are formatted for quick scanning on
    mobile devices (Telegram's primary use case).
  - Compact: only essential fields are included; full event data
    stays in the JSONL file for post-incident review.
  - Emoji headers: visual distinction between severity levels and
    message types at a glance.
  - No HTML: plain text with MarkdownV2 for broad Telegram client
    compatibility.
"""

from dataclasses import dataclass
from typing import List, Optional

from soc_ai.alert.schemas import AlertEvent, HeartbeatEvent


# ── Severity emoji map ──────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "critical": "\U0001F534",   # 🔴
    "high":     "\U0001F7E0",   # 🟠
    "medium":   "\U0001F7E1",   # 🟡
    "low":      "\U0001F535",   # 🔵
}

HEARTBEAT_EMOJI = "\U0001F493"  # 💓
SHIELD_EMOJI   = "\U0001F6E1"  # 🛡️
ALERT_EMOJI    = "\U0001F6A8"  # 🚨


# ── Alert Message ──────────────────────────────────────────────────────

@dataclass
class AlertMessage:
    """
    A Telegram-formatted alert message built from an :class:`AlertEvent`.

    The message includes:
      - Severity header with emoji
      - Title and summary
      - Confidence score
      - Category and dedup key
      - Window time range
      - Event counts
      - Recommended actions (bulleted list)

    Fields
    ------
    event : AlertEvent
        The source alert event.
    chat_id : str
        Telegram chat ID to send the message to.
    """

    event: AlertEvent
    chat_id: str = ""

    @property
    def parse_mode(self) -> Optional[str]:
        """Telegram parse mode — None means plain text."""
        return None

    @property
    def text(self) -> str:
        """
        Build the Telegram-ready alert message text.

        Uses plain text (no Markdown) for maximum compatibility.
        """
        v = self.event.verdict
        if v is None:
            return f"{ALERT_EMOJI} SOC-AI Alert (verdict missing)"

        emoji = SEVERITY_EMOJI.get(v.severity, ALERT_EMOJI)
        lines: List[str] = []

        # ── Header ────────────────────────────────────────────────────
        lines.append(f"{emoji} [{v.severity.upper()}] {v.title}")
        lines.append("")

        # ── Summary ───────────────────────────────────────────────────
        lines.append(f"Summary: {v.summary}")
        lines.append("")

        # ── Details ───────────────────────────────────────────────────
        lines.append(f"Category: {v.category}")
        lines.append(f"Confidence: {v.confidence}%")
        lines.append(f"Window: {self.event.window_start} -> {self.event.window_end}")
        lines.append(f"Events: {self.event.event_count} | Malicious IPs: {self.event.malicious_ip_count}")
        lines.append(f"Source: {self.event.log_source}")

        if v.dedup_key:
            lines.append(f"Dedup Key: {v.dedup_key}")

        # ── Recommended Actions ───────────────────────────────────────
        if v.recommended_actions:
            lines.append("")
            lines.append("Recommended Actions:")
            for i, action in enumerate(v.recommended_actions, 1):
                lines.append(f"  {i}. {action}")

        return "\n".join(lines)


# ── Heartbeat Message ──────────────────────────────────────────────────

@dataclass
class HeartbeatMessage:
    """
    A Telegram-formatted heartbeat message built from a
    :class:`HeartbeatEvent`.

    The message is deliberately minimal — it only confirms pipeline
    liveness and provides basic statistics.

    Fields
    ------
    event : HeartbeatEvent
        The source heartbeat event.
    chat_id : str
        Telegram chat ID to send the message to.
    """

    event: HeartbeatEvent
    chat_id: str = ""

    @property
    def parse_mode(self) -> Optional[str]:
        """Telegram parse mode — None means plain text."""
        return None

    @property
    def text(self) -> str:
        """Build the Telegram-ready heartbeat message text."""
        lines: List[str] = []

        # ── Header ────────────────────────────────────────────────────
        lines.append(f"{HEARTBEAT_EMOJI} SOC-AI Heartbeat")
        lines.append("")

        # ── Status ────────────────────────────────────────────────────
        lines.append(f"{SHIELD_EMOJI} No alerts in the last {self.event.hours_since_last_alert:.1f} hour(s)")
        lines.append("")

        # ── Stats ─────────────────────────────────────────────────────
        lines.append(f"Windows processed: {self.event.windows_processed}")
        lines.append(f"Events processed: {self.event.total_events_processed}")

        if self.event.last_alert_at:
            lines.append(f"Last alert at: {self.event.last_alert_at}")
        else:
            lines.append("Last alert at: (none since pipeline started)")

        return "\n".join(lines)