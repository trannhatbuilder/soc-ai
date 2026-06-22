"""Alert Detector — produces AlertEvent and HeartbeatEvent from AnalyzedLog.

The detector is the bridge between the AI analysis stage and the
Telegram notification stage.  It reads :class:`AnalyzedLog` entries
(the output of ``soc_ai.ai.pipeline``) and decides what kind of
notification event to emit:

  - **AlertEvent**  — when ``verdict.should_alert == True``.
  - **HeartbeatEvent** — when **1 hour** has elapsed with no alerts.

Heartbeat logic
---------------
A heartbeat (monitoring message) is sent when the time since the
*last notification* (alert or heartbeat) exceeds the configured
threshold (default: 1 hour).  After a heartbeat is sent the timer
resets, so the next heartbeat will not arrive for another hour of
silence.

State persistence
-----------------
The ``last_notification_at`` timestamp is persisted to a JSON file
(``.cache/alert_state.json`` by default) so the timer survives across
pipeline runs.  On the very first run (no state file), the timer
starts from the current time — no heartbeat is sent immediately.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from soc_ai.aggregation.schemas import AggregatedLog
from soc_ai.ai.schemas import AIVerdict, AnalyzedLog
from soc_ai.alert.schemas import AlertEvent, HeartbeatEvent, EVENT_TYPE_ALERT, EVENT_TYPE_HEARTBEAT


# ── Public constants ────────────────────────────────────────────────────

DEFAULT_STATE_FILE: str = ".cache/alert_state.json"
DEFAULT_HEARTBEAT_INTERVAL_HOURS: float = 1.0


# ── Detector ────────────────────────────────────────────────────────────

class AlertDetector:
    """
    Stateful alert detector that converts :class:`AnalyzedLog` entries
    into :class:`AlertEvent` or :class:`HeartbeatEvent` objects.

    The detector maintains a persistent ``last_notification_at``
    timestamp so the 1-hour heartbeat interval is respected across
    multiple pipeline runs.

    Parameters
    ----------
    state_file : str, optional
        Path to the JSON file used for persisting state.
        Defaults to ``.cache/alert_state.json``.
    heartbeat_interval_hours : float, optional
        Number of hours of silence before a heartbeat is sent.
        Defaults to 1.0 (1 hour).
    """

    def __init__(
        self,
        state_file: Optional[str] = None,
        heartbeat_interval_hours: Optional[float] = None,
    ) -> None:
        self.state_file = Path(state_file or DEFAULT_STATE_FILE)
        self.heartbeat_interval_hours = (
            heartbeat_interval_hours
            if heartbeat_interval_hours is not None
            else DEFAULT_HEARTBEAT_INTERVAL_HOURS
        )

        # ── Internal state ────────────────────────────────────────────
        # last_notification_at: timestamp of last alert or heartbeat
        self._last_notification_at: Optional[str] = None

        # Counters since last notification (for heartbeat metadata)
        self._windows_since_last: int = 0
        self._events_since_last: int = 0

        # Track whether a heartbeat was already generated in the
        # current silence period (prevents duplicate heartbeats in
        # the same batch).
        self._heartbeat_sent_this_period: bool = False

        # ── Load persisted state ───────────────────────────────────────
        self._load_state()

    # ── Public API ────────────────────────────────────────────────────

    def detect(
        self,
        analyzed: AnalyzedLog,
    ) -> List[Union[AlertEvent, HeartbeatEvent]]:
        """
        Process a single :class:`AnalyzedLog` and return zero or more
        events.

        Returns
        -------
        list[AlertEvent | HeartbeatEvent]
            - Empty list when the window is not alert-worthy and the
              heartbeat interval has not been reached.
            - One :class:`AlertEvent` when ``should_alert == True``.
            - One :class:`HeartbeatEvent` when the silence interval
              has been exceeded (no alert for 1+ hours).
            - Potentially both if the window is non-alerting AND the
              heartbeat threshold is reached.
        """
        events: List[Union[AlertEvent, HeartbeatEvent]] = []
        now = datetime.now(timezone.utc).isoformat()

        # ── Check for alert ───────────────────────────────────────────
        if analyzed.verdict.should_alert:
            alert = AlertEvent.from_analyzed_log(
                aggregated=analyzed.aggregated,
                verdict=analyzed.verdict,
                detected_at=now,
            )
            events.append(alert)

            # Reset silence tracking
            self._last_notification_at = now
            self._windows_since_last = 0
            self._events_since_last = 0
            self._heartbeat_sent_this_period = False
            self._save_state()
        else:
            # Not alert-worthy — accumulate silence counters
            self._windows_since_last += 1
            self._events_since_last += analyzed.aggregated.event_count

            # ── Check for heartbeat ────────────────────────────────────
            if self._should_send_heartbeat(now):
                heartbeat = HeartbeatEvent(
                    generated_at=now,
                    last_alert_at=self._last_notification_at,
                    hours_since_last_alert=self._hours_since_last_notification(now),
                    windows_processed=self._windows_since_last,
                    total_events_processed=self._events_since_last,
                )
                events.append(heartbeat)

                # Reset silence tracking (heartbeat counts as notification)
                self._last_notification_at = now
                self._windows_since_last = 0
                self._events_since_last = 0
                self._heartbeat_sent_this_period = True
                self._save_state()

        return events

    def detect_batch(
        self,
        analyzed_logs: List[AnalyzedLog],
    ) -> List[Union[AlertEvent, HeartbeatEvent]]:
        """
        Process a batch of :class:`AnalyzedLog` entries and return
        all emitted events.

        Events are returned in the order they were produced (alert
        events interleaved with heartbeat events if the silence
        threshold is crossed mid-batch).
        """
        all_events: List[Union[AlertEvent, HeartbeatEvent]] = []

        for analyzed in analyzed_logs:
            events = self.detect(analyzed)
            all_events.extend(events)

        return all_events

    def reset_state(self) -> None:
        """Clear all persisted and in-memory state."""
        self._last_notification_at = None
        self._windows_since_last = 0
        self._events_since_last = 0
        self._heartbeat_sent_this_period = False

        if self.state_file.exists():
            self.state_file.unlink()

    # ── Properties ────────────────────────────────────────────────────

    @property
    def last_notification_at(self) -> Optional[str]:
        """ISO 8601 timestamp of the last alert or heartbeat."""
        return self._last_notification_at

    @property
    def windows_since_last_notification(self) -> int:
        """Number of windows processed since last notification."""
        return self._windows_since_last

    @property
    def events_since_last_notification(self) -> int:
        """Number of raw events since last notification."""
        return self._events_since_last

    # ── Internal helpers ──────────────────────────────────────────────

    def _should_send_heartbeat(self, now_iso: str) -> bool:
        """
        Return True if enough time has elapsed since the last
        notification to warrant a heartbeat.

        On the very first run (no previous notification), do NOT
        send a heartbeat — the timer starts from "now".
        """
        if self._last_notification_at is None:
            return False

        if self._heartbeat_sent_this_period:
            return False

        hours = self._hours_since_last_notification(now_iso)
        return hours >= self.heartbeat_interval_hours

    def _hours_since_last_notification(self, now_iso: str) -> float:
        """Compute hours elapsed since last notification."""
        if self._last_notification_at is None:
            return 0.0

        try:
            now = datetime.fromisoformat(now_iso)
            last = datetime.fromisoformat(self._last_notification_at)
            delta = now - last
            return delta.total_seconds() / 3600.0
        except (ValueError, TypeError):
            return 0.0

    # ── State persistence ─────────────────────────────────────────────

    def _load_state(self) -> None:
        """
        Load persisted state from the state file.

        If the file is missing or corrupt, the detector starts with
        ``last_notification_at = None`` (first-run behaviour: timer
        starts from the current time on first detect() call).
        """
        if not self.state_file.exists():
            return

        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            self._last_notification_at = data.get("last_notification_at")
            self._windows_since_last = data.get("windows_since_last", 0)
            self._events_since_last = data.get("events_since_last", 0)
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable — start fresh
            self._last_notification_at = None

    def _save_state(self) -> None:
        """
        Persist current state to the state file.

        Parent directories are created automatically.
        """
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "last_notification_at": self._last_notification_at,
            "windows_since_last": self._windows_since_last,
            "events_since_last": self._events_since_last,
        }

        self.state_file.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )