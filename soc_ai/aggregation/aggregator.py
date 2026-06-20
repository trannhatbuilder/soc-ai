"""Log Aggregator — groups enriched logs into 5-minute tumbling windows.

Each output :class:`AggregatedLog` corresponds to a single
``(log_source, window_start)`` pair and contains every
:class:`EnrichedLog` whose timestamp falls into that window. Logs from
different sources are never mixed, so the downstream AI analysis stage
always receives a homogeneous batch per window.

Window semantics
----------------
A "tumbling window" of 5 minutes means windows are aligned to the Unix
epoch and never overlap:

    Window 1: 00:00:00 -> 00:05:00   (exclusive end)
    Window 2: 00:05:00 -> 00:10:00
    Window 3: 00:10:00 -> 00:15:00
    ...

A log whose timestamp is ``00:03:42`` falls into Window 1; a log at
``00:05:00`` falls into Window 2 (the boundary belongs to the next
window).

Edge cases
----------
Logs with an empty or unparseable timestamp (e.g. failed-parse
entries produced by upstream readers) cannot be assigned to any
window. They are silently skipped during aggregation, and the count
of skipped logs is exposed via :attr:`LogAggregator.skipped_count`
for diagnostics. Callers that need to keep these entries should
handle them separately before invoking the aggregator.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from soc_ai.aggregation.schemas import AggregatedLog
from soc_ai.enrichment.schemas import EnrichedLog


# ── Public constants ────────────────────────────────────────────────────

# Default window size (in minutes) matches the original evvolabs
# architecture diagram ("Log Aggregation (5-Minute Window)").
DEFAULT_WINDOW_MINUTES: int = 5


# ── Window computation ──────────────────────────────────────────────────

def compute_window_start(
    timestamp: str,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> Optional[str]:
    """
    Compute the inclusive start of the tumbling window that contains
    the given ISO 8601 timestamp.

    Window boundaries are aligned to the Unix epoch and floored to the
    nearest multiple of ``window_minutes``. This means a 5-minute
    window starting at ``00:00:00`` always ends at ``00:05:00``,
    regardless of the input timezone — only the *display* of the
    boundary uses the original timezone offset.

    Parameters
    ----------
    timestamp : str
        ISO 8601 timestamp (e.g. ``"2026-06-15T02:42:11+08:00"``).
    window_minutes : int, optional
        Window size in minutes. Defaults to 5.

    Returns
    -------
    str or None
        ISO 8601 timestamp of the inclusive window start, or ``None``
        when the input is empty or cannot be parsed.
    """
    if not timestamp:
        return None

    try:
        dt = datetime.fromisoformat(timestamp)
    except ValueError:
        return None

    # Floor the POSIX timestamp to the nearest window boundary.
    # This is timezone-safe: epoch is UTC-anchored, so window edges
    # land on global 5-minute marks (HH:00, HH:05, HH:10, ...).
    epoch_seconds = dt.timestamp()
    window_seconds = window_minutes * 60
    window_start_epoch = (int(epoch_seconds) // window_seconds) * window_seconds

    # Preserve the original timezone offset when converting back.
    window_start_dt = datetime.fromtimestamp(
        window_start_epoch,
        tz=dt.tzinfo,
    )
    return window_start_dt.isoformat()


def compute_window_end(
    window_start: str,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> str:
    """
    Compute the exclusive end timestamp of a window.

    Parameters
    ----------
    window_start : str
        ISO 8601 timestamp of the inclusive window start (as returned
        by :func:`compute_window_start`).
    window_minutes : int, optional
        Window size in minutes. Defaults to 5.

    Returns
    -------
    str
        ISO 8601 timestamp of the exclusive window end
        (``window_start + window_minutes``).
    """
    start_dt = datetime.fromisoformat(window_start)
    end_dt = start_dt + timedelta(minutes=window_minutes)
    return end_dt.isoformat()


# ── Aggregator ──────────────────────────────────────────────────────────

class LogAggregator:
    """
    Stateful aggregator that groups :class:`EnrichedLog` entries into
    fixed-size tumbling windows.

    The aggregator maintains an internal ordered map of
    ``(log_source, window_start) -> List[EnrichedLog]``. After all logs
    have been added, :meth:`aggregate` (or :meth:`finalize`) emits one
    :class:`AggregatedLog` per non-empty group, sorted by
    ``(window_start, log_source)`` so the output is in chronological
    order.

    Logs with empty or unparseable timestamps are skipped (and counted
    in :attr:`skipped_count`).

    Usage
    -----
    >>> aggregator = LogAggregator(window_minutes=5)
    >>> aggregated = aggregator.aggregate(enriched_logs)

    Or for streaming use-cases:

    >>> aggregator = LogAggregator(window_minutes=5)
    >>> aggregator.add_batch(chunk_1)
    >>> aggregator.add_batch(chunk_2)
    >>> aggregated = aggregator.finalize()
    """

    def __init__(self, window_minutes: int = DEFAULT_WINDOW_MINUTES) -> None:
        if window_minutes <= 0:
            raise ValueError(
                f"window_minutes must be a positive integer, got {window_minutes}"
            )
        self.window_minutes = window_minutes

        # Ordered mapping: (log_source, window_start) -> list of EnrichedLog
        self._groups: Dict[Tuple[str, str], List[EnrichedLog]] = {}

        # Counters for diagnostics
        self._processed_total: int = 0
        self._skipped_total: int = 0

    # ── Public API ────────────────────────────────────────────────────

    def add_batch(self, logs: List[EnrichedLog]) -> None:
        """
        Add a batch of enriched logs to the aggregator.

        Logs are grouped immediately by ``(log_source, window_start)``
        so memory usage scales with the number of distinct windows
        rather than the total number of logs.

        Parameters
        ----------
        logs : list[EnrichedLog]
            Enriched log entries to add.
        """
        for log in logs:
            self._processed_total += 1

            window_start = compute_window_start(
                log.timestamp,
                self.window_minutes,
            )
            if window_start is None:
                # Cannot assign to a window: skip and count.
                self._skipped_total += 1
                continue

            key = (log.log_source, window_start)
            self._groups.setdefault(key, []).append(log)

    def aggregate(self, logs: List[EnrichedLog]) -> List[AggregatedLog]:
        """
        Convenience method: add a batch and immediately finalize.

        Equivalent to::

            aggregator.add_batch(logs)
            return aggregator.finalize()

        Useful for the common one-shot case where all logs are
        available at once. For streaming use-cases, call
        :meth:`add_batch` repeatedly followed by a single
        :meth:`finalize`.

        Parameters
        ----------
        logs : list[EnrichedLog]
            Enriched log entries to aggregate.

        Returns
        -------
        list[AggregatedLog]
            One aggregated entry per non-empty
            ``(log_source, window_start)`` group, sorted by
            ``(window_start, log_source)``.
        """
        self.add_batch(logs)
        return self.finalize()

    def finalize(self) -> List[AggregatedLog]:
        """
        Emit one :class:`AggregatedLog` per accumulated group.

        Groups are returned sorted by ``(window_start, log_source)``
        so the output is in chronological order, with windows from
        different sources in the same 5-minute block appearing
        alphabetically by source name.

        After this call, the aggregator's state is cleared (see
        :meth:`reset`).

        Returns
        -------
        list[AggregatedLog]
        """
        result: List[AggregatedLog] = []

        for (log_source, window_start), group_logs in sorted(self._groups.items()):
            window_end = compute_window_end(window_start, self.window_minutes)
            result.append(
                AggregatedLog.from_logs(
                    window_start=window_start,
                    window_end=window_end,
                    logs=group_logs,
                )
            )

        self.reset()
        return result

    def reset(self) -> None:
        """Clear all accumulated groups and counters."""
        self._groups.clear()
        self._processed_total = 0
        self._skipped_total = 0

    # ── Diagnostics ───────────────────────────────────────────────────

    @property
    def processed_count(self) -> int:
        """Total number of input logs observed so far (this batch)."""
        return self._processed_total

    @property
    def skipped_count(self) -> int:
        """Number of logs skipped due to empty/unparseable timestamp."""
        return self._skipped_total

    @property
    def group_count(self) -> int:
        """Number of distinct ``(log_source, window_start)`` groups currently held."""
        return len(self._groups)