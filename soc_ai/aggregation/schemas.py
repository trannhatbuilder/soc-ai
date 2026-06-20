"""Data models for the Aggregation module.

An :class:`AggregatedLog` is a *container* that groups all
:class:`EnrichedLog` entries which fall into the same 5-minute tumbling
window and share the same ``log_source``. It deliberately does NOT
inherit from :class:`EnrichedLog`, because an aggregated entry
represents many logs, not a single log — copying fields like
``event_id``, ``src_ip``, ``dst_ip`` from a single representative
would be misleading and would duplicate information that is already
present inside the ``logs`` list.

Design principles:
  - Minimal: only fields that the downstream AI analysis stage needs.
  - No duplication: detailed per-log context lives inside ``logs``;
    the container only carries summary counts and window metadata.
  - Counts account for dedup: ``event_count`` is the sum of every
    log's ``dedup_count`` (so a window containing one log with
    ``dedup_count=5`` reports ``event_count=5``, not ``1``).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from soc_ai.enrichment.schemas import EnrichedLog


@dataclass
class AggregatedLog:
    """
    A 5-minute tumbling window of :class:`EnrichedLog` entries.

    One :class:`AggregatedLog` corresponds to one output line in the
    aggregated JSONL file. The downstream AI analysis stage reads
    exactly one such entry at a time and produces a verdict (alert or
    no-alert) for that window.

    Fields
    ------
    window_start : str
        ISO 8601 timestamp marking the inclusive start of the
        5-minute window (e.g. ``"2026-06-15T00:00:00+08:00"``).
    window_end : str
        ISO 8601 timestamp marking the exclusive end of the window
        (``window_start + 5 minutes``).
    log_source : str
        The log source shared by every entry in this window
        (e.g. ``"fortigate"``, ``"windows"``). Logs from different
        sources are never mixed in the same window, so the AI always
        receives a homogeneous batch.
    event_count : int
        Total number of raw events represented in this window. This
        is the sum of every :class:`EnrichedLog`'s ``dedup_count``
        (so duplicate-but-collapsed events still count toward the
        total). Useful for alert rules such as "alert if
        ``event_count > 50`` in 5 minutes".
    unique_log_count : int
        Number of distinct :class:`EnrichedLog` entries in this
        window (i.e. ``len(logs)``). Always ``<= event_count``.
    malicious_ip_count : int
        Number of distinct public IPs in this window whose
        enrichment data marks them as malicious
        (``IPEnrichment.is_malicious == True``). Zero when there are
        no malicious IPs in the window.
    logs : list[EnrichedLog]
        The actual enriched log entries that fall into this window.
        The AI analysis stage reads this list to produce its verdict.
    """

    # ── Window metadata ──────────────────────────────────────────────
    window_start: str
    window_end: str
    log_source: str

    # ── Summary counts ───────────────────────────────────────────────
    event_count: int = 0
    unique_log_count: int = 0
    malicious_ip_count: int = 0

    # ── The actual logs in this window ───────────────────────────────
    logs: List[EnrichedLog] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise to a plain dict suitable for JSONL output.

        Each entry in ``logs`` is serialised via
        :meth:`EnrichedLog.to_dict`, which itself preserves every
        upstream field (NormalizedLog + dedup metadata + enrichments).
        """
        return {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "log_source": self.log_source,
            "event_count": self.event_count,
            "unique_log_count": self.unique_log_count,
            "malicious_ip_count": self.malicious_ip_count,
            "logs": [log.to_dict() for log in self.logs],
        }

    @classmethod
    def from_logs(
        cls,
        window_start: str,
        window_end: str,
        logs: List[EnrichedLog],
    ) -> "AggregatedLog":
        """
        Build an :class:`AggregatedLog` from a list of enriched logs
        that are already known to fall into the same window.

        Summary counts are computed automatically:

          - ``event_count``    = sum of ``log.dedup_count``
          - ``unique_log_count`` = ``len(logs)``
          - ``malicious_ip_count`` = number of distinct IPs whose
            enrichment has ``is_malicious == True``
          - ``log_source`` is taken from the first log in the list
            (callers must ensure all logs in a window share the same
            source — see :mod:`soc_ai.aggregation.aggregator`).

        Parameters
        ----------
        window_start : str
            ISO 8601 timestamp of the inclusive window start.
        window_end : str
            ISO 8601 timestamp of the exclusive window end.
        logs : list[EnrichedLog]
            Enriched log entries that fall into this window. Must be
            non-empty (the aggregator never emits empty windows).

        Returns
        -------
        AggregatedLog
        """
        if not logs:
            raise ValueError(
                "Cannot build AggregatedLog from an empty log list — "
                "the aggregator must skip empty windows."
            )

        # event_count = sum of dedup_count (collapsed duplicates still count)
        event_count = sum(log.dedup_count for log in logs)

        # malicious_ip_count = distinct IPs flagged as malicious
        malicious_ips: set = set()
        for log in logs:
            for ip, enrichment in log.enrichments.items():
                if enrichment.is_malicious:
                    malicious_ips.add(ip)

        return cls(
            window_start=window_start,
            window_end=window_end,
            log_source=logs[0].log_source,
            event_count=event_count,
            unique_log_count=len(logs),
            malicious_ip_count=len(malicious_ips),
            logs=logs,
        )