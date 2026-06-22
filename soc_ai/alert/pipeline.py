"""Alert Detection pipeline — reads analyzed logs, detects alerts and
heartbeat conditions, and writes AlertEvent/HeartbeatEvent JSONL output.

Flow:

    AnalyzedLog JSONL  ->  AlertDetector  ->  AlertEvent/HeartbeatEvent JSONL

Pipeline position (per the original evvolabs architecture):

    Raw Logs
      -> Normalize Logs
      -> Deduplicate Logs
      -> Data Enrichment
      -> Log Aggregation (5-min window)
      -> AI Log Analysis
      -> Alert Detection             <-- this pipeline
      -> Send Telegram

Alert / Heartbeat logic
-----------------------
  - When ``verdict.should_alert == True``  → AlertEvent is emitted.
  - When **1 hour** passes with no alert   → HeartbeatEvent is emitted
    (monitoring / liveness message).
  - The ``last_notification_at`` timestamp is persisted to
    ``.cache/alert_state.json`` so the 1-hour timer survives across
    pipeline runs.

Input contract
--------------
The standard input is the output of ``soc_ai.ai.pipeline`` — a JSONL
file where each line is one :class:`AnalyzedLog` (an aggregated window
paired with its :class:`AIVerdict`).

Reading the analyzed input correctly requires reconstructing the full
nested object graph (AggregatedLog → EnrichedLog → IPEnrichment),
exactly as the AI analysis pipeline does.

Usage (CLI):
    python -m soc_ai.alert.pipeline <input_jsonl> <output_jsonl>

Usage (API):
    from soc_ai.alert.pipeline import alert_pipeline

    alert_pipeline(
        input_file="output/analyzed_fortigate.jsonl",
        output_file="output/alerts_fortigate.jsonl",
    )
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Union

from soc_ai.aggregation.schemas import AggregatedLog
from soc_ai.ai.schemas import AIVerdict, AnalyzedLog
from soc_ai.alert.detector import AlertDetector
from soc_ai.alert.schemas import (
    AlertEvent,
    HeartbeatEvent,
    EVENT_TYPE_ALERT,
    EVENT_TYPE_HEARTBEAT,
)
from soc_ai.enrichment.schemas import EnrichedLog, IPEnrichment


# ── IO helpers ──────────────────────────────────────────────────────────

def read_analyzed_jsonl(input_file: str) -> List[AnalyzedLog]:
    """
    Read a JSONL file of analyzed logs and return AnalyzedLog objects.

    Each line is one :class:`AnalyzedLog`. The function reconstructs
    the full nested object graph:

      1. For each log in ``aggregated.logs``: reconstruct nested
         :class:`IPEnrichment` objects, then build :class:`EnrichedLog`.
      2. Build :class:`AggregatedLog` via ``from_logs()``.
      3. Build :class:`AIVerdict` from the ``verdict`` dict.
      4. Combine into :class:`AnalyzedLog`.

    Malformed lines are skipped silently with a printed warning.

    Parameters
    ----------
    input_file : str
        Path to the analyzed JSONL file (typically the output of
        ``soc_ai.ai.pipeline``).

    Returns
    -------
    list[AnalyzedLog]
        Parsed analyzed log entries, in file order.
    """
    analyzed: List[AnalyzedLog] = []

    with open(input_file, "r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                entry = _reconstruct_analyzed_log(data)
                analyzed.append(entry)
            except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
                print(
                    f"[!] Skipping malformed analyzed line {line_number}: {exc}"
                )

    return analyzed


def _reconstruct_analyzed_log(data: Dict[str, Any]) -> AnalyzedLog:
    """
    Reconstruct an :class:`AnalyzedLog` from a plain dict.

    Performs the reverse of :meth:`AnalyzedLog.to_dict`:

      1. Reconstruct the ``aggregated`` :class:`AggregatedLog`
         (with nested EnrichedLog and IPEnrichment).
      2. Reconstruct the ``verdict`` :class:`AIVerdict`.
      3. Combine into :class:`AnalyzedLog`.
    """
    # ── Reconstruct AggregatedLog ────────────────────────────────────
    agg_data = data["aggregated"]
    window_start = agg_data["window_start"]
    window_end = agg_data["window_end"]
    raw_logs = agg_data.get("logs", [])

    logs: List[EnrichedLog] = []
    for raw_log in raw_logs:
        # Reconstruct enrichments dict-of-IPEnrichment
        raw_enrichments = raw_log.get("enrichments") or {}
        raw_log["enrichments"] = {
            ip: IPEnrichment(**ip_data)
            for ip, ip_data in raw_enrichments.items()
        }
        logs.append(EnrichedLog(**raw_log))

    if not logs:
        raise ValueError("Aggregated window has no logs")

    aggregated = AggregatedLog.from_logs(
        window_start=window_start,
        window_end=window_end,
        logs=logs,
    )

    # ── Reconstruct AIVerdict ────────────────────────────────────────
    verdict_data = data["verdict"]
    verdict = AIVerdict(
        should_alert=verdict_data["should_alert"],
        severity=verdict_data["severity"],
        confidence=verdict_data["confidence"],
        category=verdict_data["category"],
        title=verdict_data["title"],
        summary=verdict_data["summary"],
        reasoning=verdict_data["reasoning"],
        recommended_actions=verdict_data.get("recommended_actions", []),
        dedup_key=verdict_data.get("dedup_key", ""),
        model=verdict_data.get("model", ""),
        analyzed_at=verdict_data.get("analyzed_at", ""),
        tokens_used=verdict_data.get("tokens_used"),
    )

    return AnalyzedLog(aggregated=aggregated, verdict=verdict)


def write_events_jsonl(
    output_file: str,
    events: List[Union[AlertEvent, HeartbeatEvent]],
) -> None:
    """
    Write a list of AlertEvent/HeartbeatEvent objects to a JSONL file.

    Each line is the JSON serialisation of ``event.to_dict()``, with
    an ``event_type`` discriminator (``"alert"`` or ``"heartbeat"``).

    Parameters
    ----------
    output_file : str
        Path for the output JSONL file. Parent directories are
        created automatically.
    events : list[AlertEvent | HeartbeatEvent]
        Alert and heartbeat events to write.
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")


# ── Pipeline entry point ────────────────────────────────────────────────

def alert_pipeline(
    input_file: str,
    output_file: str,
    heartbeat_interval_hours: float = 1.0,
) -> List[Union[AlertEvent, HeartbeatEvent]]:
    """
    Full alert detection pipeline: read analyzed JSONL -> detect
    alerts/heartbeats -> write JSONL.

    Parameters
    ----------
    input_file : str
        Path to the analyzed JSONL file (output of the AI analysis
        pipeline).
    output_file : str
        Path for the alert/heartbeat JSONL output.
    heartbeat_interval_hours : float, optional
        Number of hours of silence before a heartbeat is sent.
        Defaults to 1.0.

    Returns
    -------
    list[AlertEvent | HeartbeatEvent]
        All emitted events, in the order they were produced.
    """
    analyzed_logs = read_analyzed_jsonl(input_file)
    print(f"[+] Read {len(analyzed_logs)} analyzed windows from: {input_file}")

    detector = AlertDetector(heartbeat_interval_hours=heartbeat_interval_hours)
    events = detector.detect_batch(analyzed_logs)

    # Summary
    alert_count = sum(1 for e in events if e.event_type == EVENT_TYPE_ALERT)
    heartbeat_count = sum(1 for e in events if e.event_type == EVENT_TYPE_HEARTBEAT)

    print(
        f"[+] Alert detection summary: "
        f"total_events={len(events)}, "
        f"alerts={alert_count}, "
        f"heartbeats={heartbeat_count}"
    )

    # Print per-event summary
    for event in events:
        if isinstance(event, AlertEvent):
            v = event.verdict
            print(
                f"    [ALERT] severity={v.severity:8s} "
                f"confidence={v.confidence:3d} "
                f"category={v.category} "
                f"window={event.window_start}"
            )
        elif isinstance(event, HeartbeatEvent):
            print(
                f"    [HEARTBEAT] "
                f"hours_since_last={event.hours_since_last_alert:.1f} "
                f"windows_processed={event.windows_processed} "
                f"events_processed={event.total_events_processed}"
            )

    write_events_jsonl(output_file, events)
    print(f"[+] Output saved to: {output_file}")

    return events


# ── CLI ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect alerts and heartbeats from analyzed log windows",
    )
    parser.add_argument(
        "input_file",
        help="Path to the analyzed JSONL file",
    )
    parser.add_argument(
        "output_file",
        help="Path for the alert/heartbeat JSONL output",
    )
    parser.add_argument(
        "--heartbeat-interval",
        type=float,
        default=1.0,
        help="Hours of silence before heartbeat (default: 1.0)",
    )

    args = parser.parse_args()

    alert_pipeline(
        input_file=args.input_file,
        output_file=args.output_file,
        heartbeat_interval_hours=args.heartbeat_interval,
    )


if __name__ == "__main__":
    main()