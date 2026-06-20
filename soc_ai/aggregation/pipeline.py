"""Aggregation pipeline — reads enriched logs, groups them into
5-minute tumbling windows, and writes AggregatedLog JSONL output.

Flow:

    EnrichedLog JSONL  ->  LogAggregator  ->  AggregatedLog JSONL

Pipeline position (per the original evvolabs architecture):

    Raw Logs
      -> Normalize Logs
      -> Deduplicate Logs
      -> Data Enrichment
      -> Log Aggregation (5-min window)   
      -> AI Log Analysis
      -> Alert Detection
      -> Send Alert to Telegram

Output contract
---------------
Each line of the output JSONL file is one :class:`AggregatedLog` —
a single ``(log_source, 5-minute window)`` group containing every
:class:`EnrichedLog` that fell into it. The downstream AI analysis
stage reads exactly one such line at a time and produces a verdict
(alert or no-alert) for that window.

Reading the enriched input correctly requires reconstructing the
nested :class:`IPEnrichment` objects inside each log's
``enrichments`` dict (plain ``json.loads`` returns a dict-of-dicts,
not a dict-of-dataclass-instances). This is handled by the
:func:`read_enriched_jsonl` helper below.

Usage (CLI):
    python -m soc_ai.aggregation.pipeline <input_jsonl> <output_jsonl> \\
        [--window-minutes 5]

Usage (API):
    from soc_ai.aggregation.pipeline import aggregate_pipeline

    aggregate_pipeline(
        input_file="output/enriched_fortigate.jsonl",
        output_file="output/aggregated_fortigate.jsonl",
        window_minutes=5,
    )
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from soc_ai.aggregation.aggregator import LogAggregator
from soc_ai.aggregation.schemas import AggregatedLog
from soc_ai.enrichment.schemas import EnrichedLog, IPEnrichment


# ── IO helpers ──────────────────────────────────────────────────────────

def read_enriched_jsonl(input_file: str) -> List[EnrichedLog]:
    """
    Read a JSONL file of enriched logs and return EnrichedLog objects.

    The nested ``enrichments`` dict is reconstructed properly: each
    value is converted from a plain dict (as produced by
    ``json.loads``) into a real :class:`IPEnrichment` instance, so
    downstream code can access typed attributes like
    ``enrichment.is_malicious`` without raising ``AttributeError``.

    Malformed lines are captured as failed-parse EnrichedLog entries
    rather than being dropped silently, mirroring the behaviour of
    the upstream pipeline readers. Failed-parse entries have an
    empty timestamp and are therefore silently skipped by the
    aggregator (counted via ``LogAggregator.skipped_count``).

    Parameters
    ----------
    input_file : str
        Path to the enriched JSONL file (typically the output of
        ``soc_ai.enrichment.pipeline``).

    Returns
    -------
    list[EnrichedLog]
        Parsed enriched log entries with properly typed
        ``enrichments`` dicts.
    """
    logs: List[EnrichedLog] = []

    with open(input_file, "r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                # Reconstruct nested IPEnrichment objects so that
                # attribute access (e.g. enrichment.is_malicious)
                # works correctly inside the aggregator.
                data = _reconstruct_enrichments(data)
                logs.append(EnrichedLog(**data))
            except (json.JSONDecodeError, TypeError) as exc:
                # Failed-parse entry: aggregator will skip it because
                # the timestamp is empty. We still emit the entry so
                # the count of malformed lines is traceable.
                logs.append(
                    EnrichedLog(
                        event_id=f"malformed-line-{line_number}",
                        timestamp="",
                        log_source="unknown",
                        log_type="unknown",
                        log_subtype="unknown",
                        severity="info",
                        device_name="",
                        device_id="",
                        raw_log=line,
                        parse_status="failed",
                        parse_errors=[str(exc)],
                    )
                )

    return logs


def _reconstruct_enrichments(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert the ``enrichments`` dict inside ``data`` from a
    dict-of-dicts into a dict-of-:class:`IPEnrichment`.

    The function mutates a copy of ``data`` and returns it. If the
    ``enrichments`` field is missing or empty, ``data`` is returned
    unchanged (with ``enrichments`` defaulted to an empty dict).
    """
    raw_enrichments = data.get("enrichments") or {}
    data["enrichments"] = {
        ip: IPEnrichment(**ip_data)
        for ip, ip_data in raw_enrichments.items()
    }
    return data


def write_aggregated_jsonl(
    output_file: str,
    aggregated_logs: List[AggregatedLog],
) -> None:
    """
    Write a list of :class:`AggregatedLog` objects to a JSONL file.

    Each line is the JSON serialisation of
    :meth:`AggregatedLog.to_dict`, which preserves every nested
    :class:`EnrichedLog` (and its nested :class:`IPEnrichment`
    objects) inside the ``logs`` array.

    Parameters
    ----------
    output_file : str
        Path for the output JSONL file. Parent directories are
        created automatically.
    aggregated_logs : list[AggregatedLog]
        Aggregated log entries to write.
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as fh:
        for log in aggregated_logs:
            fh.write(json.dumps(log.to_dict(), ensure_ascii=False) + "\n")


# ── Pipeline entry point ────────────────────────────────────────────────

def aggregate_pipeline(
    input_file: str,
    output_file: str,
    window_minutes: int = 5,
) -> List[AggregatedLog]:
    """
    Full aggregation pipeline: read enriched JSONL -> group into
    windows -> write JSONL.

    Parameters
    ----------
    input_file : str
        Path to the enriched JSONL file (output of the enrichment
        pipeline).
    output_file : str
        Path for the aggregated JSONL output.
    window_minutes : int, optional
        Tumbling window size in minutes. Defaults to 5 (matches the
        original evvolabs architecture diagram).

    Returns
    -------
    list[AggregatedLog]
        One aggregated entry per ``(log_source, window_start)``
        group, sorted by ``(window_start, log_source)``.
    """
    enriched_logs = read_enriched_jsonl(input_file)
    print(f"[+] Read {len(enriched_logs)} enriched logs from: {input_file}")

    aggregator = LogAggregator(window_minutes=window_minutes)
    aggregated_logs = aggregator.aggregate(enriched_logs)

    # Summary
    total_events = sum(a.event_count for a in aggregated_logs)
    total_malicious_ips = sum(a.malicious_ip_count for a in aggregated_logs)
    skipped = aggregator.skipped_count

    print(
        f"[+] Aggregation summary (window={window_minutes}min): "
        f"windows={len(aggregated_logs)}, "
        f"total_events={total_events}, "
        f"malicious_ips={total_malicious_ips}, "
        f"skipped={skipped}"
    )

    write_aggregated_jsonl(output_file, aggregated_logs)
    print(f"[+] Output saved to: {output_file}")

    return aggregated_logs


# ── CLI ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Aggregate enriched logs into 5-minute tumbling windows",
    )
    parser.add_argument(
        "input_file",
        help="Path to the enriched JSONL file",
    )
    parser.add_argument(
        "output_file",
        help="Path for the aggregated JSONL output",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=5,
        help="Tumbling window size in minutes (default: 5)",
    )

    args = parser.parse_args()

    aggregate_pipeline(
        input_file=args.input_file,
        output_file=args.output_file,
        window_minutes=args.window_minutes,
    )


if __name__ == "__main__":
    main()