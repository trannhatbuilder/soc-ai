"""Deduplication pipeline — reads normalized logs, removes duplicates,
and writes DeduplicatedLog JSONL output.

Flow:

    NormalizedLog JSONL  ->  LogDeduplicator  ->  DeduplicatedLog JSONL

Pipeline position (per the original evvolabs architecture):

    Raw Logs
      -> Normalize Logs
      -> Deduplicate Logs          
      -> Data Enrichment
      -> Log Aggregation
      -> AI Log Analysis
      -> Alert Detection
      -> Send Alert to Telegram

Putting dedup BEFORE enrichment reduces the number of paid API calls
(AbuseIPDB, VirusTotal) by collapsing duplicate log entries before
they reach the enrichment layer.

Usage (CLI):
    python -m soc_ai.dedup.pipeline <input_jsonl> <output_jsonl>

Usage (API):
    from soc_ai.dedup.pipeline import dedup_pipeline

    dedup_pipeline(
        input_file="output/normalized_fortigate.jsonl",
        output_file="output/deduplicated_fortigate.jsonl",
    )
"""

import argparse
import json
from pathlib import Path
from typing import List

from soc_ai.dedup.deduplicator import LogDeduplicator
from soc_ai.dedup.schemas import DeduplicatedLog
from soc_ai.normalized.schemas import NormalizedLog


# ── IO helpers ──────────────────────────────────────────────────────────

def read_normalized_jsonl(input_file: str) -> List[NormalizedLog]:
    """
    Read a JSONL file of normalized logs and return NormalizedLog objects.

    Malformed lines are captured as failed-parse NormalizedLog entries
    rather than being dropped silently. This mirrors the behaviour of
    ``soc_ai.enrichment.pipeline.read_normalized_jsonl`` so that the
    dedup pipeline is forgiving on slightly-dirty input.

    Parameters
    ----------
    input_file : str
        Path to the normalized JSONL file (typically the output of
        ``soc_ai.normalized.pipeline``).

    Returns
    -------
    list[NormalizedLog]
        Parsed normalized log entries. Lines that failed to parse are
        returned as ``NormalizedLog`` instances with
        ``parse_status="failed"``.
    """
    logs: List[NormalizedLog] = []

    with open(input_file, "r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                logs.append(NormalizedLog(**data))
            except (json.JSONDecodeError, TypeError) as exc:
                logs.append(
                    NormalizedLog(
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


def write_deduplicated_jsonl(
    output_file: str,
    deduped_logs: List[DeduplicatedLog],
) -> None:
    """
    Write a list of DeduplicatedLog objects to a JSONL file.

    Each line is the JSON serialisation of ``DeduplicatedLog.to_dict()``,
    which includes all inherited ``NormalizedLog`` fields plus the two
    dedup metadata fields (``dedup_key`` and ``dedup_count``).

    Parameters
    ----------
    output_file : str
        Path for the output JSONL file. Parent directories are created
        automatically.
    deduped_logs : list[DeduplicatedLog]
        Deduplicated log entries to write.
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as fh:
        for log in deduped_logs:
            fh.write(json.dumps(log.to_dict(), ensure_ascii=False) + "\n")


# ── Pipeline entry point ────────────────────────────────────────────────

def dedup_pipeline(
    input_file: str,
    output_file: str,
) -> List[DeduplicatedLog]:
    """
    Full deduplication pipeline: read normalized JSONL -> dedup -> write JSONL.

    Parameters
    ----------
    input_file : str
        Path to the normalized JSONL file (output of the normalize
        pipeline).
    output_file : str
        Path for the deduplicated JSONL output.

    Returns
    -------
    list[DeduplicatedLog]
        The deduplicated representative entries, in first-seen order.
    """
    normalized_logs = read_normalized_jsonl(input_file)
    print(f"[+] Read {len(normalized_logs)} normalized logs from: {input_file}")

    deduper = LogDeduplicator()
    deduped_logs = deduper.deduplicate(normalized_logs)

    # Summary
    print(
        f"[+] Dedup summary: "
        f"seen={deduper.seen_count}, "
        f"kept={deduper.representative_count}, "
        f"collapsed={deduper.collapsed_count}, "
        f"dedup_ratio={deduper.dedup_ratio:.2%}"
    )

    write_deduplicated_jsonl(output_file, deduped_logs)
    print(f"[+] Output saved to: {output_file}")

    return deduped_logs


# ── CLI ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deduplicate normalized logs into a representative JSONL file",
    )
    parser.add_argument(
        "input_file",
        help="Path to the normalized JSONL file",
    )
    parser.add_argument(
        "output_file",
        help="Path for the deduplicated JSONL output",
    )

    args = parser.parse_args()

    dedup_pipeline(
        input_file=args.input_file,
        output_file=args.output_file,
    )


if __name__ == "__main__":
    main()