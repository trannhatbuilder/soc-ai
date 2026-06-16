"""
Normalization pipeline — reads raw logs, normalizes, and writes JSONL output.

Usage (as script):
    python -m soc_ai.normalized.pipeline <input_file> <output_file> [--source fortigate]
"""

import argparse
import json
from pathlib import Path
from typing import List

from soc_ai.normalized.schemas import NormalizedLog
from soc_ai.normalized.normalizer import LogNormalizer


def read_raw_logs(input_file: str) -> List[str]:
    """
    Read a raw log file and return only actual log lines.

    Skips empty lines, comment lines (starting with #),
    and section-separator lines (starting with === or ###).
    """
    lines: List[str] = []

    with open(input_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()

            if not line:
                continue
            if line.startswith("#"):
                continue
            if line.startswith("==="):
                continue
            if line.startswith("###"):
                continue

            lines.append(line)

    return lines


def write_normalized_jsonl(
    output_file: str,
    normalized_logs: List[NormalizedLog],
) -> None:
    """Write a list of NormalizedLog objects to a JSONL file."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as fh:
        for log in normalized_logs:
            fh.write(json.dumps(log.to_dict(), ensure_ascii=False) + "\n")


def normalize_pipeline(
    input_file: str,
    output_file: str,
    log_source: str = "fortigate",
) -> List[NormalizedLog]:
    """
    Full pipeline: read raw logs → normalize → write JSONL.

    Parameters
    ----------
    input_file : str
        Path to the raw log file.
    output_file : str
        Path for the JSONL output.
    log_source : str
        Log source identifier (determines which parser to use).

    Returns
    -------
    list[NormalizedLog]
        The normalised log entries.
    """
    raw_lines = read_raw_logs(input_file)
    print(f"[+] Read {len(raw_lines)} raw log lines from: {input_file}")

    normalizer = LogNormalizer()
    normalized = normalizer.normalize_lines(raw_lines, log_source)

    # Summary statistics
    success = sum(1 for n in normalized if n.parse_status == "success")
    partial = sum(1 for n in normalized if n.parse_status == "partial")
    failed = sum(1 for n in normalized if n.parse_status == "failed")

    print(f"[+] Normalized: {success} success, {partial} partial, {failed} failed")

    write_normalized_jsonl(output_file, normalized)
    print(f"[+] Output saved to: {output_file}")

    return normalized

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize raw logs into unified JSONL format",
    )
    parser.add_argument(
        "input_file",
        help="Path to the raw log file",
    )
    parser.add_argument(
        "output_file",
        help="Path for the normalized JSONL output",
    )
    parser.add_argument(
        "--source",
        default="fortigate",
        choices=["fortigate"],
        help="Log source type (default: fortigate)",
    )

    args = parser.parse_args()

    normalize_pipeline(
        input_file=args.input_file,
        output_file=args.output_file,
        log_source=args.source,
    )


if __name__ == "__main__":
    main()