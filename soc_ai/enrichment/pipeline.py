"""
Enrichment pipeline — reads deduplicated logs, enriches public IPs,
and writes EnrichedLog output.

Flow:

    DeduplicatedLog JSONL  ->  LogEnricher  ->  EnrichedLog JSONL

Pipeline position (per the original evvolabs architecture):

    Raw Logs
      -> Normalize Logs
      -> Deduplicate Logs
      -> Data Enrichment          <-- this pipeline
      -> Log Aggregation
      -> AI Log Analysis
      -> Alert Detection
      -> Send Alert to Telegram

Input contract
--------------
The standard input is the output of ``soc_ai.dedup.pipeline`` — a
JSONL file where each line carries the full NormalizedLog field set
plus the dedup metadata fields (``dedup_key``, ``dedup_count``).

For convenience, this reader also accepts plain normalized JSONL
(output of ``soc_ai.normalized.pipeline``): when the dedup fields
are missing, :class:`DeduplicatedLog` falls back to its defaults
(``dedup_key=""``, ``dedup_count=1``) automatically. This lets the
enrichment pipeline be run in either pipeline order without code
changes, although the recommended order is normalize -> dedup ->
enrich so that paid API calls are minimised.

Usage (CLI):
    python -m soc_ai.enrichment.pipeline <input_jsonl> <output_jsonl>

Usage (API):
    from soc_ai.enrichment.pipeline import enrich_pipeline

    enrich_pipeline(
        input_file="output/deduplicated_fortigate.jsonl",
        output_file="output/enriched_fortigate.jsonl",
    )
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

from soc_ai.dedup.schemas import DeduplicatedLog
from soc_ai.enrichment.providers.abuseipdb import AbuseIPDBProvider
from soc_ai.enrichment.schemas import EnrichedLog, IPEnrichment


class LogEnricher:
    """
    Enrich :class:`DeduplicatedLog` entries with threat-intelligence data.

    For each log, public IP addresses (src_ip, dst_ip) are looked up
    via the configured provider(s).  Private/internal/invalid IPs are
    skipped automatically — they do not appear in the output at all.

    The enrichment result is a dict keyed by IP address for O(1) lookup.

    The dedup metadata (``dedup_key``, ``dedup_count``) on the input
    log is preserved on the output :class:`EnrichedLog`, so downstream
    stages (e.g. aggregation) can weight events correctly.
    """

    def __init__(
        self,
        abuseipdb: Optional[AbuseIPDBProvider] = None,
    ):
        self.abuseipdb = abuseipdb or AbuseIPDBProvider()

    def enrich(self, log: DeduplicatedLog) -> EnrichedLog:
        """
        Enrich a single :class:`DeduplicatedLog` and return an :class:`EnrichedLog`.

        Public IPs are looked up on AbuseIPDB.  Private/internal IPs
        are silently skipped (no entry in the enrichments dict).
        Duplicate IPs within the same log are looked up only once.

        The dedup metadata on the input log is carried over unchanged.
        """
        enrichments: Dict[str, IPEnrichment] = {}
        seen_ips: set = set()

        # Collect unique IPs from src_ip and dst_ip
        for ip in (log.src_ip, log.dst_ip):
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)

            result = self.abuseipdb.lookup(ip)
            if result is not None:
                enrichments[ip] = result

        return EnrichedLog.from_deduplicated(log, enrichments)

    def enrich_batch(
        self,
        logs: List[DeduplicatedLog],
    ) -> List[EnrichedLog]:
        """Enrich a batch of :class:`DeduplicatedLog` entries."""
        return [self.enrich(log) for log in logs]


def read_deduplicated_jsonl(input_file: str) -> List[DeduplicatedLog]:
    """
    Read a JSONL file of deduplicated logs and return DeduplicatedLog objects.

    Each line is parsed into a :class:`DeduplicatedLog`. Because
    :class:`DeduplicatedLog` declares ``dedup_key`` and ``dedup_count``
    with defaults, this function transparently accepts both:

      - Proper deduplicated output (has ``dedup_key``/``dedup_count``).
      - Plain normalized output (no dedup fields — defaults used).

    Malformed lines are captured as failed-parse DeduplicatedLog
    entries rather than being dropped silently, mirroring the
    behaviour of the upstream pipeline readers.

    Parameters
    ----------
    input_file : str
        Path to the input JSONL file. Typically the output of
        ``soc_ai.dedup.pipeline``.

    Returns
    -------
    list[DeduplicatedLog]
        Parsed deduplicated log entries. Lines that failed to parse
        are returned as ``DeduplicatedLog`` instances with
        ``parse_status="failed"``.
    """
    logs: List[DeduplicatedLog] = []

    with open(input_file, "r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                logs.append(DeduplicatedLog(**data))
            except (json.JSONDecodeError, TypeError) as exc:
                logs.append(
                    DeduplicatedLog(
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


def write_enriched_jsonl(
    output_file: str,
    enriched_logs: List[EnrichedLog],
) -> None:
    """Write a list of :class:`EnrichedLog` objects to a JSONL file."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as fh:
        for log in enriched_logs:
            fh.write(json.dumps(log.to_dict(), ensure_ascii=False) + "\n")


# ── Pipeline entry point ────────────────────────────────────────────────

def enrich_pipeline(
    input_file: str,
    output_file: str,
) -> List[EnrichedLog]:
    """
    Full enrichment pipeline: read deduplicated JSONL -> enrich -> write JSONL.

    Parameters
    ----------
    input_file : str
        Path to the deduplicated JSONL file (typically the output of
        ``soc_ai.dedup.pipeline``).
    output_file : str
        Path for the enriched JSONL output.

    Returns
    -------
    list[EnrichedLog]
    """
    dedup_logs = read_deduplicated_jsonl(input_file)
    print(f"[+] Read {len(dedup_logs)} deduplicated logs from: {input_file}")

    enricher = LogEnricher()
    enriched_logs = enricher.enrich_batch(dedup_logs)

    # Summary
    total_enriched_ips = sum(len(e.enrichments) for e in enriched_logs)
    logs_with_enrichment = sum(1 for e in enriched_logs if e.enrichments)

    print(f"[+] Enriched {total_enriched_ips} unique public IPs "
          f"across {logs_with_enrichment}/{len(enriched_logs)} logs")

    write_enriched_jsonl(output_file, enriched_logs)
    print(f"[+] Output saved to: {output_file}")

    return enriched_logs


# ── CLI ──────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich deduplicated logs with threat intelligence",
    )
    parser.add_argument(
        "input_file",
        help="Path to the deduplicated JSONL file",
    )
    parser.add_argument(
        "output_file",
        help="Path for the enriched JSONL output",
    )

    args = parser.parse_args()

    enrich_pipeline(
        input_file=args.input_file,
        output_file=args.output_file,
    )


if __name__ == "__main__":
    main()