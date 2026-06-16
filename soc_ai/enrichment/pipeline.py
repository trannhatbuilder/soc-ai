"""
Enrichment pipeline — reads normalized logs, enriches public IPs,
and writes EnrichedLog output.

Flow:
    NormalizedLog JSONL  →  LogEnricher  →  EnrichedLog JSONL

Usage (CLI):
    python -m soc_ai.enrichment.pipeline <input_jsonl> <output_jsonl>

Usage (API):
    from soc_ai.enrichment.pipeline import enrich_pipeline

    enrich_pipeline(
        input_file="output/normalized_fortigate.jsonl",
        output_file="output/enriched_fortigate.jsonl",
    )
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

from soc_ai.enrichment.providers.abuseipdb import AbuseIPDBProvider
from soc_ai.enrichment.schemas import EnrichedLog, IPEnrichment
from soc_ai.normalized.schemas import NormalizedLog


class LogEnricher:
    """
    Enrich NormalizedLog entries with threat intelligence data.

    For each log, public IP addresses (src_ip, dst_ip) are looked up
    via the configured provider(s).  Private/internal/invalid IPs are
    skipped automatically — they do not appear in the output at all.

    The enrichment result is a dict keyed by IP address for O(1) lookup.
    """

    def __init__(
        self,
        abuseipdb: Optional[AbuseIPDBProvider] = None,
    ):
        self.abuseipdb = abuseipdb or AbuseIPDBProvider()

    def enrich(self, log: NormalizedLog) -> EnrichedLog:
        """
        Enrich a single NormalizedLog and return an EnrichedLog.

        Public IPs are looked up on AbuseIPDB.  Private/internal IPs
        are silently skipped (no entry in the enrichments dict).
        Duplicate IPs within the same log are looked up only once.
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

        return EnrichedLog.from_normalized(log, enrichments)

    def enrich_batch(
        self,
        logs: List[NormalizedLog],
    ) -> List[EnrichedLog]:
        """Enrich a batch of NormalizedLog entries."""
        return [self.enrich(log) for log in logs]

def read_normalized_jsonl(input_file: str) -> List[NormalizedLog]:
    """
    Read a JSONL file of normalized logs and return NormalizedLog objects.

    Malformed lines are captured as failed-parse NormalizedLog entries
    rather than being dropped silently.
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
                        virtual_domain="",
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
    """Write a list of EnrichedLog objects to a JSONL file."""
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
    Full enrichment pipeline: read normalized JSONL → enrich → write JSONL.

    Parameters
    ----------
    input_file : str
        Path to the normalised JSONL file (output of the normalize pipeline).
    output_file : str
        Path for the enriched JSONL output.

    Returns
    -------
    list[EnrichedLog]
    """
    normalized_logs = read_normalized_jsonl(input_file)
    print(f"[+] Read {len(normalized_logs)} normalized logs from: {input_file}")

    enricher = LogEnricher()
    enriched_logs = enricher.enrich_batch(normalized_logs)

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
        description="Enrich normalized logs with threat intelligence",
    )
    parser.add_argument(
        "input_file",
        help="Path to the normalized JSONL file",
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