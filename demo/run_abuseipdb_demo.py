import json
from pathlib import Path

from soc_ai.enrichment.pipeline import (
    AbuseIPDBLogEnricher,
    read_jsonl,
    write_jsonl,
)


INPUT_FILE = "demo/sample_logs.jsonl"
OUTPUT_FILE = "demo/output_abuseipdb_enriched.jsonl"


def main():
    print("[+] Loading sample logs...")
    events = read_jsonl(INPUT_FILE)

    print(f"[+] Loaded {len(events)} events")

    print("[+] Running AbuseIPDB enrichment...")
    enricher = AbuseIPDBLogEnricher()
    enriched_events = enricher.enrich_events(events)

    write_jsonl(OUTPUT_FILE, enriched_events)

    print(f"[+] Done. Output saved to: {OUTPUT_FILE}")
    print()

    print("[+] Preview:")
    for enriched_event in enriched_events:
        print(json.dumps(enriched_event.to_dict(), indent=2, ensure_ascii=False))
        print("-" * 80)


if __name__ == "__main__":
    main()
