import json
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from soc_ai.enrichment.providers.abuseipdb import AbuseIPDBProvider
from soc_ai.enrichment.schemas import EnrichedEvent, EnrichmentResult
from soc_ai.enrichment.normalizers.abuseipdb_normalizer import AbuseIPDBEnrichmentNormalizer


DEFAULT_IP_FIELDS = [
    "source_ip",
    "src_ip",
    "client_ip",
    "remote_ip",
    "destination_ip",
    "dst_ip",
]


class AbuseIPDBLogEnricher:
    def __init__(
        self,
        provider: Optional[AbuseIPDBProvider] = None,
        ip_fields: Optional[List[str]] = None,
        normalizer: Optional[AbuseIPDBEnrichmentNormalizer] = None,
    ):
        self.provider = provider or AbuseIPDBProvider()
        self.ip_fields = ip_fields or DEFAULT_IP_FIELDS
        self.normalizer = normalizer or AbuseIPDBEnrichmentNormalizer()

    def enrich_event(self, event: Dict) -> EnrichedEvent:
        event_id = str(
            event.get("event_id")
            or event.get("id")
            or event.get("request_id")
            or uuid.uuid4()
        )

        enrichments: List[EnrichmentResult] = []
        seen_ips = set()

        for field_name in self.ip_fields:
            ip_value = event.get(field_name)

            if not ip_value:
                continue

            ip_value = str(ip_value).strip()

            if ip_value in seen_ips:
                continue

            seen_ips.add(ip_value)

            result = self.provider.lookup_ip(ip_value)
            result = self.normalizer.compact(result)

            raw_data = result.raw if isinstance(result.raw, dict) else {}
            raw_data = dict(raw_data)
            raw_data["event_field"] = field_name

            enrichments.append(
                EnrichmentResult(
                    indicator_value=result.indicator_value,
                    indicator_type=result.indicator_type,
                    matched_source=result.matched_source,
                    confidence_score=result.confidence_score,
                    severity=result.severity,
                    category=result.category,
                    tags=result.tags + [f"event_field:{field_name}"],
                    reputation=result.reputation,
                    reason=result.reason,
                    first_seen=result.first_seen,
                    last_seen=result.last_seen,
                    expiry_status=result.expiry_status,
                    raw=raw_data,
                )
            )

        return EnrichedEvent(
            event_id=event_id,
            original_event=event,
            enrichments=enrichments,
        )

    def enrich_events(self, events: Iterable[Dict]) -> List[EnrichedEvent]:
        return [
            self.enrich_event(event)
            for event in events
        ]


def read_jsonl(input_file: str) -> List[Dict]:
    events = []

    with open(input_file, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                events.append(
                    {
                        "event_id": f"malformed-line-{line_number}",
                        "parse_error": True,
                        "error_message": str(error),
                        "raw_line": line,
                    }
                )

    return events


def write_jsonl(output_file: str, enriched_events: List[EnrichedEvent]) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        for enriched_event in enriched_events:
            file.write(
                json.dumps(
                    enriched_event.to_dict(),
                    ensure_ascii=False,
                )
                + "\n"
            )