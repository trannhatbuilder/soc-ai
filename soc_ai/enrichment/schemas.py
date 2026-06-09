from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


@dataclass
class EnrichmentResult:
    indicator_value: str
    indicator_type: str

    matched_source: str
    confidence_score: int
    severity: str
    category: str
    tags: List[str]

    reputation: str
    reason: str

    first_seen: Optional[str]
    last_seen: Optional[str]
    expiry_status: str

    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EnrichedEvent:
    event_id: str
    original_event: Dict[str, Any]
    enrichments: List[EnrichmentResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "original_event": self.original_event,
            "enrichments": [
                enrichment.to_dict()
                for enrichment in self.enrichments
            ],
        }