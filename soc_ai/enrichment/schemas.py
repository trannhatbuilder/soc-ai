"""
Data models for the Enrichment module.

IPEnrichment  — compact threat-intelligence data for a single public IP.
EnrichedLog   — a NormalizedLog with enrichment data attached.

Design principles (v2):
  - No duplication: fields already in NormalizedLog (src_ip, dst_ip,
    src_country, etc.) are NOT repeated in the enrichment.
  - No noise: private/internal/invalid IPs are simply not enriched
    (they do not appear in the ``enrichments`` dict at all).
  - Dict-keyed by IP: O(1) lookup instead of scanning a list.
  - Renamed ``threat_severity`` to avoid clash with NormalizedLog.severity.
  - Removed low-value fields: first_seen, expiry_status, indicator_type,
    raw_ref, tags, reason.
"""

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional

from soc_ai.normalized.schemas import NormalizedLog


@dataclass
class IPEnrichment:
    """
    Compact threat-intelligence enrichment for a single public IP address.

    Only fields that add value beyond what NormalizedLog already provides
    are included.  Empty/None values are stripped during serialisation.
    """

    source: str                         # Provider name (e.g. "AbuseIPDB")
    confidence_score: int               # Abuse confidence score (0-100)
    threat_severity: str                # critical / high / medium / low / none
    reputation: str                     # malicious / suspicious / benign / unknown
    category: str                       # known_malicious / suspicious / clean

    # ── Context (only when available) ────────────────────────────────
    usage_type: Optional[str] = None    # e.g. "Data Center/Web Hosting/Transit"
    is_tor: Optional[bool] = None       # Tor exit node
    is_whitelisted: Optional[bool] = None  # Whitelisted on provider
    top_categories: Optional[List[str]] = None  # Top attack categories
    total_reports: Optional[int] = None        # Total report count
    distinct_reporters: Optional[int] = None   # Number of distinct reporters
    last_seen: Optional[str] = None     # Last reported timestamp

    # ── Error tracking (for failed lookups) ──────────────────────────
    lookup_error: Optional[str] = None  # Error description if lookup failed

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a dict, stripping None / empty values."""
        raw = asdict(self)
        return _remove_empty_values(raw)


@dataclass
class EnrichedLog(NormalizedLog):
    """
    A NormalizedLog with enrichment data attached.

    The ``enrichments`` dict is keyed by public IP address, so looking up
    the enrichment for a specific IP is O(1).  Private/internal/invalid IPs
    are NOT present — they are simply skipped during enrichment.
    """

    enrichments: Dict[str, IPEnrichment] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full enriched log to a dict."""
        result = super().to_dict()
        # Override enrichments to use to_dict on each value
        result["enrichments"] = {
            ip: enrichment.to_dict()
            for ip, enrichment in self.enrichments.items()
        }
        return result

    @classmethod
    def from_normalized(
        cls,
        normalized: NormalizedLog,
        enrichments: Optional[Dict[str, IPEnrichment]] = None,
    ) -> "EnrichedLog":
        """
        Create an EnrichedLog from a NormalizedLog instance.

        All fields from NormalizedLog are carried over; ``enrichments``
        defaults to an empty dict if not provided.
        """
        return cls(
            event_id=normalized.event_id,
            timestamp=normalized.timestamp,
            log_source=normalized.log_source,
            log_type=normalized.log_type,
            log_subtype=normalized.log_subtype,
            severity=normalized.severity,
            device_name=normalized.device_name,
            device_id=normalized.device_id,
            virtual_domain=normalized.virtual_domain,
            src_ip=normalized.src_ip,
            dst_ip=normalized.dst_ip,
            src_port=normalized.src_port,
            dst_port=normalized.dst_port,
            protocol=normalized.protocol,
            action=normalized.action,
            src_interface=normalized.src_interface,
            dst_interface=normalized.dst_interface,
            src_country=normalized.src_country,
            dst_country=normalized.dst_country,
            detail=normalized.detail,
            raw_log=normalized.raw_log,
            parse_status=normalized.parse_status,
            parse_errors=list(normalized.parse_errors),
            normalizer_version=normalized.normalizer_version,
            enrichments=enrichments or {},
        )

def _remove_empty_values(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove keys whose values are None, empty string, empty list, or empty dict."""
    cleaned: Dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        if value == "":
            continue
        if value == []:
            continue
        if value == {}:
            continue
        cleaned[key] = value
    return cleaned