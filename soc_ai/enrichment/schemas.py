"""
Data models for the Enrichment module.

IPEnrichment  — compact threat-intelligence data for a single public IP.
EnrichedLog   — a DeduplicatedLog with enrichment data attached.

Class hierarchy (matches the pipeline order):

    NormalizedLog
        └── DeduplicatedLog        (adds dedup_key, dedup_count)
                └── EnrichedLog    (adds enrichments dict)

This means an EnrichedLog carries the full lineage of every prior
pipeline stage: normalization fields + dedup metadata + enrichment
data. Downstream stages (aggregation, AI analysis, alerting) can
read every field they need from a single object.

Design principles (v3):
  - No duplication: fields already in NormalizedLog (src_ip, dst_ip)
    are NOT repeated in the enrichment.
  - Geo fields (country, city) are stored per-IP in IPEnrichment, so they
    naturally become src_country / dst_country when looked up by IP key.
  - is_malicious: derived boolean (confidence_score >= threshold) for
    quick filtering in downstream rules.
  - No noise: private/internal/invalid IPs are simply not enriched
    (they do not appear in the ``enrichments`` dict at all).
  - Dict-keyed by IP: O(1) lookup instead of scanning a list.
  - Renamed ``threat_severity`` to avoid clash with NormalizedLog.severity.
  - Removed low-value fields: first_seen, last_seen, expiry_status,
    raw_ref, tags, reason.
"""

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional

from soc_ai.dedup.schemas import DeduplicatedLog
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
    is_malicious: bool                  # True if confidence_score >= 50
    threat_severity: str                # critical / high / medium / low / none
    reputation: str                     # malicious / suspicious / benign / unknown
    category: str                       # known_malicious / suspicious / clean

    # ── Geo (from provider) ──────────────────────────────────────────
    country: Optional[str] = None       # 2-letter country code (e.g. "US", "VN")

    # ── Context (only when available) ────────────────────────────────
    usage_type: Optional[str] = None    # e.g. "Data Center/Web Hosting/Transit"
    is_tor: Optional[bool] = None       # Tor exit node
    is_whitelisted: Optional[bool] = None  # Whitelisted on provider
    top_categories: Optional[List[str]] = None  # Top attack categories
    total_reports: Optional[int] = None        # Total report count
    distinct_reporters: Optional[int] = None   # Number of distinct reporters

    # ── Error tracking (for failed lookups) ──────────────────────────
    lookup_error: Optional[str] = None  # Error description if lookup failed

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a dict, stripping None / empty values."""
        raw = asdict(self)
        return _remove_empty_values(raw)


@dataclass
class EnrichedLog(DeduplicatedLog):
    """
    A :class:`DeduplicatedLog` with threat-intelligence enrichment attached.

    Inherits all fields from :class:`DeduplicatedLog` (which in turn
    inherits from :class:`NormalizedLog`), and adds an ``enrichments``
    dict keyed by public IP address. Looking up the enrichment for a
    specific IP is O(1). Private/internal/invalid IPs are NOT present
    — they are simply skipped during enrichment.

    Carrying the dedup metadata (``dedup_key``, ``dedup_count``) through
    to the enriched output lets downstream stages (e.g. aggregation)
    weight events correctly: a log with ``dedup_count=5`` represents
    five collapsed raw entries, not just one.
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
    def from_deduplicated(
        cls,
        dedup: DeduplicatedLog,
        enrichments: Optional[Dict[str, IPEnrichment]] = None,
    ) -> "EnrichedLog":
        """
        Build an :class:`EnrichedLog` from a :class:`DeduplicatedLog`.

        This is the primary factory used by the enrichment pipeline:
        every field of the deduplicated log (including ``dedup_key``
        and ``dedup_count``) is carried over, and the supplied
        ``enrichments`` dict is attached.

        Parameters
        ----------
        dedup : DeduplicatedLog
            The source deduplicated log entry.
        enrichments : dict[str, IPEnrichment], optional
            Threat-intelligence enrichments keyed by public IP.
            Defaults to an empty dict.

        Returns
        -------
        EnrichedLog
        """
        return cls(
            event_id=dedup.event_id,
            timestamp=dedup.timestamp,
            log_source=dedup.log_source,
            log_type=dedup.log_type,
            log_subtype=dedup.log_subtype,
            severity=dedup.severity,
            device_name=dedup.device_name,
            device_id=dedup.device_id,
            src_ip=dedup.src_ip,
            dst_ip=dedup.dst_ip,
            src_port=dedup.src_port,
            dst_port=dedup.dst_port,
            protocol=dedup.protocol,
            action=dedup.action,
            detail=dedup.detail,
            raw_log=dedup.raw_log,
            parse_status=dedup.parse_status,
            parse_errors=list(dedup.parse_errors),
            normalizer_version=dedup.normalizer_version,
            dedup_key=dedup.dedup_key,
            dedup_count=dedup.dedup_count,
            enrichments=enrichments or {},
        )

    # @classmethod
    # def from_normalized(
    #     cls,
    #     normalized: NormalizedLog,
    #     enrichments: Optional[Dict[str, IPEnrichment]] = None,
    # ) -> "EnrichedLog":
    #     """
    #     Build an :class:`EnrichedLog` from a :class:`NormalizedLog`.

    #     Convenience factory for callers that have a NormalizedLog in
    #     hand but did not run it through the dedup pipeline. The dedup
    #     metadata fields are filled with neutral defaults
    #     (``dedup_key=""``, ``dedup_count=1``).

    #     Prefer :meth:`from_deduplicated` in the standard pipeline
    #     (normalize -> dedup -> enrich) so that the dedup metadata is
    #     preserved end-to-end.

    #     Parameters
    #     ----------
    #     normalized : NormalizedLog
    #         The source normalized log entry.
    #     enrichments : dict[str, IPEnrichment], optional
    #         Threat-intelligence enrichments keyed by public IP.
    #         Defaults to an empty dict.

    #     Returns
    #     -------
    #     EnrichedLog
    #     """
    #     return cls(
    #         event_id=normalized.event_id,
    #         timestamp=normalized.timestamp,
    #         log_source=normalized.log_source,
    #         log_type=normalized.log_type,
    #         log_subtype=normalized.log_subtype,
    #         severity=normalized.severity,
    #         device_name=normalized.device_name,
    #         device_id=normalized.device_id,
    #         src_ip=normalized.src_ip,
    #         dst_ip=normalized.dst_ip,
    #         src_port=normalized.src_port,
    #         dst_port=normalized.dst_port,
    #         protocol=normalized.protocol,
    #         action=normalized.action,
    #         detail=normalized.detail,
    #         raw_log=normalized.raw_log,
    #         parse_status=normalized.parse_status,
    #         parse_errors=list(normalized.parse_errors),
    #         normalizer_version=normalized.normalizer_version,
    #         dedup_key="",
    #         dedup_count=1,
    #         enrichments=enrichments or {},
    #     )


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