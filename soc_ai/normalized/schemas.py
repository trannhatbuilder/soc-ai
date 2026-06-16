"""
Data models for the Normalized Log module.

All raw log sources are transformed into the NormalizedLog structure
before being passed to downstream stages (deduplication, enrichment, etc.).
"""

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedLog:
    """
    Unified log representation across all log sources.

    Core fields are always populated (when available in the raw log).
    Type-specific fields that do not map to a core field are preserved
    in the ``detail`` dict for later use.
    """

    # ── Core fields (always present when available) ──────────────────
    event_id: str           # Unique identifier (UUID or composite key)
    timestamp: str          # ISO 8601 (e.g. 2026-06-15T02:42:11+08:00)
    log_source: str         # Origin system (fortigate, windows, etc.)
    log_type: str           # Primary type (traffic, event, utm, ...)
    log_subtype: str        # Sub-type (forward, dns, anomaly, ...)
    severity: str           # Normalised severity: critical / high / medium / low / info

    # ── Device info ──────────────────────────────────────────────────
    device_name: str        # devname / hostname
    device_id: str          # devid / device serial

    # ── Network (nullable for non-network events) ────────────────────
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None       # Human-readable protocol name
    action: Optional[str] = None
    

    # ── Type-specific fields (preserved as-is) ───────────────────────
    detail: Dict[str, Any] = field(default_factory=dict)

    # ── Metadata ─────────────────────────────────────────────────────
    raw_log: Optional[str] = None        # Original raw line (for debugging)
    parse_status: str = "success"        # success / partial / failed
    parse_errors: List[str] = field(default_factory=list)
    normalizer_version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary."""
        return asdict(self)