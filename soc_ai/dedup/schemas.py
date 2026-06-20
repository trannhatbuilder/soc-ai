"""Data models for the Deduplication module.

A ``DeduplicatedLog`` is a :class:`NormalizedLog` with two extra fields
that describe how many raw entries were collapsed into a single
representative entry during deduplication.

Design principles:
  - Inherits all fields from ``NormalizedLog`` so downstream stages
    (enrichment, aggregation, ...) can treat the JSONL output as a
    superset of the normalized format.
  - Only adds two metadata fields (``dedup_key`` and ``dedup_count``);
    no redundant timestamp-like fields are introduced, because the
    semantic dedup key already includes ``timestamp`` at second
    precision, which means duplicate entries always share the same
    timestamp.
  - Failed/partial parses are still passed through (dedup never drops
    entries, it only collapses duplicates).
"""

from dataclasses import dataclass
from typing import Optional

from soc_ai.normalized.schemas import NormalizedLog


@dataclass
class DeduplicatedLog(NormalizedLog):
    """
    A :class:`NormalizedLog` that has passed through deduplication.

    Two normalized logs are considered duplicates when they share the
    same semantic key (see ``deduplicator.py`` for the key definition).
    For each group of duplicates, exactly one representative entry is
    emitted; the rest are discarded. The representative entry carries
    ``dedup_count`` indicating how many raw entries it stands for.

    Fields
    ------
    dedup_key : str
        SHA-256 hex digest of the semantic dedup key. Useful for
        debugging and for tracing why two logs were collapsed.
    dedup_count : int
        Number of raw log entries collapsed into this representative.
        ``1`` means the entry had no duplicates.
    """

    # ── Dedup metadata ───────────────────────────────────────────────
    dedup_key: str = ""
    dedup_count: int = 1

    @classmethod
    def from_normalized(
        cls,
        normalized: NormalizedLog,
        dedup_key: str,
    ) -> "DeduplicatedLog":
        """
        Build a :class:`DeduplicatedLog` from a :class:`NormalizedLog`.

        All fields from the source log are carried over unchanged. The
        ``dedup_key`` is set to the supplied value, and ``dedup_count``
        is initialised to ``1`` (the caller — typically the
        ``LogDeduplicator`` — is responsible for incrementing it when
        duplicates are merged into this representative entry).

        Parameters
        ----------
        normalized : NormalizedLog
            The source normalized log entry.
        dedup_key : str
            Pre-computed SHA-256 dedup key for this entry.

        Returns
        -------
        DeduplicatedLog
            A new deduplicated entry initialised with ``dedup_count=1``.
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
            src_ip=normalized.src_ip,
            dst_ip=normalized.dst_ip,
            src_port=normalized.src_port,
            dst_port=normalized.dst_port,
            protocol=normalized.protocol,
            action=normalized.action,
            detail=normalized.detail,
            raw_log=normalized.raw_log,
            parse_status=normalized.parse_status,
            parse_errors=list(normalized.parse_errors),
            normalizer_version=normalized.normalizer_version,
            dedup_key=dedup_key,
            dedup_count=1,
        )