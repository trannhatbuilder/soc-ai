"""Log Deduplicator — collapses duplicate NormalizedLog entries.

Two normalised logs are considered duplicates when they share the same
semantic dedup key, which is a SHA-256 hash of the following fields:

    log_source
    log_type
    log_subtype
    device_id
    timestamp                  (ISO 8601, second precision)
    src_ip                     (may be empty)
    dst_ip                     (may be empty)
    src_port                   (may be empty)
    dst_port                   (may be empty)
    action                     (may be empty)
    detail["sessionid"]        (may be empty; VPN/traffic logs)

This corresponds to the "C2 - Semantic" dedup strategy agreed with the
user: two log entries represent the same underlying event when they come
from the same device, at the same second, on the same session between
the same (src_ip, src_port, dst_ip, dst_port) tuple, with the same
network action.

P3 fallback for non-network events
----------------------------------
When ALL of the network-discriminator fields
(``src_ip``, ``dst_ip``, ``src_port``, ``dst_port``, ``action``,
``sessionid``) are empty — which is typical for non-network events such
as FortiGate ``event/security-rating`` reports — the base key alone
would collapse unrelated events that happen to share the same second.
To prevent this, the dedup key is augmented with a stable SHA-256 hash
of the full ``detail`` dict. This keeps the deduplicator generic across
log sources (no FortiGate-specific fields are hardcoded) while still
correctly distinguishing non-network events.

Failed-parse entries are also deduplicated by their own key, which is
derived from the raw line hash. This means repeated identical raw-parse
failures collapse into a single representative entry as well.

The deduplicator preserves insertion order: the first occurrence of each
key becomes the representative, and subsequent duplicates are merged
into it (incrementing ``dedup_count``).
"""

import hashlib
import json
from typing import Any, Dict, List, Optional

from soc_ai.dedup.schemas import DeduplicatedLog
from soc_ai.normalized.schemas import NormalizedLog


# ── Public constants ────────────────────────────────────────────────────

# Names of the NormalizedLog fields used to build the semantic dedup key.
# Kept here so callers (and tests) can introspect the contract.
DEDUP_KEY_FIELDS: List[str] = [
    "log_source",
    "log_type",
    "log_subtype",
    "device_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "action",
    "sessionid",   # sourced from detail["sessionid"]
]

'''Subset of DEDUP_KEY_FIELDS that act as \"network discriminators\". When
 at least one of these is non-empty, the C2 semantic key alone is
 sufficient to tell two logs apart. When ALL of them are empty (e.g.
 non-network events such as FortiGate security-rating reports), the
 dedup key falls back to also hashing the full `detail` dict so that
 two events at the same second with different `detail` content are not
 collapsed (see P3 fallback in `compute_dedup_key`).'''

NETWORK_DISCRIMINATOR_FIELDS: List[str] = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "action",
    "sessionid",
]


# ── Key computation ─────────────────────────────────────────────────────

def compute_dedup_key(log: NormalizedLog) -> str:
    """
    Compute the SHA-256 semantic dedup key for a normalized log entry.

    The base key is built from the fields listed in
    :data:`DEDUP_KEY_FIELDS`. Missing/None values are normalised to the
    empty string so that two logs that both omit ``src_ip`` (e.g.
    non-network events) still hash to the same key component.

    P3 fallback
    -----------
    When ALL of the network-discriminator fields listed in
    :data:`NETWORK_DISCRIMINATOR_FIELDS` are empty (typical for
    non-network events such as FortiGate ``event/security-rating``
    reports), the base key would otherwise collapse unrelated events
    that share the same second. To prevent this, the dedup key is
    augmented with a stable SHA-256 hash of the full ``detail`` dict.
    """
    session_id = ""
    if log.detail and isinstance(log.detail, dict):
        raw_session = log.detail.get("sessionid")
        if raw_session is not None:
            session_id = str(raw_session)

    src_ip_str = _safe_str(log.src_ip)
    dst_ip_str = _safe_str(log.dst_ip)
    src_port_str = _safe_str(log.src_port)
    dst_port_str = _safe_str(log.dst_port)
    action_str = _safe_str(log.action)

    components: List[str] = [
        _safe_str(log.log_source),
        _safe_str(log.log_type),
        _safe_str(log.log_subtype),
        _safe_str(log.device_id),
        _safe_str(log.timestamp),
        src_ip_str,
        dst_ip_str,
        src_port_str,
        dst_port_str,
        action_str,
        session_id,
    ]

    ''' P3 fallback: when no network-discriminator field is set, augment
     the key with a stable hash of the full `detail` dict so that two
     non-network events at the same second with different content are
     not collapsed into one.'''
    network_discriminators = (
        src_ip_str,
        dst_ip_str,
        src_port_str,
        dst_port_str,
        action_str,
        session_id,
    )
    if all(d == "" for d in network_discriminators):
        components.append(_hash_detail(log.detail))

    raw_key = "|".join(components)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# ── Deduplicator ────────────────────────────────────────────────────────

class LogDeduplicator:
    """
    Stateful deduplicator that collapses duplicate NormalizedLog entries.

    The deduplicator maintains an internal ordered map of
    ``dedup_key -> DeduplicatedLog``. The first time a key is seen, the
    entry is converted to a :class:`DeduplicatedLog` with
    ``dedup_count=1`` and stored. Each subsequent entry that produces
    the same key increments the representative's ``dedup_count`` and is
    otherwise discarded.

    Insertion order is preserved (Python 3.7+ dict semantics), so the
    output list has the same relative ordering as the input list of
    first-occurrences.

    Usage
    -----
    >>> deduper = LogDeduplicator()
    >>> deduped = deduper.deduplicate(normalized_logs)
    >>> len(deduped) <= len(normalized_logs)
    True

    The same instance can be reused across batches via
    :meth:`deduplicate_stream`, or reset with :meth:`reset`.
    """

    def __init__(self) -> None:
        # Ordered mapping: dedup_key -> representative DeduplicatedLog
        self._representatives: Dict[str, DeduplicatedLog] = {}

        # Counters for diagnostics
        self._seen_total: int = 0
        self._collapsed_total: int = 0

    # ── Public API ────────────────────────────────────────────────────

    def deduplicate(self, logs: List[NormalizedLog]) -> List[DeduplicatedLog]:
        """
        Deduplicate a batch of normalized logs.

        This method is non-destructive: the input list is not modified.
        Internally it extends the deduplicator's state, so calling this
        method multiple times on the same instance is equivalent to
        deduplicating the concatenated stream (useful for streaming
        use-cases).

        Parameters
        ----------
        logs : list[NormalizedLog]
            Normalized log entries to deduplicate.

        Returns
        -------
        list[DeduplicatedLog]
            Representative entries for the *current batch only*, in
            first-seen order. Duplicates detected across batches (via
            :meth:`deduplicate_stream`) are still collapsed, but only
            the representatives introduced by this call are returned.
        """
        batch_keys: List[str] = []  # keys introduced by this batch, in order
        batch_collapse_count: int = 0

        for log in logs:
            self._seen_total += 1
            key = compute_dedup_key(log)

            if key in self._representatives:
                # Duplicate of an already-seen representative: bump count.
                self._representatives[key].dedup_count += 1
                self._collapsed_total += 1
                batch_collapse_count += 1
            else:
                rep = DeduplicatedLog.from_normalized(log, dedup_key=key)
                self._representatives[key] = rep
                batch_keys.append(key)

        return [self._representatives[k] for k in batch_keys]

    def deduplicate_stream(
        self,
        logs: List[NormalizedLog],
    ) -> List[DeduplicatedLog]:
        """
        Streaming alias for :meth:`deduplicate`.

        Provided for readability when the caller is processing logs in
        chunks (e.g. windowed aggregation). Behaviour is identical to
        :meth:`deduplicate`.
        """
        return self.deduplicate(logs)

    def all_representatives(self) -> List[DeduplicatedLog]:
        """
        Return every representative seen so far, in first-seen order.

        Useful after a series of :meth:`deduplicate_stream` calls when
        the caller wants the full deduplicated view across all batches.
        """
        return list(self._representatives.values())

    def reset(self) -> None:
        """Clear all internal state."""
        self._representatives.clear()
        self._seen_total = 0
        self._collapsed_total = 0

    # ── Diagnostics ───────────────────────────────────────────────────

    @property
    def seen_count(self) -> int:
        """Total number of input logs observed so far."""
        return self._seen_total

    @property
    def collapsed_count(self) -> int:
        """Number of duplicate logs collapsed (not emitted)."""
        return self._collapsed_total

    @property
    def representative_count(self) -> int:
        """Number of unique representatives currently stored."""
        return len(self._representatives)

    @property
    def dedup_ratio(self) -> float:
        """
        Fraction of input logs that were collapsed.

        Returns 0.0 when no logs have been seen yet.
        """
        if self._seen_total == 0:
            return 0.0
        return self._collapsed_total / self._seen_total


# ── Internal helpers ────────────────────────────────────────────────────

def _safe_str(value: Any) -> str:
    """
    Coerce a value into a stable string for hashing.

    - ``None`` -> ``""``
    - Numeric/bool values are stringified with ``str()``.
    - Strings are returned as-is.
    - Everything else is also stringified with ``str()``; this is
      defensive and should not normally trigger for dedup-key fields.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _hash_detail(detail: Any) -> str:
    """
    Produce a stable SHA-256 hash of the ``detail`` dict.

    Stability is achieved by:
      - Sorting keys at every nesting level (``sort_keys=True``).
      - Using ``ensure_ascii=False`` so non-ASCII characters are not
        escaped (avoids cross-locale differences).
      - Coercing non-JSON-serialisable values via ``default=str``.

    Returns an empty string when ``detail`` is falsy, so that two logs
    both missing ``detail`` still hash identically — this only matters
    under the P3 fallback path, where both logs would also be missing
    all network discriminators.
    """
    if not detail:
        return ""
    try:
        canonical = json.dumps(
            detail,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
    except (TypeError, ValueError):
        # Last-resort fallback: stringify the raw repr.
        canonical = repr(detail)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()