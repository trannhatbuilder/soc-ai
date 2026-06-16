"""
FortiGate Firewall raw log parser.

Parses FortiGate syslog-format lines (key=value pairs) into
the unified NormalizedLog structure.

Supported FortiGate type/subtype combinations:
  - event:  system, security-rating, user, vpn
  - traffic: forward, local
  - utm:    anomaly, app-ctrl, dns, ssl, webfilter
"""

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from soc_ai.normalized.schemas import NormalizedLog


# ── Constants ────────────────────────────────────────────────────────────

# IP protocol number → human-readable name
PROTO_MAP: Dict[str, str] = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "89": "OSP",
}

# FortiGate log level → internal severity
LEVEL_MAP: Dict[str, str] = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notification": "low",
    "information": "info",
    "notice": "info",
}

# Syslog header pattern: "Mon DD HH:MM:SS <host>"
SYSLOG_HEADER_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
)

# Key=value pattern — handles both quoted and unquoted values
KV_PATTERN = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)')

# Fields already mapped to top-level NormalizedLog attributes
# (excluded from the detail dict to avoid duplication)
_SKIP_DETAIL_KEYS = {
    "date", "time", "tz", "devname", "devid",
    "type", "subtype", "level", "severity",
    "srcip", "dstip", "srcport", "dstport",
    "proto", "action", "eventtime",
    "remip", "locip",  # VPN fields mapped to src_ip / dst_ip
}


# ── Public API ───────────────────────────────────────────────────────────

def parse_fortigate_line(line: str) -> NormalizedLog:
    """Parse a single FortiGate syslog line into a NormalizedLog."""

    parse_errors: List[str] = []

    # 1. Extract syslog header (timestamp + host)
    syslog_host = _extract_syslog_host(line)

    # 2. Extract key=value pairs
    fields = _extract_kv_pairs(line)

    if not fields:
        return _build_failed_log(line, ["No key=value fields found"])

    # 3. Build ISO 8601 timestamp
    timestamp = _build_timestamp(fields, parse_errors)

    # 4. Map core fields
    log_type = fields.get("type", "unknown")
    log_subtype = fields.get("subtype", "unknown")
    severity = _map_severity(fields)

    # 5. Map network fields (handles VPN remip/locip fallback)
    src_ip, dst_ip = _map_ip_fields(fields, log_type)
    src_port = _safe_int(fields.get("srcport"))
    dst_port = _safe_int(fields.get("dstport"))
    protocol = _map_protocol(fields.get("proto"))
    action = fields.get("action")
    src_intf = fields.get("srcintf")
    dst_intf = fields.get("dstintf")

    # 6. Build detail dict (remaining fields not mapped to top-level)
    detail = _build_detail(fields, syslog_host)

    # 7. Generate event_id
    event_id = _build_event_id(fields, timestamp)

    parse_status = "partial" if parse_errors else "success"

    return NormalizedLog(
        event_id=event_id,
        timestamp=timestamp,
        log_source="fortigate",
        log_type=log_type,
        log_subtype=log_subtype,
        severity=severity,
        device_name=fields.get("devname", ""),
        device_id=fields.get("devid", ""),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        action=action,
        detail=detail,
        raw_log=line,
        parse_status=parse_status,
        parse_errors=parse_errors,
    )


# ── Internal helpers ─────────────────────────────────────────────────────

def _extract_syslog_host(line: str) -> Optional[str]:
    """Extract the host IP from the syslog header."""
    m = SYSLOG_HEADER_RE.match(line)
    return m.group(2) if m else None


def _extract_kv_pairs(line: str) -> Dict[str, str]:
    """Extract all key=value pairs from a FortiGate log line."""
    # Skip past the syslog header portion
    rest = line
    m = SYSLOG_HEADER_RE.match(line)
    if m:
        rest = line[m.end():]

    result: Dict[str, str] = {}
    for key, value in KV_PATTERN.findall(rest):
        # Strip surrounding quotes
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        result[key] = value
    return result


def _build_timestamp(fields: Dict[str, str], errors: List[str]) -> str:
    """Build an ISO 8601 timestamp from date, time, and tz fields."""
    date_str = fields.get("date", "")
    time_str = fields.get("time", "")
    tz_str = fields.get("tz", "+0000")

    if not date_str or not time_str:
        errors.append("Missing date/time fields")
        return ""

    try:
        dt_str = f"{date_str} {time_str}"
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")

        tz_offset = _parse_tz(tz_str)
        if tz_offset is not None:
            dt = dt.replace(tzinfo=tz_offset)

        return dt.isoformat()
    except ValueError as exc:
        errors.append(f"Timestamp parse error: {exc}")
        return ""


def _parse_tz(tz_str: str) -> Optional[timezone]:
    """Parse a timezone string like '+0800' or '-05:30' into a timezone."""
    try:
        tz_str = tz_str.strip().replace(":", "")
        sign = 1 if tz_str[0] == "+" else -1
        hours = int(tz_str[1:3])
        minutes = int(tz_str[3:5])
        return timezone(timedelta(hours=sign * hours, minutes=sign * minutes))
    except (ValueError, IndexError):
        return None


def _map_severity(fields: Dict[str, str]) -> str:
    """Map FortiGate level (and optional severity) to internal severity."""
    level = fields.get("level", "").lower()

    # For utm/anomaly events, prefer the dedicated severity field
    if fields.get("subtype") == "anomaly" and "severity" in fields:
        utm_sev = fields["severity"].lower()
        if utm_sev in ("critical", "high", "medium", "low"):
            return utm_sev

    return LEVEL_MAP.get(level, "info")


def _map_ip_fields(
    fields: Dict[str, str],
    log_type: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Map src/dst IP fields, handling VPN-specific field names."""
    src_ip = fields.get("srcip")
    dst_ip = fields.get("dstip")

    # VPN logs use remip/locip instead of srcip/dstip
    if not src_ip and "remip" in fields:
        src_ip = fields.get("remip")
    if not dst_ip and "locip" in fields:
        dst_ip = fields.get("locip")

    return src_ip, dst_ip


def _map_protocol(proto: Optional[str]) -> Optional[str]:
    """Map protocol number to a human-readable name."""
    if not proto:
        return None
    return PROTO_MAP.get(proto, f"proto_{proto}")


def _safe_int(value: Optional[str]) -> Optional[int]:
    """Safely convert a string to int."""
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _build_detail(
    fields: Dict[str, str],
    syslog_host: Optional[str],
) -> Dict[str, Any]:
    """Build the detail dict with fields not mapped to top-level attributes."""
    detail: Dict[str, Any] = {}

    for key, value in fields.items():
        if key in _SKIP_DETAIL_KEYS:
            continue
        detail[key] = value

    if syslog_host:
        detail["syslog_host"] = syslog_host

    return detail


def _build_event_id(fields: Dict[str, str], timestamp: str) -> str:
    """Generate a unique event ID, preferring sessionid-based composition."""
    session_id = fields.get("sessionid")
    logid = fields.get("logid", "unknown")
    devid = fields.get("devid", "unknown")

    if session_id:
        return f"fgt-{devid}-{session_id}"

    # Fallback: composite with short UUID
    return f"fgt-{devid}-{logid}-{uuid.uuid4().hex[:8]}"


def _build_failed_log(line: str, errors: List[str]) -> NormalizedLog:
    """Create a NormalizedLog for lines that could not be parsed."""
    return NormalizedLog(
        event_id=f"parse-failed-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        log_source="fortigate",
        log_type="unknown",
        log_subtype="unknown",
        severity="info",
        device_name="",
        device_id="",
        raw_log=line,
        parse_status="failed",
        parse_errors=errors,
    )