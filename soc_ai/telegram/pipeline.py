"""Telegram Notification pipeline — reads alert/heartbeat events and
sends them to Telegram.

Flow:

    AlertEvent/HeartbeatEvent JSONL  ->  TelegramSender  ->  Telegram Chat

Input contract
--------------
The standard input is the output of ``soc_ai.alert.pipeline`` — a JSONL
file where each line is either an :class:`AlertEvent` or a
:class:`HeartbeatEvent`, discriminated by the ``event_type`` field.

Configuration
-------------
All Telegram configuration lives in ``.env``:

  - ``TELEGRAM_BOT_TOKEN``   (required for real sending)
  - ``TELEGRAM_CHAT_ID``     (required for real sending)
  - ``TELEGRAM_DRY_RUN``     (optional, ``true`` = dry-run mode)

Usage (CLI):
    python -m soc_ai.telegram.pipeline <input_jsonl>

Usage (API):
    from soc_ai.telegram.pipeline import telegram_pipeline

    telegram_pipeline(
        input_file="output/alerts_fortigate.jsonl",
    )
"""

import argparse
import json
from typing import Any, Dict, List, Optional, Union

from soc_ai.alert.schemas import (
    AlertEvent,
    HeartbeatEvent,
    EVENT_TYPE_ALERT,
    EVENT_TYPE_HEARTBEAT,
)
from soc_ai.ai.schemas import AIVerdict
from soc_ai.telegram.sender import TelegramSender


# ── IO helpers ──────────────────────────────────────────────────────────

def read_events_jsonl(input_file: str) -> List[Union[AlertEvent, HeartbeatEvent]]:
    """
    Read a JSONL file of alert/heartbeat events and return typed objects.

    Each line is parsed and reconstructed into the appropriate event
    type based on the ``event_type`` discriminator:

      - ``"alert"``     → :class:`AlertEvent`
      - ``"heartbeat"`` → :class:`HeartbeatEvent`

    Malformed or unknown event types are skipped with a warning.

    Parameters
    ----------
    input_file : str
        Path to the events JSONL file (output of
        ``soc_ai.alert.pipeline``).

    Returns
    -------
    list[AlertEvent | HeartbeatEvent]
        Parsed events, in file order.
    """
    events: List[Union[AlertEvent, HeartbeatEvent]] = []

    with open(input_file, "r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                event = _reconstruct_event(data)
                if event is not None:
                    events.append(event)
            except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
                print(
                    f"[!] Skipping malformed event line {line_number}: {exc}"
                )

    return events


def _reconstruct_event(data: Dict[str, Any]) -> Optional[Union[AlertEvent, HeartbeatEvent]]:
    """
    Reconstruct an AlertEvent or HeartbeatEvent from a plain dict.

    Uses the ``event_type`` field to determine which class to build.
    Returns ``None`` for unknown event types.
    """
    event_type = data.get("event_type", "")

    if event_type == EVENT_TYPE_ALERT:
        return _reconstruct_alert_event(data)
    elif event_type == EVENT_TYPE_HEARTBEAT:
        return _reconstruct_heartbeat_event(data)
    else:
        print(f"[!] Unknown event_type: {event_type!r}, skipping")
        return None


def _reconstruct_alert_event(data: Dict[str, Any]) -> AlertEvent:
    """Reconstruct an :class:`AlertEvent` from a plain dict."""
    verdict_data = data.get("verdict")
    verdict = None
    if verdict_data is not None:
        verdict = AIVerdict(
            should_alert=verdict_data.get("should_alert", False),
            severity=verdict_data.get("severity", "low"),
            confidence=verdict_data.get("confidence", 0),
            category=verdict_data.get("category", ""),
            title=verdict_data.get("title", ""),
            summary=verdict_data.get("summary", ""),
            reasoning=verdict_data.get("reasoning", ""),
            recommended_actions=verdict_data.get("recommended_actions", []),
            dedup_key=verdict_data.get("dedup_key", ""),
            model=verdict_data.get("model", ""),
            analyzed_at=verdict_data.get("analyzed_at", ""),
            tokens_used=verdict_data.get("tokens_used"),
        )

    return AlertEvent(
        event_type=EVENT_TYPE_ALERT,
        detected_at=data.get("detected_at", ""),
        window_start=data.get("window_start", ""),
        window_end=data.get("window_end", ""),
        log_source=data.get("log_source", ""),
        event_count=data.get("event_count", 0),
        malicious_ip_count=data.get("malicious_ip_count", 0),
        verdict=verdict,
    )


def _reconstruct_heartbeat_event(data: Dict[str, Any]) -> HeartbeatEvent:
    """Reconstruct a :class:`HeartbeatEvent` from a plain dict."""
    return HeartbeatEvent(
        event_type=EVENT_TYPE_HEARTBEAT,
        generated_at=data.get("generated_at", ""),
        last_alert_at=data.get("last_alert_at"),
        hours_since_last_alert=data.get("hours_since_last_alert", 0.0),
        windows_processed=data.get("windows_processed", 0),
        total_events_processed=data.get("total_events_processed", 0),
    )


# ── Pipeline entry point ────────────────────────────────────────────────

def telegram_pipeline(
    input_file: str,
    dry_run: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Full Telegram notification pipeline: read events JSONL -> send to
    Telegram.

    Parameters
    ----------
    input_file : str
        Path to the events JSONL file (output of
        ``soc_ai.alert.pipeline``).
    dry_run : bool, optional
        Override dry-run mode. When ``None``, reads from
        ``TELEGRAM_DRY_RUN`` env var or defaults to ``False``.

    Returns
    -------
    dict
        Summary with ``sent``, ``failed``, ``total``, ``alerts``,
        ``heartbeats`` counts.
    """
    events = read_events_jsonl(input_file)
    print(f"[+] Read {len(events)} events from: {input_file}")

    # Count by type
    alert_count = sum(1 for e in events if e.event_type == EVENT_TYPE_ALERT)
    heartbeat_count = sum(1 for e in events if e.event_type == EVENT_TYPE_HEARTBEAT)
    print(f"[+] Events: {alert_count} alerts, {heartbeat_count} heartbeats")

    # ── Initialize sender ────────────────────────────────────────────
    sender = TelegramSender(dry_run=dry_run)

    if sender.dry_run:
        print("[+] Running in DRY RUN mode — messages will be printed, NOT sent to Telegram")
    else:
        print(f"[+] Sending to Telegram chat: {sender.chat_id}")

    # ── Send all events ──────────────────────────────────────────────
    result = sender.send_events(events)

    # ── Summary ──────────────────────────────────────────────────────
    print()
    print(
        f"[+] Telegram summary: "
        f"sent={result['sent']}, "
        f"failed={result['failed']}, "
        f"total={result['total']}"
    )

    return {
        **result,
        "alerts": alert_count,
        "heartbeats": heartbeat_count,
    }


# ── CLI ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send alert/heartbeat events to Telegram",
    )
    parser.add_argument(
        "input_file",
        help="Path to the events JSONL file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print messages instead of sending to Telegram",
    )

    args = parser.parse_args()

    telegram_pipeline(
        input_file=args.input_file,
        dry_run=args.dry_run if args.dry_run else None,
    )


if __name__ == "__main__":
    main()