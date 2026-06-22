"""Telegram Notification Sender — sends alerts and heartbeats via
Telegram Bot API.

The sender reads :class:`AlertEvent` and :class:`HeartbeatEvent` objects
(produced by ``soc_ai.alert.pipeline``), formats them into human-readable
messages using :class:`AlertMessage` / :class:`HeartbeatMessage`, and
sends each one to a Telegram chat via the Bot API.

Configuration
-------------
All configuration lives in ``.env``:

  - ``TELEGRAM_BOT_TOKEN``  (required) — Bot token from @BotFather
  - ``TELEGRAM_CHAT_ID``    (required) — Target chat ID (group or user)

Robustness
----------
  - Network errors, rate limits, and API failures are caught and
    logged — the sender never crashes the pipeline.
  - Each message is sent independently; a failure on one message does
    not prevent the rest from being sent.
  - A short delay between messages avoids hitting Telegram rate limits.

Usage (API):
    from soc_ai.telegram.sender import TelegramSender

    sender = TelegramSender()
    sender.send_alert(alert_event)
    sender.send_heartbeat(heartbeat_event)
"""

import os
import time
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

from soc_ai.alert.schemas import AlertEvent, HeartbeatEvent, EVENT_TYPE_ALERT, EVENT_TYPE_HEARTBEAT
from soc_ai.telegram.schemas import AlertMessage, HeartbeatMessage


load_dotenv()


# ── Public constants ────────────────────────────────────────────────────

DEFAULT_BASE_URL: str = "https://api.telegram.org"
DEFAULT_SEND_DELAY_SECONDS: float = 0.5   # Delay between messages
DEFAULT_TIMEOUT_SECONDS: float = 15.0     # Per-request timeout


# ── Sender ──────────────────────────────────────────────────────────────

class TelegramSender:
    """
    Send alert and heartbeat notifications to a Telegram chat.

    Parameters
    ----------
    bot_token : str, optional
        Telegram bot token. Defaults to ``TELEGRAM_BOT_TOKEN`` env var.
    chat_id : str, optional
        Target Telegram chat ID. Defaults to ``TELEGRAM_CHAT_ID`` env var.
    base_url : str, optional
        Telegram API base URL. Defaults to ``https://api.telegram.org``.
    send_delay : float, optional
        Seconds to wait between consecutive messages. Defaults to 0.5.
    timeout : float, optional
        Per-request timeout in seconds. Defaults to 15.0.
    dry_run : bool, optional
        When ``True``, messages are printed to stdout but NOT sent to
        Telegram. Useful for testing without a bot token. Defaults to
        ``False`` (or ``TELEGRAM_DRY_RUN=true`` env var).
    """

    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        base_url: Optional[str] = None,
        send_delay: Optional[float] = None,
        timeout: Optional[float] = None,
        dry_run: Optional[bool] = None,
    ) -> None:
        # ── Resolve configuration ─────────────────────────────────────
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID", "")
        self.base_url = (base_url or os.getenv("TELEGRAM_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self.send_delay = float(send_delay if send_delay is not None
                                else os.getenv("TELEGRAM_SEND_DELAY", DEFAULT_SEND_DELAY_SECONDS))
        self.timeout = float(timeout if timeout is not None
                             else os.getenv("TELEGRAM_TIMEOUT", DEFAULT_TIMEOUT_SECONDS))

        # Dry run mode: print messages instead of sending
        dry_run_env = os.getenv("TELEGRAM_DRY_RUN", "").strip().lower()
        self.dry_run = dry_run if dry_run is not None else dry_run_env in ("true", "1", "yes")

        # ── Validate ──────────────────────────────────────────────────
        if not self.dry_run:
            if not self.bot_token:
                raise ValueError(
                    "Missing TELEGRAM_BOT_TOKEN. "
                    "Set it in .env or pass bot_token explicitly, "
                    "or use dry_run=True for testing."
                )
            if not self.chat_id:
                raise ValueError(
                    "Missing TELEGRAM_CHAT_ID. "
                    "Set it in .env or pass chat_id explicitly, "
                    "or use dry_run=True for testing."
                )

        # ── Counters ──────────────────────────────────────────────────
        self._sent_count: int = 0
        self._failed_count: int = 0

    # ── Public API ────────────────────────────────────────────────────

    def send_alert(self, event: AlertEvent) -> bool:
        """
        Send an :class:`AlertEvent` as a Telegram alert message.

        Returns
        -------
        bool
            ``True`` if the message was sent successfully, ``False``
            otherwise (network error, API error, etc.).
        """
        msg = AlertMessage(event=event, chat_id=self.chat_id)
        return self._send_message(msg.text, msg.parse_mode)

    def send_heartbeat(self, event: HeartbeatEvent) -> bool:
        """
        Send a :class:`HeartbeatEvent` as a Telegram heartbeat message.

        Returns
        -------
        bool
            ``True`` if the message was sent successfully, ``False``
            otherwise.
        """
        msg = HeartbeatMessage(event=event, chat_id=self.chat_id)
        return self._send_message(msg.text, msg.parse_mode)

    def send_events(
        self,
        events: List,
    ) -> Dict[str, Any]:
        """
        Send a batch of AlertEvent/HeartbeatEvent objects.

        Each event is dispatched to the correct sender method based on
        its ``event_type``. A short delay is inserted between messages
        to avoid Telegram rate limits.

        Parameters
        ----------
        events : list[AlertEvent | HeartbeatEvent]
            Events to send, in order.

        Returns
        -------
        dict
            Summary with ``sent``, ``failed``, and ``total`` counts.
        """
        results: List[bool] = []

        for i, event in enumerate(events):
            if i > 0 and self.send_delay > 0:
                time.sleep(self.send_delay)

            if event.event_type == EVENT_TYPE_ALERT:
                ok = self.send_alert(event)
            elif event.event_type == EVENT_TYPE_HEARTBEAT:
                ok = self.send_heartbeat(event)
            else:
                print(f"[!] Unknown event_type: {event.event_type}, skipping")
                ok = False

            results.append(ok)

        return {
            "sent": self._sent_count,
            "failed": self._failed_count,
            "total": len(events),
        }

    @property
    def sent_count(self) -> int:
        """Number of messages sent successfully."""
        return self._sent_count

    @property
    def failed_count(self) -> int:
        """Number of messages that failed to send."""
        return self._failed_count

    # ── Internal helpers ──────────────────────────────────────────────

    def _send_message(
        self,
        text: str,
        parse_mode: Optional[str] = None,
    ) -> bool:
        """
        Send a text message to the configured Telegram chat.

        In dry-run mode, the message is printed to stdout instead.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        # ── Dry run mode ──────────────────────────────────────────────
        if self.dry_run:
            print(f"[DRY RUN] Would send to Telegram chat {self.chat_id}:")
            print("-" * 60)
            print(text)
            print("-" * 60)
            self._sent_count += 1
            return True

        # ── Build request ─────────────────────────────────────────────
        url = f"{self.base_url}/bot{self.bot_token}/sendMessage"
        payload: Dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": text,
        }
        if parse_mode is not None:
            payload["parse_mode"] = parse_mode

        # ── Send request ──────────────────────────────────────────────
        try:
            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()

            result = response.json()
            if result.get("ok"):
                self._sent_count += 1
                return True
            else:
                error_desc = result.get("description", "Unknown error")
                print(f"[!] Telegram API error: {error_desc}")
                self._failed_count += 1
                return False

        except requests.exceptions.Timeout:
            print(f"[!] Telegram request timed out after {self.timeout}s")
            self._failed_count += 1
            return False

        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            print(f"[!] Telegram HTTP error (status={status}): {exc}")
            self._failed_count += 1
            return False

        except requests.exceptions.RequestException as exc:
            print(f"[!] Telegram request error: {exc}")
            self._failed_count += 1
            return False