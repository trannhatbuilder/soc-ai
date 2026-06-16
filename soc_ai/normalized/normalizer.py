"""
Log Normalizer — orchestrates raw-log-to-NormalizedLog conversion.

The normalizer dispatches to the appropriate source-specific parser
(e.g. FortiGate) based on the ``log_source`` parameter.
"""

from typing import List

from soc_ai.normalized.schemas import NormalizedLog
from soc_ai.normalized.parsers.fortigate import parse_fortigate_line


class LogNormalizer:
    """Normalize raw log lines into structured NormalizedLog objects."""

    SUPPORTED_SOURCES = {"fortigate"}

    def normalize_line(
        self,
        line: str,
        log_source: str = "fortigate",
    ) -> NormalizedLog:
        """
        Normalize a single raw log line.

        Parameters
        ----------
        line : str
            The raw log line (e.g. a FortiGate syslog string).
        log_source : str
            Identifier of the log source. Determines which parser to use.

        Returns
        -------
        NormalizedLog
            The normalised representation. If the source is unsupported,
            a failed-status NormalizedLog is returned.
        """
        if log_source not in self.SUPPORTED_SOURCES:
            return NormalizedLog(
                event_id=f"unsupported-{hash(line) & 0xFFFFFFFF:08x}",
                timestamp="",
                log_source=log_source,
                log_type="unknown",
                log_subtype="unknown",
                severity="info",
                device_name="",
                device_id="",
                virtual_domain="",
                raw_log=line,
                parse_status="failed",
                parse_errors=[f"Unsupported log source: {log_source}"],
            )

        if log_source == "fortigate":
            return parse_fortigate_line(line)

        # Future parsers can be added here
        return NormalizedLog(
            event_id=f"no-parser-{hash(line) & 0xFFFFFFFF:08x}",
            timestamp="",
            log_source=log_source,
            log_type="unknown",
            log_subtype="unknown",
            severity="info",
            device_name="",
            device_id="",
            virtual_domain="",
            raw_log=line,
            parse_status="failed",
            parse_errors=[f"No parser implemented for: {log_source}"],
        )

    def normalize_lines(
        self,
        lines: List[str],
        log_source: str = "fortigate",
    ) -> List[NormalizedLog]:
        """
        Normalize a batch of raw log lines.

        Parameters
        ----------
        lines : list[str]
            Raw log lines.
        log_source : str
            Log source identifier.

        Returns
        -------
        list[NormalizedLog]
        """
        return [
            self.normalize_line(line, log_source)
            for line in lines
        ]