"""
AbuseIPDB Threat Intelligence Provider.

Queries the AbuseIPDB API for public IP reputation data and returns
a compact :class:`IPEnrichment` object.  Private/internal/invalid IPs
return ``None`` — they are simply not enriched.
"""

import os
from collections import Counter
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

from soc_ai.enrichment.cache import JsonCache
from soc_ai.enrichment.ip_utils import should_lookup_external
from soc_ai.enrichment.schemas import IPEnrichment


load_dotenv()


# ── AbuseIPDB category ID → human-readable name ─────────────────────────

ABUSEIPDB_CATEGORY_MAP: Dict[int, str] = {
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBProvider:
    """
    Enrich public IP addresses with AbuseIPDB threat intelligence.

    Returns an :class:`IPEnrichment` for public IPs, or ``None`` for
    private / internal / invalid addresses (they are not enriched).
    """

    # confidence_score >= this threshold → is_malicious = True
    MALICIOUS_THRESHOLD = 50

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_age_days: Optional[int] = None,
        cache: Optional[JsonCache] = None,
    ):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = base_url or os.getenv(
            "ABUSEIPDB_BASE_URL",
            "https://api.abuseipdb.com/api/v2/check",
        )
        self.max_age_days = max_age_days or int(
            os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90")
        )
        self.cache = cache or JsonCache(
            cache_file=".cache/abuseipdb_cache.json",
            ttl_seconds=86400,
        )

        if not self.api_key:
            raise ValueError(
                "Missing ABUSEIPDB_API_KEY. Please configure it in .env"
            )

    # ── Public API ───────────────────────────────────────────────────────

    def lookup(self, ip_value: str) -> Optional[IPEnrichment]:
        """
        Look up an IP address on AbuseIPDB.

        Returns
        -------
        IPEnrichment or None
            Enrichment data for public IPs; ``None`` for private/internal/
            invalid addresses (no enrichment needed).
        """
        if not should_lookup_external(ip_value):
            return None

        # Check cache first
        cache_key = f"abuseipdb:ip:{ip_value}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return IPEnrichment(**cached)

        # Call API
        api_response = self._call_api(ip_value)
        enrichment = self._build_enrichment(api_response)

        # Cache the result (as dict for JSON serialisation)
        self.cache.set(cache_key, enrichment.to_dict())

        return enrichment

    # ── API call ─────────────────────────────────────────────────────────

    def _call_api(self, ip_value: str) -> Dict[str, Any]:
        """Call the AbuseIPDB check endpoint."""
        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
        }
        params = {
            "ipAddress": ip_value,
            "maxAgeInDays": self.max_age_days,
            "verbose": "",
        }

        try:
            response = requests.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=15,
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as error:
            status_code = (
                error.response.status_code
                if error.response is not None
                else None
            )
            return {
                "error": True,
                "error_type": "http_error",
                "status_code": status_code,
                "message": str(error),
            }

        except requests.exceptions.Timeout:
            return {
                "error": True,
                "error_type": "timeout",
                "message": "AbuseIPDB request timed out",
            }

        except requests.exceptions.RequestException as error:
            return {
                "error": True,
                "error_type": "request_error",
                "message": str(error),
            }

        except ValueError:
            return {
                "error": True,
                "error_type": "invalid_json",
                "message": "AbuseIPDB returned invalid JSON",
            }

    # ── Build IPEnrichment from API response ─────────────────────────────

    def _build_enrichment(self, api_response: Dict[str, Any]) -> IPEnrichment:
        """Convert a raw API response into a compact IPEnrichment."""
        # Handle error responses
        if api_response.get("error") is True:
            return IPEnrichment(
                source="AbuseIPDB",
                confidence_score=0,
                is_malicious=False,
                threat_severity="none",
                reputation="unknown",
                category="lookup_error",
                lookup_error=api_response.get("message", "Lookup failed"),
            )

        data = api_response.get("data", {})
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(data.get("totalReports", 0) or 0)
        distinct_users = int(data.get("numDistinctUsers", 0) or 0)

        is_malicious = score >= self.MALICIOUS_THRESHOLD

        return IPEnrichment(
            source="AbuseIPDB",
            confidence_score=score,
            is_malicious=is_malicious,
            threat_severity=self._map_severity(score, total_reports),
            reputation=self._map_reputation(score, total_reports),
            category=self._map_category(score, total_reports),
            country=data.get("countryCode") or None,
            city=data.get("city") or None,
            usage_type=data.get("usageType") or None,
            is_tor=data.get("isTor") if data.get("isTor") is not None else None,
            is_whitelisted=(
                data.get("isWhitelisted")
                if data.get("isWhitelisted") is not None
                else None
            ),
            top_categories=self._extract_top_categories(data),
            total_reports=total_reports if total_reports > 0 else None,
            distinct_reporters=distinct_users if distinct_users > 0 else None,
        )

    # ── Mapping helpers ──────────────────────────────────────────────────

    @staticmethod
    def _map_severity(score: int, total_reports: int) -> str:
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 30:
            return "medium"
        if score > 0 or total_reports > 0:
            return "low"
        return "none"

    @staticmethod
    def _map_reputation(score: int, total_reports: int) -> str:
        if score >= 70:
            return "malicious"
        if score > 0 or total_reports > 0:
            return "suspicious"
        return "benign"

    @staticmethod
    def _map_category(score: int, total_reports: int) -> str:
        if score >= 70:
            return "known_malicious"
        if score > 0 or total_reports > 0:
            return "suspicious"
        return "clean"

    # ── Category extraction ──────────────────────────────────────────────

    @staticmethod
    def _extract_top_categories(
        data: Dict[str, Any],
        max_categories: int = 5,
    ) -> Optional[List[str]]:
        """
        Extract the most frequent attack category names from reports.

        Returns None if there are no reports (avoids an empty list in output).
        """
        reports = data.get("reports") or []
        if not isinstance(reports, list) or not reports:
            return None

        counter: Counter = Counter()
        for report in reports:
            categories = report.get("categories") or []
            if not isinstance(categories, list):
                continue
            for cat_id in categories:
                name = ABUSEIPDB_CATEGORY_MAP.get(
                    cat_id, f"category:{cat_id}"
                )
                counter[name] += 1

        if not counter:
            return None

        return [name for name, _ in counter.most_common(max_categories)]