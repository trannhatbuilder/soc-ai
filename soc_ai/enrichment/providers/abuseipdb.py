import os
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

from soc_ai.enrichment.cache import JsonCache
from soc_ai.enrichment.ip_utils import classify_ip, should_lookup_external
from soc_ai.enrichment.schemas import EnrichmentResult


load_dotenv()


class AbuseIPDBProvider:
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
            "https://api.abuseipdb.com/api/v2/check"
        )
        self.max_age_days = max_age_days or int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))

        self.cache = cache or JsonCache(
            cache_file=".cache/abuseipdb_cache.json",
            ttl_seconds=86400
        )

        if not self.api_key:
            raise ValueError("Missing ABUSEIPDB_API_KEY. Please configure it in .env")

    def lookup_ip(self, ip_value: str) -> EnrichmentResult:
        ip_category, ip_reason = classify_ip(ip_value)

        if not should_lookup_external(ip_value):
            return self._build_skipped_result(
                ip_value=ip_value,
                ip_category=ip_category,
                reason=ip_reason,
            )

        cache_key = f"abuseipdb:ip:{ip_value}"
        cached_result = self.cache.get(cache_key)

        if cached_result is not None:
            return EnrichmentResult(**cached_result)

        api_response = self._call_api(ip_value)
        enrichment_result = self._normalize_response(ip_value, api_response)

        self.cache.set(cache_key, enrichment_result.to_dict())

        return enrichment_result

    def _call_api(self, ip_value: str) -> Dict[str, Any]:
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
            status_code = error.response.status_code if error.response is not None else None

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

    def _normalize_response(
        self,
        ip_value: str,
        api_response: Dict[str, Any],
    ) -> EnrichmentResult:
        if api_response.get("error") is True:
            return EnrichmentResult(
                indicator_value=ip_value,
                indicator_type="ip",
                matched_source="AbuseIPDB",
                confidence_score=0,
                severity="unknown",
                category="lookup_error",
                tags=["lookup_error", api_response.get("error_type", "unknown_error")],
                reputation="unknown",
                reason=api_response.get("message", "AbuseIPDB lookup failed"),
                first_seen=None,
                last_seen=None,
                expiry_status="not_applicable",
                raw=api_response,
            )

        data = api_response.get("data", {})

        abuse_confidence_score = int(data.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(data.get("totalReports", 0) or 0)

        severity = self._map_severity(abuse_confidence_score, total_reports)
        reputation = self._map_reputation(abuse_confidence_score, total_reports)
        category = self._map_category(abuse_confidence_score, total_reports)

        tags = self._build_tags(data, abuse_confidence_score, total_reports)

        reason = (
            f"AbuseIPDB abuse confidence score is {abuse_confidence_score}; "
            f"total reports: {total_reports}"
        )

        return EnrichmentResult(
            indicator_value=ip_value,
            indicator_type="ip",
            matched_source="AbuseIPDB",
            confidence_score=abuse_confidence_score,
            severity=severity,
            category=category,
            tags=tags,
            reputation=reputation,
            reason=reason,
            first_seen=None,
            last_seen=data.get("lastReportedAt"),
            expiry_status="active",
            raw=data,
        )

    def _build_skipped_result(
        self,
        ip_value: str,
        ip_category: str,
        reason: str,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            indicator_value=ip_value,
            indicator_type="ip",
            matched_source="AbuseIPDB",
            confidence_score=0,
            severity="none",
            category=ip_category,
            tags=["skipped_external_lookup", ip_category],
            reputation="not_applicable",
            reason=reason,
            first_seen=None,
            last_seen=None,
            expiry_status="not_applicable",
            raw=None,
        )

    def _map_severity(self, abuse_confidence_score: int, total_reports: int) -> str:
        if abuse_confidence_score >= 90:
            return "critical"

        if abuse_confidence_score >= 70:
            return "high"

        if abuse_confidence_score >= 30:
            return "medium"

        if abuse_confidence_score > 0 or total_reports > 0:
            return "low"

        return "none"

    def _map_reputation(self, abuse_confidence_score: int, total_reports: int) -> str:
        if abuse_confidence_score >= 70:
            return "malicious"

        if abuse_confidence_score > 0 or total_reports > 0:
            return "suspicious"

        return "benign"

    def _map_category(self, abuse_confidence_score: int, total_reports: int) -> str:
        if abuse_confidence_score >= 70:
            return "known_malicious"

        if abuse_confidence_score > 0 or total_reports > 0:
            return "suspicious"

        return "clean"

    def _build_tags(
        self,
        data: Dict[str, Any],
        abuse_confidence_score: int,
        total_reports: int,
    ) -> list:
        tags = ["public_ip"]

        usage_type = data.get("usageType")
        country_code = data.get("countryCode")
        isp = data.get("isp")
        domain = data.get("domain")
        is_tor = data.get("isTor")
        is_whitelisted = data.get("isWhitelisted")

        if abuse_confidence_score >= 70:
            tags.append("abuseipdb_high_confidence")

        elif abuse_confidence_score > 0:
            tags.append("abuseipdb_low_confidence")

        if total_reports > 0:
            tags.append("reported_ip")

        if usage_type:
            tags.append(f"usage_type:{usage_type}")

        if country_code:
            tags.append(f"country:{country_code}")

        if isp:
            tags.append("has_isp")

        if domain:
            tags.append("has_domain")

        if is_tor is True:
            tags.append("tor_exit_node")

        if is_whitelisted is True:
            tags.append("abuseipdb_whitelisted")

        return tags