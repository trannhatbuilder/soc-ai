from collections import Counter
from typing import Any, Dict, List, Optional

from soc_ai.enrichment.schemas import EnrichmentResult


ABUSEIPDB_CATEGORY_MAP = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
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


class AbuseIPDBEnrichmentNormalizer:
    def __init__(
        self,
        max_sample_comments: int = 3,
        max_comment_length: int = 120,
        max_top_categories: int = 5,
    ):
        self.max_sample_comments = max_sample_comments
        self.max_comment_length = max_comment_length
        self.max_top_categories = max_top_categories

    def compact(self, result: EnrichmentResult) -> EnrichmentResult:
        """
        Convert AbuseIPDB enrichment result into a compact analyst-friendly object.
        """
        if result.matched_source != "AbuseIPDB":
            return result

        raw = result.raw or {}

        if not isinstance(raw, dict):
            raw = {}

        summary = self._build_summary(raw)

        compact_raw = {
            "summary": summary,
            "raw_ref": {
                "provider": "AbuseIPDB",
                "raw_stored": False,
                "normalized_version": "1.0",
            },
        }

        compact_reason = self._build_reason(
            result=result,
            summary=summary,
        )

        compact_tags = self._compact_tags(result.tags)

        return EnrichmentResult(
            indicator_value=result.indicator_value,
            indicator_type=result.indicator_type,
            matched_source=result.matched_source,
            confidence_score=result.confidence_score,
            severity=result.severity,
            category=result.category,
            tags=compact_tags,
            reputation=result.reputation,
            reason=compact_reason,
            first_seen=result.first_seen,
            last_seen=result.last_seen,
            expiry_status=result.expiry_status,
            raw=compact_raw,
        )

    def _build_summary(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        reports = raw.get("reports") or []

        if not isinstance(reports, list):
            reports = []

        top_categories = self._extract_top_categories(reports)
        sample_comments = self._extract_sample_comments(reports)

        summary = {
            "total_reports": raw.get("totalReports", 0),
            "distinct_reporters": raw.get("numDistinctUsers", 0),
            "country_code": raw.get("countryCode"),
            "usage_type": raw.get("usageType"),
            "isp": raw.get("isp"),
            "domain": raw.get("domain"),
            "is_tor": raw.get("isTor"),
            "is_whitelisted": raw.get("isWhitelisted"),
            "top_categories": top_categories,
            "sample_report_comments": sample_comments,
        }

        return self._remove_empty_values(summary)

    def _extract_top_categories(self, reports: List[Dict[str, Any]]) -> List[str]:
        category_counter = Counter()

        for report in reports:
            categories = report.get("categories") or []

            if not isinstance(categories, list):
                continue

            for category_id in categories:
                category_name = ABUSEIPDB_CATEGORY_MAP.get(
                    category_id,
                    f"category:{category_id}",
                )
                category_counter[category_name] += 1

        return [
            category
            for category, _ in category_counter.most_common(self.max_top_categories)
        ]

    def _extract_sample_comments(self, reports: List[Dict[str, Any]]) -> List[str]:
        seen = set()
        comments = []

        for report in reports:
            comment = report.get("comment")

            if not comment:
                continue

            normalized_comment = self._normalize_comment(comment)

            if not normalized_comment:
                continue

            fingerprint = normalized_comment.lower()

            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            comments.append(normalized_comment)

            if len(comments) >= self.max_sample_comments:
                break

        return comments

    def _normalize_comment(self, comment: str) -> Optional[str]:
        if not isinstance(comment, str):
            return None

        comment = " ".join(comment.split())

        if not comment:
            return None

        if len(comment) > self.max_comment_length:
            comment = comment[: self.max_comment_length].rstrip() + "..."

        return comment

    def _build_reason(
        self,
        result: EnrichmentResult,
        summary: Dict[str, Any],
    ) -> str:
        total_reports = summary.get("total_reports", 0)
        distinct_reporters = summary.get("distinct_reporters", 0)

        if total_reports and distinct_reporters:
            return (
                f"AbuseIPDB score {result.confidence_score} "
                f"with {total_reports} reports from {distinct_reporters} distinct users"
            )

        if total_reports:
            return (
                f"AbuseIPDB score {result.confidence_score} "
                f"with {total_reports} reports"
            )

        return result.reason

    def _compact_tags(self, tags: List[str]) -> List[str]:
        if not tags:
            return []

        unnecessary_tags = {
            "public_ip",
            "has_isp",
            "has_domain",
        }

        compact_tags = []

        for tag in tags:
            if tag in unnecessary_tags:
                continue

            if tag not in compact_tags:
                compact_tags.append(tag)

        return compact_tags

    def _remove_empty_values(self, data: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = {}

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