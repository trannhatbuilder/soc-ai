# SOC AI Enrichment Module

This project implements the Threat Intelligence Enrichment layer for SOC AI.

The current completed modules are:

- AbuseIPDB IP Reputation Lookup
- AbuseIPDB Enrichment Normalizer (for deduplication/aggregation stage)

Upcoming modules:

- VirusTotal Lookup
- VirusTotal Enrichment Normalizer

---

## 1. Objective

The objective of this module is to enrich normalized security logs with external threat intelligence context before the logs are passed to later SOC AI stages such as deduplication, aggregation, correlation, investigation, and AI log analysis.

Current enrichment flow:

```text
Raw Logs
  -> Normalize Logs
  -> Enrichment (AbuseIPDB Lookup)
  -> Enrichment Normalization (compact format for deduplication)
  -> Deduplicate Logs
  -> Log Aggregation
  -> AI Log Analysis
```

## 2. Current Features

### 2.1 AbuseIPDB Lookup
The AbuseIPDB lookup module supports:

- Public IP reputation lookup
- Private/internal IP detection
- Malformed IP detection
- Reserved/link-local/loopback IP handling
- Local JSON cache with TTL
- Structured enrichment output
- JSONL input/output demo
- Local demo execution

The AbuseIPDB API check endpoint accepts one IPv4 or IPv6 address and supports parameters such as ipAddress, maxAgeInDays, and verbose. The response data is returned under the data object and can include fields such as abuseConfidenceScore, countryCode, usageType, isp, domain, totalReports, and lastReportedAt.

### 2.2 AbuseIPDB Enrichment Normalizer (Deduplicate Logs Stage)

The enrichment normalizer converts raw AbuseIPDB enrichment results into a compact, analyst-friendly format optimized for downstream deduplication and aggregation stages.

**Features:**
- Extracts top attack categories from reports
- Samples unique report comments (deduplicated)
- Builds concise summary with key metadata
- Reduces storage footprint while preserving context
- Configurable limits for comments and categories

## 3. Project Structure

```
soc-ai/
├── raw_logs/03_fortigate_firewall.txt
├── output/
│   ├── normalized_fortigate.jsonl     ← Step 1 output
│   └── enriched_fortigate.jsonl       ← Step 2 output
├── soc_ai/
│   ├── enrichment/
│   │   ├── cache.py                   
│   │   ├── ip_utils.py                
│   │   ├── schemas.py                 
│   │   ├── pipeline.py                
│   │   ├── providers/
│   │   │   ├── abuseipdb.py           
│   │   │   └── virustotal.py          
│   │   └── normalizers/
│   │       └── virustotal_normalizer.py 
│   └── normalized/
│       ├── schemas.py
│       ├── normalizer.py
│       ├── pipeline.py
│       └── parsers/fortigate.py
├── .env / .env.example
├── requirements.txt
└── README.md
```

## 4. Setup

```bash
cd soc_ai_enrichment
python -m venv .venv
```

Linux/macOS:
```bash
source .venv/bin/activate
```

Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Configure environment variables:
```bash
cp .env.example .env
# Edit .env and add your AbuseIPDB API key
```

## 5. Run Local Demo

From the project root:

```bash
cd soc-ai

# Step 1: Normalize
python -m soc_ai.normalized.pipeline raw_logs/03_fortigate_firewall.txt output/normalized_fortigate.jsonl

# Step 2: Enrich
python -m soc_ai.enrichment.pipeline output/normalized_fortigate.jsonl output/enriched_fortigate.jsonl
```

## 6. Output Schema

### 6.1 EnrichmentResult Fields (Raw Provider Output)

Each enrichment object contains:

| Field              | Description                                                          |
| ------------------ | -------------------------------------------------------------------- |
| `indicator_value`  | The IOC value, currently an IP address.                              |
| `indicator_type`   | IOC type, currently `ip`.                                            |
| `matched_source`   | Threat intelligence source, currently `AbuseIPDB`.                   |
| `confidence_score` | AbuseIPDB abuse confidence score.                                    |
| `severity`         | Internal severity mapping.                                           |
| `category`         | Internal category mapping.                                           |
| `tags`             | Additional context tags.                                             |
| `reputation`       | `benign`, `suspicious`, `malicious`, `not_applicable`, or `unknown`. |
| `reason`           | Human-readable classification reason.                                |
| `first_seen`       | First seen timestamp, if available.                                  |
| `last_seen`        | Last reported timestamp, if available.                               |
| `expiry_status`    | `active` or `not_applicable`.                                        |
| `raw`              | Raw or partial provider response for debugging.                      |

### 6.2 Normalized Output (After Deduplicate Logs Stage)

After passing through the `AbuseIPDBEnrichmentNormalizer`, the `raw` field is transformed into a compact structure:

| Field                  | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
| `summary.total_reports` | Total number of reports from AbuseIPDB.                     |
| `summary.distinct_reporters` | Number of distinct users who reported the IP.          |
| `summary.country_code` | Country code of the IP.                                      |
| `summary.usage_type`   | Usage type (e.g., Data Center, ISP).                         |
| `summary.isp`          | Internet Service Provider name.                              |
| `summary.domain`       | Domain associated with the IP.                               |
| `summary.is_tor`       | Whether the IP is a known Tor exit node.                     |
| `summary.is_whitelisted` | Whether the IP is whitelisted on AbuseIPDB.                |
| `summary.top_categories` | Top attack categories (most frequent first).               |
| `summary.sample_report_comments` | Up to 3 unique report comments (deduplicated).     |
| `raw_ref.provider`     | Provider name (e.g., `AbuseIPDB`).                           |
| `raw_ref.raw_stored`   | Always `false` (raw data not stored to save space).          |
| `raw_ref.normalized_version` | Version of the normalization schema.                   |

## 7. Severity Mapping

```text
abuseConfidenceScore >= 90  -> critical
abuseConfidenceScore >= 70  -> high
abuseConfidenceScore >= 30  -> medium
abuseConfidenceScore > 0    -> low
otherwise                   -> none
```

## 8. Reputation Mapping

```text
abuseConfidenceScore >= 70              -> malicious
abuseConfidenceScore > 0 or reports > 0 -> suspicious
otherwise                               -> benign
```

## 9. How to get API Key?

Create an account:
https://www.abuseipdb.com/register

---
