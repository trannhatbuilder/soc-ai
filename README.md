# SOC AI Enrichment Module

This project implements the Threat Intelligence Enrichment layer for SOC AI.

The current completed module is:

- AbuseIPDB IP Reputation Lookup

Upcoming module:

- VirusTotal Lookup

---

## 1. Objective

The objective of this module is to enrich normalized security logs with external threat intelligence context before the logs are passed to later SOC AI stages such as deduplication, aggregation, correlation, investigation, and AI log analysis.

Current enrichment flow:

```text
Raw Logs
  -> Normalize Logs
  -> AbuseIPDB Lookup
  -> Data Enrichment
  -> Deduplicate Logs
  -> Log Aggregation
  -> AI Log Analysis
```

## 2. Current Feature: AbuseIPDB Lookup
The AbuseIPDB lookup module supports:

- Public IP reputation lookup
- Private/internal IP detection
- Malformed IP detection
- Reserved/link-local/loopback IP handling
- Local JSON cache
- Structured enrichment output
- JSONL input/output demo
- Local demo execution

The AbuseIPDB API check endpoint accepts one IPv4 or IPv6 address and supports parameters such as ipAddress, maxAgeInDays, and verbose. The response data is returned under the data object and can include fields such as abuseConfidenceScore, countryCode, usageType, isp, domain, totalReports, and lastReportedAt.

## 3. Project Structure

```
soc_ai_enrichment/
├── soc_ai/
│   └── enrichment/
│       ├── cache.py
│       ├── ip_utils.py
│       ├── pipeline.py
│       ├── schemas.py
│       └── providers/
│       │    └── abuseipdb.py
│       └── deduplicate_logs/
│            └── abuseipdb.py
├── demo/
│   ├── run_abuseipdb_demo.py
│   └── sample_logs.jsonl
├── requirements.txt
├── .env.example
└── README.md
```

## 4. Setup
```cd soc_ai_enrichment```
``` 
python -m venv .venv
```
Linux/macOS:
```
source .venv/bin/activate
```
Windows PowerShell:
```
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 5. Run Local Demo
From the project root:
```
python -m demo.run_abuseipdb_demo
```
Input file: ```demo/sample_logs.jsonl```<br>
Output file: ```demo/output_abuseipdb_enriched.jsonl```

## 6. Output Schema
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

## 7. Severity Mapping
```
abuseConfidenceScore >= 90  -> critical
abuseConfidenceScore >= 70  -> high
abuseConfidenceScore >= 30  -> medium
abuseConfidenceScore > 0    -> low
otherwise                   -> none
```

## 8. Reputation Mapping

```
abuseConfidenceScore >= 70              -> malicious
abuseConfidenceScore > 0 or reports > 0 -> suspicious
otherwise                               -> benign
```

## 9. How to get API Key?
Create an account:
```https://www.abuseipdb.com/register```

---
