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
│           └── abuseipdb.py
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
