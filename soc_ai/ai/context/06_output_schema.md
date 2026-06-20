# Output Schema

## Required JSON Object

- Output exactly one JSON object.
- Allowed fields only:
  - `should_alert`
  - `severity`
  - `confidence`
  - `category`
  - `title`
  - `summary`
  - `reasoning`
  - `recommended_actions`
  - `dedup_key`
- No extra fields.

## Field Rules

- `should_alert`
  - boolean
- `severity`
  - one of: `low`, `medium`, `high`, `critical`
- `confidence`
  - integer `0..100`
- `category`
  - evidence-based category, not worst-case speculation
  - valid examples:
    - `auth_abuse`
    - `web_attack`
    - `business_abuse`
    - `waf_block_rate_anomaly`
    - `possible_ddos`
    - `exposed_service`
    - `lateral_movement`
    - `malicious_ip_activity`
    - `reconnaissance`
    - `ips_anomaly`
    - `internal_db_access_pattern`
    - `normal_internal_to_external_traffic`
    - `expected_vpn_activity`
    - `expected_application_traffic`
    - `internet_scan_noise`
    - `telemetry_gap`
- `title`
  - concise and specific
- `summary`
  - 1 to 3 short sentences
  - describe evidence and scope
- `reasoning`
  - explain why the activity is normal, low-signal, or malicious
  - separate suspicious evidence from normal context
  - no unsupported escalation language
- `recommended_actions`
  - short operational steps
  - proportional to confidence and evidence
  - do not recommend blocking, isolation, or credential rotation without clear malicious evidence
- `dedup_key`
  - stable string based on issue type and primary entities
  - example: `auth_brute_force:<src_ip>:<dst_ip>:<port>`
  - example: `malicious_ip:<src_ip>`
  - example: `reconnaissance:<src_ip>:<target>`

## Output Behavior

- If evidence is below threshold, set `should_alert=false`.
- If traffic is normal but noteworthy, choose a normal or low-signal category instead of `lateral_movement` or other high-risk labels.
- Prefer `reconnaissance` over `exposed_service` for isolated or short-lived probes.
- Do not output markdown or commentary outside the JSON object.