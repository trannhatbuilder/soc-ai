# Detection Policy

## Global Rules

- Alert only on correlated, anomalous, or unauthorized behavior.
- Use evidence from the full window, not worst-case speculation.
- FortiGate `action="accept"` or `action="close"` does not prove successful authentication or compromise.
- Use `sentbyte` and `rcvdbyte` as primary session-strength indicators for `traffic/forward` logs.
- Small byte volume should usually be treated as scan, probe, or low-signal reconnaissance.
- Critical asset context increases review priority but never creates an alert by itself.
- Destination port matters more than source port.
- Use known asset-role context:
  - `10.6.66.3` is the FortiGate syslog forwarder; syslog from external sources is suspicious
  - `128.106.89.53` is the FortiGate WAN public IP; inbound unsolicited traffic is normal noise
  - `10.6.11.0/24` is the internal LAN; outbound to legitimate cloud services is normal
  - `10.6.11.241` and `10.6.11.232` are user endpoints
- Use known authorized source context:
  - `219.92.154.9` is `Remote-VPN-MY`; VPN negotiation is expected
  - `121.200.246.70` is `Remote-VPN-SG`; VPN negotiation is expected
- Authorized source status lowers suspicion only when destination, port, direction, and behavior match the expected use case.
- Required telemetry health matters:
  - FortiGate `traffic` and `utm` logs are both expected inputs
  - if either required log type is absent for a full reporting interval, treat it as `telemetry_gap`
  - telemetry loss is an operational alert, not a no-alert status

## Ignore

- Single FortiGate `traffic/forward` `close` to Microsoft 365 endpoints with normal byte volume.
- FortiGate `event/system` logs: AV database reloads, performance statistics, FortiSandbox updates, scanunit activity.
- FortiGate `event/security-rating` logs: scheduled compliance scans.
- FortiGate `event/user` logs: PRNG reseeding, entropy source events.
- FortiGate `event/vpn` logs from authorized VPN clients (`219.92.154.9`, `121.200.246.70`) with `action="negotiate"` or tunnel state changes.
- FortiGate `utm/dns` queries to legitimate domains (Microsoft, Google, Apple, etc.).
- FortiGate `utm/ssl` for legitimate HTTPS sites with valid certificates.
- FortiGate `utm/app-ctrl` detections on known business applications (Microsoft Outlook, Portal, SharePoint, DNS).
- FortiGate `utm/webfilter` blocks on malicious categories — these are the firewall doing its job.
- FortiGate `traffic/local` `deny` on `wan1` for unsolicited inbound UDP (scan noise).
- Internet scans, random IP probing, or one-off probes with low byte volume.
- Single blocked WAF or IPS event with no volume anomaly.

## Low Signal

- Repeated FortiGate `traffic/local` `deny` from the same source IP within the window.
- Small FortiGate `utm/anomaly` detections with `crscore <= 30` and `action="pass"`.
- A few FortiGate `traffic/forward` flows to sensitive ports where byte volume remains small.
- Single FortiGate `utm/app-ctrl` detection on an unexpected application without repetition.
- Short-lived or low-count VPN connection attempts from unknown external IPs.
- Low-volume external SSH or RDP probing to the FortiGate WAN IP without session evidence.

## Traffic Alert Conditions

### 1. Explicit Benign Patterns (DO NOT ALERT)
Do NOT alert when:
- FortiGate `traffic/forward` from internal LAN to Microsoft 365 endpoints on `443/TCP`
- FortiGate `traffic/forward` from internal LAN to external DNS on `53/UDP`
- FortiGate `traffic/forward` between internal hosts with expected app-to-service behavior
- FortiGate `event/vpn` from authorized VPN clients with normal tunnel negotiation
- FortiGate `utm/app-ctrl` on known business applications
- FortiGate `utm/dns` for legitimate domains
- FortiGate `traffic/local` `deny` on `wan1` from random internet IPs (scan noise)

Classify as:
- `normal_internal_to_external_traffic`
- `expected_vpn_activity`
- `expected_application_traffic`
- `internet_scan_noise`

### 2. Malicious IP Activity
Classify as `malicious_ip_activity` when:
- FortiGate `traffic` or `utm` log involves an IP flagged as `is_malicious=True` by AbuseIPDB enrichment
AND at least one:
  - `confidence_score >= 70` (high-confidence malicious)
  - Multiple events from the same malicious IP in the window
  - Traffic to sensitive ports (`22`, `23`, `3389`, `445`, `5432`)
  - IPS anomaly with `crscore >= 50`

Do NOT classify as `malicious_ip_activity` when:
- The IP has `confidence_score < 30` (low-confidence, likely clean)
- The IP is in the authorized sources list (`219.92.154.9`, `121.200.246.70`)
- The activity is single-event with no repetition or session evidence

### 3. Brute Force / Auth Abuse
Classify as `auth_abuse` when:
- FortiGate `event/vpn` shows repeated failed authentication from same source IP
AND:
  - 5+ `action="tunnel-down"` or auth failures from same IP in window
  - OR `utm/anomaly` with category "Brute Force" (`crscore >= 30`)
  - OR `traffic/local` `deny` on VPN port (`500`, `4500`) 10+ times from same IP

### 4. Reconnaissance / Port Scan
Classify as `reconnaissance` when:
- FortiGate `traffic/local` `deny` from same source IP on 10+ distinct destination ports in window
OR
- FortiGate `utm/anomaly` with category "Port Scan" (`crscore >= 30`)
OR
- Multiple `traffic/forward` flows from same external IP to multiple internal hosts with low byte volume

Prefer `reconnaissance` or no-alert over `exposed_service` when:
- Destination port is sensitive but byte volume is small
- Only a few deny records are present
- The conclusion depends mainly on destination port

### 5. Web Attack
Classify as `web_attack` when:
- FortiGate `utm/anomaly` with category "Web App Attack" or "SQL Injection" (`crscore >= 50`)
- OR FortiGate `utm/webfilter` blocks a URL in attack categories repeatedly from same IP
- OR FortiGate `utm/app-ctrl` detects a known attack tool

### 6. IPS Anomaly
Classify as `ips_anomaly` when:
- FortiGate `utm/anomaly` with `crscore >= 70` and `action="pass"` (high-confidence IPS detection that was NOT blocked)

## Severity Guidance

- Single low-volume probe from one IP in one window: `low` severity or no-alert.
- Repeated matching anomalies across 2-5 windows: `medium` when pattern is clearly recurring.
- Anomalies continuing for ~30 minutes or recurring across most of the last hour: `high`.
- Use `critical` only when:
  - Confirmed service degradation or business impact
  - Clear evidence that blocking controls are failing
  - Multiple high-confidence malicious IPs attacking simultaneously

## Telemetry Health Alert Conditions

- `telemetry_gap`
  - FortiGate `traffic` logs are absent for the full reporting interval
  - OR FortiGate `utm` logs are absent for the full reporting interval
  - OR both are absent for the full reporting interval
- Do not suppress telemetry loss as a normal no-activity condition.
- A telemetry gap is valid even when attack evidence is absent.

## Hard Corrections

- Do not classify normal internal-to-Microsoft-365 traffic as `malicious_ip_activity` or `lateral_movement`.
- Do not classify FortiGate `event/system` AV reloads or perf stats as security events.
- Do not classify FortiGate `event/security-rating` as an attack; these are compliance scans.
- Do not classify FortiGate `event/vpn` from authorized VPN clients as suspicious when the tunnel negotiates normally.
- Do not auto-alert on FortiGate `traffic/local` `deny` on `wan1` from random internet IPs without repetition.
- Do not auto-alert on FortiGate `utm/webfilter` blocks; the firewall is doing its job.
- Do not auto-alert on FortiGate `utm/dns` queries to legitimate domains.
- Do not treat an authorized VPN IP as a blanket bypass. If an authorized source shows anomalous rate, scan behavior, or off-role activity, evaluate it normally.
- Treat recurrent low-volume probes to the FortiGate WAN IP as `reconnaissance` or no-alert noise unless byte count, repetition, or corroborating telemetry shows real-session behavior.