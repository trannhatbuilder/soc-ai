# Response Playbooks

## Malicious IP Activity

- Confirm the source IP is flagged `is_malicious=True` by AbuseIPDB enrichment.
- Check the AbuseIPDB `confidence_score` and `top_categories`.
- Identify all events in the window involving this IP:
  - `traffic/forward`, `traffic/local`, `utm/anomaly`, `utm/app-ctrl`, `event/vpn`
- Determine the target:
  - FortiGate WAN IP (`128.106.89.53`) — external attack on firewall
  - Internal LAN host — possible intrusion attempt
  - VPN service — brute-force on VPN
- Recommended actions (proportional to confidence and `crscore`):
  - `confidence_score >= 70` and repeated events: add source IP to FortiGate address block list
  - `confidence_score 30-69` and single event: monitor and correlate with future windows
  - Target is sensitive port (`22`, `3389`, `445`): escalate severity
- Do not recommend blocking internal LAN IPs without clear malicious evidence.

## Brute Force / Auth Abuse

- Confirm source IP and count of failed auth events in window.
- Identify the targeted service:
  - VPN (`event/vpn` with `action="tunnel-down"` or auth failures)
  - SSH (`traffic/local` on port `22`)
  - RDP (`traffic/local` on port `3389`)
- Check if source IP is in AbuseIPDB enrichment (malicious flag, confidence).
- Recommended actions:
  - 5+ failed auth from same IP: add to temporary block list (1 hour)
  - 20+ failed auth: add to permanent block list, notify SOC team
  - Targeted account enumeration: lock affected accounts, force password reset
- Pull host and service logs (Linux `auth.log`, Windows Security log) to determine if any login succeeded.

## Reconnaissance / Port Scan

- Confirm source IP and count of distinct destination ports probed.
- Check if scan targets FortiGate WAN IP or internal hosts.
- Identify probed ports:
  - Management ports (`22`, `23`, `3389`, `445`) — higher priority
  - Data-store ports (`3306`, `5432`, `6379`) — higher priority
  - Random high ports — lower priority, likely vulnerability scan
- Check AbuseIPDB enrichment for source IP reputation.
- Recommended actions:
  - 10+ distinct ports from same IP: add to temporary block list
  - 50+ distinct ports or full-range scan: add to permanent block list
  - Targeted sensitive ports: escalate severity, monitor for follow-up attacks
- Do not recommend blocking IPs with single low-volume probes.

## Web Attack

- Confirm FortiGate `utm/anomaly` category (Web App Attack, SQL Injection, XSS).
- Check `crscore` and `action`:
  - `action="drop"` and `crscore >= 50`: attack was blocked, monitor for recurrence
  - `action="pass"` and `crscore >= 50`: attack was NOT blocked, escalate immediately
- Identify the targeted internal host and service.
- Pull web server access logs to verify if the attack reached the application.
- Recommended actions:
  - Blocked attack: monitor, no immediate action unless recurrence
  - Passed attack: isolate targeted host, inspect for compromise indicators
  - Repeated attacks from same IP: add to block list

## IPS Anomaly (High Confidence)

- Confirm FortiGate `utm/anomaly` with `crscore >= 70`.
- Check `action`:
  - `action="drop"`: IPS blocked the traffic
  - `action="pass"`: IPS detected but did NOT block — escalate
- Identify the anomaly signature and affected protocol.
- Recommended actions:
  - Blocked: monitor, document for threat intel feedback
  - Passed: investigate targeted host, check for compromise
  - Repeated high-confidence anomalies: tune IPS policy to drop

## Telemetry Gap

- Treat missing FortiGate `traffic` or `utm` logs for a full reporting interval as a monitoring alert.
- Confirm which required log type is missing:
  - `traffic`
  - `utm`
  - or both
- Check pipeline health in order:
  - upstream FortiGate log delivery (FortiGate config, syslog target)
  - collector or agent process health
  - file creation and file rotation
  - forwarding and local disk availability
- Escalate as telemetry outage if the gap persists into the next interval.

## Internal DB Traffic Review

- Map source IPs to application tiers or known service owners.
- Confirm whether the destination DB or cache host is an expected shared backend.
- Compare the pattern to expected east-west architecture before escalating.
- Do not recommend isolation, blocking, or credential rotation unless malicious evidence exists.

## Lateral Movement

- Confirm source ownership and subnet legitimacy.
- Check for broad host touch, broad port touch, auth failures, compromise indicators, or rapid spread.
- Escalate only when evidence supports unauthorized internal movement.
- Recommended actions:
  - Isolate suspect internal host from LAN
  - Pull host EDR telemetry for process and user activity
  - Force credential reset for affected accounts