# Environment

## Platform

- Production network is protected by FortiGate firewalls.
- Internet-facing traffic is fronted by FortiGate WAN interfaces.
- East-west and ingress/egress network telemetry comes from FortiGate `traffic` logs (forward, local).
- Application-layer inspection (DNS, SSL, web filter, app control, IPS) is provided by FortiGate `utm` logs.
- System health and admin events are captured by FortiGate `event` logs (system, user, vpn, security-rating).
- Continuous visibility is expected from all FortiGate log types.
- Missing `traffic` or `utm` telemetry for a full monitoring interval is an operationally significant blind spot.

## Known Production Assets

- `10.6.66.3`
  - role: FortiGate syslog forwarder
  - service: log relay to SOC collector
  - environment: production
  - expected traffic: syslog UDP/TCP from FortiGate devices only
  - expected port/protocol: `514/UDP`, `6514/TCP`
- `128.106.89.53`
  - role: FortiGate WAN interface (public NAT IP)
  - service: egress NAT for internal LAN
  - environment: production
  - expected traffic: outbound NAT from internal `10.6.11.0/24`
  - expected port/protocol: not limited; reflects internal client activity
- `10.6.11.0/24`
  - role: internal LAN subnet
  - service: corporate workstations
  - environment: production
  - expected traffic: outbound HTTPS/DNS to legitimate cloud services
  - expected port/protocol: ephemeral source, `443/TCP` and `53/UDP` destination
- `10.6.11.241`
  - role: internal workstation
  - service: user endpoint
  - environment: production
  - expected traffic: Microsoft 365, DNS, HTTPS
- `10.6.11.232`
  - role: internal workstation
  - service: user endpoint
  - environment: production
  - expected traffic: DNS, HTTPS

## Authorized Source IPs

- `219.92.154.9`
  - label: `Remote-VPN-MY`
  - trust note: authorized VPN client from Malaysia; treat negotiated tunnels as expected
- `121.200.246.70`
  - label: `Remote-VPN-SG`
  - trust note: authorized VPN client from Singapore; treat negotiated tunnels as expected

## Authorized External Services

- `40.104.210.2`, `20.190.163.28`, `13.107.136.10`
  - label: `Microsoft-365`
  - trust note: legitimate Microsoft Outlook/Portal/SharePoint endpoints
  - expected direction: outbound from internal LAN
- `208.91.112.53`
  - label: `External-DNS`
  - trust note: legitimate external DNS resolver
  - expected direction: outbound DNS from internal LAN

## Normal Baseline

- Internal LAN clients connecting to Microsoft 365 endpoints on `443/TCP` is normal business traffic.
- Internal LAN clients querying external DNS on `53/UDP` is normal.
- VPN clients (`219.92.154.9`, `121.200.246.70`) negotiating IPSec tunnels is normal.
- FortiGate `event/system` logs for AV database reloads, performance statistics, and FortiSandbox updates are operational noise.
- FortiGate `event/security-rating` logs are scheduled compliance scans, not attacks.
- FortiGate `utm/dns` logs for legitimate domains (Microsoft, Google, etc.) are normal.
- FortiGate `utm/ssl` logs for legitimate HTTPS sites are normal.
- FortiGate `utm/webfilter` blocks on malicious categories are expected protective behavior.
- FortiGate `utm/app-ctrl` detections on business applications (Microsoft Outlook, DNS, etc.) are normal.
- FortiGate `traffic/local` deny on `wan1` for unsolicited inbound UDP is expected internet noise.
- Internet scans, one-off probes, and random IP noise hitting `wan1` are routine baseline.

## Traffic Assumptions

- FortiGate `action="close"` in `traffic/forward` means the connection completed normally, not that it was blocked.
- FortiGate `action="accept"` means the firewall allowed the flow. It does not prove authentication or exploit success.
- FortiGate `action="deny"` in `traffic/local` means the local-in policy blocked the flow.
- FortiGate `utm/anomaly` with `action="pass"` means IPS detected an anomaly but passed the traffic (check `crscore`).
- FortiGate `utm/anomaly` with `action="drop"` means IPS dropped the malicious traffic.
- For `traffic/forward` logs, `sentbyte` and `rcvdbyte` are primary indicators of session strength.
- Small byte volume (`sentbyte < 1000` AND `rcvdbyte < 1000`) usually indicates probing, not a real session.
- `srccountry="Reserved"` in FortiGate logs indicates private IP space, not suspicious activity.

## Triage Mode

- Evaluate activity by evidence in the batch window.
- Prefer false-negative tolerance for isolated internet noise over noisy false positives.
- Require threshold, repetition, deviation from baseline, or corroborating signals before escalation.
- Treat missing required telemetry (no `traffic` or no `utm` for a full interval) as an operational alert even when no malicious event is visible.