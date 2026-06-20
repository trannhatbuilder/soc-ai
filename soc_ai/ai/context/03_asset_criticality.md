# Asset Criticality

## Rule

- Criticality increases review priority.
- Criticality alone must never create an alert.
- A critical asset with normal behavior remains normal.

## Network Assets

- Management access ports:
  - `22` (SSH)
  - `23` (Telnet)
  - `3389` (RDP)
  - `445` (SMB)
- Data-store access ports:
  - `3306` (MySQL)
  - `5432` (PostgreSQL)
  - `6379` (Redis)
  - `27017` (MongoDB)
  - `9200` (Elasticsearch)
- VPN / IPSec ports:
  - `500` (IKE)
  - `4500` (IKE-NAT-T)
- Syslog ports:
  - `514` (UDP)
  - `6514` (TCP)
- Private services that are not intended for direct internet exposure.

## Known Asset Inventory

- `10.6.66.3`
  - production FortiGate syslog forwarder
  - service: log relay
  - expected port: `514/UDP`, `6514/TCP`
  - expected direction: inbound from FortiGate devices only
  - criticality note: external sources sending syslog here is suspicious; expected internal syslog is normal
- `128.106.89.53`
  - production FortiGate WAN public IP
  - service: egress NAT for `10.6.11.0/24`
  - expected port: not limited (reflects internal client activity)
  - expected direction: primarily outbound NAT
  - criticality note: inbound unsolicited traffic is normal internet noise; inbound established sessions to internal hosts require investigation
- `10.6.11.0/24`
  - production internal LAN subnet
  - service: corporate workstations
  - expected port: ephemeral source, `443/TCP` and `53/UDP` destination
  - expected direction: outbound to legitimate cloud services
  - criticality note: unexpected inbound to this subnet from external IPs requires investigation
- `10.6.11.241`
  - production user endpoint
  - service: workstation
  - expected traffic: Microsoft 365, DNS, HTTPS
  - criticality note: outbound to known-bad IP is suspicious
- `10.6.11.232`
  - production user endpoint
  - service: workstation
  - expected traffic: DNS, HTTPS
  - criticality note: outbound to known-bad IP is suspicious

## Authorized Sources

- `219.92.154.9`
  - `Remote-VPN-MY`
  - trusted for VPN negotiation to FortiGate only
- `121.200.246.70`
  - `Remote-VPN-SG`
  - trusted for VPN negotiation to FortiGate only

## Authorized External Services

- `40.104.210.2`, `20.190.163.28`, `13.107.136.10`
  - `Microsoft-365`
  - trusted for outbound HTTPS from internal LAN
- `208.91.112.53`
  - `External-DNS`
  - trusted for outbound DNS from internal LAN

## Internal Traffic Clarification

- Internal LAN clients connecting to Microsoft 365 endpoints on `443/TCP` is not automatically suspicious.
- Internal LAN clients querying external DNS on `53/UDP` is normal.
- Multiple internal clients reaching the same external service can be normal shared-service behavior.
- Sustained or high-count internal sessions are not proof of compromise without baseline deviation or corroborating evidence.