# Known Benign Patterns

## Internet Background Noise

- Single FortiGate `traffic/local` `deny` from random internet IP on `wan1`.
- One-off probes from random public IPs to FortiGate WAN IP.
- Port scans with `sentbyte=0` AND `rcvdbyte=0`.
- Low-byte internet noise with no repetition in the same window.
- Small-packet or low-byte accepted TCP probes to management ports (`22`, `23`) when the evidence still fits handshake-only or banner-grab behavior.
- Recurrent low-volume probes from scanner IPs to FortiGate WAN IP when there is no session or auth evidence.

## FortiGate Event System Benign Patterns

- `event/system` with `logdesc="Scanunit reloaded AV Database"` — routine AV signature update.
- `event/system` with `logdesc="System performance statistics"` — routine perf metrics.
- `event/system` with `logdesc="FortiSandbox AV database updated"` — routine sandbox signature update.
- `event/system` with `action="update"` and `msg` containing "AV database reload" — routine.
- `event/security-rating` with `auditreporttype` of `CoverageReport`, `OptimizationReport`, or `PostureReport` — scheduled compliance scans.
- `event/user` with `action="reseeding"` and `msg` containing "Reseeding PRNG" — entropy routine.

## FortiGate VPN Benign Patterns

- `event/vpn` from `219.92.154.9` (`Remote-VPN-MY`) with `action="negotiate"` — expected VPN negotiation.
- `event/vpn` from `121.200.246.70` (`Remote-VPN-SG`) with `action="negotiate"` — expected VPN negotiation.
- `event/vpn` with `action="tunnel-up"` or `action="tunnel-down"` from authorized VPN clients — normal tunnel state changes.
- FortiGate `traffic/forward` from VPN client IP to internal LAN with expected app behavior.

## FortiGate Traffic Benign Patterns

- `traffic/forward` from `10.6.11.241` to Microsoft 365 endpoints (`40.104.210.2`, `20.190.163.28`, `13.107.136.10`) on `443/TCP`.
- `traffic/forward` from `10.6.11.232` to `208.91.112.53` on `53/UDP` (DNS).
- `traffic/forward` from internal LAN to external HTTPS with normal byte volume (`sentbyte > 1000` OR `rcvdbyte > 1000`).
- `traffic/forward` between internal hosts with `action="close"` and normal session bytes.
- `traffic/local` `deny` on `wan1` from random external IP with `sentbyte=0` AND `rcvdbyte=0`.

## FortiGate UTM Benign Patterns

- `utm/dns` queries to legitimate domains (Microsoft, Google, Apple, Cloudflare, etc.).
- `utm/ssl` for legitimate HTTPS sites with valid certificates.
- `utm/app-ctrl` detections on known business applications:
  - `Microsoft.Outlook`
  - `Microsoft.Portal`
  - `Microsoft.SharePoint`
  - `DNS`
  - `HTTPS`
- `utm/webfilter` blocks on malicious or unwanted categories — these are the firewall doing its job.
- `utm/anomaly` with `crscore < 30` and `action="pass"` — low-confidence IPS detection, usually benign.

## Authorized Source Benign Patterns

- `219.92.154.9` (`Remote-VPN-MY`) negotiating IPSec with FortiGate on `500/UDP` or `4500/UDP`.
- `121.200.246.70` (`Remote-VPN-SG`) negotiating IPSec with FortiGate on `500/UDP` or `4500/UDP`.
- Authorized source traffic that stays low-rate, targets the expected service (VPN), and does not show scanning or auth failures.

## Platform Noise

- FortiGate internal system events: AV reloads, perf stats, sandbox updates.
- Syslog forwarder chatter from `10.6.66.3`.
- Routine VPN keepalive and rekey events.
- DNS resolution traffic to legitimate resolvers.

## Suppression Rule

- If the batch matches one of these patterns and there is no contradictory evidence, prefer `should_alert=false`.