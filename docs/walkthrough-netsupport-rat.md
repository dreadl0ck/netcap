---
description: A complete Netcap investigation of a real NetSupport RAT infection, from host identity to detection triage and an upstream rule fix.
---

# Worked example: a NetSupport RAT infection

This walkthrough investigates a real infection end to end with Netcap: who was hit, how it started, what the remote-access trojan did on the wire, which detections helped, and which detection was broken and got fixed. Every claim below names the record and fields it comes from, so you can reproduce it.

The traffic is Brad Duncan's [“The Lucky Turkey”](https://www.malware-traffic-analysis.net/2026/11/10/index.html) exercise from Malware-Traffic-Analysis.net. A SOC alert reported NetSupport RAT traffic to `93.152.209[.]36:443`; the capture is from the Windows host behind it.

## Input

| | |
| --- | --- |
| File | `2026-11-10-traffic-analysis-exercise.pcap`, 31,077,208 bytes, 30,182 packets |
| SHA-256 | `b52bd2a4ec9d747266206e10df01283197cc3e8ace8af20f1c1e5fb8f0b61533` |
| Time span | 2026-11-10 18:19:52.69 to 20:24:53.91 UTC |
| Network | `10.11.10.0/24`, AD domain `THELUCKYTURKEY` / `theluckyturkey[.]com`, DC `10.11.10.10` (`LUCKYTURKEY-DC`) |
| Netcap | v0.16.12, nodpi build, rules from `internal/rules/examples` |

Download the ZIP from the exercise page; the password scheme is on the site's [about page](https://www.malware-traffic-analysis.net/about.html). The capture contains live malware traffic: work in an offline VM, do not run anything extracted from it, and do not visit the indicators.

```sh
net capture -read 2026-11-10-traffic-analysis-exercise.pcap -out lucky-turkey \
  -rules netcap/internal/rules/examples -fileStorage "" -dpi=false -geoDB=false
```

`-fileStorage ""` disables file extraction, so no malware lands on disk. `-rules` points at your checkout's rule pack, so a rule you edit takes effect on the next run. The capture-manifest reports all 30,182 packets admitted, no queue drops and no truncation; `TCPReassemblyHealth.json` reports one packet rejected for TCP options and no missing bytes. Nothing below depends on that one packet.

## 1. Identify the host and the user

```sh
net triage -read lucky-turkey
```

| IP | MAC | Host name | Account |
| --- | --- | --- | --- |
| `10.11.10.147` | `00:12:f0:e5:17:43` (Intel) | `DESKTOP-5OMVI3L` | `THELUCKYTURKEY\edward.winslow` |
| `10.11.10.10` | `00:c0:4f:a2:95:e7` (Dell) | | |

The triage table is a summary; confirm each column in the underlying records.

| Claim | Record | Evidence |
| --- | --- | --- |
| Host name | `DHCPv4` | option 12 `DESKTOP-5OMVI3L`, option 81 FQDN `DESKTOP-5OMVI3L.theluckyturkey.com` |
| Host name | `Kerberos` | `AS-REQ` from `10.11.10.147:49673` at 18:19:56.242, `ClientName` `desktop-5omvi3l$` |
| User | `Kerberos` | `AS-REQ` from `10.11.10.147:49715` at 18:20:14.476, `ClientName` `edward.winslow`, realm `THELUCKYTURKEY` |
| Full name | `DCERPC` (SAMR) | `SamrQueryInformationUser` returns `Edward Winslow` |

```sh
net dump -read lucky-turkey/Kerberos.ncap.gz -csv \
  -select Timestamp,MessageType,ClientName,SrcIP,SrcPort \
  -filter 'MessageType == "AS-REQ" && !(ClientName endsWith "$")'
```

A principal ending in `$` is the computer account; the one without it is the user who logged on. The SAMR full name is the directory's answer about that account, not proof of who sat at the keyboard.

## 2. Build the timeline

All times 2026-11-10 UTC.

| Time | What | Record and fields |
| --- | --- | --- |
| 18:19:52 | Capture starts; host boots onto the domain (DHCP, LDAP, Kerberos) | `DHCPv4`, `Kerberos` |
| 18:20:14.476 | `edward.winslow` logs on | `Kerberos` `AS-REQ`, src port 49715 |
| 18:20:31 | Browser activity: Google search and sign-in services | `TLSClientHello` `SNI` `www.google[.]com`, `accounts.google[.]com` |
| 18:20:43.188 | Browser opens `crownherliving[.]com` (`66.223.49[.]89`) | `TLSClientHello` `SNI` |
| 18:20:43.8–44.3 | Same page pulls assets from an S3 bucket `bronkbuilder-website-assets` and from `adsmanagertgo[.]click` (`172.67.217[.]8`) | `TLSClientHello` `SNI` |
| 18:20:45.296 | 6,067,418 bytes downloaded from `104.21.68[.]221:443` under SNI `cloudflare-ech[.]com` | `Connection`, `TLSClientHello` |
| 18:21:49.748 | DNS answer `vericheckusgo[.]com` → `96.62.224[.]200` | `DNS` |
| 18:21:49.931 | `GET /` from `vericheckusgo[.]com` with User-Agent `…WindowsPowerShell/5.1.26100.9711`; 15,995-byte `text/html` reply from `Apache/2.4.58 (Ubuntu)` | `HTTP` |
| 18:21:52.040 | DNS and TLS to `www.python[.]org` | `DNS`, `TLSClientHello` |
| 18:21:59.047 | `GET /5555.mp4` from `96.62.224[.]200`, User-Agent `Mozilla/5.0`, 6,045,311 bytes `video/mp4` | `HTTP` |
| 18:22:05.893 | DNS query `dasiiiitt[.]com`; answer `93.152.209[.]36` at 18:22:07.497 | `DNS` |
| 18:22:07.510 | TCP SYN `10.11.10.147:51487` → `93.152.209[.]36:443` | `Connection.TimestampFirst` |
| 18:22:07.729 | First NetSupport poll | `HTTP` |
| 20:24:25.097 | Last packet on that connection; capture ends 28 s later | `Connection.TimestampLast` |

```sh
net dump -read lucky-turkey/HTTP.ncap.gz -csv \
  -select Timestamp,SrcIP,DstIP,DstPort,Method,Host,URL,UserAgent \
  -filter 'MatchesPattern(UserAgent, "(?i)powershell")'
net dump -read lucky-turkey/DNS.ncap.gz -json -filter 'any(Questions, .Name == "dasiiiitt.com")'
net dump -read lucky-turkey/TLSClientHello.ncap.gz -csv \
  -select Timestamp,DstIP,SNI -filter 'SNI == "crownherliving.com"'
```

### Reading the timeline

The pivot is the PowerShell request at 18:21:49. A browser does not send `WindowsPowerShell` in its User-Agent, so a script on the host fetched the first stage from `vericheckusgo[.]com`, not the user clicking a link. Malware-Traffic-Analysis.net identifies that 15,995-byte response as a malicious script.

The 64 seconds before it are the likely lure: a website visit, assets from an unrelated advertising domain, then a pause, then PowerShell. That pattern fits a ClickFix-style “paste this command to verify” page, but the capture cannot show the user pasting anything, and `crownherliving[.]com` may be a compromised site rather than an attacker's. Treat the lure as a hypothesis to check against browser history on the host.

`cloudflare-ech[.]com` is not the real destination. With Encrypted Client Hello, the outer SNI names Cloudflare's ECH front and the real hostname is encrypted; Netcap reports what is on the wire.

`5555.mp4` is a real 6 MB video by content type and by Netcap's content detection. The exercise author reports it is not malicious on its own. It arrives eight seconds before the RAT starts, from the same server as the script, so it belongs to the infection chain even if its role is unknown from traffic alone.

## 3. Analyze the command-and-control channel

```sh
net dump -read lucky-turkey/HTTP.ncap.gz -csv \
  -select Timestamp,Method,URL,StatusCode,UserAgent,ServerName \
  -filter 'DstIP == "93.152.209.36"'
```

| Observation | Value |
| --- | --- |
| Transport | One TCP connection, `10.11.10.147:51487` → `93.152.209[.]36:443`, Community ID `1:XvsB0/hD0V9WdPqCi9DFexx1n+0=` |
| Protocol | Cleartext HTTP/1.1, not TLS: `POST http://93.152.209.36/fakeurl.htm` |
| Client | `User-Agent: NetSupport Manager/1.3` |
| Server | `Server: NetSupport Gateway/1.92 (Windows NT)` |
| Volume | 125 HTTP requests; 256 packets, 36,172 bytes client→server, 7,450 bytes server→client |
| Cadence | Median 60.14 s between polls, maximum 60.30 s, for just over two hours |
| Body | `CMD=ENCD`, `ES=1`, `DATA=<binary>`: NetSupport's encrypted command envelope |

The first two requests at 18:22:07 get `200 OK` replies with bodies of 69 and 155 bytes: the client registers with the gateway. After that the gateway sends only TCP acknowledgements, which is why every later `HTTP` record has `StatusCode` 0. The client keeps polling once a minute and the operator never sends a command that shows up as payload in this capture.

Three points to take from this:

- Port 443 is not evidence of TLS. Netcap decoded HTTP because the bytes were HTTP; a port-based tool would have reported “HTTPS to a foreign IP” and stopped.
- The `CMD=ENCD` body is encrypted by NetSupport itself, so the commands are unreadable from the network. What is visible is the registration, the cadence and the gateway.
- `dasiiiitt[.]com` was resolved 1.6 s before the connection, so it is the configured gateway name even though every request uses the bare IP.

## 4. Triage the detections

The run raises 108 alert records under 35 rule names. These are the ones that matter for this incident:

```sh
net dump -read lucky-turkey/Alert.ncap.gz -csv -select Name,Severity,SrcIP,DstIP,DstPort \
  -filter 'SrcIP == "10.11.10.147" || DstIP == "10.11.10.147"'
```

| Alert | Source | On | Verdict |
| --- | --- | --- | --- |
| `c2.beacon` | network detection | the poll | True positive. Reports the 60 s interval and 0.001 jitter |
| `policy.http-on-443` | network detection | the poll | True positive. Exactly the port-443 point above |
| `NetSupport Manager RAT User Agent Detected` | `suspicious_user_agents.yml` | the poll | True positive |
| `HTTP POST to IP`, `Suspicious HTTP Beaconing` | `malware.yml` | the poll | True positive |
| `PowerShell User Agent Detected` | `web_attacks.yml` | the first-stage fetch | True positive, and the most useful alert in the run |
| `Unknown HTTP Proxy Detection` | `suspicious_traffic.yml` | the poll | Right flow, wrong reason: NetSupport writes absolute URIs, no proxy is involved |
| `Legacy Windows OS Detected` | `asset_discovery.yml` | `DeviceProfile.OS` `MSFT 5.0` | False positive. Every Windows version since 2000 sends DHCP vendor class `MSFT 5.0`; this host runs build 26100 |
| `Suspicious File Download` | `malware.yml` | Defender update from `au.download.windowsupdate[.]com` | False positive |
| `DotNet WebClient Detected` | `web_attacks.yml` | `Microsoft-CryptoAPI/10.0` fetching a certificate list | False positive. CryptoAPI is not .NET |
| `ICS Kerberos Detected` | `industrial_ports.yml` | any TCP/88 | Misleading. Office Kerberos labelled as ICS |
| `Port Scan High Port` | `suspicious_traffic.yml` | one SYN to the DC's RPC port 52500 | False positive. One connection is not a scan |
| `NetSupport Gateway RAT Server User Agent Detected` | `suspicious_user_agents.yml` | nothing | Missed. See below |

Nothing detects the lure page or `vericheckusgo[.]com` by name, which is expected: Netcap ships no threat-intelligence feed. You can add the indicators through a [network-detection config](network-detections.md#indicators-and-policy).

## 5. Fix the missed detection

The rule meant to flag the gateway was:

```yaml
- name: NetSupport Gateway RAT Server User Agent Detected
  type: HTTP
  expression: MatchesPattern(UserAgent, "(?i)^netsupport gateway")
```

The gateway is the server. It never sends a User-Agent; it identifies itself in the response `Server` header, which Netcap stores in `HTTP.ServerName`. The rule could not fire on any real NetSupport traffic.

The fix changes the field and the name to say what the rule checks:

```yaml
# The gateway identifies itself in the response Server header, not in a User-Agent.
- name: NetSupport Gateway Server Header Detected
  description: HTTP response from a NetSupport Gateway, the relay NetSupport RAT clients poll
  type: HTTP
  expression: MatchesPattern(ServerName, "(?i)^netsupport gateway")
```

`internal/rules/netsupport_test.go` builds a synthetic poll record and checks both NetSupport rules, plus two negative cases: a record carrying only the client User-Agent, and an Apache `Server` header. It fails before the change (`rule missing`) and passes after it:

```sh
GOWORK=off go test -tags nodpi,noyara -run TestNetSupport ./internal/rules/
```

Rerunning the capture with the fixed rule pack raises `NetSupport Gateway Server Header Detected` once, on `10.11.10.147` → `93.152.209[.]36`. The test uses no bytes from the capture, so the malware traffic never enters the repository.

The false positives in the table are open for the same treatment. The `MSFT 5.0` one is the most interesting: the rule is wrong, but so is the field it reads, because a DHCP vendor class is being reported as an operating system.

## 6. Indicators

| Indicator | Role | First seen |
| --- | --- | --- |
| `vericheckusgo[.]com`, `96.62.224[.]200` | First-stage script and `5555.mp4` host | 18:21:49 |
| `dasiiiitt[.]com`, `93.152.209[.]36:443` | NetSupport gateway | 18:22:05 |
| `NetSupport Manager/1.3`, `NetSupport Gateway/1.92`, `/fakeurl.htm` | Client and gateway fingerprints | 18:22:07 |
| `crownherliving[.]com`, `adsmanagertgo[.]click` | Pages loaded just before the first stage; unconfirmed lure | 18:20:43 |

## 7. What the capture cannot tell you

- Which process ran the PowerShell command, and whether the user typed it. That needs endpoint telemetry or PowerShell logs.
- What the first-stage script and `5555.mp4` contain; this walkthrough deliberately does not extract them.
- What the operator did. The `ENCD` channel is encrypted and no command payload follows registration.
- Whether NetSupport persists, or whether it is still running after 20:24:53 when the capture ends.

Next steps on the host: PowerShell and process-creation logs around 18:21:49, browser history around 18:20:43, NetSupport's install directory and its `client32.ini` gateway setting, and autorun entries.

## Credit

Traffic and scenario: Brad Duncan, [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/). His answer sheet agrees on the IP, MAC, host name, user and the 18:22:07 UTC start. This repository does not redistribute the capture.
