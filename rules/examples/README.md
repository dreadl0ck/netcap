# Netcap Detection Rules

This directory contains example detection rules for the Netcap network traffic analysis framework. These rules demonstrate various detection capabilities and provide a foundation for custom security monitoring.

## Table of Contents

- [Overview](#overview)
- [Rule Files](#rule-files)
- [Rule Maturity Levels](#rule-maturity-levels)
- [Known Limitations](#known-limitations)
- [Best Practices](#best-practices)
- [Customization Guide](#customization-guide)
- [Contributing](#contributing)

## Overview

The detection rules are organized by security domain and detection objective. Each rule specifies:
- **Name**: Unique identifier for the rule
- **Description**: What the rule detects
- **Type**: Protocol or packet type (TCP, UDP, HTTP, DNS, etc.)
- **Expression**: Logic for matching traffic
- **Severity**: Impact level (low, medium, high, critical)
- **MITRE ATT&CK**: Mapped tactics and techniques
- **Tags**: Categorization labels
- **Enabled**: Whether the rule is active by default

## Rule Files

### `network_reconnaissance.yml`
**Focus**: Network scanning and discovery activities  
**Maturity**: Production-ready  
**Contains**:
- SYN scan detection
- ICMP ping sweeps
- ARP scanning
- UDP port scanning
- DNS zone transfers (AXFR)
- SNMP enumeration
- NetBIOS discovery
- DHCP rogue server detection
- WPAD proxy discovery queries
- LDAP enumeration
- Connection pattern monitoring

**Best for**: Detecting external and internal reconnaissance activities, rogue network services, and domain enumeration.

### `important_ports.yml`
**Focus**: Security-relevant port monitoring  
**Maturity**: Production-ready  
**Contains**:
- Critical risk ports (cleartext protocols, legacy services)
- Database servers (MySQL, MSSQL, Oracle, MongoDB, Redis)
- Remote access protocols (RDP, VNC, SSH, Telnet)
- File sharing (SMB, FTP, NFS)
- Network services (DNS, DHCP, SNMP)
- Admin panels and management interfaces
- External connection monitoring for high-risk services

**Best for**: Monitoring critical infrastructure, detecting exposed services, and tracking external connections to sensitive ports.

### `web_attacks.yml`
**Focus**: Web application attack detection  
**Maturity**: Production-ready  
**Contains**:
- SQL injection (multiple pattern variants)
- Cross-site scripting (XSS)
- Directory traversal / path traversal
- Command injection (OS command injection)
- Web shell upload attempts
- Vulnerability scanner detection
- Sensitive file access attempts
- HTTP enumeration (OPTIONS, excessive errors)
- HTTP method anomalies
- HTTP service abuse / DoS

**Best for**: Detecting web application attacks, scanner activity, and HTTP-based reconnaissance.

### `industrial_ports.yml`
**Focus**: Industrial Control Systems (ICS/OT) monitoring  
**Maturity**: Production-ready  
**Contains**:
- SCADA protocols (Modbus, DNP3, IEC-104)
- PLC protocols (S7comm, EtherNet/IP, PROFINET)
- Building automation (BACnet)
- OPC-UA and OPC Classic
- MQTT and IIoT protocols
- ICS-specific database and file transfer monitoring
- External ICS protocol exposure detection
- ICS protocol flooding and scanning detection

**Best for**: Monitoring critical infrastructure, detecting unauthorized ICS protocol access, and identifying OT network anomalies.

### `modbus_hunt.yml`
**Focus**: Parsed Modbus requests, discovery cardinality, and visibility triage.
**Maturity**: Hunt templates; site-dependent rules and baseline collection are disabled. No automatic blocking or other response actions.

- Write coverage: FC5/15 coils and FC6/16/22/23 holding registers use `HasWriteAddress`, `WriteAddress`, and `WriteQuantity`. FC23 is checked on its write span, not its read span. `WriteValues` and FC22 `AndMask`/`OrMask` remain evidence for process-specific review, not universal malicious-value signatures.
- The example approved tuple is source `192.0.2.10`, destination `192.0.2.20`, unit 1, coils 100..199 for FC5/15 or holding registers 1000..1099 for FC6/16/22/23. These are documentation IPs and zero-based wire addresses, not deployment defaults or human-readable 4xxxx register labels.
- Approval requires the entire interval inside one tuple: `WriteAddress >= 1000 && WriteAddress <= 1099 && WriteQuantity > 0 && WriteQuantity <= 1100 - WriteAddress`. Guarded subtraction avoids end-address overflow. Add approved tuples with OR inside the negation; never exempt an approved source independently of its destination, unit, bank, function, and range.
- FC21 is separate: every `FileRecords` entry must match reference type 6, file 1, and complete record interval 100..199 for the example tuple. Do not treat file records as holding registers or approve only the first subrecord.
- Enabled observation rules cover FC43/MEI14 identification and FC8 diagnostics 4 (listen only), 10 (clear counters), and 1 (restart communications). They indicate requests, not successful changes, PLC stop, or malicious intent. Unknown-role and malformed/unsupported traffic has separate triage rules; matched responses never count as write requests.
- Cardinality uses record-time windows and per-source grouping: distinct destinations, distinct units pinned to one destination, and distinct read starts pinned to one destination/unit/bank. Clone scoped rules with unique names; adapt read functions for each bank (FC1 coils, FC2 discrete inputs, FC3/23 holding registers, FC4 input registers). Thresholds are examples. Repeated polls do not add distinct values. These rules do not detect ordered sweeps, read-then-write sequences, or count the full read span.
- Exception 2 requires a valid matched response. The initiating master is response `DstIP`, while `SrcIP` and the alert source are the responding controller. The template pins both endpoints and unit and emits individual observations. Engine thresholds group by `SrcIP`, so do not describe an unscoped response threshold as per-attacker activity. Unmatched, ambiguous, expired, or missing capture correlation cannot support this attribution; a matched exception proves rejection, not successful manipulation.

**Baseline Missing Checklist** (complete before enabling site-dependent rules):
1. Inventory approved masters, controllers/gateways, unit IDs, banks, exact function codes, and full allowed address intervals; verify wire-address conversion with the asset owner.
2. Obtain file-number/record-range permissions for FC21 and process-specific value/mask limits for FC5/6/15/16/22/23. The templates enforce addresses, not safe process values.
3. Record normal polling/inventory fan-out, distinct units/read starts, cadence, maintenance windows, and authorized diagnostic/device-ID use; set thresholds from representative captures.
4. Verify capture direction, both-way visibility, parser/correlation status, asset ownership, change tickets, and a human triage contact. Test approved and out-of-range traffic before enabling alerts; do not attach automatic blocking in OT.

Validate all templates, including disabled ones, with `go test ./rules -run TestModbus -count=1`.
In an isolated worktree without the `../go-dpi` workspace sibling, use `GOWORK=off go test -tags nodpi ./rules -run TestModbus -count=1`.

### `suspicious_traffic.yml`
**Focus**: Suspicious traffic patterns and attack behaviors  
**Maturity**: Mixed (Production-ready to Baseline)  
**Contains**:
- SSH connection monitoring and tunneling detection
- High port scanning indicators
- Internal lateral movement (RDP, SMB, SSH, WinRM)
- Credential access attacks (DCSync, Kerberos, NTLM relay)
- Remote execution (PSExec, PowerShell, WMI)
- Persistence mechanisms (service creation, scheduled tasks)
- Defense evasion (log clearing, SSH tunneling)
- DoS attacks (SYN floods, service abuse)
- Ransomware indicators (high-volume SMB writes)
- HTTP authentication brute force
- Proxy detection (HTTP CONNECT, SOCKS)
- Enhanced HTTP tunneling detection (CONNECT to non-standard ports, unknown protocol upgrades, unexpected protocol switches) 🆕
- Database external connections

**Best for**: Detecting lateral movement, credential theft, remote execution, protocol-based tunneling, and MITRE ATT&CK tactic coverage across the attack lifecycle.

### `data_exfiltration.yml`
**Focus**: Data theft and exfiltration indicators  
**Maturity**: Production-ready  
**Contains**:
- Large DNS responses (DNS exfiltration)
- Large HTTP POST requests (multiple thresholds)
- External FTP transfers
- DNS tunneling (long queries, TXT records, high volume)
- Large outbound data transfers
- After-hours data movement
- Internal file transfers (SMB)
- Cloud storage uploads

**Best for**: Detecting data exfiltration attempts via HTTP, DNS, FTP, and other protocols.

### `malware_communication.yml`
**Focus**: Malware C2 and botnet traffic  
**Maturity**: Production-ready  
**Contains**:
- IRC botnet communication
- Suspicious port usage (31337, RAT ports)
- DNS to suspicious TLDs (.tk, .cc, .pw)
- HTTP POST to IP addresses
- HTTP beaconing patterns
- SOCKS proxy connections
- Suspicious file downloads (executables)
- Scripting user agents (curl, wget, powershell)

**Best for**: Identifying command-and-control infrastructure, malware communications, and beaconing behavior.

### `threshold_detections.yml`
**Focus**: Rate-based and threshold detection  
**Maturity**: Production-ready  
**Contains**:
- Port scanning (threshold-based)
- Brute force attacks (SSH, RDP, web logins, authentication services)
- Network reconnaissance (ICMP sweeps, DNS zone transfers)
- DoS attacks (SYN floods, UDP floods)
- C2 beaconing patterns
- Web application attack patterns (SQL injection, directory traversal)
- Scanner activity detection
- Lateral movement patterns (SMB enumeration, Kerberos spikes)

**Best for**: Detecting attack patterns that require rate-based analysis and threshold alerting.

### `application_detections.yml`
**Focus**: Application-layer protocol identification  
**Maturity**: Production-ready  
**Contains**:
- Gaming applications
- Streaming services (video and music)
- Social media and messaging
- Video conferencing
- Cloud storage and file sharing
- E-commerce platforms
- VPN and proxy services
- P2P file sharing
- Cryptocurrency applications
- Malware and suspicious applications
- Industrial control system protocols

**Best for**: Application visibility, bandwidth monitoring, policy enforcement, and detecting unauthorized application usage.

### `streaming_protocols.yml`
**Focus**: Real-time media streaming protocol detection  
**Maturity**: Production-ready  
**Contains**:
- RTSP (Real-Time Streaming Protocol) - port 554 TCP/UDP
- RTMP (Real-Time Messaging Protocol) - port 1935
- MMS (Microsoft Media Server) - port 1755
- Icecast streaming - port 8000
- SHOUTcast streaming - port 8001
- RTP/RTCP (Real-time Transport Protocol)
- External streaming connection monitoring
- IP camera and surveillance system traffic

**Best for**: Monitoring IP cameras, security systems, media streaming servers, and detecting unauthorized streaming or media-based data exfiltration.

### `http2_websocket_detection.yml` 🆕
**Focus**: Modern HTTP protocol detection  
**Maturity**: Production-ready  
**Contains**:
- HTTP/2 detection via ALPN negotiation (h2, h2-16, h2-15, h2-14)
- HTTP/2 cleartext (h2c) upgrade detection
- HTTP/3 (QUIC) detection via ALPN
- HTTP/3 Alt-Svc header detection
- WebSocket upgrade request and success detection
- Secure WebSocket (wss://) connections
- Non-browser WebSocket connections (potential C2)
- Automated WebSocket tools (python, curl, etc.)
- Unknown protocol upgrades (tunneling detection)
- Unexpected protocol switches
- Protocol upgrades on unusual ports

**Best for**: Protocol inventory, monitoring adoption of modern protocols, detecting non-browser WebSocket usage (potential C2 communication), and identifying protocol-based tunneling attempts.

**Note**: Extracted from httpx analysis and ProjectDiscovery patterns.

### `http_security_headers.yml` 🆕
**Focus**: HTTP security header analysis  
**Maturity**: Production-ready  
**Contains**:
- Missing HSTS on HTTPS connections
- Missing X-Frame-Options (clickjacking protection)
- Missing X-Content-Type-Options (MIME-sniffing protection)
- Weak CSP configurations (unsafe-inline, unsafe-eval)
- Overly permissive CSP (wildcard sources)
- Cookie security flags (Secure, HttpOnly, SameSite)
- Information disclosure via headers (X-Powered-By, Server version)
- ASP.NET version disclosure
- CMS/framework disclosure (X-Generator)
- Overly permissive CORS configurations
- Sensitive content caching issues
- Weak or deprecated Referrer-Policy

**Best for**: Security posture assessment, identifying misconfigured web applications, finding information disclosure issues, and detecting weak security controls.

**Note**: Helps identify low-hanging security misconfigurations that are easy to fix and can significantly improve security posture.

### `http_technology_fingerprinting.yml` 🆕
**Focus**: Server technology and infrastructure detection  
**Maturity**: Production-ready  
**Contains**:
- Web servers (Nginx, Apache, IIS, LiteSpeed, Caddy)
- Frameworks (ASP.NET, PHP, Node.js, Express, Django, Flask, Rails, Java/Spring, Laravel)
- CMS platforms (WordPress, Drupal, Joomla, Magento, Shopify)
- CDN providers (Cloudflare, Akamai, AWS CloudFront, Fastly)
- Caching layers (Varnish, Nginx cache)
- Load balancers (HAProxy, F5 BIG-IP)
- Proxies (Squid)
- WAF detection (ModSecurity, AWS WAF, Cloudflare WAF)
- Application servers (Tomcat, Jetty, Gunicorn, uWSGI, Passenger)
- Hosting platforms (Heroku, Vercel, Netlify, GitHub Pages)

**Best for**: Asset inventory, technology stack mapping, identifying CDN/WAF usage, and understanding infrastructure composition for security assessments.

**Note**: Extracted from httpx fingerprinting patterns and web technology detection methods.

## Rule Maturity Levels

### 🟢 Production-Ready
**Characteristics**:
- Low false positive rate
- Specific, actionable detection logic
- Well-tested patterns
- Clear severity mapping

**Examples**:
- `SQL_Injection_Attempt`: Pattern-based detection with actual SQL injection signatures
- `Unix_Command_Injection`: Specific command injection patterns
- `Web_Vulnerability_Scanner`: Known scanner user agents
- `DNS_Zone_Transfer_Attempt`: AXFR query type detection
- `Telnet_Usage_Detection`: Clear insecure protocol identification
- `Unknown_DHCP_Server`: Rogue DHCP server detection
- `Docker_Daemon_Access`: Container security exposure
- `Suspicious_Port_31337`: Known backdoor port

**Usage**: Enable these rules in production environments with minimal tuning.

### 🟡 Needs Tuning
**Characteristics**:
- May generate false positives without customization
- Requires environment-specific thresholds
- Benefits from allow-lists or deny-lists
- Needs correlation with other data sources

**Examples**:
- `Large_HTTP_POST_Outbound`: Adjust size thresholds based on environment
- `Cloud_Storage_Upload`: Requires domain allow-list for known cloud services
- `HTTP_404_Scanning`: High volume in some environments
- `Excessive_HTTP_Errors_Client`: Tune error count thresholds
- `After_Hours_Data_Transfer`: Define business hours for your organization
- `High_Port_Internal_Communication`: Maintain allow-list of internal services

**Usage**: Enable with custom thresholds, allow-lists, or correlation rules.

### 🔵 Baseline/Monitoring
**Characteristics**:
- Captures traffic for aggregation and analysis
- Requires rate-based or temporal analysis
- Disabled by default due to high volume
- Useful for correlation and threat hunting

**Examples**:
- `SSH_Connection_Activity`: Requires rate analysis for brute force detection
- `TCP_Connection_Initiation`: Needs aggregation for SYN flood detection
- `Common_C2_Port_Monitoring`: Requires temporal beaconing analysis
- `External_Connection_Monitoring`: For frequency analysis
- `Connection_Pattern_Monitoring`: Needs pattern analysis for scan detection
- `SYN_Packet_Monitoring`: For flood detection at aggregation layer

**Usage**: Enable for data collection when implementing behavioral analysis or ML-based detection. Process with external analytics platform.

### 🔴 Placeholder/Disabled
**Characteristics**:
- Cannot detect claimed behavior without additional capabilities
- Requires features not currently available (e.g., TLS handshake inspection)
- Kept for documentation or future enhancement
- Disabled by default

**Examples**:
- TLS cipher suite detection rules (need handshake parsing)
- TLS protocol version detection (need handshake parsing)
- Perfect Forward Secrecy detection (need cipher suite inspection)
- Certificate algorithm detection (need X.509 parsing)

**Usage**: Do not enable unless you implement the required inspection capabilities.

## Known Limitations

### 1. Rate-Based Detection
Many attack types require analyzing **frequency and patterns over time**:
- **Brute force attacks**: Need to count failed attempts per source/destination
- **Port scanning**: Need to track unique ports per source within time windows
- **DoS/DDoS**: Need to detect abnormal connection rates
- **C2 beaconing**: Need to identify regular communication intervals

**Solution**: Implement these at the analysis/aggregation layer using:
- Time-series analysis
- Statistical anomaly detection
- Machine learning models
- SIEM correlation rules

### 2. Protocol Deep Inspection
Some detections require **parsing protocol internals**:
- TLS cipher suites and protocol versions
- Certificate validation and algorithms
- HTTP content inspection (beyond headers)
- Database protocol fingerprinting

**Current State**: Port-based detection provides baseline monitoring but cannot verify actual protocol details.

**Solution**: Implement protocol parsers or use complementary tools (e.g., Zeek, Suricata) for DPI.

### 3. Context and State
Certain detections require **contextual information**:
- GeoIP location data
- Domain reputation feeds
- Asset inventory (what's normal for each host)
- User behavior baselines

**Solution**: Enrich Netcap data with external threat intelligence and asset context.

### 4. Encrypted Traffic
**Challenge**: Most modern traffic uses encryption (TLS 1.3+), limiting packet content inspection.

**Mitigation Strategies**:
- Focus on metadata: packet sizes, timing, destinations
- Monitor TLS handshake properties (when available)
- Track connection patterns and behaviors
- Use JA3/JA3S fingerprinting for TLS clients/servers
- Implement traffic flow analysis

## Best Practices

### Starting Out
1. **Begin with production-ready rules**: Enable low false-positive detections first
2. **Monitor, don't alert initially**: Collect data to understand your baseline
3. **Tune thresholds**: Adjust size limits, port ranges, and time windows for your environment
4. **Create allow-lists**: Document known-good services, IPs, and domains

### Performance Optimization
1. **Disable baseline rules in high-volume environments** unless feeding to analytics platform
2. **Use specific port ranges** rather than broad expressions
3. **Leverage packet sampling** for high-throughput links
4. **Implement tiered detection**: Fast rules first, complex analysis second

### Reducing False Positives
1. **Add IP/domain allow-lists** for known infrastructure
2. **Correlate multiple rules** rather than alerting on single matches
3. **Use severity levels** to prioritize investigations
4. **Track time-of-day patterns** for after-hours detections
5. **Maintain asset context** (servers vs. workstations have different normal behaviors)

### Security Operations Integration
1. **Map to MITRE ATT&CK** for threat intelligence alignment
2. **Integrate with SIEM/SOAR** for correlation and response
3. **Create runbooks** for each high/critical severity rule
4. **Regular rule review**: Disable ineffective rules, tune noisy ones
5. **Track metrics**: False positive rate, detection rate, investigation time

## Customization Guide

### Modifying Thresholds

```yaml
# Original rule
- name: Large_HTTP_POST_Outbound
  expression: Method == "POST" && ReqContentLength > 10000000 && IsPublicIP(DstIP)
  severity: high

# Customized for your environment (e.g., regular 50MB uploads to cloud storage)
- name: Large_HTTP_POST_Outbound
  expression: Method == "POST" && ReqContentLength > 50000000 && IsPublicIP(DstIP)
  severity: high
```

### Adding Allow-Lists

```yaml
# Add IP exceptions using boolean logic
- name: Suspicious_Database_Access
  expression: DstPort == 3306 && IsPublicIP(DstIP) && DstIP != "203.0.113.10"
  
# Or for multiple exceptions
- name: Suspicious_Database_Access
  expression: DstPort == 3306 && IsPublicIP(DstIP) && !(DstIP in ["203.0.113.10", "203.0.113.11"])
```

### Creating Custom Rules

```yaml
- name: Custom_Internal_SSH_Lateral_Movement
  description: Detect SSH from workstation subnet to server subnet
  type: TCP
  expression: DstPort == 22 && MatchesPattern(SrcIP, "^10\\.10\\..*") && MatchesPattern(DstIP, "^10\\.20\\..*")
  severity: medium
  mitre: ["T1021.004"]
  tags: ["custom", "lateral-movement", "ssh"]
  enabled: true
```

### Rule Testing Workflow

1. **Create rule** with `enabled: false`
2. **Enable in test mode**: Monitor output without alerting
3. **Analyze matches**: Review all detections for false positives
4. **Tune expression**: Add exceptions, adjust thresholds
5. **Enable for alerting**: Set `enabled: true` and configure notifications
6. **Monitor performance**: Track detection rate and false positive rate
7. **Iterate**: Refine based on operational feedback

## Expression Language Reference

### Common Functions
- `IsPrivateIP(IP)`: Check if IP is in RFC1918 ranges
- `IsPublicIP(IP)`: Check if IP is publicly routable
- `MatchesPattern(field, regex)`: Regular expression matching
- `len(array)`: Get array length

### Operators
- `&&`: Logical AND
- `||`: Logical OR
- `!`: Logical NOT
- `==`, `!=`: Equality/inequality
- `>`, `<`, `>=`, `<=`: Comparison
- `in`: Membership testing

### Common Fields by Type

**TCP/UDP**:
- `SrcIP`, `DstIP`
- `SrcPort`, `DstPort`
- `SYN`, `ACK`, `FIN`, `RST`, `PSH`: TCP flags
- `PayloadSize`

**HTTP**:
- `Method`: GET, POST, etc.
- `URL`, `Host`
- `UserAgent`
- `StatusCode`
- `ReqContentLength`, `ResContentLength`
- `ContentType`

**DNS**:
- `Questions[0].Name`: Query domain
- `Questions[0].Type`: Query type (A=1, AAAA=28, TXT=16, AXFR=252)
- `Answers`: Response records

**ICMPv4**:
- `TypeCode`: ICMP type (8=echo request, 0=echo reply)

## Performance Considerations

### Rule Complexity Impact

| Complexity | Example | Performance |
|------------|---------|-------------|
| Simple port check | `DstPort == 22` | Very fast |
| Flag combinations | `SYN && !ACK` | Fast |
| IP range checks | `IsPublicIP(DstIP)` | Fast |
| String matching | `Method == "POST"` | Fast |
| Pattern matching | `MatchesPattern(URL, regex)` | Moderate |
| Multiple patterns | Complex regex | Slower |
| Array iteration | `Questions[0].Name` | Moderate |

**Optimization Tips**:
1. Put fast checks first: `DstPort == 22 && MatchesPattern(...)` (stops early if port doesn't match)
2. Use specific port ranges instead of broad pattern matching
3. Limit regex complexity
4. Avoid rules that match >10% of traffic unless necessary for baseline

## Threat Intelligence Integration

### Adding IOC Matching

```yaml
# Domain-based IOCs
- name: Known_Malicious_Domain
  description: Connection to known malicious domains
  type: DNS
  expression: len(Questions) > 0 && Questions[0].Name in ["evil.example.com", "malware.test"]
  severity: critical
  
# IP-based IOCs
- name: Known_C2_IP
  description: Connection to known C2 infrastructure
  type: TCP
  expression: DstIP in ["198.51.100.10", "203.0.113.50"]
  severity: critical
```

**Best Practice**: Maintain IOC lists in separate files and regenerate rules programmatically from threat feeds.

## Contributing

### Rule Submission Guidelines

When contributing new rules:

1. **Clear naming**: Use descriptive names (noun_verb pattern)
2. **Complete documentation**: Description should explain what, why, and when it triggers
3. **MITRE mapping**: Include relevant ATT&CK techniques
4. **Appropriate severity**: 
   - Critical: Active exploitation, confirmed malicious
   - High: Strong indicators of malicious activity
   - Medium: Suspicious activity requiring investigation
   - Low: Baseline monitoring, informational
5. **Tuning guidance**: Document known false positive sources
6. **Test results**: Include test cases showing true and false positives
7. **Performance notes**: Flag rules with high match rates

### Rule Review Checklist

- [ ] Unique name across all rule files
- [ ] Clear, actionable description
- [ ] Appropriate severity level
- [ ] MITRE ATT&CK mapping
- [ ] Relevant tags
- [ ] Default enabled state documented
- [ ] Known false positives documented
- [ ] Expression syntax validated
- [ ] Test cases provided

## Support and Resources

### Documentation
- [Netcap Documentation](../../docs/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Zeek Scripts Repository](https://github.com/michalpurzynski/zeek-scripts)

### Getting Help
- Review logs for rule match details
- Check expression syntax in documentation
- Test rules individually before bulk enabling
- Monitor performance metrics when enabling new rules

## Version History

### Current Version (Post-Review)
- Fixed broken rules with inverted logic
- Removed duplicate rules across files
- Consolidated overlapping detection rules
- Added comprehensive documentation for rule maturity levels
- Disabled rules requiring capabilities not yet implemented
- Added notes about rate-based detection requirements
- Improved threshold consistency across similar rules

### Future Enhancements
- [ ] TLS handshake inspection for cipher/protocol detection
- [ ] Rate-based aggregation for brute force/scanning
- [ ] GeoIP enrichment integration
- [ ] Threat intelligence feed integration
- [ ] Machine learning model integration for anomaly detection
- [ ] Behavioral baseline establishment
