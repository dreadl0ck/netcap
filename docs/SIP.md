Here is the consolidated guidance on modeling NIDS rules for SIP, synthesized from the Council's review of the best available strategies.

Executive Summary
To effectively monitor SIP (Session Initiation Protocol) for network intrusion detection, you must move beyond simple port-based rules and inspect Layer 7 fields. The most effective model breaks SIP security down into three layers:

Protocol Compliance & Sanity: Checking that headers are present, correctly formatted, and within safe size limits.
Header Logic & Semantics: Detecting anomalies in how headers like Via, Contact, From, and User-Agent are populated.
State & Frequency: Tracking the relationship between requests (INVITE) and responses (401 Unauthorized), or the rate of specific methods over time.
1. The Parsing Model: What to Extract
Your NIDS must parse specific SIP elements to be effective. Rules acting on raw payloads using regex alone are prone to high false-positive rates. Focus extraction on these key fields:

Method: REGISTER, INVITE, OPTIONS, BYE, CANCEL.
Request-URI: The target destination (e.g., sip:user@192.168.1.1).
Core Headers:
Call-ID: The unique session identifier.
User-Agent: The client software ID.
From / To: Logical sender/receiver info.
Contact: The specific IP/URI for return traffic.
Via: The transport path (crucial for spotting spoofing).
CSeq: Sequence number (detects replay/injection).
Body Attributes: Specifically Session Description Protocol (SDP) fields like c= (connection info) and m= (media type).
2. Header-Specific Threat Indicators
The following mapping connects specific SIP headers to the attacks they reveal. This serves as the logic basis for your rule creation.

| Header | Indicator / Anomaly | Associated Threat | | :--- | :--- | :--- | | User-Agent | Strings like sip-scan, sipvicious, friendly-scanner. | Reconnaissance: Vulnerability scanners identifying your PBX. | | Via | Internal IP range in Via header when packet source is external. | Spoofing / Topology Hiding: Attacker trying to bypass ACLs or map internal network. | | Contact | Rapidly changing Contact IP for a static From user. | Account Takeover: Hijacking a registration session. | | From / To | From domain matches internal network, but Source IP is external. | Spoofing: Impersonating internal users (Trust Relationship abuse). | | Authorization | High volume of distinct nonce values or Authorizations per source. | Brute Force: Password guessing attack. | | Call-ID | Non-random patterns or identical IDs from multiple IPs. | Session Hijacking: Replay attacks. | | Max-Forwards | Value is 0 or very small (e.g., 1) in an initial INVITE. | Mapping: Traceroute-style topology discovery. |

3. Rule Models & Examples (Suricata/Snort Semantic)
Below are production-ready logic templates translated into standard NIDS syntax.

A. Scanning & Reconnaissance

Attackers use tools to find active extensions.

Logic: Alert if the User-Agent matches known offensive tools.
Rule:
alert udp $EXTERNAL_NET any -> $SIP_SERVERS 5060 (
  msg:"SIP Security: Known Attack Tool User-Agent";
  content:"User-Agent:"; fast_pattern;
  pcre:"/User-Agent:\s*(sipvicious|sip-scan|friendly-scanner|sunday|iwar)/i";
  classtype:attempted-recon;
  sid:10001; rev:1;
)
B. Registration Brute Force

Attackers attempt to guess passwords by flooding REGISTER requests.

Logic: A high rate of REGISTER requests from a single source usually indicates an attack, especially if not followed by a 200 OK.
Rule (Rate Limiting):
alert udp $EXTERNAL_NET any -> $SIP_SERVERS 5060 (
  msg:"SIP Security: Excessive REGISTER attempts (Brute Force)";
  content:"REGISTER"; depth:8;
  # Threshold: Alert if > 30 attempts in 60 seconds from one IP
  threshold: type both, track by_src, count 30, seconds 60;
  classtype:attempted-admin;
  sid:10002; rev:1;
)
C. Internal Spoofing

An external attacker claims to be an internal user to bypass authorization policies.

Logic: If the From header claims to be @internal.com but the Source IP is not in $HOME_NET.
Rule:
alert udp $EXTERNAL_NET any -> $SIP_SERVERS 5060 (
  msg:"SIP Security: Internal Domain Spoofing from External IP";
  content:"INVITE"; depth:6;
  content:"From:"; 
  # Match your internal domain
  content:"@your-internal-domain.com"; within:100;
  classtype:bad-unknown;
  sid:10003; rev:1;
)
D. Fuzzing & Malformed Packets

Attempts to crash the SIP stack using buffer overflows.

Logic: SIP headers have reasonable length limits. A Call-ID or From header exceeding ~256 bytes is highly suspicious.
Rule:
alert udp any any -> $SIP_SERVERS 5060 (
  msg:"SIP Security: Malformed/Long Call-ID Header (Potential Overflow)";
  content:"Call-ID:"; fast_pattern;
  # Looking for 256+ characters after the header
  pcre:"/^Call-ID:\s?.{256,}/mi";
  classtype:attempted-dos;
  sid:10004; rev:1;
)
E. Media Hijacking (SDP Anomalies)

The signaling (SIP) might look fine, but the media (audio) is redirected to a malicious server.

Logic: Inspect the SDP body (Layer 7 payload). If the connection IP (c=IN IP4 ...) is a private IP (RFC1918) but the traffic is over the public internet, it indicates a misconfiguration or an attempt to redirect audio internally.
Rule:
alert udp $EXTERNAL_NET any -> $SIP_SERVERS 5060 (
  msg:"SIP Security: SDP Private IP Leakage from External Source";
  content:"c=IN IP4 192.168."; 
  classtype:policy-violation;
  sid:10005; rev:1;
)
4. Advanced Stateful Modeling
Signature-based rules often miss "low and slow" attacks. For a robust defense, your model should include logical state checks (implemented via scripts or advanced NIDS modules like Zeek):

The "Hanging" INVITE:
Monitor for INVITE requests that never receive an ACK. A high ratio of Un-ACK'd INVITES suggests a flood attack or scanning (e.g., "Ghost Calling").
Sequence Integrity (CSeq):
Monitor the CSeq number within a Call-ID. If the CSeq jumps unexpectedly or reverts to a lower number in an established dialog, it indicates packet injection or replay.
Authentication Failure Ratios:
Instead of just counting REGISTER packets, count 401 Unauthorized responses.
Alert Logic: IF 401_Count / Total_Request_Count > 90% for a specific Source IP (over 1 min), THEN trigger "High Confidence Brute Force."
Final Recommendations for Deployment
Define Variables: Clearly define your $SIP_SERVERS (PBX/SBC) and $HOME_NET variables to reduce false positives.
TLS Blind Spot: Remember that if you use SIPS (SIP over TLS, port 5061), network rules cannot inspect headers. In this scenario, you must offload detection to the Session Border Controller (SBC) or use a host-based agent (HIDS) that sees traffic simply decrypted.
Tuning: Start with the "Scanning" and "Malformed" rules enabled. Run the "Brute Force" rules in alert-only mode first to tune the thresholds (e.g., identifying valid heavy users like receptionists) before enabling blocking.