# Netcap Web UI Gallery

Screenshots from the Netcap service mode web interface. Start the web UI with:

```bash
./net capture -read traffic.pcap --service
```

---

## 1. Audit Records Overview

After loading a PCAP, the Audit Records page gives you a structured overview of everything Netcap decoded. Records are organized by encapsulation layer — Link, Network, Transport, Application, and Abstract Decoders — with record counts and file sizes. From here you can view records or explore any type in detail.

![Audit Records Hierarchy](gallery/audit-records-hierarchy.png)

---

## 2. Browsing Records

Drill into any audit record type to browse individual records. Switch between a structured UI and raw JSON view, and apply field-level filters to narrow results. Here, HTTP records are filtered by `UserAgent == "Download"` to isolate suspicious download activity.

![HTTP Record Browser](gallery/http-record-browser.png)

---

## 3. Exploring Patterns

The Explore page lets you chart any field from any audit record type. Choose from bar, funnel, pie, word cloud, Sankey, and network graph visualizations. This pie chart shows SMTP command sequences across mail sessions, revealing the most common command patterns at a glance.

![SMTP Commands Pie Chart](gallery/explore-smtp-pie-chart.png)

---

## 4. Protocol Hierarchy

The Sankey diagram shows how traffic flows across protocol layers — from link layer through transport to application. The sidebar lists all decoded protocols with packet counts and color-coded layer indicators. This is the fastest way to understand what a capture contains.

![Protocol Hierarchy Sankey Diagram](gallery/protocol-hierarchy-sankey.png)

---

## 5. Audit Record Distribution

The treemap shows the relative volume of each audit record type grouped by protocol layer. Large blocks mean more records — immediately spot which protocols dominate the capture.

![Audit Record Types Treemap](gallery/audit-record-treemap.png)

---

## 6. Host Communication Graph

A circular chord diagram maps connections between internal (green) and external (red) IP addresses. Node size reflects traffic volume. Use this to identify dominant talkers, unexpected communication patterns, and suspicious external connections.

![Host Communication Graph](gallery/host-communication-graph.png)

---

## 7. Connection Pattern Analysis

The 3D scatter plot visualizes connection attributes across three dimensions simultaneously. Rotate and zoom interactively to discover clusters and outliers that may indicate anomalous behavior.

![3D Scatter Plot](gallery/connection-scatter-3d.png)

---

## 8. IP Geolocation Map

A world map plots geographic locations of observed IP addresses using MaxMind GeoIP enrichment. Spot unexpected foreign connections instantly — useful for identifying C2 communication or data exfiltration to unusual regions.

![IP Geolocation Map](gallery/geolocation-map.png)

---

## 9. Services Discovery

The Services page shows all discovered network services with detected product and version (Apache httpd, nginx, NetBox httpd, Microsoft IIS). Expand any row to see traffic statistics, HTTP banners, and host information. Jump to related connections or service probes from here.

![Services Overview](gallery/services-overview.png)

---

## 10. Raw Conversation Viewer

Inspect the raw bidirectional data exchange of any TCP connection. Client-to-server traffic is shown in red, server-to-client in blue. Supports hex view for binary protocol analysis and per-connection deep inspection.

![Raw Conversation Data](gallery/raw-conversation-data.png)

---

## 11. Credentials Harvester

Netcap automatically extracts credentials observed in network traffic. The Credentials page shows summary statistics and a table with capture time, protocol (HTTP, Redis, FTP, TLS), usernames, passwords, and network flows. Expand any entry for connection details and login parameters.

![Credentials Harvester](gallery/credentials-harvester.png)

---

## 12. Alerts Dashboard

The Alerts page lists all triggered detection rules, filterable by severity. Critical alerts like IEC 104 detection, Docker API Unencrypted, MSSQL exposure, SYN Flood, and Malware are shown with counts, timestamps, and unique IPs. Expand any alert for full details.

![Alerts Dashboard](gallery/alerts-dashboard-critical.png)

---

## 13. Alert Detail: HTTP POST to IP

Expanding an alert reveals the full context: rule name, description, severity, MITRE ATT&CK tag (T1071.001), source and destination IPs, tags (C2, ruleset malware), and the complete matched record in JSON for forensic review.

![Alert Details HTTP POST](gallery/alert-details-http-post.png)

---

## 14. Alert Detail: DHCP Detection

Another alert example showing DHCP traffic detection. The detail view includes the rule expression with port-based matching logic, MITRE ATT&CK mapping (T1557.003), tags (rogue-server, subnet network recon), and the matched UDP record with full packet metadata.

![Alert Details DHCP](gallery/alert-details-dhcp.png)

---

## 15. Service Probe Editor

Configure custom service detection probes to fingerprint network services. This example shows a backdoor detection probe matching the Darkmoon/Reptile ftpd signature via regex on service banners. Define service name, product, version, hostname, OS, and device type for automated classification.

![Service Probe Editor](gallery/service-probe-editor.png)
